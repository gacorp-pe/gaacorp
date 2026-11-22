import { createServer } from 'node:http';
import { createHash, timingSafeEqual } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

const { PORT = 8080, CONTENT_DIR = './data', EDITOR_KEY, SITE_ORIGIN = 'https://gacorp-pe.github.io' } = process.env;
if (!EDITOR_KEY || EDITOR_KEY.length < 24) throw new Error('Set an EDITOR_KEY of at least 24 characters');

mkdirSync(CONTENT_DIR, { recursive: true });
const db = new DatabaseSync(join(CONTENT_DIR, 'content.sqlite'));
db.exec(`CREATE TABLE IF NOT EXISTS site_content (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  revision INTEGER NOT NULL,
  content TEXT NOT NULL
)`);
const getContent = db.prepare('SELECT revision, content FROM site_content WHERE id = 1');
const insertContent = db.prepare('INSERT OR IGNORE INTO site_content VALUES (1, 1, ?)');
const updateContent = db.prepare('UPDATE site_content SET content = ?, revision = revision + 1 WHERE id = 1 AND revision = ?');
const editorHash = hash(`Bearer ${EDITOR_KEY}`);
const maxSize = 8 * 1024 * 1024;

function hash(value) {
  return createHash('sha256').update(value).digest();
}

function send(response, status, body) {
  response.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  response.end(JSON.stringify(body));
}

async function readBody(request) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > maxSize) return null;
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString('utf8');
}

createServer(async (request, response) => {
  response.setHeader('Cache-Control', 'no-store');
  response.setHeader('Vary', 'Origin');
  if (request.headers.origin === SITE_ORIGIN) {
    response.setHeader('Access-Control-Allow-Origin', SITE_ORIGIN);
    response.setHeader('Access-Control-Allow-Methods', 'GET, PUT, OPTIONS');
    response.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type');
  }
  if (request.url === '/health' && request.method === 'GET') return send(response, 200, { ok: true });
  if (request.url !== '/v1/content') return send(response, 404, { error: 'not_found' });
  if (request.method === 'OPTIONS') {
    response.writeHead(request.headers.origin === SITE_ORIGIN ? 204 : 403);
    return response.end();
  }
  if (request.method === 'GET') {
    const current = getContent.get();
    return send(response, 200, { revision: current?.revision ?? 0, content: current ? JSON.parse(current.content) : null });
  }
  if (request.method !== 'PUT') return send(response, 405, { error: 'method_not_allowed' });
  if (!timingSafeEqual(editorHash, hash(request.headers.authorization || ''))) {
    return send(response, 401, { error: 'invalid_editor_key' });
  }
  try {
    const body = await readBody(request);
    if (body === null) return send(response, 413, { error: 'content_too_large' });
    let payload;
    try {
      payload = JSON.parse(body);
    } catch {
      return send(response, 400, { error: 'invalid_json' });
    }
    const { revision, content } = payload ?? {};
    if (!Number.isSafeInteger(revision) || revision < 0 || !content || typeof content !== 'object' || Array.isArray(content)) {
      return send(response, 400, { error: 'invalid_content' });
    }
    const encoded = JSON.stringify(content);
    const result = revision === 0 ? insertContent.run(encoded) : updateContent.run(encoded, revision);
    if (!result.changes) return send(response, 409, { error: 'revision_conflict' });
    return send(response, 200, { revision: revision + 1 });
  } catch (error) {
    console.error('Content save failed:', error.message);
    if (!response.destroyed) send(response, 500, { error: 'save_failed' });
  }
}).listen(Number(PORT), '0.0.0.0');
