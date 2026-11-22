import { createServer } from 'node:http';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

const { PORT = 8080, CONTENT_DIR = './data', SITE_PASSWORD, SITE_ORIGIN = 'https://gacorp-pe.github.io' } = process.env;
if (!SITE_PASSWORD) throw new Error('Set SITE_PASSWORD to the current login password');

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
db.exec('CREATE TABLE IF NOT EXISTS site_session (hash TEXT PRIMARY KEY, expires INTEGER NOT NULL)');
const insertSession = db.prepare('INSERT INTO site_session VALUES (?, ?)');
const findSession = db.prepare('SELECT 1 FROM site_session WHERE hash = ? AND expires > ?');
const deleteSession = db.prepare('DELETE FROM site_session WHERE hash = ?');
const cleanSessions = db.prepare('DELETE FROM site_session WHERE expires <= ?');
const passwordHash = hash(SITE_PASSWORD);
const sessionDuration = 7 * 24 * 60 * 60 * 1000;
const maxSize = 8 * 1024 * 1024;

function hash(value) {
  return createHash('sha256').update(value).digest();
}

function send(response, status, body) {
  response.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  response.end(JSON.stringify(body));
}

async function readBody(request, limit = maxSize) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > limit) return null;
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString('utf8');
}

createServer(async (request, response) => {
  response.setHeader('Cache-Control', 'no-store');
  response.setHeader('Vary', 'Origin');
  if (request.headers.origin === SITE_ORIGIN) {
    response.setHeader('Access-Control-Allow-Origin', SITE_ORIGIN);
    response.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    response.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type');
  }
  if (request.url === '/health' && request.method === 'GET') return send(response, 200, { ok: true });
  if (!['/v1/content', '/v1/session'].includes(request.url)) return send(response, 404, { error: 'not_found' });
  if (request.method === 'OPTIONS') {
    response.writeHead(request.headers.origin === SITE_ORIGIN ? 204 : 403);
    return response.end();
  }
  if (request.url === '/v1/session') {
    if (request.method === 'DELETE') {
      deleteSession.run(hash(request.headers.authorization || '').toString('hex'));
      return send(response, 200, { ok: true });
    }
    if (request.method !== 'POST') return send(response, 405, { error: 'method_not_allowed' });
    try {
      const body = await readBody(request, 4096);
      if (body === null) return send(response, 413, { error: 'request_too_large' });
      const { username, password } = JSON.parse(body) ?? {};
      if (typeof username !== 'string' || username.trim().toLowerCase() !== 'gacorp2026'
        || typeof password !== 'string' || !timingSafeEqual(passwordHash, hash(password))) {
        return send(response, 401, { error: 'invalid_credentials' });
      }
      const token = randomBytes(32).toString('hex');
      const now = Date.now();
      cleanSessions.run(now);
      insertSession.run(hash(`Bearer ${token}`).toString('hex'), now + sessionDuration);
      return send(response, 200, { token, expiresAt: now + sessionDuration });
    } catch {
      return send(response, 400, { error: 'invalid_session_request' });
    }
  }
  if (request.method === 'GET') {
    const current = getContent.get();
    return send(response, 200, { revision: current?.revision ?? 0, content: current ? JSON.parse(current.content) : null });
  }
  if (request.method !== 'PUT') return send(response, 405, { error: 'method_not_allowed' });
  if (!findSession.get(hash(request.headers.authorization || '').toString('hex'), Date.now())) {
    return send(response, 401, { error: 'invalid_session' });
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
