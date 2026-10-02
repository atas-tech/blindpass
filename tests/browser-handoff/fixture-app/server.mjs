// SPDX-License-Identifier: AGPL-3.0-only
import { createHash, randomBytes, scrypt as scryptCallback, scryptSync, timingSafeEqual } from 'node:crypto';
import { createServer } from 'node:https';
import { promisify } from 'node:util';
import { AccountRevocation } from './session-revocation.mjs';

export const SESSION_COOKIE = '__Host-bp-fixture';
const MAX_SESSION_MS = 30 * 60 * 1000;
const BODY_LIMIT = 4096;
const scrypt = promisify(scryptCallback);
const digest = (value) => createHash('sha256').update(value).digest('hex');
const escapeHtml = (value) => value.replace(/[&<>"']/g, (char) => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
})[char]);
const loginPage = `<!doctype html><html lang="en"><meta charset="utf-8"><title>Fixture sign in</title>
<main><h1>Fixture sign in</h1><form id="login"><label>Username <input name="username" autocomplete="off" required></label>
<label>Password <input name="password" type="password" autocomplete="off" required></label><button>Sign in</button></form>
<p id="status" role="status"></p></main><script src="/login.js" defer></script></html>`;
const loginScript = `document.querySelector('#login').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const status = document.querySelector('#status');
  try {
    const response = await fetch('/login', { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: form.elements.username.value, password: form.elements.password.value }) });
    await response.json();
    form.reset();
    if (response.ok) location.replace('/reports');
    else status.textContent = 'Sign in failed';
  } catch { status.textContent = 'Sign in unavailable'; }
  finally { form.reset(); }
});`;

class RequestError extends Error {
  constructor(code, status) { super(status); this.code = code; this.status = status; }
}

async function readJson(req) {
  if (req.headers['content-type']?.split(';')[0].trim() !== 'application/json') {
    req.resume();
    throw new RequestError(415, 'unsupported_media_type');
  }
  const bytes = await new Promise((resolve, reject) => {
    let length = 0;
    let chunks = [];
    req.on('data', (chunk) => {
      length += chunk.length;
      if (length > BODY_LIMIT) {
        chunks = [];
        reject(new RequestError(413, 'request_too_large'));
      } else chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', () => reject(new RequestError(400, 'invalid_request')));
  });
  let body;
  try { body = JSON.parse(bytes.toString('utf8')); } catch { throw new RequestError(400, 'invalid_request'); }
  if (!body || Array.isArray(body) || typeof body !== 'object') throw new RequestError(400, 'invalid_request');
  return body;
}

// This disposable application is a test endpoint, never a deployed account store.
// The caller supplies generated passwords; this closure retains only salted scrypt hashes.
// Website bearer sessions stay in HTTPS cookies; the store holds token digests and deadlines.
export async function startFixture({ key, cert, accounts, adminToken, sessionMaxMs = MAX_SESSION_MS,
  maxSessions = 128, loginAttemptsPerMinute = 20,
  monotonicNow = () => Number(process.hrtime.bigint() / 1_000_000n), wallNow = Date.now,
  observeLogin = async () => {} }) {
  if (!key || !cert || !/^[a-f0-9]{64}$/.test(adminToken ?? '') || !Number.isInteger(sessionMaxMs)
    || sessionMaxMs <= 0 || sessionMaxMs > MAX_SESSION_MS || !Number.isInteger(maxSessions)
    || maxSessions < 1 || maxSessions > 1000 || !Number.isInteger(loginAttemptsPerMinute)
    || loginAttemptsPerMinute < 1 || loginAttemptsPerMinute > 1000 || !Array.isArray(accounts)
    || accounts.length < 1 || accounts.length > 10 || typeof observeLogin !== 'function') throw new Error('Invalid fixture configuration');
  const users = new Map();
  for (const account of accounts) {
    if (!account || !/^[a-z][a-z0-9-]{0,31}$/.test(account.username ?? '')
      || typeof account.password !== 'string' || account.password.length < 8 || account.password.length > 512
      || typeof account.report !== 'string' || account.report.length > 1024 || users.has(account.username)) {
      throw new Error('Invalid fixture configuration');
    }
    const salt = randomBytes(16);
    users.set(account.username, { salt, hash: scryptSync(account.password, salt, 32), report: account.report });
  }
  const adminDigest = Buffer.from(digest(adminToken), 'hex');
  const dummySalt = randomBytes(16);
  const dummyHash = randomBytes(32);
  const sessions = new Map();
  const references = new Map();
  const revocation = new AccountRevocation([...users.keys()]);
  let attempts = 0;
  let attemptWindow = monotonicNow();
  let origin;

  function alive(record) {
    return monotonicNow() < record.deadline && wallNow() < record.expiresAt;
  }
  function prune() {
    for (const [reference, record] of references) {
      if (!alive(record)) {
        references.delete(reference);
        sessions.delete(record.tokenDigest);
      }
    }
  }
  function sessionFor(req) {
    const values = (req.headers.cookie ?? '').split(';').map((part) => part.trim())
      .filter((part) => part.startsWith(`${SESSION_COOKIE}=`));
    if (values.length !== 1) return undefined;
    const token = values[0].slice(SESSION_COOKIE.length + 1);
    if (!/^[a-f0-9]{64}$/.test(token)) return undefined;
    const session = sessions.get(digest(token));
    return session && !session.revoked && alive(session) ? session : undefined;
  }
  function send(res, code, status, extra = {}) {
    res.writeHead(code, { 'content-type': 'application/json; charset=utf-8', ...extra });
    res.end(code === 204 ? undefined : JSON.stringify(typeof status === 'string' ? { status } : status));
  }
  const server = createServer({ key, cert, minVersion: 'TLSv1.2' }, (req, res) => {
    res.setHeader('cache-control', 'no-store');
    res.setHeader('referrer-policy', 'no-referrer');
    res.setHeader('x-content-type-options', 'nosniff');
    res.setHeader('content-security-policy', "default-src 'none'; script-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
    void handle(req, res).catch((error) => {
      if (!res.headersSent) send(res, error instanceof RequestError ? error.code : 500,
        error instanceof RequestError ? error.status : 'unavailable');
      else res.end();
    });
  });
  server.requestTimeout = 5000;
  server.headersTimeout = 5000;
  server.keepAliveTimeout = 1000;
  server.maxConnections = 64;

  async function handle(req, res) {
    prune();
    const url = new URL(req.url, origin);
    if (req.headers.host !== new URL(origin).host || url.origin !== origin
      || (req.headers.origin !== undefined && req.headers.origin !== origin)) {
      req.resume();
      return send(res, 403, 'forbidden');
    }
    if (url.search) { req.resume(); return send(res, 400, 'invalid_request'); }
    if (url.pathname === '/login' && req.method === 'GET') {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      return res.end(loginPage);
    }
    if (url.pathname === '/login.js' && req.method === 'GET') {
      res.writeHead(200, { 'content-type': 'text/javascript; charset=utf-8' });
      return res.end(loginScript);
    }
    if (url.pathname === '/login' && req.method === 'POST') {
      await observeLogin();
      const now = monotonicNow();
      if (now - attemptWindow >= 60_000) { attempts = 0; attemptWindow = now; }
      if (++attempts > loginAttemptsPerMinute) { req.resume(); return send(res, 429, 'rate_limited'); }
      const body = await readJson(req);
      if (Object.keys(body).sort().join(',') !== 'password,username' || typeof body.username !== 'string'
        || typeof body.password !== 'string' || body.username.length > 32 || body.password.length > 512) {
        return send(res, 400, 'invalid_request');
      }
      const user = users.get(body.username);
      const generation = revocation.begin(body.username);
      const computed = await scrypt(body.password, user?.salt ?? dummySalt, 32);
      const matches = timingSafeEqual(computed, user?.hash ?? dummyHash);
      computed.fill(0);
      if (!matches || !user) return send(res, 401, 'authentication_failed');
      if (!revocation.canCommit(body.username, generation)) return send(res, 409, 'authentication_interrupted');
      prune();
      if (references.size >= maxSessions) return send(res, 503, 'unavailable');
      const token = randomBytes(32).toString('hex');
      const reference = randomBytes(16).toString('hex');
      const record = { account: body.username, reference, tokenDigest: digest(token), deadline: monotonicNow() + sessionMaxMs,
        expiresAt: wallNow() + sessionMaxMs, revoked: false };
      sessions.set(record.tokenDigest, record);
      references.set(reference, record);
      return send(res, 200, { status: 'authenticated', sessionReference: reference,
        account: record.account, expiresAt: record.expiresAt }, {
        'set-cookie': `${SESSION_COOKIE}=${token}; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=${Math.ceil(sessionMaxMs / 1000)}`,
      });
    }
    if (url.pathname.startsWith('/admin/')) {
      if (req.headers.origin !== undefined) { req.resume(); return send(res, 403, 'forbidden'); }
      const supplied = req.headers.authorization?.match(/^Bearer ([a-f0-9]{64})$/)?.[1];
      if (!supplied || !timingSafeEqual(Buffer.from(digest(supplied), 'hex'), adminDigest)) {
        req.resume();
        return send(res, 401, 'unauthorized');
      }
      if (!['/admin/sessions/revoke', '/admin/accounts/revoke', '/admin/accounts/check'].includes(url.pathname) || req.method !== 'POST') {
        req.resume();
        return send(res, 404, 'not_found');
      }
      const body = await readJson(req);
      if (url.pathname === '/admin/accounts/check') {
        if (Object.keys(body).join(',') !== 'account' || !users.has(body.account)) return send(res, 400, 'invalid_request');
        return send(res, 200, { status: 'revocation_ready', account: body.account });
      }
      if (url.pathname === '/admin/accounts/revoke') {
        if (Object.keys(body).join(',') !== 'account' || !users.has(body.account)) return send(res, 400, 'invalid_request');
        revocation.revoke(body.account, sessions, references);
        return send(res, 204);
      }
      if (Object.keys(body).sort().join(',') !== 'account,sessionReference'
        || !users.has(body.account) || !/^[a-f0-9]{32}$/.test(body.sessionReference ?? '')) {
        return send(res, 400, 'invalid_request');
      }
      const record = references.get(body.sessionReference);
      if (record && record.account !== body.account) return send(res, 409, 'binding_mismatch');
      if (record) { record.revoked = true; sessions.delete(record.tokenDigest); }
      return send(res, 204);
    }
    const session = sessionFor(req);
    if (!session) { req.resume(); return send(res, 401, 'unauthorized'); }
    if (url.pathname === '/api/session' && req.method === 'GET') {
      return send(res, 200, { account: session.account, role: 'viewer', expiresAt: session.expiresAt,
        sessionReference: session.reference });
    }
    if (url.pathname === '/reports' && req.method === 'GET') {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      return res.end(`<!doctype html><html lang="en"><meta charset="utf-8"><title>Backup reports</title>
<main><h1>Backup reports</h1><p id="account">${escapeHtml(session.account)}</p>
<p id="report">${escapeHtml(users.get(session.account).report)}</p></main></html>`);
    }
    // Every viewer mutation is denied, including unknown API paths and alternate methods.
    if (url.pathname.startsWith('/api/') || !['GET', 'HEAD'].includes(req.method)) {
      req.resume();
      return send(res, 403, 'forbidden');
    }
    return send(res, 404, 'not_found');
  }

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  origin = `https://127.0.0.1:${server.address().port}`;
  let closed = false;
  return { origin, close: async () => {
    if (closed) return;
    closed = true;
    sessions.clear();
    references.clear();
    server.closeAllConnections();
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  } };
}
