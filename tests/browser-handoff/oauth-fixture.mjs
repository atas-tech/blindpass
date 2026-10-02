// SPDX-License-Identifier: AGPL-3.0-only
import { createHash, randomBytes, scrypt as scryptCallback, scryptSync, timingSafeEqual } from 'node:crypto';
import { createServer } from 'node:https';
import { promisify } from 'node:util';

const scrypt = promisify(scryptCallback);
const digest = (value) => createHash('sha256').update(value).digest('hex');
const html = (value) => value.replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]);

// Disposable, single-client OAuth authorization-code test issuer. It has no refresh
// token, self-service account management, hosted service or reusable browser session.
export async function startOAuthFixture({ key, cert, accounts, clientId, clientSecret, redirectUri, observeLogin }) {
  let callback;
  try { callback = new URL(redirectUri()); } catch { throw new Error('Invalid OAuth fixture configuration'); }
  if (!key || !cert || callback.protocol !== 'https:' || !['127.0.0.1', 'localhost'].includes(callback.hostname)
    || callback.username || callback.password || callback.search || callback.hash
    || typeof clientId !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(clientId)
    || typeof clientSecret !== 'string' || clientSecret.length < 32 || clientSecret.length > 256
    || !Array.isArray(accounts) || accounts.length < 1 || accounts.length > 2
    || observeLogin !== undefined && typeof observeLogin !== 'function') {
    throw new Error('Invalid OAuth fixture configuration');
  }
  const approvedRedirect = callback.href;
  const users = new Map();
  for (const account of accounts) {
    if (!account || !['primary', 'isolation'].includes(account.username) || users.has(account.username)
      || typeof account.password !== 'string' || account.password.length < 8 || account.password.length > 512) {
      throw new Error('Invalid OAuth fixture configuration');
    }
    const salt = randomBytes(16);
    users.set(account.username, { salt, hash: scryptSync(account.password, salt, 32),
      profile: { sub: `p05-${account.username}`, id: `p05-${account.username}`, login: account.username,
        name: `P05 ${account.username}`, email: `${account.username}@example.invalid`,
        email_verified: true, role: 'Viewer', organizations: [account.username] } });
  }
  const pending = new Map();
  const codes = new Map();
  const tokens = new Map();
  const metrics = { authorizations: 0, credentialAccepts: 0, codeRedeems: 0, userInfos: 0, clientDenials: 0, grantDenials: 0 };
  const clientDigest = Buffer.from(digest(clientSecret), 'hex');
  const dummySalt = randomBytes(16);
  const dummyHash = randomBytes(32);
  let origin;
  let closed = false;
  let attempts = 0;
  let windowStart = performance.now();
  function send(res, code, body) {
    res.writeHead(code, { 'content-type': 'application/json', 'cache-control': 'no-store' });
    res.end(JSON.stringify(body));
  }
  async function form(req) {
    if (req.headers['content-type']?.split(';')[0] !== 'application/x-www-form-urlencoded') return undefined;
    const text = await new Promise((resolve, reject) => {
      let value = '';
      let size = 0;
      req.on('data', (chunk) => {
        size += chunk.length;
        if (size > 4096) { value = ''; reject(new Error('OAuth body too large')); }
        else value += chunk.toString('utf8');
      });
      req.on('end', () => resolve(value));
      req.on('error', () => reject(new Error('OAuth body unavailable')));
    });
    const body = new URLSearchParams(text);
    for (const name of new Set(body.keys())) if (body.getAll(name).length !== 1) return undefined;
    return body;
  }
  function prune(map) {
    for (const [key, value] of map) if (performance.now() >= value.deadline) map.delete(key);
  }
  const server = createServer({ key, cert, minVersion: 'TLSv1.2' }, (req, res) => {
    res.setHeader('cache-control', 'no-store');
    res.setHeader('referrer-policy', 'no-referrer');
    res.setHeader('content-security-policy', "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
    void handle(req, res).catch(() => {
      if (!res.headersSent) send(res, 400, { error: 'invalid_request' });
      else res.end();
    });
  });
  server.requestTimeout = 5000;
  server.headersTimeout = 5000;
  server.maxConnections = 32;
  async function handle(req, res) {
    const url = new URL(req.url, origin);
    if (req.headers.host !== new URL(origin).host || url.origin !== origin
      || req.headers.origin !== undefined && req.headers.origin !== origin) {
      req.resume();
      return send(res, 403, { error: 'forbidden' });
    }
    for (const map of [pending, codes, tokens]) prune(map);
    if (pending.size + codes.size + tokens.size >= 128) { req.resume(); return send(res, 503, { error: 'unavailable' }); }
    if (url.pathname === '/authorize' && req.method === 'GET') {
      const query = url.searchParams;
      for (const name of new Set(query.keys())) {
        if (query.getAll(name).length !== 1) return send(res, 400, { error: 'invalid_request' });
      }
      if (query.get('client_id') !== clientId || query.get('response_type') !== 'code'
        || query.get('redirect_uri') !== approvedRedirect || query.get('code_challenge_method') !== 'S256'
        || !/^[A-Za-z0-9_-]{43}$/.test(query.get('code_challenge') ?? '')
        || !query.get('state') || query.get('state').length > 512) {
        return send(res, 400, { error: 'invalid_request' });
      }
      const ticket = randomBytes(32).toString('hex');
      metrics.authorizations++;
      pending.set(digest(ticket), { state: query.get('state'), redirect: query.get('redirect_uri'),
        challenge: query.get('code_challenge'), deadline: performance.now() + 60_000 });
      // Origin-only referrers keep OAuth query state out of navigation headers while
      // letting the native same-origin form POST carry its verifiable Origin.
      res.setHeader('referrer-policy', 'origin');
      // Chromium applies form-action to the POST's redirect as well. Allow only
      // this client's exact approved callback origin; a wildcard would weaken it.
      res.setHeader('content-security-policy', `default-src 'none'; form-action 'self' ${new URL(query.get('redirect_uri')).origin}; frame-ancestors 'none'; base-uri 'none'`);
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      return res.end(`<!doctype html><html lang="en"><meta charset="utf-8"><title>Managed account sign in</title>
<main><h1>Managed account sign in</h1><form method="post" action="/authorize">
<input type="hidden" name="ticket" value="${html(ticket)}">
<label>Username <input name="username" autocomplete="off" required></label>
<label>Password <input name="password" type="password" autocomplete="off" required></label><button>Sign in</button></form></main></html>`);
    }
    if (url.pathname === '/authorize' && req.method === 'POST' && !url.search) {
      if (performance.now() - windowStart >= 60_000) { attempts = 0; windowStart = performance.now(); }
      if (++attempts > 20) { req.resume(); return send(res, 429, { error: 'rate_limited' }); }
      const body = await form(req);
      const record = body && pending.get(digest(body.get('ticket') ?? ''));
      const username = body?.get('username');
      const password = body?.get('password');
      if (!record || typeof username !== 'string' || username.length > 32
        || typeof password !== 'string' || password.length > 512) return send(res, 400, { error: 'invalid_request' });
      pending.delete(digest(body.get('ticket')));
      const user = users.get(username);
      const computed = await scrypt(password, user?.salt ?? dummySalt, 32);
      const matches = timingSafeEqual(computed, user?.hash ?? dummyHash);
      computed.fill(0);
      if (!user || !matches) return send(res, 401, { error: 'access_denied' });
      metrics.credentialAccepts++;
      // Trusted test observation receives no password, code or session. Hold
      // before issuing a code so the integrated private login remains pending.
      await observeLogin?.();
      const code = randomBytes(32).toString('hex');
      codes.set(digest(code), { ...record, username, deadline: performance.now() + 30_000 });
      const callback = new URL(record.redirect);
      callback.searchParams.set('code', code);
      callback.searchParams.set('state', record.state);
      res.writeHead(303, { location: callback.href });
      return res.end();
    }
    if (url.pathname === '/token' && req.method === 'POST' && !url.search) {
      const body = await form(req);
      let id = body?.get('client_id');
      let secret = body?.get('client_secret');
      if (req.headers.authorization?.startsWith('Basic ')) {
        const basic = Buffer.from(req.headers.authorization.slice(6), 'base64').toString('utf8');
        const separator = basic.indexOf(':');
        id = decodeURIComponent(basic.slice(0, separator));
        secret = decodeURIComponent(basic.slice(separator + 1));
      }
      if (id !== clientId || !secret || !timingSafeEqual(Buffer.from(digest(secret), 'hex'), clientDigest)) {
        metrics.clientDenials++;
        return send(res, 401, { error: 'invalid_client' });
      }
      const code = body?.get('code');
      const record = code && codes.get(digest(code));
      if (!record || body.get('grant_type') !== 'authorization_code'
        || body.get('redirect_uri') !== record.redirect
        || !/^[A-Za-z0-9._~-]{43,128}$/.test(body.get('code_verifier') ?? '')
        || createHash('sha256').update(body.get('code_verifier')).digest('base64url') !== record.challenge) {
        metrics.grantDenials++;
        return send(res, 400, { error: 'invalid_grant' });
      }
      codes.delete(digest(code));
      metrics.codeRedeems++;
      const token = randomBytes(32).toString('hex');
      // A 10m read-only identity token lets the independent 5m website session
      // maximum expire first. Authorization codes remain one-use with a 30s TTL.
      tokens.set(digest(token), { username: record.username, deadline: performance.now() + 600_000 });
      return send(res, 200, { access_token: token, token_type: 'Bearer', expires_in: 600 });
    }
    if (url.pathname === '/userinfo' && req.method === 'GET' && !url.search) {
      const token = req.headers.authorization?.match(/^Bearer ([a-f0-9]{64})$/)?.[1];
      const record = token && tokens.get(digest(token));
      if (!record) return send(res, 401, { error: 'invalid_token' });
      metrics.userInfos++;
      return send(res, 200, users.get(record.username).profile);
    }
    req.resume();
    return send(res, 404, { error: 'not_found' });
  }
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  origin = `https://localhost:${server.address().port}`;
  return { origin, metrics: () => ({ ...metrics }), close: async () => {
    if (closed) return;
    closed = true;
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
    pending.clear(); codes.clear(); tokens.clear();
    for (const user of users.values()) user.hash.fill(0);
    users.clear();
  } };
}
