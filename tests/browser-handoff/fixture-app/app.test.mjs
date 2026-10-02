// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { request } from 'node:https';
import { after, before, test } from 'node:test';
import { setTimeout } from 'node:timers/promises';
import { startFixture, SESSION_COOKIE } from './server.mjs';
import { createTestTls } from './test-tls.mjs';

let tls;
before(async () => { tls = await createTestTls(); });
after(async () => { await tls?.close(); });

async function fixture(t, options = {}) {
  const passwords = [0, 1].map(() => `P05-PASSWORD-CANARY-${randomBytes(24).toString('hex')}`);
  const adminToken = randomBytes(32).toString('hex');
  const app = await startFixture({ ...tls, adminToken, accounts: [
    { username: 'primary', password: passwords[0], report: 'Primary backup report: 12 artifacts' },
    { username: 'isolation', password: passwords[1], report: 'Isolation backup report: 3 artifacts' },
  ], ...options });
  t.after(() => app.close());
  function send(path, { method = 'GET', cookie, body, authorization, origin, ca = tls.ca,
    contentType = 'application/json', headers = {} } = {}) {
    return new Promise((resolve, reject) => {
      const req = request(`${app.origin}${path}`, { method, ca, servername: 'localhost', headers: {
        ...(cookie ? { cookie } : {}), ...(body !== undefined ? { 'content-type': contentType } : {}),
        ...(authorization ? { authorization } : {}), ...(origin ? { origin } : {}), ...headers,
      } }, (res) => {
        let text = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => { text += chunk; });
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, text,
          json: text && res.headers['content-type']?.startsWith('application/json') ? JSON.parse(text) : null }));
      });
      req.on('error', (error) => reject(Object.assign(new Error('Fixture transport failed'), { code: error.code })));
      req.end(body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body));
    });
  }
  async function login(username = 'primary', password = passwords[username === 'primary' ? 0 : 1]) {
    const response = await send('/login', { method: 'POST', body: { username, password } });
    assert.equal(response.status, 200, 'fixture login must succeed');
    const cookie = response.headers['set-cookie']?.[0];
    assert.ok(cookie, 'login must set a session cookie');
    return { ...response.json, cookie: cookie.split(';')[0], attributes: cookie.slice(cookie.indexOf(';')) };
  }
  return { ...app, send, login, adminToken, passwords };
}

test('P05-I01 / B-I13: HTTPS, private cookie, report task and no durable action UI', async (t) => {
  const app = await fixture(t);
  assert.equal((await app.send('/reports')).status, 401);
  await assert.rejects(app.send('/login', { ca: null }), { code: 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' });
  const session = await app.login();
  for (const attribute of ['Secure', 'HttpOnly', 'SameSite=Strict', 'Path=/']) {
    assert.ok(session.attributes.includes(attribute), `session cookie requires ${attribute}`);
  }
  assert.ok(!session.attributes.includes('Domain='), 'host-only cookie');
  assert.ok(session.cookie.startsWith(`${SESSION_COOKIE}=`), 'expected cookie name');
  const reports = await app.send('/reports', { cookie: session.cookie });
  assert.equal(reports.status, 200);
  assert.ok(reports.text.includes('Primary backup report: 12 artifacts'));
  assert.ok(!/password|token|recovery|authenticator|integration/i.test(reports.text), 'report UI exposes no credential changes');
  const metadata = await app.send('/api/session', { cookie: session.cookie });
  assert.equal(metadata.json.account, 'primary');
  assert.equal(metadata.json.role, 'viewer');
  assert.ok(!metadata.headers['set-cookie'], 'reading a session never renews it');
});

test('P05-I01: viewer direct requests cannot change account or mint authority', async (t) => {
  const app = await fixture(t);
  const session = await app.login();
  for (const path of ['/api/password', '/api/tokens', '/api/recovery', '/api/authenticators',
    '/api/integrations', '/api/account', '/api/admin/users']) {
    for (const method of ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']) {
      const result = await app.send(path, { method, cookie: session.cookie, body: { value: 'dummy' } });
      assert.equal(result.status, 403, `${method} ${path} must be forbidden`);
      assert.equal(result.json.status, 'forbidden');
    }
  }
});

test('P05-I01 / B-E16 / B-I13: ongoing activity and altered cookie attributes cannot extend lifetime', async (t) => {
  const app = await fixture(t, { sessionMaxMs: 240 });
  const session = await app.login();
  for (let i = 0; i < 3; i++) {
    await setTimeout(40);
    assert.equal((await app.send('/api/session', { cookie: session.cookie })).status, 200);
  }
  await setTimeout(160);
  const replay = await app.send('/reports', { cookie: `${session.cookie}; Max-Age=999999999` });
  assert.equal(replay.status, 401, 'server enforces original absolute deadline');
});

test('P05-I01 / B-I13: wall-clock rollback and activity do not reset monotonic deadline', async (t) => {
  let elapsed = 0;
  let wall = 1_000_000;
  const app = await fixture(t, { sessionMaxMs: 500, monotonicNow: () => elapsed, wallNow: () => wall });
  const session = await app.login();
  elapsed = 499;
  wall -= 50_000;
  const active = await app.send('/api/session', { cookie: session.cookie });
  assert.equal(active.status, 200);
  assert.equal(active.json.expiresAt, session.expiresAt);
  elapsed = 500;
  assert.equal((await app.send('/reports', { cookie: session.cookie })).status, 401);
});

test('P05-I01 / B-I13: wall deadline expires authority while monotonic clock is paused', async (t) => {
  let wall = 1_000_000;
  const app = await fixture(t, { sessionMaxMs: 500, monotonicNow: () => 0, wallNow: () => wall });
  const session = await app.login();
  wall += 500;
  assert.equal((await app.send('/reports', { cookie: session.cookie })).status, 401);
});

test('P05-I01 / B-E16: copied session works before revoke and fails after idempotent admin revoke', async (t) => {
  const app = await fixture(t);
  const session = await app.login();
  assert.equal((await app.send('/reports', { cookie: session.cookie })).status, 200);
  const body = { account: 'primary', sessionReference: session.sessionReference };
  for (const authorization of [undefined, 'Bearer dummy']) {
    assert.equal((await app.send('/admin/sessions/revoke', { method: 'POST', body, authorization })).status, 401);
  }
  assert.equal((await app.send('/admin/sessions/revoke', { method: 'POST', body,
    cookie: session.cookie })).status, 401, 'viewer cookie never authorizes revoke administration');
  for (let i = 0; i < 2; i++) {
    const revoke = await app.send('/admin/sessions/revoke', { method: 'POST', body,
      authorization: `Bearer ${app.adminToken}` });
    assert.equal(revoke.status, 204);
  }
  assert.equal((await app.send('/reports', { cookie: session.cookie })).status, 401);
});

test('P05-I01 / B-E02: isolation account sees its own report and cannot substitute session/account', async (t) => {
  const app = await fixture(t);
  const primary = await app.login();
  const isolation = await app.login('isolation');
  const report = await app.send('/reports', { cookie: isolation.cookie });
  assert.ok(report.text.includes('Isolation backup report: 3 artifacts'));
  assert.ok(!report.text.includes('Primary backup report'));
  assert.equal((await app.send('/admin/sessions/revoke', { method: 'POST',
    authorization: `Bearer ${app.adminToken}`,
    body: { account: 'isolation', sessionReference: primary.sessionReference } })).status, 409);
  assert.equal((await app.send('/api/session', { cookie: primary.cookie })).json.account, 'primary');
  assert.equal((await app.send('/reports', { cookie: `${primary.cookie}; ${isolation.cookie}` })).status, 401);
  assert.equal((await app.send('/reports', { cookie: `${SESSION_COOKIE}=unknown` })).status, 401);
});

test('P05-I03 lost reply: root admin revokes all account sessions without the private login handle', async (t) => {
  const app = await fixture(t);
  const first = await app.login(); const lost = await app.login(); const isolation = await app.login('isolation');
  const path = '/admin/accounts/revoke'; const body = { account: 'primary' };
  assert.equal((await app.send(path, { method: 'POST', body, cookie: first.cookie })).status, 401);
  assert.equal((await app.send(path, { method: 'POST', body, origin: app.origin,
    authorization: `Bearer ${app.adminToken}` })).status, 403);
  for (const invalid of [{}, { account: 'unknown' }, { account: 'primary', sessionReference: first.sessionReference }]) {
    assert.equal((await app.send(path, { method: 'POST', body: invalid,
      authorization: `Bearer ${app.adminToken}` })).status, 400);
  }
  for (let repeat = 0; repeat < 2; repeat++) assert.equal((await app.send(path, { method: 'POST', body,
    authorization: `Bearer ${app.adminToken}` })).status, 204);
  for (const session of [first, lost]) assert.equal((await app.send('/reports', { cookie: session.cookie })).status, 401);
  assert.equal((await app.send('/reports', { cookie: isolation.cookie })).status, 200);
});

test('P05-I06 fixture portion: invalid authentication and malformed/oversized bodies have fixed safe results', async (t) => {
  const app = await fixture(t);
  for (const username of ['primary', 'does-not-exist']) {
    const result = await app.send('/login', { method: 'POST', body: { username, password: 'wrong-canary' } });
    assert.equal(result.status, 401);
    assert.deepEqual(result.json, { status: 'authentication_failed' });
  }
  for (const body of ['{', 'null', '[]', '{"password":"dummy"}']) {
    const result = await app.send('/login', { method: 'POST', body });
    assert.equal(result.status, 400);
    assert.deepEqual(result.json, { status: 'invalid_request' });
  }
  assert.equal((await app.send('/login', { method: 'POST', body: 'x'.repeat(5000) })).status, 413);
  const result = await app.send('/login', { method: 'POST', body: { username: 'primary', password: app.passwords[0] } });
  for (const canary of app.passwords) assert.ok(!result.text.includes(canary), 'response must not include source password');
  assert.equal(result.headers['cache-control'], 'no-store');
  assert.equal(result.headers['referrer-policy'], 'no-referrer');
  assert.ok(result.headers['content-security-policy'].includes("default-src 'none'"));
});

test('P05-I01: origin/host, content type and admin browser requests fail closed', async (t) => {
  const app = await fixture(t);
  const body = { username: 'primary', password: app.passwords[0] };
  assert.equal((await app.send('/login', { method: 'POST', body, origin: 'https://wrong.example' })).status, 403);
  assert.equal((await app.send('/login', { method: 'POST', body, headers: { host: 'wrong.example' } })).status, 403);
  assert.equal((await app.send('/login', { method: 'POST', body, contentType: 'text/plain' })).status, 415);
  assert.equal((await app.send('/admin/sessions/revoke', { method: 'POST', body: {},
    origin: app.origin, authorization: `Bearer ${app.adminToken}` })).status, 403);
  assert.equal((await app.send('/login?password=dummy')).status, 400, 'no secret-bearing query interface');
});

test('P05-I01: bounded sessions and login attempts reject further issuance', async (t) => {
  const app = await fixture(t, { maxSessions: 1, loginAttemptsPerMinute: 3 });
  await app.login();
  assert.equal((await app.send('/login', { method: 'POST', body: {
    username: 'isolation', password: app.passwords[1] } })).status, 503);
  for (let i = 0; i < 2; i++) await app.send('/login', { method: 'POST', body: { username: 'unknown', password: 'dummy' } });
  assert.equal((await app.send('/login', { method: 'POST', body: {
    username: 'primary', password: app.passwords[0] } })).status, 429);
});

test('P05-I01: restart invalidates every old session', async (t) => {
  const first = await fixture(t);
  const session = await first.login();
  await first.close();
  const next = await fixture(t);
  assert.equal((await next.send('/reports', { cookie: session.cookie })).status, 401);
});

test('P05-D1: invalid configuration is rejected instead of relaxing session limits', async () => {
  const base = { ...tls, adminToken: randomBytes(32).toString('hex'), accounts: [
    { username: 'primary', password: 'generated-dummy', report: 'dummy report' },
  ] };
  for (const sessionMaxMs of [0, -1, 1_800_001, Infinity, NaN]) {
    await assert.rejects(startFixture({ ...base, sessionMaxMs }), /Invalid fixture configuration/);
  }
  await assert.rejects(startFixture({ ...base, adminToken: 'short' }), /Invalid fixture configuration/);
  await assert.rejects(startFixture({ ...base, accounts: [...base.accounts, ...base.accounts] }), /Invalid fixture configuration/);
});
