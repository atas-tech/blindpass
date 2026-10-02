// SPDX-License-Identifier: AGPL-3.0-only
// SPKI pin semantics. Chromium's --ignore-certificate-errors-spki-list ADDS trust
// (a pin match accepts hostname/expiry/chain errors). The helper therefore verifies the
// served leaf (pin + hostname + validity) before any credential is typed.
import assert from 'node:assert/strict';
import { createHash, createPublicKey } from 'node:crypto';
import { createServer } from 'node:https';
import { test } from 'node:test';
import { chromium } from 'playwright';
import { loginPrivate } from '../../helpers/login/src/private-login.mjs';
import { startFixture } from './fixture-app/server.mjs';
import { createTestTls } from './fixture-app/test-tls.mjs';

const pin = (cert) => createHash('sha256').update(createPublicKey(cert).export({ type: 'spki', format: 'der' })).digest('base64');
const password = 'P05-PIN-PASSWORD-CANARY-0123456789';

// Optionally widens what Chromium itself accepts (as if its trust store accepted the
// certificate) without changing the recipe's configured pins.
function launcher(alsoAccept = []) {
  const events = { launches: 0, closed: 0 };
  return { events, launch: async (options) => {
    events.launches++;
    const args = options.args.map((arg) => arg.startsWith('--ignore-certificate-errors-spki-list=')
      ? `${arg},${alsoAccept.join(',')}` : arg);
    const browser = await chromium.launch({ ...options, args });
    browser.on('disconnected', () => events.closed++);
    return browser;
  } };
}

// A login page that reports the first typed character, so "before any credential is typed" is observable.
async function loginServer(t, tls) {
  const counts = { requests: 0, typed: 0, posts: 0, bodies: [] };
  const server = createServer(tls, (req, res) => {
    counts.requests++;
    if (req.url === '/typed') { counts.typed++; req.resume(); res.writeHead(204); res.end(); return; }
    if (req.method === 'POST') {
      counts.posts++; let body = ''; req.on('data', (bytes) => { body += bytes; });
      req.on('end', () => { counts.bodies.push(body.length); res.writeHead(401, { 'content-type': 'application/json' }); res.end('{}'); });
      return;
    }
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end(`<!doctype html><title>Sign in</title><label>Username <input id="u" name="username"></label>
<label>Password <input id="p" name="password" type="password"></label><button>Sign in</button>
<script>for (const id of ['u', 'p']) document.getElementById(id).addEventListener('input', () => navigator.sendBeacon('/typed'));
document.querySelector('button').addEventListener('click', () => fetch('/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' }));</script>`);
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => { server.closeAllConnections(); await new Promise((resolve) => server.close(resolve)); });
  return { counts, origin: `https://127.0.0.1:${server.address().port}` };
}
const recipe = (origin, pins) => ({ kind: 'fixture', origin, account: 'primary', sessionMaxMs: 300_000, certificateSpkiPins: pins });
const attempt = (origin, pins, tracked) => loginPrivate(recipe(origin, pins), { account: 'primary', password }, { launch: tracked.launch, env: {} });

test('P05-H matching pin with a valid certificate passes the check and reaches credential entry', { timeout: 30_000 }, async (t) => {
  const tls = await createTestTls(); t.after(() => tls.close());
  const server = await loginServer(t, tls); const tracked = launcher();
  // The page answers 401, so reaching authentication_failed proves typing and submit were allowed.
  assert.deepEqual(await attempt(server.origin, [pin(tls.cert)], tracked), { status: 'authentication_failed' });
  assert.ok(server.counts.typed > 0); assert.equal(server.counts.posts, 1);
  assert.equal(tracked.events.closed, 1);
});

test('P05-H full login still succeeds on the real fixture app with the pin check enabled', { timeout: 30_000 }, async (t) => {
  const tls = await createTestTls(); t.after(() => tls.close());
  const app = await startFixture({ ...tls, adminToken: 'a'.repeat(64), sessionMaxMs: 300_000,
    accounts: [{ username: 'primary', password, report: 'Pinned report' }] });
  t.after(() => app.close());
  const result = await attempt(app.origin, [pin(tls.cert)], launcher());
  assert.equal(result.status, 'authenticated'); assert.equal(result.cookies.length, 1);
  assert.ok(!JSON.stringify(result).includes(password));
});

test('P05-H a certificate Chromium accepted but whose key is not a configured pin fails before any credential is typed', { timeout: 30_000 }, async (t) => {
  const served = await createTestTls(); const other = await createTestTls();
  t.after(() => Promise.all([served.close(), other.close()]));
  const server = await loginServer(t, served);
  // Chromium accepts the served certificate (as if trusted); the recipe pins a different key.
  const tracked = launcher([pin(served.cert)]);
  assert.deepEqual(await attempt(server.origin, [pin(other.cert)], tracked), { status: 'login_failed' });
  assert.equal(server.counts.typed, 0); assert.equal(server.counts.posts, 0);
  assert.equal(tracked.events.closed, 1);
});

test('P05-H a pin that matches the served key is not enough when the certificate is expired', { timeout: 30_000 }, async (t) => {
  const tls = await createTestTls({ expired: true }); t.after(() => tls.close());
  const server = await loginServer(t, tls); const tracked = launcher();
  assert.deepEqual(await attempt(server.origin, [pin(tls.cert)], tracked), { status: 'login_failed' });
  assert.ok(server.counts.requests > 0, 'Chromium really accepted the expired certificate through the pin flag');
  assert.equal(server.counts.typed, 0); assert.equal(server.counts.posts, 0);
});

test('P05-H a pin that matches the served key is not enough when the certificate names another host', { timeout: 30_000 }, async (t) => {
  const tls = await createTestTls({ dnsNames: ['other.example.test'], ipAddresses: [] }); t.after(() => tls.close());
  const server = await loginServer(t, tls); const tracked = launcher();
  assert.deepEqual(await attempt(server.origin, [pin(tls.cert)], tracked), { status: 'login_failed' });
  assert.ok(server.counts.requests > 0, 'Chromium really accepted the wrong-host certificate through the pin flag');
  assert.equal(server.counts.typed, 0); assert.equal(server.counts.posts, 0);
});

test('P05-H without pins nothing is added: Chromium rejects an untrusted private certificate itself', { timeout: 30_000 }, async (t) => {
  const tls = await createTestTls(); t.after(() => tls.close());
  const server = await loginServer(t, tls);
  assert.deepEqual(await attempt(server.origin, [], launcher()), { status: 'login_failed' });
  assert.equal(server.counts.requests, 0);
});
