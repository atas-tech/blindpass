// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { createHash, createPublicKey, randomBytes } from 'node:crypto';
import { createServer, request } from 'node:https';
import { test } from 'node:test';
import { chromium } from '@playwright/test';
import { loginPrivate } from '../../helpers/login/src/private-login.mjs';
import { startFixture } from './fixture-app/server.mjs';
import { createTestTls } from './fixture-app/test-tls.mjs';

const pin = (cert) => createHash('sha256').update(createPublicKey(cert).export({ type: 'spki', format: 'der' })).digest('base64');
function trackedLauncher() {
  const events = { launches: 0, contextsClosed: 0, browsersClosed: 0 };
  return { events, launch: async (options) => {
    events.launches++;
    const browser = await chromium.launch(options);
    browser.on('disconnected', () => events.browsersClosed++);
    return { newContext: async (options) => {
      const context = await browser.newContext(options);
      context.on('close', () => events.contextsClosed++);
      return context;
    }, close: () => browser.close() };
  } };
}

test('B-I01–B-I03 / P05-I06 private helper actual Chromium: password stays private, allow-listed cookie works in a fresh context, source context destroyed',
  { timeout: 30_000 }, async (t) => {
    const tls = await createTestTls();
    t.after(() => tls.close());
    const password = `P05-PRIVATE-PASSWORD-CANARY-${randomBytes(24).toString('hex')}`;
    const adminToken = randomBytes(32).toString('hex');
    const app = await startFixture({ ...tls, adminToken, sessionMaxMs: 300_000, accounts: [
      { username: 'primary', password, report: 'Primary backup report: 12 artifacts' },
      { username: 'isolation', password: randomBytes(24).toString('hex'), report: 'Isolation backup report' },
    ] });
    t.after(() => app.close());
    const recipe = { kind: 'fixture', origin: app.origin, account: 'primary', sessionMaxMs: 300_000,
      certificateSpkiPins: [pin(tls.cert)] };
    const tracked = trackedLauncher();
    const result = await loginPrivate(recipe, { account: 'primary', password }, { launch: tracked.launch, env: {} });
    assert.equal(result.status, 'authenticated');
    assert.deepEqual(tracked.events, { launches: 1, contextsClosed: 1, browsersClosed: 1 });
    assert.ok(!JSON.stringify(result).includes(password), 'protected response has no source password');
    assert.equal(result.cookies.length, 1);
    assert.equal(result.cookies[0].name, '__Host-bp-fixture');
    assert.equal(result.revokeHandle.account, 'primary');
    assert.ok(result.originalDeadlineMs <= Date.now() + 300_000);
    let stage = 'fresh-context';
    try {
      const browser = await chromium.launch({ chromiumSandbox: true, args: [`--ignore-certificate-errors-spki-list=${pin(tls.cert)}`] });
      t.after(() => browser.close());
      const context = await browser.newContext();
      await context.addCookies(result.cookies);
      const page = await context.newPage();
      stage = 'report';
      assert.equal((await page.goto(`${app.origin}/reports`)).status(), 200);
      assert.equal(await page.locator('#report').textContent(), 'Primary backup report: 12 artifacts');
      assert.ok(!(await page.content()).includes(password));
      stage = 'revoke';
      const status = await new Promise((resolve, reject) => {
        const req = request(`${app.origin}/admin/sessions/revoke`, { method: 'POST', ca: tls.ca,
          headers: { authorization: `Bearer ${adminToken}`, 'content-type': 'application/json' } }, (res) => {
          res.resume(); res.on('end', () => resolve(res.statusCode));
        });
        req.on('error', () => reject(new Error('Private helper revoke test failed')));
        req.end(JSON.stringify({ account: result.revokeHandle.account, sessionReference: result.revokeHandle.sessionReference }));
      });
      assert.equal(status, 204);
      assert.equal((await page.reload()).status(), 401);
    } catch { throw new Error(`Private helper browser check failed during ${stage}`); }
    const denied = await loginPrivate(recipe, { account: 'primary', password: 'wrong-generated-password' }, { launch: tracked.launch, env: {} });
    assert.deepEqual(denied, { status: 'authentication_failed' });
    assert.deepEqual(tracked.events, { launches: 2, contextsClosed: 2, browsersClosed: 2 });
    const tlsDenied = await loginPrivate({ ...recipe, certificateSpkiPins: [] }, { account: 'primary', password }, { launch: tracked.launch, env: {} });
    assert.deepEqual(tlsDenied, { status: 'login_failed' });
    assert.deepEqual(tracked.events, { launches: 3, contextsClosed: 3, browsersClosed: 3 });
  });

test('B-I03 private helper refuses a redirect to an unapproved credential origin before sending any password', { timeout: 20_000 }, async (t) => {
  const tls = await createTestTls();
  t.after(() => tls.close());
  let unapprovedRequests = 0;
  const other = createServer(tls, (_req, res) => { unapprovedRequests++; res.end('Unapproved login'); });
  await new Promise((resolve) => other.listen(0, '127.0.0.1', resolve));
  t.after(async () => { other.closeAllConnections(); await new Promise((resolve) => other.close(resolve)); });
  const redirect = `https://127.0.0.1:${other.address().port}/login`;
  const app = createServer(tls, (_req, res) => { res.writeHead(302, { location: redirect }); res.end(); });
  await new Promise((resolve) => app.listen(0, '127.0.0.1', resolve));
  t.after(async () => { app.closeAllConnections(); await new Promise((resolve) => app.close(resolve)); });
  const tracked = trackedLauncher();
  const result = await loginPrivate({ kind: 'fixture', origin: `https://127.0.0.1:${app.address().port}`,
    account: 'primary', sessionMaxMs: 300_000, certificateSpkiPins: [pin(tls.cert)] },
  { account: 'primary', password: 'P05-PRIVATE-PASSWORD-CANARY' }, { launch: tracked.launch, env: {} });
  assert.equal(unapprovedRequests, 0, 'no redirected request reaches an unapproved origin');
  assert.deepEqual(result, { status: 'login_failed' });
  assert.deepEqual(tracked.events, { launches: 1, contextsClosed: 1, browsersClosed: 1 });
});
