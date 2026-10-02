// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { createHash, createPublicKey, randomBytes } from 'node:crypto';
import { request } from 'node:https';
import { test } from 'node:test';
import { chromium } from '@playwright/test';
import { startFixture, SESSION_COOKIE } from './server.mjs';
import { createTestTls } from './test-tls.mjs';

test('P05-I01 fixture UI: real Chromium sign-in, read-only report, mutation denial and revoked-cookie replay',
  { timeout: 30_000 }, async (t) => {
    let stage = 'setup';
    const tls = await createTestTls();
    t.after(() => tls.close());
    const password = `P05-BROWSER-PASSWORD-CANARY-${randomBytes(24).toString('hex')}`;
    const adminToken = randomBytes(32).toString('hex');
    const app = await startFixture({ ...tls, adminToken, accounts: [
      { username: 'primary', password, report: 'Primary backup report: 12 artifacts' },
      { username: 'isolation', password: randomBytes(24).toString('hex'), report: 'Isolation backup report: 3 artifacts' },
    ] });
    t.after(() => app.close());
    try {
      // Trust only this generated certificate key in this disposable browser. The HTTP suite
      // independently checks the CA chain and rejection without trust; this is not host CA setup.
      const spki = createHash('sha256').update(createPublicKey(tls.cert)
        .export({ type: 'spki', format: 'der' })).digest('base64');
      const browser = await chromium.launch({ chromiumSandbox: true,
        args: [`--ignore-certificate-errors-spki-list=${spki}`] });
      t.after(() => browser.close());
      const context = await browser.newContext();
      const page = await context.newPage();
      stage = 'login-navigation';
      await page.goto(`${app.origin}/login`);
      stage = 'login-fields';
      await page.getByLabel('Username').fill('primary');
      await page.getByLabel('Password').fill(password);
      const loginReply = page.waitForResponse((res) => res.url() === `${app.origin}/login` && res.request().method() === 'POST');
      stage = 'login-submit';
      await page.getByRole('button', { name: 'Sign in' }).click();
      const reply = await loginReply;
      stage = `login-status-${reply.status()}`;
      assert.equal(reply.status(), 200, 'UI login status');
      stage = 'report-navigation';
      await page.waitForURL(`${app.origin}/reports`);
      stage = 'session-metadata';
      const { sessionReference } = await page.evaluate(async () => (await fetch('/api/session')).json());
      stage = 'reports';
      assert.equal(await page.locator('#report').textContent(), 'Primary backup report: 12 artifacts');
      assert.equal(await page.locator('input, form, button, a').count(), 0, 'no account-management UI');
      assert.ok(!(await page.content()).includes(password), 'source password absent from report DOM');
      const cookies = await context.cookies();
      assert.equal(cookies.length, 1, 'only the approved session cookie exists');
      assert.equal(cookies[0].name, SESSION_COOKIE);
      assert.ok(cookies[0].secure && cookies[0].httpOnly, 'private session attributes');
      stage = 'durable-action-denial';
      for (const path of ['/api/password', '/api/tokens', '/api/recovery', '/api/authenticators', '/api/integrations']) {
        const status = await page.evaluate(async (path) => (await fetch(path, {
          method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}',
        })).status, path);
        assert.equal(status, 403, 'viewer cannot change or mint credentials');
      }
      stage = 'revoke';
      const status = await new Promise((resolve, reject) => {
        const req = request(`${app.origin}/admin/sessions/revoke`, {
          method: 'POST', ca: tls.ca, headers: { authorization: `Bearer ${adminToken}`, 'content-type': 'application/json' },
        }, (res) => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
        req.on('error', () => reject(new Error('Fixture revocation transport failed')));
        req.end(JSON.stringify({ account: 'primary', sessionReference }));
      });
      assert.equal(status, 204, 'admin confirms revocation');
      stage = 'copied-cookie-replay';
      const replay = await browser.newContext();
      await replay.addCookies(cookies);
      const replayPage = await replay.newPage();
      assert.equal((await replayPage.goto(`${app.origin}/reports`)).status(), 401, 'copied cookie denied');
      assert.equal((await page.reload()).status(), 401, 'original browser denied');
      t.diagnostic(`Chromium ${browser.version()}; fixture UI and replay assertions passed; no capture artifacts`);
    } catch (error) {
      // Browser errors can contain URLs or input values. Test output has a fixed stage only.
      const code = error.message?.match(/net::[A-Z_]+/)?.[0] ?? 'assertion_or_runtime';
      throw new Error(`P05 fixture browser assertion failed during ${stage} (${code})`);
    }
  });
