// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { createHash, createPublicKey, randomBytes } from 'node:crypto';
import { request } from 'node:https';
import { test } from 'node:test';
import { setTimeout } from 'node:timers/promises';
import { chromium } from '@playwright/test';
import { startManagedGrafana } from './managed-grafana.mjs';
import { createTestTls } from './fixture-app/test-tls.mjs';

const home = process.env.P05_GRAFANA_HOME;
if (!home) throw new Error('P05_GRAFANA_HOME must identify the checksum-verified Grafana 13.2.3 distribution');

test('P05-I01 managed Grafana: app-enforced restrictions, isolated reports, revocation and active absolute session maximum',
  { timeout: 420_000 }, async (t) => {
    const tls = await createTestTls();
    t.after(() => tls.close());
    const passwords = [0, 1].map(() => `P05-MANAGED-PASSWORD-CANARY-${randomBytes(24).toString('hex')}`);
    const app = await startManagedGrafana({ home, ...tls, sessionMaxSeconds: 300, accounts: [
      { username: 'primary', password: passwords[0], report: 'Primary backup report: 12 artifacts' },
      { username: 'isolation', password: passwords[1], report: 'Isolation backup report: 3 artifacts' },
    ] });
    t.after(() => app.close());
    let stage = 'setup';
    const measured = { activeReads: 0, tokenRotations: 0, lastLiveMs: 0, rejectedAtMs: 0, lastStatus: 0 };
    const spki = createHash('sha256').update(createPublicKey(tls.cert)
      .export({ type: 'spki', format: 'der' })).digest('base64');
    const browser = await chromium.launch({ chromiumSandbox: true,
      args: [`--ignore-certificate-errors-spki-list=${spki}`] });
    t.after(() => browser.close());
    function send(path, { method = 'GET', body, cookie, headers = {} } = {}) {
      return new Promise((resolve, reject) => {
        const req = request(`${app.origin}${path}`, { method, ca: tls.ca, timeout: 5000, headers: {
          ...(cookie ? { cookie } : {}), ...(body ? { 'content-type': 'application/json' } : {}), ...headers,
        } }, (res) => {
          let text = '';
          res.setEncoding('utf8');
          res.on('data', (chunk) => { text += chunk; });
          res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, text,
            json: text && res.headers['content-type']?.includes('application/json') ? JSON.parse(text) : null }));
        });
        req.on('timeout', () => req.destroy());
        req.on('error', () => reject(new Error('Managed candidate transport failed')));
        req.end(body ? JSON.stringify(body) : undefined);
      });
    }
    function jar(previous, reply) {
      const cookies = new Map(previous?.split('; ').map((part) => {
        const separator = part.indexOf('=');
        return [part.slice(0, separator), part.slice(separator + 1)];
      }));
      for (const header of reply.headers['set-cookie'] ?? []) {
        const pair = header.split(';')[0];
        const separator = pair.indexOf('=');
        cookies.set(pair.slice(0, separator), pair.slice(separator + 1));
      }
      return [...cookies].map(([name, value]) => `${name}=${value}`).join('; ');
    }
    async function login(username, password) {
      const context = await browser.newContext();
      const page = await context.newPage();
      try {
        stage = `${username}-oauth-navigation`;
        await page.goto(`${app.origin}/login/generic_oauth`);
        assert.equal(new URL(page.url()).origin, app.issuerOrigin, 'fixed approved login origin');
        stage = `${username}-oauth-fields`;
        await page.getByLabel('Username').fill(username);
        await page.getByLabel('Password').fill(password);
        await page.getByRole('button', { name: 'Sign in' }).click();
        stage = `${username}-oauth-callback`;
        await page.waitForURL((url) => url.origin === app.origin && !url.pathname.startsWith('/login'));
        const cookies = await context.cookies(app.origin);
        assert.ok(cookies.some((cookie) => cookie.name === 'grafana_session'), 'managed session issued');
        return cookies.map((cookie) => `${cookie.name}=${cookie.value}`).join('; ');
      } finally { await context.close(); }
    }
    try {
      stage = 'header-spoof-denial';
      assert.equal((await send('/api/user', { headers: { 'x-p05-trusted-user': 'admin',
        'x-webauth-user': 'admin', authorization: 'Basic ZHVtbXk6ZHVtbXk=' } })).status, 401);
      assert.equal((await send('/login', { method: 'POST', body: { username: 'admin', password: passwords[0] } })).status, 401);
      const primary = await login('primary', passwords[0]);
      const isolation = await login('isolation', passwords[1]);
      const identity = await send('/api/user', { cookie: primary });
      assert.equal(identity.status, 200);
      assert.equal(identity.json.login, 'primary');
      assert.equal(identity.json.isGrafanaAdmin, false);
      assert.equal(identity.json.isExternal, true);
      assert.equal((await send('/api/user/orgs', { cookie: primary })).json[0].role, 'Viewer');
      const otherIdentity = await send('/api/user', { cookie: isolation });
      assert.equal(otherIdentity.json.login, 'isolation');
      assert.notEqual(identity.json.orgId, otherIdentity.json.orgId, 'separate report organizations');
      const originalEmail = identity.json.email;
      stage = 'valid-direct-mutations';
      const mutations = [
        ['/api/user', 'PUT', { login: 'primary', name: 'Changed', email: 'replacement@example.invalid' }],
        ['/api/user/password', 'PUT', { oldPassword: passwords[0], newPassword: 'replacement-dummy-password', confirmNew: 'replacement-dummy-password' }],
        ['/api/serviceaccounts', 'POST', { name: 'unapproved', role: 'Admin' }],
        ['/api/serviceaccounts/1/tokens', 'POST', { name: 'durable', secondsToLive: 0 }],
        ['/api/datasources', 'POST', { name: 'unapproved', type: 'prometheus', url: 'https://example.invalid', access: 'proxy' }],
        ['/api/org/users', 'POST', { loginOrEmail: 'isolation', role: 'Admin' }],
        ['/api/admin/users', 'POST', { login: 'unapproved', password: 'dummy-password' }],
      ];
      const statuses = [];
      for (const [path, method, body] of mutations) {
        const reply = await send(path, { method, body, cookie: primary });
        statuses.push({ path, status: reply.status });
        stage = `mutation-${statuses.length}-status-${reply.status}`;
        assert.equal(reply.status, 403, 'Grafana denies valid unauthorized mutation');
      }
      assert.equal((await send('/api/user', { cookie: primary })).json.email, originalEmail);
      stage = 'recovery-disabled';
      for (const cookie of [undefined, primary]) {
        assert.equal((await send('/api/user/password/send-reset-email', { method: 'POST',
          body: { userOrEmail: originalEmail }, cookie })).status, 401, 'password recovery disabled by Grafana');
        assert.equal((await send('/api/user/password/reset', { method: 'POST',
          body: { code: 'dummy-reset-code', newPassword: 'dummy-password', confirmPassword: 'dummy-password' }, cookie })).status, 401);
      }
      stage = 'real-ui';
      const context = await browser.newContext();
      const page = await context.newPage();
      await page.goto(`${app.origin}/login/generic_oauth`);
      await page.getByLabel('Username').fill('primary');
      await page.getByLabel('Password').fill(passwords[0]);
      await page.getByRole('button', { name: 'Sign in' }).click();
      await page.waitForURL((url) => url.origin === app.origin && !url.pathname.startsWith('/login'));
      stage = 'report-navigation';
      await page.goto(`${app.origin}/d/p05-primary`);
      stage = 'report-text';
      await page.getByText('Primary backup report: 12 artifacts', { exact: true }).waitFor();
      assert.ok(!(await page.content()).includes(passwords[0]), 'source password absent from report DOM');
      stage = 'profile-navigation';
      await page.goto(`${app.origin}/profile`);
      stage = 'profile-email';
      const email = page.locator('#edit-user-profile-email');
      await email.waitFor();
      assert.equal(await email.isEditable(), false, 'managed email control disabled');
      assert.equal(await page.locator('#edit-user-profile-name').isEditable(), false, 'managed name control disabled');
      assert.equal(await page.locator('#edit-user-profile-username').isEditable(), false, 'managed login control disabled');
      assert.equal(await page.getByText('Change password', { exact: true }).count(), 0, 'password control unavailable');
      const crossReport = await send('/api/dashboards/uid/p05-isolation', { cookie: primary });
      assert.equal(crossReport.status, 404, 'foreign report inaccessible');
      stage = 'revoke-and-replay';
      assert.equal((await app.admin(`/api/admin/users/${identity.json.id}/logout`, { method: 'POST' })).status, 200);
      assert.equal((await send('/api/user', { cookie: primary })).status, 401);
      assert.equal((await send('/api/user', { cookie: isolation })).status, 200, 'other account remains live');
      assert.equal(await page.evaluate(async () => (await fetch('/api/user')).status), 401, 'UI session invalidated too');
      stage = 'absolute-lifetime';
      let cookie = await login('primary', passwords[0]);
      stage = 'absolute-lifetime';
      const original = cookie;
      const start = performance.now();
      let reads = 0;
      let rotations = 0;
      let last = 200;
      let lastLiveMs = 0;
      let rotateAt = 50_000;
      while (performance.now() - start < 310_000) {
        // Grafana's browser explicitly calls its rotation API. Plain API reads
        // alone stop at token_needs_rotation and would not test rolling renewal.
        if (performance.now() - start >= rotateAt) {
          const renewed = await send('/api/user/auth-tokens/rotate', { method: 'POST', cookie });
          if (renewed.status === 401) { last = 401; break; }
          assert.equal(renewed.status, 200, 'real browser session rotation succeeds before absolute maximum');
          const next = jar(cookie, renewed);
          if (next !== cookie) rotations++;
          cookie = next;
          rotateAt += 50_000;
        }
        const reply = await send('/api/user', { cookie });
        const elapsed = performance.now() - start;
        measured.lastStatus = reply.status;
        measured.rejectedAtMs = Math.round(elapsed);
        if (reply.status === 401) { last = reply.status; break; }
        assert.equal(reply.status, 200, 'active session remains authorized before absolute maximum');
        reads++;
        lastLiveMs = elapsed;
        const next = jar(cookie, reply);
        if (next !== cookie) rotations++;
        cookie = next;
        Object.assign(measured, { activeReads: reads, tokenRotations: rotations, lastLiveMs: Math.round(lastLiveMs) });
        await setTimeout(1000);
      }
      const rejectedAtMs = Math.round(performance.now() - start);
      assert.equal(last, 401, 'continuing activity cannot renew authority indefinitely');
      assert.ok(lastLiveMs >= 295_000, 'original session survived until near selected 5m maximum');
      assert.ok(rejectedAtMs <= 306_000, 'expiry detected within measured request cadence bound');
      assert.ok(rotations >= 3, 'test crosses multiple actual website token rotations');
      assert.equal((await send('/api/user', { cookie: original })).status, 401, 'original copied token denied after absolute expiry');
      assert.equal((await send('/api/user', { cookie: `${cookie}; Max-Age=99999999` })).status, 401, 'cookie deadline tampering fails');
      t.diagnostic(JSON.stringify({ candidate: 'Grafana OSS', version: app.version,
        profile: 'Generic OAuth PKCE, no refresh tokens, private Unix backend, isolated Viewer accounts, 5m absolute maximum',
        appPrerequisites: 'pass', mutationStatuses: statuses, activeReads: reads,
        tokenRotations: rotations, lastLiveMs: Math.round(lastLiveMs), rejectedAtMs,
        copiedTokenAfterRevoke: 401, copiedTokenAfterExpiry: 401,
        browser: browser.version(), integratedWorkflow: 'not run' }));
    } catch (error) {
      t.diagnostic(JSON.stringify({ oauth: app.oauthMetrics() }));
      t.diagnostic(JSON.stringify({ measured }));
      const code = error.message?.match(/net::[A-Z_]+/)?.[0] ?? 'assertion_or_runtime';
      throw new Error(`Managed Grafana suitability failed during ${stage} (${code})`);
    }
  });
