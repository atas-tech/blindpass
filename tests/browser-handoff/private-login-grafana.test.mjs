// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { createHash, createPublicKey, randomBytes } from 'node:crypto';
import { test } from 'node:test';
import { chromium } from 'playwright';
import { startManagedGrafana } from './managed-grafana.mjs';
import { createTestTls } from './fixture-app/test-tls.mjs';
import { frame, runWorker, decode } from './worker-harness.mjs';

const home = process.env.P05_GRAFANA_HOME;
if (!home) throw new Error('P05_GRAFANA_HOME must identify checksum-verified Grafana OSS 13.2.3');
test('B-I01–B-I03 / P05-I06 actual private worker managed Grafana login, read-only session import and revoke',
  { timeout: 60_000 }, async (t) => {
    const tls = await createTestTls(); t.after(() => tls.close());
    const password = `P05-WORKER-GRAFANA-CANARY-${randomBytes(24).toString('hex')}`;
    const app = await startManagedGrafana({ home, ...tls, sessionMaxSeconds: 300, accounts: [
      { username: 'primary', password, report: 'Private worker report: 12 artifacts' },
      { username: 'isolation', password: randomBytes(24).toString('hex'), report: 'Isolation report' },
    ] }); t.after(() => app.close());
    const spki = createHash('sha256').update(createPublicKey(tls.cert).export({ type: 'spki', format: 'der' })).digest('base64');
    const configuration = { kind: 'grafana-managed', origin: app.origin, loginOrigin: app.issuerOrigin, account: 'primary',
      orgId: 1, sessionMaxMs: 300_000, certificateSpkiPins: [spki] };
    const raw = await runWorker(frame({ version: 1, configuration, credential: { account: 'primary', password } }));
    assert.equal(raw.code, 0); assert.equal(raw.stdout, ''); assert.equal(raw.stderr, '');
    assert.ok(!raw.output.includes(Buffer.from(password)), 'no source password in protected response');
    const result = decode(raw.output); raw.output.fill(0);
    assert.equal(result.status, 'authenticated');
    assert.deepEqual(result.cookies.map((cookie) => cookie.name).sort(), ['grafana_session', 'grafana_session_expiry']);
    const browser = await chromium.launch({ chromiumSandbox: true, args: [`--ignore-certificate-errors-spki-list=${spki}`] });
    t.after(() => browser.close());
    const context = await browser.newContext(); await context.addCookies(result.cookies);
    const page = await context.newPage();
    let stage = 'report';
    try {
      await page.goto(`${app.origin}/d/p05-primary`);
      await page.getByText('Private worker report: 12 artifacts', { exact: true }).waitFor();
      assert.ok(!(await page.content()).includes(password));
      stage = 'restricted-profile';
      assert.equal(await page.evaluate(async () => (await fetch('/api/user', { method: 'PUT',
        headers: { 'content-type': 'application/json' }, body: JSON.stringify({ login: 'primary', name: 'Changed', email: 'changed@example.invalid' }) })).status), 403);
      stage = 'revoke';
      assert.equal((await app.admin(`/api/admin/users/${result.revokeHandle.userId}/logout`, { method: 'POST' })).status, 200);
      assert.equal(await page.evaluate(async () => (await fetch('/api/user')).status), 401);
      assert.ok(result.originalDeadlineMs <= Date.now() + 300_000);
    } catch { throw new Error(`Managed private worker check failed during ${stage}`); }
  });
