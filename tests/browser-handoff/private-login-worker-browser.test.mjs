// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { createHash, createPublicKey, randomBytes } from 'node:crypto';
import { createServer } from 'node:net';
import { test } from 'node:test';
import { chromium } from 'playwright';
import { startFixture } from './fixture-app/server.mjs';
import { createTestTls } from './fixture-app/test-tls.mjs';
import { frame, runWorker, decode } from './worker-harness.mjs';

const pin = (cert) => createHash('sha256').update(createPublicKey(cert).export({ type: 'spki', format: 'der' })).digest('base64');
test('B-I01–B-I03 / P05-I06 actual separate worker: protected cookie import, no source password or diagnostics',
  { timeout: 20_000 }, async (t) => {
    const tls = await createTestTls(); t.after(() => tls.close());
    const password = `P05-WORKER-PRIVATE-CANARY-${randomBytes(24).toString('hex')}`;
    const app = await startFixture({ ...tls, adminToken: randomBytes(32).toString('hex'), accounts: [
      { username: 'primary', password, report: 'Private worker report: 12 artifacts' },
      { username: 'isolation', password: randomBytes(24).toString('hex'), report: 'Isolation report' },
    ] }); t.after(() => app.close());
    const configuration = { kind: 'fixture', origin: app.origin, account: 'primary', sessionMaxMs: 300_000,
      certificateSpkiPins: [pin(tls.cert)] };
    const raw = await runWorker(frame({ version: 1, configuration, credential: { account: 'primary', password } }));
    assert.equal(raw.code, 0); assert.equal(raw.stdout, ''); assert.equal(raw.stderr, '');
    assert.ok(!raw.output.includes(Buffer.from(password)), 'source password absent from protected response');
    const result = decode(raw.output); raw.output.fill(0);
    assert.equal(result.status, 'authenticated');
    assert.equal(result.cookies.length, 1);
    const browser = await chromium.launch({ chromiumSandbox: true, args: [`--ignore-certificate-errors-spki-list=${pin(tls.cert)}`] });
    t.after(() => browser.close());
    const context = await browser.newContext(); await context.addCookies(result.cookies);
    const page = await context.newPage();
    try {
      assert.equal((await page.goto(`${app.origin}/reports`)).status(), 200);
      assert.equal(await page.locator('#report').textContent(), 'Private worker report: 12 artifacts');
      assert.ok(!(await page.content()).includes(password));
    } catch { throw new Error('Private worker fresh-context report check failed'); }
  });

test('P05-I03 SIGTERM aborts an in-progress login and the worker exits promptly with only uncertain', { timeout: 30_000 }, async (t) => {
  // The origin accepts TCP but never completes TLS, so navigation would wait for the whole login budget.
  const sockets = new Set();
  const silent = createServer((socket) => { sockets.add(socket); socket.on('error', () => {}); socket.on('close', () => sockets.delete(socket)); });
  await new Promise((resolve) => silent.listen(0, '127.0.0.1', resolve));
  t.after(async () => { for (const socket of sockets) socket.destroy(); await new Promise((resolve) => silent.close(resolve)); });
  const configuration = { kind: 'fixture', origin: `https://127.0.0.1:${silent.address().port}`, account: 'primary', sessionMaxMs: 300_000 };
  const terminateAfterMs = 2_500; const started = performance.now();
  const raw = await runWorker(frame({ version: 1, configuration, credential: { account: 'primary', password: 'P05-WORKER-SIGTERM-CANARY' } }),
    { terminateAfterMs, timeoutMs: 20_000 });
  const elapsed = performance.now() - started;
  assert.equal(raw.code, 143, 'worker exited through its termination path, not a kill');
  assert.ok(elapsed < terminateAfterMs + 5_000, `worker took ${Math.round(elapsed)} ms to stop after SIGTERM`);
  assert.deepEqual(decode(raw.output), { status: 'uncertain' });
  assert.equal(raw.stdout, ''); assert.equal(raw.stderr, '');
  assert.ok(!raw.output.includes(Buffer.from('CANARY')));
});
