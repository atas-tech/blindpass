// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { createHash, createPublicKey, randomBytes } from 'node:crypto';
import { connect } from 'node:net';
import { request } from 'node:https';
import { lstat } from 'node:fs/promises';
import { test } from 'node:test';
import { createRevoker } from '../../helpers/login/src/session-revoker.mjs';
import { startManagedGrafana } from './managed-grafana.mjs';
import { createTestTls } from './fixture-app/test-tls.mjs';
import { frame, runWorker, decode } from './worker-harness.mjs';
const home = process.env.P05_GRAFANA_HOME;
if (!home) throw new Error('P05_GRAFANA_HOME must identify checksum-verified Grafana OSS 13.2.3');
test('P05-RV04: actual managed Grafana administrator preflight before source, bound user logout and replay denial', { timeout: 75_000 }, async t => {
  const tls = await createTestTls(); t.after(() => tls.close());
  const password = `P05-REVOKER-GRAFANA-CANARY-${randomBytes(24).toString('hex')}`;
  const app = await startManagedGrafana({ home, ...tls, accounts: [
    { username: 'primary', password, report: 'Administrator revocation report' },
    { username: 'isolation', password: randomBytes(24).toString('hex'), report: 'Isolation report' },
  ] }); t.after(() => app.close());
  const configuration = { kind: 'grafana-managed', origin: app.origin, loginOrigin: app.issuerOrigin, account: 'primary', orgId: 1, sessionMaxMs: 300_000,
    certificateSpkiPins: [createHash('sha256').update(createPublicKey(tls.cert).export({ type: 'spki', format: 'der' })).digest('base64')] };
  // Suitability setup establishes an actual external OAuth account before
  // installing the Root resource mapping. An administrator-created local user
  // cannot substitute for the application's external identity binding.
  const bootstrap = await runWorker(frame({ version: 1, configuration, credential: { account: 'primary', password } }), { timeoutMs: 60_000 });
  assert.equal(bootstrap.code, 0); assert.equal(bootstrap.stdout, ''); assert.equal(bootstrap.stderr, '');
  const established = decode(bootstrap.output); bootstrap.output.fill(0);
  assert.equal(established.status, 'authenticated');
  const userId = established.revokeHandle.userId;
  assert.equal((await app.admin(`/api/admin/users/${userId}/logout`, { method: 'POST' })).status, 200);
  for (const cookie of established.cookies) cookie.value = '';
  const profile = { kind: 'grafana-admin', credential_unit: 'blindpass-session-revoker@.service', credential_name: 'grafana-admin', user_id: userId };
  // Trusted test adapter uses the actual disposable private backend inode.
  // The production worker accepts no path or adapter and checks Root ownership
  // at its fixed /run path; this host test does not establish that manager gate.
  const options = { backendConnect: () => connect({ path: app.adminSocket }), backendCheck: async () => {
    const value = await lstat(app.adminSocket); assert.equal(value.isSocket(), true); assert.equal(value.uid, process.getuid());
    assert.equal(value.mode & 0o7777, 0o600); return `${value.dev}:${value.ino}`;
  } };
  const revoker = await createRevoker(configuration, profile, 'admin', options); t.after(() => revoker.close());
  assert.deepEqual(await revoker.preflight(), { type: 'revocation-ready' });
  const before = app.oauthMetrics().credentialAccepts;
  assert.equal(before, 1);
  for (const [selected, credential] of [[{ ...profile, user_id: userId + 1 }, 'admin'], [profile, 'isolation']]) {
    const denied = await createRevoker(configuration, selected, credential, options); t.after(() => denied.close());
    await assert.rejects(denied.preflight(), { message: 'revocation_unavailable' });
  }
  assert.equal(app.oauthMetrics().credentialAccepts, before);
  const raw = await runWorker(frame({ version: 1, configuration, credential: { account: 'primary', password } }), { timeoutMs: 60_000 });
  assert.equal(raw.code, 0); assert.equal(raw.stdout, ''); assert.equal(raw.stderr, '');
  assert.equal(raw.output.includes(Buffer.from(password)), false);
  const result = decode(raw.output); raw.output.fill(0);
  assert.equal(result.status, 'authenticated');
  assert.equal(app.oauthMetrics().credentialAccepts, before + 1); assert.equal(result.revokeHandle.userId, userId);
  const cookie = result.cookies.map(value => `${value.name}=${value.value}`).join('; ');
  function read(headers) { return new Promise((resolve, reject) => {
    const req = request(`${app.origin}/api/user`, { ca: tls.ca, headers }, res => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
    req.on('error', () => reject(new Error('test_transport_failed'))); req.end();
  }); }
  assert.equal(await read({ cookie }), 200);
  assert.equal(await read({ 'x-p05-trusted-user': 'admin' }), 401);
  assert.deepEqual(await revoker.revoke(result.revokeHandle), { type: 'revoked' });
  assert.equal(await read({ cookie }), 401);
  await revoker.revokeAccount();
  await assert.rejects(revoker.revoke({ ...result.revokeHandle, userId: userId + 1 }), { message: 'revocation_unavailable' });
  for (const value of result.cookies) value.value = '';
});
