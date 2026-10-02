// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { createHash, createPublicKey, randomBytes } from 'node:crypto';
import { request } from 'node:https';
import { test } from 'node:test';
import { compileRevocation, createRevoker } from '../../helpers/login/src/session-revoker.mjs';
import { createTestTls } from './fixture-app/test-tls.mjs';
import { startFixture } from './fixture-app/server.mjs';
const profile = { kind: 'fixture-admin', credential_unit: 'blindpass-session-revoker@.service', credential_name: 'fixture-admin' };
const configuration = { kind: 'fixture', origin: 'https://127.0.0.1:4443', account: 'primary', sessionMaxMs: 300_000 };

test('P05-RV01: fixed revocation profiles and managed user identity are strict', () => {
  assert.equal(compileRevocation(configuration, profile).account, 'primary');
  for (const invalid of [null, {}, { ...profile, kind: 'grafana-admin' }, { ...profile, endpoint: '/anywhere' },
    { ...profile, credential_unit: 'agent.service' }, { ...profile, credential_name: '../admin' }]) {
    assert.throws(() => compileRevocation(configuration, invalid), { message: 'revocation_unavailable' });
  }
  const grafana = { ...configuration, kind: 'grafana-managed', orgId: 1 };
  const managed = { ...profile, kind: 'grafana-admin', user_id: 2 };
  assert.equal(compileRevocation(grafana, managed).userId, 2);
  for (const user_id of [0, -1, 1.5, '2', 4294967296]) {
    assert.throws(() => compileRevocation(grafana, { ...managed, user_id }), { message: 'revocation_unavailable' });
  }
});

test('P05-RV03: actual pinned TLS preflight does not log out; session/account revoke denies copied cookies', async t => {
  const tls = await createTestTls(); t.after(() => tls.close());
  const credential = randomBytes(32).toString('hex'); const password = randomBytes(24).toString('hex');
  let authentications = 0;
  const app = await startFixture({ ...tls, adminToken: credential, observeLogin: async () => { authentications++; },
    accounts: [{ username: 'primary', password, report: 'Revocation report' }], sessionMaxMs: 300_000 });
  t.after(() => app.close());
  const configuration = { kind: 'fixture', origin: app.origin, account: 'primary', sessionMaxMs: 300_000,
    certificateSpkiPins: [createHash('sha256').update(createPublicKey(tls.cert).export({ type: 'spki', format: 'der' })).digest('base64')] };
  function send(path, body, cookie) { return new Promise((resolve, reject) => {
    const req = request(`${app.origin}${path}`, { ca: tls.ca, method: body ? 'POST' : 'GET',
      headers: { ...(body ? { 'content-type': 'application/json' } : {}), ...(cookie ? { cookie } : {}) } }, res => {
      let text = ''; res.setEncoding('utf8'); res.on('data', chunk => { text += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, json: text ? JSON.parse(text) : null, cookie: res.headers['set-cookie']?.[0]?.split(';')[0] }));
    }); req.on('error', () => reject(new Error('test_transport_failed'))); req.end(body ? JSON.stringify(body) : undefined);
  }); }
  const first = await send('/login', { username: 'primary', password });
  assert.equal(first.status, 200);
  const revoker = await createRevoker(configuration, profile, credential);
  t.after(() => revoker.close());
  assert.deepEqual(await revoker.preflight(), { type: 'revocation-ready' });
  assert.equal((await send('/api/session', undefined, first.cookie)).status, 200);
  assert.deepEqual(await revoker.revoke({ kind: 'fixture', account: 'primary', sessionReference: first.json.sessionReference }), { type: 'revoked' });
  assert.equal((await send('/api/session', undefined, first.cookie)).status, 401);
  const second = await send('/login', { username: 'primary', password });
  await revoker.revokeAccount();
  assert.equal((await send('/api/session', undefined, second.cookie)).status, 401);
  assert.equal(authentications, 2);
  for (const [config, admin] of [
    [configuration, 'b'.repeat(64)],
    [{ ...configuration, account: 'isolation' }, credential],
    [{ ...configuration, certificateSpkiPins: ['A'.repeat(43) + '='] }, credential],
  ]) {
    const denied = await createRevoker(config, profile, admin); t.after(() => denied.close());
    await assert.rejects(denied.preflight(), { message: 'revocation_unavailable' });
  }
  await assert.rejects(revoker.revoke({ kind: 'fixture', account: 'isolation', sessionReference: first.json.sessionReference }), { message: 'revocation_unavailable' });
  await revoker.close();
  await assert.rejects(revoker.revokeAccount(), { message: 'revocation_unavailable' });
});

test('P05-RV02/RV05: private worker clears administrator input, permits cleanup after source-preflight window and rejects bad ordering', async () => {
  const { RevocationWorker } = await import('../../helpers/login/src/session-revoker-worker.mjs');
  let now = 1000; let calls = 0; let closes = 0; const replies = [];
  const worker = new RevocationWorker({ now: () => now, send: async value => replies.push(value), create: async () => ({
    preflight: async () => { calls++; return { type: 'revocation-ready' }; },
    revokeAccount: async () => { calls++; return { type: 'revoked' }; }, close: async () => { closes++; },
  }) });
  const message = { type: 'preflight', version: 1, operationId: 'operation_aaaaaaaa', configuration, profile,
    credential: 'a'.repeat(64), deadlineBoottimeMs: 5000 };
  await worker.receive(message); assert.equal(message.credential, '');
  now += 60_000; await worker.receive({ type: 'revoke-account' });
  assert.deepEqual(replies, [{ type: 'revocation-ready' }, { type: 'revoked' }]);
  await worker.receive({ type: 'preflight', ...message, credential: 'b'.repeat(64) });
  assert.equal(worker.closed, true); assert.equal(calls, 2); assert.equal(closes, 1);
  assert.deepEqual(replies.at(-1), { type: 'revocation-unavailable' });
});

test('P05-RV05: worker reports lost application cleanup as uncertain and refuses late preflight', async () => {
  const { RevocationWorker } = await import('../../helpers/login/src/session-revoker-worker.mjs');
  let now = 1000; const replies = []; let closes = 0;
  const worker = new RevocationWorker({ now: () => now, send: async value => replies.push(value), create: async () => ({
    preflight: async () => ({ type: 'revocation-ready' }), revokeAccount: async () => { throw new Error('revocation_uncertain'); }, close: async () => { closes++; },
  }) });
  await worker.receive({ type: 'preflight', version: 1, operationId: 'operation_aaaaaaaa', configuration, profile,
    credential: 'a'.repeat(64), deadlineBoottimeMs: 5000 });
  await worker.receive({ type: 'revoke-account' });
  assert.deepEqual(replies.at(-1), { type: 'revocation-uncertain' }); assert.equal(closes, 1);
  let invoked = false;
  const late = new RevocationWorker({ now: () => now, send: async value => replies.push(value), create: async () => { invoked = true; } });
  await late.receive({ type: 'preflight', version: 1, operationId: 'operation_aaaaaaaa', configuration, profile,
    credential: 'a'.repeat(64), deadlineBoottimeMs: now });
  assert.equal(invoked, false); assert.equal(late.closed, true);
});

test('P05-RV03/RV05: credentials wait for verified TLS, redirects are not followed and lost cleanup replies stay uncertain', async t => {
  const { createServer } = await import('node:https');
  const tls = await createTestTls(); t.after(() => tls.close());
  let delivered = 0; let redirected = 0; let revoked = 0;
  const target = createServer(tls, (req, res) => { redirected++; req.resume(); res.writeHead(200); res.end(); });
  await new Promise(resolve => target.listen(0, '127.0.0.1', resolve));
  t.after(() => { target.closeAllConnections(); return new Promise(resolve => target.close(resolve)); });
  let redirect = true;
  const server = createServer(tls, (req, res) => {
    delivered++; req.resume(); req.on('end', () => {
      if (redirect) { res.writeHead(302, { location: `https://127.0.0.1:${target.address().port}/admin/accounts/check` }); res.end(); }
      else if (req.url === '/admin/accounts/check') { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify({ status: 'revocation_ready', account: 'primary' })); }
      else { revoked++; req.socket.destroy(); }
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => { server.closeAllConnections(); return new Promise(resolve => server.close(resolve)); });
  const pin = createHash('sha256').update(createPublicKey(tls.cert).export({ type: 'spki', format: 'der' })).digest('base64');
  const config = { ...configuration, origin: `https://127.0.0.1:${server.address().port}`, certificateSpkiPins: [pin] };
  const rejectedTls = await createRevoker({ ...config, certificateSpkiPins: ['A'.repeat(43) + '='] }, profile, 'a'.repeat(64));
  t.after(() => rejectedTls.close()); await assert.rejects(rejectedTls.preflight(), { message: 'revocation_unavailable' });
  assert.equal(delivered, 0);
  const revoker = await createRevoker(config, profile, 'a'.repeat(64)); t.after(() => revoker.close());
  await assert.rejects(revoker.preflight(), { message: 'revocation_unavailable' });
  assert.equal(delivered, 1); assert.equal(redirected, 0);
  redirect = false; await revoker.preflight();
  await assert.rejects(revoker.revokeAccount(), { message: 'revocation_uncertain' });
  assert.equal(revoked, 1);
});
