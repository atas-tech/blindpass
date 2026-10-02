// SPDX-License-Identifier: AGPL-3.0-only
// Disposable Root component driver. No signed grant, production dispatch or
// cgroup reconciliation claim; all control and test cookies stay private.
import assert from 'node:assert/strict';
import { createHash, createPublicKey, randomBytes } from 'node:crypto';
import { connect } from 'node:net';
import { request } from 'node:https';
import { execFileSync } from 'node:child_process';
import { lstat, readFile } from 'node:fs/promises';
import { attachFramedStream } from '/usr/lib/blindpass/login/src/browser-transport.mjs';
import { createTestTls } from './fixture-app/test-tls.mjs';
import { startFixture } from './fixture-app/server.mjs';
import { scanJournal } from './journal-canary-scan.mjs';

const tls = await createTestTls(); const credential = randomBytes(32).toString('hex'); const password = randomBytes(24).toString('hex');
const canaries = [credential, password]; const connections = new Set(); let sourceCalls = 0; let stage = 'fixture';
const app = await startFixture({ ...tls, adminToken: credential, accounts: [{ username: 'primary', password, report: 'Root revocation report' }],
  observeLogin: async () => { sourceCalls++; } });
const configuration = { kind: 'fixture', origin: app.origin, account: 'primary', sessionMaxMs: 300_000,
  certificateSpkiPins: [createHash('sha256').update(createPublicKey(tls.cert).export({ type: 'spki', format: 'der' })).digest('base64')] };
const profile = { kind: 'fixture-admin', credential_unit: 'blindpass-session-revoker@.service', credential_name: 'fixture-admin' };
const boot = () => Math.floor(Number(execFileSync('/usr/bin/cat', ['/proc/uptime'], { encoding: 'utf8' }).split(' ')[0]) * 1000);
function send(path, body, cookie) { return new Promise((resolve, reject) => {
  const req = request(`${app.origin}${path}`, { ca: tls.ca, method: body ? 'POST' : 'GET',
    headers: { ...(body ? { 'content-type': 'application/json' } : {}), ...(cookie ? { cookie } : {}) } }, res => {
    let text = ''; res.setEncoding('utf8'); res.on('data', chunk => { text += chunk; });
    res.on('end', () => resolve({ status: res.statusCode, json: text ? JSON.parse(text) : null, cookie: res.headers['set-cookie']?.[0]?.split(';')[0] }));
  }); req.on('error', () => reject(new Error('test_transport_failed'))); req.end(body ? JSON.stringify(body) : undefined);
}); }
async function native() {
  const stream = connect({ path: '/run/p05-native-supervisor/client.sock' }); connections.add(stream);
  await new Promise((resolve, reject) => { stream.once('connect', resolve); stream.once('error', () => reject(new Error('native_activation_failed'))); });
  let pending;
  const channel = attachFramedStream(stream, { receive: value => {
    if (!pending) throw new Error('unexpected_response');
    const next = pending; pending = undefined; clearTimeout(next.timer); next.resolve(value);
  }, onFailure: () => { if (pending) { const next = pending; pending = undefined; clearTimeout(next.timer); next.reject(new Error('native_control_closed')); } } });
  return message => new Promise((resolve, reject) => {
    const timer = setTimeout(() => { pending = undefined; stream.destroy(); reject(new Error('native_control_deadline')); }, 10_000);
    pending = { resolve, reject, timer }; void channel.send(message).catch(() => { clearTimeout(timer); pending = undefined; reject(new Error('native_control_send_failed')); });
  });
}
try {
  stage = 'socket-protection';
  const parent = await lstat('/run/blindpass-private'); const socket = await lstat('/run/blindpass-private/revocation.sock');
  assert.equal(parent.uid, 0); assert.equal(parent.mode & 0o7777, 0o700);
  assert.equal(socket.uid, 0); assert.equal(socket.gid, 0); assert.equal(socket.mode & 0o7777, 0o600); assert.equal(socket.nlink, 1);
  const session = await send('/login', { username: 'primary', password }); assert.equal(session.status, 200); canaries.push(session.cookie);
  stage = 'native-preflight'; const control = await native();
  const operationId = `p05_revocation_${randomBytes(16).toString('hex')}`;
  const start = { type: 'revocation-preflight', configuration, profile, credential, operationId, deadlineBoottimeMs: boot() + 120_000 };
  assert.deepEqual(await control(start), { type: 'revocation-ready' });
  assert.equal((await send('/api/session', undefined, session.cookie)).status, 200);
  assert.equal(sourceCalls, 1);
  stage = 'actual-manager';
  const unit = execFileSync('/usr/bin/systemctl', ['list-units', 'blindpass-session-revoker@*.service', '--state=running', '--no-legend', '--plain'], { encoding: 'utf8' }).trim().split(/\s+/)[0];
  assert.match(unit, /^blindpass-session-revoker@.+\.service$/);
  const fields = execFileSync('/usr/bin/systemctl', ['show', unit, '-p', 'MainPID', '-p', 'User', '-p', 'Group', '-p', 'StandardOutput', '-p', 'StandardError'], { encoding: 'utf8' });
  assert.match(fields, /^User=root$/m); assert.match(fields, /^Group=root$/m); assert.match(fields, /^StandardOutput=null$/m); assert.match(fields, /^StandardError=null$/m);
  const pid = Number(fields.match(/^MainPID=(.*)$/m)?.[1]); assert.ok(pid > 0);
  assert.match(await readFile(`/proc/${pid}/status`, 'utf8'), /^CapEff:\s+0000000000000000$/m);
  stage = 'session-revoke';
  assert.deepEqual(await control({ type: 'revocation-session', handle: { kind: 'fixture', account: 'primary', sessionReference: session.json.sessionReference } }), { type: 'revoked' });
  assert.equal((await send('/api/session', undefined, session.cookie)).status, 401);
  const second = await send('/login', { username: 'primary', password }); assert.equal(second.status, 200); canaries.push(second.cookie);
  stage = 'account-recovery';
  assert.deepEqual(await control({ type: 'revocation-account' }), { type: 'revoked' });
  assert.equal((await send('/api/session', undefined, second.cookie)).status, 401);
  assert.deepEqual(await control({ type: 'revocation-close' }), { type: 'revocation-closed' });
  stage = 'failed-preflight'; const denied = await native();
  assert.deepEqual(await denied({ ...start, credential: 'b'.repeat(64), operationId: `p05_denied_${randomBytes(16).toString('hex')}`, deadlineBoottimeMs: boot() + 120_000 }), { type: 'uncertain' });
  assert.equal(sourceCalls, 2);
  stage = 'journal-canaries';
  // Both units log nothing (StandardOutput/StandardError null), so the scan needs its positive controls:
  // non-empty source, a lifecycle line per expected unit and a real control unit read back through journald.
  await scanJournal({ units: ['blindpass-session-revoker@*', 'p05-native-supervisor@*'], canaries });
  console.log('P05-REVOKER-VM native_unix_only_and_jit_denied=true root_caps=0 preflight_non_destructive=true session_replay=401 account_replay=401 bad_admin_source_calls=0 journal_canaries=absent scope=component');
} catch { throw new Error(`P05 revocation component failed during ${stage}`); }
finally { for (const stream of connections) stream.destroy(); await app.close(); await tls.close(); canaries.fill(''); }
