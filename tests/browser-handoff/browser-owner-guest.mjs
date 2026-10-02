// SPDX-License-Identifier: AGPL-3.0-only
// Root disposable issuer; tests actual broker leases without provisioning source.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdir, rm, writeFile, readFile, access } from 'node:fs/promises';
import { createConnection } from 'node:net';
import { generateKeyPairSync, sign, verify, createPublicKey } from 'node:crypto';

const base = '/run/p05-browser-owner';
const node = '/usr/lib/blindpass/login/runtime/bin/node';
const unit = 'p05-browser-owner-agent.service';
const brokerUnit = 'p05-browser-owner-broker.service';
const invoke = (cmd, args) => execFileSync(cmd, args, { stdio: ['ignore', 'pipe', 'pipe'], encoding: 'utf8' }).trim();
function sort(value) {
  if (Array.isArray(value)) return value.map(sort);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map(key => [key, sort(value[key])]));
  return value;
}
const canonical = value => JSON.stringify(sort(value));
const pair = generateKeyPairSync('ed25519');
const publicText = pair.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('base64url');
const kid = `ed25519-${publicText}`;
async function exchange(path, frame) {
  return new Promise((resolve, reject) => {
    const socket = createConnection(path);
    const chunks = [];
    const timer = setTimeout(() => { socket.destroy(); reject(new Error('exchange_deadline')); }, 6000);
    socket.on('connect', () => socket.end(frame));
    socket.on('data', chunk => chunks.push(chunk));
    socket.on('error', () => { clearTimeout(timer); reject(new Error('exchange_failed')); });
    socket.on('end', () => { clearTimeout(timer); resolve(Buffer.concat(chunks).toString()); });
  });
}
const control = frame => exchange('/run/blindpass/control.sock', frame);
async function relay(kind, body) {
  const unsigned = { v: 1, kind, body, kid, epoch: 1 };
  const message = Buffer.concat([Buffer.from('blindpass:fleet-document:v1\0'), Buffer.from(canonical(unsigned))]);
  const document = Buffer.from(canonical({ ...unsigned, sig: sign(null, message, pair.privateKey).toString('base64url') }));
  assert.equal(await control(Buffer.concat([Buffer.from(`RELAY ${document.length}\n`), document])), `OK document_applied ${kind}\n`);
}
async function wait(predicate) {
  const deadline = performance.now() + 15000;
  while (performance.now() < deadline) { if (await predicate()) return; await new Promise(resolve => setTimeout(resolve, 25)); }
  throw new Error('guest_state_deadline');
}
async function driver(action, id, operation) {
  const result = JSON.parse(await exchange(`${base}/agent/driver.sock`, JSON.stringify({ action, id, operation })));
  assert.ok(!result.failed);
  return result;
}
const work = async (id, operation) => (await driver('work', id, operation)).reply;
const request = key => `request:${Buffer.from(canonical({ action: 'browser.session', mode: 'browser_session', purpose: 'read report', resource_id: 'report-primary', ttl_seconds: 120, request_key: key })).toString('base64url')}`;
let stage = 'setup';
async function run() {
  assert.equal(process.getuid(), 0);
  for (const path of [base, '/etc/blindpass', '/run/blindpass/workload.sock']) await assert.rejects(access(path));
  try { invoke('useradd', ['--system', '--no-create-home', '--shell', '/usr/sbin/nologin', 'blindpass-owner']); }
  catch { invoke('id', ['blindpass-owner']); }
  const uid = Number(invoke('id', ['-u', 'blindpass-owner']));
  const gid = Number(invoke('id', ['-g', 'blindpass-owner']));
  await mkdir(base, { mode: 0o755 });
  await mkdir(`${base}/agent`, { mode: 0o700 });
  invoke('chown', [`${uid}:${gid}`, `${base}/agent`]);
  await mkdir('/etc/blindpass', { mode: 0o700 });
  await writeFile('/etc/blindpass/browser-resources.json', canonical({ version: 1, resources: [{ resource_id: 'report-primary', workload_ids: ['workload-a'], credential_unit: 'blindpass-login-helper@.service', credential_name: 'primary-password', configuration: { kind: 'fixture', origin: 'https://fixture.example.invalid', account: 'primary', sessionMaxMs: 300000 } }] }), { mode: 0o600 });
  invoke('systemd-run', ['--quiet', '--collect', '--unit=p05-browser-owner-agent', '-p', 'User=blindpass-owner', '-p', 'Group=blindpass-owner', '-p', 'RuntimeMaxSec=90s', '-p', 'TimeoutStopSec=5s', '-p', 'NoNewPrivileges=yes', '-p', 'LimitCORE=0', '-p', 'RestrictAddressFamilies=AF_UNIX', node, '/tmp/browser-handoff/browser-owner-guest-client.mjs']);
  await wait(async () => { try { await access(`${base}/agent/driver.sock`); return true; } catch { return false; } });
  const invocation = invoke('systemctl', ['show', '-p', 'InvocationID', '--value', unit]);
  assert.match(invocation, /^[a-f0-9]{32}$/);
  async function start(initial) {
    if (initial) invoke('systemd-run', ['--quiet', '--collect', '--unit=p05-browser-owner-broker', '-p', 'Type=notify', '-p', 'NotifyAccess=main', '-p', 'RuntimeMaxSec=90s', '-p', 'TimeoutStopSec=5s', '-p', 'LimitCORE=0', '/usr/lib/blindpass/login/blindpass-broker', '--browser-resources', '--key-directory', `${base}/keys`, '--workload-group', 'blindpass-owner', '--map', 'blindpass-login-helper@.service=primary-password', '--workload', `node-a:workload-a:${unit}:${uid}:${invocation}`]);
    else invoke('systemctl', ['restart', brokerUnit]);
    assert.equal(await control(`PIN_ISSUER tenant-a node-a 1 ${kid} ${publicText}\n`), 'OK issuer_pinned\n');
    await relay('registration', { node_id: 'node-a', workload_id: 'workload-a', unit, account: `uid:${uid}`, invocation_id: invocation, status: 'active', consumption_mode: 'browser_session', registration_version: 1, policy_version: 1, local_ceiling_seconds: 120 });
    await relay('policy_snapshot', { policy_version: 1, local_ceiling_seconds: 120, allowed_actions: ['browser.session'], allowed_modes: ['browser_session'] });
    const challenge = (await control('TIME_CHALLENGE\n')).trim().slice(5);
    const time = Date.now();
    await relay('time_reply', { node_id: 'node-a', challenge, challenge_received_at_ms: time, controller_time_ms: time, issuer_epoch: 1 });
  }
  await start(true);
  const identity = await control('IDENTITY\n');
  const signing = identity.match(/signing_pub=([A-Za-z0-9_-]+)/)[1];
  const brokerKey = createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(signing, 'base64url')]), type: 'spki', format: 'der' });
  async function events() {
    const list = JSON.parse((await control('PULL_EVENTS\n')).split('\n')[1]);
    for (const event of list) {
      const message = Buffer.concat([Buffer.from('blindpass:fleet-node-event:v1\0'), Buffer.from(canonical({ node_id: 'node-a', idempotency_key: event.idempotency_key, kind: event.kind, body: event.body }))]);
      assert.ok(verify(null, message, brokerKey, Buffer.from(event.broker_signature, 'base64url')));
    }
    return list;
  }
  async function grant(key, index) {
    const time = Date.now();
    const grantId = `gr_${index.toString().repeat(32)}`;
    const body = { id: grantId, operation_id: `op_${index.toString().repeat(32)}`, node_id: 'node-a', workload_id: 'workload-a', invocation_id: invocation, unit, account: `uid:${uid}`, resource_id: 'report-primary', recipient_key_id: 'node-a-1', registration_version: 1, policy_version: 1, request_event_key: key, action: 'browser.session', mode: 'browser_session', audience: 'blindpass-node', issuer_epoch: 1, issued_at_ms: time, expires_at_ms: time + 120000, local_ceiling_seconds: 120 };
    await relay('grant', body);
    return { grantId, body };
  }
  stage = 'ack';
  await driver('spawn', 'original');
  const first = await work('original', request('owner_retry_1111111111111111'));
  const key = first.trim().split(' ').at(-1);
  assert.match(key, /^event_[A-Za-z0-9_-]{16,100}$/);
  stage = 'first-grant';
  const initialGrant = await grant(key, 1);
  stage = 'first-consumption';
  assert.equal(await work('original', `consume:${initialGrant.grantId}`), 'ERR browser_runtime_unavailable\n');
  stage = 'ack';
  const before = await events();
  assert.equal(before.filter(event => event.kind === 'operation_request').length, 1);
  await relay('application_ack', { node_id: 'node-a', issuer_epoch: 1, acknowledged_at_ms: Date.now(), event_keys: before.map(event => event.idempotency_key) });
  assert.equal((await events()).length, 0);
  assert.equal(await work('original', `consume:${initialGrant.grantId}`), 'ERR browser_runtime_unavailable\n');
  stage = 'restart';
  await start(false);
  await relay('grant', initialGrant.body);
  assert.equal(await work('original', request('owner_retry_1111111111111111')), first);
  assert.equal(await work('original', `consume:${initialGrant.grantId}`), 'ERR browser_original_owner_unavailable\n');
  assert.equal((await events()).length, 0);
  stage = 'exit-request';
  const second = await work('original', request('owner_retry_2222222222222222'));
  const secondKey = second.trim().split(' ').at(-1);
  assert.notEqual(secondKey, key);
  stage = 'exit-grant'; const secondGrant = await grant(secondKey, 2);
  stage = 'exit-consume';
  assert.equal(await work('original', `consume:${secondGrant.grantId}`), 'ERR browser_runtime_unavailable\n');
  const exitedAt = performance.now();
  stage = 'exit-kill';
  await driver('kill', 'original');
  stage = 'exit-cancel';
  await wait(async () => (await events()).some(event => event.kind === 'operation_cancel' && event.body.request_event_key === secondKey));
  const withdrawnMs = Math.ceil(performance.now() - exitedAt);
  stage = 'exit-bound';
  assert.ok(withdrawnMs < 5000);
  stage = 'exit-unit';
  assert.equal(invoke('systemctl', ['is-active', unit]), 'active');
  assert.equal(invoke('systemctl', ['show', '-p', 'InvocationID', '--value', unit]), invocation);
  stage = 'replacement';
  await driver('spawn', 'replacement');
  assert.equal(await work('replacement', request('owner_retry_2222222222222222')), second);
  assert.equal(await work('replacement', `status:${secondKey}`), 'OK operation_status cancelling\n');
  assert.equal(await work('replacement', `consume:${secondGrant.grantId}`), 'ERR browser_request_binding_unavailable\n');
  const after = await events();
  assert.equal(after.filter(event => event.kind === 'operation_request').length, 1);
  assert.equal(after.filter(event => event.kind === 'operation_cancel').length, 1);
  const snapshot = await readFile(`${base}/keys/pending-node-events.jsonl`, 'utf8');
  for (const privateValue of ['fixture.example.invalid', 'primary-password', 'P05-PRIVATE-CANARY']) assert.ok(!snapshot.includes(privateValue));
  process.stdout.write(`P05-BROWSER-OWNER-VM actual_original_pidfd=verified manager_revalidation=verified ack_retains_lease=verified restart_rebinding=denied original_exit_ms=${withdrawnMs} same_uid_unit_invocation_replacement=denied cancellation_signed=verified source_provisioned=none scope=original_process_lease\n`);
}
try { await run(); }
catch { process.stderr.write(`P05-BROWSER-OWNER-VM failed stage=${stage}\n`); process.exitCode = 70; }
finally {
  for (const name of [unit, brokerUnit]) { try { invoke('systemctl', ['stop', name]); } catch {} }
  await rm(base, { recursive: true, force: true });
  await rm('/etc/blindpass', { recursive: true, force: true });
  await rm('/run/blindpass', { recursive: true, force: true });
}
