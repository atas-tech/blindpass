// SPDX-License-Identifier: AGPL-3.0-only
// Disposable signed issuer fixture. Production broker actors, HPKE custody,
// helper, runtime proof, browser import and stock MCP are real. No controller claim.
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { mkdir, rm, writeFile, readFile, chown, lstat, readdir } from 'node:fs/promises';
import { createConnection } from 'node:net';
import { request } from 'node:https';
import { createInterface } from 'node:readline';
import { generateKeyPairSync, sign, verify, createPublicKey, createHash, randomBytes } from 'node:crypto';
import { createTestTls } from './fixture-app/test-tls.mjs';
import { startFixture } from './fixture-app/server.mjs';
import { findOperationRecord } from './coordinator-journal.mjs';
import { scanJournal } from './journal-canary-scan.mjs';
import { startShippedBroker } from './shipped-broker-unit.mjs';
const node = '/usr/lib/blindpass/login/runtime/bin/node';
const directory = '/run/p05-browser-agent';
const brokerUnit = 'blindpass-broker.service'; // the shipped unit, see shipped-broker-unit.mjs
const unit = 'p05-browser-agent.service';
const invoke = (cmd, args) => execFileSync(cmd, args, { stdio: ['ignore', 'pipe', 'pipe'], encoding: 'utf8' }).trim();
function sort(value) { if (Array.isArray(value)) return value.map(sort); if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map(key => [key, sort(value[key])])); return value; }
const canonical = value => JSON.stringify(sort(value));
const pair = generateKeyPairSync('ed25519');
const publicText = pair.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('base64url');
const kid = `ed25519-${publicText}`;
function exchange(path, frame) { return new Promise((resolve, reject) => {
  const socket = createConnection(path); const chunks = [];
  const timer = setTimeout(() => { socket.destroy(); reject(new Error('exchange_deadline')); }, 6000);
  socket.on('connect', () => socket.end(frame)); socket.on('data', chunk => chunks.push(chunk));
  socket.on('error', () => { clearTimeout(timer); reject(new Error('exchange_failed')); });
  socket.on('end', () => { clearTimeout(timer); resolve(Buffer.concat(chunks).toString()); });
}); }
const control = frame => exchange('/run/blindpass/control.sock', frame);
async function relay(kind, body) {
  const unsigned = { v: 1, kind, body, kid, epoch: 1 };
  const message = Buffer.concat([Buffer.from('blindpass:fleet-document:v1\0'), Buffer.from(canonical(unsigned))]);
  const document = Buffer.from(canonical({ ...unsigned, sig: sign(null, message, pair.privateKey).toString('base64url') }));
  assert.equal(await control(Buffer.concat([Buffer.from(`RELAY ${document.length}\n`), document])), `OK document_applied ${kind}\n`);
}
async function wait(predicate, timeout = 65000) { const end = performance.now() + timeout; while (performance.now() < end) { if (await predicate()) return; await new Promise(resolve => setTimeout(resolve, 50)); } throw new Error('guest_state_deadline'); }
function controlled(child) {
  const messages = []; const pending = new Map(); let stderrBytes = 0;
  child.stderr.on('data', bytes => { stderrBytes += bytes.length; bytes.fill(0); }); child.stdin.on('error', () => {});
  const closed = new Promise(resolve => child.once('close', resolve));
  createInterface({ input: child.stdout }).on('line', line => { try { const message = JSON.parse(line); const accept = pending.get(message.type); if (accept) { pending.delete(message.type); accept(message); } else messages.push(message); } catch { child.kill(); } });
  return { closed, get stderrBytes() { return stderrBytes; }, send(value) { const line = JSON.stringify(value)+'\n'; if (value.type === 'stop') child.stdin.end(line); else child.stdin.write(line); }, next(type) {
    const i = messages.findIndex(message => message.type === type); if (i >= 0) return Promise.resolve(messages.splice(i, 1)[0]);
    return new Promise((resolve, reject) => { const timer = setTimeout(() => { pending.delete(type); reject(new Error('agent_deadline')); }, 35000); pending.set(type, message => { clearTimeout(timer); resolve(message); }); });
  } };
}
async function provision(name, selectedUnit, value) { const child = spawn('/usr/lib/blindpass/login/blindpass-provision', ['--unit', selectedUnit, '--credential', name], { stdio: ['pipe', 'pipe', 'pipe'] }); let normal = ''; child.stdout.on('data', bytes => { normal += bytes; bytes.fill(0); }); child.stderr.on('data', bytes => bytes.fill(0)); const closed = new Promise(resolve => child.once('close', resolve)); const bytes = Buffer.from(value); child.stdin.end(bytes, () => bytes.fill(0)); assert.equal(await closed, 0); assert.match(normal, /^Credential provisioned for /); }
const tls = await createTestTls(); const password = `P05-COORDINATOR-SOURCE-${randomBytes(24).toString('hex')}`; const adminToken = randomBytes(32).toString('hex');
let releaseLogin; const loginLatch = new Promise(resolve => { releaseLogin = resolve; }); let loginCount = 0;
const journalPath = '/var/lib/blindpass/broker/sessions/state.json';
const app = await startFixture({ ...tls, adminToken, accounts: [{ username: 'primary', password, report: 'Coordinator report: 12 artifacts' }, { username: 'isolation', password: randomBytes(24).toString('hex'), report: 'Isolation report' }], observeLogin: async () => {
  const current = JSON.parse(await readFile(journalPath, 'utf8')).records.filter(record => record.state === 'reserved' && record.helper_unit);
  assert.equal(current.length, 1); assert.equal(invoke('systemctl', ['show', '--value', '-p', 'InvocationID', current[0].helper_unit]), current[0].helper_invocation);
  loginCount++; await loginLatch;
} });
let stage = 'setup'; let agent; let clockTimer; let clockFailure = false;
try {
  assert.equal(process.getuid(), 0);
  try { invoke('useradd', ['--system', '--no-create-home', '--shell', '/usr/sbin/nologin', 'p05-browser-agent']); } catch { invoke('id', ['p05-browser-agent']); }
  const uid = Number(invoke('id', ['-u', 'p05-browser-agent'])); const gid = Number(invoke('id', ['-g', 'p05-browser-agent']));
  await mkdir(directory, { mode: 0o755 });
  for (const name of ['output', 'home']) { await mkdir(`${directory}/${name}`, { mode: 0o700 }); await chown(`${directory}/${name}`, uid, gid); }
  await writeFile(`${directory}/stock-config.json`, JSON.stringify({ browser: { browserName: 'chromium', cdpEndpoint: 'ws+unix:/run/blindpass/browser/p05-agent/cdp.sock:/current', cdpTimeout: 10000 }, saveSession: false, outputMode: 'stdout', outputDir: `${directory}/output`, snapshot: { mode: 'full' } }), { mode: 0o600 }); await chown(`${directory}/stock-config.json`, uid, gid);
  agent = controlled(spawn('/usr/bin/systemd-run', ['--quiet', '--wait', '--pipe', '--collect', '--unit=p05-browser-agent', '-p', 'User=p05-browser-agent', '-p', 'Group=p05-browser-agent', '-p', 'NoNewPrivileges=yes', '-p', 'LimitCORE=0', '-p', 'RuntimeMaxSec=180s', '-p', 'TimeoutStopSec=5s', '-p', `WorkingDirectory=${directory}/output`, '-E', `HOME=${directory}/home`, '-E', `XDG_CACHE_HOME=${directory}/home/cache`, node, '/tmp/browser-handoff/isolated-browser-agent.mjs'], { stdio: ['pipe', 'pipe', 'pipe'] }));
  await agent.next('agent-ready'); const invocation = invoke('systemctl', ['show', '--value', '-p', 'InvocationID', unit]); assert.match(invocation, /^[a-f0-9]{32}$/);
  await mkdir('/etc/blindpass', { mode: 0o700 });
  const configuration = { kind: 'fixture', origin: app.origin, account: 'primary', sessionMaxMs: 300000, certificateSpkiPins: [createHash('sha256').update(createPublicKey(tls.cert).export({ type: 'spki', format: 'der' })).digest('base64')] };
  await writeFile('/etc/blindpass/browser-resources.json', canonical({ version: 1, resources: [{ resource_id: 'report-primary', workload_ids: ['p05-agent'], credential_unit: 'blindpass-login-helper@.service', credential_name: 'primary-password', revocation: { kind: 'fixture-admin', credential_unit: 'blindpass-session-revoker@.service', credential_name: 'fixture-admin' }, configuration }] }), { mode: 0o600 });
  for (const [path, group] of [['/run/blindpass-helper-identity', 'blindpass-login'], ['/run/blindpass-runtime', 'blindpass-runtime']]) { await mkdir(path, { recursive: true, mode: 0o750 }); invoke('chown', [`root:${group}`, path]); }
  stage = 'broker-start';
  // The shipped unit and browser-runtime drop-in (installed by private-helper-guest.sh) run unchanged
  // apart from the generated guest drop-in. The shipped ExecStart also names --node-group.
  try { invoke('getent', ['group', 'blindpass-node']); } catch { invoke('groupadd', ['--system', 'blindpass-node']); }
  await startShippedBroker({ workloadGroup: 'p05-browser-agent', workload: `node-a:p05-agent:${unit}:${uid}:${invocation}`, runtimeMaxSec: 180 });
  assert.equal(await control(`PIN_ISSUER tenant-a node-a 1 ${kid} ${publicText}\n`), 'OK issuer_pinned\n');
  await relay('registration', { node_id: 'node-a', workload_id: 'p05-agent', unit, account: `uid:${uid}`, invocation_id: invocation, status: 'active', consumption_mode: 'browser_session', registration_version: 1, policy_version: 1, local_ceiling_seconds: 120 });
  await relay('policy_snapshot', { policy_version: 1, local_ceiling_seconds: 120, allowed_actions: ['browser.session'], allowed_modes: ['browser_session'] });
  async function refreshClock() { const challenge = (await control('TIME_CHALLENGE\n')).trim().slice(5); const time = Date.now(); await relay('time_reply', { node_id: 'node-a', challenge, challenge_received_at_ms: time, controller_time_ms: time, issuer_epoch: 1 }); }
  await refreshClock(); clockTimer = setInterval(() => { refreshClock().catch(() => { clockFailure = true; }); }, 10000);
  stage = 'hpke-provision'; await provision('primary-password', 'blindpass-login-helper@.service', password); await provision('fixture-admin', 'blindpass-session-revoker@.service', adminToken);
  async function work(operation) { agent.send({ type: 'work', operation }); const result = await agent.next('work-result'); assert.ok(!result.failed); return result.reply; }
  stage = 'request';
  const reply = await work(`request:${Buffer.from(canonical({ action: 'browser.session', mode: 'browser_session', purpose: 'read report', resource_id: 'report-primary', ttl_seconds: 120, request_key: 'coordinator_1111111111111111' })).toString('base64url')}`);
  const key = reply.trim().split(' ').at(-1); assert.match(key, /^event_[A-Za-z0-9_-]{16,100}$/);
  const signing = (await control('IDENTITY\n')).match(/signing_pub=([A-Za-z0-9_-]+)/)[1];
  const brokerKey = createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(signing, 'base64url')]), type: 'spki', format: 'der' });
  async function events() { const list = JSON.parse((await control('PULL_EVENTS\n')).split('\n')[1]); for (const event of list) assert.ok(verify(null, Buffer.concat([Buffer.from('blindpass:fleet-node-event:v1\0'), Buffer.from(canonical({ node_id: 'node-a', idempotency_key: event.idempotency_key, kind: event.kind, body: event.body }))]), brokerKey, Buffer.from(event.broker_signature, 'base64url'))); return list; }
  stage = 'signed-grant'; const issued = Date.now();
  await relay('grant', { id: `gr_${'1'.repeat(32)}`, operation_id: `op_${'1'.repeat(32)}`, node_id: 'node-a', workload_id: 'p05-agent', invocation_id: invocation, unit, account: `uid:${uid}`, resource_id: 'report-primary', recipient_key_id: 'node-a-1', registration_version: 1, policy_version: 1, request_event_key: key, action: 'browser.session', mode: 'browser_session', audience: 'blindpass-node', issuer_epoch: 1, issued_at_ms: issued, expires_at_ms: issued + 120000, local_ceiling_seconds: 120 });
  stage = 'login-outside-lock'; await wait(() => loginCount === 1);
  const provisional = await events(); assert.equal(provisional.filter(event => event.kind === 'operation_result').length, 1);
  await relay('application_ack', { node_id: 'node-a', issuer_epoch: 1, acknowledged_at_ms: Date.now(), event_keys: provisional.map(event => event.idempotency_key) }); assert.equal((await events()).length, 0);
  releaseLogin(); stage = 'ready'; let status;
  await wait(async () => { status = await work(`status:${key}`); if (/^OK operation_status (cancelling|closed)/.test(status)) throw new Error('actor_withdrawn'); return status.startsWith('OK operation_status ready ctx_'); }); assert.match(status, /^OK operation_status ready ctx_[a-f0-9]{64}\n$/);
  const active = findOperationRecord(JSON.parse(await readFile(journalPath, 'utf8')), `op_${'1'.repeat(32)}`, 'active'); assert.ok(active?.browser_unit && active.browser_invocation);
  assert.equal(invoke('systemctl', ['show', '--value', '-p', 'InvocationID', active.browser_unit]), active.browser_invocation);
  const stateBytes = await readFile(journalPath); assert.ok(!stateBytes.includes(Buffer.from(password))); assert.ok(!stateBytes.includes(Buffer.from(adminToken))); stateBytes.fill(0);
  stage = 'stock-task'; agent.send({ type: 'run', origin: app.origin }); const task = await agent.next('task-result'); assert.ok(task.passed); assert.equal(task.stderrBytes, 0); assert.equal(task.messages.length, 2);
  const visible = JSON.stringify(task.messages); assert.ok(visible.includes('Coordinator report: 12 artifacts')); for (const canary of [password, adminToken, 'Isolation report', 'ws+unix:', '/devtools/browser/']) assert.ok(!visible.includes(canary));
  async function copyCookie() {
    agent.send({ type: 'copy-session' }); const copied = await agent.next('copied-session'); assert.ok(copied.passed); assert.equal(copied.stderrBytes, 0);
    const text = JSON.stringify(copied.copied); const cookie = text.match(/__Host-bp-fixture=([A-Za-z0-9_-]{20,200})/)?.[0]; assert.ok(cookie); return cookie;
  }
  function cookieStatus(cookie) { return new Promise((resolve, reject) => { const req = request(`${app.origin}/reports`, { ca: tls.ca, headers: { cookie }, timeout: 5000 }, response => { response.resume(); response.once('end', () => resolve(response.statusCode)); }); req.once('error', () => reject(new Error('replay_transport_failed'))); req.once('timeout', () => req.destroy()); req.end(); }); }
  stage = 'copyable-session'; const copiedCookie = await copyCookie(); assert.ok(!visible.includes(copiedCookie.split('=')[1])); assert.equal(await cookieStatus(copiedCookie), 200);
  stage = 'cancel-cleanup'; assert.match(await work(`cancel:${key}`), /^OK /);
  await wait(async () => findOperationRecord(JSON.parse(await readFile(journalPath, 'utf8')), active.binding.operation_id, 'closed'));
  assert.notEqual(invoke('systemctl', ['show', '--value', '-p', 'ActiveState', active.browser_unit]), 'active');
  await assert.rejects(lstat('/run/blindpass-browser-'+active.browser_unit.slice('blindpass-browser@'.length, -'.service'.length)), { code: 'ENOENT' });
  assert.equal(await cookieStatus(copiedCookie), 401);
  const final = await events(); assert.equal(final.filter(event => event.kind === 'operation_result').length, 1); assert.ok(final.filter(event => event.kind === 'operation_result').every(event => !provisional.some(old => old.idempotency_key === event.idempotency_key)));
  assert.equal(loginCount, 1); assert.equal(clockFailure, false);
  await scanJournal({ units: [brokerUnit, 'blindpass-login-helper@*', 'blindpass-runtime-manager@*', 'blindpass-browser@*', 'blindpass-browser-supervisor@*', unit], canaries: [password, adminToken, copiedCookie.split('=')[1]] });
  stage = 'restart-request';
  const secondRequest = `request:${Buffer.from(canonical({ action: 'browser.session', mode: 'browser_session', purpose: 'read report', resource_id: 'report-primary', ttl_seconds: 120, request_key: 'coordinator_2222222222222222' })).toString('base64url')}`;
  const secondReply = await work(secondRequest); const secondKey = secondReply.trim().split(' ').at(-1); assert.notEqual(secondKey, key);
  const secondIssued = Date.now();
  await relay('grant', { id: `gr_${'2'.repeat(32)}`, operation_id: `op_${'2'.repeat(32)}`, node_id: 'node-a', workload_id: 'p05-agent', invocation_id: invocation, unit, account: `uid:${uid}`, resource_id: 'report-primary', recipient_key_id: 'node-a-1', registration_version: 1, policy_version: 1, request_event_key: secondKey, action: 'browser.session', mode: 'browser_session', audience: 'blindpass-node', issuer_epoch: 1, issued_at_ms: secondIssued, expires_at_ms: secondIssued + 120000, local_ceiling_seconds: 120 });
  stage = 'restart-ready'; await wait(async () => { const status = await work(`status:${secondKey}`); if (/^OK operation_status (cancelling|closed)/.test(status)) throw new Error('actor_withdrawn'); return status.startsWith('OK operation_status ready ctx_'); });
  const secondActive = findOperationRecord(JSON.parse(await readFile(journalPath, 'utf8')), `op_${'2'.repeat(32)}`, 'active'); assert.ok(secondActive?.browser_unit && secondActive.browser_invocation);
  const secondCookie = await copyCookie(); assert.equal(await cookieStatus(secondCookie), 200); assert.equal(loginCount, 2);
  stage = 'broker-sigkill'; clearInterval(clockTimer);
  // systemctl can race the unit's disappearance from its own kill request.
  // Accept only manager evidence of actual SIGKILL, never the command status.
  try { invoke('systemctl', ['kill', '--signal=SIGKILL', brokerUnit]); } catch {}
  stage = 'broker-sigkill-observe';
  await wait(() => {
    let fields; try { fields = invoke('systemctl', ['show', '-p', 'ActiveState', '-p', 'MainPID', '-p', 'ExecMainCode', '-p', 'ExecMainStatus', brokerUnit]); } catch { return false; }
    return /^ActiveState=failed$/m.test(fields) && /^MainPID=0$/m.test(fields) && /^ExecMainCode=2$/m.test(fields) && /^ExecMainStatus=9$/m.test(fields);
  }, 15000);
  stage = 'restart-recovery'; invoke('systemctl', ['restart', brokerUnit]);
  await refreshClock();
  clockTimer = setInterval(() => { refreshClock().catch(() => { clockFailure = true; }); }, 10000);
  // Ephemeral custody was lost with the process. Re-provision only admin for
  // recovery; source is deliberately absent, so recovery cannot repeat login.
  stage = 'recovery-admin-provision'; await provision('fixture-admin', 'blindpass-session-revoker@.service', adminToken);
  stage = 'recovery-account-close'; await wait(async () => findOperationRecord(JSON.parse(await readFile(journalPath, 'utf8')), secondActive.binding.operation_id, 'closed'));
  assert.equal(await cookieStatus(secondCookie), 401); assert.equal(loginCount, 2);
  assert.equal(await work(secondRequest), secondReply); assert.equal(loginCount, 2);
  const recoveryEvents = await events(); assert.equal(recoveryEvents.filter(event => event.kind === 'operation_result' && event.body.operation_id === secondActive.binding.operation_id && event.body.result_code === 'browser_session_closed').length, 1);
  assert.notEqual(invoke('systemctl', ['show', '--value', '-p', 'ActiveState', secondActive.browser_unit]), 'active');
  await assert.rejects(lstat('/run/blindpass-browser-'+secondActive.browser_unit.slice('blindpass-browser@'.length, -'.service'.length)), { code: 'ENOENT' });
  await scanJournal({ units: [brokerUnit, unit, 'blindpass-login-helper@*', 'blindpass-runtime-manager@*', 'blindpass-browser@*', 'blindpass-browser-supervisor@*'], canaries: [password, adminToken, copiedCookie.split('=')[1], secondCookie.split('=')[1]] });
  assert.equal(clockFailure, false);
  console.log('P05-COORDINATOR-VM signed_fixture_issuer=verified production_dispatch=verified hpke_source=verified broker_lock_during_login=available browser_identity_before_import=durable stock_reads=2 reconnects=1 copied_cookie_cancel=401 broker_sigkill_recovery=verified copied_cookie_restart=401 login_count=2 recovery_relogin=0 distinct_final_signed_result=verified source_canaries=absent scope=broker_runtime_not_controller_or_ai_clients');
} catch (error) {
  process.stderr.write(`P05-COORDINATOR-VM failed stage=${stage}\n`);
  process.stderr.write(`P05-COORDINATOR-VM clock_delivery_failed=${clockFailure}\n`);
  if (Number.isSafeInteger(error.status)) process.stderr.write(`P05-COORDINATOR-VM command_exit=${error.status}\n`);
  try { for (const property of ['ActiveState', 'LoadState', 'Result']) { const value = invoke('systemctl', ['show', '--value', '-p', property, brokerUnit]); if (/^[a-z-]{1,32}$/.test(value)) process.stderr.write(`P05-COORDINATOR-VM broker_${property}=${value}\n`); } } catch {}
  try {
    for (const line of invoke('systemctl', ['list-jobs', '--no-pager', '--no-legend']).split('\n')) {
      if (/^[0-9]+\s+[a-zA-Z0-9_.:@\\-]+\s+(start|stop|restart)\s+(running|waiting)\s*$/.test(line.trim())) process.stderr.write(`P05-COORDINATOR-VM manager_job=${line.trim()}\n`);
    }
    for (const line of invoke('systemctl', ['list-units', '--all', '--plain', '--no-pager', '--no-legend', 'blindpass-runtime-manager@*.service']).split('\n')) {
      const name = line.trim().split(/\s+/)[0];
      if (/^blindpass-runtime-manager@[a-zA-Z0-9_.:@-]+\.service$/.test(name)) {
        const value = invoke('systemctl', ['show', '-p', 'ActiveState', '-p', 'SubState', '-p', 'Result', '-p', 'TasksCurrent', name]);
        for (const field of value.split('\n')) if (/^(ActiveState|SubState|Result|TasksCurrent)=[a-z0-9-]{1,32}$/.test(field)) process.stderr.write(`P05-COORDINATOR-VM manager_${field}\n`);
      }
    }
  } catch {}
  try {
    const pid = invoke('systemctl', ['show', '--value', '-p', 'MainPID', brokerUnit]);
    if (/^[1-9][0-9]{0,9}$/.test(pid)) {
      for (const tid of (await readdir(`/proc/${pid}/task`)).slice(0,32)) if (/^[0-9]+$/.test(tid)) {
        const name = (await readFile(`/proc/${pid}/task/${tid}/comm`, 'utf8')).trim(); const wait = (await readFile(`/proc/${pid}/task/${tid}/wchan`, 'utf8')).trim();
        if (/^[a-zA-Z0-9_-]{1,32}$/.test(name) && /^[a-zA-Z0-9_.-]{1,64}$/.test(wait)) process.stderr.write(`P05-COORDINATOR-VM thread=${name} wait=${wait}\n`);
        if (name === 'bp-browser-disp') {
          try { const syscall = (await readFile(`/proc/${pid}/task/${tid}/syscall`, 'utf8')).trim().split(/\s+/);
            if (syscall[0] === '7' && /^0x[a-f0-9]{1,16}$/.test(syscall[3])) process.stderr.write(`P05-COORDINATOR-VM dispatcher_poll_timeout=${parseInt(syscall[3],16)}\n`);
          } catch {}
          try { for (const line of (await readFile(`/proc/${pid}/task/${tid}/stack`, 'utf8')).split('\n')) {
            const symbol = /^\[<[a-f0-9]+>\] ([a-zA-Z0-9_.]+)\+/.exec(line);
            if (symbol) process.stderr.write(`P05-COORDINATOR-VM dispatcher_kernel=${symbol[1]}\n`);
          } } catch {}
        }
      }
    }
  } catch {}
  try { const log = invoke('journalctl', ['--no-pager', '-o', 'cat', '-u', brokerUnit]);
    process.stderr.write(`P05-COORDINATOR-VM broker_panic=${log.includes('panicked at')}\n`);
    for (const line of log.split('\n')) {
      const panic = /^thread '([a-z-]{1,64})' panicked at ([a-zA-Z0-9_./-]+\.rs:[0-9]+:[0-9]+):$/.exec(line);
      if (panic) process.stderr.write(`P05-COORDINATOR-VM panic_thread=${panic[1]} location=${panic[2]}\n`);
    }
    for (const line of log.split('\n')) if (/^blindpass-browser: (actor_failed|recovery_waiting|startup_recovery_waiting|record_released) stage=[a-z-]+$/.test(line) || /^blindpass-browser: (startup_recovery_complete|journal_unfenced)$/.test(line)) process.stderr.write(line+'\n');
    const records = JSON.parse(await readFile(journalPath, 'utf8')).records;
    for (const record of records) if (['reserved','active','revoking','blocked_uncertain','closed'].includes(record.state)) process.stderr.write(`P05-COORDINATOR-VM state=${record.state} helper_bound=${Boolean(record.helper_unit)} browser_bound=${Boolean(record.browser_unit)} handle_bound=${Boolean(record.revoke_handle)}\n`);
  } catch {} process.exitCode = 70;
  const diagnosticHold = Number(process.env.BLINDPASS_P05_DIAGNOSTIC_HOLD_SECONDS ?? 0);
  if (Number.isInteger(diagnosticHold) && diagnosticHold > 0 && diagnosticHold <= 240) {
    process.stderr.write(`P05-COORDINATOR-VM diagnostic_hold_seconds=${diagnosticHold}\n`);
    await new Promise(resolve => setTimeout(resolve, diagnosticHold * 1000));
  }
}
finally {
  clearInterval(clockTimer); releaseLogin(); if (agent) { agent.send({ type: 'stop' }); await agent.closed; }
  for (const name of [brokerUnit, unit]) { try { invoke('systemctl', ['stop', name]); } catch {} }
  await app.close(); await tls.close(); await rm(directory, { recursive: true, force: true }); await rm('/etc/blindpass', { recursive: true, force: true }); await rm('/run/blindpass', { recursive: true, force: true });
}
