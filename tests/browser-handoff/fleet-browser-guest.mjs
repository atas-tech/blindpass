// SPDX-License-Identifier: AGPL-3.0-only
// P05-PC08: real controller -> unprivileged node -> broker -> private helper
// -> kernel-bound browser/stock tool. Disposable admin seed; no useful AI client claim.
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { mkdir, rm, writeFile, readFile, chown, lstat } from 'node:fs/promises';
import { request } from 'node:https';
import { createInterface } from 'node:readline';
import { createPublicKey, createHash, randomBytes } from 'node:crypto';
import { createTestTls } from './fixture-app/test-tls.mjs';
import { startFixture } from './fixture-app/server.mjs';
import { findOperationRecord } from './coordinator-journal.mjs';
import { startFleetController, runPrivate, waitFor, approveBrowserOperation, isProvisionalBrowserOperation, isConfirmedBrowserClosure } from './fleet-controller-fixture.mjs';
import { guestBrowserProfile, copiedSession } from './guest-browser-profile.mjs';
import { startManagedFleetApp } from './managed-fleet-app.mjs';
import { runAiTask } from './ai-task-guest.mjs';
import { scanJournal } from './journal-canary-scan.mjs';
import { startShippedBroker } from './shipped-broker-unit.mjs';
const node = '/usr/lib/blindpass/login/runtime/bin/node';
const directory = '/run/p05-browser-agent';
const brokerUnit = 'blindpass-broker.service'; // the shipped unit, see shipped-broker-unit.mjs
const aiClient = process.env.BLINDPASS_P05_AI_CLIENT;
if (aiClient !== undefined && !['claude', 'codex'].includes(aiClient)) throw new Error('invalid_ai_client');
const unit = aiClient ? `p05-ai-${aiClient}.service` : 'p05-browser-agent.service';
const agentDirectory = aiClient ? `/run/p05-ai-${aiClient}` : directory;
const invoke = (cmd, args) => execFileSync(cmd, args, { stdio: ['ignore', 'pipe', 'pipe'], encoding: 'utf8' }).trim();
function sort(value) { if (Array.isArray(value)) return value.map(sort); if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map(key => [key, sort(value[key])])); return value; }
const canonical = value => JSON.stringify(sort(value));
const wait = waitFor;
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
const tls = await createTestTls(); const password = `P05-FLEET-BROWSER-SOURCE-${randomBytes(24).toString('hex')}`; const adminToken = randomBytes(32).toString('hex');
const browserProfile = guestBrowserProfile(process.env.BLINDPASS_P05_BROWSER_APP);
const certificateSpkiPins = [createHash('sha256').update(createPublicKey(tls.cert).export({ type: 'spki', format: 'der' })).digest('base64')];
let releaseLogin; const loginLatch = new Promise(resolve => { releaseLogin = resolve; });
let loginCount = 0; let verifiedLoginCount = 0; let observerFailed = false; let reservedRecords = 0;
const journalPath = '/var/lib/blindpass/broker/sessions/state.json';
const observeLogin = async () => {
  // Count the actual POST before validating the observer; a failed test
  // assertion must never be reported as zero authentication attempts.
  loginCount++;
  try {
    const current = JSON.parse(await readFile(journalPath, 'utf8')).records.filter(record => record.state === 'reserved' && record.helper_unit);
    reservedRecords = current.length;
    assert.equal(current.length, 1); assert.equal(invoke('systemctl', ['show', '--value', '-p', 'InvocationID', current[0].helper_unit]), current[0].helper_invocation);
    verifiedLoginCount++;
  } catch { observerFailed = true; throw new Error('fixture_helper_binding_failed'); }
  await loginLatch;
};
let app;
try {
  app = browserProfile.kind === 'grafana-managed'
    ? await startManagedFleetApp({ home: '/usr/lib/blindpass/grafana', tls, password, isolationPassword: randomBytes(24).toString('hex'), observeLogin, certificateSpkiPins })
    : await startFixture({ ...tls, adminToken, accounts: [{ username: 'primary', password, report: 'Coordinator report: 12 artifacts' }, { username: 'isolation', password: randomBytes(24).toString('hex'), report: 'Isolation report' }], observeLogin });
} catch { await tls.close(); process.stderr.write('P05-FLEET-BROWSER-VM failed stage=application-setup\n'); process.exit(70); }
let stage = 'setup'; let agent; let aiChild; let aiClosed; let controller; let nodeId; let workloadId;
try {
  assert.equal(process.getuid(), 0);
  try { invoke('useradd', ['--system', '--no-create-home', '--shell', '/usr/sbin/nologin', 'p05-browser-agent']); } catch { invoke('id', ['p05-browser-agent']); }
  const uid = Number(invoke('id', ['-u', 'p05-browser-agent'])); const gid = Number(invoke('id', ['-g', 'p05-browser-agent']));
  stage = 'controller-start'; controller = await startFleetController();
  try { invoke('useradd', ['--system', '--no-create-home', '--shell', '/usr/sbin/nologin', 'blindpass-node']); } catch { invoke('id', ['blindpass-node']); }
  stage = 'enrollment-broker';
  invoke('systemd-run', ['--quiet', '--unit=p05-enrollment-broker', '-p', 'Type=notify', '-p', 'NotifyAccess=main', '-p', 'RuntimeMaxSec=480s', '-p', 'LimitCORE=0', '/usr/lib/blindpass/login/blindpass-broker', '--node-group', 'blindpass-node']);
  const enrollment = await controller.api('/api/v3/enrollments', 'POST', { name: 'P05 real browser node' });
  stage = 'actual-node-enrollment';
  const enrollmentBytes = await runPrivate('/usr/lib/blindpass/login/blindpass-node', ['enroll', '--controller', controller.controllerOrigin, '--issuer-fingerprint', controller.issuerFingerprint, '--token-stdin'], { input: enrollment.token });
  const submitted = enrollmentBytes.toString(); enrollmentBytes.fill(0); delete enrollment.token;
  nodeId = submitted.match(/node_id=([A-Za-z0-9_-]+)/)?.[1];
  const fingerprint = submitted.match(/fingerprint=([a-f0-9]{64})/)?.[1];
  assert.equal(nodeId, enrollment.node_id); assert.match(fingerprint, /^[a-f0-9]{64}$/);
  const details = await controller.api(`/api/v3/enrollments/${enrollment.id}`);
  assert.equal(details.fingerprint, fingerprint);
  await controller.api(`/api/v3/enrollments/${enrollment.id}/approve`, 'POST', { expected_fingerprint: fingerprint, expected_version: details.version }, true, { 'if-match': `"${details.version}"` });
  stage = 'policy-and-workload';
  const policy = await controller.api('/api/v3/policies');
  await controller.api('/api/v3/policies', 'PUT', { expected_version: policy.version, rules: [{ id: 'p05-browser-approval', action: 'browser.session', mode: 'browser_session', decision: 'pending_approval', approval_required: true, approver_ids: [controller.adminId], max_ttl_seconds: 120 }] }, true, { 'if-match': `"${policy.version}"` });
  const workload = await controller.api('/api/v3/workloads', 'POST', { node_id: nodeId, name: 'P05 report reader', unit, account: `uid:${uid}`, consumption_mode: 'browser_session', local_ceiling_seconds: 120 });
  workloadId = workload.id; assert.match(workloadId, /^wl_[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/);
  invoke('systemctl', ['stop', 'p05-enrollment-broker.service']);
  await mkdir(agentDirectory, { mode: 0o755 });
  for (const name of ['output', 'home', ...(aiClient ? ['home/tmp'] : [])]) { await mkdir(`${agentDirectory}/${name}`, { mode: 0o700 }); await chown(`${agentDirectory}/${name}`, uid, gid); }
  await writeFile(`${agentDirectory}/stock-config.json`, JSON.stringify({ browser: { browserName: 'chromium', cdpEndpoint: `ws+unix:/run/blindpass/browser/${workloadId}/cdp.sock:/current`, cdpTimeout: 10000 }, saveSession: false, outputMode: 'stdout', outputDir: `${agentDirectory}/output`, snapshot: { mode: 'full' } }), { mode: aiClient ? 0o640 : 0o600 }); await chown(`${agentDirectory}/stock-config.json`, aiClient ? 0 : uid, gid);
  const child = spawn('/usr/bin/systemd-run', ['--quiet', '--wait', '--pipe', '--collect', `--unit=${unit.slice(0, -'.service'.length)}`, '-p', 'User=p05-browser-agent', '-p', 'Group=p05-browser-agent', '-p', 'NoNewPrivileges=yes', '-p', 'LimitCORE=0', '-p', 'RuntimeMaxSec=480s', '-p', 'TimeoutStopSec=5s', '-p', `WorkingDirectory=${agentDirectory}/output`,
    ...(aiClient ? ['-p', 'UMask=0077', '-p', 'ProtectSystem=strict', '-p', 'ProtectHome=yes', '-p', `ReadWritePaths=${agentDirectory}/home ${agentDirectory}/output`, '-p', 'CapabilityBoundingSet=', '-p', 'RestrictAddressFamilies=AF_UNIX', '-E', `TMPDIR=${agentDirectory}/home/tmp`, '-E', 'BLINDPASS_FLEET_MCP=1', '-E', `BLINDPASS_NODE_ID=${nodeId}`, '-E', `BLINDPASS_WORKLOAD_ID=${workloadId}`, '-E', `BLINDPASS_WORKLOAD_UNIT=${unit}`] : []),
    '-E', `BLINDPASS_P05_NODE_ID=${nodeId}`, '-E', `BLINDPASS_P05_WORKLOAD_ID=${workloadId}`, '-E', `BLINDPASS_P05_BROWSER_APP=${browserProfile.kind}`, '-E', `HOME=${agentDirectory}/home`, '-E', `XDG_CACHE_HOME=${agentDirectory}/home/cache`, node, aiClient ? '/tmp/browser-handoff/ai-client-agent-guest.mjs' : '/tmp/browser-handoff/isolated-browser-agent.mjs'], { stdio: ['pipe', 'pipe', 'pipe'] });
  if (aiClient) { aiChild = child; aiClosed = new Promise(resolve => child.once('close', resolve)); await wait(async () => { try { return /^[a-f0-9]{32}$/.test(invoke('systemctl', ['show', '--value', '-p', 'InvocationID', unit])); } catch { return false; } }, 5000); }
  else { agent = controlled(child); await agent.next('agent-ready'); }
  const invocation = invoke('systemctl', ['show', '--value', '-p', 'InvocationID', unit]); assert.match(invocation, /^[a-f0-9]{32}$/);
  await mkdir('/etc/blindpass', { mode: 0o700 });
  const configuration = app.configuration ?? { kind: 'fixture', origin: app.origin, account: 'primary', sessionMaxMs: 300000, certificateSpkiPins };
  await writeFile('/etc/blindpass/browser-resources.json', canonical({ version: 1, resources: [{ resource_id: 'report-primary', workload_ids: [workloadId], credential_unit: 'blindpass-login-helper@.service', credential_name: 'primary-password', revocation: app.revocation ?? { kind: 'fixture-admin', credential_unit: 'blindpass-session-revoker@.service', credential_name: 'fixture-admin' }, configuration }] }), { mode: 0o600 });
  for (const [path, group] of [['/run/blindpass-helper-identity', 'blindpass-login'], ['/run/blindpass-runtime', 'blindpass-runtime']]) { await mkdir(path, { recursive: true, mode: 0o750 }); invoke('chown', [`root:${group}`, path]); }
  stage = 'broker-start';
  // The shipped unit and browser-runtime drop-in (installed by private-helper-guest.sh) run unchanged
  // apart from the generated guest drop-in (workload group, per-run --workload, test-only overrides).
  await startShippedBroker({ workloadGroup: 'p05-browser-agent', workload: `${nodeId}:${workloadId}:${unit}:${uid}:${invocation}`, runtimeMaxSec: 480 });
  stage = 'actual-node-channel';
  invoke('systemd-run', ['--quiet', '--unit=p05-fleet-node', '-p', 'User=blindpass-node', '-p', 'Group=blindpass-node', '-p', 'NoNewPrivileges=yes', '-p', 'LimitCORE=0', '-p', 'RuntimeMaxSec=480s', '-p', 'StateDirectory=blindpass/p05-node', '-p', 'StateDirectoryMode=0700', '-p', 'UMask=0077', '-p', 'ProtectSystem=strict', '-p', 'ProtectHome=yes', '-p', 'ReadWritePaths=/var/lib/blindpass/p05-node', '-p', 'InaccessiblePaths=/var/lib/blindpass/broker', '-p', 'MemoryDenyWriteExecute=yes', '-p', 'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6', '-p', 'CapabilityBoundingSet=', '/usr/lib/blindpass/login/blindpass-node', 'run', '--controller', controller.controllerOrigin, '--state-dir', '/var/lib/blindpass/p05-node']);
  await wait(async () => (await controller.api(`/api/v3/nodes/${nodeId}`)).status === 'online');
  // Registration, policy and clock arrive only through the real node channel.
  await wait(async () => { try { const registration = JSON.parse(await readFile(`/var/lib/blindpass/broker/fleet-registration-${workloadId}.json`, 'utf8')); return JSON.stringify(registration).includes(workloadId); } catch { return false; } });
  stage = 'hpke-provision'; await provision('primary-password', 'blindpass-login-helper@.service', password); await provision('fixture-admin', 'blindpass-session-revoker@.service', app.administrator ?? adminToken);
  function cookieStatus(cookie, path = browserProfile.replayPath, method = 'GET', body) { return new Promise((resolve, reject) => { const req = request(`${app.origin}${path}`, { ca: tls.ca, method, headers: { cookie, ...(body ? { 'content-type': 'application/json' } : {}) }, timeout: 5000 }, response => { response.resume(); response.once('end', () => resolve(response.statusCode)); }); req.once('error', () => reject(new Error('replay_transport_failed'))); req.once('timeout', () => req.destroy()); req.end(body ? JSON.stringify(body) : undefined); }); }
  if (aiClient) {
    stage = 'ai-client-task';
    await runAiTask({ name: aiClient, child: aiChild, controller, app, browserProfile,
      canaries: [password, adminToken, app.administrator ?? adminToken], releaseLogin, cookieStatus, brokerUnit,
      loginState: () => ({ count: loginCount, verified: verifiedLoginCount, failed: observerFailed }) });
  } else {
  async function work(operation) { agent.send({ type: 'work', operation }); const result = await agent.next('work-result'); assert.ok(!result.failed); return result.reply; }
  stage = 'request';
  const reply = await work(`request:${Buffer.from(canonical({ action: 'browser.session', mode: 'browser_session', purpose: 'read report', resource_id: 'report-primary', ttl_seconds: 120, request_key: 'coordinator_1111111111111111' })).toString('base64url')}`);
  const key = reply.trim().split(' ').at(-1); assert.match(key, /^event_[A-Za-z0-9_-]{16,100}$/);
  stage = 'actual-approval-and-grant'; const firstOperation = await approveBrowserOperation(controller, key);
  stage = 'login-outside-lock'; await wait(() => loginCount === 1);
  assert.equal(observerFailed, false); assert.equal(verifiedLoginCount, 1);
  // The application HTTP endpoint stays responsive while private login is held.
  stage = 'provisional-controller-result';
  await wait(async () => isProvisionalBrowserOperation(await controller.api(`/api/v3/operations/${firstOperation.id}`)));
  releaseLogin(); stage = 'ready'; let status;
  await wait(async () => { status = await work(`status:${key}`); if (/^OK operation_status (cancelling|closed)/.test(status)) throw new Error('actor_withdrawn'); return status.startsWith('OK operation_status ready ctx_'); }); assert.match(status, /^OK operation_status ready ctx_[a-f0-9]{64}\n$/);
  const active = findOperationRecord(JSON.parse(await readFile(journalPath, 'utf8')), firstOperation.id, 'active'); assert.ok(active?.browser_unit && active.browser_invocation);
  assert.equal(invoke('systemctl', ['show', '--value', '-p', 'InvocationID', active.browser_unit]), active.browser_invocation);
  const stateBytes = await readFile(journalPath); assert.ok(!stateBytes.includes(Buffer.from(password))); assert.ok(!stateBytes.includes(Buffer.from(adminToken))); stateBytes.fill(0);
  stage = 'stock-task'; agent.send({ type: 'run', origin: app.origin }); const task = await agent.next('task-result');
  if (!task.passed && /^(initialize|navigate|snapshot|report-wait)-[01]$/.test(task.stage)) process.stderr.write(`P05-STOCK-TASK failed stage=${task.stage} stderr_bytes=${Number.isSafeInteger(task.stderrBytes) ? task.stderrBytes : 'invalid'}\n`);
  assert.ok(task.passed); stage = 'stock-task-output'; assert.equal(task.stderrBytes, 0); assert.equal(task.messages.length, 2);
  stage = 'stock-report-snapshot';
  const visible = JSON.stringify(task.messages); assert.ok(visible.includes('Coordinator report: 12 artifacts')); for (const canary of [password, adminToken, 'Isolation report', 'ws+unix:', '/devtools/browser/']) assert.ok(!visible.includes(canary));
  async function copyCookie() {
    agent.send({ type: 'copy-session' }); const copied = await agent.next('copied-session'); assert.ok(copied.passed); assert.equal(copied.stderrBytes, 0);
    return copiedSession(JSON.stringify(copied.copied), browserProfile);
  }
  stage = 'copyable-session'; const copiedCookie = await copyCookie(); assert.ok(!visible.includes(copiedCookie.split(';')[0].split('=')[1])); assert.equal(await cookieStatus(copiedCookie), 200);
  if (browserProfile.kind === 'grafana-managed') {
    stage = 'managed-durable-mutations';
    for (const [path, method, body] of [
      ['/api/user', 'PUT', { login: 'primary', name: 'Changed', email: 'changed@example.invalid' }],
      ['/api/user/password', 'PUT', { oldPassword: password, newPassword: 'dummy-new-password', confirmNew: 'dummy-new-password' }],
      ['/api/serviceaccounts', 'POST', { name: 'unapproved', role: 'Admin' }],
      ['/api/datasources', 'POST', { name: 'unapproved', type: 'prometheus', url: 'https://example.invalid', access: 'proxy' }],
    ]) assert.equal(await cookieStatus(copiedCookie, path, method, body), 403);
    assert.equal(await cookieStatus(copiedCookie, '/api/user/password/send-reset-email', 'POST', { userOrEmail: 'primary@example.invalid' }), 401);
    assert.equal(app.oauthMetrics().credentialAccepts, 2); // One app bootstrap plus one operation.
  }
  stage = 'cancel-cleanup'; assert.match(await work(`cancel:${key}`), /^OK /);
  await wait(async () => findOperationRecord(JSON.parse(await readFile(journalPath, 'utf8')), active.binding.operation_id, 'closed'));
  assert.notEqual(invoke('systemctl', ['show', '--value', '-p', 'ActiveState', active.browser_unit]), 'active');
  await assert.rejects(lstat('/run/blindpass-browser-'+active.browser_unit.slice('blindpass-browser@'.length, -'.service'.length)), { code: 'ENOENT' });
  assert.equal(await cookieStatus(copiedCookie), 401);
  stage = 'controller-cancellation-result';
  await wait(async () => isConfirmedBrowserClosure(await controller.api(`/api/v3/operations/${firstOperation.id}`)));
  const final = await controller.api(`/api/v3/operations/${firstOperation.id}`);
  assert.equal(final.status, 'revoked'); assert.equal(final.result?.result_code, 'browser_session_closed'); assert.equal(loginCount, 1);
  await scanJournal({ units: [brokerUnit, 'blindpass-login-helper@*', 'blindpass-runtime-manager@*', 'blindpass-browser@*', 'blindpass-browser-supervisor@*', unit], canaries: [password, adminToken, copiedCookie.split(';')[0].split('=')[1]] });
  stage = 'restart-request';
  const secondRequest = `request:${Buffer.from(canonical({ action: 'browser.session', mode: 'browser_session', purpose: 'read report', resource_id: 'report-primary', ttl_seconds: 120, request_key: 'coordinator_2222222222222222' })).toString('base64url')}`;
  const secondReply = await work(secondRequest); const secondKey = secondReply.trim().split(' ').at(-1); assert.notEqual(secondKey, key);
  const secondOperation = await approveBrowserOperation(controller, secondKey);
  stage = 'restart-ready'; await wait(async () => { const status = await work(`status:${secondKey}`); if (/^OK operation_status (cancelling|closed)/.test(status)) throw new Error('actor_withdrawn'); return status.startsWith('OK operation_status ready ctx_'); });
  const secondActive = findOperationRecord(JSON.parse(await readFile(journalPath, 'utf8')), secondOperation.id, 'active'); assert.ok(secondActive?.browser_unit && secondActive.browser_invocation);
  const secondCookie = await copyCookie(); assert.equal(await cookieStatus(secondCookie), 200); assert.equal(loginCount, 2);
  stage = 'broker-sigkill';
  // systemctl can race the unit's disappearance from its own kill request.
  // Accept only manager evidence of actual SIGKILL, never the command status.
  try { invoke('systemctl', ['kill', '--signal=SIGKILL', brokerUnit]); } catch {}
  stage = 'broker-sigkill-observe';
  await wait(() => {
    let fields; try { fields = invoke('systemctl', ['show', '-p', 'ActiveState', '-p', 'MainPID', '-p', 'ExecMainCode', '-p', 'ExecMainStatus', brokerUnit]); } catch { return false; }
    return /^ActiveState=failed$/m.test(fields) && /^MainPID=0$/m.test(fields) && /^ExecMainCode=2$/m.test(fields) && /^ExecMainStatus=9$/m.test(fields);
  }, 15000);
  stage = 'restart-recovery'; invoke('systemctl', ['restart', brokerUnit]);
  // Ephemeral custody was lost with the process. Re-provision only admin for
  // recovery; source is deliberately absent, so recovery cannot repeat login.
  stage = 'recovery-admin-provision'; await provision('fixture-admin', 'blindpass-session-revoker@.service', app.administrator ?? adminToken);
  stage = 'recovery-account-close'; await wait(async () => findOperationRecord(JSON.parse(await readFile(journalPath, 'utf8')), secondActive.binding.operation_id, 'closed'));
  assert.equal(await cookieStatus(secondCookie), 401); assert.equal(loginCount, 2);
  assert.equal(await work(secondRequest), secondReply); assert.equal(loginCount, 2);
  stage = 'controller-recovery-result';
  await wait(async () => isConfirmedBrowserClosure(await controller.api(`/api/v3/operations/${secondOperation.id}`)));
  const recovered = await controller.api(`/api/v3/operations/${secondOperation.id}`);
  assert.equal(recovered.result?.result_code, 'browser_session_closed');
  assert.equal(verifiedLoginCount, 2); assert.equal(observerFailed, false);
  if (browserProfile.kind === 'grafana-managed') assert.equal(app.oauthMetrics().credentialAccepts, 3);
  assert.notEqual(invoke('systemctl', ['show', '--value', '-p', 'ActiveState', secondActive.browser_unit]), 'active');
  await assert.rejects(lstat('/run/blindpass-browser-'+secondActive.browser_unit.slice('blindpass-browser@'.length, -'.service'.length)), { code: 'ENOENT' });
  await scanJournal({ units: [brokerUnit, unit, 'blindpass-login-helper@*', 'blindpass-runtime-manager@*', 'blindpass-browser@*', 'blindpass-browser-supervisor@*'], canaries: [password, adminToken, copiedCookie.split(';')[0].split('=')[1], secondCookie.split(';')[0].split('=')[1]] });
  console.log('P05-FLEET-BROWSER-VM actual_controller=sqlite actual_node=unprivileged actual_enrollment=verified actual_policy_approval=verified signed_channel=verified production_dispatch=verified hpke_source=verified browser_identity_before_import=durable stock_reads=2 reconnects=1 copied_cookie_cancel=401 broker_sigkill_recovery=verified copied_cookie_restart=401 login_count=2 recovery_relogin=0 controller_final_result=verified source_canaries=absent scope=controller_node_runtime_not_ai_clients_or_two_hosts');
  if (browserProfile.kind === 'grafana-managed') console.log('P05-MANAGED-FLEET-VM grafana=13.2.3 external_viewer=true setup_logins=1 operation_logins=2 recovery_logins=0 durable_mutations=403 recovery_api=401 fixed_root_backend=verified copied_session_cancel=401 copied_session_restart=401 scope=integrated_controller_node_browser_not_ai_client_or_full_lifetime_matrix');
  }
} catch (error) {
  process.stderr.write(`P05-FLEET-BROWSER-VM failed stage=${stage}\n`);
  process.stderr.write(`P05-FLEET-BROWSER-VM login_posts=${loginCount} verified_login_posts=${verifiedLoginCount} observer_failed=${observerFailed} reserved_records=${reservedRecords}\n`);
  if (error.code === 'ERR_ASSERTION') process.stderr.write('P05-FLEET-BROWSER-VM cause=driver_assertion\n');
  if (/^(fleet_controller_http_[0-9]{3}|fleet_controller_setup_[a-z-]+_failed|private_command_failed|fleet_guest_state_deadline|agent_deadline)$/.test(error.message)) process.stderr.write(`P05-FLEET-BROWSER-VM cause=${error.message}\n`);
  try { const log = invoke('journalctl', ['--no-pager', '-o', 'cat', '-u', brokerUnit]);
    for (const line of log.split('\n')) if (/^blindpass-browser: (actor_failed|recovery_waiting|startup_recovery_waiting|record_released) stage=[a-z-]+$/.test(line) || /^blindpass-browser: (startup_recovery_complete|journal_unfenced)$/.test(line) || /^blindpass-browser: helper_reply_failed code=(unavailable|uncertain|authentication_failed|login_failed|timed_out|unsupported_authentication|invalid_configuration|binding_mismatch|unsafe_configuration|invalid_request)$/.test(line)) process.stderr.write(line+'\n');
  } catch {}
  process.exitCode = 70;
}
finally {
  releaseLogin(); if (agent) { agent.send({ type: 'stop' }); await agent.closed; }
  if (aiChild) { aiChild.stdin.end(); try { invoke('systemctl', ['stop', unit]); } catch {} await aiClosed; }
  for (const name of ['p05-fleet-node.service', 'p05-enrollment-broker.service', brokerUnit, unit]) { try { invoke('systemctl', ['stop', name]); } catch {} }
  if (controller) await controller.close();
  await app.close(); await tls.close(); await rm(agentDirectory, { recursive: true, force: true }); await rm('/etc/blindpass', { recursive: true, force: true }); await rm('/run/blindpass', { recursive: true, force: true });
}
