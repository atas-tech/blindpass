// SPDX-License-Identifier: AGPL-3.0-only
// Real systemd/namespace/stock-tool probe. Root orchestration here is a test
// driver. Native proxy peer checks are real; the lease is synthetic, not a signed grant.
import assert from 'node:assert/strict';
import { createHash, createPublicKey, randomBytes } from 'node:crypto';
import { request } from 'node:https';
import { connect } from 'node:net';
import { execFileSync, spawn } from 'node:child_process';
import { chmod, chown, lstat, mkdir, readFile, readlink, rm, writeFile } from 'node:fs/promises';
import { createInterface } from 'node:readline';
import { createTestTls } from './fixture-app/test-tls.mjs';
import { startFixture } from './fixture-app/server.mjs';
import { waitRuntimeRemoval } from './runtime-cleanup.mjs';
import { scanDirectory, scanJournal, writeScanMarker } from './journal-canary-scan.mjs';
import { attachFramedStream } from '/usr/lib/blindpass/login/src/browser-transport.mjs';
import { parseSupervisorBoottime, privateBackendPath } from '/usr/lib/blindpass/login/src/browser-supervisor-worker.mjs';

const NODE = '/usr/lib/blindpass/login/runtime/bin/node';
const directory = '/run/p05-browser-agent';
const socketPath = '/run/blindpass/browser/p05-agent/cdp.sock';
const operationId = 'p05_outside_supervisor_probe';
const backendPath = privateBackendPath(operationId);
const configPath = `${directory}/stock-config.json`;
const password = `P05-NAMESPACE-SOURCE-CANARY-${randomBytes(24).toString('hex')}`;
const adminToken = randomBytes(32).toString('hex');
const tls = await createTestTls();
const app = await startFixture({ ...tls, adminToken, accounts: [
  { username: 'primary', password, report: 'Namespace report: 12 artifacts' },
  { username: 'isolation', password: randomBytes(24).toString('hex'), report: 'Isolation report' },
] });
let stage = 'private-login'; let channel; let supervisor; let supervisorClosed; let browserUnit; let supervisorUnit; let rootClientUnit; let agent; let native; let runtimeProof;
let proofCanary = '';
let supervisorNormalBytes = 0;
const waits = new Map();
const boottime = async () => parseSupervisorBoottime(await readFile('/proc/uptime', 'utf8'));
function wait(type, timeout = 20_000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { waits.delete(type); reject(new Error('private channel deadline')); }, timeout);
    waits.set(type, (message) => { clearTimeout(timer); resolve(message); });
  });
}
// Resolves once no new message has arrived on a controlled channel for quietMs (bounded by maxMs).
async function quiet(channel, { quietMs = 400, maxMs = 5_000 } = {}) {
  const started = performance.now(); let seen = channel.received; let last = started;
  while (performance.now() - started < maxMs) {
    await new Promise((resolve) => setTimeout(resolve, 50));
    if (channel.received !== seen) { seen = channel.received; last = performance.now(); }
    else if (performance.now() - last >= quietMs) return;
  }
}
const show = (unit, fields) => execFileSync('/usr/bin/systemctl', ['show', unit, ...fields.flatMap((field) => ['-p', field])], { encoding: 'utf8' });
function field(text, name) { return text.match(new RegExp(`^${name}=(.*)$`, 'm'))?.[1]; }
async function send(path, { body, cookie } = {}) {
  return new Promise((resolve, reject) => {
    const req = request(`${app.origin}${path}`, { ca: tls.ca, method: body ? 'POST' : 'GET', headers: {
      ...(cookie ? { cookie } : {}), ...(body ? { authorization: `Bearer ${adminToken}`, 'content-type': 'application/json' } : {}),
    } }, (res) => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
    req.on('error', () => reject(new Error('app request unavailable'))); req.end(body ? JSON.stringify(body) : undefined);
  });
}
function controlled(child) {
  const messages = []; const pending = new Map(); const stderr = [];
  let received = 0;
  const closed = new Promise((resolve) => child.on('close', resolve));
  child.stderr.on('data', (bytes) => stderr.push(bytes)); child.stdin.on('error', () => {});
  createInterface({ input: child.stdout }).on('line', (line) => {
    try {
      // Every message gets its arrival sequence from this driver (never from the probe), so a later
      // request can be bound to "outcomes that arrived after it was sent".
      const message = JSON.parse(line); message.sequence = ++received; const accept = pending.get(message.type);
      if (accept) { pending.delete(message.type); accept(message); } else messages.push(message);
    } catch { child.kill(); }
  });
  return { child, stderr, closed, get received() { return received; }, mark() { return received; },
    // Removes and returns every queued message of one type, oldest first.
    drain(type) { const taken = messages.filter((message) => message.type === type); for (const message of taken) messages.splice(messages.indexOf(message), 1); return taken; },
    async nextAfter(type, marker, timeout) { const message = await this.next(type, timeout); assert.ok(message.sequence > marker, 'message predates the bound request'); return message; },
    next(type, timeout = 35_000) {
    const index = messages.findIndex((message) => message.type === type);
    if (index >= 0) return Promise.resolve(messages.splice(index, 1)[0]);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { pending.delete(type); reject(new Error('private control deadline')); }, timeout);
      pending.set(type, (message) => { clearTimeout(timer); resolve(message); });
    });
  }, send(value) {
    const line = `${JSON.stringify(value)}\n`;
    if (value.type === 'stop') child.stdin.end(line); else child.stdin.write(line);
  } };
}
function startAgent() {
  return controlled(spawn('/usr/bin/systemd-run', ['--quiet', '--wait', '--pipe', '--collect', '--unit=p05-browser-agent',
    '-p', 'User=p05-browser-agent', '-p', 'Group=p05-browser-agent', '-p', 'NoNewPrivileges=yes', '-p', 'LimitCORE=0',
    '-p', 'RuntimeMaxSec=120s', '-p', 'TimeoutStopSec=5s',
    '-p', `WorkingDirectory=${directory}/output`, '-E', `HOME=${directory}/home`, '-E', `XDG_CACHE_HOME=${directory}/home/cache`,
    NODE, '/tmp/browser-handoff/isolated-browser-agent.mjs'], { stdio: ['pipe', 'pipe', 'pipe'] }));
}
async function otherUnitAttempt() {
  const python = 'import socket\ns=socket.socket(socket.AF_UNIX)\ns.settimeout(5)\ns.connect("/run/blindpass/browser/p05-agent/cdp.sock")\ns.sendall(b"GET /current HTTP/1.1\\r\\nHost: localhost\\r\\nX-Workload-Unit: p05-browser-agent.service\\r\\n\\r\\n")\nassert s.recv(1024).startswith(b"HTTP/1.1 403")\nprint("same_uid_denied")';
  const child = spawn('/usr/bin/systemd-run', ['--quiet', '--wait', '--pipe', '--collect', '--unit=p05-browser-other',
    '-p', 'User=p05-browser-agent', '-p', 'Group=p05-browser-agent', '/usr/bin/python3', '-c', python], { stdio: ['ignore', 'pipe', 'pipe'] });
  let output = ''; let errors = 0; child.stdout.on('data', (bytes) => { output += bytes; }); child.stderr.on('data', (bytes) => { errors += bytes.length; bytes.fill(0); });
  assert.equal(await new Promise((resolve) => child.on('close', resolve)), 0); assert.equal(errors, 0); assert.equal(output.trim(), 'same_uid_denied');
}

async function runtimeOtherUnitAttempt(uid, gid, challenge) {
  // Only the protected stdin carries the challenge, even for this deliberate
  // same-UID wrong-unit attempt. Never argv, environment or normal output.
  const python = 'import socket,json,sys,struct\ns=socket.socket(socket.AF_UNIX)\ns.settimeout(5)\ns.connect("/run/blindpass-runtime/identity.sock")\nb=json.dumps({"version":1,"challenge":sys.stdin.read()}).encode()\ns.sendall(struct.pack("!I",len(b))+b)\ns.shutdown(socket.SHUT_WR)\nassert s.recv(64)==b"ERR runtime_identity_denied\\n"\nprint("runtime_other_unit_denied")';
  const child = spawn('/usr/bin/systemd-run', ['--quiet', '--wait', '--pipe', '--collect', '--unit=p05-runtime-other',
    '-p', `User=${uid}`, '-p', `Group=${gid}`, '-p', 'SupplementaryGroups=blindpass-runtime',
    '-p', 'LimitCORE=0', '/usr/bin/python3', '-c', python], { stdio: ['pipe', 'pipe', 'pipe'] });
  let output = ''; let errors = 0;
  child.stdout.on('data', (bytes) => { output += bytes; bytes.fill(0); });
  child.stderr.on('data', (bytes) => { errors += bytes.length; bytes.fill(0); });
  child.stdin.on('error', () => {});
  const bytes = Buffer.from(challenge); child.stdin.end(bytes, () => bytes.fill(0));
  assert.equal(await new Promise((resolve) => child.on('close', resolve)), 0);
  assert.equal(errors, 0); assert.equal(output.trim(), 'runtime_other_unit_denied');
}

function privateChallenge(child) {
  return new Promise((resolve, reject) => {
    const bytes = Buffer.alloc(64); let used = 0;
    child.stdio[3].on('data', (chunk) => {
      if (used + chunk.length > bytes.length) { chunk.fill(0); bytes.fill(0); child.kill(); reject(new Error('private proof unavailable')); return; }
      chunk.copy(bytes, used); used += chunk.length; chunk.fill(0);
    });
    child.stdio[3].once('end', () => {
      try {
        assert.equal(used, 64); const challenge = bytes.toString('ascii'); assert.match(challenge, /^[a-f0-9]{64}$/); resolve(challenge);
      } catch { reject(new Error('private proof unavailable')); }
      finally { bytes.fill(0); }
    });
    child.stdio[3].once('error', () => { bytes.fill(0); reject(new Error('private proof unavailable')); });
  });
}

async function supervisorExit(child, closed) {
  let timer;
  try {
    return await Promise.race([closed, new Promise((_, reject) => {
      timer = setTimeout(() => { child.kill?.('SIGKILL'); child.destroy?.(); reject(new Error('private supervisor deadline')); }, 5_000);
    })]);
  } finally { clearTimeout(timer); }
}

async function lostSupervisor(configuration, reason) {
  const child = spawn(NODE, ['/usr/lib/blindpass/login/src/browser-supervisor-worker.mjs'], {
    env: { PATH: '/usr/bin:/bin', HOME: '/nonexistent' }, stdio: ['ignore', 'pipe', 'pipe', 'pipe'],
  });
  const closed = new Promise(resolve => child.once('close', resolve)); let normalBytes = 0; let unit; let resolvePrepared;
  const preparedReply = new Promise(resolve => { resolvePrepared = resolve; });
  for (const stream of [child.stdout, child.stderr]) stream.on('data', bytes => { normalBytes += bytes.length; bytes.fill(0); });
  const control = attachFramedStream(child.stdio[3], { receive: message => resolvePrepared(message), onFailure: () => {} });
  let lossStage = 'start';
  try {
    await control.send({ type: 'start', version: 1, operationId: `p05_supervisor_loss_${reason}`, configuration,
      deadlineBoottimeMs: await boottime() + 30_000 });
    let prepareTimer; let prepared;
    try { prepared = await Promise.race([preparedReply, new Promise((_, reject) => {
      prepareTimer = setTimeout(() => reject(new Error('private prepare deadline')), 20_000);
    })]); } finally { clearTimeout(prepareTimer); }
    lossStage = 'prepared'; assert.equal(prepared.type, 'prepared');
    const candidates = execFileSync('/usr/bin/systemctl', ['list-units', 'blindpass-browser@*.service', '--state=running', '--no-legend', '--plain'], { encoding: 'utf8' })
      .trim().split('\n').filter(Boolean).map(line => line.split(/\s+/)[0]);
    lossStage = 'identity';
    unit = candidates.find(candidate => Number(field(show(candidate, ['MainPID']), 'MainPID')) === prepared.pid); assert.ok(unit);
    const identity = show(unit, ['ControlGroup', 'RuntimeDirectory', 'InvocationID', 'DynamicUser', 'PrivateNetwork']);
    assert.equal(field(identity, 'InvocationID'), prepared.invocation); assert.equal(field(identity, 'DynamicUser'), 'yes');
    assert.equal(field(identity, 'PrivateNetwork'), 'yes');
    const profile = `/run/${field(identity, 'RuntimeDirectory')}/profile`;
    const cgroup = `/sys/fs/cgroup${field(identity, 'ControlGroup')}/cgroup.procs`;
    const before = await boottime(); lossStage = 'supervisor-exit';
    if (reason === 'eof') control.close(); else child.kill('SIGKILL');
    assert.equal(await supervisorExit(child, closed), reason === 'eof' ? 0 : null);
    lossStage = 'runtime-removal';
    // Include supervisor exit in the original five-second bound, then require
    // both process disappearance and runtime-profile removal. Either alone is
    // insufficient manager teardown evidence.
    await waitRuntimeRemoval({ cgroup, profile, now: boottime, startedAt: before });
    const elapsed = await boottime() - before; assert.ok(elapsed < 5_000);
    lossStage = 'normal-output'; assert.equal(normalBytes, 0);
    return elapsed;
  } catch (error) {
    const code = ['cleanup_cgroup', 'cleanup_profile', 'cleanup_deadline'].includes(error.message) ? error.message : 'assertion_or_transport';
    process.stderr.write(`P05-SUPERVISOR-LOSS failed mode=${reason} stage=${lossStage} code=${code}\n`);
    throw new Error('supervisor_loss_failed');
  } finally {
    control.close(); child.kill('SIGKILL'); await closed;
    if (unit) execFileSync('/usr/bin/systemctl', ['stop', unit], { stdio: 'ignore' });
  }
}

try {
  stage = 'supervisor-invocation-denial';
  for (const profile of [
    { args: [], stdio: ['ignore', 'pipe', 'pipe'], env: {} },
    { args: ['model-endpoint'], stdio: ['ignore', 'pipe', 'pipe', 'pipe'], env: {} },
    { args: [], stdio: ['ignore', 'pipe', 'pipe', 'pipe'], env: { DEBUG: 'P05-SUPERVISOR-DEBUG-CANARY' } },
  ]) {
    const denied = spawn(NODE, ['/usr/lib/blindpass/login/src/browser-supervisor-worker.mjs', ...profile.args], {
      stdio: profile.stdio, env: { PATH: '/usr/bin:/bin', HOME: '/nonexistent', ...profile.env },
    });
    let normal = 0;
    for (const stream of [denied.stdout, denied.stderr]) stream.on('data', bytes => { normal += bytes.length; bytes.fill(0); });
    assert.equal(await new Promise(resolve => denied.once('close', resolve)), 64); assert.equal(normal, 0);
  }
  stage = 'private-login';
  const configuration = { kind: 'fixture', origin: app.origin, account: 'primary', sessionMaxMs: 300_000,
    certificateSpkiPins: [createHash('sha256').update(createPublicKey(tls.cert).export({ type: 'spki', format: 'der' })).digest('base64')] };
  const login = await new Promise((resolve, reject) => {
    const child = spawn('/usr/lib/blindpass/login/blindpass-private-helper-probe', [], { stdio: ['pipe', 'pipe', 'pipe', 'pipe'] });
    const chunks = []; let normalBytes = 0;
    child.stdout.on('data', (bytes) => { normalBytes += bytes.length; bytes.fill(0); });
    child.stderr.on('data', (bytes) => { normalBytes += bytes.length; bytes.fill(0); });
    child.stdio[3].on('data', (bytes) => chunks.push(bytes));
    child.on('error', () => reject(new Error('private login unavailable')));
    child.on('close', (code) => {
      const data = Buffer.concat(chunks);
      try { assert.equal(code, 0); assert.equal(normalBytes, 0); assert.equal(data.readUInt32BE(), data.length - 4);
        const result = JSON.parse(data.subarray(4)); assert.equal(result.status, 'authenticated'); resolve(result); }
      catch { reject(new Error('private login unavailable')); }
      finally { data.fill(0); for (const bytes of chunks) bytes.fill(0); }
    });
    const bytes = Buffer.from(JSON.stringify({ version: 1, configuration, credential: { account: 'primary', password } }));
    child.stdin.end(bytes, () => bytes.fill(0));
  });
  const cookieCanary = login.cookies[0].value;
  const copiedCookie = login.cookies.map(({ name, value }) => `${name}=${value}`).join('; ');
  const agentExists = spawn('/usr/bin/id', ['p05-browser-agent'], { stdio: 'ignore' });
  if (await new Promise((resolve) => agentExists.on('close', resolve)) !== 0) execFileSync('/usr/sbin/useradd', ['--system', '--no-create-home', '--shell', '/usr/sbin/nologin', 'p05-browser-agent']);
  const agentUid = Number(execFileSync('/usr/bin/id', ['-u', 'p05-browser-agent'], { encoding: 'utf8' }).trim());
  const agentGid = Number(execFileSync('/usr/bin/id', ['-g', 'p05-browser-agent'], { encoding: 'utf8' }).trim());
  await mkdir(directory, { mode: 0o751 }); await chmod(directory, 0o751);
  await mkdir(`${directory}/output`, { mode: 0o700 }); await chown(`${directory}/output`, agentUid, agentGid);
  await mkdir(`${directory}/home`, { mode: 0o700 }); await chown(`${directory}/home`, agentUid, agentGid);
  // The stock tool may legitimately write nothing here. A non-secret marker makes "content is expected" true,
  // so the later scans fail on an emptied or unreadable directory instead of passing vacuously.
  for (const name of ['output', 'home']) await writeScanMarker(`${directory}/${name}`, '.p05-scan-marker', { uid: agentUid, gid: agentGid });
  stage = 'namespace-prepare';
  supervisor = connect({ path: '/run/p05-native-supervisor/client.sock' });
  supervisorClosed = new Promise(resolve => supervisor.once('close', () => resolve(0)));
  await new Promise((resolve, reject) => { supervisor.once('connect', resolve); supervisor.once('error', reject); });
  channel = attachFramedStream(supervisor, { receive: async (message) => {
    if (message.type === 'uncertain') for (const accept of waits.values()) accept(message);
    else waits.get(message.type)?.(message);
  }, onFailure: () => {} });
  const preparedReply = wait('prepared'); await channel.send({ type: 'start', version: 1, operationId, configuration,
    deadlineBoottimeMs: await boottime() + 30_000 });
  const prepared = await preparedReply; assert.equal(prepared.type, 'prepared');
  const activeUnits = pattern => execFileSync('/usr/bin/systemctl', ['list-units', pattern, '--state=running', '--no-legend', '--plain'], { encoding: 'utf8' })
    .trim().split('\n').filter(Boolean).map(line => line.split(/\s+/)[0]);
  const clients = activeUnits('p05-native-supervisor@*.service'); assert.equal(clients.length, 1); rootClientUnit = clients[0];
  const clientIdentity = show(rootClientUnit, ['RestrictAddressFamilies', 'MemoryDenyWriteExecute', 'StandardOutput', 'StandardError']);
  assert.equal(field(clientIdentity, 'RestrictAddressFamilies'), 'AF_UNIX'); assert.equal(field(clientIdentity, 'MemoryDenyWriteExecute'), 'yes');
  assert.equal(field(clientIdentity, 'StandardOutput'), 'null'); assert.equal(field(clientIdentity, 'StandardError'), 'null');
  // The Rust probe also actually attempts an INET socket and RW->RX mprotect:
  // reaching prepare proves both were denied, not just configured.
  const supervisors = activeUnits('blindpass-browser-supervisor@*.service'); assert.equal(supervisors.length, 1); supervisorUnit = supervisors[0];
  const outsideIdentity = show(supervisorUnit, ['User', 'Group', 'MainPID', 'StandardOutput', 'StandardError']);
  assert.equal(field(outsideIdentity, 'User'), 'root'); assert.equal(field(outsideIdentity, 'Group'), 'root');
  assert.equal(field(outsideIdentity, 'StandardOutput'), 'null'); assert.equal(field(outsideIdentity, 'StandardError'), 'null');
  const outsideStatus = await readFile(`/proc/${field(outsideIdentity, 'MainPID')}/status`, 'utf8');
  assert.match(outsideStatus, /^CapEff:\s+0+$/m);
  assert.equal((await lstat('/run/blindpass-private/supervisor.sock')).mode & 0o7777, 0o600);
  const units = execFileSync('/usr/bin/systemctl', ['list-units', 'blindpass-browser@*.service', '--state=running', '--no-legend', '--plain'], { encoding: 'utf8' }).trim();
  const candidates = units.split('\n').filter(Boolean).map((line) => line.split(/\s+/)[0]);
  browserUnit = candidates.find((unit) => Number(field(show(unit, ['MainPID']), 'MainPID')) === prepared.pid);
  assert.ok(browserUnit);
  const identity = show(browserUnit, ['InvocationID', 'MainPID', 'User', 'DynamicUser', 'PrivateNetwork', 'ControlGroup', 'RuntimeDirectory']);
  assert.equal(field(identity, 'InvocationID'), prepared.invocation);
  assert.equal(field(identity, 'DynamicUser'), 'yes'); assert.equal(field(identity, 'PrivateNetwork'), 'yes');
  const workerNamespace = await readlink(`/proc/${prepared.pid}/ns/net`);
  assert.notEqual(workerNamespace, await readlink('/proc/self/ns/net'));
  const status = await readFile(`/proc/${prepared.pid}/status`, 'utf8');
  const browserUid = Number(status.match(/^Uid:\s+(\d+)/m)?.[1]);
  const browserGid = Number(status.match(/^Gid:\s+(\d+)/m)?.[1]);
  const loginUid = Number(execFileSync('/usr/bin/id', ['-u', 'blindpass-login'], { encoding: 'utf8' }).trim());
  assert.ok(browserUid > 0 && browserUid !== agentUid && browserUid !== loginUid);
  const profile = `/run/${field(identity, 'RuntimeDirectory')}/profile`;
  const [port] = (await readFile(`${profile}/DevToolsActivePort`, 'utf8')).split('\n');
  const outsideCannotConnect = await new Promise((resolve) => {
    const socket = connect({ host: '127.0.0.1', port: Number(port) });
    const timer = setTimeout(() => { socket.destroy(); resolve(true); }, 1000);
    socket.once('error', () => { clearTimeout(timer); resolve(true); });
    socket.once('connect', () => { clearTimeout(timer); socket.destroy(); resolve(false); });
  });
  assert.ok(outsideCannotConnect, 'CDP is unreachable on the guest host loopback');
  stage = 'runtime-worker-proof';
  const runtimeGroup = Number(execFileSync('/usr/bin/getent', ['group', 'blindpass-runtime'], { encoding: 'utf8' }).split(':')[2]);
  runtimeProof = controlled(spawn('/usr/lib/blindpass/login/blindpass-runtime-identity-probe', [], { stdio: ['pipe', 'pipe', 'pipe', 'pipe'] }));
  const challengeReply = privateChallenge(runtimeProof.child);
  runtimeProof.send({ version: 1, unit: browserUnit, invocation: prepared.invocation, uid: browserUid,
    group: runtimeGroup, helperUid: loginUid, workloadUid: agentUid });
  await runtimeProof.next('identity-ready'); proofCanary = await challengeReply;
  await runtimeOtherUnitAttempt(browserUid, browserGid, proofCanary);
  const provedReply = wait('identity-proved');
  await channel.send({ type: 'prove', version: 1, challenge: proofCanary });
  assert.equal((await provedReply).type, 'identity-proved'); await runtimeProof.next('identity-verified');
  runtimeProof.child.stdin.write('check\n'); assert.equal((await runtimeProof.next('identity-status')).status, 'alive');
  stage = 'trusted-import';
  const sessionDeadlineBoottimeMs = await boottime() + Math.min(300_000, login.originalDeadlineMs - Date.now()) - 1_000;
  const importedReply = wait('imported'); await channel.send({ type: 'import', originalDeadlineMs: login.originalDeadlineMs,
    sessionDeadlineBoottimeMs, cookies: login.cookies, revokeHandle: login.revokeHandle });
  assert.equal((await importedReply).type, 'imported');
  await assert.rejects(lstat(backendPath), { code: 'ENOENT' });
  const publishedReply = wait('published'); await channel.send({ type: 'publish' });
  assert.deepEqual(await publishedReply, { type: 'published', contextHandle: `ctx_${createHash('sha256').update(operationId).digest('hex')}` });
  const backendMetadata = await lstat(backendPath); const backendDirectory = backendPath.slice(0, backendPath.lastIndexOf('/'));
  assert.ok(backendMetadata.isSocket()); assert.equal(backendMetadata.uid, 0); assert.equal(backendMetadata.gid, 0);
  assert.equal(backendMetadata.mode & 0o7777, 0o600); assert.equal(backendMetadata.nlink, 1);
  const privateDirectory = await lstat(backendDirectory);
  assert.equal(privateDirectory.uid, 0); assert.equal(privateDirectory.gid, 0); assert.equal(privateDirectory.mode & 0o7777, 0o700);
  const privateDenied = spawn('/usr/sbin/runuser', ['-u', 'p05-browser-agent', '--', '/usr/bin/test', '-r', backendPath], { stdio: 'ignore' });
  assert.notEqual(await new Promise(resolve => privateDenied.once('close', resolve)), 0);
  const endpoint = `ws+unix:${socketPath}:/current`;
  await writeFile(configPath, JSON.stringify({ browser: { browserName: 'chromium', cdpEndpoint: endpoint, cdpTimeout: 10_000 },
    saveSession: false, outputMode: 'stdout', outputDir: `${directory}/output`, snapshot: { mode: 'full' } }), { mode: 0o600 });
  await chown(configPath, agentUid, agentGid);
  stage = 'agent-invocation'; agent = startAgent(); await agent.next('agent-ready');
  const invocation = field(show('p05-browser-agent.service', ['InvocationID']), 'InvocationID');
  assert.ok(/^[a-f0-9]{32}$/.test(invocation));
  stage = 'native-proxy';
  native = controlled(spawn('/usr/lib/blindpass/login/blindpass-browser-proxy-probe', [], { stdio: ['pipe', 'pipe', 'pipe'] }));
  native.send({ version: 1, uid: agentUid, group: agentGid, unit: 'p05-browser-agent.service', invocation,
    devtoolsPath: prepared.devtoolsPath, deadlineBoottimeMs: sessionDeadlineBoottimeMs });
  await native.next('ready');
  stage = 'other-uid-and-unit';
  const denied = execFileSync('/usr/sbin/runuser', ['-u', 'nobody', '--', '/usr/bin/python3', '-c',
    'import socket\ns=socket.socket(socket.AF_UNIX)\ntry: s.connect("/run/blindpass/browser/p05-agent/cdp.sock")\nexcept PermissionError: print("denied")\nelse: raise SystemExit(1)'], { encoding: 'utf8' }).trim();
  assert.equal(denied, 'denied');
  await otherUnitAttempt(); assert.equal((await native.next('outcome')).status, 'denied');
  stage = 'stock-bound-task'; agent.send({ type: 'run', origin: app.origin });
  const task = await agent.next('task-result'); assert.ok(task.passed); assert.equal(task.stderrBytes, 0);
  assert.equal(task.messages.length, 2);
  const visible = JSON.stringify(task.messages);
  assert.ok(visible.includes('Namespace report: 12 artifacts'));
  for (const canary of [password, cookieCanary, endpoint, prepared.devtoolsPath, proofCanary]) assert.ok(!visible.includes(canary));
  stage = 'restarted-invocation';
  agent.send({ type: 'stop' }); assert.equal(await agent.closed, 0);
  stage = 'restarted-invocation-launch';
  agent = startAgent(); await agent.next('agent-ready');
  const replacement = field(show('p05-browser-agent.service', ['InvocationID']), 'InvocationID');
  assert.notEqual(replacement, invocation);
  stage = 'restarted-invocation-raw';
  // The proxy probe's outcome lines carry no connection id. Bind the replacement's denial to this request by
  // sequence: first let outcomes of the earlier stock connections arrive, require that none of them is a
  // denial (so an old queued `denied` can never stand in for the replacement's), then mark and send.
  await quiet(native);
  const earlier = native.drain('outcome');
  assert.ok(earlier.every((outcome) => ['closed', 'revoked', 'unavailable'].includes(outcome.status)), 'earlier stock connections were not denied');
  const rawMarker = native.mark();
  agent.send({ type: 'raw' });
  const rejected = await agent.next('raw-result'); assert.equal(rejected.opened, false);
  let deniedOutcome;
  // Earlier stock connections may still close, revoke or reset after their old process exited. Only outcomes
  // that arrived after the raw request count; a bounded run of such late non-denials is tolerated, the first
  // denial is the replacement's, and no second denial may follow.
  stage = 'restarted-invocation-proxy';
  for (let attempt = 0; attempt < 8; attempt++) {
    deniedOutcome = await native.nextAfter('outcome', rawMarker);
    assert.ok(['closed', 'revoked', 'unavailable', 'denied'].includes(deniedOutcome.status));
    if (deniedOutcome.status === 'denied') break;
  }
  assert.equal(deniedOutcome.status, 'denied');
  await quiet(native);
  assert.ok(!native.drain('outcome').some((outcome) => outcome.status === 'denied'), 'exactly one denial for the replacement invocation');
  stage = 'restarted-invocation-stop';
  agent.send({ type: 'stop' }); assert.equal(await agent.closed, 0); agent = undefined;
  native.child.stdin.end('stop\n'); assert.equal(await native.closed, 0); native = undefined;
  stage = 'artifacts-and-profile';
  // Each tree must still hold its harness marker (non-empty, readable) and the scanner must find an injected
  // control file; only then does "no canary found" mean anything.
  const scanCanaries = [password, cookieCanary, endpoint, prepared.devtoolsPath, proofCanary];
  for (const name of ['output', 'home']) await scanDirectory(`${directory}/${name}`, scanCanaries, { required: ['.p05-scan-marker'] });
  const unreadable = spawn('/usr/sbin/runuser', ['-u', 'p05-browser-agent', '--', '/usr/bin/test', '-r', `${profile}/DevToolsActivePort`], { stdio: 'ignore' });
  assert.notEqual(await new Promise((resolve) => unreadable.on('close', resolve)), 0);
  stage = 'stop-and-revoke';
  const stopped = wait('stopped'); await channel.send({ type: 'stop' }); assert.equal((await stopped).type, 'stopped');
  assert.equal(await supervisorExit(supervisor, supervisorClosed), 0); assert.equal(supervisorNormalBytes, 0); supervisor = undefined;
  await assert.rejects(lstat(backendDirectory), { code: 'ENOENT' });
  await new Promise((resolve) => setTimeout(resolve, 500));
  const cgroup = field(identity, 'ControlGroup');
  try { assert.equal((await readFile(`/sys/fs/cgroup${cgroup}/cgroup.procs`, 'utf8')).trim(), ''); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
  await assert.rejects(readFile(`${profile}/DevToolsActivePort`), { code: 'ENOENT' });
  runtimeProof.child.stdin.write('check\n'); assert.equal((await runtimeProof.next('identity-status')).status, 'exited');
  runtimeProof.child.stdin.end('stop\n'); assert.equal(await runtimeProof.closed, 0);
  assert.equal(Buffer.concat(runtimeProof.stderr).length, 0); runtimeProof = undefined;
  assert.equal(await send('/admin/accounts/revoke', { body: { account: 'primary' } }), 204);
  assert.equal(await send('/reports', { cookie: copiedCookie }), 401);
  stage = 'supervisor-loss';
  const eofCleanupMs = await lostSupervisor(configuration, 'eof');
  const crashCleanupMs = await lostSupervisor(configuration, 'crash');
  // These units log nothing normally; the scan requires a lifecycle line per unit, a real journald control and
  // a detected injected token before "journal_canaries absent" is meaningful.
  await scanJournal({ units: ['blindpass-browser@*', 'blindpass-browser-supervisor@*', 'p05-native-supervisor@*', 'p05-browser-agent.service', 'p05-runtime-other.service'], canaries: scanCanaries });
  console.log(`P05-BROWSER-VM outside_supervisor=production_socket native_client=rust native_inet=denied native_rw_to_rx=denied broker_sandbox=preserved private_activation=root600 supervisor_capabilities=none backend=root600 backend_parent=root700 import_before_publication=verified backend_after_stop=removed supervisor_normal_output=null supervisor_invalid_launch=denied supervisor_eof_cleanup_ms=${eofCleanupMs} supervisor_crash_cleanup_ms=${crashCleanupMs} loss_scope=prepared_without_source_or_session dynamic_uid=separate private_network=verified outside_cdp=denied other_uid=denied profile=private sandbox=enabled stock_tool=0.0.83 task_reads=2 reconnects=1 same_uid_other_unit=denied restarted_invocation=denied kernel_pidfd=verified runtime_worker_pidfd=verified runtime_wrong_unit=denied runtime_exit=denied proof_before_cookie_import=verified copied_session_after_account_revoke=401 cgroup=empty profile=removed normal_canaries=absent`);
} catch { throw new Error(`Isolated browser VM failed during ${stage}`); }
finally {
  if (agent) { agent.send({ type: 'stop' }); execFileSync('/usr/bin/systemctl', ['stop', 'p05-browser-agent.service'], { stdio: 'ignore' }); }
  if (native) { native.child.stdin.end('stop\n'); await native.closed; }
  if (runtimeProof) { runtimeProof.child.stdin.end('stop\n'); await runtimeProof.closed; }
  channel?.close();
  if (supervisor) { supervisor.destroy(); await supervisorExit(supervisor, supervisorClosed); }
  for (const unit of [supervisorUnit, rootClientUnit]) if (unit) execFileSync('/usr/bin/systemctl', ['stop', unit], { stdio: 'ignore' });
  if (browserUnit) execFileSync('/usr/bin/systemctl', ['stop', browserUnit], { stdio: 'ignore' });
  await rm(directory, { recursive: true, force: true }); await app.close(); await tls.close();
}
