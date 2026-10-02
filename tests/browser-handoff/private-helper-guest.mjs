// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { createHash, createPublicKey, randomBytes } from 'node:crypto';
import { request, createServer } from 'node:https';
import { writeFile, mkdir, readFile, rm } from 'node:fs/promises';
import { execFileSync, spawn } from 'node:child_process';
import { createTestTls } from './fixture-app/test-tls.mjs';
import { startFixture } from './fixture-app/server.mjs';
import { findNewJournalRecord } from './coordinator-journal.mjs';
import { scanJournal } from './journal-canary-scan.mjs';

const tls = await createTestTls();
const password = `P05-VM-PRIVATE-CANARY-${randomBytes(24).toString('hex')}`;
const adminToken = randomBytes(32).toString('hex');
let loginObservations = 0;
const app = await startFixture({ ...tls, adminToken, accounts: [
  { username: 'primary', password, report: 'Private VM report: 12 artifacts' },
  { username: 'isolation', password: randomBytes(24).toString('hex'), report: 'Isolation report' },
], observeLogin: async () => {
  // Read the durable Root file while the actual helper is authenticating.
  const snapshot = JSON.parse(await readFile('/var/lib/blindpass/broker/sessions/state.json', 'utf8'));
  assert.equal(snapshot.version, 4);
  const current = snapshot.records.filter((record) => record.state === 'reserved' && record.helper_unit);
  assert.equal(current.length, 1);
  const fields = execFileSync('/usr/bin/systemctl', ['show', current[0].helper_unit, '-p', 'InvocationID', '-p', 'User', '-p', 'MainPID'], { encoding: 'utf8' });
  assert.equal(fields.match(/^InvocationID=(.*)$/m)?.[1], current[0].helper_invocation);
  assert.equal(fields.match(/^User=(.*)$/m)?.[1], 'blindpass-login');
  assert.ok(Number(fields.match(/^MainPID=(.*)$/m)?.[1]) > 0);
  loginObservations += 1;
} });
let stage = 'socket';
try {
  const configuration = { kind: 'fixture', origin: app.origin, account: 'primary', sessionMaxMs: 300_000,
    certificateSpkiPins: [createHash('sha256').update(createPublicKey(tls.cert).export({ type: 'spki', format: 'der' })).digest('base64')] };
  async function exchange(configuration, observation, withholdSource = false, withdrawJournal = false) { return new Promise((resolve, reject) => {
    const child = spawn('/usr/lib/blindpass/login/blindpass-private-helper-probe', [], {
      stdio: ['pipe', 'pipe', 'pipe', 'pipe', ...(observation ? ['pipe'] : [])],
      env: { ...process.env, ...(withholdSource ? { P05_PROBE_SOURCE_DENY: '1' } : {}), ...(withdrawJournal ? { P05_PROBE_JOURNAL_WITHDRAW: '1' } : {}) },
    });
    const chunks = []; let bytes = 0; let normalBytes = 0;
    const timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('native private IPC deadline')); }, 70_000);
    child.on('error', () => { clearTimeout(timer); reject(new Error('native private IPC failed')); });
    child.stdin.on('error', () => {});
    child.stdout.on('data', (chunk) => { normalBytes += chunk.length; chunk.fill(0); });
    child.stderr.on('data', (chunk) => { normalBytes += chunk.length; chunk.fill(0); });
    const proof = [];
    child.stdio[4]?.on('data', (bytes) => proof.push(bytes));
    child.stdio[3].on('data', (chunk) => {
      bytes += chunk.length;
      if (bytes > 16_388) { chunk.fill(0); child.kill('SIGKILL'); }
      else chunks.push(chunk);
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      const data = Buffer.concat(chunks);
      try {
        assert.equal(code, 0); assert.equal(normalBytes, 0); assert.ok(bytes <= 16_388);
        assert.ok(data.length >= 4); assert.equal(data.readUInt32BE(), data.length - 4);
        assert.ok(!data.includes(Buffer.from(password)));
        if (observation) observation.proofVerified = Buffer.concat(proof).equals(Buffer.from('proof_verified\n'));
        resolve(JSON.parse(data.subarray(4)));
      } catch { reject(new Error('native private IPC invalid')); }
      finally { data.fill(0); for (const chunk of chunks) chunk.fill(0); for (const chunk of proof) chunk.fill(0); }
    });
    const data = Buffer.from(JSON.stringify({ version: 1, configuration, credential: { account: 'primary', password } }));
    child.stdin.end(data, () => data.fill(0));
  }); }
  const result = await exchange(configuration);
  stage = `response-${result.status}`;
  assert.equal(result.status, 'authenticated');
  assert.equal(loginObservations, 1);
  stage = 'helper-journal-enospc';
  const dropInProof = '/etc/systemd/system/blindpass-login-helper@.service.d';
  await mkdir(dropInProof, { recursive: true });
  await writeFile(`${dropInProof}/p05-proof-delay.conf`, '[Service]\nExecStartPre=/usr/bin/sleep 1\n');
  execFileSync('/usr/bin/systemctl', ['daemon-reload']);
  execFileSync('/usr/bin/mount', ['-t', 'tmpfs', '-o', 'size=64k,mode=0700', 'tmpfs', '/var/lib/blindpass/broker/sessions']);
  const observation = {};
  try {
    const withheld = exchange(configuration, observation);
    let reserved = false;
    for (let attempt = 0; attempt < 100; attempt += 1) {
      try {
        const snapshot = JSON.parse(await readFile('/var/lib/blindpass/broker/sessions/state.json', 'utf8'));
        if (snapshot.records.length === 1 && snapshot.records[0].state === 'reserved') { reserved = true; break; }
      } catch {}
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    assert.ok(reserved, 'original reservation persisted before proof delay');
    let diskFull = false;
    try { await writeFile('/var/lib/blindpass/broker/sessions/fill', Buffer.alloc(262_144)); }
    catch (error) { assert.equal(error.code, 'ENOSPC'); diskFull = true; }
    assert.ok(diskFull);
    assert.deepEqual(await withheld, { status: 'unavailable' });
    assert.equal(observation.proofVerified, true, 'kernel proof completed before actual journal write failure');
    assert.equal(loginObservations, 1, 'withheld source starts no website authentication');
    const stateBytes = await readFile('/var/lib/blindpass/broker/sessions/state.json');
    try {
      const snapshot = JSON.parse(stateBytes);
      assert.equal(snapshot.records[0].helper_unit, null);
      assert.equal(snapshot.records[0].revoke_handle, null);
      assert.ok(!stateBytes.includes(Buffer.from(password)));
    } finally { stateBytes.fill(0); }
  } finally {
    execFileSync('/usr/bin/umount', ['/var/lib/blindpass/broker/sessions']);
    await rm(`${dropInProof}/p05-proof-delay.conf`); execFileSync('/usr/bin/systemctl', ['daemon-reload']);
  }
  console.log('P05-HELPER-JOURNAL-VM schema=4 exact_manager_identity=durable_before_authentication reverse_proof=verified actual_enospc=observed source_delivery=withheld second_authentication=0');
  function send(path, options = {}) {
    return new Promise((resolve, reject) => {
      const req = request(`${app.origin}${path}`, { ca: tls.ca, method: options.method ?? 'GET',
        headers: options.headers ?? {}, timeout: 5000 }, (res) => {
        const chunks = []; res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString() }));
      });
      req.on('error', () => reject(new Error('app request failed'))); req.on('timeout', () => req.destroy()); req.end(options.body);
    });
  }
  stage = 'imported-cookie';
  const cookie = result.cookies.map(({ name, value }) => `${name}=${value}`).join('; ');
  assert.equal((await send('/reports', { headers: { cookie } })).status, 200);
  stage = 'other-uid';
  const denied = execFileSync('/usr/sbin/runuser', ['-u', 'nobody', '--', '/usr/bin/python3', '-c',
    'import socket\ns=socket.socket(socket.AF_UNIX)\ntry: s.connect("/run/blindpass-private/login.sock")\nexcept PermissionError: print("denied")\nelse: raise SystemExit(1)'], { encoding: 'utf8' }).trim();
  assert.equal(denied, 'denied');
  stage = 'revoke';
  assert.equal((await send('/admin/sessions/revoke', { method: 'POST', headers: {
    authorization: `Bearer ${adminToken}`, 'content-type': 'application/json',
  }, body: JSON.stringify({ account: result.revokeHandle.account, sessionReference: result.revokeHandle.sessionReference }) })).status, 204);
  assert.equal((await send('/reports', { headers: { cookie } })).status, 401);
  stage = 'current-authority-source-gate';
  const beforeGate = JSON.parse(await readFile('/var/lib/blindpass/broker/sessions/state.json', 'utf8'));
  const currentGate = {};
  assert.deepEqual(await exchange(configuration, currentGate, true), { status: 'unavailable' });
  assert.equal(currentGate.proofVerified, true);
  assert.equal(loginObservations, 1);
  const gatedSnapshot = JSON.parse(await readFile('/var/lib/blindpass/broker/sessions/state.json', 'utf8'));
  const gated = findNewJournalRecord(beforeGate, gatedSnapshot);
  assert.ok(gated.helper_unit && gated.helper_invocation);
  assert.equal(gated.revoke_handle, null);
  console.log('P05-HELPER-AUTHORITY-VM reverse_proof=verified helper_identity=durable current_source_gate=denied source_delivery=withheld second_authentication=0 scope=guard-callback');
  stage = 'detached-journal-source-withdrawal';
  const detachedGate = {};
  assert.deepEqual(await exchange(configuration, detachedGate, false, true), { status: 'unavailable' });
  assert.equal(detachedGate.proofVerified, true);
  assert.equal(loginObservations, 1);
  const detachedSnapshot = JSON.parse(await readFile('/var/lib/blindpass/broker/sessions/state.json', 'utf8'));
  const withdrawn = findNewJournalRecord(gatedSnapshot, detachedSnapshot);
  assert.equal(withdrawn.state, 'revoking');
  assert.ok(withdrawn.helper_unit && withdrawn.helper_invocation);
  assert.equal(withdrawn.revoke_handle, null);
  console.log('P05-HELPER-DETACHED-VM reverse_proof=verified helper_identity=durable journal_access=detached journal_permission=withdrawn source_delivery=withheld second_authentication=0 scope=sealed-channel');
  stage = 'journal-exposure';
  // The helper unit logs nothing (StandardError=null, stdout is the activation socket): the scan requires
  // lifecycle lines for the helper instances, a real journald control and a detected injected token.
  const journalCanaries = [password, result.cookies[0].value];
  await scanJournal({ units: ['blindpass-login-helper@*'], canaries: journalCanaries });
  stage = 'manager-deadline';
  const dropIn = '/etc/systemd/system/blindpass-login-helper@.service.d';
  await mkdir(dropIn, { recursive: true });
  await writeFile(`${dropIn}/p05-deadline.conf`, '[Service]\nRuntimeMaxSec=2s\nTimeoutStopSec=1s\n');
  execFileSync('/usr/bin/systemctl', ['daemon-reload']);
  const stalled = createServer(tls, () => {});
  await new Promise((resolve) => stalled.listen(0, '127.0.0.1', resolve));
  let controlGroup; let invocation; let unit;
  const started = performance.now();
  const inspect = setInterval(() => {
    const units = execFileSync('/usr/bin/systemctl', ['list-units', 'blindpass-login-helper@*.service', '--state=running', '--no-legend', '--plain'], { encoding: 'utf8' }).trim();
    if (!units) return;
    unit = units.split(/\s+/)[0];
    const fields = execFileSync('/usr/bin/systemctl', ['show', unit, '-p', 'InvocationID', '-p', 'ControlGroup'], { encoding: 'utf8' });
    invocation = fields.match(/^InvocationID=([a-f0-9]{32})$/m)?.[1];
    controlGroup = fields.match(/^ControlGroup=(\/system\.slice\/[^\n]+)$/m)?.[1];
  }, 100);
  try {
    const killed = await exchange({ ...configuration, origin: `https://127.0.0.1:${stalled.address().port}` });
    stage = `manager-result-${killed?.status ?? 'empty'}`;
    // exchange() rejects on a missing/invalid frame, so a result is always an object here.
    assert.ok(killed.status === 'uncertain' && Object.keys(killed).length === 1, 'manager deadline returns no session material or definite authentication outcome');
    stage = `manager-identity-${Boolean(invocation)}-${Boolean(controlGroup)}-${Boolean(unit)}`;
    assert.ok(invocation && controlGroup && unit, 'manager identity and cgroup observed before kill');
    const deadlineMs = Math.round(performance.now() - started);
    stage = `manager-bound-${deadlineMs}`;
    assert.ok(deadlineMs >= 1800 && deadlineMs <= 5000, 'test override enforces bounded manager cleanup');
    await new Promise((resolve) => setTimeout(resolve, 500));
    stage = 'manager-cgroup';
    try { assert.equal((await readFile(`/sys/fs/cgroup${controlGroup}/cgroup.procs`, 'utf8')).trim(), '', 'verified cgroup empty'); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
    const state = execFileSync('/usr/bin/systemctl', ['show', unit, '-p', 'Result', '--value'], { encoding: 'utf8' }).trim();
    stage = `manager-cause-${state}`;
    assert.equal(state, 'timeout', 'actual systemd runtime deadline caused the termination');
    // This failed instance is the deliberate one; acknowledge it so the end-of-run leak check can treat any
    // other failed or still-running helper/browser/manager unit as a failure.
    try { execFileSync('/usr/bin/systemctl', ['reset-failed', unit], { stdio: 'ignore' }); } catch { /* no longer loaded: nothing left to acknowledge */ }
    // Rescan after the deadline stage: the killed helper's lifecycle and any late output are in the journal now.
    stage = 'manager-deadline-journal';
    await scanJournal({ units: ['blindpass-login-helper@*'], canaries: journalCanaries });
    console.log(`P05-HELPER-VM deadline_override_ms=2000 observed_cleanup_ms=${deadlineMs} verified_cgroup=empty journal_canaries=absent`);
  } finally {
    clearInterval(inspect); stalled.closeAllConnections(); await new Promise((resolve) => stalled.close(resolve));
    await rm(`${dropIn}/p05-deadline.conf`); execFileSync('/usr/bin/systemctl', ['daemon-reload']);
  }
  console.log('P05-HELPER-VM native_broker_ipc=verified normal_output=empty login=authenticated private_uid=blindpass-login cross_uid=denied report=200 revoked_copy=401 sandbox=enabled');
} catch {
  throw new Error(`Private helper VM failed during ${stage}`);
} finally { await app.close(); await tls.close(); }
