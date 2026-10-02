// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { createServer, connect } from 'node:net';
import { mkdir, chmod, rm } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import { startManagedGrafana } from './managed-grafana.mjs';
import { decodeBootstrapReply } from './guest-browser-profile.mjs';

// App preparation only: descriptor-mode worker as the separate login UID.
// The production operations below still require actual reverse kernel proof,
// durable helper identity and HPKE custody through the installed socket service.
async function establishAccount(configuration, password) {
  const uid = Number(execFileSync('id', ['-u', 'blindpass-login'], { encoding: 'utf8' }).trim());
  const gid = Number(execFileSync('id', ['-g', 'blindpass-login'], { encoding: 'utf8' }).trim());
  assert.ok(uid > 0 && gid > 0);
  const child = spawn('/usr/lib/blindpass/login/runtime/bin/node', ['/usr/lib/blindpass/login/src/worker.mjs'], {
    uid, gid, cwd: '/', env: { PATH: '/usr/bin:/bin', HOME: '/nonexistent', PLAYWRIGHT_BROWSERS_PATH: '/usr/lib/blindpass/login/browsers' },
    stdio: ['ignore', 'pipe', 'pipe', 'pipe', 'pipe'],
  });
  const chunks = []; let bytes = 0; let normal = 0; let failed = false;
  for (const stream of [child.stdout, child.stderr]) stream.on('data', data => { normal += data.length; data.fill(0); });
  child.stdio[3].on('error', () => {});
  child.stdio[4].on('data', data => { bytes += data.length; if (bytes > 16388) { failed = true; data.fill(0); child.kill('SIGKILL'); } else chunks.push(data); });
  const completed = new Promise(resolve => { child.once('error', () => { failed = true; }); child.once('close', resolve); });
  const timer = setTimeout(() => { failed = true; child.kill('SIGKILL'); }, 65000);
  const body = Buffer.from(JSON.stringify({ version: 1, configuration, credential: { account: 'primary', password } }));
  const frame = Buffer.alloc(body.length + 4); frame.writeUInt32BE(body.length); body.copy(frame, 4); body.fill(0);
  child.stdio[3].end(frame, () => frame.fill(0));
  let output;
  try {
    const code = await completed; output = Buffer.concat(chunks);
    if (failed || code !== 0 || normal !== 0 || output.includes(Buffer.from(password))) {
      process.stderr.write(`P05-MANAGED-SETUP worker_failed timeout_or_overflow=${failed} normal_bytes=${normal} exit=${Number.isInteger(code) ? code : 'signal'}\n`);
      throw new Error('guest_bootstrap_failed');
    }
    try {
      const value = JSON.parse(output.subarray(4));
      if (['uncertain', 'invalid_request', 'unsafe_configuration', 'authentication_failed', 'timed_out', 'unsupported_authentication', 'invalid_configuration', 'login_failed', 'binding_mismatch'].includes(value.status)) process.stderr.write(`P05-MANAGED-SETUP worker_status=${value.status}\n`);
    } catch { /* fixed framed parser below handles malformed private data */ }
    return decodeBootstrapReply(output);
  } finally { clearTimeout(timer); output?.fill(0); frame.fill(0); for (const chunk of chunks) chunk.fill(0); }
}

export async function startManagedFleetApp({ home, tls, password, isolationPassword, observeLogin, certificateSpkiPins }) {
  assert.equal(process.getuid(), 0);
  let observeOperations = false;
  // The application is disposable test infrastructure. Its database remains
  // live across broker SIGKILL; only broker recovery state needs disk durability.
  await mkdir('/run/p05-managed-app', { mode: 0o700 });
  let app;
  try { app = await startManagedGrafana({ home, ...tls, accounts: [
    { username: 'primary', password, report: 'Coordinator report: 12 artifacts' },
    { username: 'isolation', password: isolationPassword, report: 'Isolation report' },
  ], administrator: `p05_admin_${randomBytes(8).toString('hex')}`, stateRoot: '/run/p05-managed-app', observeLogin: async () => { if (observeOperations) await observeLogin(); } }); }
  catch (error) {
    const stage = /^Managed Grafana setup failed during (setup|readiness|account-setup)$/.exec(error.message)?.[1] ?? 'application';
    const code = Number.isInteger(error.grafanaExitCode) ? error.grafanaExitCode : 'none';
    const signal = ['SIGKILL', 'SIGTERM', 'SIGSEGV', 'SIGABRT', 'SIGBUS', 'SIGSYS', 'SIGHUP'].includes(error.grafanaExitSignal) ? error.grafanaExitSignal : 'none';
    const health = Number.isInteger(error.grafanaHealthStatus) && error.grafanaHealthStatus >= 100 && error.grafanaHealthStatus <= 599 ? error.grafanaHealthStatus : 0;
    process.stderr.write(`P05-MANAGED-SETUP failed stage=${stage} process_exit=${code} process_signal=${signal} health_status=${health} expected_version=${error.grafanaHealthVersionMatches === true}\n`);
    const startup = error.grafanaStartup;
    if (startup) process.stderr.write(`P05-MANAGED-SETUP database=${startup.database === true} migrations=${startup.migrations === true} migration_complete=${startup.migrationComplete === true} http_listening=${startup.http === true} error_lines=${Number.isSafeInteger(startup.errors) ? startup.errors : 0} output_bytes=${Number.isSafeInteger(startup.outputBytes) ? startup.outputBytes : 0}\n`);
    await rm('/run/p05-managed-app', { recursive: true, force: true }); throw new Error('guest_bootstrap_failed');
  }
  const configuration = { kind: 'grafana-managed', origin: app.origin, loginOrigin: app.issuerOrigin,
    account: 'primary', orgId: 1, sessionMaxMs: 300000, certificateSpkiPins };
  const sockets = new Set(); let backend;
  let stage = 'bootstrap';
  async function close() {
    for (const socket of sockets) socket.destroy();
    if (backend?.listening) await new Promise(resolve => backend.close(resolve));
    await app.close(); await rm('/run/blindpass-app', { recursive: true, force: true });
    await rm('/run/p05-managed-app', { recursive: true, force: true });
  }
  try {
    const established = await establishAccount(configuration, password);
    const userId = established.revokeHandle.userId;
    assert.equal(app.oauthMetrics().credentialAccepts, 1);
    stage = 'bootstrap-logout'; assert.equal((await app.admin(`/api/admin/users/${userId}/logout`, { method: 'POST' })).status, 200);
    for (const cookie of established.cookies) cookie.value = '';
    stage = 'fixed-backend'; await mkdir('/run/blindpass-app', { mode: 0o700 });
    backend = createServer(peer => {
      const upstream = connect(app.adminSocket); sockets.add(peer); sockets.add(upstream);
      peer.once('close', () => { sockets.delete(peer); upstream.destroy(); });
      upstream.once('close', () => { sockets.delete(upstream); peer.destroy(); });
      peer.on('error', () => peer.destroy()); upstream.on('error', () => upstream.destroy());
      peer.pipe(upstream); upstream.pipe(peer);
    });
    await new Promise((resolve, reject) => { backend.once('error', reject); backend.listen('/run/blindpass-app/grafana.sock', resolve); });
    await chmod('/run/blindpass-app/grafana.sock', 0o600);
    observeOperations = true;
    return { ...app, configuration, revocation: { kind: 'grafana-admin', credential_unit: 'blindpass-session-revoker@.service', credential_name: 'fixture-admin', user_id: userId }, bootstrapLogins: 1, close };
  } catch { process.stderr.write(`P05-MANAGED-SETUP failed stage=${stage}\n`); await close(); throw new Error('guest_bootstrap_failed'); }
}
