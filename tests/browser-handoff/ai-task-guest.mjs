// SPDX-License-Identifier: AGPL-3.0-only
// Disposable Root test driver. The host keeps model credentials; only MCP and
// a bounded final transcript enter these private guest sockets.
import assert from 'node:assert/strict';
import { createServer } from 'node:net';
import { mkdir, writeFile, readFile, chmod, lstat, rm } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { createAgentPipe } from './ai-client-pipe.mjs';
import { readJsonFrames } from './json-frame-reader.mjs';
import { AiTaskObserver } from './ai-task-observer.mjs';
import { copiedSession } from './guest-browser-profile.mjs';
import { findOperationRecord } from './coordinator-journal.mjs';
import { scanJournal } from './journal-canary-scan.mjs';
import { approveBrowserOperation, waitFor, isProvisionalBrowserOperation, isConfirmedBrowserClosure } from './fleet-controller-fixture.mjs';
const directory = '/run/p05-ai-client';
const journalPath = '/var/lib/blindpass/broker/sessions/state.json';
const invoke = (cmd, args) => execFileSync(cmd, args, { stdio: ['ignore', 'pipe', 'pipe'], encoding: 'utf8' }).trim();
const failed = () => new Error('client_task_failed');

async function listen(server, path) {
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(path, resolve); });
  await chmod(path, 0o600); const info = await lstat(path);
  assert.equal(info.uid, 0); assert.equal(info.mode & 0o7777, 0o600); assert.ok(info.isSocket());
}

export async function runAiTask({ name, child, controller, app, browserProfile, canaries, loginState, releaseLogin, cookieStatus, brokerUnit }) {
  if (process.getuid() !== 0 || !['claude', 'codex'].includes(name) || browserProfile.kind !== 'grafana-managed' || brokerUnit !== 'blindpass-broker.service') throw failed();
  await mkdir(directory, { mode: 0o700 }); const info = await lstat(directory);
  assert.equal(info.uid, 0); assert.equal(info.mode & 0o7777, 0o700); assert.ok(info.isDirectory());
  let model; let attached = false; let transportFailed = false; let operation; let active; let cookie; let cancelTime;
  let lastMethod = 'none';
  let callbackStage = 'none';
  const progress = value => { callbackStage = value; process.stdout.write(`P05-AI-PROGRESS stage=${value}\n`); };
  let result; let resultDone = false; let pipe; let queued = 0; let modelQueue = Promise.resolve();
  const sockets = new Set(); let transcript = ''; let transcriptBytes = 0;
  const stopTransport = () => { transportFailed = true; for (const socket of sockets) socket.destroy(); };
  const observer = new AiTaskObserver({
    async requested(key) {
      progress('approval');
      operation = await approveBrowserOperation(controller, key);
      progress('login-observation');
      await waitFor(() => loginState().count === 1 && (loginState().verified === 1 || loginState().failed));
      assert.equal(loginState().verified, 1); assert.equal(loginState().failed, false);
      progress('provisional-result');
      await waitFor(async () => isProvisionalBrowserOperation(await controller.api(`/api/v3/operations/${operation.id}`)));
      releaseLogin();
      progress('login-released');
    },
    async ready() {
      progress('durable-browser-ready');
      active = findOperationRecord(JSON.parse(await readFile(journalPath, 'utf8')), operation.id, 'active');
      assert.ok(active?.browser_unit && active.browser_invocation);
      assert.equal(invoke('systemctl', ['show', '--value', '-p', 'InvocationID', active.browser_unit]), active.browser_invocation);
    },
    async firstSnapshot() {
      progress('session-copy');
      const copied = await pipe.bridge.control('copy-session');
      cookie = copiedSession(JSON.stringify(copied.copied), browserProfile);
      for (const pair of cookie.split('; ')) pipe.bridge.addCanary(pair.slice(pair.indexOf('=') + 1));
      assert.equal(await cookieStatus(cookie), 200);
      progress('stock-reconnect');
      assert.deepEqual(await pipe.bridge.control('restart-stock'), { ready: true });
      progress('stock-reconnected');
    },
    cancelled() { cancelTime = Number(readFileSyncUptime()); progress('cancel-requested'); },
  });
  pipe = createAgentPipe({ child, canaries, onServer: message => observer.fromServer(message),
    sendModel: message => { if (!model || model.destroyed) throw failed(); if (!model.write(JSON.stringify(message) + '\n')) throw failed(); },
    onFailure: stopTransport });
  const modelServer = createServer(socket => {
    if (attached) { socket.destroy(); return; } attached = true; model = socket; sockets.add(socket);
    socket.setTimeout(240000, () => { stopTransport(); socket.destroy(); });
    socket.once('close', () => sockets.delete(socket)); socket.on('error', stopTransport);
    readJsonFrames(socket, message => {
      lastMethod = ['server/discover', 'subscriptions/listen', 'initialize', 'notifications/initialized', 'notifications/cancelled', 'tools/list', 'tools/call', 'ping'].includes(message.method) ? message.method : 'other';
      if (++queued > 16) { stopTransport(); return; }
      modelQueue = modelQueue.then(async () => { observer.fromModel(message); await pipe.bridge.fromModel(message); })
        .catch(stopTransport).finally(() => { queued--; });
    }, stopTransport);
  });
  let reportAttached = false;
  let stage = 'listen-model';
  const resultServer = createServer(socket => {
    if (reportAttached) { socket.destroy(); return; } reportAttached = true; sockets.add(socket);
    socket.setTimeout(15000, stopTransport); socket.once('close', () => sockets.delete(socket)); socket.on('error', stopTransport);
    readJsonFrames(socket, message => {
      try {
        if (resultDone || !Number.isSafeInteger(message.id) || message.method !== 'p05/transcript' || !message.params) throw failed();
        if (message.params.type === 'chunk' && typeof message.params.text === 'string' && message.params.text.length <= 16384) {
          transcriptBytes += Buffer.byteLength(message.params.text); if (transcriptBytes > 2 * 1024 * 1024) throw failed();
          transcript += message.params.text;
        } else if (message.params.type === 'result') {
          // Scan the entire bounded transcript, including canaries split across
          // chunks. The private session never travels back to the host scanner.
          pipe.bridge.scanClientTranscript(transcript); transcript = '';
          result = { exitCode: message.params.exitCode, artifactCount: message.params.artifactCount };
          resultDone = true;
        } else throw failed();
        socket.write(JSON.stringify({ jsonrpc: '2.0', id: message.id, result: { accepted: true } }) + '\n');
      } catch { stopTransport(); }
    }, stopTransport, () => { if (!resultDone) stopTransport(); });
  });
  try {
    await listen(modelServer, `${directory}/${name}.model.sock`);
    stage = 'listen-result';
    await listen(resultServer, `${directory}/${name}.result.sock`);
    stage = 'other-uid-denial';
    // A different UID must fail at the actual Root directory boundary.
    const denied = invoke('runuser', ['-u', 'p05-browser-agent', '--', '/usr/lib/blindpass/login/runtime/bin/node', '-e',
      `const s=require('node:net').connect(${JSON.stringify(`${directory}/${name}.model.sock`)});s.once('connect',()=>process.exit(1));s.once('error',e=>process.exit(e.code==='EACCES'?0:2));setTimeout(()=>process.exit(3),3000);`]);
    assert.equal(denied, '');
    stage = 'startup';
    assert.deepEqual(await pipe.bridge.control('startup'), { ready: true });
    stage = 'publish-info';
    await writeFile(`${directory}/${name}.info.json`, JSON.stringify({ ready: true, origin: app.origin, reportPath: browserProfile.reportPath }), { mode: 0o600 });
    stage = 'await-client';
    await waitFor(() => { if (transportFailed || pipe.failed) throw failed(); return resultDone; }, 240000);
    stage = 'verify-task';
    await modelQueue; await pipe.drain(); assert.equal(pipe.failed, false); assert.equal(transportFailed, false);
    stage = 'verify-observer';
    assert.deepEqual(observer.result(), { brokerRequests: 1, readyObserved: true, stockReportReads: 2, stockReconnects: 1, cancellationRequested: true });
    stage = 'verify-client-result';
    assert.deepEqual(result, { exitCode: 0, artifactCount: 12 }); assert.ok(cookie && active && cancelTime !== undefined);
    stage = 'verify-journal-closed';
    await waitFor(async () => findOperationRecord(JSON.parse(await readFile(journalPath, 'utf8')), operation.id, 'closed'), 30000);
    stage = 'verify-runtime-removed';
    assert.notEqual(invoke('systemctl', ['show', '--value', '-p', 'ActiveState', active.browser_unit]), 'active');
    const cgroup = invoke('systemctl', ['show', '--value', '-p', 'ControlGroup', active.browser_unit]);
    if (cgroup) { const events = await readFile(`/sys/fs/cgroup${cgroup}/cgroup.events`, 'utf8').catch(error => { if (error.code === 'ENOENT') return 'populated 0'; throw failed(); }); assert.match(events, /(?:^|\n)populated 0(?:\n|$)/); }
    await assert.rejects(lstat('/run/blindpass-browser-' + active.browser_unit.slice('blindpass-browser@'.length, -'.service'.length)), { code: 'ENOENT' });
    stage = 'verify-session-revoked';
    assert.equal(await cookieStatus(cookie), 401);
    stage = 'verify-controller-closure';
    await waitFor(async () => isConfirmedBrowserClosure(await controller.api(`/api/v3/operations/${operation.id}`)), 30000);
    stage = 'verify-closure-time';
    const closureMs = Number(readFileSyncUptime()) - cancelTime; assert.ok(closureMs >= 0 && closureMs <= 30000);
    stage = 'verify-login-counts';
    assert.equal(loginState().count, 1); assert.equal(loginState().verified, 1); assert.equal(loginState().failed, false);
    assert.equal(app.oauthMetrics().credentialAccepts, 2);
    stage = 'verify-journal-scan';
    await scanJournal({ units: [brokerUnit, `p05-ai-${name}.service`, 'blindpass-login-helper@*', 'blindpass-browser@*', 'blindpass-browser-supervisor@*'],
      canaries: [...canaries, ...cookie.split('; ').map(pair => pair.slice(pair.indexOf('=') + 1))] });
    console.log(`P05-AI-TASK client=${name} actual_mcp_request=true actual_controller_approval=true actual_node=true hpke_source=true stock_report_reads=2 stock_reconnects=1 parsed_artifacts=12 copied_cookie_cancel=401 exact_runtime_removed=true root_transport_other_uid=denied source_session_canaries=absent setup_logins=1 operation_logins=1 closure_ms=${closureMs} scope=application_task_not_full_phase`);
  } catch {
    process.stderr.write(`P05-AI-TASK failed stage=${stage} method=${lastMethod} callback=${callbackStage} tool=${observer.lastTool} reason=${observer.failureReason} tool_trace=${observer.toolTrace.join(",")} pipe_failed=${pipe.failed} exposure_detected=${pipe.bridge.exposureDetected} stderr_bytes=${pipe.stderrBytes}${pipe.diagnosticStage ? ` agent_stage=${pipe.diagnosticStage}` : ''}${pipe.stockFailure ? ` stock_failure=${pipe.stockFailure}` : ''}${pipe.transportFailure ? ` transport_failure=${pipe.transportFailure}` : ''}\n`);
    throw failed();
  } finally {
    transcript = ''; pipe.close(); for (const socket of sockets) socket.destroy();
    await Promise.all([modelServer, resultServer].map(server => new Promise(resolve => server.close(resolve))));
    await rm(directory, { recursive: true, force: true });
  }
}

function readFileSyncUptime() {
  const text = readFileSync('/proc/uptime', 'utf8'); if (!/^\d+\.\d{2} \d+\.\d{2}\n?$/.test(text)) throw failed();
  return Math.floor(Number(text.split(' ')[0]) * 1000);
}
