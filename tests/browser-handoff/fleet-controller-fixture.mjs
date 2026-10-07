// SPDX-License-Identifier: AGPL-3.0-only
// Disposable real controller, private seed credentials and verified TLS proxy.
// No test bypass substitutes for enrollment, policy, approval or node relay.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:https';
import { request } from 'node:http';
import { chmod, mkdir, rm, writeFile } from 'node:fs/promises';
import { randomBytes, createHash, randomUUID } from 'node:crypto';
import { createTestTls } from './fixture-app/test-tls.mjs';

const binary = '/usr/lib/blindpass/login/blindpass-controller';
const directory = '/run/p05-fleet-controller';
const origin = 'http://127.0.0.1:5175';
const port = 3205;

export function isProvisionalBrowserOperation(value) {
  return value?.status === 'executing' && value.result?.result_code === 'result_uncertain';
}

export function isConfirmedBrowserClosure(value) {
  return ['completed', 'revoked'].includes(value?.status) && value.result?.result_code === 'browser_session_closed';
}

export function decodeControllerResponse(status, bytes) {
  if (status === 204 && bytes.length === 0) return {};
  try {
    const value = JSON.parse(bytes.toString());
    if (status < 200 || status >= 300) throw new Error('controller_rejected');
    return value;
  } catch { throw new Error(`fleet_controller_http_${status}`); }
}

export async function runPrivate(binaryPath, args, { env, input, timeout = 15000 } = {}) {
  const child = spawn(binaryPath, args, { env, stdio: ['pipe', 'pipe', 'pipe'] });
  const chunks = []; let length = 0; let failed = false;
  child.on('error', () => { failed = true; });
  child.stdout.on('data', bytes => {
    length += bytes.length;
    if (length > 65536) { bytes.fill(0); failed = true; child.kill('SIGKILL'); }
    else chunks.push(bytes);
  });
  child.stderr.on('data', bytes => bytes.fill(0));
  child.stdin.on('error', () => {});
  const timer = setTimeout(() => { failed = true; child.kill('SIGKILL'); }, timeout);
  const bytes = input === undefined ? undefined : Buffer.from(input);
  const closed = new Promise(resolve => child.once('close', resolve));
  child.stdin.end(bytes, () => bytes?.fill(0));
  const code = await closed; clearTimeout(timer);
  const output = Buffer.concat(chunks); for (const chunk of chunks) chunk.fill(0);
  if (failed || code !== 0) { output.fill(0); throw new Error('private_command_failed'); }
  return output;
}

export async function waitFor(predicate, timeout = 65000) {
  const end = performance.now() + timeout;
  while (performance.now() < end) {
    if (await predicate()) return;
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  throw new Error('fleet_guest_state_deadline');
}

export async function startFleetController() {
  assert.equal(process.getuid(), 0);
  const tls = await createTestTls(); let controller; let proxy; let session; let stage = 'credentials';
  await mkdir(directory, { mode: 0o700 });
  const env = { PATH: '/usr/bin:/bin', LANG: 'C', BLINDPASS_TEST_MODE: '1',
    BLINDPASS_LISTEN: `127.0.0.1:${port}`, BLINDPASS_PUBLIC_URL: 'https://127.0.0.1:8445',
    BLINDPASS_UI_BASE_URL: origin, BLINDPASS_DATABASE_URL_FILE: `${directory}/database-url`,
    BLINDPASS_ROOT_SECRET_FILE: `${directory}/root`, BLINDPASS_AGENT_JWT_SECRET_FILE: `${directory}/agent`,
    BLINDPASS_ISSUER_KEY_FILE: `${directory}/issuer`, BLINDPASS_ADMIN_SOCKET_PATH: `${directory}/admin.sock` };
  const sockets = new Set();
  async function close() {
    if (controller) {
      const closed = new Promise(resolve => controller.once('close', resolve));
      controller.kill('SIGTERM');
      const timer = setTimeout(() => controller.kill('SIGKILL'), 5000);
      if (controller.exitCode === null && controller.signalCode === null) await closed;
      clearTimeout(timer);
    }
    if (proxy) { for (const socket of sockets) socket.destroy(); await new Promise(resolve => proxy.close(resolve)); }
    await rm('/usr/local/share/ca-certificates/blindpass-p05-fleet.crt', { force: true });
    try { (await runPrivate('/usr/sbin/update-ca-certificates', [])).fill(0); } catch {}
    tls.key.fill(0); await tls.close(); await rm(directory, { recursive: true, force: true });
  }
  try {
    for (const name of ['root', 'agent', 'issuer']) {
      const bytes = randomBytes(32); await writeFile(`${directory}/${name}`, bytes, { mode: 0o600, flag: 'wx' }); bytes.fill(0);
    }
    await writeFile(`${directory}/database-url`, `sqlite:${directory}/controller.sqlite?mode=rwc\n`, { mode: 0o600 });
    await writeFile(`${directory}/fixture.json`, JSON.stringify({ agents: ['p05-disposable-fixture'], local_admin: true }), { mode: 0o600 });
    stage = 'migrate'; (await runPrivate(binary, ['migrate'], { env })).fill(0);
    stage = 'seed';
    const seedBytes = await runPrivate(binary, ['seed', '--fixture', `${directory}/fixture.json`], { env });
    const seed = JSON.parse(seedBytes.toString()); seedBytes.fill(0); session = seed.local_admin;
    assert.ok(session?.session_id && session.csrf_token && session.temporary_password);
    stage = 'serve'; controller = spawn(binary, ['serve'], { env, stdio: ['ignore', 'ignore', 'pipe'] });
    controller.stderr.on('data', bytes => bytes.fill(0)); controller.on('error', () => {});
    await waitFor(async () => { try { return (await api('/api/v3/capabilities', 'GET', undefined, false)).issuer_pub; } catch { return false; } }, 20000);
    stage = 'password';
    await api('/api/v3/admin/session/change-password', 'POST', { current_password: session.temporary_password, new_password: randomBytes(32).toString('base64url') });
    delete session.temporary_password;
    stage = 'tls-proxy'; proxy = createServer({ key: tls.key, cert: tls.cert }, (incoming, outgoing) => {
      const upstream = request({ host: '127.0.0.1', port, method: incoming.method, path: incoming.url,
        headers: { ...incoming.headers, host: `127.0.0.1:${port}` } }, reply => {
        outgoing.writeHead(reply.statusCode, reply.headers); reply.pipe(outgoing);
      });
      upstream.on('error', () => { outgoing.writeHead(502); outgoing.end(); });
      incoming.on('error', () => upstream.destroy()); outgoing.on('close', () => upstream.destroy());
      incoming.pipe(upstream);
    });
    proxy.on('connection', socket => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
    await new Promise((resolve, reject) => { proxy.once('error', reject); proxy.listen(8445, '127.0.0.1', resolve); });
    stage = 'trust';
    await writeFile('/usr/local/share/ca-certificates/blindpass-p05-fleet.crt', tls.ca, { mode: 0o644 });
    await chmod('/usr/local/share/ca-certificates/blindpass-p05-fleet.crt', 0o644);
    (await runPrivate('/usr/sbin/update-ca-certificates', [])).fill(0);
    stage = 'capabilities'; const capabilities = await api('/api/v3/capabilities', 'GET', undefined, false);
    const issuerFingerprint = createHash('sha256').update(Buffer.from(capabilities.issuer_pub, 'base64url')).digest('hex');
    return { api, close, issuerFingerprint, adminId: session.operator_id, controllerOrigin: 'https://127.0.0.1:8445' };
  } catch { await close(); throw new Error(`fleet_controller_setup_${stage}_failed`); }

  async function api(path, method = 'GET', body, authenticated = true, extraHeaders = {}) {
    const headers = { accept: 'application/json', ...extraHeaders };
    if (body !== undefined) headers['content-type'] = 'application/json';
    if (authenticated) {
      headers.cookie = `bp_session=${session.session_id}; bp_csrf=${session.csrf_token}`;
      if (method !== 'GET') { headers.origin = origin; headers['x-csrf-token'] = session.csrf_token; }
    }
    return new Promise((resolve, reject) => {
      const req = request({ host: '127.0.0.1', port, path, method, headers, timeout: 8000 }, reply => {
        const chunks = []; let size = 0;
        reply.on('data', bytes => { size += bytes.length; if (size > 1048576) { bytes.fill(0); reply.destroy(); } else chunks.push(bytes); });
        reply.on('error', () => reject(new Error('fleet_controller_response_failed')));
        reply.on('end', () => {
          const bytes = Buffer.concat(chunks); for (const chunk of chunks) chunk.fill(0);
          try {
            resolve(decodeControllerResponse(reply.statusCode, bytes));
          } catch (error) { reject(error); }
          finally { bytes.fill(0); }
        });
      });
      req.on('error', () => reject(new Error('fleet_controller_transport_failed')));
      req.on('timeout', () => req.destroy()); req.end(body === undefined ? undefined : JSON.stringify(body));
    });
  }
}

export async function approveBrowserOperation(controller, requestEventKey) {
  let operation;
  await waitFor(async () => {
    const list = await controller.api('/api/v3/operations');
    for (const item of list.items) {
      if (item.status !== 'awaiting_approval' || !item.approval_id) continue;
      const detail = await controller.api(`/api/v3/approvals/${item.approval_id}`);
      if (detail.operations.some(member => member.id === item.id && member.broker_event_key === requestEventKey)) {
        operation = item; return true;
      }
    }
    return false;
  });
  assert.ok(operation.approval_id);
  const approval = await controller.api(`/api/v3/approvals/${operation.approval_id}`);
  assert.equal(approval.requester_summary.requester_type, 'workload');
  await controller.api(`/api/v3/approvals/${approval.id}/approve`, 'POST', {
    expected_status: 'pending', expected_version: approval.version, operation_ids: approval.operation_ids,
  }, true, { 'idempotency-key': `p05-${randomUUID().replaceAll('-', '')}`, 'if-match': `"${approval.version}"` });
  return operation;
}

// P06: the packaged native controller runs in another guest and is reached over verified HTTPS. The harness writes
// the connection details (and the operator's generated password) to a root-only file before this process starts;
// nothing here starts, seeds or proxies a controller.
export async function startRemoteFleetController(configPath = '/root/p06-remote-controller.json') {
  const { readFile } = await import('node:fs/promises');
  const { request: httpsRequest } = await import('node:https');
  const config = JSON.parse(await readFile(configPath, 'utf8'));
  const origin = new URL(config.origin);
  const ca = await readFile(config.ca_path);
  let session; let csrf;
  const { Agent } = await import('node:https');
  const agent = new Agent({ keepAlive: true, maxSockets: 1 }); // the host forward accepts one connection at a time
  const sendOnce = (path, method, body, headers) => new Promise((resolve, reject) => {
    const req = httpsRequest({ host: origin.hostname, port: Number(origin.port) || 443, path, method, ca, agent, servername: origin.hostname, headers: { host: origin.host, accept: 'application/json', ...headers }, timeout: 8000 }, reply => {
      const chunks = []; let size = 0;
      reply.on('data', bytes => { size += bytes.length; if (size > 1048576) { bytes.fill(0); reply.destroy(); } else chunks.push(bytes); });
      reply.on('error', () => reject(new Error('fleet_controller_response_failed')));
      reply.on('end', () => {
        const bytes = Buffer.concat(chunks); for (const chunk of chunks) chunk.fill(0);
        try { resolve({ status: reply.statusCode, bytes, headers: reply.headers }); } catch (error) { reject(error); }
      });
    });
    req.on('error', () => reject(new Error('fleet_controller_transport_failed')));
    req.on('timeout', () => req.destroy()); req.end(body === undefined ? undefined : JSON.stringify(body));
  });
  // Reads are retried on a transport failure (the forwarded listener is one connection deep); writes never are.
  async function send(path, method, body, headers) {
    for (let attempt = 0; ; attempt++) {
      try { return await sendOnce(path, method, body, headers); }
      catch (error) { if (method !== 'GET' || attempt >= 4) throw error; await new Promise(resolve => setTimeout(resolve, 250)); }
    }
  }
  async function api(path, method = 'GET', body, authenticated = true, extraHeaders = {}) {
    const headers = { ...extraHeaders };
    if (body !== undefined) headers['content-type'] = 'application/json';
    if (authenticated) {
      headers.cookie = `bp_session=${session}; bp_csrf=${csrf}`;
      if (method !== 'GET') { headers.origin = config.origin; headers['x-csrf-token'] = csrf; }
    }
    const reply = await send(path, method, body, headers);
    try {
      if (reply.status < 200 || reply.status >= 300) {
        // Status, route and the controller's fixed error code only: no request or response body.
        let code = 'unparsed'; try { const parsed = JSON.parse(reply.bytes.toString()); if (typeof parsed.error === 'string' && /^[a-z0-9_.-]{1,64}$/.test(parsed.error)) code = parsed.error; } catch {}
        process.stderr.write(`P06-REMOTE-CONTROLLER status=${reply.status} error=${code} route=${method} ${path.replace(/[A-Za-z0-9_-]{16,}/g, ':id')}\n`);
      }
      return decodeControllerResponse(reply.status, reply.bytes);
    } finally { reply.bytes.fill(0); }
  }
  const token = randomBytes(32).toString('base64url').slice(0, 43);
  const login = await send('/api/v3/admin/session/login', 'POST', { username: config.username, password: config.password },
    { 'content-type': 'application/json', origin: config.origin, cookie: `bp_csrf=${token}`, 'x-csrf-token': token });
  assert.equal(login.status, 200, `remote_login_${login.status}`);
  const loginBody = JSON.parse(login.bytes.toString()); login.bytes.fill(0);
  session = (login.headers['set-cookie'] ?? []).map(value => value.match(/^bp_session=([^;]+)/)?.[1]).find(Boolean);
  csrf = loginBody.csrf_token; assert.ok(session && csrf);
  const capabilities = await api('/api/v3/capabilities', 'GET', undefined, false);
  const issuerFingerprint = createHash('sha256').update(Buffer.from(capabilities.issuer_pub, 'base64url')).digest('hex');
  return { api, close: async () => { try { await api('/api/v3/admin/session/logout', 'POST'); } catch {} agent.destroy(); }, issuerFingerprint, adminId: loginBody.operator.id, controllerOrigin: config.origin };
}
