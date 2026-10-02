// SPDX-License-Identifier: AGPL-3.0-only
// A persistent agent unit holds one real invocation while two actual stock MCP
// subprocesses connect/reconnect. Parent IO is private test control, not a model.
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { connect } from 'node:net';
import { guestWorkload } from './guest-workload.mjs';
import { guestBrowserProfile, reportSteps } from './guest-browser-profile.mjs';

const NODE = '/usr/lib/blindpass/login/runtime/bin/node';
const CONFIG = '/run/p05-browser-agent/stock-config.json';
const { nodeId, workloadId } = guestWorkload(process.env);
const browserProfile = guestBrowserProfile(process.env.BLINDPASS_P05_BROWSER_APP);
const ENDPOINT = `/run/blindpass/browser/${workloadId}/cdp.sock`;
const opening = 'GET /current HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n';
function client() {
  const child = spawn(NODE, ['/usr/lib/blindpass/login/node_modules/@playwright/mcp/cli.js', '--config', CONFIG], { stdio: ['pipe', 'pipe', 'pipe'] });
  const pending = new Map(); let sequence = 0; let stderrBytes = 0;
  const closed = new Promise((resolve) => child.on('close', resolve));
  child.stderr.on('data', (bytes) => { stderrBytes += bytes.length; bytes.fill(0); }); child.stdin.on('error', () => {});
  createInterface({ input: child.stdout }).on('line', (line) => {
    try { const value = JSON.parse(line); pending.get(value.id)?.(value); pending.delete(value.id); }
    catch { child.kill(); }
  });
  return { request(method, params) { return new Promise((resolve, reject) => {
    const id = ++sequence; const timer = setTimeout(() => { pending.delete(id); reject(new Error('stock_deadline')); }, 15_000);
    pending.set(id, (value) => { clearTimeout(timer); resolve(value); });
    child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`);
  }); }, notify(method) { child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method })}\n`); },
  async close() { child.stdin.end(); const timer = setTimeout(() => child.kill('SIGKILL'), 5000);
    try { await closed; } finally { clearTimeout(timer); } return stderrBytes;
  } };
}

async function rawChannel() {
  return new Promise((resolve, reject) => {
    const socket = connect({ path: ENDPOINT }); let bytes = 0; let headers = ''; let opened = false;
    const timer = setTimeout(() => { socket.destroy(); reject(new Error('channel_deadline')); }, 5000);
    socket.on('connect', () => socket.write(opening));
    socket.on('data', (data) => {
      bytes += data.length;
      if (!opened) {
        headers += data.toString('ascii');
        if (headers.includes('\r\n\r\n')) {
          if (!headers.startsWith('HTTP/1.1 101')) { clearTimeout(timer); socket.destroy(); resolve({ opened: false, closed: true }); return; }
          opened = true; clearTimeout(timer);
          process.stdout.write(`${JSON.stringify({ type: 'attached' })}\n`);
        }
      }
      data.fill(0);
    });
    socket.on('close', () => { clearTimeout(timer); resolve({ opened, closed: true, bytes }); });
    socket.on('error', () => { clearTimeout(timer); resolve({ opened: false, closed: true }); });
  });
}

async function work(operation) {
  return new Promise((resolve, reject) => {
    const socket = connect('/run/blindpass/workload.sock'); const chunks = [];
    const timer = setTimeout(() => { socket.destroy(); reject(new Error('work_deadline')); }, 5000);
    socket.on('connect', () => socket.end(`WORK ${nodeId} ${workloadId} p05-browser-agent.service ${process.env.INVOCATION_ID} ${operation}\n`));
    socket.on('data', bytes => chunks.push(bytes));
    socket.on('error', () => { clearTimeout(timer); reject(new Error('work_failed')); });
    socket.on('end', () => { clearTimeout(timer); resolve(Buffer.concat(chunks).toString()); });
  });
}

process.stdout.write(`${JSON.stringify({ type: 'agent-ready' })}\n`);
const input = createInterface({ input: process.stdin });
for await (const line of input) {
  let command;
  try { command = JSON.parse(line); } catch { process.exitCode = 64; break; }
  if (command.type === 'stop') break;
  if (command.type === 'work' && typeof command.operation === 'string' && command.operation.length <= 1800 && !/[\r\n]/.test(command.operation)) {
    try { process.stdout.write(`${JSON.stringify({ type: 'work-result', reply: await work(command.operation) })}\n`); }
    catch { process.stdout.write(`${JSON.stringify({ type: 'work-result', failed: true })}\n`); }
    continue;
  }
  if (command.type === 'raw') {
    const result = await rawChannel(); process.stdout.write(`${JSON.stringify({ type: 'raw-result', ...result })}\n`); continue;
  }
  if (command.type === 'copy-session') {
    const stock = client(); let result;
    try {
      const initialized = await stock.request('initialize', { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'p05-copyable-session-probe', version: '1' } });
      if (!initialized.result) throw new Error('stock_failed'); stock.notify('notifications/initialized');
      const copied = await stock.request('tools/call', { name: 'browser_run_code_unsafe', arguments: { code: `async (page) => (await page.context().cookies()).filter(cookie => ${JSON.stringify(browserProfile.cookieNames)}.includes(cookie.name)).map(cookie => cookie.name + "=" + cookie.value).join("; ")` } });
      if (copied.error || copied.result.isError) throw new Error('stock_failed');
      result = { type: 'copied-session', passed: true, copied };
    } catch { result = { type: 'copied-session', passed: false }; }
    finally { result.stderrBytes = await stock.close(); }
    // Session bytes go only through the private Root scanner pipe. This probe
    // demonstrates that the workload session is copyable; never log its value.
    process.stdout.write(`${JSON.stringify(result)}\n`); continue;
  }
  if (command.type !== 'run' || typeof command.origin !== 'string') { process.exitCode = 64; break; }
  let result; let stage = 'initialize'; const messages = []; let stderrBytes = 0;
  try {
    for (let connection = 0; connection < 2; connection++) {
      const stock = client();
      try {
        stage = `initialize-${connection}`;
        const initialize = await stock.request('initialize', { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'p05-real-invocation-stock-probe', version: '1' } });
        if (!initialize.result) throw new Error('stock_failed'); stock.notify('notifications/initialized');
        const responses = {};
        for (const step of reportSteps(browserProfile, command.origin)) {
          const label = { browser_navigate: 'navigate', browser_wait_for: 'report-wait', browser_snapshot: 'snapshot' }[step.name];
          stage = `${label}-${connection}`;
          const response = await stock.request('tools/call', step);
          if (response.error || response.result.isError) throw new Error('stock_failed');
          if (label !== 'report-wait') responses[label] = response;
        }
        messages.push(responses);
      } finally { stderrBytes += await stock.close(); }
    }
    result = { type: 'task-result', passed: true, messages, stderrBytes };
  } catch { result = { type: 'task-result', passed: false, stage, stderrBytes }; }
  // Successful stock results go only to the root canary scanner. Never print
  // upstream failure messages or a raw endpoint in diagnostic output.
  process.stdout.write(`${JSON.stringify(result)}\n`);
}
