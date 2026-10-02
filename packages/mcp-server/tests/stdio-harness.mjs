// SPDX-License-Identifier: MIT
// Shared newline-stdio subprocess harness for protocol/robustness tests. Not a
// test file: node --test runs only tests/*.test.mjs.
import { spawn } from 'node:child_process';

export const LEGACY_CLIENT = { name: 'blindpass-protocol-contract', version: '1' };

export function launch(entry, { env = {}, args = [], cwd } = {}) {
  const child = spawn(process.execPath, [entry instanceof URL ? entry.pathname : entry, ...args],
    { stdio: ['pipe', 'pipe', 'pipe'], env: { PATH: process.env.PATH, ...env }, cwd });
  const lines = []; const waiting = new Map(); let stderr = ''; let stdout = ''; let partial = '';
  let next = 0;
  const closed = new Promise(resolve => child.once('close', (code, signal) => resolve({ code, signal })));
  child.stderr.on('data', bytes => { stderr += bytes; });
  // The server may close its input first (oversize, SIGTERM); late writes are expected to fail.
  child.stdin.on('error', () => {});
  child.stdout.on('data', bytes => {
    stdout += bytes; partial += bytes;
    let index;
    while ((index = partial.indexOf('\n')) !== -1) {
      const line = partial.slice(0, index); partial = partial.slice(index + 1);
      let value; try { value = JSON.parse(line); } catch { value = { unparsable: true }; }
      lines.push(value);
      if (value?.id !== undefined && value.id !== null) { waiting.get(value.id)?.(value); waiting.delete(value.id); }
    }
  });
  const harness = {
    child, lines, closed,
    get stderr() { return stderr; }, get stdout() { return stdout; },
    send(value) { child.stdin.write(`${typeof value === 'string' ? value : JSON.stringify(value)}\n`); },
    raw(value) { child.stdin.write(value); },
    request(method, params, { timeoutMs = 5000 } = {}) {
      const id = ++next;
      const result = new Promise((resolve, reject) => {
        const timer = setTimeout(() => { waiting.delete(id); reject(new Error('MCP harness response deadline')); }, timeoutMs);
        waiting.set(id, value => { clearTimeout(timer); resolve(value); });
      });
      harness.send({ jsonrpc: '2.0', id, method, params });
      return result;
    },
    notify(method, params) { harness.send({ jsonrpc: '2.0', method, ...(params === undefined ? {} : { params }) }); },
    initialize(protocolVersion = '2025-11-25', capabilities = {}, clientInfo = LEGACY_CLIENT) {
      return harness.request('initialize', { protocolVersion, capabilities, clientInfo });
    },
    async finish({ killAfterMs = 2000 } = {}) {
      child.stdin.end();
      const timer = setTimeout(() => child.kill('SIGKILL'), killAfterMs);
      try { return await closed; } finally { clearTimeout(timer); }
    },
    kill() { child.kill('SIGKILL'); },
  };
  return harness;
}

export async function waitUntil(predicate, { timeoutMs = 4000, label = 'condition' } = {}) {
  const deadline = performance.now() + timeoutMs;
  while (performance.now() < deadline) {
    if (await predicate()) return;
    await new Promise(resolve => setTimeout(resolve, 10));
  }
  throw new Error(`deadline waiting for ${label}`);
}

// Every stdout line of an MCP stdio server must be a JSON-RPC message.
export function assertProtocolOnly(harness, assert) {
  assert.ok(!harness.lines.some(line => line?.unparsable === true), 'stdout carried a non-JSON line');
  assert.ok(harness.lines.every(line => line?.jsonrpc === '2.0'), 'stdout carried a non JSON-RPC line');
}
