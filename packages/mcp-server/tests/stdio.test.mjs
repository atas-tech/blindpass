// SPDX-License-Identifier: MIT
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { test } from 'node:test';
import { createInterface } from 'node:readline';
import { createMcpServer } from '../src/index.mjs';

const fixture = new URL('./stdio-fixture.mjs', import.meta.url);
function connect(meta, entry = fixture) {
  const child = spawn(process.execPath, [entry.pathname], { stdio: ['pipe', 'pipe', 'pipe'], env: { PATH: process.env.PATH } });
  const waiting = new Map(); let next = 0; let stderr = '';
  const closed = new Promise((resolve) => child.on('close', resolve));
  child.stderr.on('data', (data) => { stderr += data; });
  createInterface({ input: child.stdout }).on('line', (line) => {
    try { const message = JSON.parse(line); waiting.get(message.id)?.(message); waiting.delete(message.id); }
    catch { child.kill(); }
  });
  return { request(method, params) {
    return new Promise((resolve, reject) => {
      const id = ++next; const timer = setTimeout(() => reject(new Error('MCP test response deadline')), 5000);
      if (meta) params = { ...params, _meta: meta };
      waiting.set(id, (value) => { clearTimeout(timer); resolve(value); });
      child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`);
    });
  }, notify(method) { child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method })}\n`); },
  async close() { child.stdin.end(); const timer = setTimeout(() => child.kill('SIGKILL'), 1000);
    try { await closed; } finally { clearTimeout(timer); }
    assert.equal(stderr, ''); } };
}
for (const protocolVersion of ['2024-11-05', '2025-03-26', '2025-06-18', '2025-11-25']) {
  test(`M01 official SDK newline stdio initialize/list/call on ${protocolVersion}`, { timeout: 10_000 }, async () => {
    const client = connect();
    try {
      const initialized = await client.request('initialize', { protocolVersion, capabilities: {}, clientInfo: { name: 'blindpass-contract', version: '1' } });
      assert.equal(initialized.result.protocolVersion, protocolVersion);
      assert.equal(initialized.result.serverInfo.name, 'blindpass');
      client.notify('notifications/initialized');
      const list = await client.request('tools/list', {});
      assert.deepEqual(list.result.tools.map((tool) => tool.name), ['safe_status', 'upstream_failure', 'returned_failure']);
      const result = await client.request('tools/call', { name: 'safe_status', arguments: { resourceId: 'report-primary' } });
      assert.deepEqual(result.result.content, [{ type: 'text', text: 'ready' }]);
      const failed = await client.request('tools/call', { name: 'upstream_failure', arguments: {} });
      assert.equal(failed.result.isError, true);
      assert.deepEqual(failed.result.content, [{ type: 'text', text: 'Operation failed' }]);
      assert.ok(!JSON.stringify(failed).includes('CANARY'));
    } finally { await client.close(); }
  });
}
test('M01 registry refuses duplicate names, arbitrary schema and invalid handlers at startup', () => {
  const tool = { name: 'safe_status', inputSchema: { type: 'object', properties: {} }, execute: async () => ({ content: [] }) };
  assert.throws(() => createMcpServer({ tools: [tool, tool] }), /invalid_tool_configuration/);
  assert.throws(() => createMcpServer({ tools: [{ ...tool, name: '' }] }), /invalid_tool_configuration/);
  assert.throws(() => createMcpServer({ tools: [{ ...tool, execute: null }] }), /invalid_tool_configuration/);
});

test('M01 official SDK modern per-request envelope serves tools without initialize', { timeout: 10_000 }, async () => {
  const client = connect({ 'io.modelcontextprotocol/protocolVersion': '2026-07-28',
    'io.modelcontextprotocol/clientCapabilities': {},
    'io.modelcontextprotocol/clientInfo': { name: 'blindpass-modern-contract', version: '1' } });
  try {
    const list = await client.request('tools/list', {});
    assert.deepEqual(list.result.tools.map((tool) => tool.name), ['safe_status', 'upstream_failure', 'returned_failure']);
    const result = await client.request('tools/call', { name: 'safe_status', arguments: { resourceId: 'report-primary' } });
    assert.deepEqual(result.result.content, [{ type: 'text', text: 'ready' }]);
  } finally { await client.close(); }
});

test('M01 returned legacy failure payloads cannot reflect private content or structured fields', { timeout: 10_000 }, async () => {
  const client = connect({ 'io.modelcontextprotocol/protocolVersion': '2026-07-28',
    'io.modelcontextprotocol/clientCapabilities': {},
    'io.modelcontextprotocol/clientInfo': { name: 'blindpass-modern-contract', version: '1' } });
  try {
    const failed = await client.request('tools/call', { name: 'returned_failure', arguments: {} });
    assert.equal(failed.result.isError, true);
    assert.deepEqual(failed.result.content, [{ type: 'text', text: 'Operation failed' }]);
    assert.equal(failed.result.structuredContent, undefined);
    assert.ok(!JSON.stringify(failed).includes('P05-RETURNED-PRIVATE-CANARY'));
  } finally { await client.close(); }
});

test('M01 actual legacy handler caught upstream errors cannot reflect private text over stdio', { timeout: 10_000 }, async () => {
  const client = connect({ 'io.modelcontextprotocol/protocolVersion': '2026-07-28',
    'io.modelcontextprotocol/clientCapabilities': {},
    'io.modelcontextprotocol/clientInfo': { name: 'blindpass-legacy-failure-contract', version: '1' } },
  new URL('./legacy-failure-fixture.mjs', import.meta.url));
  try {
    const failed = await client.request('tools/call', { name: 'list_secrets', arguments: {} });
    assert.equal(failed.result.isError, true);
    assert.deepEqual(failed.result.content, [{ type: 'text', text: 'Operation failed' }]);
    assert.ok(!JSON.stringify(failed).includes('P05-LEGACY-RETURNED-URL-CODE-CANARY'));
  } finally { await client.close(); }
});
