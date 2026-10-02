// SPDX-License-Identifier: MIT
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { test } from 'node:test';
import { createMcpOptions } from '../../openclaw-plugin/mcp-server.mjs';

test('M01 legacy callbacks adapt into official SDK schemas without importing plugin from SDK package', async () => {
  const options = createMcpOptions({ runtime: {
    emitManagedStoreBootstrapReminderFn: async () => ({ emitted: false }),
    listManagedSecretNamesFn: async () => ({ names: ['primary.secret'] }),
  } });
  const names = options.tools.map((tool) => tool.name);
  for (const name of ['request_secret', 'request_secret_exchange', 'fulfill_secret_exchange', 'list_secrets', 'delete_secret', 'confirm_delete_secret']) assert.ok(names.includes(name));
  assert.ok(!names.includes('store_secret'));
  const list = options.tools.find((tool) => tool.name === 'list_secrets');
  assert.equal(list.inputSchema.type, 'object');
  assert.match((await list.execute({}, {})).content[0].text, /primary.secret/);
});

for (const protocolVersion of ['2025-11-25', '2026-07-28']) {
 for (const protocolOnly of [false, true]) {
  test(`M01 ${protocolOnly ? 'protocol-only embedding' : 'actual OpenClaw wrapper'} starts official newline transport on ${protocolVersion}`, { timeout: 10_000 }, async () => {
    const entry = protocolOnly ? './protocol-wrapper-fixture.mjs' : '../../openclaw-plugin/mcp-server.mjs';
    const child = spawn(process.execPath, [new URL(entry, import.meta.url).pathname],
      { env: { PATH: process.env.PATH, BLINDPASS_AUTO_PERSIST: 'false' }, stdio: ['pipe', 'pipe', 'pipe'] });
    const waiting = new Map(); const output = []; let errors = 0; let id = 0;
    const closed = new Promise((resolve) => child.once('close', resolve));
    child.stderr.on('data', (bytes) => { errors += bytes.length; bytes.fill(0); });
    createInterface({ input: child.stdout }).on('line', (line) => {
      try { const value = JSON.parse(line); output.push(value); waiting.get(value.id)?.(value); waiting.delete(value.id); }
      catch { child.kill(); }
    });
    async function call(method, params = {}) {
      const requestId = ++id;
      if (protocolVersion === '2026-07-28') params._meta = { 'io.modelcontextprotocol/protocolVersion': protocolVersion,
        'io.modelcontextprotocol/clientCapabilities': {}, 'io.modelcontextprotocol/clientInfo': { name: 'wrapper-contract', version: '1' } };
      const result = new Promise((resolve, reject) => {
        const timer = setTimeout(() => { waiting.delete(requestId); reject(new Error('wrapper response deadline')); }, 4000);
        waiting.set(requestId, (value) => { clearTimeout(timer); resolve(value); });
      });
      const frame = `${JSON.stringify({ jsonrpc: '2.0', id: requestId, method, params })}\n`;
      // Standard newline framing, deliberately split over several writes.
      child.stdin.write(frame.slice(0, 7)); child.stdin.write(frame.slice(7)); return result;
    }
    try {
      if (protocolVersion !== '2026-07-28') {
        const result = await call('initialize', { protocolVersion, capabilities: {}, clientInfo: { name: 'wrapper-contract', version: '1' } });
        assert.equal(result.result.protocolVersion, protocolVersion);
        child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' })}\n`);
      }
      const list = await call('tools/list');
      if (protocolOnly) assert.deepEqual(list.result.tools.map(tool => tool.name), ['safe_status']);
      else {
        assert.ok(list.result.tools.some((tool) => tool.name === 'request_secret_exchange'));
        assert.ok(list.result.tools.some((tool) => tool.name === 'list_secrets'));
      }
      assert.ok(!list.result.tools.some((tool) => tool.name === 'store_secret'));
      const invalid = await call('tools/call', { name: protocolOnly ? 'safe_status' : 'list_secrets', arguments: { endpoint: 'PRIVATE-WRAPPER-CANARY' } });
      assert.ok(invalid.error || invalid.result?.isError);
      assert.ok(!JSON.stringify(output).includes('PRIVATE-WRAPPER-CANARY'));
      child.stdin.end(); assert.equal(await closed, 0); assert.equal(errors, 0);
    } finally { child.kill(); }
  });
 }
}
