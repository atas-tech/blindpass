// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import test from 'node:test';
import { RootMcpBridge, browserTools } from './ai-client-bridge.mjs';

function bridge(options = {}) {
  const server = []; const model = [];
  const value = new RootMcpBridge({ sendServer: message => server.push(message), sendModel: message => model.push(message),
    privateTimeoutMs: 100, ...options });
  return { value, server, model };
}

test('P05-PC14A: ordinary legacy/modern MCP crosses; model cannot use private methods or reserved IDs', async () => {
  const { value, server, model } = bridge();
  await value.fromModel({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} });
  await value.fromModel({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: { _meta: {} } });
  await value.fromModel({ jsonrpc: '2.0', id: 3, method: 'server/discover', params: { _meta: {} } });
  await value.fromModel({ jsonrpc: '2.0', id: 4, method: 'subscriptions/listen', params: { _meta: {} } });
  await value.fromServer({ jsonrpc: '2.0', id: 2, result: { tools: [] } });
  assert.equal(server.length, 4); assert.equal(model.length, 1);
  for (const message of [{ jsonrpc: '2.0', id: 3, method: 'p05/private', params: {} },
    { jsonrpc: '2.0', id: 'root_control_forged', method: 'tools/list' },
    { jsonrpc: '2.0', method: 'notifications/cancelled', params: { requestId: 'root_control_forged' } }, []]) {
    await assert.rejects(value.fromModel(message), { message: 'client_transport_failed' });
  }
  assert.equal(server.length, 4); value.close();
});

test('P05-PC14A: startup and private replies remain live while a normal response observer awaits control', async () => {
  let value; const model = [];
  value = new RootMcpBridge({ sendServer: async message => {
    if (message.method === 'p05/private') await value.fromServer({ jsonrpc: '2.0', id: message.id, result: { ready: true } });
  }, sendModel: message => model.push(message),
  onServer: async () => assert.deepEqual(await value.control('startup'), { ready: true }) });
  await value.fromServer({ jsonrpc: '2.0', id: 1, result: { tools: [] } });
  assert.equal(model.length, 1); assert.ok(!value.transcript().includes('root_control_')); value.close();
});

test('P05-PC14A: private session replies never cross the model channel; unknown and late IDs deny', async () => {
  const { value, server, model } = bridge();
  const privateReply = value.control('copy-session');
  await Promise.resolve();
  assert.match(server[0].id, /^root_control_[a-f0-9]{32}$/);
  assert.deepEqual(server[0].params, { type: 'copy-session' });
  await value.fromServer({ jsonrpc: '2.0', id: server[0].id, result: { cookie: 'PRIVATE-SESSION-CANARY' } });
  assert.deepEqual(await privateReply, { cookie: 'PRIVATE-SESSION-CANARY' }); assert.equal(model.length, 0);
  await assert.rejects(value.fromServer({ jsonrpc: '2.0', id: server[0].id, result: { cookie: 'PRIVATE-SESSION-CANARY' } }), { message: 'client_transport_failed' });
  await assert.rejects(value.control('arbitrary-command'), { message: 'client_transport_failed' }); value.close();
});

test('P05-PC14A: private timeout and closure reject pending work without reflecting private errors', async () => {
  const { value } = bridge({ privateTimeoutMs: 5 });
  await assert.rejects(value.control('restart-stock'), { message: 'client_transport_failed' });
  const pending = value.control('copy-session'); value.close();
  await assert.rejects(pending, { message: 'client_transport_failed' });
  await assert.rejects(value.control('copy-session'), { message: 'client_transport_failed' });
});

test('P05-PC14C: normal source/session/endpoint canaries and overlarge frames fail before model delivery', async () => {
  const { value, model } = bridge({ canaries: ['PRIVATE-SOURCE-CANARY'] });
  for (const text of ['PRIVATE-SOURCE-CANARY', 'ws+unix:/private', '/devtools/browser/private', 'x'.repeat(65536)]) {
    await assert.rejects(value.fromServer({ jsonrpc: '2.0', id: 1, result: { content: [{ type: 'text', text }] } }), { message: 'client_transport_failed' });
  }
  value.addCanary('PRIVATE-SESSION-CANARY');
  assert.throws(() => value.scanClientTranscript('prefix PRIVATE-SESSION-CANARY suffix'), /client_transport_failed/);
  assert.throws(() => value.scanClientTranscript('x'.repeat(2 * 1024 * 1024 + 1)), /client_transport_failed/);
  await assert.rejects(value.fromModel({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'browser_navigate', arguments: { url: 'PRIVATE-SESSION-CANARY' } } }), { message: 'client_transport_failed' });
  assert.equal(model.length, 0); assert.equal(value.exposureDetected, true); value.close();
});

test('P05-PC14B: exact unique stock descriptors and real calls are preserved; missing/duplicate schema denies', async () => {
  const calls = []; const stock = { request: async (...args) => { calls.push(args); return { result: { content: [{ type: 'text', text: 'real-result' }] } }; } };
  const descriptors = ['browser_navigate', 'browser_wait_for', 'browser_snapshot'].map(name => ({ name, description: 'Actual registry', inputSchema: { type: 'object', properties: {} } }));
  const tools = browserTools(descriptors, () => stock);
  assert.deepEqual(tools.map(tool => tool.name), descriptors.map(tool => tool.name));
  assert.deepEqual(await tools[0].execute({ url: 'https://approved.invalid' }, { mcpReq: { signal: new AbortController().signal } }), { content: [{ type: 'text', text: 'real-result' }] });
  assert.equal(calls[0][0], 'tools/call'); assert.deepEqual(calls[0][1], { name: 'browser_navigate', arguments: { url: 'https://approved.invalid' } });
  for (const invalid of [[], [...descriptors, descriptors[0]], descriptors.map(tool => ({ ...tool, inputSchema: {} }))]) assert.throws(() => browserTools(invalid, () => stock), /client_transport_failed/);
});

test('P05-PC14C: failed stock calls emit only fixed private diagnostics and generic protocol errors', async () => {
  const descriptors = ['browser_navigate', 'browser_wait_for', 'browser_snapshot'].map(name => ({ name,
    description: 'registry', inputSchema: { type: 'object' } }));
  for (const [text, category] of [['EROFS: mkdir /private/PRIVATE-SOURCE-CANARY', 'read-only'],
    ['EACCES: PRIVATE-SESSION-CANARY', 'permission'], ['EAFNOSUPPORT PRIVATE-ENDPOINT-CANARY', 'address-family'],
    ['ECONNREFUSED PRIVATE-ENDPOINT-CANARY', 'connection'], ['timeout PRIVATE-SOURCE-CANARY', 'timeout'],
    ['No open pages available. PRIVATE-SOURCE-CANARY', 'no-page'],
    ['Target page, context or browser has been closed PRIVATE-SOURCE-CANARY', 'closed'],
    ['PRIVATE-SOURCE-CANARY', 'upstream']]) {
    const diagnostics = [];
    const tools = browserTools(descriptors, () => ({ request: async () => ({ result: { isError: true,
      content: [{ type: 'text', text }] } }) }), (name, reason) => diagnostics.push({ name, reason }));
    await assert.rejects(tools[0].execute({}, { mcpReq: { signal: new AbortController().signal } }),
      { message: 'client_transport_failed' });
    assert.deepEqual(diagnostics, [{ name: 'browser_navigate', reason: category }]);
    assert.ok(!JSON.stringify(diagnostics).includes('PRIVATE-'));
  }
  const diagnostics = [];
  const tools = browserTools(descriptors, () => ({ request: async () => { throw new Error('PRIVATE-SOURCE-CANARY'); } }),
    (name, reason) => diagnostics.push({ name, reason }));
  await assert.rejects(tools[0].execute({}, { mcpReq: { signal: new AbortController().signal } }),
    { message: 'client_transport_failed' });
  assert.deepEqual(diagnostics, [{ name: 'browser_navigate', reason: 'transport' }]);
});
