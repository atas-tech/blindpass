// SPDX-License-Identifier: MIT
// M01 robustness gaps over the actual newline stdio transport: batches,
// malformed/oversized input, version negotiation, repeated initialize,
// SIGTERM mid-request and the outer/inner time-bound ordering.
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { MAX_MESSAGE_BYTES } from '../src/stdio.mjs';
import { BROKER_CALL_TIMEOUT_MS, CALL_TIMEOUT_MS, createBrokerClient } from '../src/broker-client.mjs';
import { createMcpServer } from '../src/index.mjs';
import { assertProtocolOnly, launch, waitUntil } from './stdio-harness.mjs';

const plain = new URL('./stdio-fixture.mjs', import.meta.url);
const abortFixture = new URL('./broker-abort-fixture.mjs', import.meta.url);
const orderingFixture = new URL('./bound-ordering-fixture.mjs', import.meta.url);
const modern = { 'io.modelcontextprotocol/protocolVersion': '2026-07-28', 'io.modelcontextprotocol/clientCapabilities': {},
  'io.modelcontextprotocol/clientInfo': { name: 'abort-contract', version: '1' } };
const submit = { jsonrpc: '2.0', id: 11, method: 'tools/call', params: { name: 'blindpass_request_operation',
  arguments: { action: 'browser.session', resourceId: 'report-primary', requestKey: 'retry_0123456789abcdef' }, _meta: modern } };

// A tools/call whose serialized line is exactly `bytes` long (excluding "\n").
function sizedCall(id, bytes) {
  const base = JSON.stringify({ jsonrpc: '2.0', id, method: 'tools/call', params: { name: 'safe_status', arguments: { resourceId: '' } } });
  const frame = JSON.stringify({ jsonrpc: '2.0', id, method: 'tools/call', params: { name: 'safe_status', arguments: { resourceId: 'r'.repeat(bytes - base.length) } } });
  assert.equal(Buffer.byteLength(frame), bytes);
  return frame;
}

test('M01 batched JSON-RPC arrays are never executed or echoed and do not break the connection', { timeout: 10_000 }, async () => {
  const server = launch(plain);
  try {
    await server.initialize(); server.notify('notifications/initialized');
    server.send(JSON.stringify([{ jsonrpc: '2.0', id: 90, method: 'tools/call', params: { name: 'safe_status', arguments: { resourceId: 'P05-BATCH-CANARY' } } },
      { jsonrpc: '2.0', id: 91, method: 'tools/list' }]));
    const list = await server.request('tools/list', {});
    assert.equal(list.result.tools.length, 3);
    assert.ok(!server.lines.some(line => line.id === 90 || line.id === 91), 'a batch member was answered');
    assert.ok(!server.stdout.includes('P05-BATCH-CANARY'));
    assertProtocolOnly(server, assert);
  } finally {
    const exit = await server.finish(); assert.equal(exit.code, 0); assert.equal(server.stderr, '');
  }
});

test('M01 malformed lines are dropped without echo, stderr output or a closed connection', { timeout: 10_000 }, async () => {
  const server = launch(plain);
  try {
    await server.initialize(); server.notify('notifications/initialized');
    for (const line of ['{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"safe_status","arguments":{"resourceId":"P05-MALFORMED-CANARY"}',
      '{"jsonrpc":"1.0","id":6,"method":"P05-MALFORMED-CANARY"}', '"P05-MALFORMED-CANARY"', 'P05-MALFORMED-CANARY', '{"id":{"P05-MALFORMED-CANARY":1}}', '', '   ', '\u0000\u0000{']) server.send(line);
    server.raw(Buffer.from([0xff, 0xfe, 0x0a]));
    const result = await server.request('tools/call', { name: 'safe_status', arguments: { resourceId: 'report-primary' } });
    assert.deepEqual(result.result.content, [{ type: 'text', text: 'ready' }]);
    assert.ok(!server.stdout.includes('P05-MALFORMED-CANARY'));
    assertProtocolOnly(server, assert);
  } finally {
    const exit = await server.finish(); assert.equal(exit.code, 0); assert.equal(server.stderr, '');
  }
});

test('M01 legal messages at and just under the cap are accepted, including back-to-back and split writes', { timeout: 15_000 }, async () => {
  const server = launch(plain);
  try {
    await server.initialize(); server.notify('notifications/initialized');
    const answered = id => waitUntil(() => server.lines.some(line => line.id === id), { label: `response ${id}` });
    // Exactly at the documented limit, written in one piece.
    server.send(sizedCall(101, MAX_MESSAGE_BYTES)); await answered(101);
    // Several 40 KB messages in one write: more than one transport chunk, with a
    // partial line pending when the next full chunk arrives.
    server.raw(`${[102, 103, 104, 105].map(id => sizedCall(id, 40_000)).join('\n')}\n`);
    for (const id of [102, 103, 104, 105]) await answered(id);
    // A near-cap message split over several small writes.
    const frame = `${sizedCall(106, MAX_MESSAGE_BYTES - 1)}\n`;
    for (let offset = 0; offset < frame.length; offset += 7_001) server.raw(frame.slice(offset, offset + 7_001));
    await answered(106);
    for (const id of [101, 102, 103, 104, 105, 106]) {
      assert.deepEqual(server.lines.find(line => line.id === id).result.content, [{ type: 'text', text: 'ready' }]);
    }
    assertProtocolOnly(server, assert);
  } finally {
    const exit = await server.finish(); assert.equal(exit.code, 0); assert.equal(server.stderr, '');
  }
});

for (const [name, payload] of [
  ['one byte over the cap, newline terminated', () => `${sizedCall(201, MAX_MESSAGE_BYTES + 1)}\n`],
  ['an unterminated 300 KiB line', () => 'P05-OVERSIZE-CANARY'.padEnd(300 * 1024, 'x')],
]) {
  test(`M01 oversized input (${name}) gets a bounded fixed error and a clean close that withdraws in-flight work`, { timeout: 15_000 }, async () => {
    const directory = await mkdtemp(join(tmpdir(), 'blindpass-mcp-oversize-')); const events = join(directory, 'events');
    const server = launch(abortFixture, { env: { P05_MCP_EVENT_FILE: events } });
    try {
      server.send(submit);
      await waitUntil(async () => (await readFile(events, 'utf8').catch(() => '')).includes('submitted'), { label: 'submission' });
      server.raw(payload());
      const exit = await Promise.race([server.closed, new Promise((_, reject) => setTimeout(() => reject(new Error('oversized input left the server hanging')), 6000))]);
      assert.equal(exit.code, 0);
      assert.equal((await readFile(events, 'utf8')).trim(), 'submitted\nwithdrawal');
      assert.deepEqual(server.lines, [{ jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Message too large' } }]);
      assert.equal(server.stderr, ''); assert.ok(!server.stdout.includes('CANARY'));
    } finally { server.kill(); await server.closed; await rm(directory, { recursive: true, force: true }); }
  });
}

test('M01 unsupported initialize revisions negotiate to the reviewed latest; unknown modern claims are refused', { timeout: 10_000 }, async () => {
  const server = launch(plain);
  try {
    const initialized = await server.initialize('1999-01-01');
    assert.equal(initialized.result.protocolVersion, '2025-11-25');
    server.notify('notifications/initialized');
    assert.equal((await server.request('tools/list', {})).result.tools.length, 3);
  } finally { const exit = await server.finish(); assert.equal(exit.code, 0); assert.equal(server.stderr, ''); }
  const modernServer = launch(plain);
  try {
    const refused = await modernServer.request('tools/list', { _meta: { ...modern, 'io.modelcontextprotocol/protocolVersion': '2030-01-01' } });
    assert.ok(refused.error, 'an unsupported modern revision must be an error'); assert.equal(refused.result, undefined);
    assert.ok(!JSON.stringify(refused).includes('safe_status'));
    // The refusal does not pin an era: a supported claim still works afterwards.
    assert.equal((await modernServer.request('tools/list', { _meta: modern })).result.tools.length, 3);
  } finally { const exit = await modernServer.finish(); assert.equal(exit.code, 0); assert.equal(modernServer.stderr, ''); }
});

test('M01 a second initialize is refused and cannot replace the negotiated version, client identity or capabilities', { timeout: 10_000 }, async () => {
  const server = launch(new URL('./delivery-stdio-fixture.mjs', import.meta.url));
  try {
    const first = await server.initialize('2025-11-25', {}, { name: 'delivery-transport-contract', version: '1' });
    assert.equal(first.result.protocolVersion, '2025-11-25'); server.notify('notifications/initialized');
    const second = await server.initialize('2025-11-25', { elicitation: { url: {} } }, { name: 'delivery-transport-contract', version: '1' });
    assert.equal(second.result, undefined); assert.equal(second.error.code, -32600); assert.equal(second.error.message, 'Already initialized');
    const call = await server.request('tools/call', { name: 'review_browser_request', arguments: {} });
    // The first (non-URL) declaration still governs delivery: no URL elicitation was sent.
    assert.deepEqual(JSON.parse(call.result.content[0].text), { status: 'delivered', provider: 'operator_app' });
    assert.ok(!server.lines.some(line => line.method === 'elicitation/create'));
    assertProtocolOnly(server, assert);
  } finally { const exit = await server.finish(); assert.equal(exit.code, 0); assert.equal(server.stderr, ''); }
});

test('M01 SIGTERM mid-request follows the EOF withdrawal path and exits cleanly', { timeout: 15_000 }, async () => {
  const directory = await mkdtemp(join(tmpdir(), 'blindpass-mcp-sigterm-')); const events = join(directory, 'events');
  const server = launch(abortFixture, { env: { P05_MCP_EVENT_FILE: events } });
  try {
    server.send(submit);
    await waitUntil(async () => (await readFile(events, 'utf8').catch(() => '')).includes('submitted'), { label: 'submission' });
    server.child.kill('SIGTERM');
    const exit = await Promise.race([server.closed, new Promise((_, reject) => setTimeout(() => reject(new Error('SIGTERM left the server running')), 8000))]);
    assert.deepEqual(exit, { code: 0, signal: null });
    assert.equal((await readFile(events, 'utf8')).trim(), 'submitted\nwithdrawal');
    assert.equal(server.stderr, ''); assertProtocolOnly(server, assert);
    assert.ok(!server.lines.some(line => line.id === 11), 'an aborted request must not be answered');
  } finally { server.kill(); await server.closed; await rm(directory, { recursive: true, force: true }); }
});

test('M01 the broker client bound is clearly shorter than the outer 30s tool bound and is enforced at startup', () => {
  assert.equal(CALL_TIMEOUT_MS, 30_000);
  assert.ok(CALL_TIMEOUT_MS - BROKER_CALL_TIMEOUT_MS >= 1000, 'margin between inner and outer bound must be at least one second');
  const identity = { nodeId: 'node-a', workloadId: 'workload-a', unit: 'agent.service', invocationId: 'a'.repeat(32) };
  assert.equal(createBrokerClient(identity).callTimeoutMs, BROKER_CALL_TIMEOUT_MS);
  assert.throws(() => createBrokerClient(identity, { callTimeoutMs: BROKER_CALL_TIMEOUT_MS + 1 }));
  assert.throws(() => createBrokerClient(identity, { callTimeoutMs: CALL_TIMEOUT_MS - 100 }));
  const inner = { request: async () => ({}), status: async () => ({}), cancel: async () => ({}), callTimeoutMs: 2000 };
  assert.throws(() => createMcpServer({ brokerClient: inner, toolTimeoutMs: 2500 }), /invalid_tool_configuration/);
  createMcpServer({ brokerClient: inner, toolTimeoutMs: 3000 });
  createMcpServer({ brokerClient: { ...inner, callTimeoutMs: undefined }, toolTimeoutMs: 100 });
});

test('M01 a stalled submission and withdrawal resolve as safe uncertainty before the outer tool bound', { timeout: 15_000 }, async () => {
  const server = launch(orderingFixture, { env: { P05_BROKER_CALL_MS: '800', P05_BROKER_CLEANUP_MS: '200', P05_TOOL_MS: '2500' } });
  try {
    const started = performance.now();
    const result = await server.request('tools/call', { name: 'blindpass_request_operation',
      arguments: { action: 'browser.session', resourceId: 'report-primary', requestKey: 'retry_0123456789abcdef' }, _meta: modern }, { timeoutMs: 6000 });
    assert.notEqual(result.result.isError, true, 'the agent must see uncertainty, not Operation failed');
    assert.deepEqual(result.result.structuredContent, { status: 'uncertain', requestKey: 'retry_0123456789abcdef', cancellation: 'unconfirmed' });
    assert.ok(performance.now() - started < 2500, 'uncertain result arrived after the outer bound');
  } finally { server.kill(); await server.closed; }
});
