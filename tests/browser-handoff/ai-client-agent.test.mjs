// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { PassThrough } from 'node:stream';
import test from 'node:test';
import { startAiAgent } from './ai-client-agent.mjs';

const descriptors = ['browser_navigate', 'browser_wait_for', 'browser_snapshot'].map(name => ({ name,
  description: 'test descriptor', inputSchema: { type: 'object', properties: {}, additionalProperties: false } }));
async function fixture() {
  const input = new PassThrough(); const output = new PassThrough(); const frames = []; const calls = []; let opens = 0, closes = 0, aborts = 0;
  output.on('data', bytes => frames.push(JSON.parse(bytes.toString())));
  const agent = await startAiAgent({ input, output, profile: { cookieNames: ['__Host-bp-fixture'] },
    brokerClient: { abortActive() { aborts++; } }, openStock: () => {
      opens++; return { stderrBytes: 0, notify(method) { calls.push({ method }); },
        async request(method, params) { calls.push({ method, params });
          if (method === 'initialize') return { result: { protocolVersion: '2025-11-25' } };
          if (method === 'tools/list') return { result: { tools: descriptors } };
          return { result: { content: [{ type: 'text', text: 'private test reply' }] } };
        }, async close() { closes++; return 0; } };
    }, runProtocolStdio: async (options, streams) => {
      assert.equal(options.tools.length, 3); assert.ok(options.brokerClient);
      streams.input.on('data', bytes => { calls.push({ ordinary: JSON.parse(bytes.toString()) }); });
      return { async close() {} };
    } });
  return { agent, input, frames, calls, counts: () => ({ opens, closes, aborts }) };
}
const settle = () => new Promise(resolve => setImmediate(resolve));

test('P05-PC14B: workload worker uses actual registry, protocol factory, fixed private copy and reconnect', async () => {
  const { agent, input, frames, calls, counts } = await fixture();
  for (const [i, type] of ['startup', 'copy-session', 'restart-stock'].entries()) {
    input.write(JSON.stringify({ jsonrpc: '2.0', id: 'root_control_' + String(i).repeat(32), method: 'p05/private', params: { type } }) + '\n');
    await settle();
  }
  assert.equal(frames.length, 3); assert.deepEqual(frames[0].result, { ready: true });
  assert.equal(calls.filter(value => value.method === 'initialize').length, 2);
  assert.equal(calls.filter(value => value.method === 'tools/list').length, 2);
  const copy = calls.find(value => value.params?.name === 'browser_run_code_unsafe');
  assert.ok(copy.params.arguments.code.includes('__Host-bp-fixture'));
  assert.ok(!calls.some(value => value.ordinary?.method === 'p05/private'));
  input.write(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }) + '\n'); await settle();
  assert.equal(calls.at(-1).ordinary.method, 'tools/list');
  await agent.close(); assert.deepEqual(counts(), { opens: 2, closes: 2, aborts: 1 });
});

test('P05-PC14A: invalid private controls fail closed; EOF aborts broker and stock without private output', async () => {
  for (const message of [{ jsonrpc: '2.0', id: 1, method: 'p05/private', params: { type: 'copy-session' } },
    { jsonrpc: '2.0', id: 'root_control_' + '0'.repeat(32), method: 'p05/private', params: { type: 'arbitrary', code: 'PRIVATE-CODE' } }]) {
    const { agent, input, frames, counts } = await fixture(); input.write(JSON.stringify(message) + '\n');
    await agent.closed; assert.equal(agent.failed, true); assert.equal(frames.length, 0); assert.equal(counts().aborts, 1);
  }
  const { agent, input, counts } = await fixture(); input.end(); await agent.closed;
  assert.equal(agent.failed, false); assert.equal(counts().closes, 1); assert.equal(counts().aborts, 1);
});
