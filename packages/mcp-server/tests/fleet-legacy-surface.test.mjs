// SPDX-License-Identifier: MIT
// P05-D8 / M07: fleet mode must not keep the legacy plaintext/raw-link/channel
// exposure switches beside the broker tools.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createMcpOptions } from '../../openclaw-plugin/mcp-server.mjs';
import { launch } from './stdio-harness.mjs';

const entry = new URL('../../openclaw-plugin/mcp-server.mjs', import.meta.url);
const broker = { request: async () => ({}), status: async () => ({}), cancel: async () => ({}) };
const fleetEnv = { BLINDPASS_FLEET_MCP: '1', BLINDPASS_NODE_ID: 'node-a', BLINDPASS_WORKLOAD_ID: 'workload-a',
  BLINDPASS_WORKLOAD_UNIT: 'agent.service', INVOCATION_ID: 'a'.repeat(32), BLINDPASS_AUTO_PERSIST: 'false' };
const EXPOSURE = ['raw_link', 'channel_id', 'channel', 'target'];
const FAILED = { isError: true, content: [{ type: 'text', text: 'Operation failed' }] };
const runtime = { emitManagedStoreBootstrapReminderFn: async () => ({ emitted: false }), listManagedSecretNamesFn: async () => ({ names: [] }) };

test('P05-D8 fleet mode drops the exposure parameters from every legacy schema; non-fleet keeps them', () => {
  const legacy = createMcpOptions({ runtime, env: {} });
  const request = legacy.tools.find(tool => tool.name === 'request_secret');
  for (const name of EXPOSURE) assert.ok(name in request.inputSchema.properties, `non-fleet ${name} must be unchanged`);
  const fleet = createMcpOptions({ runtime, env: {}, brokerClient: broker });
  assert.deepEqual(fleet.tools.map(tool => tool.name), legacy.tools.map(tool => tool.name));
  for (const tool of fleet.tools) {
    for (const name of [...EXPOSURE, 'chat_id']) assert.ok(!(name in tool.inputSchema.properties), `${tool.name} still lists ${name}`);
    assert.equal(tool.inputSchema.additionalProperties, false);
  }
  const retained = Object.keys(fleet.tools.find(tool => tool.name === 'request_secret').inputSchema.properties).sort();
  assert.deepEqual(retained, ['description', 'persist', 're_request', 'secret_name']);
  assert.equal(fleet.brokerClient, broker);
});

test('P05-D8 fleet handlers reject any exposure argument with the fixed error before the legacy handler runs', async () => {
  let reached = 0;
  const fleet = createMcpOptions({ runtime, env: {}, brokerClient: broker,
    toolContext: { get probe() { reached++; return undefined; } } });
  for (const tool of fleet.tools) {
    for (const name of [...EXPOSURE, 'chat_id']) for (const value of [true, false, 'P05-EXPOSURE-CANARY', null, undefined]) {
      const result = await tool.execute({ description: 'x', secret_name: 'a', [name]: value }, { mcpReq: {} });
      assert.deepEqual(result, FAILED); assert.ok(!JSON.stringify(result).includes('CANARY'));
    }
  }
  assert.equal(reached, 0, 'a legacy handler ran for a rejected call');
  const permitted = fleet.tools.find(tool => tool.name === 'list_secrets');
  await permitted.execute({}, { mcpReq: {} }); assert.equal(reached, 1);
  // Non-fleet behaviour is unchanged: the arguments are not rejected by the adapter.
  const legacy = createMcpOptions({ runtime, env: {}, toolContext: { get probe() { reached++; return undefined; } } });
  await legacy.tools.find(tool => tool.name === 'list_secrets').execute({ target: 'x' }, { mcpReq: {} });
  assert.equal(reached, 2);
});

test('P05-D8 fleet startup fails closed when either legacy exposure environment switch is set', () => {
  for (const env of [{ OPENCLAW_SECRETS_RAW_LINK: '1' }, { OPENCLAW_SECRETS_RAW_LINK: 'true' }, { BLINDPASS_ALLOW_EXPOSE_PLAINTEXT: 'true' },
    { BLINDPASS_ALLOW_EXPOSE_PLAINTEXT: '1' }, { BLINDPASS_ALLOW_EXPOSE_PLAINTEXT: 'P05-ENV-CANARY' }, { OPENCLAW_SECRETS_RAW_LINK: 'yes', BLINDPASS_ALLOW_EXPOSE_PLAINTEXT: 'on' }]) {
    assert.throws(() => createMcpOptions({ runtime, env, brokerClient: broker }), error => error.message === 'invalid_startup' && !String(error.stack).includes('CANARY'));
  }
  for (const env of [{}, { OPENCLAW_SECRETS_RAW_LINK: '' }, { OPENCLAW_SECRETS_RAW_LINK: '0' }, { BLINDPASS_ALLOW_EXPOSE_PLAINTEXT: 'false' }, { BLINDPASS_ALLOW_EXPOSE_PLAINTEXT: 'off', OPENCLAW_SECRETS_RAW_LINK: 'no' }]) {
    createMcpOptions({ runtime, env, brokerClient: broker });
  }
  // Non-fleet startup ignores the switches (existing behaviour).
  createMcpOptions({ runtime, env: { OPENCLAW_SECRETS_RAW_LINK: '1', BLINDPASS_ALLOW_EXPOSE_PLAINTEXT: 'true' } });
});

for (const env of [{ OPENCLAW_SECRETS_RAW_LINK: '1' }, { BLINDPASS_ALLOW_EXPOSE_PLAINTEXT: 'true-P05-ENV-CANARY' }]) {
  test(`P05-D8 actual stdio startup refuses fleet mode with ${Object.keys(env)[0]} set: exit 64, no output, no echo`, { timeout: 10_000 }, async () => {
    const server = launch(entry, { env: { ...fleetEnv, ...env } });
    const exit = await Promise.race([server.closed, new Promise((_, reject) => setTimeout(() => reject(new Error('refused startup left a process running')), 5000))]);
    assert.equal(exit.code, 64); assert.equal(server.stdout, ''); assert.equal(server.stderr, '');
  });
}

test('P05-D8 actual stdio fleet mode lists broker tools plus legacy tools without exposure parameters and rejects them', { timeout: 15_000 }, async () => {
  const server = launch(entry, { env: fleetEnv });
  try {
    await server.initialize(); server.notify('notifications/initialized');
    const listed = (await server.request('tools/list', {})).result.tools;
    const names = listed.map(tool => tool.name);
    for (const name of ['blindpass_request_operation', 'blindpass_operation_status', 'blindpass_cancel_operation', 'request_secret', 'list_secrets']) assert.ok(names.includes(name), name);
    for (const tool of listed.filter(tool => !tool.name.startsWith('blindpass_'))) {
      for (const name of EXPOSURE) assert.ok(!(name in tool.inputSchema.properties), `${tool.name} lists ${name}`);
    }
    for (const exposure of [{ raw_link: true }, { channel_id: 'P05-EXPOSURE-CANARY' }, { target: 'P05-EXPOSURE-CANARY' }, { channel: 'telegram' }]) {
      const result = await server.request('tools/call', { name: 'request_secret', arguments: { description: 'P05 canary check', ...exposure } });
      assert.ok(result.error || result.result?.isError === true, 'exposure argument was accepted');
      // Rejected either by the SDK's strict-schema validation (names the key, never a value) or by the adapter's fixed error.
      if (result.result) assert.ok(result.result.content[0].text === 'Operation failed' || /^Input validation error: .*Unrecognized key/.test(result.result.content[0].text));
      assert.ok(!JSON.stringify(result).includes('CANARY'));
    }
    assert.ok(!server.stdout.includes('P05-EXPOSURE-CANARY'));
  } finally { const exit = await server.finish(); assert.equal(exit.code, 0); assert.equal(server.stderr, ''); }
});

test('P05-D8 actual stdio non-fleet mode keeps the legacy schemas and ignores the unused switches', { timeout: 15_000 }, async () => {
  const server = launch(entry, { env: { BLINDPASS_AUTO_PERSIST: 'false', OPENCLAW_SECRETS_RAW_LINK: '1' } });
  try {
    await server.initialize(); server.notify('notifications/initialized');
    const listed = (await server.request('tools/list', {})).result.tools;
    assert.ok(!listed.some(tool => tool.name.startsWith('blindpass_')));
    const request = listed.find(tool => tool.name === 'request_secret');
    for (const name of EXPOSURE) assert.ok(name in request.inputSchema.properties, name);
  } finally { const exit = await server.finish(); assert.equal(exit.code, 0); assert.equal(server.stderr, ''); }
});
