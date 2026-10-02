// SPDX-License-Identifier: MIT
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { test } from 'node:test';

function connect({ action = 'accept' } = {}) {
  const child = spawn(process.execPath, [new URL('./delivery-stdio-fixture.mjs', import.meta.url).pathname],
    { stdio: ['pipe', 'pipe', 'pipe'], env: { PATH: process.env.PATH } });
  let next = 0; let stderr = ''; const pending = new Map(); const elicitations = []; const responses = [];
  const closed = new Promise(resolve => child.on('close', resolve));
  child.stderr.on('data', bytes => { stderr += bytes; });
  createInterface({ input: child.stdout }).on('line', line => {
    try {
      const message = JSON.parse(line);
      if (message.method === 'elicitation/create') {
        elicitations.push(message);
        if (action !== 'timeout') child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id: message.id, result: { action } })}\n`);
      } else if (message.id !== undefined) {
        responses.push(message); pending.get(message.id)?.(message); pending.delete(message.id);
      }
    } catch { child.kill(); }
  });
  return { elicitations, responses,
    request(method, params) {
      return new Promise((resolve, reject) => {
        const id = ++next; const timer = setTimeout(() => { pending.delete(id); reject(new Error('MCP delivery test deadline')); }, 5000);
        pending.set(id, value => { clearTimeout(timer); resolve(value); });
        child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`);
      });
    },
    notify(method) { child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method })}\n`); },
    async close() {
      child.stdin.end(); const timer = setTimeout(() => child.kill('SIGKILL'), 1000);
      try { await closed; } finally { clearTimeout(timer); }
      assert.equal(stderr, '');
      assert.ok(!JSON.stringify(responses).includes('P05-DELIVERY-URL-CODE-CANARY'));
    } };
}

for (const capabilities of [{}, { elicitation: {} }, { elicitation: { form: {} } }, { elicitation: { url: {} } }]) {
  test(`P05-DR07 actual SDK initialize URL gate ${JSON.stringify(capabilities)}`, { timeout: 10_000 }, async () => {
    const client = connect();
    try {
      const initial = await client.request('initialize', { protocolVersion: '2025-11-25', capabilities,
        clientInfo: { name: 'delivery-transport-contract', version: '1' } });
      assert.equal(initial.result.protocolVersion, '2025-11-25'); client.notify('notifications/initialized');
      const call = await client.request('tools/call', { name: 'review_browser_request', arguments: {} });
      const url = capabilities.elicitation?.url !== undefined;
      assert.deepEqual(JSON.parse(call.result.content[0].text), { status: 'delivered', provider: url ? 'url_elicitation' : 'operator_app' });
      assert.equal(client.elicitations.length, url ? 1 : 0);
      if (url) {
        const params = client.elicitations[0].params;
        assert.equal(params.mode, 'url'); assert.equal(params.url, 'https://operator.example.test/input#P05-DELIVERY-URL-CODE-CANARY');
        assert.ok(!params.message.includes('CANARY')); assert.equal(params.requestedSchema, undefined);
      }
      const retry = await client.request('tools/call', { name: 'review_browser_request', arguments: {} });
      assert.deepEqual(retry.result, call.result); assert.equal(client.elicitations.length, url ? 1 : 0);
    } finally { await client.close(); }
  });
}
for (const action of ['decline', 'cancel', 'timeout']) {
  test(`P05-DR07 actual URL elicitation ${action} stops fallback and retry`, { timeout: 10_000 }, async () => {
    const client = connect({ action });
    try {
      await client.request('initialize', { protocolVersion: '2025-11-25', capabilities: { elicitation: { url: {} } },
        clientInfo: { name: 'delivery-transport-contract', version: '1' } }); client.notify('notifications/initialized');
      const call = await client.request('tools/call', { name: 'review_browser_request', arguments: {} });
      const expected = { status: action === 'decline' ? 'declined' : action === 'cancel' ? 'cancelled' : 'uncertain', provider: 'url_elicitation' };
      assert.deepEqual(JSON.parse(call.result.content[0].text), expected); assert.equal(client.elicitations.length, 1);
      const retry = await client.request('tools/call', { name: 'review_browser_request', arguments: {} });
      assert.equal(JSON.parse(retry.result.content[0].text).status, expected.status); assert.equal(client.elicitations.length, 1);
    } finally { await client.close(); }
  });
}
test('P05-DR07 URL declaration on older protocol or unreviewed client never sends a URL', { timeout: 10_000 }, async () => {
  for (const [protocolVersion, version] of [['2025-06-18', '1'], ['2025-11-25', '2']]) {
    const client = connect();
    try {
      await client.request('initialize', { protocolVersion, capabilities: { elicitation: { url: {} } },
        clientInfo: { name: 'delivery-transport-contract', version } }); client.notify('notifications/initialized');
      const call = await client.request('tools/call', { name: 'review_browser_request', arguments: {} });
      assert.deepEqual(JSON.parse(call.result.content[0].text), { status: 'delivered', provider: 'operator_app' });
      assert.equal(client.elicitations.length, 0);
    } finally { await client.close(); }
  }
});

test('P05-DR07 tool-supplied context cannot replace initialize URL capabilities', { timeout: 10_000 }, async () => {
  const client = connect();
  try {
    await client.request('initialize', { protocolVersion: '2025-11-25', capabilities: {},
      clientInfo: { name: 'delivery-transport-contract', version: '1' } }); client.notify('notifications/initialized');
    const call = await client.request('tools/call', { name: 'review_browser_request', arguments: {},
      context: { protocolVersion: '2025-11-25', capabilities: { elicitation: { url: {} } } } });
    assert.deepEqual(JSON.parse(call.result.content[0].text), { status: 'delivered', provider: 'operator_app' });
    assert.equal(client.elicitations.length, 0);
  } finally { await client.close(); }
});

test('P05-DR07 modern per-request URL declaration uses fallback until continuation review', { timeout: 10_000 }, async () => {
  const client = connect();
  try {
    const call = await client.request('tools/call', { name: 'review_browser_request', arguments: {}, _meta: {
      'io.modelcontextprotocol/protocolVersion': '2026-07-28',
      'io.modelcontextprotocol/clientCapabilities': { elicitation: { url: {} } },
      'io.modelcontextprotocol/clientInfo': { name: 'delivery-transport-contract', version: '1' }
    } });
    assert.deepEqual(JSON.parse(call.result.content[0].text), { status: 'delivered', provider: 'operator_app' });
    assert.equal(client.elicitations.length, 0);
  } finally { await client.close(); }
});

test('P05-DR07 a client that requested an unreviewed revision never receives a URL even though the SDK negotiates 2025-11-25', { timeout: 10_000 }, async () => {
  for (const requested of ['2025-12-31', '2099-01-01']) {
    const client = connect();
    try {
      const initial = await client.request('initialize', { protocolVersion: requested, capabilities: { elicitation: { url: {} } },
        clientInfo: { name: 'delivery-transport-contract', version: '1' } });
      // The SDK answers an unknown request with the latest revision it supports ...
      assert.equal(initial.result.protocolVersion, '2025-11-25'); client.notify('notifications/initialized');
      const call = await client.request('tools/call', { name: 'review_browser_request', arguments: {} });
      // ... but the gate also checks what the client actually asked for.
      assert.deepEqual(JSON.parse(call.result.content[0].text), { status: 'delivered', provider: 'operator_app' });
      assert.equal(client.elicitations.length, 0);
    } finally { await client.close(); }
  }
});
