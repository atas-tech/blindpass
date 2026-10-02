// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import test from 'node:test';
import { StockMcpClient } from './stock-mcp-client.mjs';

function fixture(options = {}) {
  const child = new EventEmitter(); const sent = [];
  child.stdin = new PassThrough(); child.stdout = new PassThrough(); child.stderr = new PassThrough();
  child.stdin.on('data', bytes => sent.push(JSON.parse(bytes.toString())));
  child.stdin.on('finish', () => queueMicrotask(() => child.emit('close', 0)));
  child.kill = () => { child.emit('close', 1); return true; };
  const client = new StockMcpClient({ child, timeoutMs: 50, closeTimeoutMs: 50, ...options });
  return { client, child, sent, reply: value => child.stdout.write(JSON.stringify(value) + '\n') };
}

test('P05-PC14B: split actual newline replies preserve result and notification frames', async () => {
  const { client, child, sent } = fixture();
  const pending = client.request('initialize', { protocolVersion: '2025-11-25' });
  const frame = JSON.stringify({ jsonrpc: '2.0', id: sent[0].id, result: { protocolVersion: '2025-11-25' } }) + '\n';
  child.stdout.write(frame.slice(0, 9)); child.stdout.write(frame.slice(9));
  assert.equal((await pending).result.protocolVersion, '2025-11-25');
  client.notify('notifications/initialized'); assert.equal(sent[1].method, 'notifications/initialized');
  child.stderr.write(Buffer.from('PRIVATE-STOCK-ERROR')); assert.equal(client.stderrBytes, 19);
  assert.equal(await client.close(), 0);
});

test('P05-PC14B: stock tool-list notifications do not abort calls or expand the advertised registry', async () => {
  const { client, sent, reply } = fixture();
  const pending = client.request('tools/call', { name: 'browser_navigate', arguments: {} });
  reply({ jsonrpc: '2.0', method: 'notifications/tools/list_changed' });
  reply({ jsonrpc: '2.0', id: sent[0].id, result: { content: [{ type: 'text', text: 'report' }] } });
  assert.equal((await pending).result.content[0].text, 'report');
  assert.equal(sent.length, 1); await client.close();
});

test('P05-PC14C: stock transport diagnoses fixed failure categories without private frame text', async () => {
  for (const [bytes, reason] of [[Buffer.from('PRIVATE-SOURCE-CANARY\n'), 'decode'],
    [Buffer.from('x'.repeat(65537)), 'frame-size'],
    [Buffer.from(JSON.stringify({ jsonrpc: '2.0', method: 'PRIVATE-SOURCE-CANARY' }) + '\n'), 'notification'],
    [Buffer.from(JSON.stringify({ jsonrpc: '2.0', id: 99, result: {} }) + '\n'), 'reply-id']]) {
    const diagnostics = []; const { client, child } = fixture({ onFailure: value => diagnostics.push(value) });
    const pending = client.request('ping', {}); child.stdout.write(bytes);
    await assert.rejects(pending, { message: 'stock_transport_failed' });
    assert.deepEqual(diagnostics, [reason]); await client.close(); assert.deepEqual(diagnostics, [reason]);
  }
});

test('P05-PC14B: abort cancels the exact request; one late reply is withheld', async () => {
  const { client, sent, reply } = fixture(); const controller = new AbortController();
  const pending = client.request('tools/call', { name: 'browser_snapshot', arguments: {} }, { signal: controller.signal });
  controller.abort(); await assert.rejects(pending, { message: 'stock_transport_failed' });
  assert.equal(sent[1].method, 'notifications/cancelled'); assert.equal(sent[1].params.requestId, sent[0].id);
  reply({ jsonrpc: '2.0', id: sent[0].id, result: { content: [] } });
  const next = client.request('ping', {}); reply({ jsonrpc: '2.0', id: sent.at(-1).id, result: {} }); await next;
  await client.close();
});

test('P05-PC14B: deadlines cancel, and closed or already aborted requests never write', async () => {
  const { client, sent } = fixture({ timeoutMs: 5 });
  await assert.rejects(client.request('ping', {}), { message: 'stock_transport_failed' });
  assert.equal(sent[1].method, 'notifications/cancelled');
  const controller = new AbortController(); controller.abort();
  await assert.rejects(client.request('ping', {}, { signal: controller.signal }), { message: 'stock_transport_failed' });
  assert.equal(sent.length, 2); await client.close();
  await assert.rejects(client.request('ping', {}), { message: 'stock_transport_failed' });
});

test('P05-PC14B: invalid JSON, UTF-8, unknown replies and oversized frames reject with fixed errors', async () => {
  for (const bytes of [Buffer.from('PRIVATE-STOCK-ERROR\n'), Buffer.from([255, 10]), Buffer.from('x'.repeat(65537)),
    Buffer.from(JSON.stringify({ jsonrpc: '2.0', id: 99, result: {} }) + '\n')]) {
    const { client, child } = fixture(); const pending = client.request('ping', {});
    child.stdout.write(bytes); await assert.rejects(pending, { message: 'stock_transport_failed' });
    await client.close();
  }
});

test('P05-PC14B: child error/EOF reject pending calls and limit concurrency and outbound frame size', async () => {
  for (const event of ['error', 'close', 'end']) {
    const { client, child } = fixture(); const pending = client.request('ping', {});
    if (event === 'end') child.stdout.end(); else child.emit(event, new Error('PRIVATE-STOCK-ERROR'));
    await assert.rejects(pending, { message: 'stock_transport_failed' }); await client.close();
  }
  const { client } = fixture();
  const pending = Array.from({ length: 8 }, () => client.request('ping', {}).catch(error => error.message));
  await assert.rejects(client.request('ping', {}), { message: 'stock_transport_failed' });
  await assert.rejects(client.request('tools/call', { data: 'x'.repeat(65536) }), { message: 'stock_transport_failed' });
  await client.close(); assert.deepEqual(await Promise.all(pending), Array(8).fill('stock_transport_failed'));
});
