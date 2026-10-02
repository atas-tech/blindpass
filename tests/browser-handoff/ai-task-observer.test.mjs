// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import test from 'node:test';
import { AiTaskObserver } from './ai-task-observer.mjs';

test('P05-PC14D: actual broker request, ready, report reads, reconnect and cancel must all be observed', async () => {
  const stages = [];
  const value = new AiTaskObserver({ requested: async key => stages.push(key), ready: async () => stages.push('ready'),
    firstSnapshot: async () => stages.push('reconnect'), cancelled: () => stages.push('cancel') });
  let id = 0;
  async function call(name, result) {
    const requestId = ++id; value.fromModel({ jsonrpc: '2.0', id: requestId, method: 'tools/call', params: { name } });
    await value.fromServer({ jsonrpc: '2.0', id: requestId, result });
  }
  await call('blindpass_request_operation', { structuredContent: { status: 'requested', eventKey: 'event_' + '1'.repeat(32) } });
  await call('blindpass_operation_status', { structuredContent: { status: 'ready' } });
  for (let i = 0; i < 2; i++) {
    await call('browser_navigate', { content: [] }); await call('browser_wait_for', { content: [] });
    await call('browser_snapshot', { content: [{ type: 'text', text: 'Coordinator report: 12 artifacts' }] });
  }
  await call('blindpass_cancel_operation', { structuredContent: { status: 'cancellation_requested' } });
  assert.deepEqual(value.result(), { brokerRequests: 1, readyObserved: true, stockReportReads: 2, stockReconnects: 1, cancellationRequested: true });
  assert.deepEqual(stages, ['event_' + '1'.repeat(32), 'ready', 'reconnect', 'cancel']);
});

test('P05-PC14D: a second report snapshot requires a fresh completed navigation and wait', async () => {
  const value = new AiTaskObserver({ requested: async () => {}, ready: async () => {}, firstSnapshot: async () => {}, cancelled: () => {} });
  let id = 0;
  async function call(name, result) {
    const requestId = ++id; value.fromModel({ jsonrpc: '2.0', id: requestId, method: 'tools/call', params: { name } });
    await value.fromServer({ jsonrpc: '2.0', id: requestId, result });
  }
  await call('blindpass_request_operation', { structuredContent: { status: 'requested', eventKey: 'event_' + '1'.repeat(32) } });
  await call('blindpass_operation_status', { structuredContent: { status: 'ready' } });
  await call('browser_navigate', { content: [] }); await call('browser_wait_for', { content: [] });
  const report = { content: [{ type: 'text', text: 'Coordinator report: 12 artifacts' }] };
  await call('browser_snapshot', report);
  await assert.rejects(call('browser_snapshot', report), { message: 'client_task_failed' });
  assert.equal(value.result().stockReportReads, 1);
  value.fromModel({ jsonrpc: '2.0', id: ++id, method: 'tools/call', params: { name: 'PRIVATE-SOURCE-CANARY' } });
  await value.fromServer({ jsonrpc: '2.0', id, result: {} });
  assert.equal(value.toolTrace.at(-1), 'other'); assert.ok(!value.toolTrace.join(',').includes('PRIVATE-'));
});

test('P05-PC14D: partial/error/duplicate requests and untrusted artifact answers cannot establish task success', async () => {
  const value = new AiTaskObserver({ requested: async () => {}, ready: async () => {}, firstSnapshot: async () => {}, cancelled: () => {} });
  value.fromModel({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'browser_snapshot' } });
  await assert.rejects(value.fromServer({ jsonrpc: '2.0', id: 1, result: { content: [{ type: 'text', text: 'PRIVATE-INVALID' }] } }), { message: 'client_task_failed' });
  assert.equal(value.result().stockReportReads, 0);
  value.fromModel({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'blindpass_request_operation' } });
  await assert.rejects(value.fromServer({ jsonrpc: '2.0', id: 2, result: { isError: true, content: [] } }), { message: 'client_task_failed' });
  assert.equal(value.lastTool, 'blindpass_request_operation'); assert.equal(value.failureReason, 'tool-error');
});
