// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import test from 'node:test';
import { findOperationRecord, findNewJournalRecord } from './coordinator-journal.mjs';
const first = `op_${'1'.repeat(32)}`, second = `op_${'2'.repeat(32)}`;
test('P05-PC08 automatic intent uses an exact SHA-256 operation ID', () => {
  const operation = `op_${'abc01234'.repeat(8)}`;
  const record = { binding: { operation_id: operation }, state: 'closed' };
  const short = { binding: { operation_id: operation.slice(0, 35) }, state: 'closed' };
  assert.equal(findOperationRecord({ version: 4, records: [short, record] }, operation, 'closed'), record);
});
test('P05-PC08 operation selection rejects framing/path/size substitutions', () => {
  for (const id of ['op_', 'op_a\nWORK other', 'op_../other', `op_${'a'.repeat(126)}`, 'op_é']) {
    assert.throws(() => findOperationRecord({ version: 4, records: [] }, id, 'closed'), { message: 'invalid_operation_id' });
  }
});
test('P05-PC08 actual controller UUID IDs match only their exact nested record', () => {
  const operation = 'op_01234567-89ab-4cde-8012-3456789abcde';
  const record = { binding: { operation_id: operation }, state: 'closed' };
  const fixture = { binding: { operation_id: operation.replaceAll('-', '') }, state: 'closed' };
  assert.equal(findOperationRecord({ version: 4, records: [fixture, record] }, operation, 'closed'), record);
});
test('a previous closure cannot satisfy another operation recovery', () => {
  const closed = { binding: { operation_id: first }, state: 'closed' };
  const pending = { binding: { operation_id: second }, state: 'blocked_uncertain' };
  const snapshot = { version: 4, records: [closed, pending] };
  assert.equal(findOperationRecord(snapshot, second, 'closed'), undefined);
  assert.equal(findOperationRecord(snapshot, first, 'closed'), closed);
  pending.state = 'closed';
  assert.equal(findOperationRecord(snapshot, second, 'closed'), pending);
});
test('missing or top-level-only operation IDs never authorize closure', () => {
  assert.throws(() => findOperationRecord({ version: 4, records: [] }, undefined, 'closed'));
  assert.equal(findOperationRecord({ version: 3, records: [{ operation_id: second, state: 'closed' }] }, second, 'closed'), undefined);
  assert.throws(() => findOperationRecord({ version: 2, records: [] }, second, 'closed'));
});
test('a new helper record is selected independently of journal sort order', () => {
  const old = { binding: { operation_id: first }, state: 'closed' };
  const added = { binding: { operation_id: 'helper-probe-123-456' }, state: 'reserved' };
  const before = { records: [old] };
  assert.equal(findNewJournalRecord(before, { records: [added, old] }), added);
  assert.throws(() => findNewJournalRecord(before, before));
  assert.throws(() => findNewJournalRecord(before, { records: [added, { binding: { operation_id: second } }, old] }));
});
