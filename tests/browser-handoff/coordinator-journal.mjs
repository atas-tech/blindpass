// SPDX-License-Identifier: AGPL-3.0-only
// Match the protected journal's nested binding, never an absent top-level ID.
export function findOperationRecord(snapshot, operationId, state) {
  if (typeof operationId !== 'string' || !/^op_[A-Za-z0-9_-]{1,125}$/.test(operationId)) throw new Error('invalid_operation_id');
  if (![3, 4].includes(snapshot?.version) || !Array.isArray(snapshot.records)) throw new Error('invalid_session_journal');
  return snapshot.records.find(record => record.binding?.operation_id === operationId && record.state === state);
}
export function findNewJournalRecord(before, after) {
  if (!Array.isArray(before?.records) || !Array.isArray(after?.records)) throw new Error('invalid_session_journal');
  const previous = new Set(before.records.map(record => record.binding?.operation_id));
  const added = after.records.filter(record => typeof record.binding?.operation_id === 'string' && !previous.has(record.binding.operation_id));
  if (added.length !== 1) throw new Error('ambiguous_new_record');
  return added[0];
}
