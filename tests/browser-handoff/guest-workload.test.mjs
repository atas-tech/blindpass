// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import test from 'node:test';
import { guestWorkload } from './guest-workload.mjs';

test('P05-PC08 guest driver retains the signed-fixture default profile', () => {
  assert.deepEqual(guestWorkload({}), { nodeId: 'node-a', workloadId: 'p05-agent' });
});

test('P05-PC08 guest driver accepts controller-issued node/workload metadata', () => {
  const nodeId = 'nd_01234567-89ab-4cde-8012-3456789abcde';
  const workloadId = 'wl_abcdef01-2345-4678-9012-3456789abcde';
  assert.deepEqual(guestWorkload({ BLINDPASS_P05_NODE_ID: nodeId, BLINDPASS_P05_WORKLOAD_ID: workloadId }), { nodeId, workloadId });
});

test('P05-PC08 guest driver refuses partial or substituted metadata', () => {
  for (const values of [
    { BLINDPASS_P05_NODE_ID: 'node-a' },
    { BLINDPASS_P05_WORKLOAD_ID: 'p05-agent' },
    { BLINDPASS_P05_NODE_ID: 'node-a\nWORK forged', BLINDPASS_P05_WORKLOAD_ID: 'p05-agent' },
    { BLINDPASS_P05_NODE_ID: 'node-a', BLINDPASS_P05_WORKLOAD_ID: '../other' },
    { BLINDPASS_P05_NODE_ID: '', BLINDPASS_P05_WORKLOAD_ID: '' },
  ]) assert.throws(() => guestWorkload(values), { message: 'guest_workload_metadata_invalid' });
});
