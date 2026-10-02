// SPDX-License-Identifier: AGPL-3.0-only
// Root driver labels select a fixture profile. They never establish authority;
// the production broker still verifies the peer's kernel unit and invocation.
export function guestWorkload(values) {
  const nodeId = values.BLINDPASS_P05_NODE_ID;
  const workloadId = values.BLINDPASS_P05_WORKLOAD_ID;
  if (nodeId === undefined && workloadId === undefined) return { nodeId: 'node-a', workloadId: 'p05-agent' };
  const valid = value => typeof value === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(value);
  if (!valid(nodeId) || !valid(workloadId)) throw new Error('guest_workload_metadata_invalid');
  return { nodeId, workloadId };
}
