// SPDX-License-Identifier: MIT
import { createBrokerClient } from '../src/broker-client.mjs';
import { runMcpServerStdio } from '../src/index.mjs';

// Scaled-down timing so the ordering (broker bound < outer tool bound) can be
// exercised without waiting the production 27 s / 30 s. Every exchange stalls
// after submission, so the client must resolve through its own bounds.
const brokerClient = createBrokerClient({ nodeId: 'node-a', workloadId: 'workload-a', unit: 'agent.service', invocationId: 'a'.repeat(32) }, {
  callTimeoutMs: Number(process.env.P05_BROKER_CALL_MS), cleanupTimeoutMs: Number(process.env.P05_BROKER_CLEANUP_MS),
  async exchange(_frame, { onSent }) { onSent(); return new Promise(() => {}); },
});
runMcpServerStdio({ brokerClient, toolTimeoutMs: Number(process.env.P05_TOOL_MS) });
