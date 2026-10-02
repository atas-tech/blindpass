// SPDX-License-Identifier: MIT
import { appendFile } from 'node:fs/promises';
import { createBrokerClient } from '../src/broker-client.mjs';
import { runMcpServerStdio } from '../src/index.mjs';
const brokerClient = createBrokerClient({ nodeId: 'node-a', workloadId: 'workload-a', unit: 'agent.service', invocationId: 'a'.repeat(32) }, {
  callTimeoutMs: 2000, cleanupTimeoutMs: 500,
  async exchange(frame, { onSent }) {
    onSent(); const operation = frame.trimEnd().split(' ')[5];
    await appendFile(process.env.P05_MCP_EVENT_FILE, operation.startsWith('request:') ? 'submitted\n' : 'withdrawal\n', { mode: 0o600 });
    if (operation.startsWith('request:')) return new Promise(() => {});
    return 'OK operation_cancel requested\n';
  },
});
runMcpServerStdio({ brokerClient });
