// SPDX-License-Identifier: MIT
import { runMcpServerStdio } from '../src/index.mjs';
runMcpServerStdio({ brokerClient: {
  request: async (args, signal) => {
    if (!(signal instanceof AbortSignal)) throw new Error('missing cancellation signal');
    if (args.resourceId === 'fail') throw new Error('P05-TOOL-PRIVATE-URL-CODE-CANARY');
    return { status: 'requested', requestKey: args.requestKey, eventKey: 'event_0123456789abcdef' };
  },
  status: async (eventKey) => eventKey === 'event_ready_0123456789abcdef' ? { status:'ready',contextHandle:'ctx_'+ 'a'.repeat(64),eventKey } : eventKey === 'event_completed_0123456789' ? { status: 'closed', outcome: 'completed', eventKey } : eventKey === 'event_malformed_0123456789' ? { status: 'pending', eventKey, sourcePassword: 'P05-MALFORMED-PRIVATE-CANARY' } : { status: 'pending', eventKey },
  cancel: async () => ({ status: 'cancellation_requested' }),
} });
