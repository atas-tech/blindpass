// SPDX-License-Identifier: MIT
import { runMcpServerStdio } from '../src/index.mjs';
runMcpServerStdio({ tools: [
  { name: 'safe_status', inputSchema: { type: 'object', properties: { resourceId: { type: 'string' } }, required: ['resourceId'], additionalProperties: false },
    execute: async () => ({ content: [{ type: 'text', text: 'ready' }] }) },
  { name: 'upstream_failure', inputSchema: { type: 'object', properties: {}, additionalProperties: false },
    execute: async () => { throw new Error('P05-URL-PASSWORD-CODE-CANARY', { cause: new Error('nested-private-cookie') }); } },
  { name: 'returned_failure', inputSchema: { type: 'object', properties: {}, additionalProperties: false },
    execute: async () => ({ isError: true, content: [{ type: 'text', text: 'P05-RETURNED-PRIVATE-CANARY' }],
      structuredContent: { endpoint: 'P05-RETURNED-PRIVATE-CANARY' } }) },
] });
