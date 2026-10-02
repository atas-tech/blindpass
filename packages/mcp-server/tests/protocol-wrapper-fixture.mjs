// SPDX-License-Identifier: MIT
import { runProtocolStdio } from '../../openclaw-plugin/mcp-server.mjs';
await runProtocolStdio({ tools: [{ name: 'safe_status', description: 'Embedding callback',
  inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  execute: async () => ({ content: [{ type: 'text', text: 'ready' }] }),
}] });
