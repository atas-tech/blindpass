// SPDX-License-Identifier: MIT
import { runMcpServerStdio } from '../src/index.mjs';
runMcpServerStdio({ toolTimeoutMs: 80, tools: [{ name: 'bounded_legacy', inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  execute: async (_args, context) => new Promise((_, reject) => context.mcpReq.signal.addEventListener('abort', () => reject(new Error('P05-TIMEOUT-PRIVATE-CANARY')), { once: true })) }] });
