// SPDX-License-Identifier: MIT
import { runMcpServerStdio } from '../../openclaw-plugin/mcp-server.mjs';
runMcpServerStdio({ runtime: {
  emitManagedStoreBootstrapReminderFn: async () => ({ emitted: false }),
  listManagedSecretNamesFn: async () => { throw new Error('P05-LEGACY-RETURNED-URL-CODE-CANARY'); },
} });
