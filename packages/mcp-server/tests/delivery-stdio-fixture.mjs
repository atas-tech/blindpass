// SPDX-License-Identifier: MIT
import { serveStdio } from '@modelcontextprotocol/server/stdio';
import { createMcpServer } from '../src/index.mjs';
import { createStdioTransport } from '../src/stdio.mjs';
import { createDeliveryRouter, createUrlElicitationProvider } from '../src/deliver.mjs';
import { brokerClockMs } from '../src/broker-client.mjs';

// Synthetic URL and atomic in-memory ledger are transport fixtures only.
// No production delivery ledger, operator session or client UI is claimed.
const privateRequest = Object.freeze({ operationKey: 'operation_key_0001', elicitationId: 'elicitation_key_01',
  operatorId: 'operator-primary', nodeId: 'node-primary', invocationId: 'invocation-primary', intendedHostId: 'host-primary',
  deadlineMs: brokerClockMs() + 25_000,
  url: 'https://operator.example.test/input#P05-DELIVERY-URL-CODE-CANARY' });
// The transport records the first initialize request's protocolVersion, which
// the SDK does not expose; the URL gate also requires it to be the reviewed one.
const transport = createStdioTransport(process.stdin, process.stdout);
serveStdio(() => {
  let router; let reserved; let completed;
  const server = createMcpServer({ tools: [{ name: 'review_browser_request',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
    execute: async (_args, context) => {
      const status = await router.deliver(privateRequest, context, { operatorAuthenticated: true, operatorId: privateRequest.operatorId });
      return { content: [{ type: 'text', text: JSON.stringify(status) }] };
    } }] });
  router = createDeliveryRouter({ mode: 'browser_session', timeoutMs: 100,
    allowedOrigins: ['https://operator.example.test'], ledger: {
      async reserve(key, fingerprint) {
        if (reserved) return reserved !== fingerprint ? { status: 'conflict' }
          : completed ? { status: 'existing', result: completed } : { status: 'pending' };
        reserved = fingerprint; return { status: 'reserved' };
      },
      async complete(_key, _fingerprint, result) { completed = result; }
    }, providers: [createUrlElicitationProvider(server.server, { reviewedClients: [{ name: 'delivery-transport-contract', version: '1' }],
      requestedProtocolVersion: () => transport.requestedProtocolVersion }),
      { kind: 'operator_app', humanOnly: true, available: async () => ({ supported: true }), deliver: async () => 'delivered' }] });
  return server;
}, { legacy: 'serve', transport, onerror: () => {} });
