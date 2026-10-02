// SPDX-License-Identifier: MIT
import { McpServer } from '@modelcontextprotocol/server';
import { serveStdio } from '@modelcontextprotocol/server/stdio';
// zod is installed separately for this package and for the SDK server/core (all
// 4.6.5; tests/zod-identity.test.mjs fails if any copy drifts from the pin).
import { z } from 'zod';
import { createBrokerTools } from './broker-tools.mjs';
import { brokerClockMs, CALL_TIMEOUT_MS } from './broker-client.mjs';
import { createDiagnostics } from './diagnostics.mjs';
import { createStdioTransport } from './stdio.mjs';
export { createDeliveryRouter, createUrlElicitationProvider } from './deliver.mjs';
export { createDiagnostics } from './diagnostics.mjs';
export { createStdioTransport, MAX_MESSAGE_BYTES } from './stdio.mjs';

// After SIGTERM the connection is closed exactly as on EOF. If something still
// keeps the loop alive past this grace period (the broker client's withdrawal
// phase is bounded to 5 s), the process stops instead of ignoring the signal.
const SIGTERM_GRACE_MS = 8_000;
// The broker client's own bound must leave the outer bound this much room for
// its explicit "uncertain" result to be delivered.
const BROKER_BOUND_MARGIN_MS = 1_000;

const SAFE_FAILURE = Object.freeze({ isError: true, content: [{ type: 'text', text: 'Operation failed' }] });

async function executeBounded(tool, args, context, timeout) {
  const now = process.platform === 'linux' ? brokerClockMs : () => performance.now();
  const deadline = now() + timeout; const controller = new AbortController();
  const signal = context.mcpReq.signal; let rejectAbort;
  const stopped = new Promise((_, reject) => { rejectAbort = reject; });
  stopped.catch(() => {});
  const abort = () => { controller.abort(); rejectAbort(new Error('tool_interrupted')); };
  const check = () => { try { if (now() >= deadline || signal.aborted) abort(); } catch { abort(); } };
  signal.addEventListener('abort', abort, { once: true });
  const timer = setInterval(check, Math.min(25, timeout));
  try {
    check(); if (controller.signal.aborted) throw new Error('tool_interrupted');
    const result = await Promise.race([tool.execute(args, { ...context, mcpReq: { ...context.mcpReq, signal: controller.signal } }), stopped]);
    check(); if (controller.signal.aborted) throw new Error('tool_interrupted');
    return result;
  } finally { clearInterval(timer); signal.removeEventListener('abort', abort); controller.abort(); }
}

// Tool implementations are injected by the trusted runtime. This package does
// not import the OpenClaw plugin, login helper or AGPL controller/broker code.
export function createMcpServer({ tools = [], brokerClient, toolTimeoutMs = CALL_TIMEOUT_MS, diagnostics = createDiagnostics() } = {}) {
  if (!Number.isSafeInteger(toolTimeoutMs) || toolTimeoutMs < 1 || toolTimeoutMs > CALL_TIMEOUT_MS) throw new Error('invalid_tool_configuration');
  if (brokerClient?.callTimeoutMs !== undefined && !(Number.isSafeInteger(brokerClient.callTimeoutMs)
    && brokerClient.callTimeoutMs + BROKER_BOUND_MARGIN_MS <= toolTimeoutMs)) throw new Error('invalid_tool_configuration');
  if (!Array.isArray(tools) || tools.length > 64) throw new Error('invalid_tool_configuration');
  if (brokerClient !== undefined) tools = [...tools, ...createBrokerTools(brokerClient)];
  if (tools.length > 64) throw new Error('invalid_tool_configuration');
  const server = new McpServer({ name: 'blindpass', version: '0.1.0' }, { capabilities: { tools: {} } });
  if (typeof brokerClient?.abortActive === 'function') {
    const onclose = server.server.onclose;
    server.server.onclose = () => { brokerClient.abortActive(); onclose?.(); };
  }
  const names = new Set();
  for (const tool of tools) {
    if (!tool || typeof tool.name !== 'string' || !/^[a-z][a-z0-9_]{0,63}$/.test(tool.name)
      || names.has(tool.name) || typeof tool.execute !== 'function'
      || tool.inputSchema?.type !== 'object') throw new Error('invalid_tool_configuration');
    names.add(tool.name);
    let inputSchema;
    try { inputSchema = z.fromJSONSchema(tool.inputSchema); }
    catch { throw new Error('invalid_tool_configuration'); }
    server.registerTool(tool.name, { description: tool.description ?? '', inputSchema }, async (args, context) => {
      try {
        const result = await executeBounded(tool, args, context, toolTimeoutMs);
        if (result?.isError === true) throw new Error('tool_failed');
        return result;
      }
      catch (error) {
        diagnostics.record('tool', 'error', error?.message === 'tool_interrupted' ? 'interrupted' : 'failed');
        return { isError: SAFE_FAILURE.isError, content: SAFE_FAILURE.content.map((item) => ({ ...item })) };
      }
    });
  }
  return server;
}

export function runMcpServerStdio(options = {}, streams = {}) {
  const diagnostics = options.diagnostics ?? createDiagnostics();
  const transport = createStdioTransport(streams.input ?? process.stdin, streams.output ?? process.stdout,
    { onEvent: reason => diagnostics.record('transport', 'denied', reason) });
  // Upstream errors may contain request links, codes or cookies. Fixed tool
  // failures are returned above; transport exceptions never reach stderr and the
  // optional sink records only a fixed reason code, never the error itself.
  const handle = serveStdio(() => createMcpServer({ ...options, diagnostics }), { legacy: 'serve', transport, onerror: diagnostics.onerror });
  // SIGTERM follows the EOF path: closing the connection aborts in-flight calls,
  // so a submitted broker request is withdrawn before the process exits.
  const host = streams.process ?? (streams.input === undefined ? process : undefined);
  if (host) {
    host.once('SIGTERM', () => {
      diagnostics.record('transport', 'completed', 'signal');
      handle.close().catch(() => {});
      setTimeout(() => host.exit?.(1), SIGTERM_GRACE_MS).unref();
    });
  }
  return handle;
}
