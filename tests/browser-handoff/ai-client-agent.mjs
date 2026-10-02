// SPDX-License-Identifier: AGPL-3.0-only
// The Root test driver owns stdin/stdout. The actual official SDK and stock
// subprocess share this registered non-root workload invocation.
import { PassThrough } from 'node:stream';
import { browserTools } from './ai-client-bridge.mjs';
import { readJsonFrames } from './json-frame-reader.mjs';
const failed = () => new Error('client_agent_failed');
const CONTROL = new Set(['startup', 'copy-session', 'restart-stock']);

export async function startAiAgent({ input, output, openStock, runProtocolStdio, brokerClient, profile, onStockFailure }) {
  if (!input || !output || typeof openStock !== 'function' || typeof runProtocolStdio !== 'function'
    || !brokerClient || !Array.isArray(profile?.cookieNames) || profile.cookieNames.length < 1
    || profile.cookieNames.some(name => !/^[A-Za-z0-9_-]{1,128}$/.test(name))) throw failed();
  const protocolInput = new PassThrough({ highWaterMark: 65536 });
  let stock; let handle; let stopped = false; let failure = false; let controls = 0; let queue = Promise.resolve();
  let stage = 'stock-open';
  let resolveClosed; const closed = new Promise(resolve => { resolveClosed = resolve; }); let closePromise; let stopReader;
  async function initializeStock() {
    const candidate = openStock(); stock = candidate;
    try {
      stage = 'stock-initialize';
      const initialized = await candidate.request('initialize', { protocolVersion: '2025-11-25', capabilities: {},
        clientInfo: { name: 'p05-actual-ai-stock-browser', version: '1' } });
      if (initialized.error || initialized.result?.protocolVersion !== '2025-11-25' || stopped) throw failed();
      candidate.notify('notifications/initialized');
      stage = 'stock-registry';
      const listed = await candidate.request('tools/list', {});
      if (listed.error || !listed.result || stopped) throw failed();
      return browserTools(listed.result.tools, () => stock, onStockFailure);
    } catch { await candidate.close(); throw failed(); }
  }
  async function close() {
    if (closePromise) return closePromise;
    stopped = true; stopReader?.(); protocolInput.end(); brokerClient.abortActive?.();
    closePromise = (async () => { try { await handle?.close(); await stock?.close(); }
      finally { resolveClosed(); } })();
    return closePromise;
  }
  const fail = () => { failure = true; close().catch(() => {}); };
  try {
    const tools = await initializeStock();
    stage = 'sdk-start';
    handle = await runProtocolStdio({ tools, brokerClient }, { input: protocolInput, output });
    stopReader = readJsonFrames(input, message => {
      if (message.method !== 'p05/private') {
        if (typeof message.id === 'string' && message.id.startsWith('root_control_')) { fail(); return; }
        if (!protocolInput.write(JSON.stringify(message) + '\n')) fail();
        return;
      }
      if (!/^root_control_[a-f0-9]{32}$/.test(message.id) || !message.params || Object.keys(message.params).length !== 1
        || !CONTROL.has(message.params.type) || controls >= 4) { fail(); return; }
      controls++;
      queue = queue.then(async () => {
        if (stopped) return;
        let result;
        try {
          if (message.params.type === 'startup') result = { ready: true };
          else if (message.params.type === 'restart-stock') { await stock.close(); await initializeStock(); result = { ready: true }; }
          else {
            const copied = await stock.request('tools/call', { name: 'browser_run_code_unsafe', arguments: {
              code: `async (page) => (await page.context().cookies()).filter(cookie => ${JSON.stringify(profile.cookieNames)}.includes(cookie.name)).map(cookie => cookie.name + "=" + cookie.value).join("; ")` } });
            if (copied.error || copied.result?.isError || !copied.result) throw failed();
            result = { copied: copied.result };
          }
          if (!stopped) output.write(JSON.stringify({ jsonrpc: '2.0', id: message.id, result }) + '\n');
        } catch {
          if (!stopped) output.write(JSON.stringify({ jsonrpc: '2.0', id: message.id,
            error: { code: -32603, message: 'Operation failed' } }) + '\n');
        } finally { controls--; }
      }).catch(fail);
    }, fail, () => { close().catch(fail); });
    stage = 'ready';
  } catch { failure = true; await close(); const error = failed(); error.stage = stage; throw error; }
  return { close, closed, get failed() { return failure; } };
}
