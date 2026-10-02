// SPDX-License-Identifier: AGPL-3.0-only
import { RootMcpBridge } from './ai-client-bridge.mjs';
import { readJsonFrames } from './json-frame-reader.mjs';

// Private responses dispatch immediately: a normal observer can await a Root
// probe without blocking the stdout pump that delivers its reply.
export function createAgentPipe({ child, sendModel, onServer, canaries, onFailure = () => {} }) {
  let stopped = false; let failure = false; let queued = 0; let queue = Promise.resolve(); let stderrBytes = 0; let stopReader;
  let diagnosticStage; let stockFailure; let transportFailure; let diagnosticBuffer = '';
  const bridge = new RootMcpBridge({ sendServer: message => {
    if (stopped || !child.stdin.write(JSON.stringify(message) + '\n')) throw new Error('client_transport_failed');
  }, sendModel, onServer, canaries });
  function close() { if (stopped) return; stopped = true; stopReader?.(); child.stdin.end(); bridge.close(); }
  function fail() { if (failure || stopped) return; failure = true; close(); onFailure(); }
  child.stdin.on('error', fail); child.stdout.on('error', fail); child.once('error', fail);
  child.stderr.on('data', bytes => {
    stderrBytes += bytes.length;
    diagnosticBuffer += bytes.toString('utf8'); bytes.fill(0);
    for (const line of diagnosticBuffer.split('\n').slice(0, -1)) {
      const match = /^P05-AI-AGENT failed stage=(stock-open|stock-initialize|stock-registry|sdk-start)$/.exec(line);
      if (match) diagnosticStage = match[1];
      const stockMatch = /^P05-AI-STOCK failed tool=(browser_navigate|browser_wait_for|browser_snapshot) reason=(read-only|permission|address-family|connection|timeout|no-page|closed|upstream|transport)$/.exec(line);
      if (stockMatch) stockFailure = `${stockMatch[1]}:${stockMatch[2]}`;
      const transportMatch = /^P05-AI-TRANSPORT failed reason=(child-close|child-error|stream-error|stdout-end|frame-size|decode|shape|notification|reply-shape|reply-id|deadline)$/.exec(line);
      if (transportMatch) transportFailure = transportMatch[1];
    }
    diagnosticBuffer = diagnosticBuffer.slice(diagnosticBuffer.lastIndexOf('\n') + 1).slice(-192);
  }); child.stderr.on('error', fail);
  stopReader = readJsonFrames(child.stdout, message => {
    if (typeof message.id === 'string' && message.id.startsWith('root_control_')) {
      bridge.fromServer(message).catch(fail); return;
    }
    if (++queued > 16) { fail(); return; }
    queue = queue.then(() => { if (!stopped) return bridge.fromServer(message); }).catch(fail).finally(() => { queued--; });
  }, fail, () => { if (!stopped) fail(); });
  return { bridge, close, drain: () => queue, get failed() { return failure; }, get stderrBytes() { return stderrBytes; }, get diagnosticStage() { return diagnosticStage; }, get stockFailure() { return stockFailure; }, get transportFailure() { return transportFailure; } };
}
