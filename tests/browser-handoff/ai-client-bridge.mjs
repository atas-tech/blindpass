// SPDX-License-Identifier: AGPL-3.0-only
// Root-owned disposable test transport. Private probes never reach the model.
import { randomBytes } from 'node:crypto';
const failed = () => new Error('client_transport_failed');
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const PREFIX = 'root_control_';
const METHODS = new Set(['server/discover', 'subscriptions/listen', 'initialize', 'notifications/initialized', 'notifications/cancelled', 'tools/list', 'tools/call', 'ping']);
const CONTROL = new Set(['startup', 'copy-session', 'restart-stock']);
const BROWSER_TOOLS = ['browser_navigate', 'browser_wait_for', 'browser_snapshot'];

export class RootMcpBridge {
  #sendServer; #sendModel; #observe; #canaries; #private = new Map(); #timeout; #closed = false;
  #transcript = []; #bytes = 0;
  exposureDetected = false;
  constructor({ sendServer, sendModel, onServer = async () => {}, canaries = [], privateTimeoutMs = 5000 }) {
    if (typeof sendServer !== 'function' || typeof sendModel !== 'function' || typeof onServer !== 'function'
      || !Array.isArray(canaries) || canaries.length > 16 || !Number.isInteger(privateTimeoutMs)
      || privateTimeoutMs < 1 || privateTimeoutMs > 5000) throw failed();
    this.#sendServer = sendServer; this.#sendModel = sendModel; this.#observe = onServer; this.#timeout = privateTimeoutMs;
    this.#canaries = ['ws+unix:', '/devtools/browser/'];
    for (const canary of canaries) this.addCanary(canary);
  }
  addCanary(value) {
    if (typeof value !== 'string' || value.length < 8 || value.length > 16384 || this.#canaries.length >= 32) throw failed();
    this.#canaries.push(value);
    this.#scan(this.#transcript.join(''));
  }
  #scan(text) {
    if (this.#canaries.some(canary => text.includes(canary))) { this.exposureDetected = true; throw failed(); }
  }
  #frame(message) {
    if (this.#closed || !object(message) || message.jsonrpc !== '2.0') throw failed();
    let text;
    try { text = JSON.stringify(message); } catch { throw failed(); }
    if (Buffer.byteLength(text) > 65536) throw failed();
    return text;
  }
  #remember(text) {
    this.#scan(text); this.#bytes += Buffer.byteLength(text);
    if (this.#bytes > 2 * 1024 * 1024) throw failed();
    this.#transcript.push(text + '\n');
  }
  async fromModel(message) {
    const text = this.#frame(message);
    if (typeof message.id === 'string' && message.id.startsWith(PREFIX)
      || message.method === 'notifications/cancelled' && typeof message.params?.requestId === 'string' && message.params.requestId.startsWith(PREFIX)
      || message.method !== undefined && !METHODS.has(message.method)
      || message.method === undefined && (!Object.hasOwn(message, 'id') || (!Object.hasOwn(message, 'result') && !Object.hasOwn(message, 'error')))) throw failed();
    this.#remember(text);
    try { await this.#sendServer(message); } catch { throw failed(); }
  }
  async fromServer(message) {
    const text = this.#frame(message);
    if (typeof message.id === 'string' && message.id.startsWith(PREFIX)) {
      const pending = this.#private.get(message.id);
      if (!pending) throw failed();
      this.#private.delete(message.id); clearTimeout(pending.timer);
      if (message.error || !Object.hasOwn(message, 'result')) pending.reject(failed());
      else pending.resolve(message.result);
      return;
    }
    if (message.method === 'p05/private') throw failed();
    this.#remember(text);
    try { await this.#observe(message); this.#scan(text); await this.#sendModel(message); }
    catch { throw failed(); }
  }
  async control(type) {
    if (this.#closed || !CONTROL.has(type) || this.#private.size >= 4) throw failed();
    const id = PREFIX + randomBytes(16).toString('hex');
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { this.#private.delete(id); reject(failed()); }, this.#timeout);
      this.#private.set(id, { resolve, reject, timer });
      Promise.resolve().then(() => this.#sendServer({ jsonrpc: '2.0', id, method: 'p05/private', params: { type } })).catch(() => {
        this.#private.delete(id); clearTimeout(timer); reject(failed());
      });
    });
  }
  transcript() { return this.#transcript.join(''); }
  scanClientTranscript(text) {
    if (this.#closed || typeof text !== 'string' || Buffer.byteLength(text) > 2 * 1024 * 1024) throw failed();
    this.#scan(text);
  }
  close() {
    this.#closed = true;
    for (const entry of this.#private.values()) { clearTimeout(entry.timer); entry.reject(failed()); }
    this.#private.clear(); this.#transcript = [];
  }
}

export function browserTools(descriptors, getStock, onFailure = () => {}) {
  if (!Array.isArray(descriptors) || descriptors.length > 64 || typeof getStock !== 'function' || typeof onFailure !== 'function') throw failed();
  const registry = new Map();
  for (const descriptor of descriptors) {
    if (!object(descriptor) || typeof descriptor.name !== 'string' || registry.has(descriptor.name)) throw failed();
    registry.set(descriptor.name, descriptor);
  }
  return BROWSER_TOOLS.map(name => {
    const descriptor = registry.get(name);
    if (!descriptor || !object(descriptor.inputSchema) || descriptor.inputSchema.type !== 'object'
      || typeof descriptor.description !== 'string' || descriptor.description.length > 8192) throw failed();
    return { name, description: descriptor.description, inputSchema: descriptor.inputSchema,
      async execute(args, context) {
        let reply;
        try { reply = await getStock().request('tools/call', { name, arguments: args }, { signal: context.mcpReq.signal }); }
        catch { onFailure(name, 'transport'); throw failed(); }
        if (reply.error || !object(reply.result) || reply.result.isError === true) {
          // Only fixed categories cross the private diagnostic channel. Never
          // copy upstream errors, paths, endpoints or values into SDK errors.
          const text = (reply.result?.content ?? []).filter(item => item?.type === 'text' && typeof item.text === 'string')
            .map(item => item.text).join('\n').slice(0, 65536);
          const reason = /\bEROFS\b/.test(text) ? 'read-only' : /\b(EACCES|EPERM)\b/.test(text) ? 'permission'
            : /\bEAFNOSUPPORT\b/.test(text) ? 'address-family' : /\bECONNREFUSED\b/.test(text) ? 'connection'
              : /timeout|timed out/i.test(text) ? 'timeout' : /No open pages available|No open tabs/i.test(text) ? 'no-page'
                : /(?:page|context|browser).*has been closed|Target closed/i.test(text) ? 'closed' : 'upstream';
          onFailure(name, reason); throw failed();
        }
        return reply.result;
      } };
  });
}
