// SPDX-License-Identifier: AGPL-3.0-only
// Bounded stdio client for the actual pinned stock browser tool. Upstream
// stderr is counted and discarded; transport errors carry no private text.
const failed = () => new Error('stock_transport_failed');
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
export class StockMcpClient {
  #child; #pending = new Map(); #retired = new Set(); #sequence = 0; #buffer = Buffer.alloc(0);
  #timeout; #closeTimeout; #failed = false; #ended = false; #closed; #closePromise; #onFailure;
  stderrBytes = 0;
  constructor({ child, timeoutMs = 15000, closeTimeoutMs = 5000, onFailure = () => {} }) {
    if (!child?.stdin || !child.stdout || !child.stderr || !Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 15000
      || !Number.isInteger(closeTimeoutMs) || closeTimeoutMs < 1 || closeTimeoutMs > 5000 || typeof onFailure !== 'function') throw failed();
    this.#child = child; this.#timeout = timeoutMs; this.#closeTimeout = closeTimeoutMs;
    this.#onFailure = onFailure;
    this.#closed = new Promise(resolve => child.once('close', code => { this.#ended = true; this.#stop('child-close'); resolve(code); }));
    child.once('error', () => this.#stop('child-error')); child.stdin.on('error', () => this.#stop('stream-error'));
    child.stdout.on('error', () => this.#stop('stream-error')); child.stdout.once('end', () => this.#stop('stdout-end'));
    child.stderr.on('error', () => this.#stop('stream-error'));
    child.stderr.on('data', bytes => { this.stderrBytes += bytes.length; bytes.fill(0); });
    child.stdout.on('data', bytes => this.#receive(bytes));
  }
  #stop(reason) {
    if (this.#failed) return;
    this.#failed = true; this.#buffer.fill(0); this.#buffer = Buffer.alloc(0);
    if (reason) this.#onFailure(reason);
    for (const pending of this.#pending.values()) pending.finish(failed());
    this.#pending.clear(); this.#retired.clear();
  }
  #write(value) {
    if (this.#failed) throw failed();
    let frame; try { frame = Buffer.from(JSON.stringify(value) + '\n'); } catch { throw failed(); }
    if (frame.length > 65536) { frame.fill(0); throw failed(); }
    try { this.#child.stdin.write(frame, () => frame.fill(0)); } catch { frame.fill(0); this.#stop(); throw failed(); }
  }
  #receive(bytes) {
    if (this.#failed) { bytes.fill(0); return; }
    const joined = Buffer.concat([this.#buffer, bytes]); this.#buffer.fill(0); bytes.fill(0); this.#buffer = joined;
    let reason = 'frame-size';
    try {
      for (;;) {
        const end = this.#buffer.indexOf(10);
        if (end < 0) { if (this.#buffer.length > 65536) throw failed(); return; }
        if (end >= 65536) throw failed();
        const line = this.#buffer.subarray(0, end); let value; reason = 'decode';
        try { value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(line)); } finally { line.fill(0); }
        const rest = Buffer.from(this.#buffer.subarray(end + 1)); this.#buffer.fill(0); this.#buffer = rest;
        reason = 'shape'; if (!object(value) || value.jsonrpc !== '2.0') throw failed();
        if (!Object.hasOwn(value, 'id')) {
          reason = 'notification';
          if (!['notifications/message', 'notifications/tools/list_changed'].includes(value.method)) throw failed();
          reason = 'frame-size';
          continue;
        }
        reason = 'reply-shape';
        if (!Number.isSafeInteger(value.id) || (!Object.hasOwn(value, 'result') && !Object.hasOwn(value, 'error'))) throw failed();
        const pending = this.#pending.get(value.id);
        if (pending) pending.finish(undefined, value);
        else if (!this.#retired.delete(value.id)) { reason = 'reply-id'; throw failed(); }
        reason = 'frame-size';
      }
    } catch { this.#stop(reason); this.#child.kill('SIGKILL'); }
  }
  request(method, params = {}, { signal } = {}) {
    return new Promise((resolve, reject) => {
      if (this.#failed || signal?.aborted || this.#pending.size >= 8
        || !['initialize', 'tools/list', 'tools/call', 'ping'].includes(method) || !object(params)) { reject(failed()); return; }
      const id = ++this.#sequence; let timer;
      const finish = (error, value) => {
        if (!this.#pending.delete(id)) return;
        clearTimeout(timer); signal?.removeEventListener('abort', abort);
        if (error) reject(failed()); else resolve(value);
      };
      const abort = () => {
        if (!this.#pending.has(id)) return;
        if (this.#retired.size >= 16) { this.#stop(); return; }
        this.#retired.add(id);
        try { this.#write({ jsonrpc: '2.0', method: 'notifications/cancelled', params: { requestId: id } }); } catch { /* Fixed failure below. */ }
        finish(failed());
      };
      this.#pending.set(id, { finish }); timer = setTimeout(() => { this.#onFailure('deadline'); abort(); }, this.#timeout);
      signal?.addEventListener('abort', abort, { once: true });
      try { this.#write({ jsonrpc: '2.0', id, method, params }); } catch { finish(failed()); }
    });
  }
  notify(method) {
    if (method !== 'notifications/initialized') throw failed();
    this.#write({ jsonrpc: '2.0', method });
  }
  close() {
    if (this.#closePromise) return this.#closePromise;
    this.#stop();
    this.#closePromise = (async () => {
      if (this.#ended) return await this.#closed;
      try { this.#child.stdin.end(); } catch { this.#child.kill('SIGKILL'); }
      const timer = setTimeout(() => this.#child.kill('SIGKILL'), this.#closeTimeout);
      try { return await this.#closed; } finally { clearTimeout(timer); }
    })();
    return this.#closePromise;
  }
}
