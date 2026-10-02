// SPDX-License-Identifier: AGPL-3.0-only
// Private supervisor/namespace-worker pipe protocol. No endpoints or secrets
// belong in diagnostics. CDP bytes are intentionally available to the workload.
import { TextDecoder } from 'node:util';

export const MAX_FRAME_BYTES = 65_536;
export const MAX_TUNNEL_CHUNK = 32_768;
// Largest tunnel data frame: a 32 KiB chunk is 43,692 base64 characters plus the
// fixed JSON fields and 4-byte length header.
export const MAX_DATA_FRAME_BYTES = 43_800;
// At most one data frame per channel is queued (each channel awaits its own send
// before reading more), so the outbound queue is sized from the channel limit
// times the largest data frame, plus room for control frames. A smaller fixed
// cap failed the whole session with about six busy channels.
export const MAX_CHANNELS = 32;
const DEFAULT_MAX_QUEUED_BYTES = MAX_CHANNELS * MAX_DATA_FRAME_BYTES + MAX_FRAME_BYTES;
const DEFAULT_QUEUE_STALL_MS = 10_000;
// Frames returned per decoder call; the rest of a read waits for the caller.
const MAX_BATCH = 128;
const invalid = () => new Error('invalid_frame');
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));

// JSON.parse alone accepts duplicate keys, including escaped aliases. Check
// every object before materializing the message and cap nesting independently.
export function parseUniqueJson(text) {
  let offset = 0;
  const whitespace = () => { while (/[\t\n\r ]/.test(text[offset] ?? '\0')) offset++; };
  function string() {
    const start = offset++;
    while (offset < text.length) {
      const char = text[offset++];
      if (char === '\\') offset++;
      else if (char === '"') return JSON.parse(text.slice(start, offset));
    }
    throw invalid();
  }
  function value(depth) {
    if (depth > 16) throw invalid();
    whitespace();
    if (text[offset] === '"') { string(); return; }
    if (text[offset] === '{') {
      offset++; whitespace(); const keys = new Set();
      if (text[offset] === '}') { offset++; return; }
      for (;;) {
        whitespace(); if (text[offset] !== '"') throw invalid();
        const key = string(); if (keys.has(key)) throw invalid(); keys.add(key);
        whitespace(); if (text[offset++] !== ':') throw invalid();
        value(depth + 1); whitespace();
        const char = text[offset++]; if (char === '}') return;
        if (char !== ',') throw invalid();
      }
    }
    if (text[offset] === '[') {
      offset++; whitespace(); if (text[offset] === ']') { offset++; return; }
      for (;;) {
        value(depth + 1); whitespace();
        const char = text[offset++]; if (char === ']') return;
        if (char !== ',') throw invalid();
      }
    }
    const start = offset;
    while (offset < text.length && !/[\t\n\r ,}\]]/.test(text[offset])) offset++;
    if (offset === start) throw invalid();
    JSON.parse(text.slice(start, offset));
  }
  value(0); whitespace(); if (offset !== text.length) throw invalid();
  const result = JSON.parse(text);
  if (!result || typeof result !== 'object' || Array.isArray(result)) throw invalid();
  return result;
}

export function encodeFrame(message) {
  let body;
  try {
    body = Buffer.from(JSON.stringify(message));
    if (body.length < 2 || body.length > MAX_FRAME_BYTES) throw invalid();
    const output = Buffer.allocUnsafe(body.length + 4);
    output.writeUInt32BE(body.length); body.copy(output, 4);
    return output;
  } catch { throw invalid(); }
  finally { body?.fill(0); }
}

export class FrameDecoder {
  #header = Buffer.alloc(4);
  #headerBytes = 0;
  #body;
  #bodyBytes = 0;
  #closed = false;
  #rest = Buffer.alloc(0);
  #offset = 0;
  // True while a previous read still holds undecoded frames. Callers drain()
  // before offering more bytes: a legitimate burst of small frames is paused
  // and processed in bounded batches, never treated as a protocol failure.
  get pending() { return this.#offset < this.#rest.length; }
  push(chunk) {
    if (this.#closed || !Buffer.isBuffer(chunk) || chunk.length > 262_144 || this.pending) throw invalid();
    this.#rest.fill(0);
    this.#rest = Buffer.from(chunk); this.#offset = 0;
    return this.drain();
  }
  drain() {
    if (this.#closed) throw invalid();
    const messages = []; const chunk = this.#rest; let offset = this.#offset;
    try {
      while (offset < chunk.length && messages.length < MAX_BATCH) {
        if (!this.#body) {
          const count = Math.min(4 - this.#headerBytes, chunk.length - offset);
          chunk.copy(this.#header, this.#headerBytes, offset, offset + count);
          this.#headerBytes += count; offset += count;
          if (this.#headerBytes !== 4) continue;
          const length = this.#header.readUInt32BE();
          if (length < 2 || length > MAX_FRAME_BYTES) throw invalid();
          this.#body = Buffer.allocUnsafe(length);
        }
        const count = Math.min(this.#body.length - this.#bodyBytes, chunk.length - offset);
        chunk.copy(this.#body, this.#bodyBytes, offset, offset + count);
        this.#bodyBytes += count; offset += count;
        if (this.#bodyBytes === this.#body.length) {
          const text = new TextDecoder('utf-8', { fatal: true }).decode(this.#body);
          messages.push(parseUniqueJson(text));
          this.#body.fill(0); this.#body = undefined; this.#bodyBytes = 0; this.#headerBytes = 0;
        }
      }
      this.#offset = offset;
      if (!this.pending) { this.#rest.fill(0); this.#rest = Buffer.alloc(0); this.#offset = 0; }
      return messages;
    } catch { this.destroy(); throw invalid(); }
  }
  finish() {
    const partial = this.#headerBytes !== 0 || this.#body !== undefined || this.pending;
    this.destroy(); if (partial) throw invalid();
  }
  destroy() {
    this.#closed = true; this.#header.fill(0); this.#body?.fill(0); this.#body = undefined;
    this.#rest.fill(0); this.#rest = Buffer.alloc(0); this.#offset = 0;
  }
}

// Each peer chooses its own connector from trusted configuration. An open frame
// contains only the channel kind; a peer can never substitute a network target.
// Odd IDs are root-originated CDP, even IDs worker-originated app TLS egress.
export class TunnelMux {
  #role; #send; #connect; #onFailure; #maxChannels;
  #channels = new Map(); #tombstones = new Set();
  #nextId; #lastRemoteId = 0; #active = false; #closed = false;
  constructor({ role, send, connect, onFailure, maxChannels = MAX_CHANNELS }) {
    if (!['root', 'worker'].includes(role) || typeof send !== 'function' || typeof connect !== 'function'
      || typeof onFailure !== 'function' || !Number.isInteger(maxChannels) || maxChannels < 1 || maxChannels > MAX_CHANNELS) {
      throw new Error('invalid_configuration');
    }
    this.#role = role; this.#send = send; this.#connect = connect; this.#onFailure = onFailure;
    this.#maxChannels = maxChannels; this.#nextId = role === 'root' ? 1 : 2;
  }
  activate() { if (this.#closed) throw new Error('channel_unavailable'); this.#active = true; }
  #fail() { if (!this.#closed) { this.close(); this.#onFailure(); } }
  async #publish(message) {
    if (this.#closed) return;
    try { await this.#send(message); } catch { this.#fail(); }
  }
  #remember(id) {
    this.#tombstones.add(id);
    if (this.#tombstones.size > 64) this.#tombstones.delete(this.#tombstones.values().next().value);
  }
  #remove(id, notify) {
    const record = this.#channels.get(id); if (!record) return;
    this.#channels.delete(id); this.#remember(id); clearTimeout(record.timer);
    record.socket?.destroy();
    if (notify) void this.#publish({ type: 'close', id });
  }
  #install(id, socket, opened, onReady) {
    socket.pause();
    const record = { socket, opened, timer: undefined, onReady };
    this.#channels.set(id, record);
    if (!opened) record.timer = setTimeout(() => this.#remove(id, true), 5000);
    socket.on('error', () => this.#remove(id, true));
    socket.on('end', () => this.#remove(id, true));
    socket.on('close', () => this.#remove(id, true));
    socket.on('data', (bytes) => {
      socket.pause();
      void (async () => {
        try {
          // A single socket event cannot create an unbounded pipe queue.
          if (bytes.length > MAX_FRAME_BYTES) { this.#remove(id, true); return; }
          for (let offset = 0; offset < bytes.length; offset += MAX_TUNNEL_CHUNK) {
            if (!this.#channels.has(id)) return;
            await this.#publish({ type: 'data', id, data: bytes.subarray(offset, offset + MAX_TUNNEL_CHUNK).toString('base64') });
          }
          if (this.#channels.has(id)) socket.resume();
        } finally { bytes.fill(0); }
      })().catch(() => this.#fail());
    });
    return record;
  }
  attach(kind, socket, { onReady } = {}) {
    const expected = this.#role === 'root' ? 'cdp' : 'egress';
    if (this.#closed || kind !== expected || kind === 'cdp' && !this.#active
      || this.#channels.size >= this.#maxChannels || this.#nextId > 0x7fffffff) throw new Error('channel_unavailable');
    const id = this.#nextId; this.#nextId += 2;
    this.#install(id, socket, false, onReady);
    void this.#publish({ type: 'open', id, kind });
    return id;
  }
  async receive(message) {
    if (this.#closed) return;
    try {
      if (!Number.isInteger(message?.id) || message.id < 1 || message.id > 0x7fffffff) throw invalid();
      const id = message.id;
      if (message.type === 'open') {
        const expectedKind = this.#role === 'root' ? 'egress' : 'cdp';
        const expectedParity = this.#role === 'root' ? 0 : 1;
        if (!exact(message, ['type', 'id', 'kind']) || message.kind !== expectedKind || id % 2 !== expectedParity
          || id <= this.#lastRemoteId || message.kind === 'cdp' && !this.#active) throw invalid();
        this.#lastRemoteId = id;
        if (this.#channels.size >= this.#maxChannels) { this.#remember(id); await this.#publish({ type: 'close', id }); return; }
        const record = { opened: false, timer: setTimeout(() => this.#remove(id, true), 5000) };
        this.#channels.set(id, record);
        let socket;
        try { socket = await this.#connect(message.kind); }
        catch { this.#remove(id, true); return; }
        if (this.#channels.get(id) !== record || this.#closed) { socket.destroy(); return; }
        clearTimeout(record.timer); this.#install(id, socket, true);
        await this.#publish({ type: 'opened', id });
        if (this.#channels.has(id)) socket.resume();
        return;
      }
      if (!exact(message, message.type === 'data' ? ['type', 'id', 'data'] : ['type', 'id'])
        || !['data', 'opened', 'close'].includes(message.type)) throw invalid();
      const record = this.#channels.get(id);
      if (!record) {
        if (this.#tombstones.has(id) && message.type !== 'opened') return;
        throw invalid();
      }
      if (message.type === 'close') { this.#remove(id, false); return; }
      if (message.type === 'opened') {
        if (record.opened || !record.socket) throw invalid();
        clearTimeout(record.timer); record.opened = true;
        record.onReady?.(); record.socket.resume(); return;
      }
      if (!record.opened || typeof message.data !== 'string' || message.data.length < 4
        || message.data.length > 43_692 || !/^[A-Za-z0-9+/]+={0,2}$/.test(message.data)) throw invalid();
      const bytes = Buffer.from(message.data, 'base64');
      try {
        if (!bytes.length || bytes.length > MAX_TUNNEL_CHUNK || bytes.toString('base64') !== message.data) throw invalid();
        await new Promise((resolve, reject) => record.socket.write(bytes, (error) => error ? reject(invalid()) : resolve()));
      } finally { bytes.fill(0); }
    } catch { this.#fail(); }
  }
  close() {
    this.#closed = true;
    for (const id of this.#channels.keys()) this.#remove(id, false);
  }
}

// The stream is inherited from the root-only activated Unix socket. Serialize
// processing and writes, bound queued output, and clear frame buffers after IO.
// Outbound frames are admitted in submission order. When the queue is full a
// sender waits (backpressure) until earlier frames are written; only a peer that
// accepts nothing for queueStallMs fails the session.
export function attachFramedStream(stream, { receive, onFailure, maxQueuedBytes = DEFAULT_MAX_QUEUED_BYTES,
  queueStallMs = DEFAULT_QUEUE_STALL_MS }) {
  if (!Number.isSafeInteger(maxQueuedBytes) || maxQueuedBytes < 1 || !Number.isSafeInteger(queueStallMs) || queueStallMs < 1) throw new Error('invalid_configuration');
  const decoder = new FrameDecoder(); let closed = false; let bytesQueued = 0; let tail = Promise.resolve();
  const waiting = [];
  // A destroyed stream may never complete an in-flight write callback; every
  // sender still settles once the session has failed.
  let markClosed; const dead = new Promise((_, reject) => { markClosed = () => reject(new Error('channel_unavailable')); });
  dead.catch(() => {});
  function admit() {
    while (waiting.length && bytesQueued + waiting[0].size <= maxQueuedBytes) {
      const next = waiting.shift(); clearTimeout(next.timer); bytesQueued += next.size; next.resolve();
    }
  }
  function fail() {
    if (closed) return;
    closed = true; markClosed(); decoder.destroy(); stream.destroy();
    for (const next of waiting.splice(0)) { clearTimeout(next.timer); next.reject(new Error('channel_unavailable')); }
    onFailure();
  }
  stream.on('error', fail);
  stream.on('end', () => { try { decoder.finish(); } catch { /* same safe parent-loss outcome */ } fail(); });
  stream.on('close', fail);
  stream.on('data', (chunk) => {
    stream.pause();
    void (async () => {
      try {
        let messages = decoder.push(chunk);
        for (;;) {
          for (const message of messages) { if (closed) break; await receive(message); }
          if (closed || !decoder.pending) break;
          messages = decoder.drain();
        }
        if (!closed) stream.resume();
      } catch { fail(); }
      finally { chunk.fill(0); }
    })();
  });
  return {
    async send(message) {
      if (closed) throw new Error('channel_unavailable');
      const frame = encodeFrame(message); const size = frame.length;
      if (size > maxQueuedBytes) { frame.fill(0); fail(); throw new Error('channel_unavailable'); }
      if (waiting.length === 0 && bytesQueued + size <= maxQueuedBytes) bytesQueued += size;
      else {
        try {
          await new Promise((resolve, reject) => {
            const next = { size, resolve, reject, timer: setTimeout(fail, queueStallMs) };
            waiting.push(next);
          });
        } catch (error) { frame.fill(0); throw error; }
      }
      const write = tail.then(async () => {
        if (closed) throw new Error('channel_unavailable');
        await new Promise((resolve, reject) => stream.write(frame, (error) => error ? reject(new Error('channel_unavailable')) : resolve()));
      });
      tail = write.catch(fail);
      try { await Promise.race([write, dead]); } finally { frame.fill(0); bytesQueued -= size; admit(); }
    },
    close: fail,
  };
}
