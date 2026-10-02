// SPDX-License-Identifier: MIT
import { Transform } from 'node:stream';
import { StdioServerTransport } from '@modelcontextprotocol/server/stdio';

// One legal newline-framed message may be up to this many bytes, excluding its
// line terminator. Bytes are counted per line by BoundedLines below, not as one
// shared buffer: the SDK buffer limit counts an unread partial line plus a whole
// 64 KiB read chunk, so it also closed the connection for legal back-to-back
// messages that were individually under the cap.
export const MAX_MESSAGE_BYTES = 65_536;
const NEWLINE = 0x0a;
// JSON-RPC 2.0 reply for input that cannot be a valid message; id is unknowable.
const OVERSIZE_REPLY = '{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"Message too large"}}\n';
const REPEAT_ERROR = Object.freeze({ code: -32600, message: 'Already initialized' });

// Re-frames input into whole lines and enforces the per-message limit. An
// over-limit line trips the stream once: fixed error reply, stream destroyed,
// which the SDK transport treats as a clean close (in-flight work is aborted
// through the same path as EOF).
class BoundedLines extends Transform {
  #max; #pending = []; #length = 0; #tripped = false; #onOversize;
  constructor(max, onOversize) { super(); this.#max = max; this.#onOversize = onOversize; }
  _transform(chunk, _encoding, done) {
    if (this.#tripped) { done(); return; }
    let start = 0;
    while (start < chunk.length) {
      const end = chunk.indexOf(NEWLINE, start);
      const stop = end === -1 ? chunk.length : end;
      if (this.#length + (stop - start) > this.#max) { this.#trip(); done(); return; }
      if (end === -1) { this.#pending.push(Buffer.from(chunk.subarray(start))); this.#length += stop - start; break; }
      const tail = chunk.subarray(start, end + 1);
      this.push(this.#pending.length ? Buffer.concat([...this.#pending, tail]) : Buffer.from(tail));
      this.#pending = []; this.#length = 0; start = end + 1;
    }
    done();
  }
  #trip() {
    this.#tripped = true; this.#pending = []; this.#length = 0;
    try { this.#onOversize(); } catch { /* the reply is best effort */ }
    process.nextTick(() => this.destroy());
  }
}

// Newline stdio transport with a per-message size bound and a one-initialize
// guard. The SDK 2.2.0 initialize handler overwrites the stored negotiated
// version, client identity and capabilities on every call, so a repeated
// initialize could swap the identity/capabilities that gate URL delivery after
// the first handshake. Here only the first initialize request is forwarded; later
// ones get a fixed JSON-RPC error. The first request's protocolVersion is kept as
// `requestedProtocolVersion`, which the SDK does not expose (it only records the
// negotiated version, which falls back to the latest for an unknown request).
export function createStdioTransport(input = process.stdin, output = process.stdout, { maxMessageBytes = MAX_MESSAGE_BYTES, onEvent = () => {} } = {}) {
  if (!Number.isSafeInteger(maxMessageBytes) || maxMessageBytes < 1) throw new Error('invalid_tool_configuration');
  const event = reason => { try { onEvent(reason); } catch { /* diagnostics never break the transport */ } };
  const bounded = new BoundedLines(maxMessageBytes, () => { event('message_too_large'); output.write(OVERSIZE_REPLY); });
  // The SDK transport attaches its own listeners in start(); these keep early errors from being unhandled.
  bounded.on('error', () => {});
  const failInput = error => bounded.destroy(error);
  input.on('error', failInput);
  const inner = new StdioServerTransport(bounded, output, { maxBufferSize: maxMessageBytes + 1 });
  let initializeSeen = false; let requested;
  const stop = () => { input.off('error', failInput); input.unpipe(bounded); bounded.destroy(); };
  return {
    get requestedProtocolVersion() { return requested; },
    async start() { input.pipe(bounded); return inner.start(); },
    async close() { stop(); return inner.close(); },
    send: (message, options) => inner.send(message, options),
    set onmessage(handler) {
      inner.onmessage = handler && ((message, extra) => {
        if (message?.method === 'initialize' && message.id !== undefined) {
          if (initializeSeen) {
            event('repeat_initialize');
            inner.send({ jsonrpc: '2.0', id: message.id, error: { ...REPEAT_ERROR } }).catch(() => {});
            return;
          }
          initializeSeen = true;
          const version = message.params?.protocolVersion;
          requested = typeof version === 'string' && version.length <= 32 ? version : undefined;
        }
        handler(message, extra);
      });
    },
    get onmessage() { return inner.onmessage; },
    set onclose(handler) { inner.onclose = handler; },
    get onclose() { return inner.onclose; },
    set onerror(handler) { inner.onerror = handler; },
    get onerror() { return inner.onerror; },
  };
}
