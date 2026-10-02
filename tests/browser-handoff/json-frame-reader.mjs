// SPDX-License-Identifier: AGPL-3.0-only
// Fixed-size JSON-RPC newline framing for protected test pipes and sockets.
export function readJsonFrames(input, onFrame, onFailure, onEnd = () => {}) {
  let buffer = Buffer.alloc(0); let stopped = false;
  const stop = () => { if (stopped) return; stopped = true; buffer.fill(0); buffer = Buffer.alloc(0);
    input.off('data', data); input.off('end', end); input.off('error', fail); };
  const fail = () => { if (stopped) return; stop(); onFailure(); };
  const end = () => { if (buffer.length) { fail(); return; } stop(); onEnd(); };
  const data = bytes => {
    if (stopped) { bytes.fill(0); return; }
    const joined = Buffer.concat([buffer, bytes]); buffer.fill(0); bytes.fill(0); buffer = joined;
    try {
      for (;;) {
        const index = buffer.indexOf(10);
        if (index < 0) { if (buffer.length > 65536) throw new Error(); return; }
        if (index >= 65536) throw new Error();
        let value;
        try { value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(buffer.subarray(0, index))); }
        finally { buffer.subarray(0, index).fill(0); }
        const remaining = Buffer.from(buffer.subarray(index + 1)); buffer.fill(0); buffer = remaining;
        if (!value || typeof value !== 'object' || Array.isArray(value) || value.jsonrpc !== '2.0') throw new Error();
        onFrame(value);
        if (stopped) return;
      }
    } catch { fail(); }
  };
  input.on('data', data); input.once('end', end); input.on('error', fail);
  return stop;
}
