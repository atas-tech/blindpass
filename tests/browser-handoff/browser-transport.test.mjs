// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { Duplex, PassThrough } from 'node:stream';
import { test } from 'node:test';
import { FrameDecoder, encodeFrame, TunnelMux, attachFramedStream } from '../../helpers/login/src/browser-transport.mjs';

const frame = (text) => { const data = Buffer.from(text); const header = Buffer.alloc(4);
  header.writeUInt32BE(data.length); return Buffer.concat([header, data]); };
const tick = () => new Promise((resolve) => setImmediate(resolve));
// In-memory link that copies bytes (a real socket does not alias the sender's buffer) and completes each
// write one event-loop turn later, so frames from concurrent channels are queued together.
function linkedPair() {
  let left; let right;
  left = new Duplex({ read() {}, write(bytes, _encoding, callback) { right.push(Buffer.from(bytes)); setImmediate(callback); } });
  right = new Duplex({ read() {}, write(bytes, _encoding, callback) { left.push(Buffer.from(bytes)); setImmediate(callback); } });
  return [left, right];
}

test('B-I02 isolated browser framing handles split and batched frames with bounded input', () => {
  const decoder = new FrameDecoder();
  const first = encodeFrame({ type: 'prepared', devtoolsPath: '/devtools/browser/test' });
  const second = encodeFrame({ type: 'active' });
  const all = Buffer.concat([first, second]); const messages = [];
  for (const byte of all) messages.push(...decoder.push(Buffer.from([byte])));
  assert.deepEqual(messages, [{ type: 'prepared', devtoolsPath: '/devtools/browser/test' }, { type: 'active' }]);
  decoder.finish();
  assert.equal(new FrameDecoder().push(all).length, 2);
  const oversized = Buffer.alloc(4); oversized.writeUInt32BE(65_537);
  assert.throws(() => new FrameDecoder().push(oversized), /invalid_frame/);
});

test('P05-I06 isolated framing rejects duplicate keys, malformed UTF8, depth, trailing and partial data', () => {
  for (const data of [frame('{"type":"open","type":"data"}'), frame('{"nested":{"id":1,"\\u0069d":2}}'),
    frame('null'), frame('[]'), frame('{} {}'), frame('{"nested":' + '['.repeat(20) + '0' + ']'.repeat(20) + '}')]) {
    assert.throws(() => new FrameDecoder().push(data), /invalid_frame/);
  }
  const malformed = Buffer.from([0, 0, 0, 2, 0xc0, 0xaf]);
  assert.throws(() => new FrameDecoder().push(malformed), /invalid_frame/);
  const partial = new FrameDecoder(); partial.push(frame('{"type":"active"}').subarray(0, 9));
  assert.throws(() => partial.finish(), /invalid_frame/);
  assert.throws(() => encodeFrame({ data: 'x'.repeat(70_000) }), /invalid_frame/);
});

function pair({ active = true, connectEgress, connectCdp, maxChannels = 32 } = {}) {
  const failures = []; const messages = [];
  let root; let worker;
  root = new TunnelMux({ role: 'root', maxChannels,
    send: async (message) => { messages.push(message); await worker.receive(message); },
    connect: async (kind) => { assert.equal(kind, 'egress'); return connectEgress(); },
    onFailure: () => failures.push('root') });
  worker = new TunnelMux({ role: 'worker', maxChannels,
    send: async (message) => { messages.push(message); await root.receive(message); },
    connect: async (kind) => { assert.equal(kind, 'cdp'); return connectCdp(); },
    onFailure: () => failures.push('worker') });
  if (active) { root.activate(); worker.activate(); }
  return { root, worker, failures, messages };
}

test('B-I02 tunnel directions and activation gate forbid early CDP and target substitution', async () => {
  let connections = 0;
  const { root, worker, failures } = pair({ active: false, connectCdp: () => { connections++; return new PassThrough(); } });
  assert.throws(() => root.attach('cdp', new PassThrough()), /channel_unavailable/);
  await worker.receive({ type: 'open', id: 1, kind: 'cdp', target: 'http://agent-substituted.invalid' });
  assert.equal(connections, 0); assert.deepEqual(failures, ['worker']);
  root.close(); worker.close();
});

test('B-I02 egress reaches only root-selected connector and CDP only worker-selected connector', async () => {
  const selected = [];
  const egress = new PassThrough(); const cdp = new PassThrough();
  // Duplex test streams discard remote writes instead of echoing them back.
  const { Duplex } = await import('node:stream');
  const endpoint = (kind) => new Duplex({ read() {}, write(bytes, _encoding, callback) {
    selected.push([kind, bytes.toString()]); callback(); } });
  const { root, worker, failures, messages } = pair({ connectEgress: () => endpoint('egress'), connectCdp: () => endpoint('cdp') });
  worker.attach('egress', egress); root.attach('cdp', cdp);
  await tick(); egress.write('opaque-TLS-bytes'); cdp.write('websocket-opening');
  await tick(); await tick();
  assert.deepEqual(selected, [['egress', 'opaque-TLS-bytes'], ['cdp', 'websocket-opening']]);
  assert.deepEqual(messages.filter((message) => message.type === 'open').map(({ id, kind }) => [id, kind]), [[2, 'egress'], [1, 'cdp']]);
  assert.deepEqual(failures, []); root.close(); worker.close();
});

test('P05-I02 bounded channels and canonical data reject replay, wrong direction and oversized payloads', async () => {
  for (const message of [{ type: 'open', id: 2, kind: 'cdp' }, { type: 'open', id: 1, kind: 'egress' },
    { type: 'data', id: 1, data: 'not base64' }, { type: 'data', id: 1, data: 'A'.repeat(50_000) },
    { type: 'open', id: 1, kind: 'cdp', password: 'PRIVATE-CANARY' }]) {
    const { root, worker, failures } = pair({ connectCdp: () => new PassThrough() });
    await worker.receive(message); assert.equal(failures.length, 1); root.close(); worker.close();
  }
  const { root, worker } = pair({ maxChannels: 1, connectCdp: () => new PassThrough() });
  root.attach('cdp', new PassThrough()); await tick();
  assert.throws(() => root.attach('cdp', new PassThrough()), /channel_unavailable/);
  root.close(); worker.close();
});

test('P05-I02 private framed IO serializes batched work and carries only framed replies', async () => {
  let left; let right;
  left = new Duplex({ read() {}, write(bytes, _encoding, callback) { right.push(Buffer.from(bytes)); callback(); } });
  right = new Duplex({ read() {}, write(bytes, _encoding, callback) { left.push(Buffer.from(bytes)); callback(); } });
  const received = []; const answers = []; let worker;
  const root = attachFramedStream(left, { receive: async (message) => answers.push(message), onFailure() {} });
  worker = attachFramedStream(right, { receive: async (message) => {
    received.push(`start-${message.id}`); await tick(); received.push(`end-${message.id}`);
    await worker.send({ type: 'answer', id: message.id });
  }, onFailure() {} });
  await Promise.all([root.send({ type: 'job', id: 1 }), root.send({ type: 'job', id: 2 })]);
  for (let attempt = 0; attempt < 10 && answers.length < 2; attempt++) await tick();
  assert.deepEqual(received, ['start-1', 'end-1', 'start-2', 'end-2']);
  assert.deepEqual(answers, [{ type: 'answer', id: 1 }, { type: 'answer', id: 2 }]);
  root.close(); worker.close();
});

test('P05-I06 malformed private IO closes once and never passes duplicate metadata to the worker', async () => {
  const stream = new PassThrough(); let failures = 0; let calls = 0;
  const channel = attachFramedStream(stream, { receive: async () => calls++, onFailure: () => failures++ });
  stream.write(frame('{"type":"start","type":"import"}')); await tick();
  assert.equal(failures, 1); assert.equal(calls, 0);
  await assert.rejects(channel.send({ type: 'active' }), /channel_unavailable/);
  channel.close(); assert.equal(failures, 1);
});

test('P05-I02 a read carrying more than 128 frames is processed in bounded batches, not treated as a protocol failure', () => {
  const decoder = new FrameDecoder();
  const all = Buffer.concat(Array.from({ length: 300 }, (_, index) => encodeFrame({ type: 'close', id: index + 1 })));
  const first = decoder.push(all);
  assert.equal(first.length, 128); assert.equal(decoder.pending, true);
  const second = decoder.drain(); const third = decoder.drain();
  assert.deepEqual([second.length, third.length, decoder.pending], [128, 44, false]);
  assert.deepEqual([...first, ...second, ...third].map((message) => message.id), Array.from({ length: 300 }, (_, index) => index + 1));
  decoder.finish();
  // A caller must drain a batch before offering more bytes; undrained input is never dropped silently.
  const busy = new FrameDecoder(); busy.push(all);
  assert.throws(() => busy.push(encodeFrame({ type: 'close', id: 1 })), /invalid_frame/);
  const partial = new FrameDecoder(); partial.push(all); assert.throws(() => partial.finish(), /invalid_frame/);
});

test('P05-I02 framed IO applies backpressure to a burst of 300 small frames instead of failing the session', async () => {
  const [left, right] = linkedPair(); const received = []; const failures = [];
  const root = attachFramedStream(left, { receive: async () => {}, onFailure: () => failures.push('root') });
  const worker = attachFramedStream(right, { receive: async (message) => { await tick(); received.push(message.id); }, onFailure: () => failures.push('worker') });
  left.write(Buffer.concat(Array.from({ length: 300 }, (_, index) => encodeFrame({ type: 'close', id: index + 1 }))));
  for (let attempt = 0; attempt < 400 && received.length < 300; attempt++) await tick();
  assert.deepEqual(failures, []); assert.deepEqual(received, Array.from({ length: 300 }, (_, index) => index + 1));
  root.close(); worker.close();
});

test('P05-I02 concurrent egress channels each holding a full 32 KiB frame neither fail the session nor lose bytes', { timeout: 20_000 }, async () => {
  const channels = 8; const perChannel = 4; const chunk = 65_536; const failures = [];
  const [left, right] = linkedPair(); const sinks = []; let rootMux; let workerMux; let rootChannel; let workerChannel;
  rootMux = new TunnelMux({ role: 'root', send: (message) => rootChannel.send(message), onFailure: () => failures.push('root-mux'),
    connect: async () => {
      const sink = { bytes: 0, wrong: 0, index: sinks.length };
      sink.stream = new Duplex({ read() {}, write(bytes, _encoding, callback) {
        sink.bytes += bytes.length; for (const byte of bytes) if (byte !== sink.index + 1) sink.wrong++; callback(); } });
      sinks.push(sink); return sink.stream;
    } });
  workerMux = new TunnelMux({ role: 'worker', send: (message) => workerChannel.send(message), onFailure: () => failures.push('worker-mux'),
    connect: async () => new PassThrough() });
  rootChannel = attachFramedStream(left, { receive: (message) => rootMux.receive(message), onFailure: () => failures.push('root-channel') });
  workerChannel = attachFramedStream(right, { receive: (message) => workerMux.receive(message), onFailure: () => failures.push('worker-channel') });
  rootMux.activate(); workerMux.activate();
  const browsers = Array.from({ length: channels }, () => new PassThrough());
  for (const socket of browsers) workerMux.attach('egress', socket);
  const opened = performance.now() + 5_000;
  while (sinks.length < channels && failures.length === 0 && performance.now() < opened) await new Promise((resolve) => setTimeout(resolve, 5));
  assert.deepEqual(failures, []); assert.equal(sinks.length, channels);
  // Every channel offers a 64 KiB read at once: two 32 KiB frames per channel, all channels in flight together.
  for (let round = 0; round < perChannel; round++) browsers.forEach((socket, index) => socket.write(Buffer.alloc(chunk, index + 1)));
  const deadline = performance.now() + 15_000;
  while (sinks.some((sink) => sink.bytes < perChannel * chunk) && failures.length === 0 && performance.now() < deadline) await tick();
  assert.deepEqual(failures, []);
  assert.deepEqual(sinks.map((sink) => [sink.bytes, sink.wrong]), Array.from({ length: channels }, () => [perChannel * chunk, 0]));
  rootMux.close(); workerMux.close(); rootChannel.close(); workerChannel.close();
});

test('P05-I02 a full outbound queue makes senders wait in order; only a stalled peer fails the session', { timeout: 10_000 }, async () => {
  const slow = []; let release; let failures = 0;
  const stream = new Duplex({ read() {}, write(bytes, _encoding, callback) { slow.push(Buffer.from(bytes)); release = callback; } });
  const frameSize = encodeFrame({ type: 'data', id: 1, data: 'A'.repeat(1000) }).length;
  const channel = attachFramedStream(stream, { receive: async () => {}, onFailure: () => failures++,
    maxQueuedBytes: frameSize * 2, queueStallMs: 5_000 });
  const sent = [1, 2, 3, 4, 5].map((id) => channel.send({ type: 'data', id, data: 'A'.repeat(1000) }));
  await tick(); await tick();
  assert.equal(failures, 0, 'exceeding the bound must apply backpressure, not fail');
  const driver = setInterval(() => { const callback = release; release = undefined; callback?.(); }, 1);
  try { await Promise.all(sent); } finally { clearInterval(driver); }
  const ids = []; let all = Buffer.concat(slow);
  while (all.length) { const length = all.readUInt32BE(); ids.push(JSON.parse(all.subarray(4, 4 + length)).id); all = all.subarray(4 + length); }
  assert.deepEqual(ids, [1, 2, 3, 4, 5], 'frames keep their submission order');
  assert.equal(failures, 0); channel.close();
  const stalled = new Duplex({ read() {}, write() { /* peer never accepts */ } }); let stalledFailures = 0;
  const jammed = attachFramedStream(stalled, { receive: async () => {}, onFailure: () => stalledFailures++, maxQueuedBytes: frameSize, queueStallMs: 80 });
  const results = [1, 2, 3].map((id) => jammed.send({ type: 'data', id, data: 'A'.repeat(1000) }).then(() => 'sent', () => 'rejected'));
  assert.deepEqual(await Promise.all(results), ['rejected', 'rejected', 'rejected']);
  assert.equal(stalledFailures, 1);
});
