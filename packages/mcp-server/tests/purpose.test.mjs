// SPDX-License-Identifier: MIT
// Purpose is operator-visible request metadata: it must not be able to hide
// text, reorder it or smuggle line structure (Cc controls, format and bidi characters).
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createBrokerClient } from '../src/broker-client.mjs';

const identity = { nodeId: 'node-a', workloadId: 'workload-a', unit: 'agent.service', invocationId: 'a'.repeat(32) };
const args = { action: 'browser.session', resourceId: 'report-primary', requestKey: 'retry_0123456789abcdef' };
const frames = [];
const broker = createBrokerClient(identity, { callTimeoutMs: 500, cleanupTimeoutMs: 100,
  async exchange(frame, { onSent }) { frames.push(frame); onSent(); return 'OK operation_request event_0123456789abcdef\n'; } });
const hex = code => `U+${code.toString(16).toUpperCase().padStart(4, '0')}`;
const ranges = (...pairs) => pairs.flatMap(([from, to = from]) => Array.from({ length: to - from + 1 }, (_, index) => from + index));
const categories = {
  'C0 controls (Cc)': ranges([0x00, 0x1f]),
  'DEL and C1 controls (Cc)': ranges([0x7f, 0x9f]),
  'soft hyphen': ranges([0xad]),
  'Arabic letter mark': ranges([0x061c]),
  'zero-width and directional marks U+200B-U+200F': ranges([0x200b, 0x200f]),
  'line and paragraph separators': ranges([0x2028, 0x2029]),
  'bidi embeddings and overrides U+202A-U+202E': ranges([0x202a, 0x202e]),
  'word joiner and invisible operators U+2060-U+2064': ranges([0x2060, 0x2064]),
  'bidi isolates U+2066-U+2069': ranges([0x2066, 0x2069]),
  'byte order mark': ranges([0xfeff]),
};

for (const [name, codes] of Object.entries(categories)) {
  test(`P05-E purpose rejects ${name} at the start, middle and end`, async () => {
    const before = frames.length;
    for (const code of codes) {
      const character = String.fromCodePoint(code);
      for (const purpose of [`${character}Read report`, `Read${character}report`, `Read report${character}`]) {
        await assert.rejects(broker.request({ ...args, purpose }), error => error.message === 'broker_operation_failed', hex(code));
      }
    }
    assert.equal(frames.length, before, 'a rejected purpose reached the broker');
  });
}

test('P05-E ordinary multilingual purpose text and neighbouring characters are still accepted', async () => {
  const accepted = ['Read approved report', 'Lire le rapport approuvé', '读取已批准的报告', 'отчёт — Q3 (draft) #12', 'Prüfe € 100 – 200 “ok” …',
    'emoji 📊 report', 'tab-free text with U+00A0 no-break space', 'zero̸width neighbours: ¬®‐⁥ ⁰   　', '  ', 'á combining'];
  const before = frames.length;
  for (const purpose of accepted) assert.equal((await broker.request({ ...args, purpose })).status, 'requested', purpose);
  assert.equal(frames.length, before + accepted.length);
  assert.equal((await broker.request(args)).status, 'requested');
});

test('P05-E purpose rejects lone surrogates before they can be mis-encoded', async () => {
  const before = frames.length;
  for (const purpose of ['\ud800', 'abc\udc00', '\udc00\ud800']) await assert.rejects(broker.request({ ...args, purpose }));
  assert.equal(frames.length, before);
  assert.equal((await broker.request({ ...args, purpose: 'pair 📊 ok' })).status, 'requested');
});
