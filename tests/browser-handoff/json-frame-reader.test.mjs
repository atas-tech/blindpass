// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { PassThrough } from 'node:stream';
import test from 'node:test';
import { readJsonFrames } from './json-frame-reader.mjs';

test('P05-PC14A: bounded frame reader handles split UTF-8 and multiple JSON-RPC frames', () => {
  const input = new PassThrough(); const frames = []; const failures = [];
  const stop = readJsonFrames(input, value => frames.push(value), () => failures.push(true));
  const bytes = Buffer.from(JSON.stringify({ jsonrpc: '2.0', id: 1, result: { text: 'é' } }) + '\n');
  const i = bytes.indexOf(0xc3); input.write(bytes.subarray(0, i + 1)); input.write(Buffer.from(bytes.subarray(i + 1)));
  input.write(JSON.stringify({ jsonrpc: '2.0', id: 2, result: {} }) + '\n');
  assert.equal(frames[0].result.text, 'é'); assert.equal(frames.length, 2); assert.equal(failures.length, 0); stop();
});

test('P05-PC14A: oversized, invalid and incomplete private input fails once without reflecting text', async () => {
  for (const bytes of [Buffer.from('PRIVATE-INVALID\n'), Buffer.from([255, 10]), Buffer.from('x'.repeat(65537)),
    Buffer.from('[]\n'), Buffer.from('{"jsonrpc":"1.0"}\n'), Buffer.from('{')]) {
    const input = new PassThrough(); let failures = 0; let frames = 0;
    readJsonFrames(input, () => frames++, () => failures++);
    input.end(bytes); await new Promise(resolve => setImmediate(resolve));
    assert.equal(failures, 1); assert.equal(frames, 0);
  }
});
