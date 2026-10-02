// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import test from 'node:test';

const binary = new URL('../../target/debug/blindpass-private-helper-probe', import.meta.url);
async function run(input, args = [], output = 'pipe') {
  return new Promise((resolve, reject) => {
    const child = spawn(binary.pathname, args, { stdio: ['pipe', 'pipe', 'pipe', output] });
    const normal = []; const protectedChunks = [];
    child.on('error', reject);
    child.stdout.on('data', (bytes) => normal.push(bytes));
    child.stderr.on('data', (bytes) => normal.push(bytes));
    child.stdio[3]?.on('data', (bytes) => protectedChunks.push(bytes));
    child.stdin.on('error', () => {});
    const timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('probe deadline')); }, 3000);
    child.on('close', (code) => { clearTimeout(timer); resolve({ code, normal: Buffer.concat(normal), protected: Buffer.concat(protectedChunks) }); });
    child.stdin.end(input);
  });
}
test('native probe rejects argv and missing private descriptor without normal output', async () => {
  for (const result of [await run('{}', ['untrusted']), await run('{}', [], 'ignore')]) {
    assert.equal(result.code, 1); assert.equal(result.normal.length, 0); assert.equal(result.protected.length, 0);
  }
});
test('native probe bounds private input and emits only a fixed protected outcome', async () => {
  for (const input of ['', 'x'.repeat(16_385)]) {
    const result = await run(input);
    assert.equal(result.code, 0); assert.equal(result.normal.length, 0);
    assert.equal(result.protected.readUInt32BE(), result.protected.length - 4);
    assert.deepEqual(JSON.parse(result.protected.subarray(4)), { status: 'invalid_request' });
  }
});
