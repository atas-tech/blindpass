// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';

const worker = new URL('../../helpers/login/src/worker.mjs', import.meta.url);
export function frame(value) {
  const body = Buffer.from(JSON.stringify(value));
  const size = Buffer.alloc(4); size.writeUInt32BE(body.length);
  return Buffer.concat([size, body]);
}
export function runWorker(input, { env = {}, args = [], descriptors = true, terminateAfterMs, timeoutMs = 10_000 } = {}) {
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 65_000) throw new Error('Invalid private worker deadline');
  return new Promise((resolve, reject) => {
    const socketMode = args.length === 1 && args[0] === '--socket';
    const child = spawn(process.execPath, [worker.pathname, ...args], {
      env: { PATH: process.env.PATH, HOME: process.env.HOME, ...env },
      stdio: socketMode ? ['pipe', 'pipe', 'pipe'] : descriptors ? ['ignore', 'pipe', 'pipe', 'pipe', 'pipe'] : ['ignore', 'pipe', 'pipe'],
    });
    const output = []; const stdout = []; const stderr = [];
    child.stdout.on('data', (data) => (socketMode ? output : stdout).push(data));
    child.stderr.on('data', (data) => stderr.push(data));
    child.stdio[4]?.on('data', (data) => output.push(data));
    const inputStream = socketMode ? child.stdin : child.stdio[3];
    inputStream?.on('error', () => {});
    const timer = setTimeout(() => { child.kill('SIGKILL'); }, timeoutMs);
    child.on('error', () => reject(new Error('Private worker spawn failed')));
    child.on('close', (code) => { clearTimeout(timer); resolve({ code, stdout: Buffer.concat(stdout).toString(),
      stderr: Buffer.concat(stderr).toString(), output: Buffer.concat(output) }); });
    if (terminateAfterMs !== undefined) {
      inputStream?.write(input); setTimeout(() => child.kill('SIGTERM'), terminateAfterMs);
    } else inputStream?.end(input);
  });
}
export function decode(output) {
  assert.ok(output.length >= 4, 'private IPC response present');
  assert.equal(output.readUInt32BE(), output.length - 4, 'exact response frame');
  return JSON.parse(output.subarray(4));
}
