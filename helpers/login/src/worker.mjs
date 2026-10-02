// SPDX-License-Identifier: AGPL-3.0-only
// One private input/output job. stdout/stderr never receive browser diagnostics.
import { Socket } from 'node:net';
import { fstatSync, writeSync } from 'node:fs';
import { TextDecoder } from 'node:util';
import { parseUniqueJson } from './browser-transport.mjs';
import { createBudget, LOGIN_TOTAL_MS } from './worker-budget.mjs';

// One monotonic budget for control/proof wait, job wait and login together.
const budget = createBudget(LOGIN_TOTAL_MS);
const socketMode = process.argv.length === 3 && process.argv[2] === '--socket';
const inputFd = socketMode ? 0 : 3;
const outputFd = socketMode ? 1 : 4;
const MAX_FRAME = 16_384;
let terminationRequested = false;
let inputStream;
let published = false;
const cancellation = new AbortController();
const TERMINATION_GRACE_MS = 2_000;
for (const signal of ['SIGTERM', 'SIGINT']) {
  process.on(signal, () => {
    terminationRequested = true;
    inputStream?.destroy(new Error('cancelled'));
    // Abort the in-progress login (it closes its browser); if that does not
    // finish promptly the worker still answers uncertain and exits itself.
    cancellation.abort();
    setTimeout(() => {
      try { respond({ status: 'uncertain' }); } catch { process.exit(74); }
      process.exit(143);
    }, TERMINATION_GRACE_MS).unref();
  });
}
function respond(value) {
  if (published) return;
  published = true; publish(value);
}
function publish(value) {
  const body = Buffer.from(JSON.stringify(value));
  if (body.length > MAX_FRAME) throw new Error('invalid_response');
  const header = Buffer.alloc(4); header.writeUInt32BE(body.length);
  const output = Buffer.concat([header, body]);
  try {
    let offset = 0;
    while (offset < output.length) offset += writeSync(outputFd, output, offset);
  } finally { output.fill(0); body.fill(0); }
}
function exactKeys(value, keys) {
  return value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}
async function readJob() {
  const chunks = []; let bytes = 0; let proved = !socketMode;
  const stream = new Socket({ fd: inputFd, readable: true, writable: false });
  inputStream = stream;
  let timer = setTimeout(() => stream.destroy(new Error('invalid_request')), budget.stage(5000));
  try {
    for await (const chunk of stream) {
      bytes += chunk.length;
      const maximum = proved ? MAX_FRAME : 256;
      if (bytes > maximum + 4) { chunk.fill(0); throw new Error('invalid_request'); }
      chunks.push(chunk);
      if (bytes >= 4) {
        const header = Buffer.concat(chunks, bytes);
        const declared = header.readUInt32BE(); header.fill(0);
        if (declared < 2 || declared > maximum || bytes > declared + 4) throw new Error('invalid_request');
        if (!proved && bytes === declared + 4) {
          const control = Buffer.concat(chunks);
          let challenge;
          try {
            // Root emits one canonical control frame. Exact grammar also
            // rejects duplicate keys and source/configuration/endpoint fields.
            const text = new TextDecoder('utf-8', { fatal: true }).decode(control.subarray(4));
            challenge = /^\{"version":2,"challenge":"([a-f0-9]{64})"\}$/.exec(text)?.[1];
            if (!challenge) throw new Error('invalid_request');
          } finally { control.fill(0); for (const bytes of chunks) bytes.fill(0); chunks.length = 0; bytes = 0; }
          try {
            const { proveHelperIdentity } = await import('./runtime-identity-client.mjs');
            await proveHelperIdentity(challenge);
          } finally { challenge = ''; }
          proved = true;
          clearTimeout(timer);
          timer = setTimeout(() => stream.destroy(new Error('invalid_request')), budget.stage(5000));
        }
      }
    }
    const input = Buffer.concat(chunks);
    try {
      if (!proved || input.length < 4 || input.readUInt32BE() !== input.length - 4) throw new Error('invalid_request');
      // Duplicate and escaped-alias keys are refused, as for every other private frame.
      const job = parseUniqueJson(new TextDecoder('utf-8', { fatal: true }).decode(input.subarray(4)));
      if (!exactKeys(job, ['version', 'configuration', 'credential']) || job.version !== 1
        || !exactKeys(job.credential, ['account', 'password'])) throw new Error('invalid_request');
      return job;
    } finally { input.fill(0); }
  } finally {
    clearTimeout(timer); stream.destroy(); inputStream = null;
    for (const chunk of chunks) chunk.fill(0);
  }
}

// The supervisor must supply a clean environment: Node preload/inspection flags
// take effect before this script. Runtime debug flags are refused before imports.
try {
  if (!fstatSync(inputFd).isSocket() || !fstatSync(outputFd).isSocket()) process.exit(64);
} catch { process.exit(64); }
let result;
if (['DEBUG', 'PWDEBUG', 'NODE_OPTIONS'].some((name) => process.env[name])) {
  result = { status: 'unsafe_configuration' };
} else if (process.argv.length !== 2 && !socketMode) {
  result = { status: 'invalid_request' };
} else {
  let job;
  try { job = await readJob(); } catch { result = { status: 'invalid_request' }; }
  if (job) {
    try {
      const { loginPrivate } = await import('./private-login.mjs');
      const { chromium } = await import('playwright');
      // Manager RuntimeMaxSec also bounds stuck browser shutdown and kills all
      // descendants. A process timer alone is not verified cgroup cleanup. The
      // login gets only what the shared budget has left after the read stages.
      if (budget.expired()) result = { status: 'timed_out' };
      else result = await loginPrivate(job.configuration, job.credential, { launch: (options) => chromium.launch(options),
        timeoutMs: budget.remaining(), signal: cancellation.signal });
    } catch { result = { status: 'uncertain' }; }
    finally { job.credential.password = ''; job = null; }
  }
}
if (terminationRequested) result = { status: 'uncertain' };
try { respond(result); } catch { process.exit(74); }

process.exit(terminationRequested ? 143 : 0);
