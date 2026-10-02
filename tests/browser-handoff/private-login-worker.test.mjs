// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { test } from 'node:test';

import { frame, runWorker, decode } from './worker-harness.mjs';

const job = { version: 1, configuration: { kind: 'fixture', origin: 'https://example.invalid', account: 'primary',
  sessionMaxMs: 300_000 }, credential: { account: 'primary', password: 'P05-WORKER-PASSWORD-CANARY' } };

test('P05-I02 socket helper refuses a source job before reverse kernel proof', async () => {
  const result = await runWorker(frame(job), { args: ['--socket'] });
  assert.equal(result.stdout, ''); assert.equal(result.stderr, '');
  assert.deepEqual(decode(result.output), { status: 'invalid_request' });
});

test('P05-I02 helper socket control is bounded, exact and cannot supply identity or source fields', async () => {
  const control = { version: 2, challenge: 'a'.repeat(64) };
  const duplicate = Buffer.from('{"version":2,"challenge":"' + 'a'.repeat(64) + '","challenge":"' + 'b'.repeat(64) + '"}');
  const header = Buffer.alloc(4); header.writeUInt32BE(duplicate.length);
  const oversized = Buffer.alloc(4); oversized.writeUInt32BE(257);
  for (const input of [frame(control), frame({ ...control, uid: 900 }), frame({ ...control, credential: job.credential }),
    frame({ ...control, challenge: 'A'.repeat(64) }), Buffer.concat([header, duplicate]), oversized,
    Buffer.concat([frame(control), frame(job)])]) {
    const result = await runWorker(input, { args: ['--socket'] });
    assert.equal(result.stdout, ''); assert.equal(result.stderr, '');
    assert.deepEqual(decode(result.output), { status: 'invalid_request' });
    result.output.fill(0);
  }
});

test('B-I01 / P05-I06 worker rejects malformed private frames without logging input or nested exceptions', { timeout: 20_000 }, async () => {
  const large = Buffer.alloc(4); large.writeUInt32BE(16_385);
  for (const input of [Buffer.alloc(0), Buffer.from([0, 0]), large, frame({ version: 99 }),
    Buffer.concat([frame(job), frame(job)]), frame({ ...job, scripts: 'agent-script' }),
    Buffer.concat([Buffer.from([0, 0, 0, 1]), Buffer.from([0xff])])]) {
    const result = await runWorker(input);
    assert.equal(result.stdout, ''); assert.equal(result.stderr, '');
    assert.deepEqual(decode(result.output), { status: 'invalid_request' });
    assert.equal(result.code, 0);
  }
});

test('P05-I06 worker refuses debug and arbitrary argv; no descriptor failure leaks diagnostics', { timeout: 20_000 }, async () => {
  for (const env of [{ DEBUG: 'pw:*' }, { PWDEBUG: '1' }]) {
    const result = await runWorker(frame(job), { env });
    assert.equal(result.stdout, ''); assert.equal(result.stderr, '');
    assert.deepEqual(decode(result.output), { status: 'unsafe_configuration' });
  }
  const missing = await runWorker(null, { descriptors: false });
  assert.equal(missing.stdout, ''); assert.equal(missing.stderr, '');
  assert.equal(missing.code, 64);
  const extra = await runWorker(frame(job), { args: ['--trace-private'] });
  assert.equal(extra.stdout, ''); assert.equal(extra.stderr, '');
  assert.deepEqual(decode(extra.output), { status: 'invalid_request' });
});

test('P05-I03 worker interruption returns only uncertain, never a definite authentication outcome', { timeout: 10_000 }, async () => {
  const result = await runWorker(frame(job), { terminateAfterMs: 200 });
  assert.equal(result.code, 143);
  assert.deepEqual(decode(result.output), { status: 'uncertain' });
  assert.equal(result.stdout, ''); assert.equal(result.stderr, '');
});

test('P05-I02 job frame uses the duplicate-key-rejecting parser: duplicate and aliased keys are invalid requests', async () => {
  const body = (text) => { const data = Buffer.from(text); const header = Buffer.alloc(4); header.writeUInt32BE(data.length); return Buffer.concat([header, data]); };
  const configuration = JSON.stringify(job.configuration);
  for (const text of [
    `{"version":1,"configuration":${configuration},"credential":{"account":"primary","password":"P05-WORKER-PASSWORD-CANARY","password":"P05-WORKER-OTHER-CANARY"}}`,
    `{"version":1,"configuration":${configuration},"credential":{"account":"primary","\\u0070assword":"P05-WORKER-PASSWORD-CANARY","password":"P05-WORKER-OTHER-CANARY"}}`,
    `{"version":1,"version":1,"configuration":${configuration},"credential":{"account":"primary","password":"P05-WORKER-PASSWORD-CANARY"}}`,
    `{"version":1,"configuration":{"kind":"fixture","kind":"fixture","origin":"https://example.invalid","account":"primary","sessionMaxMs":300000},"credential":{"account":"primary","password":"P05-WORKER-PASSWORD-CANARY"}}`]) {
    const result = await runWorker(body(text));
    assert.equal(result.stdout, ''); assert.equal(result.stderr, '');
    assert.deepEqual(decode(result.output), { status: 'invalid_request' });
  }
});

test('P05-I03 worker login budget is one monotonic budget: read stages and login together never exceed 55 s', async () => {
  const { createBudget, LOGIN_TOTAL_MS } = await import('../../helpers/login/src/worker-budget.mjs');
  assert.equal(LOGIN_TOTAL_MS, 55_000);
  let now = 1_000; const budget = createBudget(LOGIN_TOTAL_MS, () => now);
  assert.equal(budget.remaining(), 55_000);
  assert.equal(budget.stage(5_000), 5_000);
  now += 5_000;           // control frame + identity proof consume their full 5 s
  now += 5_000;           // job frame consumes its full 5 s
  assert.equal(budget.remaining(), 45_000);
  assert.equal(budget.stage(5_000), 5_000);
  const loginTimeout = budget.remaining();
  assert.ok(5_000 + 5_000 + loginTimeout <= LOGIN_TOTAL_MS);
  now += 44_500; assert.equal(budget.stage(5_000), 500);
  now += 600; assert.equal(budget.remaining(), -100); assert.equal(budget.expired(), true);
  assert.equal(budget.stage(5_000), 1, 'a stage is never zero or negative');
  assert.throws(() => createBudget(0), /invalid_budget/); assert.throws(() => createBudget(60_001), /invalid_budget/);
  assert.throws(() => createBudget(1000, 'clock'), /invalid_budget/);
});

test('P05-I03 the worker gives login only what the shared budget has left, never a fixed 55 s after its read stages', async () => {
  const { readFile } = await import('node:fs/promises');
  const source = await readFile(new URL('../../helpers/login/src/worker.mjs', import.meta.url), 'utf8');
  assert.match(source, /createBudget\(LOGIN_TOTAL_MS\)/);
  assert.match(source, /timeoutMs: budget\.remaining\(\)/);
  assert.doesNotMatch(source, /timeoutMs: 55_000/);
  assert.equal((source.match(/setTimeout\(\(\) => stream\.destroy\(new Error\('invalid_request'\)\), budget\.stage\(5000\)\)/g) ?? []).length, 2,
    'both read stages (control/proof and job) are drawn from the same budget');
});
