// SPDX-License-Identifier: MIT
// Diagnostics sink: fixed-vocabulary metadata lines in a 0600 file under the
// workload state directory; never URLs, codes, cookies, endpoints or upstream text.
import assert from 'node:assert/strict';
import { mkdtemp, readdir, readFile, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { createDiagnostics, DIAGNOSTIC_FILE } from '../src/diagnostics.mjs';
import { createDeliveryRouter } from '../src/deliver.mjs';
import { launch } from './stdio-harness.mjs';

const CANARY = 'P05-DIAG-URL-PASSWORD-CODE-CANARY';
const LINE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z stage=[a-z_]+ status=[a-z_]+ reason=[a-z_]+( provider=[a-z_]+)?$/;
async function directory(t) {
  const value = await mkdtemp(join(tmpdir(), 'blindpass-mcp-diag-'));
  t.after(() => rm(value, { recursive: true, force: true }));
  return value;
}
const nested = () => {
  const error = new Error(CANARY, { cause: new Error(`nested-${CANARY}`, { cause: new Error(`cookie=${CANARY}`) }) });
  Object.assign(error, { url: `https://x.test/?code=${CANARY}`, endpoint: CANARY, code: CANARY, data: { password: CANARY } });
  return error;
};

test('P05-DIAG no-op without a configured directory: nothing created, nothing thrown', async t => {
  const cwd = await directory(t);
  const previous = process.cwd(); process.chdir(cwd);
  try {
    for (const sink of [createDiagnostics({ env: {} }), createDiagnostics({ env: { STATE_DIRECTORY: '' } }),
      createDiagnostics({ env: { STATE_DIRECTORY: 'relative/path' } }), createDiagnostics({ env: { STATE_DIRECTORY: join(cwd, 'missing') } }),
      createDiagnostics({ directory: '' })]) {
      assert.equal(sink.enabled, false);
      sink.record('tool', 'error', 'failed'); sink.onerror(nested()); sink.audit({ provider: 'openclaw', decision: 'selected' });
    }
  } finally { process.chdir(previous); }
  assert.deepEqual(await readdir(cwd), []);
});

test('P05-DIAG writes only fixed-vocabulary lines to a 0600 file under STATE_DIRECTORY (first entry of a list)', async t => {
  const state = await directory(t); const other = await directory(t);
  const sink = createDiagnostics({ env: { STATE_DIRECTORY: `${state}:${other}` }, now: () => Date.UTC(2026, 9, 2, 12, 0, 0) });
  assert.equal(sink.enabled, true);
  sink.record('tool', 'error', 'failed'); sink.record('transport', 'denied', 'message_too_large');
  sink.record('nonsense', 'a b', `${CANARY}\n`); sink.record('tool', 'error', 'bad reason');
  const path = join(state, DIAGNOSTIC_FILE);
  assert.equal((await stat(path)).mode & 0o777, 0o600);
  const lines = (await readFile(path, 'utf8')).trimEnd().split('\n');
  assert.equal(lines.length, 4);
  for (const line of lines) assert.match(line, LINE);
  assert.equal(lines[0], '2026-10-02T12:00:00.000Z stage=tool status=error reason=failed');
  assert.equal(lines[2], '2026-10-02T12:00:00.000Z stage=unknown status=unknown reason=unknown');
  assert.deepEqual(await readdir(other), []);
  assert.ok(!(await readFile(path, 'utf8')).includes(CANARY));
});

test('P05-DIAG a nested canary in an upstream error or audit record never reaches the file', async t => {
  const state = await directory(t); const sink = createDiagnostics({ directory: state });
  sink.onerror(nested());
  sink.onerror(Object.assign(new Error(CANARY), { name: CANARY, constructor: { name: CANARY } }));
  sink.onerror(CANARY); sink.onerror({ message: CANARY, toString() { return CANARY; } }); sink.onerror(undefined);
  sink.onerror(new SyntaxError(CANARY)); sink.onerror(Object.assign(new Error('ReadBuffer exceeded maximum size'), { cause: CANARY }));
  sink.audit({ provider: CANARY, decision: CANARY }); sink.audit({ provider: 'openclaw', decision: `selected ${CANARY}` });
  sink.audit({ provider: 'openclaw', decision: 'selected', url: CANARY }); sink.audit(CANARY); sink.audit(null);
  const text = await readFile(join(state, DIAGNOSTIC_FILE), 'utf8');
  assert.ok(!text.includes(CANARY) && !text.includes('canary') && !text.toLowerCase().includes('cookie'));
  const lines = text.trimEnd().split('\n'); assert.ok(lines.length >= 10);
  for (const line of lines) assert.match(line, LINE);
  assert.ok(lines.some(line => line.includes('reason=message_too_large')));
});

test('P05-DIAG delivery router default audit records provider decisions without the URL', async t => {
  const state = await directory(t); const previous = process.env.STATE_DIRECTORY;
  process.env.STATE_DIRECTORY = state;
  try {
    const store = new Map();
    const router = createDeliveryRouter({ mode: 'browser_session', allowedOrigins: ['https://operator.example.test'],
      ledger: { reserve: async key => (store.has(key) ? { status: 'pending' } : (store.set(key, 1), { status: 'reserved' })), complete: async () => {} },
      providers: [{ kind: 'operator_app', humanOnly: true, available: async () => ({ supported: true }), deliver: async () => 'delivered' }] });
    const value = await router.deliver({ operationKey: 'operation_key_0001', elicitationId: 'elicitation_key_01', operatorId: 'operator-primary',
      nodeId: 'node-primary', invocationId: 'invocation-primary', intendedHostId: 'host-a', deadlineMs: Number.MAX_SAFE_INTEGER,
      url: `https://operator.example.test/input#${CANARY}` }, { mcpReq: { signal: new AbortController().signal } },
    { operatorAuthenticated: true, operatorId: 'operator-primary' });
    assert.deepEqual(value, { status: 'delivered', provider: 'operator_app' });
  } finally { if (previous === undefined) delete process.env.STATE_DIRECTORY; else process.env.STATE_DIRECTORY = previous; }
  const text = await readFile(join(state, DIAGNOSTIC_FILE), 'utf8');
  assert.ok(!text.includes(CANARY) && !text.includes('operator.example.test'));
  assert.ok(text.includes('stage=delivery status=skipped reason=not_configured provider=url_elicitation'));
  assert.ok(text.includes('stage=delivery status=selected reason=selected provider=operator_app'));
  assert.ok(text.includes('stage=delivery status=completed reason=delivered provider=operator_app'));
  for (const line of text.trimEnd().split('\n')) assert.match(line, LINE);
});

test('P05-DIAG size is bounded by rotation and the file stays 0600', async t => {
  const state = await directory(t); const sink = createDiagnostics({ directory: state, maxBytes: 1024 });
  for (let index = 0; index < 400; index++) sink.record('tool', 'error', 'failed');
  const names = (await readdir(state)).sort();
  assert.deepEqual(names, [DIAGNOSTIC_FILE, `${DIAGNOSTIC_FILE}.1`]);
  for (const name of names) {
    const info = await stat(join(state, name));
    assert.ok(info.size <= 1024, `${name} is ${info.size} bytes`); assert.equal(info.mode & 0o777, 0o600);
  }
});

test('P05-DIAG refuses symlinked or foreign-linked log files and widens nothing', async t => {
  const state = await directory(t); const target = join(state, 'target');
  await writeFile(target, 'keep\n', { mode: 0o644 });
  await symlink(target, join(state, DIAGNOSTIC_FILE));
  const sink = createDiagnostics({ directory: state });
  sink.record('tool', 'error', 'failed');
  assert.equal(await readFile(target, 'utf8'), 'keep\n'); assert.equal(sink.enabled, false);
  const other = await directory(t); await writeFile(join(other, DIAGNOSTIC_FILE), 'old\n', { mode: 0o666 });
  createDiagnostics({ directory: other }).record('tool', 'error', 'failed');
  assert.equal((await stat(join(other, DIAGNOSTIC_FILE))).mode & 0o777, 0o600);
});

test('P05-DIAG actual stdio server: upstream canary stays out of stdout, stderr and the diagnostics file', { timeout: 15_000 }, async t => {
  const state = await directory(t);
  const server = launch(new URL('./stdio-fixture.mjs', import.meta.url), { env: { STATE_DIRECTORY: state } });
  try {
    await server.initialize(); server.notify('notifications/initialized');
    const failed = await server.request('tools/call', { name: 'upstream_failure', arguments: {} });
    assert.deepEqual(failed.result.content, [{ type: 'text', text: 'Operation failed' }]);
    server.send(`{"jsonrpc":"2.0","id":7,"method":"${CANARY}","params":{"url":"https://x.test/#${CANARY}"}`);
    server.send(JSON.stringify({ id: CANARY, endpoint: CANARY }));
    await server.request('tools/list', {});
  } finally { const exit = await server.finish(); assert.equal(exit.code, 0); assert.equal(server.stderr, ''); }
  assert.ok(!server.stdout.includes(CANARY));
  const text = await readFile(join(state, DIAGNOSTIC_FILE), 'utf8');
  assert.ok(!text.includes('CANARY') && !text.includes('nested-private-cookie'));
  assert.ok(text.includes('stage=tool status=error reason=failed'));
  assert.ok(text.includes('reason=invalid_message'));
  for (const line of text.trimEnd().split('\n')) assert.match(line, LINE);
  assert.equal((await stat(join(state, DIAGNOSTIC_FILE))).mode & 0o777, 0o600);
});

test('P05-DIAG actual stdio server without STATE_DIRECTORY writes no file and nothing to stdout/stderr', { timeout: 15_000 }, async t => {
  const cwd = await directory(t);
  const server = launch(new URL('./stdio-fixture.mjs', import.meta.url), { cwd });
  try {
    await server.initialize(); server.notify('notifications/initialized');
    await server.request('tools/call', { name: 'upstream_failure', arguments: {} });
  } finally { const exit = await server.finish(); assert.equal(exit.code, 0); assert.equal(server.stderr, ''); }
  assert.deepEqual(await readdir(cwd), []);
});
