// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHash } from 'node:crypto';
import { BrowserSupervisor } from '../../helpers/login/src/browser-supervisor.mjs';

const operationId = `op_${'a'.repeat(64)}`;
const configuration = { kind: 'fixture', origin: 'https://example.invalid', account: 'primary', sessionMaxMs: 300_000 };
const start = () => ({ type: 'start', version: 1, operationId, configuration: { ...configuration }, deadlineBoottimeMs: 31_000 });
const prepared = () => ({ type: 'prepared', version: 1, pid: 123, invocation: 'a'.repeat(32), devtoolsPath: `/devtools/browser/${'a'.repeat(8)}-${'a'.repeat(4)}-${'a'.repeat(4)}-${'a'.repeat(4)}-${'a'.repeat(12)}` });
const cookie = () => ({ name: '__Host-bp-fixture', value: 'P05-SUPERVISOR-COOKIE-CANARY', domain: 'example.invalid', path: '/', secure: true, httpOnly: true, sameSite: 'Strict', expires: 1_100 });
const importing = () => ({ type: 'import', originalDeadlineMs: 1_100_000, sessionDeadlineBoottimeMs: 101_000, cookies: [cookie()] });
function fixture({ createBackend } = {}) {
  const worker = []; const parent = []; const events = []; let boottime = 1_000;
  const mux = { activate() { events.push('mux-active'); }, close() { events.push('mux-closed'); },
    async receive(value) { events.push(`tunnel-${value.type}`); }, attach(kind, socket) { events.push(`attach-${kind}`); socket.attached = true; } };
  const supervisor = new BrowserSupervisor({ sendWorker: async (value) => worker.push(structuredClone(value)),
    sendParent: async (value) => parent.push(structuredClone(value)), mux, now: () => boottime, wallNow: () => 1_000_000,
    createBackend: createBackend ?? (async (id, accept) => {
      events.push(`backend-${id}`); return { accept, async close() { events.push('backend-closed'); } };
    }), closeWorker: async () => events.push('worker-closed'), onTerminal: () => events.push('terminal') });
  return { supervisor, worker, parent, events, advance(value) { boottime = value; } };
}
async function prove(f) {
  await f.supervisor.receiveParent(start()); await f.supervisor.receiveWorker(prepared());
  await f.supervisor.receiveParent({ type: 'prove', version: 1, challenge: 'c'.repeat(64) });
  await f.supervisor.receiveWorker({ type: 'identity-proved' });
}

test('P05-I02 supervisor imports privately and publishes only after explicit Root publication', async () => {
  const f = fixture(); await prove(f);
  const input = importing(); await f.supervisor.receiveParent(input);
  assert.equal(input.cookies[0].value, '');
  assert.deepEqual(f.worker.at(-1), { type: 'import', originalDeadlineMs: 1_100_000, cookies: [cookie()] });
  await f.supervisor.receiveWorker({ type: 'active' });
  assert.equal(f.events.some(value => value.startsWith('backend-')), false);
  await f.supervisor.receiveParent({ type: 'publish' });
  assert.deepEqual(f.parent.at(-1), { type: 'published', contextHandle: `ctx_${createHash('sha256').update(operationId).digest('hex')}` });
  assert.equal(f.events.filter(value => value === 'mux-active').length, 1);
  assert.ok(f.events.includes(`backend-${operationId}`));
  assert.equal(JSON.stringify(f.parent).includes('P05-SUPERVISOR-COOKIE-CANARY'), false);
  await f.supervisor.close();
});

test('P05-I02 supervisor rejects reordered, duplicate, arbitrary or source-bearing parent input', async () => {
  for (const message of [importing(), { type: 'publish' }, { type: 'prove', version: 1, challenge: 'c'.repeat(64) },
    { ...start(), endpoint: 'P05-PRIVATE-ENDPOINT-CANARY' }, { ...start(), credential: { password: 'P05-SOURCE-CANARY' } },
    { ...start(), configuration: { ...configuration, scripts: ['model script'] } }, { ...start(), deadlineBoottimeMs: 122_000 }]) {
    const f = fixture(); await f.supervisor.receiveParent(message);
    assert.equal(f.worker.length, 0); assert.deepEqual(f.parent.at(-1), { type: 'uncertain' });
    assert.ok(f.events.includes('mux-closed')); await f.supervisor.close();
  }
  const f = fixture(); await f.supervisor.receiveParent(start()); await f.supervisor.receiveParent(start());
  assert.equal(f.worker.length, 1); assert.deepEqual(f.parent.at(-1), { type: 'uncertain' }); await f.supervisor.close();
});

test('P05-I02 supervisor rejects worker claims and cannot treat prepared/active as kernel proof or publication', async () => {
  for (const message of [{ type: 'active' }, { type: 'identity-proved' }, { ...prepared(), unit: 'model-claimed.service' },
    { ...prepared(), devtoolsPath: '/current?P05-PRIVATE-ENDPOINT-CANARY' }, { ...prepared(), invocation: 'claimed' }]) {
    const f = fixture(); await f.supervisor.receiveParent(start()); await f.supervisor.receiveWorker(message);
    assert.deepEqual(f.parent.at(-1), { type: 'uncertain' });
    assert.equal(f.events.some(value => value.startsWith('backend-')), false); await f.supervisor.close();
  }
  const f = fixture(); await f.supervisor.receiveParent(start()); await f.supervisor.receiveWorker(prepared());
  await f.supervisor.receiveParent(importing());
  assert.equal(f.worker.some(value => value.type === 'import'), false); await f.supervisor.close();
});

test('P05-I03 supervisor boot-time expiry cannot be extended by a late startup, import or active reply', async () => {
  for (const phase of ['prepared', 'active']) {
    const f = fixture();
    if (phase === 'active') { await prove(f); await f.supervisor.receiveParent(importing()); }
    else await f.supervisor.receiveParent(start());
    f.advance(phase === 'active' ? 101_001 : 31_001);
    await f.supervisor.receiveWorker(phase === 'active' ? { type: 'active' } : prepared());
    assert.deepEqual(f.parent.at(-1), { type: 'uncertain' });
    assert.equal(f.events.some(value => value.startsWith('backend-')), false); await f.supervisor.close();
  }
});

test('P05-I06 supervisor bounds session/cookies and clears rejected cookie references without publishing them', async () => {
  for (const change of [{ sessionDeadlineBoottimeMs: 302_000 }, { sessionDeadlineBoottimeMs: 101_001 }, { originalDeadlineMs: 1_301_000 },
    { cookies: [{ ...cookie(), domain: 'other.invalid' }] }, { cookies: [{ ...cookie(), httpOnly: false }] },
    { cookies: [{ ...cookie(), name: 'source-password' }] }]) {
    const f = fixture(); await prove(f); const input = { ...importing(), ...change };
    await f.supervisor.receiveParent(input);
    assert.equal(input.cookies[0].value, ''); assert.equal(f.worker.some(value => value.type === 'import'), false);
    assert.deepEqual(f.parent.at(-1), { type: 'uncertain' }); await f.supervisor.close();
  }
});

test('P05-I03 publication delayed beyond startup deadline or parent loss closes the late backend', async () => {
  for (const reason of ['deadline', 'parent-loss']) {
    let resolveBackend; let closes = 0;
    const f = fixture({ createBackend: () => new Promise(resolve => { resolveBackend = resolve; }) });
    await prove(f); await f.supervisor.receiveParent(importing()); await f.supervisor.receiveWorker({ type: 'active' });
    const publishing = f.supervisor.receiveParent({ type: 'publish' });
    await new Promise(resolve => setImmediate(resolve));
    if (reason === 'deadline') { f.advance(31_000); await f.supervisor.checkDeadline(); }
    else await f.supervisor.close();
    resolveBackend({ close: async () => { closes++; } }); await publishing;
    assert.equal(closes, 1); assert.equal(f.supervisor.closed, true);
    assert.equal(f.parent.some(message => message.type === 'published'), false);
    assert.equal(f.events.includes('mux-active'), false);
  }
});

test('P05-I03 published session retains its original BOOTTIME bound and stop requires a worker acknowledgement', async () => {
  for (const reason of ['expiry', 'stop', 'duplicate-publication']) {
    const f = fixture(); await prove(f); await f.supervisor.receiveParent(importing());
    await f.supervisor.receiveWorker({ type: 'active' }); await f.supervisor.receiveParent({ type: 'publish' });
    f.advance(31_000); await f.supervisor.checkDeadline(); assert.equal(f.supervisor.closed, false);
    if (reason === 'expiry') { f.advance(101_000); await f.supervisor.checkDeadline(); }
    if (reason === 'duplicate-publication') await f.supervisor.receiveParent({ type: 'publish' });
    if (reason === 'stop') {
      await f.supervisor.receiveParent({ type: 'stop' });
      assert.equal(f.parent.some(message => message.type === 'stopped'), false);
      await f.supervisor.receiveWorker({ type: 'stopped' }); assert.deepEqual(f.parent.at(-1), { type: 'stopped' });
    } else assert.deepEqual(f.parent.at(-1), { type: 'uncertain' });
    assert.equal(f.events.filter(event => event === 'mux-active').length, 1); await f.supervisor.close();
  }
});

test('P05-I03 supervisor failure closes its private backend and never reports verified cgroup/website cleanup', async () => {
  const f = fixture(); await prove(f); await f.supervisor.receiveParent(importing());
  await f.supervisor.receiveWorker({ type: 'active' }); await f.supervisor.receiveParent({ type: 'publish' });
  await f.supervisor.receiveWorker({ type: 'uncertain', password: 'P05-SOURCE-CANARY' });
  assert.ok(f.events.includes('backend-closed')); assert.ok(f.events.includes('worker-closed'));
  assert.deepEqual(f.parent.at(-1), { type: 'uncertain' });
  assert.equal(JSON.stringify(f.parent).includes('P05-SOURCE-CANARY'), false);
  await f.supervisor.close();
});

test('P05-I03 frames in flight while stopping are dropped quietly and stopped is not turned into uncertain', async () => {
  const f = fixture(); await prove(f); await f.supervisor.receiveParent(importing());
  await f.supervisor.receiveWorker({ type: 'active' }); await f.supervisor.receiveParent({ type: 'publish' });
  await f.supervisor.receiveParent({ type: 'stop' });
  const tunnelBefore = f.events.filter(value => value.startsWith('tunnel-')).length;
  for (const message of [{ type: 'data', id: 2, data: 'AAAA' }, { type: 'close', id: 2 }, { type: 'open', id: 4, kind: 'cdp' }, { type: 'opened', id: 2 }]) {
    await f.supervisor.receiveWorker(message);
  }
  assert.equal(f.supervisor.closed, false, 'late tunnel frames must not terminate the stop');
  assert.equal(f.parent.some(message => message.type === 'uncertain'), false);
  assert.equal(f.events.filter(value => value.startsWith('tunnel-')).length, tunnelBefore, 'dropped frames never reach the closed mux');
  await f.supervisor.receiveWorker({ type: 'stopped' });
  assert.deepEqual(f.parent.at(-1), { type: 'stopped' });
  assert.equal(f.parent.some(message => message.type === 'uncertain'), false);
  // Non-tunnel garbage while stopping is still a protocol failure.
  const g = fixture(); await prove(g); await g.supervisor.receiveParent(importing());
  await g.supervisor.receiveWorker({ type: 'active' }); await g.supervisor.receiveParent({ type: 'publish' });
  await g.supervisor.receiveParent({ type: 'stop' }); await g.supervisor.receiveWorker({ type: 'prepared' });
  assert.deepEqual(g.parent.at(-1), { type: 'uncertain' });
});
