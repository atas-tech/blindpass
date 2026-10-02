// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { IsolatedBrowserSession, approvedConnectAuthority } from '../../helpers/login/src/isolated-browser.mjs';

const configuration = { kind: 'fixture', origin: 'https://reports.example.invalid', account: 'primary', sessionMaxMs: 300_000 };
const cookie = (deadline) => ({ name: '__Host-bp-fixture', value: 'a'.repeat(64), domain: 'reports.example.invalid',
  path: '/', secure: true, httpOnly: true, sameSite: 'Strict', expires: Math.floor(deadline / 1000) });
function harness({ existingCookies = [], importError = false, proofError = false } = {}) {
  const calls = []; const sent = []; let clock = 1_800_000_000_000;
  const context = { cookies: async () => existingCookies,
    addCookies: async (cookies) => { calls.push(['import', structuredClone(cookies)]); if (importError) throw new Error('PRIVATE-UPSTREAM-CANARY'); },
    close: async () => { calls.push('browser-close'); } };
  const mux = { activate: () => calls.push('activate'), close: () => calls.push('mux-close'), receive: async (message) => calls.push(message) };
  const session = new IsolatedBrowserSession({
    send: async (message) => sent.push(message), mux, now: () => clock,
    prove: async () => { calls.push('identity-proof'); if (proofError) throw new Error('PRIVATE-PROOF-CANARY'); },
    start: async (recipe) => { calls.push(['start', recipe]); return { context,
      devtoolsPath: '/devtools/browser/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee', pid: 1234,
      invocation: 'a'.repeat(32), cleanup: async () => calls.push('profile-removed') }; },
  });
  return { session, calls, sent, now: () => clock, advance: (ms) => { clock += ms; } };
}

test('P05-I02 fresh browser is prepared before cookie import and CDP opens only after import acknowledgment', async () => {
  const { session, calls, sent, now } = harness();
  await session.receive({ type: 'start', version: 1, configuration });
  assert.equal(sent[0].type, 'prepared'); assert.ok(!calls.includes('activate'));
  const deadline = now() + 290_000;
  const cookies = [cookie(deadline)];
  await session.receive({ type: 'prove', version: 1, challenge: 'a'.repeat(64) });
  await session.receive({ type: 'import', originalDeadlineMs: deadline, cookies });
  assert.deepEqual(calls.slice(-2).map((call) => Array.isArray(call) ? call[0] : call), ['import', 'activate']);
  assert.deepEqual(sent[1], { type: 'identity-proved' });
  assert.deepEqual(sent[2], { type: 'active' }); assert.equal(cookies[0].value, '', 'wire cookie reference cleared after import');
  await session.receive({ type: 'stop' });
  assert.ok(calls.includes('browser-close')); assert.ok(calls.includes('profile-removed'));
  assert.deepEqual(sent[3], { type: 'stopped' });
});

test('P05-I02 denies source credential, caller flags, unsafe cookie scope and repeated starts', async () => {
  for (const message of [{ type: 'start', version: 1, configuration, password: 'PRIVATE-SOURCE-CANARY' },
    { type: 'start', version: 1, configuration: { ...configuration, args: ['--no-sandbox'] } },
    { type: 'import', originalDeadlineMs: 1_800_000_290_000, cookies: [cookie(1_800_000_290_000)] }]) {
    const { session, calls, sent } = harness(); await session.receive(message);
    assert.deepEqual(sent, [{ type: 'uncertain' }]); assert.ok(!calls.some((call) => Array.isArray(call) && call[0] === 'start'));
  }
  for (const update of [{ domain: '.example.invalid' }, { name: 'password-reset' }, { sameSite: 'Lax' },
    { secure: false }, { httpOnly: false }, { path: '/api' }, { expires: -1 }, { value: 'x\n' }]) {
    const { session, calls, sent, now } = harness(); await session.receive({ type: 'start', version: 1, configuration });
    const deadline = now() + 290_000;
    await session.receive({ type: 'prove', version: 1, challenge: 'a'.repeat(64) });
    await session.receive({ type: 'import', originalDeadlineMs: deadline, cookies: [{ ...cookie(deadline), ...update }] });
    assert.equal(sent.at(-1).type, 'uncertain'); assert.ok(!calls.includes('activate')); assert.ok(calls.includes('profile-removed'));
  }
  const { session, sent, calls } = harness(); await session.receive({ type: 'start', version: 1, configuration });
  await session.receive({ type: 'start', version: 1, configuration });
  assert.equal(sent.at(-1).type, 'uncertain'); assert.equal(calls.filter((call) => Array.isArray(call) && call[0] === 'start').length, 1);
});

test('P05-I03 expiry, contaminated context, import failure and parent loss close browser with safe results', async () => {
  for (const options of [{ existingCookies: [{ name: 'unexpected' }] }, { importError: true }, {}]) {
    const { session, calls, sent, now, advance } = harness(options);
    await session.receive({ type: 'start', version: 1, configuration });
    if (!options.existingCookies) {
      const deadline = now() + 2000;
      await session.receive({ type: 'prove', version: 1, challenge: 'a'.repeat(64) });
      await session.receive({ type: 'import', originalDeadlineMs: deadline, cookies: [cookie(deadline)] });
      advance(2000); await session.checkDeadline();
    }
    assert.ok(calls.includes('browser-close')); assert.ok(calls.includes('profile-removed'));
    assert.ok(!JSON.stringify(sent).includes('PRIVATE-UPSTREAM-CANARY'));
  }
  const { session, calls } = harness(); await session.receive({ type: 'start', version: 1, configuration });
  await session.close(); assert.ok(calls.includes('profile-removed'));
});

test('P05-I02 cookie import requires successful exact one-use worker identity proof', async () => {
  for (const invalid of [undefined, { type: 'prove', version: 1, challenge: 'a'.repeat(63) },
    { type: 'prove', version: 2, challenge: 'a'.repeat(64) },
    { type: 'prove', version: 1, challenge: 'a'.repeat(64), endpoint: 'PRIVATE-ENDPOINT-CANARY' }]) {
    const { session, calls, sent, now } = harness();
    await session.receive({ type: 'start', version: 1, configuration });
    if (invalid) await session.receive(invalid);
    await session.receive({ type: 'import', originalDeadlineMs: now() + 2000, cookies: [cookie(now() + 2000)] });
    assert.equal(sent.at(-1).type, 'uncertain');
    assert.ok(!calls.some((call) => Array.isArray(call) && call[0] === 'import'));
  }
  for (const proofError of [false, true]) {
    const { session, calls, sent } = harness({ proofError });
    await session.receive({ type: 'start', version: 1, configuration });
    const proof = { type: 'prove', version: 1, challenge: 'a'.repeat(64) };
    await session.receive(proof);
    assert.equal(proof.challenge, '', 'private challenge reference cleared');
    if (!proofError) await session.receive({ type: 'prove', version: 1, challenge: 'a'.repeat(64) });
    assert.equal(sent.at(-1).type, 'uncertain');
    assert.equal(calls.filter((call) => call === 'identity-proof').length, 1);
    assert.ok(!JSON.stringify(sent).includes('PRIVATE-PROOF-CANARY'));
    assert.ok(calls.includes('profile-removed'));
  }
});

test('B-I02 app CONNECT authority excludes issuer, other ports and substituted targets', () => {
  assert.equal(approvedConnectAuthority(configuration), 'reports.example.invalid:443');
  assert.equal(approvedConnectAuthority({ ...configuration, origin: 'https://127.0.0.1:43210' }), '127.0.0.1:43210');
  assert.equal(approvedConnectAuthority({ ...configuration, origin: 'https://[::1]:43210' }), '[::1]:43210');
  assert.throws(() => approvedConnectAuthority({ ...configuration, origin: 'http://reports.example.invalid' }), /invalid_configuration/);
});

test('P05-I03 late-start disposal still removes the proxy/profile when closing the browser context throws', async () => {
  for (const failure of ['context-close', 'none']) {
    const calls = []; let release; const sent = [];
    const mux = { activate() {}, close: () => calls.push('mux-close'), receive: async () => {} };
    const session = new IsolatedBrowserSession({ send: async (message) => sent.push(message), mux, now: () => 1_800_000_000_000, prove: async () => {},
      start: () => new Promise((resolve) => { release = () => resolve({ context: { cookies: async () => [],
        close: async () => { calls.push('context-close'); if (failure === 'context-close') throw new Error('PRIVATE-CLOSE-CANARY'); } },
      devtoolsPath: '/devtools/browser/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee', pid: 1234, invocation: 'a'.repeat(32),
      cleanup: async () => calls.push('profile-removed') }); }) });
    const starting = session.receive({ type: 'start', version: 1, configuration });
    await new Promise((resolve) => setImmediate(resolve));
    await session.close(); release(); await starting;
    assert.deepEqual(calls.filter((call) => call !== 'mux-close'), ['context-close', 'profile-removed']);
    assert.ok(!sent.some((message) => message.type === 'prepared'), 'a late browser is never published');
    assert.ok(!JSON.stringify(sent).includes('CANARY'));
  }
});
