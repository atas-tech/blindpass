// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { compileRecipe, selectSessionCookies, loginPrivate } from '../../helpers/login/src/private-login.mjs';

const recipe = { kind: 'fixture', origin: 'https://reports.example.invalid', account: 'primary',
  sessionMaxMs: 300_000 };
const cookie = { name: '__Host-bp-fixture', value: 'a'.repeat(64), domain: 'reports.example.invalid',
  path: '/', expires: -1, httpOnly: true, secure: true, sameSite: 'Strict' };

test('B-I01 / P05-I06 helper only compiles fixed approved HTTPS recipes', () => {
  const compiled = compileRecipe(recipe);
  assert.equal(compiled.origin, recipe.origin);
  assert.equal(compiled.loginOrigin, recipe.origin);
  assert.ok(Object.isFrozen(compiled));
  for (const update of [{ origin: 'http://reports.example.invalid' }, { origin: 'https://user:password@example.invalid' },
    { origin: 'https://reports.example.invalid/path' }, { kind: 'generic-login' }, { account: '' },
    { sessionMaxMs: 1_800_001 }, { recordHar: { path: 'private.har' } }, { trace: true }, { ignoreHTTPSErrors: true },
    { chromiumArgs: ['--no-sandbox'] }, { selectors: { password: '#agent-selected-input' } }]) {
    assert.throws(() => compileRecipe({ ...recipe, ...update }), /invalid_configuration/);
  }
});

test('B-I02 helper imports only exact-origin approved session cookies with strict attributes and bounded expiry', () => {
  const compiled = compileRecipe(recipe);
  const deadline = Date.now() + 300_000;
  const selected = selectSessionCookies(compiled, [cookie,
    { ...cookie, name: 'oauth_code_verifier', value: 'PRIVATE-OAUTH-CANARY' }], deadline);
  assert.equal(selected.length, 1);
  assert.equal(selected[0].name, cookie.name);
  assert.ok(selected[0].expires <= deadline / 1000);
  assert.equal(selected[0].expires, Math.floor(deadline / 1000));
  for (const update of [{ domain: '.example.invalid' }, { domain: 'other.example.invalid' }, { path: '/login' },
    { secure: false }, { httpOnly: false }, { sameSite: 'None' }, { value: '' }, { value: 'a'.repeat(4097) },
    { expires: 1 }]) {
    assert.throws(() => selectSessionCookies(compiled, [{ ...cookie, ...update }], deadline), /invalid_session/);
  }
  assert.throws(() => selectSessionCookies(compiled, [], deadline), /invalid_session/);
  assert.throws(() => selectSessionCookies(compiled, [cookie, cookie], deadline), /invalid_session/);
  assert.throws(() => selectSessionCookies(compiled, [cookie], Date.now() - 1), /invalid_session/);
});

test('P05-I06 helper denies private capture/debug settings before launch and never returns nested upstream errors', async () => {
  let launches = 0;
  const upstreamCanary = 'P05-PRIVATE-UPSTREAM-PASSWORD-CANARY';
  const launch = async () => { launches++; throw new Error(upstreamCanary, { cause: new Error('private-link-and-code') }); };
  for (const env of [{ DEBUG: 'pw:api' }, { PWDEBUG: '1' }, { NODE_OPTIONS: '--inspect' }]) {
    const result = await loginPrivate(recipe, { account: 'primary', password: upstreamCanary }, { launch, env });
    assert.deepEqual(result, { status: 'unsafe_configuration' });
  }
  assert.equal(launches, 0);
  const result = await loginPrivate(recipe, { account: 'primary', password: upstreamCanary }, { launch, env: {} });
  assert.deepEqual(result, { status: 'login_failed' });
  assert.ok(!JSON.stringify(result).includes(upstreamCanary));
  assert.equal(launches, 1);
});

test('B-I03 helper rejects account substitution and unsupported authentication before launch', async () => {
  let launches = 0;
  const launch = async () => { launches++; throw new Error('must not launch'); };
  assert.deepEqual(await loginPrivate(recipe, { account: 'isolation', password: 'dummy-password' }, { launch, env: {} }),
    { status: 'binding_mismatch' });
  assert.deepEqual(await loginPrivate({ ...recipe, kind: 'passkey' }, { account: 'primary', password: 'dummy-password' }, { launch, env: {} }),
    { status: 'unsupported_authentication' });
  assert.equal(launches, 0);
});

test('P05-I06 helper launches a sandboxed private context with capture disabled and disposes it on errors', async () => {
  const calls = [];
  const context = { newPage: async () => { throw new Error('P05-PRIVATE-PASSWORD-CANARY'); },
    close: async () => { calls.push('context-close'); } };
  const browser = { newContext: async (options) => { calls.push(options); return context; },
    close: async () => { calls.push('browser-close'); } };
  const result = await loginPrivate(recipe, { account: 'primary', password: 'dummy-password' }, {
    env: {}, launch: async (options) => { calls.push(options); return browser; },
  });
  assert.deepEqual(result, { status: 'login_failed' });
  assert.equal(calls[0].chromiumSandbox, true);
  assert.equal(calls[0].headless, true);
  assert.deepEqual(calls[0].args, []);
  assert.deepEqual(calls[1], { acceptDownloads: false, serviceWorkers: 'block' });
  assert.ok(calls.includes('context-close') && calls.includes('browser-close'));
});

test('P05-I03 an abort signal closes the browser and ends an in-progress login promptly; a pre-aborted signal never launches', async () => {
  const configuration = { ...recipe, kind: 'fixture' }; const credential = { account: 'primary', password: 'P05-ABORT-PASSWORD-CANARY' };
  let launches = 0; let closes = 0; let rejectContext; let requested; const reached = new Promise((resolve) => { requested = resolve; });
  // Like Playwright, closing the browser rejects calls that are still pending.
  const launch = async () => { launches++; return { newContext: () => new Promise((_, reject) => { rejectContext = reject; requested(); }),
    close: async () => { closes++; rejectContext?.(new Error('Target closed')); } }; };
  const controller = new AbortController();
  const pending = loginPrivate(configuration, credential, { launch, env: {}, signal: controller.signal });
  await reached; controller.abort();
  const result = await Promise.race([pending, new Promise((resolve) => setTimeout(() => resolve('hung'), 2000))]);
  assert.deepEqual(result, { status: 'login_failed' }); assert.ok(closes >= 1);
  const early = new AbortController(); early.abort(); launches = 0;
  assert.deepEqual(await loginPrivate(configuration, credential, { launch, env: {}, signal: early.signal }), { status: 'login_failed' });
  assert.equal(launches, 0);
});
