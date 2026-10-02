// SPDX-License-Identifier: MIT
import assert from 'node:assert/strict';
import { test as nodeTest } from 'node:test';
import { createDeliveryRouter, createUrlElicitationProvider } from '../src/deliver.mjs';

const request = Object.freeze({ operationKey: 'operation_key_0001', elicitationId: 'elicitation_key_01',
  operatorId: 'operator-primary', nodeId: 'node-primary', invocationId: 'invocation-primary', intendedHostId: 'host-a',
  deadlineMs: Number.MAX_SAFE_INTEGER,
  url: 'https://operator.example.test/input#P05-DELIVERY-URL-CODE-CANARY' });
const routing = Object.freeze({ allowLocalOpen: true, currentHostId: 'host-a',
  operatorAuthenticated: true, operatorId: request.operatorId });
const context = () => ({ mcpReq: { signal: new AbortController().signal } });
const test = (name, callback) => nodeTest(name, { timeout: 1000 }, callback);
const kinds = ['url_elicitation', 'openclaw', 'telegram', 'local_open', 'operator_app'];
function ledger() {
  const entries = new Map(); const calls = [];
  return { calls, entries,
    async reserve(key, fingerprint) {
      calls.push('reserve'); const current = entries.get(key);
      if (current) return current.fingerprint !== fingerprint ? { status: 'conflict' }
        : current.result ? { status: 'existing', result: current.result } : { status: 'pending' };
      entries.set(key, { fingerprint }); return { status: 'reserved' };
    },
    async complete(key, fingerprint, result) {
      calls.push('complete'); assert.equal(entries.get(key)?.fingerprint, fingerprint);
      entries.get(key).result = result;
    },
    // Optional compare-and-set: reopens only a definite "no provider supported" record.
    async reopen(key, fingerprint) {
      calls.push('reopen'); const current = entries.get(key);
      if (!current || current.fingerprint !== fingerprint) return { status: 'conflict' };
      if (current.result?.status === 'unavailable' && current.result.provider === undefined) { delete current.result; return { status: 'reserved' }; }
      return current.result ? { status: 'existing', result: current.result } : { status: 'pending' };
    } };
}
const withoutReopen = store => { delete store.reopen; return store; };
function provider(kind, deliver = async () => 'delivered', available = async () => ({ supported: true })) {
  return { kind, humanOnly: true, available, deliver };
}
function router(providers, extra = {}) {
  return createDeliveryRouter({ mode: 'browser_session', providers, ledger: ledger(),
    allowedOrigins: ['https://operator.example.test'], ...extra });
}

test('P05-DR01 provider precedence is fixed regardless of configuration order', async () => {
  const calls = []; const store = ledger(); const audit = [];
  const providers = [...kinds].reverse().map(kind => provider(kind, async () => {
    calls.push(kind); assert.equal(store.calls[0], 'reserve');
    return kind === 'local_open' ? 'delivered' : 'definite_failure';
  }));
  const value = await router(providers, { ledger: store, audit: item => audit.push(item) }).deliver(request, context(), routing);
  assert.deepEqual(calls, kinds.slice(0, 4));
  assert.deepEqual(value, { status: 'delivered', provider: 'local_open' });
  assert.ok(!JSON.stringify([value, audit, [...store.entries]]).includes('CANARY'));
});

test('P05-DR03 thrown, invalid, uncertain, declined and cancelled provider replies stop fallback', async () => {
  for (const outcome of ['uncertain', 'declined', 'cancelled', 'throw', { url: request.url }, 'invalid']) {
    let fallback = 0;
    const first = provider('openclaw', async () => {
      if (outcome === 'throw') throw new Error(request.url, { cause: new Error('private-cookie') });
      return outcome;
    });
    const result = await router([first, provider('telegram', async () => { fallback++; return 'delivered'; })])
      .deliver(request, context(), routing);
    assert.equal(fallback, 0);
    assert.equal(result.status, ['declined', 'cancelled'].includes(outcome) ? outcome : 'uncertain');
    assert.ok(!JSON.stringify(result).includes('CANARY'));
  }
});

test('P05-DR03 bounded timeout and cancellation after dispatch remain uncertain without fallback', async () => {
  for (const cancel of [false, true]) {
    let fallback = 0; let dispatched; const reached = new Promise(resolve => { dispatched = resolve; });
    const controller = new AbortController(); let privateSignal;
    const target = router([provider('openclaw', async (_value, signal) => {
      privateSignal = signal; dispatched(); return new Promise(() => {});
    }), provider('telegram', async () => { fallback++; return 'delivered'; })], { timeoutMs: 50 });
    const pending = target.deliver(request, { mcpReq: { signal: controller.signal } }, routing);
    await reached; if (cancel) controller.abort();
    assert.deepEqual(await pending, { status: 'uncertain', provider: 'openclaw' });
    assert.equal(privateSignal.aborted, true); assert.equal(fallback, 0);
  }
});

test('P05-DR04 durable reservation, concurrent exact retry and cached result prevent another send', async () => {
  const store = ledger(); let called = 0; let release; let reached;
  const started = new Promise(resolve => { reached = resolve; });
  const deferred = new Promise(resolve => { release = resolve; });
  const target = router([provider('operator_app', async () => {
    called++; reached(); await deferred; return 'delivered';
  })], { ledger: store });
  const first = target.deliver(request, context(), routing); await started;
  assert.deepEqual(await target.deliver(request, context(), routing), { status: 'uncertain' });
  release(); assert.deepEqual(await first, { status: 'delivered', provider: 'operator_app' });
  assert.deepEqual(await target.deliver(request, context(), routing), await first);
  assert.equal(called, 1); assert.equal(store.calls.filter(value => value === 'complete').length, 1);
  for (const [field, value] of Object.entries({ operatorId: 'operator-other', nodeId: 'node-other',
    invocationId: 'invocation-other', elicitationId: 'elicitation_key_02', url: `${request.url}-other`, intendedHostId: 'host-b' })) {
    assert.deepEqual(await target.deliver({ ...request, [field]: value }, context(), routing), { status: 'denied' });
  }
  assert.equal(called, 1);
});

test('P05-DR04 pending, failed or malformed reservation and failed completion never authorize another send', async () => {
  for (const value of [{ status: 'pending' }, { status: 'capacity' }, { status: 'foreign' },
    { status: 'reserved', private: request.url }, 'throw']) {
    let called = 0;
    const store = { reserve: async () => { if (value === 'throw') throw new Error(request.url); return value; }, complete: async () => {} };
    const result = await router([provider('openclaw', async () => { called++; return 'delivered'; })], { ledger: store })
      .deliver(request, context(), routing);
    assert.equal(called, 0); assert.equal(result.status, value.status === 'capacity' ? 'capacity' : 'uncertain');
  }
  const store = ledger(); store.complete = async () => { throw new Error(request.url); };
  let called = 0;
  const target = router([provider('openclaw', async () => { called++; return 'delivered'; })], { ledger: store });
  assert.deepEqual(await target.deliver(request, context(), routing), { status: 'uncertain', provider: 'openclaw' });
  assert.deepEqual(await target.deliver(request, context(), routing), { status: 'uncertain' });
  assert.equal(called, 1);
});

test('P05-DR05 local-open needs explicit permission and exact intended host; operator needs matching authentication', async () => {
  for (const [change, bound] of [[{ allowLocalOpen: false }, {}], [{ currentHostId: 'host-b' }, {}], [{ currentHostId: undefined }, {}],
    [{}, { intendedHostId: 'host-b' }], [{ intendedHostId: 'host-b' }, {}]]) {
    let local = 0;
    const result = await router([provider('local_open', async () => { local++; return 'delivered'; }), provider('operator_app')])
      .deliver({ ...request, ...bound }, context(), { ...routing, ...change });
    assert.equal(local, 0); assert.deepEqual(result, { status: 'delivered', provider: 'operator_app' });
  }
  let local = 0;
  assert.deepEqual(await router([provider('local_open', async () => { local++; return 'delivered'; })])
    .deliver(request, context(), { ...routing, intendedHostId: 'host-a' }), { status: 'delivered', provider: 'local_open' });
  assert.equal(local, 1);
  for (const change of [{ operatorAuthenticated: false }, { operatorId: 'operator-other' }]) {
    let operator = 0;
    const result = await router([provider('operator_app', async () => { operator++; return 'delivered'; })])
      .deliver(request, context(), { ...routing, ...change });
    assert.equal(operator, 0); assert.deepEqual(result, { status: 'unavailable' });
  }
});

test('P05-DR06 unreviewed routes, unsafe URLs, origins, bindings and exposure flags fail closed', async () => {
  assert.throws(() => router([], { allowRawLink: true }), /invalid_delivery_configuration/);
  assert.throws(() => router([], { allowPlaintext: true }), /invalid_delivery_configuration/);
  assert.throws(() => router([], { mode: 'plaintext' }), /invalid_delivery_configuration/);
  assert.throws(() => router([], { ledger: undefined }), /invalid_delivery_configuration/);
  assert.throws(() => router([provider('unknown')]), /invalid_delivery_configuration/);
  assert.throws(() => router([provider('openclaw'), provider('openclaw')]), /invalid_delivery_configuration/);
  assert.throws(() => router([], { allowedOrigins: ['https://operator.example.test/path'] }), /invalid_delivery_configuration/);
  const unreviewed = { ...provider('openclaw'), humanOnly: false };
  assert.deepEqual(await router([unreviewed]).deliver(request, context(), routing), { status: 'unavailable' });
  for (const url of ['http://operator.example.test/', 'https://foreign.example.test/',
    'https://user:pass@operator.example.test/', 'https://operator.example.test/\ncanary', 'x'.repeat(8193)]) {
    assert.deepEqual(await router([provider('openclaw')]).deliver({ ...request, url }, context(), routing), { status: 'denied' });
  }
  assert.deepEqual(await router([provider('openclaw')]).deliver({ ...request, endpoint: request.url }, context(), routing), { status: 'denied' });
});

test('P05-DR03 pre-aborted request sends nothing; late provider resolution cannot start fallback', async () => {
  const controller = new AbortController(); controller.abort(); let called = 0;
  assert.deepEqual(await router([provider('openclaw', async () => { called++; return 'delivered'; })])
    .deliver(request, { mcpReq: { signal: controller.signal } }, routing), { status: 'cancelled' });
  assert.equal(called, 0);
  let resolve; let fallback = 0;
  const target = router([provider('openclaw', async () => new Promise(done => { resolve = done; })),
    provider('telegram', async () => { fallback++; return 'delivered'; })], { timeoutMs: 40 });
  assert.equal((await target.deliver(request, context(), routing)).status, 'uncertain');
  resolve('definite_failure'); await new Promise(done => setTimeout(done, 5)); assert.equal(fallback, 0);
});

test('P05-DR02 URL gate reads exact negotiated SDK identity/capabilities, never tool arguments', async () => {
  let sent = 0;
  const identity = { name: 'reviewed-contract', version: '1' };
  const server = { getClientVersion: () => identity, getNegotiatedProtocolVersion: () => '2025-11-25',
    getClientCapabilities: () => ({ elicitation: { url: {} } }), elicitInput: async () => { sent++; return { action: 'accept' }; } };
  const url = createUrlElicitationProvider(server, { reviewedClients: [identity] });
  assert.deepEqual(await url.available(), { supported: true });
  for (const version of ['2024-11-05', '2025-03-26', '2025-06-18', '2026-07-28', undefined]) {
    server.getNegotiatedProtocolVersion = () => version;
    assert.deepEqual(await url.available(), { supported: false, reason: 'protocol' });
  }
  server.getNegotiatedProtocolVersion = () => '2025-11-25';
  for (const capabilities of [{}, { elicitation: {} }, { elicitation: { form: {} } },
    { elicitation: { url: false } }, { elicitation: { url: [] } }, { elicitation: { url: null } }]) {
    server.getClientCapabilities = () => capabilities;
    assert.deepEqual(await url.available({ capabilities: { elicitation: { url: {} } } }), { supported: false, reason: 'capability' });
  }
  server.getClientCapabilities = () => ({ elicitation: { url: {} } });
  server.getClientVersion = () => ({ name: identity.name, version: '2' });
  assert.deepEqual(await url.available(), { supported: false, reason: 'unreviewed' });
  assert.equal(sent, 0);
});

test('P05-DR02 URL-mode parameters contain link only in url and acceptance does not prove provisioning', async () => {
  let params; const identity = { name: 'reviewed-contract', version: '1' };
  const server = { getClientVersion: () => identity, getNegotiatedProtocolVersion: () => '2025-11-25',
    getClientCapabilities: () => ({ elicitation: { url: {} } }), elicitInput: async value => { params = value; return { action: 'accept' }; } };
  const target = router([createUrlElicitationProvider(server, { reviewedClients: [identity] })]);
  assert.deepEqual(await target.deliver(request, context(), routing), { status: 'delivered', provider: 'url_elicitation' });
  assert.deepEqual(Object.keys(params).sort(), ['elicitationId', 'message', 'mode', 'url']);
  assert.equal(params.url, request.url); assert.equal(params.mode, 'url'); assert.equal(params.elicitationId, request.elicitationId);
  assert.ok(!params.message.includes('CANARY'));
});

test('P05-DR03 invalid clock and BOOTTIME expiry at response withhold success and fallback', async () => {
  for (const clock of [() => NaN, () => Infinity]) {
    let calls = 0;
    const value = await router([provider('openclaw', async () => { calls++; return 'delivered'; })], { now: clock })
      .deliver(request, context(), routing);
    assert.equal(value.status, 'uncertain'); assert.equal(calls, 0);
  }
  let time = 0; let fallback = 0;
  const value = await router([provider('openclaw', async () => { time = 30_000; return 'delivered'; }),
    provider('telegram', async () => { fallback++; return 'delivered'; })], { now: () => time })
    .deliver(request, context(), routing);
  assert.deepEqual(value, { status: 'uncertain', provider: 'openclaw' }); assert.equal(fallback, 0);
});

test('P05-DR02 URL provider rechecks capabilities immediately before sending', async () => {
  let calls = 0; const identity = { name: 'reviewed-contract', version: '1' };
  const server = { getClientVersion: () => identity, getNegotiatedProtocolVersion: () => '2025-11-25',
    getClientCapabilities: () => ({}), elicitInput: async () => { calls++; return { action: 'accept' }; } };
  const url = createUrlElicitationProvider(server, { reviewedClients: [identity] });
  assert.equal(await url.deliver(request, new AbortController().signal), 'definite_failure'); assert.equal(calls, 0);
});

test('P05-DR06 mutable inputs and malformed support diagnostics cannot replace a bound URL or leak it', async () => {
  const mutable = { ...request }; const audit = []; let envelope;
  const store = ledger(); const reserve = store.reserve;
  store.reserve = async (...args) => { const result = await reserve(...args); mutable.url = 'https://foreign.example.test/'; return result; };
  const value = await router([provider('openclaw', async input => { envelope = input; return 'delivered'; })], { ledger: store })
    .deliver(mutable, context(), routing);
  assert.equal(value.status, 'delivered'); assert.equal(envelope.url, request.url); assert.equal(Object.isFrozen(envelope), true);
  let called = 0;
  const malformed = provider('openclaw', async () => { called++; return 'delivered'; },
    async () => ({ supported: false, reason: request.url }));
  const bad = await router([malformed, provider('telegram')], { audit: item => audit.push(item) }).deliver(request, context(), routing);
  assert.deepEqual(bad, { status: 'uncertain', provider: 'openclaw' }); assert.equal(called, 0);
  assert.ok(!JSON.stringify([bad, audit]).includes('CANARY'));
});

test('P05-DR04 trusted request deadline is immutable, cannot renew on retry and expires before dispatch', async () => {
  const store = ledger(); let calls = 0; let time = 100;
  const target = router([provider('openclaw', async () => { calls++; return 'delivered'; })], { ledger: store, now: () => time });
  assert.deepEqual(await target.deliver({ ...request, deadlineMs: 99 }, context(), routing), { status: 'denied' });
  assert.equal(calls, 0); assert.equal(store.calls.length, 0);
  const live = { ...request, deadlineMs: 200 };
  assert.equal((await target.deliver(live, context(), routing)).status, 'delivered');
  assert.deepEqual(await target.deliver({ ...live, deadlineMs: 300 }, context(), routing), { status: 'denied' });
  time = 201;
  assert.deepEqual(await target.deliver(live, context(), routing), { status: 'denied' });
  assert.equal(calls, 1);
  for (const deadlineMs of [undefined, NaN, Infinity, -1, 0, 1.5]) {
    assert.deepEqual(await target.deliver({ ...request, deadlineMs }, context(), routing), { status: 'denied' });
  }
});

test('P05-DR04 timeout or abort after reservation records uncertain in the ledger and blocks any resend', async () => {
  for (const stage of ['deliver-timeout', 'deliver-abort', 'available-timeout']) {
    const store = ledger(); let sends = 0; const controller = new AbortController();
    let reached; const dispatched = new Promise(resolve => { reached = resolve; });
    const hang = new Promise(() => {});
    const target = router([provider('openclaw', async () => { sends++; reached(); return hang; },
      stage === 'available-timeout' ? async () => hang : undefined)], { ledger: store, timeoutMs: 50 });
    const pending = target.deliver(request, { mcpReq: { signal: controller.signal } }, routing);
    if (stage === 'deliver-abort') { await dispatched; controller.abort(); }
    const value = await pending;
    assert.deepEqual(value, { status: 'uncertain', provider: 'openclaw' }, stage);
    assert.deepEqual(store.entries.get(request.operationKey).result, { status: 'uncertain', provider: 'openclaw' }, `${stage}: ledger record left pending`);
    assert.equal(store.calls.filter(call => call === 'complete').length, 1);
    // Safe rule: never resend after uncertain, even when the ledger supports reopening.
    const retry = await target.deliver(request, context(), routing);
    assert.deepEqual(retry, { status: 'uncertain', provider: 'openclaw' }); assert.equal(sends, stage === 'available-timeout' ? 0 : 1);
    assert.ok(!store.calls.includes('reopen'));
  }
});

test('P05-DR04 a hung or failing ledger completion cannot hold the call past a bounded recording budget', async () => {
  for (const complete of [() => new Promise(() => {}), async () => { throw new Error(request.url); }]) {
    const store = ledger(); store.complete = complete;
    const target = router([provider('openclaw', async () => new Promise(() => {}))], { ledger: store, timeoutMs: 30, recordTimeoutMs: 100 });
    const started = performance.now(); const value = await target.deliver(request, context(), routing);
    assert.deepEqual(value, { status: 'uncertain', provider: 'openclaw' }); assert.ok(performance.now() - started < 900);
  }
});

test('P05-DR04 intendedHostId is bound into the request: required, immutable between reservation and retry', async () => {
  const store = ledger(); let sends = 0;
  const target = router([provider('local_open', async () => { sends++; return 'delivered'; })], { ledger: store });
  const { intendedHostId: _omitted, ...missing } = request;
  assert.deepEqual(await target.deliver(missing, context(), routing), { status: 'denied' });
  for (const bad of ['', 'host a', 'x'.repeat(129), 7, null]) assert.deepEqual(await target.deliver({ ...request, intendedHostId: bad }, context(), routing), { status: 'denied' });
  assert.equal(store.calls.length, 0);
  assert.deepEqual(await target.deliver(request, context(), routing), { status: 'delivered', provider: 'local_open' });
  const other = { ...routing, currentHostId: 'host-b' };
  // Changing the host on retry, in the request or only in the routing context, cannot redirect the bound delivery.
  assert.deepEqual(await target.deliver({ ...request, intendedHostId: 'host-b' }, context(), other), { status: 'denied' });
  assert.deepEqual(await target.deliver(request, context(), other), { status: 'delivered', provider: 'local_open' });
  assert.equal(sends, 1);
});

test('P05-DR04 a definite unavailable result may be re-evaluated with the same operationKey; uncertain never is', async () => {
  const store = ledger(); let ready = false; let sends = 0;
  const target = router([provider('operator_app', async () => { sends++; return 'delivered'; }, async () => ready ? { supported: true } : { supported: false, reason: 'capability' })], { ledger: store });
  assert.deepEqual(await target.deliver(request, context(), routing), { status: 'unavailable' });
  assert.deepEqual(store.entries.get(request.operationKey).result, { status: 'unavailable' });
  assert.equal(sends, 0);
  // Still unreachable: re-evaluated, still unavailable, nothing sent.
  assert.deepEqual(await target.deliver(request, context(), routing), { status: 'unavailable' });
  ready = true;
  assert.deepEqual(await target.deliver(request, context(), routing), { status: 'delivered', provider: 'operator_app' });
  assert.equal(sends, 1);
  // Delivered is final: exact retry is cached and a changed binding is denied.
  assert.deepEqual(await target.deliver(request, context(), routing), { status: 'delivered', provider: 'operator_app' });
  assert.deepEqual(await target.deliver({ ...request, url: `${request.url}x` }, context(), routing), { status: 'denied' });
  assert.equal(sends, 1);
  assert.equal(store.calls.filter(call => call === 'reopen').length, 2);
});

test('P05-DR04 without a reopen-capable ledger a cached unavailable result stays cached; concurrent re-evaluation sends once', async () => {
  const store = withoutReopen(ledger()); let ready = false; let sends = 0;
  const target = router([provider('operator_app', async () => { sends++; return 'delivered'; }, async () => ready ? { supported: true } : { supported: false, reason: 'host' })], { ledger: store });
  assert.deepEqual(await target.deliver(request, context(), routing), { status: 'unavailable' });
  ready = true;
  assert.deepEqual(await target.deliver(request, context(), routing), { status: 'unavailable' }); assert.equal(sends, 0);
  // With reopen: simultaneous retries race for the single compare-and-set.
  const racing = ledger(); ready = false;
  const second = router([provider('operator_app', async () => { sends++; return 'delivered'; }, async () => ready ? { supported: true } : { supported: false, reason: 'host' })], { ledger: racing });
  await second.deliver(request, context(), routing); ready = true;
  const results = await Promise.all([second.deliver(request, context(), routing), second.deliver(request, context(), routing), second.deliver(request, context(), routing)]);
  assert.equal(sends, 1); assert.ok(results.some(value => value.status === 'delivered'));
  assert.ok(results.every(value => ['delivered', 'uncertain'].includes(value.status)));
});

test('P05-DR04 a reopen that is refused, fails or returns an unexpected shape keeps the cached unavailable result and sends nothing', async () => {
  for (const reopen of [async () => ({ status: 'conflict' }), async () => { throw new Error(request.url); }, async () => ({ status: 'reserved', private: request.url }), async () => 'reserved']) {
    const store = ledger(); let ready = false; let sends = 0;
    const target = router([provider('operator_app', async () => { sends++; return 'delivered'; }, async () => ready ? { supported: true } : { supported: false, reason: 'host' })], { ledger: store });
    await target.deliver(request, context(), routing); ready = true; store.reopen = reopen;
    const value = await target.deliver(request, context(), routing);
    assert.ok(['unavailable', 'denied', 'uncertain'].includes(value.status)); assert.equal(sends, 0);
  }
});

test('P05-DR02 URL gate can also require the client-requested protocol version (SDK does not expose it)', async () => {
  const identity = { name: 'reviewed-contract', version: '1' }; let sent = 0;
  const server = { getClientVersion: () => identity, getNegotiatedProtocolVersion: () => '2025-11-25',
    getClientCapabilities: () => ({ elicitation: { url: {} } }), elicitInput: async () => { sent++; return { action: 'accept' }; } };
  // Current behaviour without the seam: only the negotiated version is available to check.
  assert.deepEqual(createUrlElicitationProvider(server, { reviewedClients: [identity] }).available(), { supported: true });
  let requested = '2025-11-25';
  const strict = createUrlElicitationProvider(server, { reviewedClients: [identity], requestedProtocolVersion: () => requested });
  assert.deepEqual(strict.available(), { supported: true });
  for (const value of ['2025-12-31', '2025-06-18', '2026-07-28', '', undefined, null, 20251125]) {
    requested = value; assert.deepEqual(strict.available(), { supported: false, reason: 'protocol' });
    assert.equal(await strict.deliver({ url: request.url, elicitationId: request.elicitationId }, new AbortController().signal), 'definite_failure');
  }
  assert.equal(sent, 0);
  for (const bad of ['2025-11-25', {}, null]) assert.throws(() => createUrlElicitationProvider(server, { reviewedClients: [identity], requestedProtocolVersion: bad }), /invalid_delivery_configuration/);
  const broken = createUrlElicitationProvider(server, { reviewedClients: [identity], requestedProtocolVersion: () => { throw new Error(request.url); } });
  assert.deepEqual(broken.available(), { supported: false, reason: 'protocol' });
});
