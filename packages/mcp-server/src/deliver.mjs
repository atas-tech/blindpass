// SPDX-License-Identifier: MIT
import { createHash } from 'node:crypto';
import { brokerClockMs } from './broker-client.mjs';
import { createDiagnostics } from './diagnostics.mjs';

const REVIEWED_VERSION = '2025-11-25';
const ORDER = ['url_elicitation', 'openclaw', 'telegram', 'local_open', 'operator_app'];
const REASONS = ['not_configured', 'unreviewed', 'protocol', 'capability', 'host', 'authentication'];
const STATUSES = ['delivered', 'declined', 'cancelled', 'unavailable', 'uncertain', 'denied', 'capacity'];
// intendedHostId is part of the bound request (and so of the ledger fingerprint):
// the host a local-open may target cannot change between reservation and retry.
// An embedding whose request names no host passes a fixed token such as "none",
// which never equals a real current host.
const REQUEST_FIELDS = ['operationKey', 'elicitationId', 'operatorId', 'nodeId', 'invocationId', 'intendedHostId', 'url', 'deadlineMs'];
const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value)
  && [Object.prototype, null].includes(Object.getPrototypeOf(value));
const exact = (value, fields) => plain(value) && Object.keys(value).length === fields.length
  && fields.every(field => Object.hasOwn(value, field));
const result = (status, provider) => Object.freeze(provider ? { status, provider } : { status });
const safeResult = value => (exact(value, ['status']) || exact(value, ['status', 'provider']))
  && STATUSES.includes(value.status) && (value.provider === undefined || ORDER.includes(value.provider));

// The embedding supplies an atomic durable ledger. reserve() must commit the
// pending record before returning reserved, and must not replace pending/closed
// records. No ledger callback receives a URL. A test in-memory ledger is not a
// production substitute; the protocol package imports no application store.
//
// Recording rules (the ledger is the only memory that prevents a resend):
//  - After a successful reservation every exit path records a result. If the
//    delivery deadline, a caller abort or a failed completion interrupts the
//    normal path, the router records "uncertain" explicitly, under its own short
//    recordTimeoutMs budget, so the record is never left pending by the router.
//    A failed record leaves it pending, which also never authorizes a resend.
//  - "uncertain" is final for the operationKey: it is never re-evaluated.
//  - A definite "unavailable" (no provider supported; nothing was sent) may be
//    re-evaluated with the same operationKey if the ledger offers the optional
//    reopen(operationKey, fingerprint, signal). reopen must be a compare-and-set
//    that atomically turns exactly that closed record back into a pending one and
//    answers like reserve() ({status:'reserved'} for the single winner). Without
//    reopen the cached unavailable result is returned unchanged.
//  - If reserve() itself is interrupted the router cannot know whether the
//    pending record was committed; it returns uncertain and the ledger owner must
//    expire stale pending records.
export function createDeliveryRouter({ mode, providers, ledger, allowedOrigins, timeoutMs = 25_000, recordTimeoutMs = 1_000,
  allowRawLink = false, allowPlaintext = false, audit = createDiagnostics().audit,
  now = process.platform === 'linux' ? brokerClockMs : () => performance.now() } = {}) {
  const invalid = () => { throw new Error('invalid_delivery_configuration'); };
  if (mode !== 'browser_session' || allowRawLink !== false || allowPlaintext !== false
    || !Array.isArray(providers) || providers.length > ORDER.length
    || typeof ledger?.reserve !== 'function' || typeof ledger?.complete !== 'function'
    || !Array.isArray(allowedOrigins) || !allowedOrigins.length || allowedOrigins.length > 8
    || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 25_000
    || !Number.isSafeInteger(recordTimeoutMs) || recordTimeoutMs < 1 || recordTimeoutMs > 4_000
    || typeof audit !== 'function' || typeof now !== 'function') invalid();
  const origins = new Set();
  for (const origin of allowedOrigins) {
    let parsed; try { parsed = new URL(origin); } catch { invalid(); }
    if (typeof origin !== 'string' || parsed.protocol !== 'https:' || parsed.origin !== origin
      || parsed.username || parsed.password || parsed.pathname !== '/' || parsed.search || parsed.hash) invalid();
    origins.add(origin);
  }
  const configured = new Map();
  for (const provider of providers) {
    if (!provider || !ORDER.includes(provider.kind) || configured.has(provider.kind)
      || typeof provider.available !== 'function' || typeof provider.deliver !== 'function') invalid();
    configured.set(provider.kind, Object.freeze({ ...provider }));
  }
  const record = (provider, decision) => {
    try { audit(Object.freeze({ provider, decision })); } catch { /* No upstream diagnostic. */ }
  };
  const validate = request => {
    if (!exact(request, REQUEST_FIELDS)) return false;
    for (const field of REQUEST_FIELDS.filter(field => !['url', 'deadlineMs'].includes(field))) {
      if (typeof request[field] !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(request[field])) return false;
    }
    if (!Number.isSafeInteger(request.deadlineMs) || request.deadlineMs <= 0
      || request.operationKey.length < 16 || request.elicitationId.length < 16
      || typeof request.url !== 'string' || request.url.length > 8192 || /[\x00-\x20\x7f]/.test(request.url)) return false;
    try {
      const url = new URL(request.url);
      return url.protocol === 'https:' && origins.has(url.origin) && !url.username && !url.password;
    } catch { return false; }
  };
  return Object.freeze({ async deliver(request, context, routing = {}) {
    if (!validate(request) || !context?.mcpReq?.signal
      || typeof context.mcpReq.signal.addEventListener !== 'function') return result('denied');
    // Snapshot trusted input so mutation across asynchronous callbacks cannot
    // change the operator, original invocation, URL or local-host decision.
    const envelope = Object.freeze({ ...request }); const route = Object.freeze({ ...routing });
    const fingerprint = createHash('sha256').update(JSON.stringify(REQUEST_FIELDS.map(field => envelope[field]))).digest('hex');
    const controller = new AbortController(); const caller = context.mcpReq.signal;
    let deadline;
    try {
      const start = now(); if (!Number.isFinite(start)) return result('uncertain');
      if (start >= envelope.deadlineMs) return result('denied');
      deadline = Math.min(start + timeoutMs, envelope.deadlineMs);
    }
    catch { return result('uncertain'); }
    let interrupt;
    const stopped = new Promise((_, reject) => { interrupt = reject; }); stopped.catch(() => {});
    const abort = () => { controller.abort(); interrupt(new Error('delivery_interrupted')); };
    const check = () => {
      try { const current = now(); if (!Number.isFinite(current) || caller.aborted || current >= deadline) abort(); }
      catch { abort(); }
    };
    caller.addEventListener('abort', abort, { once: true });
    const timer = setInterval(check, Math.min(25, timeoutMs));
    const bounded = async callback => {
      check(); if (controller.signal.aborted) throw new Error('delivery_interrupted');
      const value = await Promise.race([Promise.resolve().then(callback), stopped]);
      check(); if (controller.signal.aborted) throw new Error('delivery_interrupted');
      return value;
    };
    // Records a result outside the interrupted delivery bound. Never throws.
    const persist = async value => {
      const budget = new AbortController(); let timer;
      const expired = new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('ledger_timeout')), recordTimeoutMs); });
      expired.catch(() => {});
      try { await Promise.race([Promise.resolve().then(() => ledger.complete(envelope.operationKey, fingerprint, value, budget.signal)), expired]); return true; }
      catch { budget.abort(); return false; }
      finally { clearTimeout(timer); }
    };
    const finish = async value => {
      if (!controller.signal.aborted) {
        try { await bounded(() => ledger.complete(envelope.operationKey, fingerprint, value, controller.signal)); return value; }
        catch { /* interrupted or failed: record uncertainty below */ }
      }
      // "unavailable" means nothing was dispatched, so it is still the true record
      // when only the persistence step was interrupted.
      const unsent = value.status === 'unavailable';
      const stored = await persist(unsent ? value : result('uncertain', value.provider));
      return stored && unsent ? value : result('uncertain', value.provider);
    };
    const settle = reservation => {
      if (exact(reservation, ['status', 'result']) && reservation.status === 'existing' && safeResult(reservation.result)) {
        return result(reservation.result.status, reservation.result.provider);
      }
      if (!exact(reservation, ['status'])) return result('uncertain');
      if (reservation.status === 'conflict') return result('denied');
      if (reservation.status === 'capacity') return result('capacity');
      if (reservation.status !== 'reserved') return result('uncertain');
      return undefined;
    };
    try {
      check(); if (caller.aborted) return result('cancelled');
      let reservation;
      try { reservation = await bounded(() => ledger.reserve(envelope.operationKey, fingerprint, controller.signal)); }
      catch { return result('uncertain'); }
      let final = settle(reservation);
      if (final?.status === 'unavailable' && final.provider === undefined && typeof ledger.reopen === 'function') {
        try { reservation = await bounded(() => ledger.reopen(envelope.operationKey, fingerprint, controller.signal)); }
        catch { return result('uncertain'); }
        final = settle(reservation);
      }
      if (final) return final;
      for (const kind of ORDER) {
        const provider = configured.get(kind);
        if (!provider) { record(kind, 'not_configured'); continue; }
        if (provider.humanOnly !== true) { record(kind, 'unreviewed'); continue; }
        if (kind === 'local_open' && (route.allowLocalOpen !== true || !route.currentHostId
          || route.currentHostId !== envelope.intendedHostId
          || (route.intendedHostId !== undefined && route.intendedHostId !== envelope.intendedHostId))) { record(kind, 'host'); continue; }
        if (kind === 'operator_app' && (route.operatorAuthenticated !== true
          || route.operatorId !== envelope.operatorId)) { record(kind, 'authentication'); continue; }
        let supported;
        try { supported = await bounded(() => provider.available(context, route)); }
        catch { record(kind, 'uncertain'); return await finish(result('uncertain', kind)); }
        if (exact(supported, ['supported', 'reason']) && supported.supported === false && REASONS.includes(supported.reason)) {
          record(kind, supported.reason); continue;
        }
        if (!exact(supported, ['supported']) || supported.supported !== true) {
          record(kind, 'uncertain'); return await finish(result('uncertain', kind));
        }
        record(kind, 'selected');
        let delivered;
        try { delivered = await bounded(() => provider.deliver(envelope, controller.signal, context)); }
        catch { record(kind, 'uncertain'); return await finish(result('uncertain', kind)); }
        if (delivered === 'definite_failure') { record(kind, 'definite_failure'); continue; }
        const status = ['delivered', 'declined', 'cancelled'].includes(delivered) ? delivered : 'uncertain';
        record(kind, status); return await finish(result(status, kind));
      }
      return await finish(result('unavailable'));
    } finally { clearInterval(timer); caller.removeEventListener('abort', abort); controller.abort(); }
  } });
}

// Only the reviewed 2025-era push channel is enabled here. The modern SDK era
// requires an input_required continuation, which needs its own review/tests.
// Capabilities and identity come from actual SDK initialize state, never args.
//
// The SDK records only the negotiated version: an initialize request for an
// unknown revision is answered with the latest supported one, so the negotiated
// value alone cannot show what the client asked for. A trusted embedding that
// has the first initialize request (createStdioTransport exposes
// requestedProtocolVersion) passes it as requestedProtocolVersion(); the gate then
// also requires the client-requested version to be exactly the reviewed one.
// Without that function only the negotiated version is checked.
export function createUrlElicitationProvider(server, { reviewedClients = [], requestedProtocolVersion } = {}) {
  if (['getClientVersion', 'getNegotiatedProtocolVersion', 'getClientCapabilities', 'elicitInput']
    .some(name => typeof server?.[name] !== 'function')
    || (requestedProtocolVersion !== undefined && typeof requestedProtocolVersion !== 'function') || !Array.isArray(reviewedClients)
    || reviewedClients.length > 16 || reviewedClients.some(client => !exact(client, ['name', 'version'])
      || typeof client.name !== 'string' || !client.name.length || client.name.length > 128
      || typeof client.version !== 'string' || !client.version.length || client.version.length > 128)) {
    throw new Error('invalid_delivery_configuration');
  }
  const reviewed = reviewedClients.map(client => Object.freeze({ ...client }));
  const available = () => {
      if (server.getNegotiatedProtocolVersion() !== REVIEWED_VERSION) return { supported: false, reason: 'protocol' };
      if (requestedProtocolVersion !== undefined) {
        let requested; try { requested = requestedProtocolVersion(); } catch { /* unknown */ }
        if (requested !== REVIEWED_VERSION) return { supported: false, reason: 'protocol' };
      }
      const url = server.getClientCapabilities()?.elicitation?.url;
      if (!plain(url)) return { supported: false, reason: 'capability' };
      const client = server.getClientVersion();
      if (!reviewed.some(value => client?.name === value.name && client?.version === value.version)) {
        return { supported: false, reason: 'unreviewed' };
      }
      return { supported: true };
  };
  return Object.freeze({ kind: 'url_elicitation', humanOnly: true, available,
    async deliver(request, signal) {
      if (!available().supported) return 'definite_failure';
      // accept records consent to navigate. Controller/broker completion, not
      // this response, must independently establish approval/provisioning.
      const value = await server.elicitInput({ mode: 'url', message: 'Open the authenticated operator page to review this browser request.',
        url: request.url, elicitationId: request.elicitationId }, { signal });
      if (!exact(value, ['action'])) return 'uncertain';
      if (value.action === 'accept') return 'delivered';
      if (value.action === 'decline') return 'declined';
      if (value.action === 'cancel') return 'cancelled';
      return 'uncertain';
    } });
}
