// SPDX-License-Identifier: MIT
import { lstat } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { createConnection } from 'node:net';

export const BROKER_SOCKET = '/run/blindpass/workload.sock';
// Outer bound for any registered MCP callback. The broker client's own bound is
// deliberately several seconds shorter: its withdrawal (cleanup) phase must
// finish, and the agent must receive the explicit "uncertain" result, before the
// outer bound turns the call into the fixed "Operation failed" error.
export const CALL_TIMEOUT_MS = 30_000;
export const BROKER_CALL_TIMEOUT_MS = CALL_TIMEOUT_MS - 3_000;
const KEY = /^[A-Za-z0-9_-]{16,128}$/;
const ID = /^[A-Za-z0-9_-]{1,128}$/;
const UNIT = /^[A-Za-z0-9_.@:-]{1,256}$/;
const INVOCATION = /^[a-f0-9]{32}$/;
const CLOSED = new Set(['rejected', 'expired', 'cancelled', 'denied', 'completed']);
const isKey = value => typeof value === 'string' && KEY.test(value);
const isId = value => typeof value === 'string' && ID.test(value);
const failed = () => new Error('broker_operation_failed');
// Purpose is operator-visible text: no Cc control characters (including CR, LF,
// NUL, DEL and C1), and none of the format/bidi characters that can hide,
// reorder or re-line text: U+00AD, U+061C, U+200B-U+200F, U+2028-U+2029,
// U+202A-U+202E, U+2060-U+2064, U+2066-U+2069 and U+FEFF. The Rust broker
// applies the identical rule. Lone surrogates are not valid text either.
const PURPOSE_FORBIDDEN = /[\p{Cc}\u00AD\u061C\u200B-\u200F\u2028\u2029\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF]/u;
class BrokerRejected extends Error { constructor() { super('broker_operation_rejected'); } }

// Kernel uptime includes suspend; no caller-supplied wall clock grants time.
// Linux man-pages proc_uptime(5): https://man7.org/linux/man-pages/man5/proc_uptime.5.html
export function brokerClockMs() {
  const value = readFileSync('/proc/uptime', 'utf8');
  if (value.length > 96 || !/^\d+\.\d{2} \d+\.\d{2}\n?$/.test(value)) throw failed();
  const milliseconds = Math.floor(Number(value.split(' ')[0]) * 1000);
  if (!Number.isSafeInteger(milliseconds)) throw failed();
  return milliseconds;
}
function identity(value) {
  if (!value || !isId(value.nodeId) || !isId(value.workloadId)
    || typeof value.unit !== 'string' || !UNIT.test(value.unit) || typeof value.invocationId !== 'string' || !INVOCATION.test(value.invocationId)) throw failed();
  return Object.freeze({ nodeId: value.nodeId, workloadId: value.workloadId,
    unit: value.unit, invocationId: value.invocationId });
}
export function brokerIdentityFromEnvironment(env = process.env) {
  if (env.BLINDPASS_FLEET_MCP !== '1') {
    if (env.BLINDPASS_FLEET_MCP !== undefined && env.BLINDPASS_FLEET_MCP !== '0') throw failed();
    return undefined;
  }
  if (process.platform !== 'linux') throw failed();
  return identity({ nodeId: env.BLINDPASS_NODE_ID, workloadId: env.BLINDPASS_WORKLOAD_ID,
    unit: env.BLINDPASS_WORKLOAD_UNIT, invocationId: env.INVOCATION_ID });
}
export async function verifyBrokerSocket(stat = lstat) {
  for (const path of ['/', '/run', '/run/blindpass']) {
    const value = await stat(path, { bigint: true });
    if (!value.isDirectory() || Number(value.uid) !== 0 || (Number(value.mode) & 0o7022) !== 0
      || path === '/run/blindpass' && (Number(value.mode) & 0o7777) !== 0o751) throw failed();
  }
  const value = await stat(BROKER_SOCKET, { bigint: true });
  if (!value.isSocket() || Number(value.uid) !== 0 || Number(value.nlink) !== 1
    || (Number(value.mode) & 0o7777) !== 0o660) throw failed();
  return { dev: value.dev, ino: value.ino, gid: value.gid };
}

// The injected IO hooks are for trusted embedding/tests, never tool parameters.
export async function exchangeWithBroker(frame, { signal, onSent = () => {} },
  { verify = verifyBrokerSocket, connect = createConnection } = {}) {
  let expected;
  try { expected = await verify(); } catch { throw failed(); }
  if (signal?.aborted) throw failed();
  return new Promise((resolve, reject) => {
    let socket, done = false, readEnded = false, total = 0; const chunks = [];
    const finish = (error, value) => {
      if (done) return; done = true;
      signal?.removeEventListener('abort', abort);
      for (const chunk of chunks) chunk.fill(0);
      socket?.destroy();
      if (error) reject(failed()); else resolve(value);
    };
    const abort = () => finish(true);
    signal?.addEventListener('abort', abort, { once: true });
    if (signal?.aborted) { finish(true); return; }
    try { socket = connect({ path: BROKER_SOCKET }); } catch { finish(true); return; }
    socket.on('error', () => finish(true));
    socket.on('close', () => { if (!done && !readEnded) finish(true); });
    socket.on('data', chunk => {
      total += chunk.length;
      if (total > 4096) { chunk.fill(0); finish(true); return; }
      chunks.push(Buffer.from(chunk)); chunk.fill(0);
    });
    socket.on('connect', async () => {
      try {
        const actual = await verify();
        if (done || signal?.aborted) return;
        if (actual.dev !== expected.dev || actual.ino !== expected.ino || actual.gid !== expected.gid) { finish(true); return; }
        onSent(); socket.end(frame);
      } catch { finish(true); }
    });
    socket.on('end', async () => {
      readEnded = true;
      try {
        const actual = await verify();
        if (done) return;
        if (actual.dev !== expected.dev || actual.ino !== expected.ino || actual.gid !== expected.gid) { finish(true); return; }
        const buffer = Buffer.concat(chunks);
        let value; try { value = new TextDecoder('utf-8', { fatal: true }).decode(buffer); } finally { buffer.fill(0); }
        if (!/^[\x20-\x7e]+\n$/.test(value)) { finish(true); return; }
        finish(false, value);
      } catch { finish(true); }
    });
  });
}
function requestArgs(args) {
  if (!args || Object.keys(args).some(key => !['action', 'resourceId', 'purpose', 'ttlSeconds', 'requestKey'].includes(key))
    || args.action !== 'browser.session' || !isId(args.resourceId) || !isKey(args.requestKey)) throw failed();
  const purpose = args.purpose ?? 'Read approved report'; const ttlSeconds = args.ttlSeconds ?? 60;
  if (typeof purpose !== 'string' || Buffer.byteLength(purpose, 'utf8') > 512 || PURPOSE_FORBIDDEN.test(purpose)
    || !purpose.isWellFormed() || !Number.isSafeInteger(ttlSeconds) || ttlSeconds < 1 || ttlSeconds > 120) throw failed();
  return { action: args.action, mode: 'browser_session', purpose,
    resource_id: args.resourceId, ttl_seconds: ttlSeconds, request_key: args.requestKey };
}
function cancelArgs(args) {
  if (!args || Object.keys(args).some(key => !['eventKey', 'requestKey'].includes(key))
    || (args.eventKey !== undefined) === (args.requestKey !== undefined)) throw failed();
  const key = args.eventKey ?? args.requestKey; if (!isKey(key)) throw failed();
  return `${args.eventKey === undefined ? 'cancel-key' : 'cancel'}:${key}`;
}
function parseReply(value, operation) {
  if (typeof value !== 'string' || value.length > 4096 || !/^[\x20-\x7e]+\n$/.test(value)) throw failed();
  if (value.startsWith('ERR ')) throw new BrokerRejected();
  let match;
  if (operation === 'request' && (match = /^OK operation_request (event_[A-Za-z0-9_-]{16,100})\n$/.exec(value))) return { status: 'requested', eventKey: match[1] };
  if (operation === 'status') {
    if ((match = /^OK operation_status (unknown|pending|cancelling)\n$/.exec(value))) return { status: match[1] };
    if ((match = /^OK operation_status ready (ctx_[a-f0-9]{64})\n$/.exec(value))) return { status: 'ready', contextHandle: match[1] };
    if ((match = /^OK operation_status granted (gr_[A-Za-z0-9_-]{16,100}) (op_[A-Za-z0-9_-]{16,100})\n$/.exec(value))) return { status: 'granted', grantId: match[1], operationId: match[2] };
    if ((match = /^OK operation_status closed ([a-z]+)\n$/.exec(value)) && CLOSED.has(match[1])) return { status: 'closed', outcome: match[1] };
  }
  if (operation === 'cancel') {
    if (value === 'OK operation_cancel requested\n') return { status: 'cancellation_requested' };
    if ((match = /^OK operation_cancel closed ([a-z]+)\n$/.exec(value)) && CLOSED.has(match[1])) return { status: 'closed', outcome: match[1] };
  }
  throw failed();
}
export function createBrokerClient(config, { exchange = exchangeWithBroker, now = brokerClockMs,
  callTimeoutMs = BROKER_CALL_TIMEOUT_MS, cleanupTimeoutMs = 5000 } = {}) {
  const owner = identity(config);
  if (!Number.isSafeInteger(callTimeoutMs) || callTimeoutMs < 2 || callTimeoutMs > BROKER_CALL_TIMEOUT_MS
    || !Number.isSafeInteger(cleanupTimeoutMs) || cleanupTimeoutMs < 1 || cleanupTimeoutMs > 5000
    || cleanupTimeoutMs >= callTimeoutMs) throw failed();
  const frame = operation => {
    const value = `WORK ${owner.nodeId} ${owner.workloadId} ${owner.unit} ${owner.invocationId} ${operation}\n`;
    if (Buffer.byteLength(value) > 4096 || operation.length > 2048) throw failed();
    return value;
  };
  async function bounded(operation, deadline, signal, onSent = () => {}) {
    const controller = new AbortController(); let interval; let rejectAbort;
    const abort = () => { controller.abort(); rejectAbort?.(failed()); };
    const stopped = new Promise((_, reject) => { rejectAbort = reject; });
    stopped.catch(() => {});
    signal?.addEventListener('abort', abort, { once: true });
    const check = () => { try { if (now() >= deadline || signal?.aborted) abort(); } catch { abort(); } };
    try {
      check(); if (controller.signal.aborted) throw failed();
      interval = setInterval(check, Math.min(25, Math.max(1, deadline - now())));
      const result = await Promise.race([exchange(frame(operation), { signal: controller.signal, onSent }), stopped]);
      check(); if (controller.signal.aborted) throw failed();
      return result;
    } finally { clearInterval(interval); signal?.removeEventListener('abort', abort); controller.abort(); }
  }
  async function withdraw(operation, deadline) {
    try { return parseReply(await bounded(operation, Math.min(deadline, now() + cleanupTimeoutMs)), 'cancel'); }
    catch { return undefined; }
  }
  const api = {
    async request(args, signal) {
      const payload = requestArgs(args); const deadline = now() + callTimeoutMs; let sent = false;
      try {
        const encoded = Buffer.from(JSON.stringify(payload)).toString('base64url');
        if (encoded.length > 1536) throw failed();
        const result = parseReply(await bounded(`request:${encoded}`, deadline - cleanupTimeoutMs, signal, () => { sent = true; }), 'request');
        return { ...result, requestKey: payload.request_key };
      } catch (error) {
        if (!sent || error instanceof BrokerRejected) throw failed();
        const cancellation = await withdraw(`cancel-key:${payload.request_key}`, deadline);
        return { status: 'uncertain', requestKey: payload.request_key,
          cancellation: cancellation?.status === 'closed' ? 'closed' : cancellation ? 'requested' : 'unconfirmed' };
      }
    },
    async status(eventKey, signal) {
      if (!isKey(eventKey)) throw failed();
      const result = parseReply(await bounded(`status:${eventKey}`, now() + callTimeoutMs, signal), 'status');
      return { ...result, eventKey };
    },
    async cancel(args, signal) {
      const operation = cancelArgs(args); const deadline = now() + callTimeoutMs; let sent = false;
      try { return parseReply(await bounded(operation, deadline - cleanupTimeoutMs, signal, () => { sent = true; }), 'cancel'); }
      catch (error) {
        if (!sent || error instanceof BrokerRejected) throw failed();
        return await withdraw(operation, deadline) ?? { status: 'uncertain', cancellation: 'unconfirmed' };
      }
    },
  };
  let ordinary = 0, cancellations = 0;
  const active = new Set();
  const guarded = (execute, cancel) => async (...args) => {
    if (cancel ? cancellations >= 4 : ordinary >= 12) throw failed();
    if (cancel) cancellations++; else ordinary++;
    const controller = new AbortController(); const outer = args[1];
    const abort = () => controller.abort();
    outer?.addEventListener('abort', abort, { once: true });
    if (outer?.aborted) abort();
    active.add(controller);
    try { return await execute(args[0], controller.signal); }
    finally { active.delete(controller); outer?.removeEventListener('abort', abort); if (cancel) cancellations--; else ordinary--; }
  };
  return Object.freeze({ callTimeoutMs, request: guarded(api.request, false), status: guarded(api.status, false),
    cancel: guarded(api.cancel, true), abortActive() { for (const controller of active) controller.abort(); } });
}
