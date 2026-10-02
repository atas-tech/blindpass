// SPDX-License-Identifier: AGPL-3.0-only
// Root administrator channel. It consumes no source password or website cookie.
import { Agent, request } from 'node:http';
import { connect as unixConnect } from 'node:net';
import { connect as tlsConnect, checkServerIdentity } from 'node:tls';
import { createHash, X509Certificate } from 'node:crypto';
import { lstat } from 'node:fs/promises';
import { compileRecipe } from './private-login.mjs';

const BACKEND = '/run/blindpass-app/grafana.sock';
const unavailable = () => new Error('revocation_unavailable');
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const credentialName = value => typeof value === 'string' && /^[A-Za-z0-9_.-]{1,128}$/.test(value);
export function compileRevocation(configuration, profile) {
  try {
    const recipe = compileRecipe(configuration);
    if (!exact(profile, ['kind', 'credential_unit', 'credential_name', ...(recipe.kind === 'grafana-managed' ? ['user_id'] : [])])
      || profile.kind !== (recipe.kind === 'fixture' ? 'fixture-admin' : 'grafana-admin')
      || profile.credential_unit !== 'blindpass-session-revoker@.service' || !credentialName(profile.credential_name)
      || recipe.kind === 'grafana-managed' && (!Number.isSafeInteger(profile.user_id) || profile.user_id < 1 || profile.user_id > 4294967295)) throw unavailable();
    return Object.freeze({ ...recipe, userId: profile.user_id });
  } catch { throw unavailable(); }
}
async function protectedBackend() {
  for (const path of ['/run', '/run/blindpass-app']) {
    const value = await lstat(path);
    if (!value.isDirectory() || value.uid !== 0 || value.gid !== 0 || (value.mode & 0o022) !== 0
      || path !== '/run' && (value.mode & 0o7777) !== 0o700) throw unavailable();
  }
  const value = await lstat(BACKEND);
  if (!value.isSocket() || value.uid !== 0 || value.gid !== 0 || (value.mode & 0o7777) !== 0o600 || value.nlink !== 1) throw unavailable();
  return `${value.dev}:${value.ino}`;
}
async function verifiedTls(recipe, remaining, sockets) {
  const origin = new URL(recipe.origin); const host = origin.hostname.replace(/^\[|\]$/g, '');
  const socket = tlsConnect({ host, port: Number(origin.port || 443), minVersion: 'TLSv1.2',
    servername: host.includes(':') || /^\d+\.\d+\.\d+\.\d+$/.test(host) ? undefined : host,
    rejectUnauthorized: recipe.certificateSpkiPins.length === 0 });
  sockets.add(socket); socket.once('close', () => sockets.delete(socket));
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => { socket.destroy(); reject(unavailable()); }, remaining());
    socket.once('error', () => { clearTimeout(timer); reject(unavailable()); });
    socket.once('secureConnect', () => {
      clearTimeout(timer);
      try {
        const certificate = socket.getPeerCertificate();
        if (checkServerIdentity(host, certificate)) throw unavailable();
        const x509 = new X509Certificate(certificate.raw); const now = Date.now();
        if (now < Date.parse(x509.validFrom) || now >= Date.parse(x509.validTo)) throw unavailable();
        const pin = createHash('sha256').update(x509.publicKey.export({ type: 'spki', format: 'der' })).digest('base64');
        if (recipe.certificateSpkiPins.length && !recipe.certificateSpkiPins.includes(pin)) throw unavailable();
        remaining(); resolve();
      } catch { socket.destroy(); reject(unavailable()); }
    });
  });
  return socket;
}

export async function createRevoker(configuration, profile, credential, { now = performance.now.bind(performance),
  backendCheck = protectedBackend, backendConnect = () => unixConnect({ path: BACKEND }) } = {}) {
  const recipe = compileRevocation(configuration, profile);
  if (typeof credential !== 'string' || (recipe.kind === 'fixture' ? !/^[a-f0-9]{64}$/.test(credential)
    : !/^[a-z][a-z0-9_-]{0,31}$/.test(credential)) || typeof now !== 'function') throw unavailable();
  let closed = false; let busy = false; let ready = false; const sockets = new Set();
  async function send(path, body, started) {
    if (closed) throw unavailable();
    const deadline = now() + 5000;
    const remaining = () => { const value = deadline - now(); if (!Number.isFinite(value) || value <= 0) throw unavailable(); return Math.ceil(value); };
    let agent; let socket; let before;
    try {
      const origin = new URL(recipe.origin);
      const headers = { host: origin.host, connection: 'close', ...(body ? { 'content-type': 'application/json' } : {}) };
      if (recipe.kind === 'fixture') {
        // The administrator bearer header is built only after destination TLS
        // identity, validity and optional Root-installed SPKI pins are verified.
        socket = await verifiedTls(recipe, remaining, sockets);
        agent = new Agent({ keepAlive: false, maxSockets: 1 }); agent.createConnection = () => socket;
        headers.authorization = `Bearer ${credential}`;
      } else {
        // Trusted embedding hooks support isolated app tests. The installed
        // worker supplies only `now`, retaining the fixed protected path.
        before = await backendCheck(); remaining(); socket = backendConnect();
        sockets.add(socket); socket.once('close', () => sockets.delete(socket));
        await new Promise((resolve, reject) => {
          const timer = setTimeout(() => { socket.destroy(); reject(unavailable()); }, remaining());
          socket.once('error', () => { clearTimeout(timer); reject(unavailable()); });
          socket.once('connect', () => { clearTimeout(timer); resolve(); });
        });
        if (await backendCheck() !== before || closed) throw unavailable(); remaining();
        agent = new Agent({ keepAlive: false, maxSockets: 1 }); agent.createConnection = () => socket;
        headers['x-p05-trusted-user'] = credential; headers['x-forwarded-proto'] = 'https';
      }
      return await new Promise((resolve, reject) => {
        let bytes = 0; const chunks = []; let completed = false;
        const finish = (error, value) => {
          if (completed) return; completed = true; clearTimeout(timer);
          for (const chunk of chunks) chunk.fill(0);
          if (error) { req.destroy(); reject(unavailable()); } else resolve(value);
        };
        const req = request({ host: origin.hostname.replace(/^\[|\]$/g, ''), port: Number(origin.port || 443),
          agent,
          path, method: body ? 'POST' : 'GET', headers, maxHeaderSize: 4096 }, res => {
          res.on('data', chunk => {
            bytes += chunk.length;
            if (bytes > 16_384) { chunk.fill(0); finish(true); } else chunks.push(chunk);
          });
          res.on('aborted', () => finish(true)); res.on('error', () => finish(true));
          res.on('end', () => {
            const data = Buffer.concat(chunks);
            try {
              if (res.statusCode < 200 || res.statusCode >= 300) throw unavailable();
              const text = new TextDecoder('utf-8', { fatal: true }).decode(data);
              const json = text ? JSON.parse(text) : null;
              finish(false, { status: res.statusCode, json });
            } catch { finish(true); } finally { data.fill(0); }
          });
        });
        const timer = setTimeout(() => finish(true), remaining());
        req.on('error', () => finish(true));
        req.on('socket', stream => {
          sockets.add(stream); stream.once('close', () => sockets.delete(stream));
        });
        started(); req.end(body ? JSON.stringify(body) : undefined);
      });
    } finally { agent?.destroy(); socket?.destroy(); }
  }
  async function action(run, uncertain = false) {
    if (closed || busy) throw unavailable(); busy = true; let started = false;
    try { return await run((path, body) => send(path, body, () => { started = true; })); }
    catch { throw new Error(uncertain && started ? 'revocation_uncertain' : 'revocation_unavailable'); }
    finally { busy = false; }
  }
  async function preflight() {
    ready = false;
    return action(async send => {
      if (recipe.kind === 'fixture') {
        const result = await send('/admin/accounts/check', { account: recipe.account });
        if (result.status !== 200 || !exact(result.json, ['status', 'account']) || result.json.status !== 'revocation_ready'
          || result.json.account !== recipe.account) throw unavailable();
      } else {
        const administrator = await send('/api/user');
        if (administrator.status !== 200 || administrator.json?.login !== credential || administrator.json?.isGrafanaAdmin !== true) throw unavailable();
        const account = await send(`/api/users/lookup?loginOrEmail=${encodeURIComponent(recipe.account)}`);
        if (account.status !== 200 || account.json?.login !== recipe.account || account.json?.id !== recipe.userId) throw unavailable();
      }
      ready = true; return { type: 'revocation-ready' };
    });
  }
  async function revoke(handle) {
    if (!ready || !(recipe.kind === 'fixture'
      ? exact(handle, ['kind', 'account', 'sessionReference']) && handle.kind === 'fixture' && /^[a-f0-9]{32}$/.test(handle.sessionReference ?? '')
      : exact(handle, ['kind', 'account', 'userId', 'orgId']) && handle.kind === 'grafana-managed' && handle.userId === recipe.userId && handle.orgId === recipe.orgId)
      || handle.account !== recipe.account) throw unavailable();
    return action(async send => {
      const result = recipe.kind === 'fixture' ? await send('/admin/sessions/revoke', { account: recipe.account, sessionReference: handle.sessionReference })
        : await send(`/api/admin/users/${recipe.userId}/logout`, {});
      if (result.status !== (recipe.kind === 'fixture' ? 204 : 200)) throw unavailable();
      return { type: 'revoked' };
    }, true);
  }
  async function revokeAccount() {
    if (!ready) throw unavailable();
    return action(async send => {
      const result = recipe.kind === 'fixture' ? await send('/admin/accounts/revoke', { account: recipe.account })
        : await send(`/api/admin/users/${recipe.userId}/logout`, {});
      if (result.status !== (recipe.kind === 'fixture' ? 204 : 200)) throw unavailable();
      return { type: 'revoked' };
    }, true);
  }
  return { preflight, revoke, revokeAccount, close: async () => { closed = true; ready = false; credential = ''; for (const socket of sockets) socket.destroy(); } };
}
