// SPDX-License-Identifier: AGPL-3.0-only
// Fixed Root activation, protected IPC only. No stdout/stderr diagnostics.
import { Socket } from 'node:net';
import { fstatSync, readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { attachFramedStream } from './browser-transport.mjs';
import { parseSupervisorBoottime, selectSupervisorTransport } from './browser-supervisor-worker.mjs';
import { createRevoker } from './session-revoker.mjs';
const unavailable = () => new Error('revocation_unavailable');
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));

export class RevocationWorker {
  #send; #create; #now; #revoker; #deadline; #state = 'idle';
  constructor({ send, now, create = createRevoker }) { this.#send = send; this.#now = now; this.#create = create; }
  async close() { this.#state = 'closed'; await this.#revoker?.close(); }
  async checkDeadline() { if (this.#deadline !== undefined && this.#now() >= this.#deadline) await this.close(); }
  get closed() { return this.#state === 'closed'; }
  async receive(message) {
    try {
      await this.checkDeadline(); if (this.closed) throw unavailable();
      if (message?.type === 'preflight') {
        const now = this.#now();
        if (this.#state !== 'idle' || !exact(message, ['type', 'version', 'operationId', 'configuration', 'profile', 'credential', 'deadlineBoottimeMs'])
          || message.version !== 1 || !/^[A-Za-z0-9_-]{16,128}$/.test(message.operationId ?? '')
          || !Number.isSafeInteger(message.deadlineBoottimeMs) || message.deadlineBoottimeMs <= now
          || message.deadlineBoottimeMs > now + 5000) throw unavailable();
        this.#state = 'checking'; this.#deadline = message.deadlineBoottimeMs;
        this.#revoker = await this.#create(message.configuration, message.profile, message.credential, { now: this.#now });
        const result = await this.#revoker.preflight();
        await this.checkDeadline(); if (this.closed || result?.type !== 'revocation-ready') throw unavailable();
        this.#state = 'ready'; this.#deadline = this.#now() + 32 * 60_000;
        await this.#send({ type: 'revocation-ready' }); return;
      }
      if (this.#state !== 'ready') throw unavailable();
      if (message?.type === 'close' && exact(message, ['type'])) {
        await this.close(); await this.#send({ type: 'revocation-closed' }); return;
      }
      let result;
      if (message?.type === 'revoke-session' && exact(message, ['type', 'handle'])) result = await this.#revoker.revoke(message.handle);
      else if (message?.type === 'revoke-account' && exact(message, ['type'])) result = await this.#revoker.revokeAccount();
      else throw unavailable();
      await this.checkDeadline(); if (this.closed || result?.type !== 'revoked') throw unavailable();
      await this.#send({ type: 'revoked' });
    } catch (error) {
      await this.close(); await this.#send({ type: error?.message === 'revocation_uncertain' ? 'revocation-uncertain' : 'revocation-unavailable' });
    } finally { if (message && typeof message === 'object' && Object.hasOwn(message, 'credential')) message.credential = ''; }
  }
}
async function main() {
  let fd;
  try { fd = selectSupervisorTransport(process.argv.slice(2), process.getuid(), process.env, fstatSync); } catch { process.exit(64); }
  process.umask(0o077); const stream = new Socket({ fd, readable: true, writable: true });
  const now = () => parseSupervisorBoottime(readFileSync('/proc/uptime', 'utf8'));
  let channel;
  const worker = new RevocationWorker({ send: message => channel.send(message), now });
  const terminate = async () => { await worker.close(); stream.destroy(); clearInterval(timer); };
  channel = attachFramedStream(stream, { receive: async value => {
    await worker.receive(value); if (worker.closed) { stream.end(); clearInterval(timer); }
  }, onFailure: () => { void terminate(); } });
  const timer = setInterval(() => { void worker.checkDeadline().then(() => { if (worker.closed) void terminate(); }).catch(() => { void terminate(); }); }, 100);
  timer.unref();
  for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => { void terminate(); });
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) void main().catch(() => process.exit(70));
