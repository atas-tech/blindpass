// SPDX-License-Identifier: AGPL-3.0-only
// Fixed production outside-channel supervisor; not a workload API. Kernel
// identity, manager/profile, journal and signed authority are broker gates.
import { createHash } from 'node:crypto';
import { compileRecipe } from './private-login.mjs';
import { validateCookies } from './isolated-browser.mjs';

const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const invalid = () => new Error('supervisor_unavailable');
const integer = value => Number.isSafeInteger(value) && value > 0;
const wipeCookies = message => {
  if (Array.isArray(message?.cookies)) for (const cookie of message.cookies) {
    if (cookie && typeof cookie === 'object') cookie.value = '';
  }
};

export class BrowserSupervisor {
  #sendWorker; #sendParent; #mux; #now; #wallNow; #createBackend; #closeWorker; #onTerminal;
  #state = 'idle'; #recipe; #operationId; #contextHandle; #proved = false; #deadline; #sessionDeadline;
  #backend; #timer; #closing; #terminal = false;
  constructor({ sendWorker, sendParent, mux, now, wallNow = Date.now, createBackend, closeWorker, onTerminal = () => {} }) {
    if ([sendWorker, sendParent, now, wallNow, createBackend, closeWorker, onTerminal].some(value => typeof value !== 'function')
      || !mux || ['activate', 'close', 'receive', 'attach'].some(name => typeof mux[name] !== 'function')) throw invalid();
    this.#sendWorker = sendWorker; this.#sendParent = sendParent; this.#mux = mux;
    this.#now = now; this.#wallNow = wallNow; this.#createBackend = createBackend;
    this.#closeWorker = closeWorker; this.#onTerminal = onTerminal;
    this.#timer = setInterval(() => { void this.checkDeadline(); }, 100); this.#timer.unref();
  }
  get configuration() { return this.#recipe; }
  get closed() { return this.#state === 'closed'; }
  async #finish(message) {
    await this.close();
    try { await this.#sendParent(message); } catch { /* private parent unavailable */ }
    if (!this.#terminal) { this.#terminal = true; this.#onTerminal(); }
  }
  async fail() { if (!this.closed) await this.#finish({ type: 'uncertain' }); }
  async checkDeadline() {
    try {
      if (!this.closed && this.#deadline !== undefined && this.#now() >= this.#deadline) await this.fail();
    } catch { await this.fail(); }
  }
  async receiveParent(message) {
    try {
      await this.checkDeadline(); if (this.closed) return;
      if (message?.type === 'start') {
        const now = this.#now();
        if (this.#state !== 'idle' || !exact(message, ['type', 'version', 'operationId', 'configuration', 'deadlineBoottimeMs'])
          || message.version !== 1 || !/^[A-Za-z0-9_-]{16,128}$/.test(message.operationId ?? '')
          || !integer(message.deadlineBoottimeMs) || message.deadlineBoottimeMs <= now
          || message.deadlineBoottimeMs > now + 120_000) throw invalid();
        this.#recipe = compileRecipe(message.configuration); this.#operationId = message.operationId;
        this.#contextHandle = `ctx_${createHash('sha256').update(message.operationId).digest('hex')}`;
        this.#deadline = message.deadlineBoottimeMs; this.#state = 'starting';
        await this.#sendWorker({ type: 'start', version: 1, configuration: message.configuration });
        await this.checkDeadline(); return;
      }
      if (message?.type === 'prove') {
        if (this.#state !== 'prepared' || this.#proved || !exact(message, ['type', 'version', 'challenge'])
          || message.version !== 1 || !/^[a-f0-9]{64}$/.test(message.challenge ?? '')) throw invalid();
        this.#state = 'proving'; await this.#sendWorker(message); return;
      }
      if (message?.type === 'import') {
        const now = this.#now();
        if (this.#state !== 'prepared' || !this.#proved || !exact(message, ['type', 'originalDeadlineMs', 'sessionDeadlineBoottimeMs', 'cookies'])
          || !integer(message.sessionDeadlineBoottimeMs) || message.sessionDeadlineBoottimeMs <= now
          || message.sessionDeadlineBoottimeMs > now + this.#recipe.sessionMaxMs) throw invalid();
        const wallNow = this.#wallNow();
        validateCookies(this.#recipe, message.cookies, message.originalDeadlineMs, wallNow);
        if (message.sessionDeadlineBoottimeMs > now + message.originalDeadlineMs - wallNow) throw invalid();
        this.#sessionDeadline = message.sessionDeadlineBoottimeMs;
        this.#deadline = Math.min(this.#deadline, this.#sessionDeadline); this.#state = 'importing';
        await this.#sendWorker({ type: 'import', originalDeadlineMs: message.originalDeadlineMs, cookies: message.cookies });
        await this.checkDeadline(); return;
      }
      if (message?.type === 'publish') {
        if (this.#state !== 'imported' || !exact(message, ['type'])) throw invalid();
        this.#state = 'publishing';
        const backend = await this.#createBackend(this.#operationId, socket => {
          try {
            if (this.#state !== 'ready' || this.#now() >= this.#deadline) throw invalid();
            this.#mux.attach('cdp', socket);
          } catch { socket.destroy(); }
        });
        if (this.closed) { await backend.close(); return; }
        this.#backend = backend;
        await this.checkDeadline(); if (this.closed) return;
        this.#mux.activate(); this.#deadline = this.#sessionDeadline; this.#state = 'ready';
        await this.#sendParent({ type: 'published', contextHandle: this.#contextHandle }); return;
      }
      if (message?.type === 'stop') {
        if (!exact(message, ['type']) || this.#state === 'stopping') throw invalid();
        this.#state = 'stopping'; this.#deadline = this.#now() + 5_000;
        this.#mux.close(); await this.#backend?.close();
        await this.#sendWorker({ type: 'stop' }); return;
      }
      throw invalid();
    } catch { await this.fail(); }
    finally { wipeCookies(message); if (message?.type === 'prove') message.challenge = ''; }
  }
  async receiveWorker(message) {
    try {
      await this.checkDeadline(); if (this.closed) return;
      if (message?.type === 'prepared') {
        if (this.#state !== 'starting' || !exact(message, ['type', 'version', 'pid', 'invocation', 'devtoolsPath'])
          || message.version !== 1 || !integer(message.pid) || !/^[a-f0-9]{32}$/.test(message.invocation ?? '')
          || !/^\/devtools\/browser\/[a-f0-9-]{36}$/.test(message.devtoolsPath ?? '')) throw invalid();
        this.#state = 'prepared';
        // These are private hints only. The broker must obtain the actual
        // kernel/manager identity and may not authorize from these fields.
        await this.#sendParent(message); return;
      }
      if (message?.type === 'identity-proved') {
        if (this.#state !== 'proving' || !exact(message, ['type'])) throw invalid();
        this.#proved = true; this.#state = 'prepared'; await this.#sendParent(message); return;
      }
      if (message?.type === 'active') {
        if (this.#state !== 'importing' || !exact(message, ['type'])) throw invalid();
        this.#state = 'imported'; await this.#sendParent({ type: 'imported' }); return;
      }
      if (message?.type === 'stopped') {
        if (this.#state !== 'stopping' || !exact(message, ['type'])) throw invalid();
        await this.#finish({ type: 'stopped' }); return;
      }
      if (['open', 'opened', 'data', 'close'].includes(message?.type) && this.#state === 'stopping') {
        // The tunnel is already closed for the stop; frames the worker had in
        // flight are dropped quietly so they cannot turn `stopped` into `uncertain`.
        return;
      }
      if (['open', 'opened', 'data', 'close'].includes(message?.type) && this.#state !== 'idle') {
        await this.#mux.receive(message); return;
      }
      throw invalid();
    } catch { await this.fail(); }
    finally { wipeCookies(message); }
  }
  async close() {
    if (this.#closing) return this.#closing;
    this.#state = 'closed'; clearInterval(this.#timer); this.#mux.close();
    this.#closing = (async () => {
      try { await this.#backend?.close(); } catch { /* Root reconciles uncertain cleanup */ }
      try { await this.#closeWorker(); } catch { /* manager cgroup proof is a separate gate */ }
    })();
    return this.#closing;
  }
}
