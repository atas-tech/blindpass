// SPDX-License-Identifier: AGPL-3.0-only
import { compileRecipe } from './private-login.mjs';

const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
const invalid = () => new Error('invalid_session');

export function approvedConnectAuthority(configuration) {
  const recipe = compileRecipe(configuration);
  const origin = new URL(recipe.origin);
  return `${origin.hostname}:${origin.port || '443'}`;
}

export function validateCookies(recipe, cookies, deadline, now) {
  const required = recipe.kind === 'fixture' ? '__Host-bp-fixture' : 'grafana_session';
  const allowed = new Set([required, ...(recipe.kind === 'grafana-managed' ? ['grafana_session_expiry'] : [])]);
  if (!Number.isSafeInteger(deadline) || deadline <= now || deadline > now + recipe.sessionMaxMs
    || !Array.isArray(cookies) || !cookies.length || cookies.length > 2) throw invalid();
  const hostname = new URL(recipe.origin).hostname; const names = new Set();
  for (const cookie of cookies) {
    if (!exact(cookie, ['name', 'value', 'domain', 'path', 'secure', 'httpOnly', 'sameSite', 'expires'])
      || !allowed.has(cookie.name) || names.has(cookie.name) || cookie.domain !== hostname || cookie.path !== '/'
      || cookie.secure !== true || typeof cookie.httpOnly !== 'boolean' || cookie.name === required && !cookie.httpOnly
      || !['Strict', 'Lax'].includes(cookie.sameSite) || recipe.kind === 'fixture' && cookie.sameSite !== 'Strict'
      || typeof cookie.value !== 'string' || !/^[A-Za-z0-9_-]{1,4096}$/.test(cookie.value)
      || !Number.isSafeInteger(cookie.expires) || cookie.expires * 1000 <= now || cookie.expires * 1000 > deadline) throw invalid();
    names.add(cookie.name);
  }
  if (!names.has(required)) throw invalid();
}

// start is a supervisor-owned function. It returns a fresh sandboxed browser
// inside a private network namespace, never an agent-provided browser endpoint.
// Manager identity must be persisted by the root broker before sending import.
export class IsolatedBrowserSession {
  #send; #mux; #start; #prove; #proved = false; #now; #onTerminal;
  #state = 'idle'; #recipe; #runtime; #deadline; #timer; #closing;
  constructor({ send, mux, start, prove, now = Date.now, onTerminal = () => {} }) {
    if (typeof prove !== 'function') throw invalid();
    this.#send = send; this.#mux = mux; this.#start = start; this.#prove = prove; this.#now = now; this.#onTerminal = onTerminal;
    this.#timer = setInterval(() => { void this.checkDeadline(); }, 250);
    this.#timer.unref();
  }
  get closed() { return this.#state === 'closed'; }
  async #publish(message) { await this.#send(message); }
  async fail() {
    if (this.closed) return;
    await this.close();
    try { await this.#publish({ type: 'uncertain' }); } catch { /* private peer unavailable */ }
    this.#onTerminal();
  }
  async checkDeadline() {
    if (!this.closed && this.#deadline !== undefined && this.#now() >= this.#deadline) await this.fail();
  }
  async receive(message) {
    if (this.closed) return;
    try {
      await this.checkDeadline(); if (this.closed) return;
      if (message?.type === 'start') {
        if (this.#state !== 'idle' || !exact(message, ['type', 'version', 'configuration']) || message.version !== 1) throw invalid();
        this.#recipe = compileRecipe(message.configuration); this.#state = 'starting';
        this.#deadline = this.#now() + 30_000;
        this.#runtime = await this.#start(this.#recipe);
        if (this.closed) {
          // A deadline can fire while browser startup awaits. Dispose a late
          // result; never publish its endpoint or make it importable. Cleanup
          // (proxy and profile removal) runs even if closing the context throws.
          try { await this.#runtime.context.close(); } finally { await this.#runtime.cleanup(); }
          return;
        }
        if ((await this.#runtime.context.cookies()).length !== 0) throw invalid();
        if (!/^\/devtools\/browser\/[a-f0-9-]{36}$/.test(this.#runtime.devtoolsPath)
          || !Number.isSafeInteger(this.#runtime.pid) || this.#runtime.pid < 1
          || !/^[a-f0-9]{32}$/.test(this.#runtime.invocation)) throw invalid();
        this.#state = 'prepared';
        await this.#publish({ type: 'prepared', version: 1, pid: this.#runtime.pid,
          invocation: this.#runtime.invocation, devtoolsPath: this.#runtime.devtoolsPath });
        return;
      }
      if (message?.type === 'prove') {
        try {
          if (this.#state !== 'prepared' || this.#proved || !exact(message, ['type', 'version', 'challenge'])
            || message.version !== 1 || typeof message.challenge !== 'string' || !/^[a-f0-9]{64}$/.test(message.challenge)) throw invalid();
          this.#state = 'proving';
          await this.#prove(message.challenge);
          await this.checkDeadline(); if (this.closed) return;
          this.#proved = true; this.#state = 'prepared';
          await this.#publish({ type: 'identity-proved' });
        } finally {
          // The challenge stays on protected IPC. Drop the V8 input reference;
          // the root listener stores only its hash and consumes it once.
          message.challenge = '';
        }
        return;
      }
      if (message?.type === 'import') {
        try {
          if (this.#state !== 'prepared' || !this.#proved || !exact(message, ['type', 'originalDeadlineMs', 'cookies'])) throw invalid();
          validateCookies(this.#recipe, message.cookies, message.originalDeadlineMs, this.#now());
          this.#state = 'importing'; this.#deadline = message.originalDeadlineMs;
          await this.#runtime.context.addCookies(message.cookies);
          await this.checkDeadline(); if (this.closed) return;
          this.#state = 'active'; this.#mux.activate();
          await this.#publish({ type: 'active' });
        } finally {
          // V8 strings cannot be deterministically zeroized. Drop input cookie
          // references immediately; browser memory holds the intentional session.
          if (Array.isArray(message.cookies)) for (const cookie of message.cookies) {
            if (cookie && typeof cookie === 'object') cookie.value = '';
          }
        }
        return;
      }
      if (message?.type === 'stop') {
        if (!exact(message, ['type'])) throw invalid();
        const success = await this.close();
        await this.#publish({ type: success ? 'stopped' : 'uncertain' }); this.#onTerminal(); return;
      }
      if (['open', 'opened', 'data', 'close'].includes(message?.type) && this.#state !== 'idle') {
        await this.#mux.receive(message); return;
      }
      throw invalid();
    } catch { await this.fail(); }
  }
  async close() {
    if (this.#closing) return this.#closing;
    this.#state = 'closed'; clearInterval(this.#timer); this.#mux.close();
    this.#closing = (async () => {
      if (!this.#runtime) return true;
      try { await this.#runtime.context.close(); await this.#runtime.cleanup(); return true; }
      catch { return false; }
    })();
    return this.#closing;
  }
}
