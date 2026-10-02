// SPDX-License-Identifier: AGPL-3.0-only
import { verifyPinnedLeaf } from './certificate-pins.mjs';

const MAX_SESSION_MS = 30 * 60_000;
const MAX_HELPER_MS = 60_000;
const CONFIG_KEYS = new Set(['kind', 'origin', 'account', 'sessionMaxMs', 'loginOrigin', 'orgId', 'certificateSpkiPins']);
class HelperFailure extends Error {
  constructor(status) { super(status); this.status = status; }
}

function originOnly(value) {
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.username || url.password || url.pathname !== '/'
    || url.search || url.hash || url.origin !== value) throw new Error('invalid_configuration');
  return url.origin;
}

// Configuration is selected by the administrator/broker, never the agent request.
// This API has no arbitrary selectors, scripts, Chromium flags or capture options.
export function compileRecipe(configuration) {
  try {
    if (!configuration || typeof configuration !== 'object' || Array.isArray(configuration)
      || Object.keys(configuration).some((key) => !CONFIG_KEYS.has(key))
      || !['fixture', 'grafana-managed'].includes(configuration.kind)
      || typeof configuration.account !== 'string' || !/^[a-z][a-z0-9_-]{0,31}$/.test(configuration.account)
      || !Number.isInteger(configuration.sessionMaxMs) || configuration.sessionMaxMs < 1000
      || configuration.sessionMaxMs > MAX_SESSION_MS) throw new Error('invalid_configuration');
    const origin = originOnly(configuration.origin);
    const loginOrigin = originOnly(configuration.loginOrigin ?? origin);
    if (configuration.kind === 'fixture' && loginOrigin !== origin
      || configuration.kind === 'grafana-managed' && (!Number.isSafeInteger(configuration.orgId) || configuration.orgId < 1)) {
      throw new Error('invalid_configuration');
    }
    const pins = configuration.certificateSpkiPins ?? [];
    if (!Array.isArray(pins) || pins.length > 2 || pins.some((pin) => typeof pin !== 'string' || !/^[A-Za-z0-9+/]{43}=$/.test(pin))) {
      throw new Error('invalid_configuration');
    }
    return Object.freeze({ kind: configuration.kind, origin, loginOrigin,
      account: configuration.account, sessionMaxMs: configuration.sessionMaxMs,
      orgId: configuration.orgId, certificateSpkiPins: Object.freeze([...pins]) });
  } catch { throw new Error('invalid_configuration'); }
}

export function selectSessionCookies(recipe, cookies, originalDeadlineMs) {
  const required = recipe.kind === 'fixture' ? '__Host-bp-fixture' : 'grafana_session';
  const allowed = new Set([required, ...(recipe.kind === 'grafana-managed' ? ['grafana_session_expiry'] : [])]);
  const hostname = new URL(recipe.origin).hostname;
  if (!Array.isArray(cookies) || cookies.length > 64 || !Number.isFinite(originalDeadlineMs)
    || originalDeadlineMs <= Date.now()) throw new Error('invalid_session');
  const selected = [];
  const names = new Set();
  for (const cookie of cookies) {
    if (!allowed.has(cookie.name)) continue;
    if (names.has(cookie.name) || cookie.domain !== hostname || cookie.path !== '/' || !cookie.secure
      || cookie.name === required && !cookie.httpOnly || !['Strict', 'Lax'].includes(cookie.sameSite)
      || typeof cookie.value !== 'string' || !/^[A-Za-z0-9_-]{1,4096}$/.test(cookie.value)
      || !Number.isFinite(cookie.expires) || cookie.expires !== -1 && cookie.expires * 1000 <= Date.now()) {
      throw new Error('invalid_session');
    }
    names.add(cookie.name);
    selected.push({ name: cookie.name, value: cookie.value, domain: hostname, path: '/', secure: true,
      httpOnly: cookie.httpOnly, sameSite: cookie.sameSite,
      expires: Math.floor(Math.min(originalDeadlineMs / 1000, cookie.expires === -1 ? Infinity : cookie.expires)) });
  }
  if (!names.has(required)) throw new Error('invalid_session');
  return selected;
}

// The supervisor supplies a pinned Playwright launch function in its own process.
// Only its protected IPC consumer receives the returned session material. The AI
// receives a separate opaque broker context handle after the later import step.
//
// Certificate pins: Chromium's --ignore-certificate-errors-spki-list ADDS trust
// (a listed key is accepted despite hostname/expiry/chain errors); it does not
// restrict the connection to the pin. When pins are configured the flag is kept
// (a private service has no public CA chain) and this function additionally reads
// the certificate Chromium used through CDP Network.getCertificate and requires
// leaf SPKI == a configured pin AND hostname/IP match AND validity period
// (certificate-pins.mjs). CDP answers only for the origin of the document being
// shown, so the login origin (the only origin that receives the credential) is
// checked before anything is typed, and the application origin is checked after the
// login lands on it, before the session is published. The application origin is
// therefore not checked before the OAuth redirect first reaches it. Failure is the
// fixed login_failed before authentication and uncertain after. Without pins Chromium's normal CA
// validation applies and nothing is added.
//
// signal: an AbortSignal for cancellation (worker SIGTERM). Abort closes the browser
// so pending Playwright calls reject; the result is never a definite success.
export async function loginPrivate(configuration, credential, { launch, env = process.env, timeoutMs = MAX_HELPER_MS, signal } = {}) {
  if (['DEBUG', 'PWDEBUG', 'NODE_OPTIONS'].some((name) => env[name])) return { status: 'unsafe_configuration' };
  if (!['fixture', 'grafana-managed'].includes(configuration?.kind)) return { status: 'unsupported_authentication' };
  let recipe;
  try { recipe = compileRecipe(configuration); } catch { return { status: 'invalid_configuration' }; }
  if (credential?.account !== recipe.account) return { status: 'binding_mismatch' };
  if (typeof credential.password !== 'string' || credential.password.length < 8 || credential.password.length > 512
    || typeof launch !== 'function' || !Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > MAX_HELPER_MS) {
    return { status: 'invalid_configuration' };
  }
  if (signal?.aborted) return { status: 'login_failed' };
  let browser;
  let context;
  let authenticationStarted = false;
  let result;
  const started = performance.now();
  const originalMaximum = Date.now() + recipe.sessionMaxMs;
  const remaining = () => {
    if (signal?.aborted) throw new HelperFailure(authenticationStarted ? 'uncertain' : 'login_failed');
    const value = Math.floor(timeoutMs - (performance.now() - started));
    if (value <= 0) throw new HelperFailure(authenticationStarted ? 'uncertain' : 'timed_out');
    return value;
  };
  const abort = () => { void Promise.resolve(browser?.close()).catch(() => {}); };
  signal?.addEventListener('abort', abort, { once: true });
  const pinned = recipe.certificateSpkiPins.length > 0;
  try {
    browser = await launch({ headless: true, chromiumSandbox: true, timeout: remaining(),
      args: recipe.certificateSpkiPins.length ? [`--ignore-certificate-errors-spki-list=${recipe.certificateSpkiPins.join(',')}`] : [] });
    remaining();
    // Captures are absent before the first private navigation. Downloads and
    // service workers are disabled; no storage state or agent context is used.
    context = await browser.newContext({ acceptDownloads: false, serviceWorkers: 'block' });
    const page = await context.newPage();
    // Chromium Fetch pauses every redirect hop before network delivery. A
    // Playwright route alone follows redirects without invoking its filter again.
    const network = await context.newCDPSession(page);
    let networkFailed = false;
    network.on('Fetch.requestPaused', (event) => {
      let allowed = false;
      try { allowed = [recipe.origin, recipe.loginOrigin].includes(new URL(event.request.url).origin); } catch { /* deny */ }
      void network.send(allowed ? 'Fetch.continueRequest' : 'Fetch.failRequest', {
        requestId: event.requestId, ...(allowed ? {} : { errorReason: 'BlockedByClient' }),
      }).catch(() => { networkFailed = true; void page.close().catch(() => {}); });
    });
    await network.send('Fetch.enable', { patterns: [{ urlPattern: '*', requestStage: 'Request' }] });
    if (pinned) await network.send('Network.enable');
    // Reads the certificate Chromium actually used. CDP Network.getCertificate answers only for the origin
    // of the document Chromium currently shows, so each origin is checked while it is that document: the
    // login origin before the credential is typed, the application origin after the login lands on it.
    const verifyCertificate = async (origin, failure) => {
      try {
        const { tableNames } = await network.send('Network.getCertificate', { origin });
        verifyPinnedLeaf({ chain: tableNames, origin, pins: recipe.certificateSpkiPins });
      } catch { throw new HelperFailure(failure); }
    };
    await context.routeWebSocket('**/*', (socket) => socket.close());
    const loginPath = recipe.kind === 'fixture' ? '/login' : '/login/generic_oauth';
    await page.goto(`${recipe.origin}${loginPath}`, { timeout: remaining() });
    if (new URL(page.url()).origin !== recipe.loginOrigin) throw new HelperFailure('unsupported_authentication');
    if (pinned) await verifyCertificate(recipe.loginOrigin, 'login_failed');
    await page.getByLabel('Username', { exact: true }).fill(recipe.account, { timeout: remaining() });
    await page.getByLabel('Password', { exact: true }).fill(credential.password, { timeout: remaining() });
    const expectedPath = recipe.kind === 'fixture' ? '/login' : '/authorize';
    const response = page.waitForResponse((reply) => {
      const url = new URL(reply.url());
      return url.origin === recipe.loginOrigin && url.pathname === expectedPath && reply.request().method() === 'POST';
    }, { timeout: remaining() });
    // If click fails, consume the pending waiter rejection without exposing it.
    void response.catch(() => {});
    authenticationStarted = true;
    await page.getByRole('button', { name: 'Sign in', exact: true }).click({ timeout: remaining() });
    const reply = await response;
    if (reply.status() === 401) { authenticationStarted = false; throw new HelperFailure('authentication_failed'); }
    if (reply.status() !== (recipe.kind === 'fixture' ? 200 : 303)) throw new HelperFailure('uncertain');
    await page.waitForURL((url) => url.origin === recipe.origin && !url.pathname.startsWith('/login'), { timeout: remaining() });
    async function metadata(path) {
      const timeout = remaining();
      const value = await page.evaluate(async ({ path, timeout }) => {
        const response = await fetch(path, { redirect: 'error', signal: AbortSignal.timeout(timeout) });
        return { status: response.status, body: response.status === 200 ? await response.json() : null };
      }, { path, timeout });
      remaining();
      if (value.status !== 200) throw new HelperFailure('uncertain');
      return value.body;
    }
    let deadline = originalMaximum;
    let revokeHandle;
    if (recipe.kind === 'fixture') {
      const info = await metadata('/api/session');
      if (info.account !== recipe.account || info.role !== 'viewer' || !Number.isSafeInteger(info.expiresAt)
        || info.expiresAt <= Date.now() || !/^[a-f0-9]{32}$/.test(info.sessionReference ?? '')) throw new HelperFailure('uncertain');
      deadline = Math.min(deadline, info.expiresAt);
      revokeHandle = { kind: 'fixture', account: recipe.account, sessionReference: info.sessionReference };
    } else {
      const info = await metadata('/api/user');
      const orgs = await metadata('/api/user/orgs');
      if (info.login !== recipe.account || info.isGrafanaAdmin !== false || info.isExternal !== true
        || !Number.isSafeInteger(info.id) || info.id < 1 || info.orgId !== recipe.orgId
        || !Array.isArray(orgs) || orgs.length !== 1 || orgs[0].orgId !== recipe.orgId || orgs[0].role !== 'Viewer') {
        throw new HelperFailure('uncertain');
      }
      revokeHandle = { kind: 'grafana-managed', account: recipe.account, userId: info.id, orgId: recipe.orgId };
    }
    if (networkFailed) throw new HelperFailure('uncertain');
    if (pinned) await verifyCertificate(recipe.origin, 'uncertain');
    const cookies = selectSessionCookies(recipe, await context.cookies(recipe.origin), deadline);
    remaining();
    result = { status: 'authenticated', cookies, originalDeadlineMs: deadline, revokeHandle };
  } catch (error) {
    result = { status: error instanceof HelperFailure ? error.status : authenticationStarted ? 'uncertain' : 'login_failed' };
  } finally {
    signal?.removeEventListener('abort', abort);
    // Session material is not published until private contexts are closed. A
    // supervisor must still kill the verified cgroup on crash or a stuck close.
    try { await context?.close(); } catch { result = { status: authenticationStarted ? 'uncertain' : 'login_failed' }; }
    try { await browser?.close(); } catch { result = { status: authenticationStarted ? 'uncertain' : 'login_failed' }; }
  }
  return result;
}
