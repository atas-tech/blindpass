// SPDX-License-Identifier: MIT
// Source-level guards for the fleet-mode input page. They don't run the page (the
// Playwright specs under packages/console/e2e do); they pin the rules that must
// hold in every build: the unverified sealing helper is unreachable from the page,
// credentials are omitted everywhere except the fleet flow, no Source or cookie
// can reach storage, the console or an inline script, and the CSP rules stand.
import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";

const code = (text) => text.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
const read = (name) => readFile(new URL(`../${name}`, import.meta.url), "utf8");
const [app, flow, html, i18n, lifecycle, provisioning] = await Promise.all(["src/app.js", "src/fleet-flow.js", "index.html", "src/i18n.js", "src/lifecycle.js", "src/fleet-provisioning.js"].map(read));

test("P05-PV06-S GUI: the page can only seal through the verified path, with the server's time", () => {
  assert.ok(!/sealBrowserSource\b/.test(app), "app.js never names the unverified sealer");
  assert.ok(!/sealBrowserSource\b/.test(flow), "the flow never names the unverified sealer");
  assert.match(flow, /sealVerifiedBrowserSource/);
  assert.match(flow, /verifyBrowserRecipientOffer/);
  assert.ok(!/Date\.now\(\)/.test(flow), "the flow never reads the browser clock itself");
  assert.ok(!/from "\.\/fleet-provisioning\.js"/.test(app), "app.js reaches the sealer only through fleet-flow.js");
  // The helper still exports the lower-level sealer for the crypto tests.
  assert.match(provisioning, /export async function sealBrowserSource/);
});

test("P05-PV06-S GUI: legacy calls omit credentials and only the fleet flow sends the operator cookie, same origin", () => {
  assert.equal([...app.matchAll(/credentials:/g)].length, 1);
  assert.match(app, /credentials: "omit", \.\.\.init/);
  assert.ok(!/same-origin/.test(code(app)), "app.js code never opts in to cookies itself");
  assert.match(flow, /credentials: "same-origin"/);
  assert.ok(!/credentials: "include"/.test(app + flow), "cookies are never sent cross-origin");
  assert.match(flow, /redirect: "error"/);
});

test("P05-PV06-S GUI: no Source, cookie or capability reaches storage, history, the console or the URL", () => {
  for (const [name, text] of [["app.js", app], ["fleet-flow.js", flow], ["lifecycle.js", lifecycle]]) {
    assert.ok(!/\bconsole\./.test(text), `${name} writes nothing to the console`);
    assert.ok(!/sessionStorage|indexedDB|document\.cookie\s*=/.test(text), `${name} stores nothing`);
    assert.ok(!/history\.(push|replace)State/.test(text), `${name} never rewrites the address`);
    assert.ok(!/localStorage\.setItem/.test(text), `${name} never stores a value`);
  }
  // Locale preference is the only thing the page ever stores.
  assert.equal([...i18n.matchAll(/localStorage\??\.setItem\(([^,]+),/g)].map((match) => match[1].trim()).join(), "LOCALE_STORAGE_KEY");
  // The CSRF value is read from its cookie and goes only into a header.
  assert.match(flow, /"x-csrf-token": token/);
  assert.ok(!/csrf/i.test(code(flow).replace(/"x-csrf-token": token|csrfToken/g, "")));
  // Paths carry only the encoded id and capability.
  assert.match(flow, /\/api\/v3\/fleet\/provisioning\/\$\{id\}\/metadata\?sig=\$\{encodeURIComponent\(ctx\.metadataSig\)\}/);
  assert.match(flow, /\/api\/v3\/fleet\/provisioning\/\$\{id\}\/submit\?sig=\$\{encodeURIComponent\(ctx\.submitSig\)\}/);
});

test("P05-PV06-S GUI: the typed value is cleared on every terminal state, a hidden page and unload", () => {
  assert.match(app, /if \(TERMINAL_STATES\.has\(state\)\) \{\s*clearValues\(\);/);
  assert.match(app, /if \(fleet && page\.state === "ready"\) \{\s*clearValues\(\);/);
  assert.match(app, /addEventListener\("pagehide", \(\) => \{\s*clearValues\(\);/);
  // The flow holds the value only as a function argument.
  assert.ok(!/this\.|\bvalue\s*=\s*[^=]/.test(flow.replace(/const value = /g, "")), "the flow never assigns or stores the value");
});

test("P04-E03: the page keeps the CSP rules: no inline script, handler or style", () => {
  assert.ok(!/<script(?![^>]*\bsrc=)[^>]*>/.test(html), "only external module scripts");
  assert.ok(!/<style[\s>]/.test(html), "no style element");
  assert.ok(!/\sstyle=/.test(html), "no style attribute");
  assert.ok(!/\son[a-z]+=/i.test(html.replace(/data-[a-z-]+="[^"]*"/g, "")), "no inline event handler");
  assert.ok(!/javascript:/i.test(html + app), "no javascript: URL");
  assert.match(html, /id="outcome-link"[^>]*rel="noopener noreferrer"/);
  // The sign-in link is a fixed path: never built from the link's capabilities.
  assert.match(app, /ui\.link\.href = "\/login"/);
});

test("P05-PV06-S GUI: fleet-only copy never repeats a legacy string, so the page has no ambiguous text in either mode", async () => {
  const strings = async (locale) => JSON.parse(await readFile(new URL(`../../i18n/locales/${locale}/browser-ui.json`, import.meta.url), "utf8"));
  const flat = (value, prefix = "") => Object.entries(value).flatMap(([key, entry]) => (typeof entry === "string" ? [[`${prefix}${key}`, entry]] : flat(entry, `${prefix}${key}.`)));
  // Keys that appear in the markup only through data-i18n="fleet.*" (not swapped in place of a legacy key).
  const fleetOnly = [...html.matchAll(/<[^>]*\sdata-i18n="(fleet\.[^"]+)"[^>]*>/g)].filter((match) => !/data-i18n-fleet=/.test(match[0])).map((match) => match[1]);
  assert.ok(fleetOnly.length >= 7, "the fleet summary has its own labelled fields");
  for (const locale of ["en", "vi"]) {
    const all = flat(await strings(locale));
    const legacy = new Map(all.filter(([key]) => !key.startsWith("fleet.")).map(([key, text]) => [text, key]));
    for (const key of fleetOnly) {
      const text = all.find(([name]) => name === key)?.[1];
      assert.ok(text, `${locale} has ${key}`);
      assert.ok(!legacy.has(text), `${locale} ${key} repeats the legacy string ${legacy.get(text)}`);
    }
  }
});
