#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-only
// P06 stock-browser check against a packaged controller: real Chromium signs in to the embedded console over
// verified HTTPS, reads the node list and the approvals page, signs out through the UI and proves the old
// session cookie is dead. Configuration comes from the environment so no credential reaches argv or output:
//   P06_CONSOLE_URL        https://p03-controller:8443
//   P06_CONSOLE_RESOLVE    host:ip:port pair mapping the name to the forwarded listener, e.g. 127.0.0.1:8443
//   P06_CONSOLE_SPKI       base64 SHA-256 of the served leaf certificate public key (trusted instead of disabling verification)
//   P06_CONSOLE_USER / P06_CONSOLE_PASSWORD
//   P06_CONSOLE_NODE_ID    node id that must be listed as online
//   BLINDPASS_PLAYWRIGHT_EXECUTABLE_PATH  optional Chromium binary
import { chromium } from "@playwright/test";

const need = (name) => {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
};
const url = need("P06_CONSOLE_URL");
const [resolveIp, resolvePort] = need("P06_CONSOLE_RESOLVE").split(":");
const spki = need("P06_CONSOLE_SPKI");
const user = need("P06_CONSOLE_USER");
const password = need("P06_CONSOLE_PASSWORD");
const nodeId = need("P06_CONSOLE_NODE_ID");
const origin = new URL(url);

const browser = await chromium.launch({
  executablePath: process.env.BLINDPASS_PLAYWRIGHT_EXECUTABLE_PATH || undefined,
  args: [`--host-resolver-rules=MAP ${origin.hostname} ${resolveIp}:${resolvePort}`, `--ignore-certificate-errors-spki-list=${spki}`]
});
const problems = [];
const steps = [];
try {
  const context = await browser.newContext({ baseURL: url });
  await context.addInitScript(() => {
    window.__csp = [];
    document.addEventListener("securitypolicyviolation", (event) => window.__csp.push(`${event.violatedDirective} ${event.blockedURI}`));
  });
  const page = await context.newPage();
  const foreign = new Set();
  page.on("request", (request) => {
    const target = new URL(request.url());
    if (!["data:", "blob:"].includes(target.protocol) && target.origin !== origin.origin) foreign.add(target.origin);
  });
  page.on("pageerror", (error) => problems.push(`script error: ${error.message.slice(0, 80)}`));

  await page.goto("/login");
  await page.getByLabel("Username").fill(user);
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.waitForURL((u) => !u.pathname.startsWith("/login"), { timeout: 20000 });
  steps.push("sign-in");

  const response = await page.goto("/nodes");
  if (!response || response.status() !== 200) problems.push(`/nodes shell answered ${response && response.status()}`);
  await page.getByText(nodeId, { exact: false }).first().waitFor({ timeout: 20000 });
  const row = page.locator("tr, li, article", { hasText: nodeId }).first();
  const rowText = (await row.innerText()).toLowerCase();
  if (!rowText.includes("online")) problems.push("the node row does not show online");
  steps.push("nodes-online");

  const approvals = await page.goto("/approvals");
  if (!approvals || approvals.status() !== 200) problems.push(`/approvals shell answered ${approvals && approvals.status()}`);
  await page.getByRole("heading").first().waitFor({ timeout: 20000 });
  steps.push("approvals");

  const violations = await page.evaluate(() => window.__csp);
  if (violations.length) problems.push(`CSP violations: ${violations.length}`);
  if (foreign.size) problems.push(`requests left the controller origin (${foreign.size})`);

  const sessionCookies = (await context.cookies()).filter((cookie) => cookie.name !== "bp_csrf");
  await page.getByRole("button", { name: "Sign out" }).click();
  await page.waitForURL((u) => u.pathname.startsWith("/login"), { timeout: 20000 });
  steps.push("sign-out");
  // Requests go through the page so they use Chromium's own resolver and trust settings.
  const nodesStatus = (target) => target.evaluate(async () => (await fetch("/api/v3/nodes?limit=1", { credentials: "include" })).status);
  const afterApi = await nodesStatus(page);
  if (afterApi !== 401 && afterApi !== 403) problems.push(`the signed-out context still reads nodes (${afterApi})`);
  await page.goto("/nodes");
  // The console redirects client-side once its session probe is refused.
  await page.waitForURL((u) => u.pathname.startsWith("/login"), { timeout: 15000 }).catch(() => problems.push("a signed-out visit to /nodes did not return to /login"));
  const replay = await browser.newContext({ baseURL: url });
  await replay.addCookies(sessionCookies);
  const replayPage = await replay.newPage();
  await replayPage.goto("/login");
  const replayed = await nodesStatus(replayPage);
  if (replayed === 200) problems.push("the old session cookie still works after sign-out");
  steps.push("cookie-replay-dead");
} finally {
  await browser.close();
}
if (problems.length) {
  console.log(`P06-BROWSER FAIL ${problems.join("; ")} (steps ${steps.join(",")})`);
  process.exit(1);
}
console.log(`P06-BROWSER PASS ${steps.join(",")}`);
