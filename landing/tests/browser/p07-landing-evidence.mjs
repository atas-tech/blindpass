// P07-I06 / P07-E04 browser evidence for the landing page. Not part of `npm run test:landing`: it needs a browser
// and, for the CTA click-through, real network access to github.com. Run from the repository root:
//
//   node landing/tests/browser/p07-landing-evidence.mjs <output-directory>
//
// It serves landing/dist from a throwaway loopback server, loads it in a fresh browser context per viewport and
// records every request, cookie and storage key; then clicks each CTA and anchor and records where it landed. Raw HARs
// (content omitted) and the JSON summary go to <output-directory>; nothing is written into the repository.
import { chromium } from "@playwright/test";
import { createServer } from "node:http";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";

const out = process.argv[2];
if (!out) throw new Error("usage: p07-landing-evidence.mjs <output-directory>");
mkdirSync(out, { recursive: true });

const dist = fileURLToPath(new URL("../../dist/", import.meta.url));
const MIME = { ".html": "text/html; charset=utf-8", ".css": "text/css", ".js": "text/javascript", ".txt": "text/plain", ".svg": "image/svg+xml", ".woff2": "font/woff2", ".mp4": "video/mp4", ".jpg": "image/jpeg" };

const server = createServer((request, response) => {
  const path = normalize(decodeURIComponent(new URL(request.url, "http://x").pathname)).replace(/^(\.\.[/\\])+/, "");
  let file = join(dist, path.endsWith("/") ? `${path}index.html` : path);
  if (!existsSync(file)) { response.writeHead(404).end("not found"); return; }
  const body = readFileSync(file);
  const range = /bytes=(\d+)-(\d*)/.exec(request.headers.range ?? "");
  const headers = { "content-type": MIME[extname(file)] ?? "application/octet-stream", "cache-control": "no-store", "accept-ranges": "bytes" };
  if (range) {
    const start = Number(range[1]);
    const end = range[2] ? Number(range[2]) : body.length - 1;
    response.writeHead(206, { ...headers, "content-range": `bytes ${start}-${end}/${body.length}`, "content-length": end - start + 1 }).end(body.subarray(start, end + 1));
  } else {
    response.writeHead(200, { ...headers, "content-length": body.length }).end(body);
  }
});
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const origin = `http://127.0.0.1:${server.address().port}`;

const executablePath = existsSync("/usr/bin/chromium") ? "/usr/bin/chromium" : undefined;
const browser = await chromium.launch({ executablePath });
const VIEWPORTS = [
  { name: "desktop", options: { viewport: { width: 1440, height: 900 } } },
  { name: "mobile", options: { viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true, deviceScaleFactor: 2 } }
];
const EXTERNAL = [
  { placement: "desktop nav “View on GitHub”", selector: ".header-cta" },
  { placement: "mobile nav “View on GitHub”", selector: "#mobile-nav a[href^='https://']", needsMenu: true },
  { placement: "hero “Read the docs”", selector: ".hero-actions a.text-link" },
  { placement: "closing “Explore BlindPass”", selector: ".closing-action a" },
  { placement: "footer “GitHub”", selector: ".site-footer a:has-text('GitHub')" },
  { placement: "footer “Security”", selector: ".site-footer a:has-text('Security')" }
];

const summary = { date: new Date().toISOString(), browser: browser.version(), executable: executablePath ?? "playwright bundled", origin: "http://127.0.0.1:<ephemeral>", viewports: {} };

for (const viewport of VIEWPORTS) {
  const result = { load: {}, ctas: [], anchors: [] };
  // 1. Fresh profile: load, scroll the whole page, record everything the browser did.
  {
    const context = await browser.newContext({ ...viewport.options, recordHar: { path: join(out, `p07-landing-${viewport.name}.har`), content: "omit" }, serviceWorkers: "block" });
    const page = await context.newPage();
    const requests = [];
    const failed = [];
    const consoleErrors = [];
    page.on("request", (request) => requests.push({ url: request.url(), type: request.resourceType() }));
    page.on("requestfailed", (request) => failed.push({ url: request.url(), error: request.failure()?.errorText }));
    page.on("console", (message) => { if (["error", "warning"].includes(message.type())) consoleErrors.push(message.text()); });
    page.on("pageerror", (error) => consoleErrors.push(`pageerror: ${error.message}`));
    await page.goto(origin, { waitUntil: "networkidle" });
    const height = await page.evaluate(() => document.documentElement.scrollHeight);
    for (let y = 0; y <= height; y += 300) { await page.evaluate((top) => window.scrollTo(0, top), y); await page.waitForTimeout(60); }
    await page.waitForTimeout(500);
    const state = await page.evaluate(async () => ({
      cookie: document.cookie,
      localStorageKeys: Object.keys(localStorage),
      sessionStorageKeys: Object.keys(sessionStorage),
      indexedDb: (await indexedDB.databases?.())?.map((db) => db.name) ?? [],
      scripts: [...document.scripts].map((script) => script.src || "inline"),
      inlineScripts: [...document.scripts].filter((script) => !script.src).length,
      consentUi: [...document.querySelectorAll("body *")].filter((el) => /cookie|consent|gdpr|accept all/i.test(`${el.id} ${el.className} ${el.getAttribute("aria-label") ?? ""}`)).length,
      canonical: document.querySelector("link[rel=canonical]")?.href,
      ogUrl: document.querySelector("meta[property='og:url']")?.content,
      ogImage: document.querySelector("meta[property='og:image']")?.content,
      diagramLabel: document.querySelector("[role=img]")?.getAttribute("aria-label")?.slice(0, 60),
      overflow: { scrollWidth: document.documentElement.scrollWidth, innerWidth: window.innerWidth },
      title: document.title
    }));
    const cookies = await context.cookies();
    const origins = [...new Set(requests.map((request) => new URL(request.url).origin))];
    const thirdParty = requests.filter((request) => new URL(request.url).origin !== origin);
    result.load = {
      requestCount: requests.length,
      origins: origins.map((value) => (value === origin ? "same-origin (loopback)" : value)),
      thirdPartyRequests: thirdParty,
      trackerRequests: requests.filter((request) => /googletagmanager|google-analytics|analytics\.google|doubleclick/i.test(request.url)),
      byType: Object.fromEntries([...new Set(requests.map((request) => request.type))].map((type) => [type, requests.filter((request) => request.type === type).length])),
      mediaRequestedAfterScroll: requests.some((request) => request.url.endsWith(".mp4")),
      failed, consoleErrors, cookies: cookies.map((cookie) => cookie.name), ...state
    };
    if (viewport.name === "mobile") await page.screenshot({ path: join(out, "p07-landing-mobile.png"), fullPage: false });
    else await page.screenshot({ path: join(out, "p07-landing-desktop.png"), fullPage: false });
    await context.close();
  }

  // 2. Six external CTAs, one fresh page each; mobile-nav links are reached through the menu button.
  for (const cta of EXTERNAL) {
    const context = await browser.newContext({ ...viewport.options, serviceWorkers: "block" });
    const page = await context.newPage();
    await page.goto(origin, { waitUntil: "networkidle" });
    const row = { placement: cta.placement };
    let locator = page.locator(cta.selector).first();
    row.visibleWithoutMenu = await locator.isVisible();
    row.href = await locator.getAttribute("href");
    if (cta.needsMenu && !row.visibleWithoutMenu) {
      const toggle = page.locator(".menu-toggle");
      if (await toggle.isVisible()) {
        await toggle.click();
        row.menuExpanded = await toggle.getAttribute("aria-expanded");
        row.visibleAfterMenu = await locator.isVisible();
      } else row.menuButtonVisible = false;
    }
    if (await locator.isVisible()) {
      const chain = [];
      page.on("response", (response) => { if (response.request().isNavigationRequest() && response.frame() === page.mainFrame()) chain.push({ status: response.status(), url: response.url() }); });
      try {
        await Promise.all([page.waitForURL((url) => url.origin !== origin, { timeout: 30_000, waitUntil: "domcontentloaded" }), locator.click()]);
        await page.waitForLoadState("domcontentloaded");
        row.clicked = true;
        row.finalUrl = page.url();
        row.finalStatus = chain.at(-1)?.status ?? null;
        row.chain = chain;
        row.title = (await page.title()).slice(0, 80);
      } catch (error) {
        row.clicked = true;
        row.error = String(error.message).split("\n")[0];
        row.chain = chain;
      }
    } else row.clicked = false;
    result.ctas.push(row);
    await context.close();
  }

  // 3. Internal anchors: every in-page link that is visible (the mobile ones through the menu button).
  {
    const context = await browser.newContext({ ...viewport.options, serviceWorkers: "block" });
    const page = await context.newPage();
    await page.goto(origin, { waitUntil: "networkidle" });
    const hrefs = await page.evaluate(() => [...new Set([...document.querySelectorAll("a[href^='#']")].map((a) => a.getAttribute("href")).filter((href) => href.length > 1))]);
    const labels = await page.evaluate(() => [...document.querySelectorAll("a[href^='#']")].filter((a) => a.getAttribute("href").length > 1).map((a) => ({ href: a.getAttribute("href"), text: a.textContent.trim().replace(/\s+/g, " ").slice(0, 40), nav: a.closest("nav")?.id || a.closest("nav")?.getAttribute("aria-label") || a.closest("section")?.id || a.closest("section")?.className.split(" ")[0] || "page" })));
    for (const entry of labels) {
      await page.goto(`${origin}/`, { waitUntil: "load" });
      const scope = entry.nav === "mobile-nav" ? "#mobile-nav " : "";
      const link = page.locator(`${scope}a[href='${entry.href}']`).filter({ hasText: entry.text.replace(/\s*[↗→]\s*$/, "") }).first();
      const row = { ...entry, targetExists: await page.locator(entry.href).count() === 1 };
      if (scope && !(await link.isVisible())) {
        const toggle = page.locator(".menu-toggle");
        if (await toggle.isVisible()) await toggle.click();
      }
      row.visible = await link.isVisible();
      row.skipLink = (await link.getAttribute("class"))?.includes("skip-link") ?? false;
      if (row.visible) {
        try {
          // The skip link is off-screen until it takes keyboard focus, so it is activated from the keyboard.
          if (row.skipLink) { await link.focus(); await page.keyboard.press("Enter"); } else await link.click({ timeout: 8_000 });
        } catch (error) { row.error = String(error.message).split("\n")[0]; }
        await page.waitForTimeout(900);
        row.hash = new URL(page.url()).hash;
        row.targetTop = await page.evaluate((selector) => Math.round(document.querySelector(selector).getBoundingClientRect().top), entry.href);
        row.landed = row.hash === entry.href && row.targetTop < viewport.options.viewport.height && row.targetTop > -400;
      }
      result.anchors.push(row);
    }
    result.anchorTargets = hrefs;
    await context.close();
  }
  summary.viewports[viewport.name] = result;
}

await browser.close();
server.close();
writeFileSync(join(out, "p07-landing-summary.json"), `${JSON.stringify(summary, null, 2)}\n`);
console.log(`wrote ${join(out, "p07-landing-summary.json")}`);
