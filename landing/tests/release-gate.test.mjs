import assert from "node:assert/strict";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

// P07.5 landing gate: P07-D1 (GA4 removed), P07-D7 (six GitHub-bound CTAs), P07-I06 static half.
// The browser network and click evidence is recorded in docs/testing/evidence/p07-landing-2026-10-06.md.
const dist = fileURLToPath(new URL("../dist/", import.meta.url));
const repoRoot = fileURLToPath(new URL("../../", import.meta.url));
const html = readFileSync(join(dist, "index.html"), "utf8");
const llms = readFileSync(join(dist, "llms.txt"), "utf8");
const readme = readFileSync(new URL("../README.md", import.meta.url), "utf8");

const REPO = "https://github.com/atas-tech/blindpass";
const TEXT_EXTENSIONS = /\.(html|js|css|txt|svg|json|xml)$/;

function textFiles(directory) {
  return readdirSync(directory).flatMap((name) => {
    const path = join(directory, name);
    if (statSync(path).isDirectory()) return textFiles(path);
    return TEXT_EXTENSIONS.test(name) ? [path] : [];
  });
}

test("no analytics or tag-manager reference remains in any published text file", () => {
  const files = textFiles(dist);
  assert.ok(files.length >= 5, "the scan must cover index.html, script.js, reel.js, styles.css and llms.txt");
  for (const file of files) {
    const hit = readFileSync(file, "utf8").match(/googletagmanager|google-analytics|analytics\.google|gtag|dataLayer|\bG-[A-Z0-9]{8,12}\b|doubleclick/i);
    assert.equal(hit?.[0], undefined, `${file} still references a tracker`);
  }
});

test("the page requests nothing from another origin", () => {
  // Anchors are visitor-initiated navigation; every other URL-bearing attribute and every CSS url() is a request.
  const requests = [...html.matchAll(/<(?!a\b)[a-z]+\b[^>]*?\b(?:src|href|poster|data|action)="(https?:)?\/\/[^"]+"/gi)].map((match) => match[0]);
  // Canonical, hreflang and og:* values are metadata, not fetches.
  const fetched = requests.filter((tag) => !/rel="canonical"|<meta\b/i.test(tag));
  assert.deepEqual(fetched, [], "no script, stylesheet, image, media or font may load from another origin");
  assert.equal(html.match(/rel="(?:preconnect|dns-prefetch|prefetch|prerender)"/i)?.[0], undefined, "no connection hints to other origins");
  for (const file of textFiles(dist).filter((path) => /\.(css|js)$/.test(path))) {
    const source = readFileSync(file, "utf8");
    assert.equal(source.match(/url\(\s*["']?(?:https?:)?\/\//i)?.[0], undefined, `${file} fetches a remote asset from CSS`);
    assert.equal(source.match(/\b(?:fetch|XMLHttpRequest|sendBeacon|WebSocket|EventSource|importScripts)\b/)?.[0], undefined, `${file} makes a network call`);
  }
  assert.equal(html.match(/<iframe\b/i)?.[0], undefined, "no embedded third-party frames");
});

test("the page and its scripts keep nothing in cookies or browser storage", () => {
  for (const file of textFiles(dist).filter((path) => path.endsWith(".js"))) {
    assert.equal(readFileSync(file, "utf8").match(/document\.cookie|localStorage|sessionStorage|indexedDB/)?.[0], undefined, `${file} stores data in the browser`);
  }
});

// P07-D7 placement table. `pending` rows depend on a release tag that does not exist yet; they keep their current honest
// target and stay blocked on P07.6. They must never carry a placeholder tag.
const CTAS = [
  { placement: "desktop nav “View on GitHub”", pattern: /<a class="header-cta" href="([^"]+)">View on GitHub/, href: REPO },
  { placement: "mobile nav “View on GitHub”", pattern: /<nav id="mobile-nav"[^>]*>[\s\S]*?<a href="([^"]+)">View on GitHub/, href: REPO },
  { placement: "hero “Read the docs”", pattern: /<a class="text-link" href="([^"]+)">Read the docs/, href: `${REPO}#readme`, pending: true },
  { placement: "closing “Explore BlindPass”", pattern: /<a class="button button-primary" href="([^"]+)">Explore BlindPass/, href: REPO, pending: true },
  { placement: "footer “GitHub”", pattern: /<footer[\s\S]*?<a href="([^"]+)">GitHub/, href: REPO },
  { placement: "footer “Security”", pattern: /<footer[\s\S]*?<a href="([^"]+)">Security/, href: `${REPO}/blob/main/SECURITY.md` }
];

test("the six GitHub-bound CTAs point where P07-D7 says", () => {
  for (const cta of CTAS) {
    const found = html.match(cta.pattern)?.[1];
    assert.equal(found, cta.href, `${cta.placement}${cta.pending ? " (tag-dependent, interim target)" : ""}`);
  }
});

test("exactly six external anchors exist and none carries a placeholder tag", () => {
  const external = [...html.matchAll(/<a\b[^>]*\bhref="(https?:\/\/[^"]+)"/g)].map((match) => match[1]);
  assert.equal(external.length, 6, `unexpected external anchors: ${external.join(", ")}`);
  for (const href of [...external, ...llms.match(/https?:\/\/\S+/g)]) {
    assert.doesNotMatch(href, /\/(?:blob|tree|releases\/tag)\/(?:v?0\.x|v?X|TAG|\{|<)/i, `placeholder tag in ${href}`);
  }
});

test("every repository link on the page and in llms.txt resolves to a file or directory in this tree", () => {
  const links = [...html.matchAll(/href="(https:\/\/github\.com\/atas-tech\/blindpass\/(?:blob|tree)\/main\/[^"#]+)/g), ...llms.matchAll(/(https:\/\/github\.com\/atas-tech\/blindpass\/(?:blob|tree)\/main\/[^\s)#]+)/g)];
  assert.ok(links.length >= 5);
  for (const [, link] of links) {
    const path = link.replace(`${REPO}/`, "").replace(/^(?:blob|tree)\/main\//, "");
    assert.ok(existsSync(join(repoRoot, path)), `${link} has no ${path} in the repository`);
  }
});

test("SECURITY.md exists, states supported versions honestly and points at the threat model", () => {
  const policy = readFileSync(join(repoRoot, "SECURITY.md"), "utf8");
  assert.match(policy, /^# Security policy/m);
  assert.match(policy, /## Supported versions/);
  assert.match(policy, /## Reporting a vulnerability/);
  assert.match(policy, /docs\/security\/blindpass-threat-model\.md/);
  assert.doesNotMatch(policy, /[\w.+-]+@[\w-]+\.[\w.-]+/, "no contact address may be invented; the channel is an owner decision");
});

test("README and llms.txt record the GA4 disposition without claiming the host collects nothing", () => {
  const analytics = readme.match(/## Analytics\n([\s\S]*?)\n## /)?.[1] ?? "";
  assert.match(analytics, /GA4 (?:was )?removed/i);
  assert.match(analytics, /GitHub Pages/);
  assert.match(analytics, /not verified|cannot verify|unverified/i, "the host's own logging must be stated as unverified, not as absent");
  assert.doesNotMatch(analytics, /loads Google Analytics 4|only third-party request/);
  assert.doesNotMatch(readme, /GA4 consent\s*\|/, "the consent decision is moot once the tag is gone");
  assert.match(llms, /no analytics/i);
  assert.match(llms, /GitHub Pages/);
  assert.doesNotMatch(llms, /collects nothing|no data is collected|zero data/i);
});
