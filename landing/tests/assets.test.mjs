import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const html = readFileSync(new URL("../dist/index.html", import.meta.url), "utf8");

// Pages serves each file with max-age=600. If a stylesheet or script keeps its URL across a deploy,
// a browser can pair new HTML with the old cached file; the reel then rendered at 1600px and broke the layout.
test("stylesheet and scripts are versioned by their current content", () => {
  for (const file of ["styles.css", "script.js", "reel.js"]) {
    const hash = createHash("sha256").update(readFileSync(new URL(`../dist/${file}`, import.meta.url))).digest("hex").slice(0, 8);
    const refs = [...html.matchAll(new RegExp(`(?:href|src)="${file.replace(".", "\\.")}(\\?v=[0-9a-f]{8})?"`, "g"))];
    assert.equal(refs.length, 1, `${file} should be referenced exactly once`);
    assert.equal(refs[0][1], `?v=${hash}`, `${file} changed: set its reference to ${file}?v=${hash}`);
  }
});

test("shared UI stylesheets are versioned and match assets/ui", () => {
  for (const file of ["assets/ui/fonts.css", "assets/ui/tokens.css"]) {
    const bytes = readFileSync(new URL(`../dist/${file}`, import.meta.url));
    assert.ok(bytes.equals(readFileSync(new URL(`../../${file}`, import.meta.url))), `${file} differs from the shared source; run node scripts/sync-ui-assets.mjs`);
    const hash = createHash("sha256").update(bytes).digest("hex").slice(0, 8);
    const refs = [...html.matchAll(new RegExp(`href="${file.replaceAll(".", "\\.")}(\\?v=[0-9a-f]{8})?"`, "g"))];
    assert.equal(refs.length, 1, `${file} should be referenced exactly once`);
    assert.equal(refs[0][1], `?v=${hash}`, `${file} changed: set its reference to ${file}?v=${hash}`);
  }
  const font = readFileSync(new URL("../dist/assets/ui/fonts/InterVariable.woff2", import.meta.url));
  assert.ok(font.equals(readFileSync(new URL("../../assets/ui/fonts/InterVariable.woff2", import.meta.url))), "landing font differs from assets/ui");
  assert.match(html, /<link rel="preload" href="assets\/ui\/fonts\/InterVariable\.woff2" as="font" type="font\/woff2" crossorigin>/);
});

test("the landing stylesheet takes its palette from the shared tokens", () => {
  const styles = readFileSync(new URL("../dist/styles.css", import.meta.url), "utf8");
  assert.doesNotMatch(styles, /@font-face/, "the font face lives in assets/ui/fonts.css");
  const root = styles.match(/:root\{([^}]*)\}/)?.[1] ?? "";
  for (const alias of ["--bg", "--panel", "--ink", "--muted", "--dim", "--lime", "--line"]) {
    assert.match(root, new RegExp(`${alias}:var\\(--bp-`), `${alias} must alias a --bp- token`);
  }
  assert.doesNotMatch(styles, /fonts\.googleapis|fonts\.gstatic|unpkg|jsdelivr/);
});
