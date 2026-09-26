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
