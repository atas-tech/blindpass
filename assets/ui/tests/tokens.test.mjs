// Contract tests for the shared design tokens (P04-I01, DR-E07 computed contrast).
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const css = await readFile(path.join(root, "tokens.css"), "utf8");

function tokens() {
  const values = new Map();
  const block = css.slice(css.indexOf(":root {"), css.indexOf("}", css.indexOf(":root {")));
  for (const match of block.matchAll(/(--bp-[a-z0-9-]+):\s*([^;]+);/g)) {
    values.set(match[1], match[2].trim());
  }
  return values;
}

function luminance(hex) {
  const value = Number.parseInt(hex.slice(1), 16);
  return [value >> 16, (value >> 8) & 255, value & 255]
    .map((channel) => {
      const c = channel / 255;
      return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
    })
    .reduce((sum, c, index) => sum + c * [0.2126, 0.7152, 0.0722][index], 0);
}

function contrast(a, b) {
  const [x, y] = [luminance(a), luminance(b)];
  return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05);
}

const map = tokens();
const color = (name) => {
  const value = map.get(`--bp-color-${name}`);
  assert.match(value ?? "", /^#[0-9a-f]{6}$/i, `--bp-color-${name} must be a six-digit hex colour`);
  return value;
};

const SURFACES = ["sunken", "bg", "panel", "raised", "overlay"];

test("body and secondary text reach 4.5:1 on every surface", () => {
  for (const text of ["ink", "ink-soft", "muted", "dim", "lime", "ok", "warn", "danger", "info", "neutral"]) {
    for (const surface of SURFACES) {
      const ratio = contrast(color(text), color(surface));
      assert.ok(ratio >= 4.5, `${text} on ${surface} is ${ratio.toFixed(2)}:1`);
    }
  }
});

test("control boundaries reach 3:1 against every surface (WCAG 1.4.11)", () => {
  for (const surface of SURFACES) {
    const ratio = contrast(color("control"), color(surface));
    assert.ok(ratio >= 3, `control on ${surface} is ${ratio.toFixed(2)}:1`);
  }
});

test("the divider is never mistaken for a control boundary", () => {
  assert.ok(contrast(color("line"), color("bg")) < 3, "line is decorative; controls must use --bp-color-control");
});

test("status text reaches 4.5:1 on its own tinted background", () => {
  const pairs = [["ok", "ok-soft"], ["lime", "lime-soft"], ["warn", "warn-soft"], ["danger", "danger-soft"], ["info", "info-soft"], ["neutral", "neutral-soft"], ["ink", "lime-soft"], ["muted", "lime-soft"], ["danger-strong", "danger-hover"]];
  for (const [text, background] of pairs) {
    const ratio = contrast(color(text), color(background));
    assert.ok(ratio >= 4.5, `${text} on ${background} is ${ratio.toFixed(2)}:1`);
  }
});

test("primary action text is readable on lime at rest and on hover", () => {
  assert.ok(contrast(color("lime-ink"), color("lime")) >= 4.5);
  assert.ok(contrast(color("lime-ink"), color("lime-strong")) >= 4.5);
});

test("the focus ring is visible against the page background", () => {
  assert.ok(contrast(color("lime"), color("bg")) >= 3);
  assert.ok(contrast(color("lime"), color("panel")) >= 3);
});

test("coarse pointer targets are at least 44 CSS px", () => {
  assert.equal(map.get("--bp-target-coarse"), "2.75rem");
});

test("reduced motion collapses every duration token", () => {
  const reduced = css.slice(css.indexOf("prefers-reduced-motion"));
  for (const name of ["fast", "base", "slow"]) {
    assert.match(reduced, new RegExp(`--bp-duration-${name}: 0ms`));
  }
});

test("tokens and fonts load nothing from a third-party origin", async () => {
  const fonts = await readFile(path.join(root, "fonts.css"), "utf8");
  for (const source of [css, fonts]) {
    assert.doesNotMatch(source, /https?:\/\//, "no absolute URLs in shared UI assets");
    assert.doesNotMatch(source, /@import/, "no nested imports");
  }
  assert.match(fonts, /url\("\.\/fonts\/InterVariable\.woff2"\)/);
});
