import assert from "node:assert/strict";
import test from "node:test";
import { revealControls } from "../src/display-text.js";

test("O05 / SI-E01: bidi overrides, terminal escapes and zero-width characters in a description are shown, not applied", () => {
  assert.equal(revealControls("pay\u202Egpj.exe"), "pay⟨U+202E⟩gpj.exe");
  assert.equal(revealControls("\u001b[31mred\u001b[0m"), "⟨U+001B⟩[31mred⟨U+001B⟩[0m");
  assert.equal(revealControls("a\u200Bb\u2066c\u2069d\uFEFF\u0000\u007F\u0085"), "a⟨U+200B⟩b⟨U+2066⟩c⟨U+2069⟩d⟨U+FEFF⟩⟨U+0000⟩⟨U+007F⟩⟨U+0085⟩");
  const plain = "Thông tin 漢 🔑\n\tsecond line — ok";
  assert.equal(revealControls(plain), plain);
});
