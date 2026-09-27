import { describe, expect, it } from "vitest";
import { formatCountdown, formatDurationSeconds, groupFingerprint, normalizeFingerprint, revealControls, toMs } from "./format.js";
import { safeReturnPath } from "./routing.js";

describe("format", () => {
  it("O05: shows invisible control, bidi and zero-width characters in untrusted text as visible code points", () => {
    expect(revealControls("pay\u202Egpj.exe")).toBe("pay⟨U+202E⟩gpj.exe");
    expect(revealControls("\u001b[31mred\u001b[0m")).toBe("⟨U+001B⟩[31mred⟨U+001B⟩[0m");
    expect(revealControls("a\u200Bb\u2066c\u2069d\uFEFF\u0000\u007F\u0085")).toBe("a⟨U+200B⟩b⟨U+2066⟩c⟨U+2069⟩d⟨U+FEFF⟩⟨U+0000⟩⟨U+007F⟩⟨U+0085⟩");
    // Line breaks, tabs and ordinary non-ASCII text are left as written.
    const plain = "Thông tin 漢 🔑\n\tsecond line — ok";
    expect(revealControls(plain)).toBe(plain);
  });

  it("normalises controller timestamps in seconds, milliseconds and ISO form", () => {
    expect(toMs(1_790_000_000)).toBe(1_790_000_000_000);
    expect(toMs(1_790_000_000_123)).toBe(1_790_000_000_123);
    expect(toMs("2026-09-27T12:00:00.000Z")).toBe(Date.UTC(2026, 8, 27, 12));
    expect(toMs("1790000000")).toBe(1_790_000_000_000);
    expect(toMs(null)).toBeNull();
    expect(toMs("not a date")).toBeNull();
  });

  it("never shows a negative countdown", () => {
    expect(formatCountdown(-5_000)).toBe("00:00");
    expect(formatCountdown(65_400)).toBe("01:05");
    expect(formatCountdown(3_725_000)).toBe("1:02:05");
  });

  it("formats durations in both locales", () => {
    expect(formatDurationSeconds(90, "en")).toMatch(/1 min.*30 sec/);
    expect(formatDurationSeconds(0, "vi")).toMatch(/0/);
    expect(formatDurationSeconds(null, "en")).toBe("—");
  });

  it("groups and normalises fingerprints for comparison", () => {
    expect(groupFingerprint("ABCDEF0123456789")).toBe("abcd ef01 2345 6789");
    expect(normalizeFingerprint("ab:cd ef-01")).toBe("abcdef01");
  });
});

describe("safeReturnPath", () => {
  it("accepts only same-origin application paths", () => {
    expect(safeReturnPath("/approvals?status=pending")).toBe("/approvals?status=pending");
    for (const value of ["https://evil.test/", "//evil.test", "/\\evil.test", "javascript:alert(1)", "/login", "/setup", null, 42]) {
      expect(safeReturnPath(value)).toBe("/");
    }
  });
});
