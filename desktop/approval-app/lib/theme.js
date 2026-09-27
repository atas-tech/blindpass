// SPDX-License-Identifier: AGPL-3.0-only
// The shared BlindPass tokens (assets/ui/tokens.css) for QML. Keep values in
// step with that file; its contrast test covers these pairings.
.pragma library

var color = {
  sunken: "#080b0a",
  bg: "#0b0e0d",
  panel: "#101512",
  raised: "#151b17",
  overlay: "#161c18",
  scrim: "#b8050706",
  ink: "#f0f3ed",
  inkSoft: "#c3cbc4",
  muted: "#9ca59d",
  dim: "#818c83",
  line: "#27302a",
  lineStrong: "#36412f",
  control: "#5a6a60",
  controlHover: "#7a8a7f",
  lime: "#c5f277",
  limeStrong: "#d6ff92",
  limeInk: "#16210b",
  limeSoft: "#202b19",
  limeLine: "#647545",
  warn: "#ebc17c",
  warnSoft: "#2c2419",
  warnLine: "#6b5733",
  danger: "#f2a8a0",
  dangerSoft: "#2a1d1b",
  dangerLine: "#74443e",
  dangerStrong: "#ffb9b1",
  dangerHover: "#3a2320",
  info: "#a9cdf0",
  infoSoft: "#16202a",
  infoLine: "#3e5670",
  neutral: "#b9c2ba",
  neutralSoft: "#1a201c"
};

var font = {
  sans: "Inter Variable",
  mono: "monospace",
  xs: 12,
  sm: 13,
  md: 14,
  base: 16,
  lg: 20,
  xl: 25
};

var space = { s1: 4, s2: 8, s3: 12, s4: 16, s5: 20, s6: 24, s8: 32 };
var radius = { sm: 4, md: 6, lg: 9, pill: 999 };
/** 44 px is the product minimum target. */
var target = 44;

function tone(name) {
  switch (name) {
  case "ok":
  case "pending":
    return { fg: color.lime, bg: color.limeSoft, line: color.limeLine };
  case "warn":
    return { fg: color.warn, bg: color.warnSoft, line: color.warnLine };
  case "danger":
  case "rejected":
    return { fg: color.danger, bg: color.dangerSoft, line: color.dangerLine };
  case "info":
  case "approved":
    return { fg: color.info, bg: color.infoSoft, line: color.infoLine };
  default:
    return { fg: color.neutral, bg: color.neutralSoft, line: color.lineStrong };
  }
}
