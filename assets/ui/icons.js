// BlindPass interface icons. Original 24×24 outline drawings, MIT licensed
// with the rest of assets/ui. Each icon is a list of SVG child elements
// rendered with stroke="currentColor", fill="none", stroke-width 1.6 and
// round caps/joins, so consumers can build DOM nodes without innerHTML.

/** @typedef {[("path"|"circle"|"rect"|"line"|"polyline"), Record<string, string | number>]} IconPart */

/** @type {Record<string, IconPart[]>} */
export const ICONS = {
  overview: [
    ["rect", { x: 3.5, y: 3.5, width: 7, height: 7, rx: 1.5 }],
    ["rect", { x: 13.5, y: 3.5, width: 7, height: 7, rx: 1.5 }],
    ["rect", { x: 3.5, y: 13.5, width: 7, height: 7, rx: 1.5 }],
    ["rect", { x: 13.5, y: 13.5, width: 7, height: 7, rx: 1.5 }]
  ],
  approvals: [
    ["path", { d: "M12 3 4.5 6v5.5c0 4.4 3.1 8.1 7.5 9.5 4.4-1.4 7.5-5.1 7.5-9.5V6Z" }],
    ["path", { d: "m8.8 12.2 2.2 2.2 4.4-4.6" }]
  ],
  agents: [
    ["rect", { x: 4.5, y: 8, width: 15, height: 11, rx: 2.5 }],
    ["path", { d: "M12 4.5V8" }],
    ["circle", { cx: 12, cy: 3.8, r: 0.9 }],
    ["path", { d: "M9.2 13h.01M14.8 13h.01" }],
    ["path", { d: "M2.5 12.5v2.5M21.5 12.5v2.5" }]
  ],
  policy: [
    ["path", { d: "M4 6.5h9M17 6.5h3M4 12h3M11 12h9M4 17.5h11M19 17.5h1" }],
    ["circle", { cx: 15, cy: 6.5, r: 2 }],
    ["circle", { cx: 9, cy: 12, r: 2 }],
    ["circle", { cx: 17, cy: 17.5, r: 2 }]
  ],
  audit: [
    ["path", { d: "M6.5 3.5h8l4 4v13h-12Z" }],
    ["path", { d: "M14.5 3.5v4h4" }],
    ["path", { d: "M9.5 12h6M9.5 15.5h6M9.5 8.5h2" }]
  ],
  enrollments: [
    ["path", { d: "M14 4.5h3.5A2.5 2.5 0 0 1 20 7v10a2.5 2.5 0 0 1-2.5 2.5H14" }],
    ["path", { d: "M4 12h11M11 8l4 4-4 4" }]
  ],
  nodes: [
    ["rect", { x: 3.5, y: 4, width: 17, height: 6.5, rx: 1.5 }],
    ["rect", { x: 3.5, y: 13.5, width: 17, height: 6.5, rx: 1.5 }],
    ["path", { d: "M7 7.25h.01M7 16.75h.01M11 7.25h5.5M11 16.75h5.5" }]
  ],
  workloads: [
    ["path", { d: "m12 3.5 8 4.5v8l-8 4.5-8-4.5V8Z" }],
    ["path", { d: "m4 8 8 4.5L20 8M12 12.5v8" }]
  ],
  grants: [
    ["circle", { cx: 8, cy: 12, r: 4 }],
    ["path", { d: "M12 12h8.5M17.5 12v3M20.5 12v2" }]
  ],
  operations: [
    ["path", { d: "M3.5 12h3.5l2.5-6 5 12 2.5-6h3.5" }]
  ],
  operators: [
    ["circle", { cx: 9, cy: 8.5, r: 3.5 }],
    ["path", { d: "M3 19.5c.6-3.3 3-5.5 6-5.5s5.4 2.2 6 5.5" }],
    ["path", { d: "M15.5 5.2a3.5 3.5 0 0 1 0 6.6M17.5 14.3c1.8.8 3.1 2.7 3.5 5.2" }]
  ],
  settings: [
    ["circle", { cx: 12, cy: 12, r: 3 }],
    ["path", { d: "M12 3v2.5M12 18.5V21M3 12h2.5M18.5 12H21M5.6 5.6l1.8 1.8M16.6 16.6l1.8 1.8M5.6 18.4l1.8-1.8M16.6 7.4l1.8-1.8" }]
  ],
  logout: [
    ["path", { d: "M10 4.5H6.5A2 2 0 0 0 4.5 6.5v11a2 2 0 0 0 2 2H10" }],
    ["path", { d: "M14.5 8 19 12l-4.5 4M19 12H9.5" }]
  ],
  menu: [["path", { d: "M4 7h16M4 12h16M4 17h16" }]],
  close: [["path", { d: "M6 6l12 12M18 6 6 18" }]],
  check: [["path", { d: "m5 12.5 4.5 4.5L19 7.5" }]],
  cross: [["path", { d: "M7 7l10 10M17 7 7 17" }]],
  alert: [
    ["path", { d: "M12 4 2.8 19.5h18.4Z" }],
    ["path", { d: "M12 10v4.2M12 17h.01" }]
  ],
  info: [
    ["circle", { cx: 12, cy: 12, r: 8.5 }],
    ["path", { d: "M12 11v5.5M12 7.8h.01" }]
  ],
  clock: [
    ["circle", { cx: 12, cy: 12, r: 8.5 }],
    ["path", { d: "M12 7.5V12l3 2" }]
  ],
  lock: [
    ["rect", { x: 5, y: 10.5, width: 14, height: 10, rx: 2 }],
    ["path", { d: "M8 10.5V8a4 4 0 0 1 8 0v2.5M12 14.5v2" }]
  ],
  key: [
    ["circle", { cx: 8, cy: 15.5, r: 4 }],
    ["path", { d: "m10.9 12.6 8.1-8.1M16 7.5l2.5 2.5M13.5 10l2 2" }]
  ],
  fingerprint: [
    ["path", { d: "M6.5 18.5c.9-2 1.5-4.2 1.5-6.5a4 4 0 0 1 8 0c0 1.2-.1 2.4-.3 3.5" }],
    ["path", { d: "M12 12c0 3.3-.8 6.1-2.3 8.5M15 19.2c.2-.6.4-1.2.5-1.8" }],
    ["path", { d: "M4.3 14.5c.2-.8.2-1.6.2-2.5a7.5 7.5 0 0 1 12.6-5.5M19.3 10.5c.1.5.2 1 .2 1.5 0 .9-.1 1.8-.2 2.7" }]
  ],
  copy: [
    ["rect", { x: 8.5, y: 8.5, width: 11, height: 11, rx: 2 }],
    ["path", { d: "M15.5 8.5V6.5a2 2 0 0 0-2-2h-7a2 2 0 0 0-2 2v7a2 2 0 0 0 2 2h2" }]
  ],
  eye: [
    ["path", { d: "M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12Z" }],
    ["circle", { cx: 12, cy: 12, r: 2.8 }]
  ],
  "eye-off": [
    ["path", { d: "M4 4l16 16" }],
    ["path", { d: "M9.9 5.8A9 9 0 0 1 12 5.5c6 0 9.5 6.5 9.5 6.5a16 16 0 0 1-2.6 3.4M6.4 7.5A15.6 15.6 0 0 0 2.5 12S6 18.5 12 18.5a8.7 8.7 0 0 0 4.2-1" }],
    ["path", { d: "M10 10.2a2.8 2.8 0 0 0 3.9 3.9" }]
  ],
  refresh: [
    ["path", { d: "M19.5 12a7.5 7.5 0 0 1-13 5.1M4.5 12a7.5 7.5 0 0 1 13-5.1" }],
    ["path", { d: "M17.5 3.5v3.4h-3.4M6.5 20.5v-3.4h3.4" }]
  ],
  plus: [["path", { d: "M12 5v14M5 12h14" }]],
  trash: [
    ["path", { d: "M4.5 7h15M9.5 7V4.5h5V7M6.5 7l.8 12.5h9.4L17.5 7" }],
    ["path", { d: "M10.2 11v5M13.8 11v5" }]
  ],
  rotate: [
    ["path", { d: "M4.5 12a7.5 7.5 0 1 0 2.2-5.3L4.5 9" }],
    ["path", { d: "M4.5 4.5V9H9" }]
  ],
  ban: [
    ["circle", { cx: 12, cy: 12, r: 8.5 }],
    ["path", { d: "M6 6l12 12" }]
  ],
  "chevron-right": [["path", { d: "m9.5 6 6 6-6 6" }]],
  "chevron-left": [["path", { d: "m14.5 6-6 6 6 6" }]],
  "chevron-down": [["path", { d: "m6 9.5 6 6 6-6" }]],
  "chevron-up": [["path", { d: "m6 14.5 6-6 6 6" }]],
  "arrow-right": [["path", { d: "M5 12h14M13 6l6 6-6 6" }]],
  "arrow-up-right": [["path", { d: "M7 17 17 7M9 7h8v8" }]],
  external: [
    ["path", { d: "M13.5 4.5h6v6M19.5 4.5 11 13" }],
    ["path", { d: "M17.5 14v4a1.5 1.5 0 0 1-1.5 1.5H6A1.5 1.5 0 0 1 4.5 18V8A1.5 1.5 0 0 1 6 6.5h4" }]
  ],
  globe: [
    ["circle", { cx: 12, cy: 12, r: 8.5 }],
    ["path", { d: "M3.5 12h17M12 3.5c2.3 2.4 3.5 5.2 3.5 8.5s-1.2 6.1-3.5 8.5c-2.3-2.4-3.5-5.2-3.5-8.5S9.7 5.9 12 3.5Z" }]
  ],
  user: [
    ["circle", { cx: 12, cy: 8.5, r: 3.8 }],
    ["path", { d: "M5 20c.7-3.7 3.5-6 7-6s6.3 2.3 7 6" }]
  ],
  terminal: [
    ["rect", { x: 3.5, y: 4.5, width: 17, height: 15, rx: 2 }],
    ["path", { d: "m7.5 9.5 3 2.5-3 2.5M12.5 15h4" }]
  ],
  link: [
    ["path", { d: "M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1" }],
    ["path", { d: "M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1" }]
  ],
  signal: [
    ["circle", { cx: 12, cy: 12, r: 2 }],
    ["path", { d: "M8 8a5.6 5.6 0 0 0 0 8M16 16a5.6 5.6 0 0 0 0-8M5.2 5.2a9.6 9.6 0 0 0 0 13.6M18.8 18.8a9.6 9.6 0 0 0 0-13.6" }]
  ],
  dot: [["circle", { cx: 12, cy: 12, r: 3.5 }]]
};

/** @param {string} name */
export function hasIcon(name) {
  return Object.hasOwn(ICONS, name);
}
