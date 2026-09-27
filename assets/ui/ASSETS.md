# Shared UI assets

One source for the BlindPass visual system. The landing site, the secret-input page (`packages/browser-ui`) and the operator console (`packages/console`) consume these files; none of them keeps its own palette or font copy.

| File | What it is | License |
|---|---|---|
| `tokens.css` | Colour, type, space, radius, focus, target-size and motion custom properties (`--bp-*`) | MIT ([LICENSE](LICENSE)) |
| `fonts.css` | `@font-face` for the self-hosted Inter variable font | MIT |
| `fonts/InterVariable.woff2` | Inter 4.1 variable, subset (see below) | SIL Open Font License 1.1 ([fonts/OFL.txt](fonts/OFL.txt)) |
| `icons.js`, `icons.d.ts` | Original 24×24 outline icons as element data, rendered without `innerHTML` | MIT |
| `tests/tokens.test.mjs` | Contrast, target-size, reduced-motion and no-CDN checks | MIT |

This directory contains no application code and no translated strings. The English/Vietnamese resources stay in `packages/i18n`, which is AGPL-3.0-only; they are not copied here and this directory does not relicense them.

## Consumers

- **Console** imports `tokens.css`, `fonts.css` and `icons.js` through Vite, which fingerprints the font.
- **Input page** imports the same files through its Vite build.
- **Landing** is static, so `node scripts/sync-ui-assets.mjs` copies `tokens.css`, `fonts.css` and the font into `landing/dist/assets/ui/`. `npm run test:landing` fails if the copies differ from this directory.

Changing a colour in a consumer stylesheet instead of `tokens.css` is a defect (Decision 0001).

## Font provenance

- Upstream: `https://github.com/rsms/inter/releases/download/v4.1/Inter-4.1.zip` (downloaded 2026-09-27, SHA-256 `9883fdd4a49d4fb66bd8177ba6625ef9a64aa45899767dde3d36aa425756b11e`).
- Source file: `InterVariable.ttf` from that archive, SHA-256 `4989b125924991b90d05b2d16e0e388c48f7d5bb8b30539bbf9c755278d0ccaf`, version 4.001. The OFL notice declares no Reserved Font Name, so the subset keeps the family name.
- Subset with fontTools `pyftsubset` 4.64 and compressed with `woff2_compress`:

```bash
pyftsubset InterVariable.ttf \
  --unicodes="U+0000-00FF,U+0131,U+0152-0153,U+02BB-02BC,U+02C6,U+02DA,U+02DC,U+0300-0304,U+0306,U+0308-0309,U+030C,U+0323,U+0100-017F,U+01A0-01A1,U+01AF-01B0,U+0110-0111,U+1EA0-1EF9,U+2000-206F,U+20AB,U+20AC,U+2122,U+2190-2199,U+2212,U+2215,U+2713,U+2717,U+2715,U+00D7,U+2026,U+FEFF,U+FFFD" \
  --layout-features='kern,liga,calt,ccmp,locl,mark,mkmk,tnum,zero,ss01,cv05,cv08,cv11,case' \
  --output-file=InterVariable-subset.ttf --no-hinting --desubroutinize
woff2_compress InterVariable-subset.ttf
```

- Result: 90,900 bytes, SHA-256 `93c62f7904208ab286eb713da565a13c045fb8a97fb4c02610fa10e1231259d4`, `wght` 100–900 and `opsz` 14–32 axes retained.

The font this replaces (`landing/dist/assets/inter.woff2`, 48 KB) was a Latin-only subset without an adjacent licence notice: it had no `ơ`, `ư`, `đ` or U+1EA0–U+1EF9 glyphs, so Vietnamese screens fell back to Arial for most accented letters. The new subset covers the full Vietnamese alphabet.
