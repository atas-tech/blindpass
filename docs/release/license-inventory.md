# License inventory (P07 slice 4)

**Status:** reconciliation of declared licenses against [LICENSES.md](../../LICENSES.md) and decisions [0003](../product/decisions/0003-dependency-baseline-2026-09.md)–[0009](../product/decisions/0009-p06-sbom-scanner-dependency-review.md), taken 2026-10-06 on the uncommitted tree above `8a595ad`. It records what manifests, lockfiles and source headers say. It is not legal advice and assigns no license. [LICENSES.md](../../LICENSES.md) was **not** edited: every row it contains matches the evidence; the gaps below are decisions, not corrections.

**Final pass 2026-10-06 21:30 +07** (after the library rename, `release.yml` and the PKGBUILD): Socket scan `4b646e22-a090-424b-91cd-316213de0e45` reports the same 634 artifacts and an identical alert set as `b101cb03-…` (one workspace artifact renamed); `LICENSES.md`, `Cargo.lock` and every crate manifest are unchanged since the first pass, so every row below that is not marked "updated 2026-10-06" was re-read and stands. The earlier sections are kept as dated record; where a name or fact went stale, a dated note says so. **P07-I05 and the P07 license assignment are not complete**: L-01, L-02, L-03, L-04, L-06 and L-07 are open.

**Update 2026-10-07 (legacy stack removed).** `packages/sps-server` and `packages/dashboard` were removed, and `package-lock.json` now has 264 entries (252 under `node_modules`, 10 of them workspace links) where the rows below counted 394 (380). The `@x402/*`, `viem`, `ox`, `abitype`, `@noble/*`, `fastify`, `ioredis` and `lightningcss*` packages are no longer in the lockfile, and the MCP bundle lists 10 packages, all MIT, with a single `zod` (4.6.5). The workspace, L-05, L-06, L-07 and npm rows below were re-read against the lockfile, `packages/*/package.json` and `packages/openclaw-plugin/dist/licenses/bundle-packages.json` on that date. The Socket scan figures (634 artifacts, alert counts) are of the 2026-10-06 tree and were not re-run. The Cargo section is unchanged.

Method and limits: manifests and `Cargo.lock`/`package-lock.json` as declared; `cargo metadata --locked --offline` for crate licenses (the 40 crates that are locked but never compiled on Linux have no local metadata); Socket scan `b101cb03-…` for its license alerts ([evidence](../security/dependency-evidence-2026-10-06.md)); SPDX headers by leading-comment grep. A declared license is not a clearance of file contents.

## Workspace licenses

| Path | `package.json` / `Cargo.toml` | LICENSES.md | `LICENSE` file | Matches |
|---|---|---|---|---|
| `packages/console` | AGPL-3.0-only | AGPL-3.0-only | yes | yes |
| `packages/i18n` | AGPL-3.0-only | AGPL-3.0-only | **no** (documented in LICENSES.md) | yes |
| `packages/contract-tests` | AGPL-3.0-only | AGPL-3.0-only | **no** (private test package) | yes |
| `packages/agent-skill`, `browser-ui`, `gateway`, `openclaw-plugin`, `mcp-server` *(renamed 2026-10-06: the `packages/mcp-server` directory is the private, unpublished library `@blindpass/mcp-server-lib`; the LICENSES.md row is by path and still matches)* | MIT | MIT | yes | yes |
| Published npm bundle `@blindpass/mcp-server` *(staged by `scripts/publish_dist.sh`, not a workspace)* | MIT (generated `package.json`) | no row: it is MIT workspace code plus 10 bundled third-party packages, all MIT *(2026-10-07; 19 packages, 16 MIT and 3 Apache-2.0, before the x402/viem removal)* | `LICENSE` copied from `openclaw-plugin`; a license text per bundled package in `dist/licenses` | matches the `openclaw-plugin` row; the bundle is not itself a LICENSES.md row |
| `helpers/login`, `helpers/browser-tool` | AGPL-3.0-only | AGPL-3.0-only | yes | yes |
| `assets/ui` | MIT (Inter: OFL-1.1) | MIT (OFL-1.1) | yes | yes |
| `crates/blindpass-{core,broker,controller,cli,node}` | `license.workspace = "AGPL-3.0-only"` | AGPL-3.0-only | **no** | yes |
| `desktop/approval-app`, `desktop/omarchy-widget` | SPDX headers AGPL-3.0-only (28 files); no manifest license field for the app | AGPL-3.0-only | no | yes |
| root `package.json` | `SEE LICENSE IN LICENSES.md`, `private` | same | none | yes |

Direct Cargo crates in LICENSES.md (14 rows): every locked version and license matches `Cargo.lock` and crate metadata.

## Boundary and assignment findings

| ID | Finding | Evidence | Needed decision |
|---|---|---|---|
| L-01 | **The MIT `@blindpass/browser-ui` embeds AGPL-3.0-only i18n code and strings.** `src/i18n.js` imports `resolveLocale`, `resolveLocaleFromBrowser` and `locales/{en,vi}/browser-ui.json` from `@blindpass/i18n`, declared as a devDependency (`package.json` line 18); Vite bundles them. All 96 English strings longer than 25 characters from `packages/i18n/locales/en/browser-ui.json` appear verbatim in `packages/browser-ui/dist/assets/index-DbiCBHEa.js` (built 2026-10-05). LICENSES.md says MIT packages "should not vendor or embed AGPL application code", and P04-D7 in the vault plan says rights-holder-approved string separation is a prerequisite to MIT client reuse. | `packages/browser-ui/src/i18n.js:1-3`; dist inspection *(re-checked 2026-10-06 21:2x on the `dist` rebuilt at 18:46: still 96 of 96 strings; no change to `packages/browser-ui/src/i18n.js` or `package.json`)* | Rights holder: relicense the browser-ui locale resources and resolver (git history of `packages/i18n` shows the author names Hung Vo and tuthan; whether one rights holder covers both is not established here), ship a separate MIT string set, or stop labelling the built input page MIT. Until then a standalone browser-ui artifact (including the legacy `browser-ui` image) must not be described as MIT-only. The controller image is AGPL-3.0-only as a whole, so it is not affected. |
| L-02 | License assignment is missing for top-level areas that will ship or be published: `landing/` (published site, 9 code files, no SPDX header), `deploy/` (headers AGPL-3.0-only on 17 code files), `scripts/` (mixed: 10 AGPL, 2 MIT, 34 no header), `tests/` (headers AGPL-3.0-only except one), `agents/`, `docs/`. | LICENSES.md has no row for them; header survey | Owner assigns; the release packet must carry an assignment for everything in a release archive (P07 "license assignment"). Not inferred here. |
| L-03 | No license text file in `crates/*` or at the repository root; the AGPL text is carried only by the AGPL package `LICENSE` files (`packages/console/LICENSE` is what the controller image copies to `/usr/share/doc/blindpass/LICENSE`). Source tarballs and the P06 release archives need the text and the AGPL source-offer location stated. | `ls LICENSE* crates/*/LICENSE*` *(updated 2026-10-06: the AGPL text **is** carried by the controller image (`packages/console/LICENSE`), by the controller/node release archives (`scripts/release/release-artifacts.py:239-240`: `LICENSE` and `LICENSES.md`) and by the desktop archive (`scripts/release/build-desktop-archive.py:85`); it is still absent from the repository root, from the crates and from a plain source archive, and no AGPL source-offer location is stated in any release file I read)* | Add a root license text in the release archive step; check against [release-layout.md](../deploy/release-layout.md). |
| L-04 | No Cargo crate sets `publish = false`. | `crates/*/Cargo.toml` | Add it (manifest edit, not made here) so `cargo publish` of an AGPL internal crate cannot happen by accident. |
| L-05 | **Updated 2026-10-06 (workstream E, owner decision on the package name).** `packages/mcp-server` is the private library `@blindpass/mcp-server-lib` and is never published. The public npm package `@blindpass/mcp-server` is the staged esbuild bundle (`scripts/publish_dist.sh`): MIT, no runtime dependencies, with the licence text of each of the 19 bundled packages in `dist/licenses` (`bundle-packages.json` records name, version, licence and SHA-256). The earlier text of this row (an all-MIT closure of three packages for a published library) no longer describes anything that ships. **Updated 2026-10-07:** the bundle lists 10 packages, all MIT: `@modelcontextprotocol/core` and `/server` 2.2.0, `hpke-js` and the five `@hpke/*` packages, `jose` 6.1.3 and a single `zod` 4.6.5 (`dist/licenses/bundle-packages.json`). The Apache-2.0 `@x402/core`, `@x402/evm` and `@x402/fetch` 2.8.0 (frozen legacy payment code; canonical Apache text retained as `licenses/x402-Apache-LICENSE`) and the MIT `viem`, `ox`, `abitype`, `@noble/*` and second `zod` major that this row listed on 2026-10-06 were removed from the bundle on 2026-10-07, so the Apache-2.0 attribution is no longer needed there. `scripts/bundle-mcp-notices.mjs` guards both bundled entrypoints (MCP server and resolver) against AGPL workspace code. | `node scripts/release/check-npm-pack.mjs --tarball <candidate> --self-contained`; `node scripts/release/bundle-sbom.mjs --package <installed package> --out <file>` | None for MIT. No payment support is claimed. Re-run both commands on the final candidate (the candidate job does); the built `dist` was read for this update, not a tarball. |
| L-06 | Controller image notices have no license allowlist or completeness check (`scripts/release/controller-notices.mjs` copies any `LICENSE`/`COPYING`/`NOTICE`/`OFL` file it finds). Of the 202 compiled registry crates, 201 ship such a file; **`crc-catalog` 2.5.0** (declared `MIT OR Apache-2.0`) ships none, so the image carries no text for it. | crate source scan in the local registry cache | Supply a canonical license text with recorded provenance, or accept and record. Add a per-crate completeness check to the notices step. |
| L-07 | **The node release archive ships third-party binaries and packages whose licenses are not enumerated here:** the Node runtime (`lib/login/runtime/bin/node` with `runtime/LICENSE`, 24.21.0 or 26.10.0), **Chrome Headless Shell 145.0.7632.6** (`lib/login/browsers/chromium_headless_shell-1208`, the build requires `LICENSE.headless_shell` to exist), Playwright 1.58.2, `playwright-core` 1.58.2 and `@playwright/mcp` 0.0.83 with its nested `1.64.0-alpha` pair (Apache-2.0 per the lockfile), and the MCP bundle with its 10 bundled packages' license texts (19 on 2026-10-06). | `scripts/release/release-artifacts.py:196-238` | Owner: confirm the node archive's notice set is complete for the browser (Chrome Headless Shell bundles many third-party components under its own notices) and for Node; none of it was assessed here. See D-11 in the [dependency evidence](../security/dependency-evidence-2026-10-06.md) for the security side. |

## Cargo: compiled set (202 registry crates + 5 workspace crates)

No copyleft in the compiled registry set; the only AGPL code is the five workspace crates.

| Declared license expression | Registry crates |
|---|---|
| `MIT OR Apache-2.0` | 116 (includes 6 declared with the deprecated `/` spelling and normalised by the SBOM: `flume`, `serde_urlencoded`, `stringprep`, `unicode-properties`, `vcpkg`, `version_check`) |
| `MIT` | 36 |
| `Unicode-3.0` | 18 (ICU4X data/provider crates) |
| `Apache-2.0 OR MIT` | 14 |
| `ISC` | 3 (`rustls-webpki`, `simple_asn1`, `untrusted`) |
| `Unlicense OR MIT` | 2 (`byteorder`, `memchr`) |
| `CDLA-Permissive-2.0` | 2 (`webpki-roots` 0.26.11 and 1.0.9, Mozilla trust-anchor data embedded in the binary) |
| Single crates | `ring` `Apache-2.0 AND ISC` (its tree also ships `LICENSE-BoringSSL` and `LICENSE-other-bits`), `matchit` `MIT AND BSD-3-Clause`, `rustls` `Apache-2.0 OR ISC OR MIT`, `subtle` `BSD-3-Clause`, `foldhash` `Zlib`, `sync_wrapper` `Apache-2.0`, `ryu` `Apache-2.0 OR BSL-1.0`, `whoami` `Apache-2.0 OR BSL-1.0 OR MIT`, `tinyvec` `Zlib OR Apache-2.0 OR MIT`, `zerocopy` `BSD-2-Clause OR Apache-2.0 OR MIT`, `unicode-ident` `(MIT OR Apache-2.0) AND Unicode-3.0` |

(The counts sum to 202 compiled registry crates; per-crate values are in [cargo.cdx.json](sbom/cargo.cdx.json), where the 5 AGPL-3.0-only workspace crates are the other compiled components.)

Socket license alerts on the compiled set, all triaged against declared metadata: `nonpermissiveLicense` on `webpki-roots` (CDLA-Permissive-2.0 is permissive for data; flag is a heuristic, but the license text must ship with the binary: check the notice inventory); `unidentifiedLicense` on `parking`, `unicode-bidi`, `unicode-normalization`, `unicode-properties`, `utf8_iter` (each declares `MIT OR Apache-2.0` in Cargo metadata, Socket found no clean file match); `licenseException` on `wasi` (not compiled on Linux).

## npm: lockfile (264 entries; the table counts the 252 under `node_modules`)

Re-counted from `package-lock.json` on 2026-10-07 after the legacy stack was removed. On 2026-10-06 the lockfile had 394 entries and the table counted 380: MIT 311, Apache-2.0 17 (including `@x402/*`), ISC/BSD-3-Clause/BSD-2-Clause/MIT-0 15/7/3/1, MPL-2.0 13 (`axe-core` and the 12 `lightningcss*` packages), CC-BY-4.0 1 and 12 workspace links.

| License | Entries | Where used |
|---|---|---|
| MIT | 213 | runtime and dev |
| Apache-2.0 | 11 | includes Playwright and TypeScript |
| ISC, BSD-3-Clause, BSD-2-Clause, MIT-0 | 11, 2, 2, 1 | mixed |
| **MPL-2.0** | 1 | `axe-core`: **dev only**, in no runtime closure |
| **CC-BY-4.0** | 1 | `caniuse-lite`: dev only |
| none (workspace links) | 10 | licenses declared in their own manifests |

Socket `copyleftLicense`/`nonpermissiveLicense` alerts on npm (14 and 15 packages, scan of the 2026-10-06 tree) are exactly `axe-core`, the `lightningcss` family (no longer in the lockfile), `jsdom` 26.1.0 and (non-permissive only) `typescript` 5.9.3; the ones still in the lockfile are `dev` or `devOptional` there. No MPL-2.0 or CC-BY-4.0 package is in the `mcp-server`, console, browser-ui or OpenClaw-bundle runtime closure computed from the lockfile (`axe-core` and `caniuse-lite` are `dev`); the SPS runtime closure no longer exists.

OpenClaw bundle (`packages/openclaw-plugin/dist/licenses/bundle-packages.json`, 10 packages on 2026-10-07): all MIT. On 2026-10-06 it had 19 packages, MIT except `@x402/core`, `@x402/evm` and `@x402/fetch` (Apache-2.0, license text supplied from a digest-pinned repository copy because the npm packages omit it), and contained frozen x402/viem code whose shipping was a scope question for the owner, not a licensing one. The owner removed that payment code on 2026-10-07.

## Not covered

Chrome Headless Shell 145.0.7632.6 and the Node runtime inside the node release archive (L-07), the PKGBUILD (no scanner covers it; its `license=('AGPL-3.0-only')` matches the archive's AGPL text and `LICENSES.md`), Debian and PGDG packages in the controller image (125 packages, licenses not enumerated here; the attested SPDX of P06 carries package-declared licenses), Quickshell and Qt (host libraries the app runs against with their own license terms, not enumerated; nothing is bundled yet and the PKGBUILD does not exist), Chromium, Node runtime archives, the bundled SQLite 3.46.0 amalgamation in `libsqlite3-sys` and the BoringSSL-derived code in `ring` (only their crate-level declared expressions are recorded), font files other than Inter, and image/icon assets in `landing/`.
