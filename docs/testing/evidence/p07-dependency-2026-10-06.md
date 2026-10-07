# P07 dependency evidence — 2026-10-06

**Status (updated 2026-10-06 21:30 +07):** a [final pass after the package rename](#final-pass-2026-10-06-after-the-package-rename) (scan `4b646e22-a090-424b-91cd-316213de0e45`, same alerts as the first scan, new SBOMs, PKGBUILD and `release.yml` reviewed) sits below this paragraph; the sections after it are the 17:34–17:52 record, kept with dated correction notes. Execution record for P07 slice 4 (P07-D5) and the dependency part of P07-I05, on the **uncommitted** working tree above `8a595ad18783634da59e046595942e729b56147b`. **P07-I05 is not passed**: the release-candidate artifacts, the packed MCP tarball install outside the repository and an attested SBOM for the candidate do not exist yet. **No dependency was added, upgraded or removed; no manifest or lockfile was edited by this work.** Analysis and decisions needed are in [dependency-evidence-2026-10-06](../../security/dependency-evidence-2026-10-06.md); inventories in [docs/release/sbom](../../release/sbom/README.md) and the [license inventory](../../release/license-inventory.md). Raw outputs are in [p07-dependency-2026-10-06/](p07-dependency-2026-10-06/).

## Final pass 2026-10-06 after the package rename

Run 21:06–21:30 +07 at the coordinator's request, after other workstreams renamed `packages/mcp-server` to the private `@blindpass/mcp-server-lib`, added `release.yml`, the bundle packaging (`scripts/release/bundle-sbom.mjs`, `publish_dist.sh`) and `desktop/packaging/arch/PKGBUILD`. Same rules: no manifest or lockfile edit, no Cargo build, Docker or QEMU run, no git command that changes the tree or index, no vault edit, no `cargo-cyclonedx`. **Everything above this section is the 17:34–17:52 record and is kept; stale statements carry inline "renamed/corrected 2026-10-06" notes.** Analysis: [final pass in the dependency evidence](../../security/dependency-evidence-2026-10-06.md#final-pass-2026-10-06-after-the-package-rename).

**Inputs.** 28 manifests, workflows and both lockfiles were hashed before the scan and again at 21:17: all 28 identical ([hashes](p07-dependency-2026-10-06/final-pass-inputs-2026-10-06.txt)). `Cargo.lock` `e6f028b69fa3038b` (unchanged since the first pass); `package-lock.json` `350e67141a8d9b39` (was `11da70354f526bdd`; workspace link and `name` rename only); `package.json` `98ea62c62152aad8` (was `f1a584fc…`; scripts only); `packages/mcp-server/package.json` `8ed9c27f85b70dda` (renamed, `private: true`, exact pins `@modelcontextprotocol/server` 2.2.0, `zod` 4.6.5); `release.yml` `05d27ced12a8f6c0`; `build-and-push-images.yml` `610e5fa02f8a1615`; `ci.yml` `ca39d5f4c633dcf8`. Cargo manifests and the other nine npm manifests are unchanged since the first pass.

| # | Command (from repository root) | Result |
|---|---|---|
| F1 | `bash ~/.claude/skills/dependency-guard/scripts/discover_scan_targets.sh .` | 79 `file=` lines (was 78); the only new entry outside git-ignored `.claude/worktrees/` is `.github/workflows/release.yml`: [output](p07-dependency-2026-10-06/discover-scan-targets-final-2026-10-06.txt) |
| F2 | `socket scan create --no-interactive --json --report --exclude-paths 'docs/release/sbom/**' --repo blindpass --branch p07-dependency-evidence --commit-hash 8a595ad… --tmp --set-as-alerts-page=false .` | scan **`4b646e22-a090-424b-91cd-316213de0e45`**, 29 files, `healthy: true`, no error-level policy action |
| F3 | `socket scan report <id> --json --fold=version --report-level=defer --license`; `socket scan view <id> --json` | 634 artifacts (378 npm, 256 Cargo), 1,286 alert occurrences. Compared with `b101cb03-…`: **same alerts**; the only artifact difference is `mcp-server@0.1.0` → `mcp-server-lib@0.1.0`; the defer report is identical apart from the scan id: [comparison](p07-dependency-2026-10-06/final-pass-scan-comparison-2026-10-06.txt) |
| F4 | `bash scripts/publish_dist.sh --skip-build --skip-validate --stage-dir <scratch>` | stages the published bundle package from the existing `packages/openclaw-plugin/dist`; no repository file written |
| F5 | `node scripts/release/bundle-sbom.mjs --package <stage> --out <scratch>` then copy | CycloneDX 1.5, 19 components, sha256 `0b9d91aba47cc371d9f1116437d4c247006dfd5a8a7ede9631dd148e8e913404`, **equal to workstream E's recorded hash**; written as `docs/release/sbom/mcp-bundle.cdx.json` |
| F6 | `BLINDPASS_BUNDLE_OUT=<scratch> bash scripts/build_bundle.sh`, then `diff -rq <scratch> packages/openclaw-plugin/dist` | exit 0, diff empty (`blindpass.mjs`, `blindpass-resolver.mjs`, `index.mjs`, `mcp-server.mjs`, `licenses/bundle-packages.json`). **Side effect:** the script first runs `npm run build` for `packages/gateway` and `packages/agent-skill`, which re-emitted their git-ignored `dist/*.js`/`*.d.ts` in the shared checkout at 21:09 (mtimes changed; the bundle came out byte-identical, so the content did not change in any way the bundle can see). No tracked file changed |
| F7 | `python3 docs/release/sbom/generate-cargo-cdx.py --check` | OK: 261 components, byte-identical, `Cargo.lock` sha256 `e6f028b6…` equals the hash inside the SBOM; `cargo.cdx.json` `9ee4203a…` untouched |
| F8 | `npm sbom --sbom-format cyclonedx --workspaces` in the shared checkout | **fails** `ESBOMPROBLEMS: missing: @blindpass/mcp-server-lib@file:…`: `node_modules/@blindpass/mcp-server` still links the old name until `npm ci` is run there (owner action for workstream E). `--package-lock-only --workspaces` also fails (incomplete optional dev WASM entries in the virtual tree) |
| F9 | Scratch directory with only the manifests and `package-lock.json`: `npm ci --offline --ignore-scripts --no-audit --no-fund` | exit 0, 312 packages from the local cache in 13 s; one `npm warn deprecated whatwg-encoding@3.1.1`. Doubles as a clean-install check of the lockfile. The shared `node_modules` was not touched |
| F10 | In that tree: `npm sbom --sbom-format cyclonedx --workspaces`; `… --workspace=@blindpass/mcp-server-lib --omit=dev` | exit 0 both. `npm-workspaces.cdx.json` 309 components (sha256 `72aaa5a0…`), no component added, removed or relicensed against the 17:43 file; `mcp-server-lib-runtime.cdx.json` 4 components, all MIT (sha256 `a2ba923b…`). Replaces #15's `2a5e16d6…` for the first |
| F11 | `bash -n desktop/packaging/arch/PKGBUILD`; read the PKGBUILD and `scripts/release/render-pkgbuild.sh` | syntax OK; review table P-01…P-07 in the analysis document. `shellcheck`, `namcap` and `makepkg` not installed or not run |
| F12 | Read `.github/workflows/release.yml` (25 `uses:`), `scripts/release/release-artifacts.py`, `scripts/build_bundle.sh`, `scripts/publish_dist.sh`; `grep` of every `uses:` in the other five workflows | W-01…W-10 and D-11/D-12 in the analysis document |
| F13 | Link check of every relative link and a trailing-whitespace scan over the files this slice wrote (`git diff --check` cannot cover untracked files) | no broken link, no trailing whitespace |

**Corrections to the earlier record in this file.** Row #16 and #23 name `@blindpass/mcp-server` as the workspace library: that is now `@blindpass/mcp-server-lib` (private); the pre-rename file `mcp-server-runtime.cdx.json` is kept as the dated record (`474a1cf6…`) and `npm pack --workspace=@blindpass/mcp-server` no longer packs the library (the published package is the staged bundle). Row #15's hash `2a5e16d6…` is superseded by F10. In "C." the Chromium row says the browser is the development host's package and implies it is not shipped: the node release archive **does** ship Chrome Headless Shell 145.0.7632.6 and a Node runtime (D-11); and "test-only" for the helper packages was wrong for the same reason. The "Not run" bullet "PKGBUILD (does not exist)" is obsolete: it exists and was read (F11), but no scanner covers it.

**Not run in this pass:** `makepkg`, `shellcheck`, `namcap`, `actionlint`, any hosted workflow run, any container or VM; a Socket score or `--reach` analysis; `npm audit`/RUSTSEC/OSV; SBOM schema validation; regeneration of the Debian package list (needs `docker run`); resolution of the 25 action SHAs against GitHub (E did it through the API; not repeated here); deep reviews of Playwright 1.58.2, `@playwright/mcp` 0.0.83, Node or Chrome Headless Shell (not needed to record the finding, needed before any upgrade).

**P07-I05 is still not passed.** What this slice owns passes or is recorded: lock sync, offline clean install, deterministic Cargo and bundle SBOMs, fresh-build identity of the bundle, a Socket scan with no drift against the first pass. What I05 still needs and does not have: (1) a release candidate: `release.yml` has never run, there is no release key and no commit, so every scan and SBOM here describes an uncommitted tree above `8a595ad`; (2) an attested SBOM for the candidate image (the only attested SPDX is the P06 build of an earlier tree); (3) owner decisions on the recorded risks (D-01, D-03, D-04, D-05, D-11, D-12), without which none can be called "reviewed"; (4) coverage of the components no scanner reaches (D-09, D-11, the image OS layer, Qt/Quickshell, the Syft scanner image); (5) schema validation of the SBOMs; (6) an install of the CI-built tarball outside the repository; (7) a final scan of the final manifests: edits after 21:06 are unscanned.

## Environment

Arch Linux, kernel 7.2.3; Node v26.10.0 (mise) / npm 11.19.1; rustc and cargo 1.98.1; Python 3.14; Socket CLI 1.1.176 (org `atas-tech`, token from the CLI config; never printed or stored here); dependency-guard skill 1.2.0. Cargo runs used `--locked --offline` and **no build** (the build directory belongs to another workstream). Only manifests uploaded by `socket scan create` and package coordinates sent by `check_dependency.sh` left the machine. `npm audit` was deliberately not run: it would send the dependency tree to the npm registry, which the slice did not prescribe.

## Inputs

All manifests and both lockfiles predate the first scan (17:34 +07) except the two noted. SHA-256 prefixes at scan time:

| File | mtime (+07) | SHA-256 |
|---|---|---|
| `Cargo.lock` | 2026-10-02 18:38 | `e6f028b69fa3038b` |
| `package-lock.json` | 2026-10-01 16:46 | `11da70354f526bdd` |
| `Cargo.toml` / controller / cli / node / broker / core `Cargo.toml` | 09-25 … 10-02 | `f3589e6c…` / `06132812…` / `52ea6571…` / `20fe192e…` / `e582dfa4…` / `f794866c…` |
| 10 `packages/*/package.json`, 2 `helpers/*`, `assets/ui` | 09-27 … 10-01 | in `git` working tree; only `mcp-server` changed after the scan (`c857b9ab…` at 17:44, metadata only). *Renamed 2026-10-06: it is now `@blindpass/mcp-server-lib`, private, hash `8ed9c27f85b70dda` at 20:50* |
| `package.json` | 10-06 17:36 (after scan 1) | `f1a584fc…` (`scripts.test:landing` only) |

Both lockfiles hashed identically before and after every command in this record (`sha256sum -c`).

## Commands and results

| # | Command (from repository root) | Result |
|---|---|---|
| 1 | `bash ~/.claude/skills/dependency-guard/scripts/discover_scan_targets.sh .` | 78 `file=` lines, 51 under git-ignored `.claude/worktrees/`; JavaScript GA, Rust GA, GitHub Actions **experimental**: [output](p07-dependency-2026-10-06/discover-scan-targets.txt) |
| 2 | `socket scan create --read-only --no-interactive --json .` | "Found 28 files", stopped before upload |
| 3 | `socket scan create --no-interactive --json --report --repo blindpass --branch p07-dependency-evidence --commit-hash 8a595ad… --tmp --set-as-alerts-page=false .` | scan `b101cb03-d0ed-4758-ada2-83531a18aedc`, 28 files, `healthy: true`, no error-level alert |
| 4 | `socket scan report <id> --json --fold=version --report-level=defer --license`; `socket scan view <id> --json`; `socket scan metadata <id> --json` | 634 artifacts (378 npm, 256 Cargo); `incomplete: false`. Deduplicated middle/high alerts: [socket-scan-alerts.tsv](p07-dependency-2026-10-06/socket-scan-alerts.tsv) (204 rows, shipped-scope tagged) |
| 5 | Same as 3 without `--exclude-paths`, after manifest edits by other workstreams | `73147a69-68db-4fa1-bd70-cd9c77ec982c`: 31 files, 696 artifacts; the extra files were this slice's own `docs/release/sbom/*.cdx.json`. **Superseded.** |
| 6 | Same as 3 plus `--exclude-paths 'docs/release/sbom/**'` | `90f22ef7-1214-490a-aa9c-cc40a145703d`: 28 files, 634 artifacts, alert multiset **identical** to #3, `healthy: true` |
| 7 | `check_dependency.sh cargo cargo-cyclonedx --mode deep` | 0.5.7, 139 transitive, deep overall 36 → `block`: [report](p07-dependency-2026-10-06/socket-deep-cargo-cyclonedx-0.5.7.md). Not installed. |
| 8 | `check_dependency.sh npm @cyclonedx/cyclonedx-npm --mode deep` | Looked up by mistake (npm has `npm sbom`); report discarded, nothing installed |
| 9 | `check_dependency.sh npm fast-uri 3.1.8 --mode deep`; `… npm ws 8.21.0 --mode deep` | fast-uri 3.1.8 overall 75; ws 8.21.0 overall 80, both `block_pending_human_review` under the strict matrix: [fast-uri](p07-dependency-2026-10-06/socket-deep-fast-uri-3.1.8.md), [ws](p07-dependency-2026-10-06/socket-deep-ws-8.21.0.md). Nothing applied. |
| 10 | `cargo metadata --locked --offline --format-version 1` | **fails**: `failed to download anstyle-wincon v3.0.11` (all-platform resolve needs Windows crates not in the offline cache) |
| 11 | `cargo metadata --locked --offline --filter-platform x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu` | both succeed; Cargo.lock unchanged, so lock and manifests are in sync |
| 12 | `cargo tree --locked --offline --target <t> --workspace -e normal,build,dev --prefix none --no-dedupe` for both targets | 207 compiled packages each (5 workspace + 202 registry), **identical** between x86_64 and aarch64. `-i rsa` and `-i sqlx-mysql` print nothing (locked, not compiled) |
| 13 | `cargo tree --locked --offline --target x86_64-unknown-linux-gnu --workspace -d` | duplicates `getrandom`, `hashbrown`, `syn`, `webpki-roots`: [output](p07-dependency-2026-10-06/cargo-tree-duplicates-x86_64.txt) |
| 14 | `python3 docs/release/sbom/generate-cargo-cdx.py` then `--check` (twice) | 261 components, 207 `required`, 54 `excluded`; file byte-identical on regeneration; sha256 `9ee4203a…` |
| 15 | `npm sbom --sbom-format cyclonedx --workspaces` | exit 0; 309 components, unique `bom-ref`s, every component has a license; sha256 `2a5e16d6…` *(superseded 2026-10-06 by F10, `72aaa5a0…`)* |
| 16 | `npm sbom --sbom-format cyclonedx --workspace=@blindpass/mcp-server --omit=dev` *(renamed 2026-10-06: the workspace is `@blindpass/mcp-server-lib`; see F10)* | exit 0; 3 packages + the workspace, all MIT; sha256 `474a1cf6…` |
| 17 | `npm ci --dry-run --ignore-scripts --offline` | exit 0 "up to date": lockfile and manifests agree |
| 18 | `npm ls --all --workspaces --include-workspace-root` | exit 0; 0 non-optional problems, 94 `UNMET OPTIONAL DEPENDENCY` lines (optional peers) |
| 19 | `node scripts/generate-controller-types.mjs --check` | exit 0 (generated declarations match `docs/api/controller.openapi.yaml`) |
| 20 | `node scripts/tests/controller-openapi.test.mjs` | 13 pass, 0 fail |
| 21 | `npm run test:ui-assets` | `sync-ui-assets --check` ok; 9 pass, 0 fail |
| 22 | `node --test scripts/tests/release_metadata.test.mjs` | 1 pass |
| 23 | `npm pack --workspace=@blindpass/mcp-server --dry-run` *(renamed 2026-10-06: that workspace is now private `@blindpass/mcp-server-lib`; the published `@blindpass/mcp-server` is the staged bundle)* | prepack check "OK, 14 file(s)", no tarball written (workstream E's manifest at 17:44) |
| 24 | `docker run --rm --pull never --network none --read-only --entrypoint dpkg-query blindpass-p06-controller:final-sbom -W …` | 125 packages; differs from the recorded P06 list only in five `perl*` versions (`deb12u3` → `deb12u4`) |
| 25 | `readelf -d target/debug/<bin>` (NEEDED only; no execution) | broker: `libsystemd.so.0`, `libcrypto.so.3`; controller, node: `libcrypto.so.3`; cli, workload client, credential loader: none beyond libc/libgcc |

A before/after `git status --short` comparison around commands 19–22 was empty (they changed no tracked file); #23 is `--dry-run` and wrote no tarball.

## A. Scan results

| Measure | Value |
|---|---|
| Artifacts | npm 378, Cargo 256 (every registry crate in `Cargo.lock`; workspace crates are not Socket artifacts) |
| Unique package×alert pairs | npm 10 high / 65 middle / 283 low; Cargo 0 high / 129 middle / 126 low; none critical |
| Policy actions on alert occurrences | `ignore` 1,172, `monitor` 94, `warn` 20 (19 high `cve`, 1 `deprecated` `whatwg-encoding`), `error` 0 |
| High alerts | `browserslist` 4.28.1, `fast-uri` 3.1.0 (8 CVEs), `nanoid` 3.3.11, `picomatch` 4.0.3, `postcss` 8.5.8, `source-map-js` 1.2.1, `ws` 8.18.3 and 8.19.0; plus `indent-string`/`safer-buffer` `socketUpgradeAvailable` (policy `ignore`) |
| Shipped exposure of the high alerts | `fast-uri` in the legacy SPS runtime; `ws` in the `agent-skill` source closure; all others dev-only (`dev: true` in the lockfile, in no computed runtime closure) |
| Cargo mediumCVE | `jsonwebtoken` 9.3.1 (GHSA-h395-gr6q-cpjc), `block-buffer` 0.10.4 (GHSA-qwgh-2vcv-g2f7) |
| Cargo build-time execution (compiled) | 20 `build.rs`, 12 proc-macro crates, `links`: `libsqlite3-sys`, `ring` |
| npm install scripts in the lockfile | `esbuild` 0.27.3 (dev), `fsevents` 2.3.2 (optional, `helpers/login`) and 2.3.3 (dev) |

Runtime closures were computed from `package-lock.json` (including optional peers, so they over-approximate): `@blindpass/mcp-server` 3 packages, console 14, browser-ui 6, agent-skill 25, SPS 83; the OpenClaw bundle uses the 19-package inventory the bundle step wrote on 2026-10-05.

## B. SBOMs

`docs/release/sbom/` holds the Cargo CycloneDX 1.5 file and its generator, the two `npm sbom` outputs and the Debian package list; the README states how each is regenerated and which are reproducible. **Not validated against the CycloneDX JSON schema** (not on this host; no validator installed). Generator self-checks passed: unique refs, all dependency refs resolve, component count equals `Cargo.lock` (261), registry components carry a purl and a 64-hex SHA-256, 221 license expressions parse as SPDX syntax. 40 excluded components carry no license (metadata not in the offline cache). Compared with P06: the attested SPDX (O10/SB01 passed on image config `95e1d931…` of an earlier tree, [record](p06-postgres-backup-2026-10-04.md)) remains the only image SBOM; there is **no attested SBOM for the current tree or any P07 candidate**.

## C. Non-npm/Cargo components

| Item | Evidence |
|---|---|
| Quickshell 0.3.1-1, qt6-base / qt6-declarative / qt6-wayland 6.11.2, curl 8.22.0 | `pacman -Q` on the development host; approval-app README states the same tested versions |
| Chromium 152.0.7977.82-1 | `pacman -Q`, `chromium --version`; Playwright cache `chromium_headless_shell-1208`. *Corrected 2026-10-06: the node release archive ships Chrome Headless Shell 145.0.7632.6 (revision 1208) and a Node runtime; see D-11* |
| OpenSSL 3.6.4, systemd 261.2, SQLite 3.53.4 (host) | `pacman -Q`; the controller does **not** link host SQLite (bundled 3.46.0) |
| Image base | `debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251`, `node:26.10.0-bookworm@sha256:abbacf6e…`, `rust:1.98.1-bookworm@sha256:c49256cb…` (Dockerfile ARGs) |
| Image packages, local `:final-sbom` (id `sha256:f88404523a4dfab8b963dbfd1b510d60daf7536c4afa46c82534256f345f303f`, created 2026-10-05) | 125; vs the recorded list: `libperl5.36`, `perl`, `perl-base`, `perl-modules-5.36` 5.36.0-7+deb12u3 → +deb12u4. The apt layer is resolved from the live Debian mirror at build time |
| `esbuild` used by `scripts/build_bundle.sh` | `npx --yes esbuild` ×2; resolves to hoisted 0.27.3 (`npm ls esbuild`: via Vite and tsx), declared in no manifest |
| GitHub Actions | 11 distinct `uses:` refs, all mutable tags; `dtolnay/rust-toolchain@stable` ×3 |

Not scanned by Socket or any other tool in this record: all of the above, bundled C (SQLite 3.46.0 from `sqlite3.h`, `ring`), Debian/PGDG package vulnerabilities, Qt/Quickshell, Chromium, Node runtime archives, the Syft scanner image.

## D. Reproducibility of selected versions (P07-I05 inputs)

*(Renamed 2026-10-06: "`@blindpass/mcp-server` direct dependencies" below means the private library `@blindpass/mcp-server-lib`; the published bundle has none.)* Passed: Cargo lock in sync (`--locked` on metadata and tree); npm lock in sync (`npm ci --dry-run`); `npm ls` clean apart from optional peers; OpenAPI declarations, UI assets and release-metadata checks reproduce without changing tracked files; both Linux targets compile the same crate set; `@blindpass/mcp-server` direct dependencies are exact pins (`2.2.0`, `4.6.5`).

Not reproducible or unpinned: OS packages in the controller image (D-07); `npx --yes esbuild` (D-06); mutable GitHub Action refs (D-08); every other npm workspace declares caret ranges (the lockfile pins them, `npm ci` enforces it).

## E. Cargo SBOM tool decision

`cargo-cyclonedx` 0.5.7 is **blocked** (deep overall 36; see the analysis document). The plan's verification line `cargo cyclonedx` should be replaced by `python3 docs/release/sbom/generate-cargo-cdx.py --check` and the attested BuildKit SPDX from the release workflow. No command was added to any script or workflow.

## Not run, not covered

- Any Socket **score** for the scan (not in scan output); direct deep reviews only for the three packages in #7–#9.
- Reachability analysis (`socket scan create --reach`): not run; "unreachable" is not claimed for any CVE.
- `npm audit`, `cargo audit`/RUSTSEC, OSV: not run (no installed tool, no registry upload approved). The RUSTSEC database was not consulted; Cargo advisories above come from Socket only.
- Attested SBOM for the P07 candidate, SPDX/CycloneDX schema validation, SBOM signing: not done.
- PKGBUILD (*did not exist at 17:50; reviewed in the final pass, F11, as shell code only*), Qt/Quickshell packaging, Chromium provenance, aarch64 native hardware, Debian image CVE review: not done.
- The packed `@blindpass/mcp-server` tarball installed outside the repository (P07-E01): not done; #23 is the plan's "preliminary files check" only.
- GitHub Actions workflow scan is experimental and produced no artifacts.
- Scans 1–3 cover the tree at 17:34–17:50 +07 on 2026-10-06; scan 4 covers it at 21:06 +07; later manifest edits are unscanned.

## Files written by this slice

`docs/security/dependency-evidence-2026-10-06.md`, `docs/release/license-inventory.md`, `docs/release/sbom/{README.md,generate-cargo-cdx.py,cargo.cdx.json,npm-workspaces.cdx.json,mcp-server-runtime.cdx.json,controller-image-debian-packages.tsv}`, this record and `p07-dependency-2026-10-06/{discover-scan-targets.txt,socket-scan-alerts.tsv,socket-deep-*.md,cargo-tree-duplicates-x86_64.txt}`. *Final pass 2026-10-06 added `docs/release/sbom/{mcp-server-lib-runtime.cdx.json,mcp-bundle.cdx.json}`, regenerated `npm-workspaces.cdx.json` and `README.md`, and `p07-dependency-2026-10-06/{discover-scan-targets-final-2026-10-06.txt,final-pass-inputs-2026-10-06.txt,final-pass-scan-comparison-2026-10-06.txt}`; `LICENSES.md`, every manifest and both lockfiles were not edited.* Raw Socket JSON (scan views, 2.2 MB each) and the intermediate reports stay in the git-ignored scratch/`tmp/socket-reports/` directories.
