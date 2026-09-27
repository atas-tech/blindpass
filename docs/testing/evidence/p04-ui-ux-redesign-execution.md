# P04 operator interfaces and secret-input redesign: execution record

**Date:** 2026-09-28. **Plan:** [P04](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/phases/04-ui-ux-redesign.md). **Scenarios:** [P04 tests](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/testing/phases/04-ui-ux-redesign.md), [DR catalog](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/testing/Dashboard%20Redesign.md), [SI catalog](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/testing/Secret%20Input%20Redesign.md).

**Status:** All 13 slices are implemented as local commits, which have not been pushed. The gates below were run locally against real Rust controllers on SQLite and, where stated, PostgreSQL. **This is not an acceptance record.** P04 acceptance needs the owner's review row in the plan. It also needs the items under [Not run](#not-run) and [Decisions for the owner](#decisions-for-the-owner): P04-D4 provisioning is blocked, and there has been no real Omarchy session run and no hosted CI run.

## Tested tree and environment

- Code: the 13 P04 slice commits from `bcab450` to the slice 13 commit that adds this record. The base is P03 at `2100222`; `6ae65ec` is an i18n fix.
- Host: Omarchy 4.0.4 on Arch Linux; Node.js 26.10.0; Playwright 1.58.2 with Chromium headless shell 1208; Rust 1.98.1; Quickshell 0.3.1 with Qt 6.11.2 (`/usr/lib/qt6/bin/qmltestrunner`); curl 8.22.0; PostgreSQL 16 at `127.0.0.1:5433` from the local test Compose file.
- Every browser and desktop run starts its own controller in test mode, using a temporary SQLite file or a throwaway PostgreSQL schema. Keys, passwords, tokens and secret values are generated dummies or canaries. None are kept in the repository or in this record.

## Slices

| Slice | Commit | Scope |
|---|---|---|
| 1 | vault only | D0 review artefacts: route/role/state matrix, screen/API list and EN/VI copy, recorded in the vault dashboard design note. Owner sign-off is pending |
| 2 | `bcab450` | `assets/ui`: shared tokens, Inter 4.1 variable (Latin, Latin Extended-A, Vietnamese) with OFL and provenance, and icons. Computed WCAG 2.2 AA contrast test (P04-I01) |
| 3–4 | `30a1339`, `92e791f` | React console scaffold, sign-in/setup/settings, typed client with CSRF, auth E2E against the controller |
| 5 | `6fbb722` | Overview and approvals queue/detail with a reconciling decision flow |
| 6 | `c8a468a` | Agents, exchange policy editor, audit log and exchange timeline |
| 7 | `fc29122` | Fleet: enrollments, nodes, workloads, fleet policy, grants, operations |
| 8 | `653296e` | `/settings/operators` and the unavailable page for retired hosted paths |
| 9–10 | `2cf3c39`, `342cb40` | Secret-input page rebuilt on the P04 state machine; CT19 reconciliation of unconfirmed submits |
| 11 | `daf6f95` | P04-D3 desktop session transport and the Quickshell approval app |
| 12 | `ed5adb3` | Metadata-only Omarchy bar widget |
| 13 | this commit | Embedding (P04-D9), P04-E04, CC02/CC03 runner relocation, dashboard marked removable, the fixes listed below |

## Slice 13 changes and findings

- **Embedding.** The controller serves `packages/console/dist` at `/`. It serves `packages/browser-ui/dist-embedded` at `/` when the query has a complete signed link (`id`, `metadata_sig`, `submit_sig`), and that page's assets under `/input/`.
  - Headers: the P04 CSP as a response header, plus `X-Frame-Options: DENY`, COOP `same-origin` and the Permissions-Policy.
  - Caching: pages are `no-store`; hashed `/assets/*` are `public, max-age=31536000, immutable`.
  - The shell is served only for GET/HEAD inside the console's route sections. A non-GET request in those sections gets 405 with `Allow: GET, HEAD`.
  - Every other miss keeps the controller's SPS-compatible JSON 404.
  - The section list is checked against the router by `packages/console/src/embedded-routes.test.ts`.
- **Build order.** `npm run build` must run before `cargo build`, because `build.rs` embeds whatever is in the two dist directories at compile time. A build without them serves no UI, and `tests/embedded_ui.rs` checks that case. CI now builds the workspace first.
- **Regression found and fixed:** the first fallback served the console shell for any extension-less path. The Rust contract suite caught it: CT18 expects `GET /route-that-does-not-exist` to return the JSON 404. The fix is the section allowlist above. CT01–CT19 now pass again on both stores.
- **Hardening (pilot O05).** Requester text can contain bidi overrides, terminal escapes and zero-width characters. These now display as visible code points such as `⟨U+202E⟩` and are never applied. The isolated block uses `unicode-bidi: isolate` and `dir="auto"`. This covers the console's untrusted blocks and audit metadata, the desktop app's purpose, and the input page's description. Before this, a purpose containing U+202E could visually reverse part of itself.
- **Harness fix.** Under `vite preview`, Chromium failed every request after about seven full reloads in one browser context with `net::ERR_INSUFFICIENT_RESOURCES`. The embedded controller passed 25 reloads.
  - The preview server's `Cache-Control: no-cache` revalidation was the trigger; the Chromium net-log shows no network-stack error.
  - The preview server now serves the embedded cache profile (pages `no-store`, hashed assets immutable), so it matches production and passes.
  - The Chromium root cause is not identified. It does not affect the embedded product path.
- **Accessibility sweep found and fixed two defects.** The new `a11y.spec.ts` covers every route at every declared width.
  - `/audit`'s table spilled out of its panel at 768–1024 px, by about 165 px. It now scrolls inside a positioned `.table-wrap`; being positioned also contains the visually hidden header text that leaked 2 px at 320 px.
  - The overview's text links were 32 px tall on touch. Text links and text buttons now meet 44 px on coarse pointers.
- **Relocation.** The P02 CC02/CC03 runner moved from `packages/dashboard/e2e` to `packages/console/p02-browser` (`npm run test:p02-browser --workspace=@blindpass/console`), and CI calls it there.
  - The dashboard's `browser-ui-locale.spec.ts` (scenarios 501/502) tested the pre-P04 input page, which slice 9 replaced. It is superseded by a console input E2E: browser language selects VI or EN, and a stored choice wins on reload.
- **Dashboard.** `packages/dashboard` is marked eligible for removal in `LICENSES.md`, the architecture page and the docs index.
  - Its remaining specs, image (`packages/dashboard/Dockerfile`, `build-and-push-images.yml`) and Unraid template belong to the hosted SPS stack. They go with the package; SPS retirement stays in P08.
  - No controller image or template exists yet. P06 packaging must build the workspace before the controller.

## Gate results (2026-09-28)

| Gate | Result |
|---|---|
| `npm run build` | Pass. Console initial route 156.9 kB gzip against the 250 kB budget (`packages/console/scripts/check-bundle.mjs`, which also rejects CDN references) |
| `npm test` | Pass. Console, browser-ui, i18n, agent-skill, gateway and dashboard suites pass; SPS keeps its 101 pre-existing database-gated skips |
| `cargo fmt --all -- --check`; workspace Clippy `-D warnings` | Pass |
| `cargo test --workspace --locked` | 285 passed, 4 ignored: the three desktop E2E tests (run below) and the PostgreSQL outage test |
| Controller on PostgreSQL (`P02_TEST_BACKEND=postgres`): `desktop_session`, `admin_session`, `store_transitions`, `fleet_approvals`, `embedded_ui` | 8, 4, 35, 7 and 5 passed |
| Rust contract suite `SUT=rust`, SQLite and PostgreSQL, with the no-skip and progress gates | 40/40 Vitest cases and 20/20 contract cases on each store, no skips |
| P02 clients (`test:p02:clients`, SQLite); CC02/CC03 browser runner from its new location, SQLite and PostgreSQL | Pass; 3/3 on each store |
| OpenAPI generation (`--check`), drift and route inventory | Pass; 12/12 |
| `npm run test:desktop` | Session helper 10/10, approval-app QML 50/50 (31 library, 19 view), widget 17/17, widget under Quickshell 1/1 |
| `desktop_app_e2e` (ignored by default), SQLite and PostgreSQL | 3/3 on each store |
| Console Playwright, preview profile (`npm run test:e2e --workspace=@blindpass/console`) | 65/65, including rollback |
| Console Playwright, embedded profile (`npm run test:e2e:embedded`) | 65/65: the same journeys served by the controller itself |
| Console Playwright on PostgreSQL (`BLINDPASS_E2E_POSTGRES_URL`, preview profile) | 65/65; no schema left behind |

The three console runs are the final ones, after every fix above, and all three set `BLINDPASS_E2E_PREVIOUS_CONTROLLER_BIN`. The rollback case ran against a build of `ed5adb3`, the previous commit, which has no embedded UI. Each run has 65 tests across 9 spec files and none skipped. Earlier runs during slice 13 found the defects listed above. One earlier preview run had a failure in the I10 fleet case while a second Playwright process shared its `test-results` directory. That was a harness collision, not a product result; the case passed in all three final runs.

## Scenario coverage

"Pass" means an executed test with that ID passed in the runs above. The test files are under `packages/console/e2e`, `packages/console/src`, `packages/browser-ui/tests`, `assets/ui/tests`, `desktop/*/tests` and `crates/blindpass-controller/tests`.

### P04 phase scenarios

| ID | Status | Evidence and limits |
|---|---|---|
| P04-I01 | Pass | `assets/ui/tests/tokens.test.mjs` computes contrast from the one token file. `test:ui-assets` fails when the landing copy drifts. All three UIs build from `assets/ui`. The embedded E2E checks self-hosted Inter and that no request leaves the controller origin |
| P04-I02 | Pass | Five console E2E cases: expiry mid-decision, lost reply after apply, request never arrived, viewer direct write refused, setup race with one winner |
| P04-I03 | Pass | CT19 capability is minimal and scoped; a 410 after a lost reply is never failure and never resubmits; expired credentials get 410 on both routes |
| P04-I04 | Pass (portable) | Widget source inspection and summary reader. The IPC target exposes only show/hide (`desktop_app_e2e`). The summary file holds only `v`, `state`, `pending`, `updated_at`. Same-UID separation is not claimed |
| P04-I05 | Pass | Failed reads show "Unavailable", never zero. Fleet routes are absent when the controller lacks `fleet.v3` (DR-E25) |
| P04-E01 | Partial | Bootstrap, enroll with the exact fingerprint, register, edit and revoke a workload, approve exact scope, audit (fleet and approvals specs; full suite on the embedded build). **Provision is not implemented (P04-D4).** Operations and grants run end to end only as empty and refused states, because creating them needs broker evidence from a live node; their copy is component-tested |
| P04-E02 | Partial | The real app runs offscreen against a real controller: sign-in, a decision on a real pending operation, restart rotation, sign-out revocation, revoked-token cleanup, redirect refusal and unverified-certificate refusal. **Not run:** a real Omarchy/Hyprland session (lock, logout, shell restart), a remote TLS controller, trust rotation |
| P04-E03 | Pass | Ten input states in EN/VI at 320–1440 px with long text, axe, 44 px targets and reduced motion; multiline exact bytes; reveal/clear; tab suspension simulated with Playwright clock and visibility events (not a real OS suspend) |
| P04-E04 | Pass | `embedded.spec.ts`: deep-link reloads under the CSP header with no violations, cache headers, misses, the same-origin input page, and rollback to the previous artifact on the same database with sessions intact. The CC02/CC03 runner survives relocation. The full console suite passes on the embedded build |

### DR catalog

| ID | Status | Notes |
|---|---|---|
| DR-E01 | Pass with deviation | Retired hosted paths show a static unavailable page with a docs link, per the P04 route matrix. The catalog says removed routes redirect to `/`; the plan's matrix was followed. Owner to confirm |
| DR-E02, DR-E04, DR-E08–E15, DR-E17, DR-E20, DR-E24, DR-E25, DR-I01, DR-I05 | Pass | Console E2E against the controller, with the API cross-checks named in each test |
| DR-E03 | Pass | Phone navigation, queue/detail stacking, no overflow |
| DR-E06 | Pass | `locale.spec.ts`: VI chosen at sign-in holds on 13 screens at 390 and 1440 px, through reload and sign-out/in. Each page is scanned for any English catalog string that has a different VI translation (a control proves the scan finds English on an EN page) |
| DR-E07 | Pass (automated) | `a11y.spec.ts`: 13 routes at 320/390/768/1024/1440 px with no horizontal overflow, axe at 390 and 1440 px, 44 px touch targets, a 200% zoom equivalent (720 CSS px layout) and reduced motion (no transition or animation over 16 ms). Also the phone/queue cases in the approvals and fleet specs. **Manual screen-reader and real browser-zoom review not done** |
| DR-E16 | Pass (component) | Independent panel failures, retry and 403/429/500/network states in Vitest; the E2E covers the unavailable aggregate |
| DR-E22 | Pass (automated) | Keyboard walk of every route checks each focus stop for visibility, on-screen position and an indicator, and the skip link. Visual comparison with the landing mark and font is a manual review item |
| DR-E23 | Pass | Rollback case of `embedded.spec.ts`; UI-only release, same schema. Schema-changing rollback stays with P06 |
| DR-E26 | Pass | Assets come only from the controller origin; exact CSP with no font/CDN origins; Inter self-hosted and loaded; one token file (P04-I01) |
| DR-I02 | Pass | Controller RBAC, audit, agent rotation/revocation and policy validation on SQLite and PostgreSQL (`admin_session`, `store_transitions`, fleet tests) |
| DR-I03 | Pass | Contract suite CT08–CT13 within the full Rust run on both stores |
| DR-I06 | Pass | Build, unit suites, i18n validation, `cargo test`, contract suite with `SUT=rust`, console E2E |
| DR-E05, DR-E18, DR-E19, DR-E21, DR-I04 | Withdrawn | Withdrawn 2026-09-22 |

### SI catalog

| ID | Status | Notes |
|---|---|---|
| SI-E01–E06, SI-I01–I03 | Pass | Input E2E against the controller, separately hosted profile, plus the embedded same-origin page in `embedded.spec.ts`. SI-E01 now also covers bidi/escape display |
| SI-I04 | Pass | Workspace build/tests, CC03 on both stores, contract suite |

### Pilot cases named by P04

| ID | Status | Notes |
|---|---|---|
| CC03 | Pass | Relocated runner on SQLite and PostgreSQL; the input spec on the separate-origin profile |
| O04 | Partial | The widget follows the app's real summary file under Quickshell and shows stale after 90 s. A shell plugin restart inside a real Omarchy session was not run |
| O05 | Pass | Console, desktop and input page: markup inert, long text wraps, bidi/escape characters shown as code points, verified identity separate |
| I10 | Pass | Fleet E2E: a mismatched fingerprint can't be approved; the desktop bearer is limited to the approval routes (`desktop_session`) |
| E10 | Partial | Offline-node revocation in the console E2E; app restart keeps requests bound to the same identities. A real Omarchy lock/logout is not run |

## Not run

- A real Omarchy session: widget installed in `omarchy-shell`, lock, logout, shell restart (P04-E02, O04, E10). Doing it here would change the live desktop of the development host. A disposable Omarchy VM runner (`tests/desktop/omarchy-session.sh` in the plan) does not exist yet.
- A remote TLS controller for the desktop app, and certificate/trust rotation.
- P04-D4 provisioning handoff: no route and no UI control (see below).
- The packaged nginx input image and CC03's header check (needs Docker on the runner); the hosted `ci-full` run (commits not pushed).
- Manual accessibility review: screen reader, real browser zoom, touch devices.
- Real OS tab suspension. Suspension is simulated with the Playwright clock and visibility events.

## Deviations

- **P04-D9 embedding** uses a std-only `build.rs` with `include_bytes!` rather than `rust-embed`. The behaviour is the same and no dependency is added.
- **P04-D1 dependencies:** the console reuses the locked React/Vite/i18next/Playwright set, plus `axe-core` 4.13.0 as a dev dependency, with owner approval. This is a recorded deviation from Decision 0003 Tier B.
- **Operation audit** `/audit/operation/:id` is not built. `GET /api/v3/audit` is still `planned` in the controller OpenAPI, and the plan says not to reconstruct it from the exchange audit list. Operation detail links to its approval and grant instead.
- **Legacy zero-knowledge strings:** `packages/i18n` `auth.json` and `layout.json`, which only the old dashboard uses, still contain zero-knowledge copy. No new surface uses them.
- **Controller behaviours surfaced truthfully, not changed:**
  - An exchange approval's detail read returns 404 once its window has passed, even after a decision.
  - A non-admin operators POST with an invalid body gets 422 before the role check's 403. Nothing is written.

## Decisions for the owner

1. P04 review row: accept, reject or scope the phase against this record.
2. **P04-D4 provisioning** is blocked on three unspecified points: who retrieves the ciphertext, its HPKE context/AAD, and how cancellation or key rotation invalidates the link. The app shows no provisioning control until it is specified.
3. DR-E01: the unavailable page (the plan) or a redirect to `/` (the catalog).
4. Licensing: `desktop/approval-app` and `desktop/omarchy-widget` are recorded as AGPL-3.0-only in `LICENSES.md`, like the console. This needs confirmation.
5. Whether the operators route should authorize before validating the body (the 422-before-403 order above).
