# P05 operator Source provisioning UI — 2026-10-02

## Scope

This record covers the operator-facing half of fleet Source provisioning
(P04-D4, P05 PV06 GUI portion): the controller's provisioning state on operations,
the console "Provide Source" panel, the `kind=fleet` mode of the secret-input page
and the browser journeys against the real Rust controller. Scenario IDs follow the
vault plans where they exist: P05-PV06-S, P04-E03 and P05-E01 (GUI portion). The
controller state cases PV06-S10 to S17 were added to the authoritative vault test
plan after implementation (2026-10-02); the GUI case titles remain test-title names
without separate vault IDs.

The browser journeys are the **API-node-fixture variant**. The node is a
test-only JavaScript fixture (`packages/console/e2e/support/fleet-node.ts`) that
enrolls through the admin API, opens a node session, signs events and offers with
generated Ed25519 keys from `node:crypto`, and reads its inbox. The controller
accepts the JavaScript-signed offer, which is itself an interoperability check.
There is no real broker, no `blindpass-node` process, no systemd identity, no Unix
control socket, no desktop approval app and no Omarchy session in any run below.

## Plaintext and lifetime

The Source value is consumed by two parties only. The operator's browser holds it
in the input field and in short-lived page memory until it is sealed with HPKE to
the node's one-use offer key (X25519, HKDF-SHA256, ChaCha20-Poly1305, AAD bound to
the signed offer binding) and is then cleared. The recipient (in production the
node's broker; in these runs the test fixture, holding the offer private key) opens
the delivery. The controller, the console page and the network see ciphertext
only. The console panel never receives, stores or logs the link: the input path is
used for one `window.open(..., "_blank", "noopener,noreferrer")` call. The input
page sends no Source or link in a URL, storage, console message, error text or i18n
parameter. JavaScript strings have no forensic erasure guarantee.

All values typed by tests are generated dummy canaries. The main journey types
`" <random canary> é漢字🔑"` (a leading space, an accented letter, CJK and an
astral character).

## What changed

- **Controller.** `provisioning` object (`state`, `offer_expires_at_ms`,
  `can_provide`) on operation detail and list items, from the same authority checks
  as the link route (`authority_core!` with the owner rule switched off only for
  the read), so `can_provide` cannot be weaker than the route. States:
  `not_applicable`, `awaiting_offer`, `offer_ready`, `link_issued`, `submitted`,
  `expired`. No link id, signature, key, ciphertext or link is ever included.
  OpenAPI, generated types and `openapi-types.test.ts` (schema version 12 to 16)
  updated.
- **Console.** `ProvideSourcePanel` on the operation detail with every state, 3 s
  polling while a state can change, the remaining offer time on the controller
  clock, role rules, a stable per-operation `Idempotency-Key`
  (`console-source-<operation id>`, hashed if too long), English and Vietnamese
  strings. One breadcrumb CSS rule so a long operation id wraps (see findings).
- **Input page.** `kind=fleet` mode: strict link parsing, same-origin operator
  cookie and `x-csrf-token` from `bp_csrf` in fleet mode only, verified offer,
  server-time deadline, exact UTF-8 bytes up to 65 536, the specified outcome states,
  clearing on terminal, hidden and `pagehide`. It seals only through
  `sealVerifiedBrowserSource` with the controller's time, never `sealBrowserSource`.
  Details: [browser-ui README](../../../packages/browser-ui/README.md).
- **Test support.** `scan.ts` (fail-closed canary scanner with a positive control),
  `fleet-node.ts`, `provisioning-world.ts`, a `vite preview` plugin that serves the
  embedded input page like the controller does (preview profile only).

## Executed checks

Environment: Linux, Node 26.10.0, Chromium from the locked Playwright, controller
built to `target/agent-u` after `npm run build`, disposable PostgreSQL on
`127.0.0.1:5433`. Playwright ran one process at a time.

| Check | Command or evidence | Result |
|---|---|---|
| Controller provisioning state, 8 tests | `cargo test -p blindpass-controller --test fleet_provisioning_state --locked -- --test-threads=1` (PostgreSQL adds `P02_TEST_BACKEND=postgres P02_TEST_POSTGRES_URL=...`) | SQLite 8 pass; PostgreSQL 8 pass |
| Whole controller crate | `cargo test -p blindpass-controller --locked [--no-fail-fast] -- --test-threads=1` | SQLite 28 binaries, 203 pass, 0 fail, 4 ignored; PostgreSQL the same (includes `fleet_provisioning_submit` 24, `fleet_provisioning_offers` 11, `embedded_ui` 5) |
| Clippy | `cargo clippy -p blindpass-controller --all-targets --locked -- -D warnings` | exit 0 |
| OpenAPI | `npm run generate:api` (no further diff), `npm run test:controller-openapi` | 13 pass |
| OpenAPI types | `npm run test:openapi-types --workspace=@blindpass/contract-tests` | 1 pass |
| Console unit | `npx vitest run` in `packages/console` | 11 files, 105 pass; the new `provide-source.test.tsx` has 17 |
| Input page unit | `npm test --workspace=@blindpass/browser-ui` | 57 pass: `fleet-flow` 12 (real signed offer and real HPKE open), `fleet-page-source` 6, `lifecycle` 8, `clock` 8, `request-context` 6 |
| Locale validator | `npm run validate --workspace=@blindpass/i18n` and its 3 tests | valid; `browser-ui` 160 keys, `console` 875 keys in both languages; 3 pass |
| Build | `npm run build` | exit 0 |
| Root tests | `npm test` | exit 0: 23, 105, 42, 9, 80 passed with 101 skipped (SPS suites needing services), and node suites 57, 3, 108, 13, 2, 7, 146, all passing |
| Provisioning journeys | `npx playwright test e2e/provisioning.spec.ts`; embedded with `BLINDPASS_E2E_EMBEDDED=1`; PostgreSQL with `BLINDPASS_E2E_POSTGRES_URL=postgres://...` | 9 pass in each of preview/SQLite, embedded/SQLite, preview/PostgreSQL and embedded/PostgreSQL (the last run on its own after the full runs, on the same final build) |
| Full console E2E | `npx playwright test` in `packages/console` | see "Full console suite" |

### Provisioning journeys (`packages/console/e2e/provisioning.spec.ts`, 9 tests)

1. **Main journey (P05-PV06-S / P04-E03 / P05-E01 GUI).** The owner signs in to the
   console; the panel shows "waiting for the node" with no button; the fixture posts
   a JavaScript-signed offer; the button appears; the click opens a new tab with a
   null `window.opener` and the `kind=fleet` link; the page shows the verified
   purpose, workload, unit, credential and a countdown; the canary is typed and
   submitted. The node inbox then holds exactly one `provisioning_delivery` that
   opens with the offer private key to the exact typed bytes (hex-compared,
   including the leading space). The console shows receipt with no action. A
   byte-identical replay of the submit body answers 200 and adds no second
   delivery; a reload shows "Already submitted" and no field. The canary is absent
   from every request URL and body (the body carries only `{enc, ciphertext}`),
   console messages, page errors, CSP violations (none), storage, page HTML, the
   address bar, the Playwright artifact tree, the SQLite data directory (files
   scanned) and the controller log.
2. **Roles.** Other operator, administrator and viewer get 403 from the link route
   with no link material; a second operator sees the state and offer time but no
   button; a viewer's console route is role-gated; the owner's link shows "Sign in
   as the named operator" with a `/login` link to another operator, the
   administrator and an anonymous session, with no field and no submit request.
3. **Malformed and altered links.** Eight malformed `kind=fleet` variants (short,
   uppercase, bad signature, extra, duplicate, empty and foreign `kind`) show
   "unavailable" with zero `/api/` requests; an unknown well-formed link and a real
   link with an altered capability show "unavailable" (controller 403
   `provisioning_capability_invalid`) and never open a field.
4. **Expiry.** A 14 s offer: the open input page clears the typed value when the
   controller-timed deadline passes, says nothing was sent, and no submit request
   was made; the console flips to "The Source offer ended"; a new link request gets
   410.
5. **Second tab and conflict.** Reopening reuses one link (one idempotency key on
   both link requests); the first tab submits; the second tab, with a different
   value, gets 409 and "already submitted"; the node holds exactly the first
   tab's bytes.
6. **Lost reply.** The controller stores the ciphertext and the browser's reply is
   aborted; the page reconciles from the receipt ("The connection dropped, but a
   re-check shows the controller holds the receipt") with one POST and one delivery.
7. **Refusals.** A 429 keeps the value; a 503 with no receipt shows "Submission not
   confirmed", is not repeated for 1.5 s and by "Check again", and nothing was
   delivered; a fresh page for the same live link then delivers the same value once.
8. **Clearing.** The hidden-page and `pagehide` handlers clear the typed value
   (events are dispatched, see limits); a reload keeps the link but starts empty and
   ready again.
9. **Vietnamese and keyboard.** Console and input page follow the locale; Tab,
   typing and Enter alone submit; the delivery decrypts to the typed value.

### Accessibility (`e2e/a11y.spec.ts`, one new test)

The operation detail with the panel (waiting, offer ready, link issued, submitted)
and the input page (ready, submitted, refused) at 320, 390, 768, 1024 and 1440 px:
no horizontal overflow, axe (WCAG 2.x A/AA, 2.2 AA, best practice) clean at 390 and
1440 px, and a keyboard focus walk with a visible indicator on every stop.

### Canary scanner

`e2e/support/scan.ts` throws when a root is missing or yields no files, searches
raw bytes and file names for the canary as UTF-8, URL, JSON, `\u` escapes, hex,
UTF-16 and base64/base64url at all three alignments, inflates ZIP and trace
entries, reads a ZIP cut off before its directory entry by entry, and reports an
archive with nothing readable as a finding. A positive control plants the canary in
10 forms (including a deflated and a truncated ZIP) beside clean files and must
find every one. The spec runs it on the whole Playwright output root, so artifacts
of other specs in the same run are scanned too.

Playwright tracing is off for `provisioning.spec.ts` (`trace: "off"`), because the
recorder stores the text a test types in the live trace. An earlier version with
tracing on found the canary in the in-flight `.trace` file, which confirms the
scanner works on real Playwright artifacts and why the trace is off.

## Full console suite

`npx playwright test` in `packages/console`, 75 tests including the new ones.

| Profile | Result |
|---|---|
| preview, SQLite | 74 pass, 1 skipped, 0 fail |
| embedded, SQLite | 74 pass, 1 skipped, 0 fail |
| preview, PostgreSQL | 74 pass, 1 skipped, 0 fail |

The one skip is `P04-E04 / DR-E23 rollback`, which needs
`BLINDPASS_E2E_PREVIOUS_CONTROLLER_BIN`; it was not set. Affected existing specs
(approvals, fleet, input, a11y, embedded, locale, settings, admin, auth) are part of
these runs.

## Findings fixed during the work

- The operation detail overflowed horizontally by 130 px at 390 px and 200 px at
  320 px because its breadcrumb held the unbreakable operation id (pre-existing;
  `/operations/:id` was in no accessibility route list). One CSS rule fixes it.
- A first full run failed `SI-E01` in the existing input spec: the new fleet purpose
  hint repeated the legacy hint text, so `getByText` matched two elements. The fleet
  copy was reworded and a unit guard now rejects fleet-only copy equal to legacy
  copy in either language (red, then green).
- A 403 that names a bad capability (`provisioning_capability_invalid` or
  `_required`) now shows "unavailable" instead of "Sign in as the named operator".
  Other 403 answers still ask for sign-in.
- A Playwright test that times out leaves a truncated `trace.zip` (no central
  directory); the first scanner version reported it as unreadable. It is now read
  entry by entry, with a control.
- One full PostgreSQL controller run failed `pv06_s14` once with a 408 on a fixture
  login (the controller's 10 s request limit) while the host was busy (one-minute
  load average up to 6.8). The test passed 3 of 3 times alone and
  the whole crate then passed on PostgreSQL (203 pass). Treat it as host-load
  sensitivity of a 14-fixture test, not a product result.

## Limits and what is not established

- No real broker, `blindpass-node` process, systemd VM, stock client, desktop
  approval app, Omarchy session or hosted CI run. The fixture is not a broker; it
  proves the controller, console and page contracts, not broker custody or use of
  the Source.
- Test-first held for the controller state tests (red before the implementation),
  the capability mapping and the copy guard. The other new browser-ui, console unit
  and E2E tests were written against implemented code and have no separate red run.
- The hidden-page and `pagehide` clearing is exercised by dispatching the events.
  A real tab switch, window minimise or back/forward-cache restore was not driven.
- The `Idempotency-Key` is stable per operation, not fresh per click, because an
  exact retry returns the link only for the same key. Reopening is therefore
  idempotent by design.
- The signed capabilities stay in the input page's address bar. The controller
  selects the page only when `id`, `metadata_sig` and `submit_sig` are present and
  reload recovery needs them; they are short-lived, scoped and useless without the
  named operator's session.
- Fleet mode needs the page served by the controller (embedded) or the preview
  plugin; a build with a cross-origin API origin refuses fleet links. The preview
  plugin mirrors the controller's routing and is test support, not a production path.
- Viewers cannot read operations (existing authorization), so they see no
  provisioning state. The console gates the route instead.
- PostgreSQL data was not scanned for the canary (the controller stores ciphertext
  only; the SQLite directory and the controller log were). The scan proves absence
  from the files named above, not from process memory.
- The console policy editor and some OpenAPI enums still list only `noop.marker`,
  `file` and `socket`; `browser.session` rules were set through the API.
- `window.open` runs after an awaited request, so a strict popup blocker can stop
  it; the panel then says to allow pop-ups and press again.
