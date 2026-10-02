# Repository test setup

This is the current command reference. The [Linux Fleet Pilot](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/testing/Linux%20Fleet%20Pilot.md) defines proposed W0–W6 acceptance scenarios; historical phase cases remain in the Obsidian vault. A passing workspace suite does not establish the new broker, browser or deployment guarantees.

The phase acceptance index and P00–P10 plans are maintained in the Obsidian vault. P01's portable Rust checks and disposable-VM harness are in this repository. Revised P01-I01 and P01-I06 checks passed on clean committed SHA `6d41a1f6df8d90d283b53b3c7241281937702ac2` in the selected local Ubuntu 24.04/QEMU-KVM profile on 2026-09-24. The user accepted W0 as NARROW for that tested systemd 255, no-TPM profile only; untested scenarios and other profiles remain open. A shared self-hosted CI runner remains an explicit prerequisite and is never inferred from hosted CI.

The proposed landing-aligned dashboard rebuild and secret-input acceptance plans are maintained in the Obsidian vault. The Rust controller implementation is complete locally and remains gated by the [Controller Contract Suite](Controller%20Contract%20Suite.md), an HTTP-level compatibility suite run against both servers, and by hosted CI. Current P02 execution and open acceptance items are recorded in the [P02 evidence report](evidence/p02-controller-api-migration-rerun.md) and the paired vault plan.

The secret-input redesign plan covers the companion input-page mockup's proposed SI scenarios and keeps prototype inspection separate from product E2E evidence in the vault.

## Environment

Run commands from the repository root with Node.js 26.x and installed lockfile dependencies. Use a disposable test database: suites and demo helpers create, alter or clean up workspace/account state. Keep real secrets out of fixtures and captured outputs.

```bash
npm ci
cp .env.example .env
```

Review the file, then export it in each test/migration shell:

```bash
set -a
source .env
set +a
```

Workspace scripts run inside their package directories. Root `.env` and package `.env.test` are not interchangeable, and `.env.test` is not loaded automatically. Explicitly export the chosen test file before invoking scripts; `DOTENV_CONFIG_PATH=.env.test` is useful for SPS's dotenv-enabled entry point only when the path resolves from that package.

## Services and preparation

```bash
docker compose -f docker-compose.test.yml up -d --wait
npm run db:migrate --workspace=packages/sps-server
npm run build
```

The harness maps PostgreSQL to `127.0.0.1:5433` and Redis to `127.0.0.1:6380`. `make up` starts the same services without waiting; `npm run redis:up` starts only Redis. Both Compose files use the same explicit container names/ports, so do not start them as independent simultaneous stacks.

For the local Rust controller, install `blindpass` and `blindpass-controller` together; its environment is described in [controller configuration](../architecture/README.md#controller-configuration). With the controller's file-backed database and key environment configured, run `blindpass migrate` to apply its schema before service startup. `blindpass admin bootstrap` creates the first administrator over the local administration socket and prints a one-time temporary password; `blindpass admin bootstrap-token` instead mints a one-use, 15-minute token for the HTTP first-run setup. In an isolated test profile only, `BLINDPASS_TEST_MODE=1 blindpass admin seed --fixture <file>` accepts a JSON object with an `agents` array. Optional `policy`, `rotated_agents`, `revoked_agents` and `local_admin: true` fields create richer VM fixtures. It prints generated test credentials and agent keys; keep that output out of logs. `blindpass admin reset-password <operator-id>` uses the private local administration socket and returns a one-time temporary password; the operator identifier comes from the administration API's operator list, and the CLI has no local listing command. An operator holding a temporary password can only read, refresh or end the session and change the password; every other administrative route answers 403 `password_change_required` until the change completes. `blindpass admin reconcile-clock` recovers the durable controller clock fence after a database or host clock regression, changed Linux boot ID, or unreadable boot ID. Run it with the controller stopped. It deletes secret requests, exchanges, pending and approved approvals, bootstrap tokens, rate windows and idempotency keys; revokes operator sessions; resets the database/host/boottime/boot-ID anchor; and writes one `clock_reconciled` audit event with the counts. Operators, agents, policy, rejected approvals and history are kept. With a healthy unfenced clock it changes nothing and prints `regression_detected: false`.

The isolated test harness consumes fixture plaintext from the seed command's stdout in memory and should discard it after the run; the controller does not write agent keys, refresh tokens or temporary passwords in plaintext to its database. The seed access token lasts 15 minutes. An opt-in local browser session's refresh token lasts at most 30 days with a 12-hour idle limit; each refresh issues a successor with a new 30-day expiry, so a session family used within the idle limit has no absolute lifetime. Agent keys remain usable until rotation or revocation. The session's CSRF secret is stored in controller state for validation. The reset command likewise exposes its temporary password once on stdout; deliver it directly to the intended local operator and require a password change at login.

The root build invokes the plugin bundler as well as TypeScript/Vite. Its [build script](../../scripts/build_bundle.sh) currently invokes esbuild through `npx`; missing tooling/network access can block that step. This is not evidence of an application test failure.

## Test matrix

| Command | What it runs | Additional requirements |
|---|---|---|
| `npm test` | Ordinary workspace tests, excluding the separately gated P00 contract package | Built shared package inputs where imported; gated DB/Redis suites can skip |
| `npm test --workspace=packages/sps-server` | SPS Vitest suite | Same gating behavior |
| `npm run test:integration` | SPS Redis integration | Redis; script sets `SPS_REDIS_INTEGRATION=1` |
| `npm run test:e2e --workspace=packages/sps-server` | SPS `tests/e2e.test.ts` | PostgreSQL and `DATABASE_URL`; script sets `SPS_PG_INTEGRATION=1` |
| `SPS_PG_INTEGRATION=1 npm test --workspace=packages/sps-server` | Wider SPS tests including PostgreSQL-gated cases | Disposable PostgreSQL database; Redis integration still has its separate flag |
| `npm run test:e2e` | Dashboard Playwright suite | PostgreSQL, Redis, Chromium and available local application ports |
| `npm run test:release-metadata` | Version, staged package files and npm entrypoint metadata | Plugin dist artifacts; test builds them if absent |
| `npm run test:landing` | Landing workflow demo and JavaScript syntax checks | No external services |
| `npm run test:skill-install` | Installer regression | See script prerequisites and generated bundle |
| `npm run test:audience-packaging` | Audience packaging paths | See script prerequisites and generated bundle |
| `npm run test:openclaw-activation` | OpenClaw activation contract harness | Defined local harness, not proof of every released OpenClaw version |
| `SUT=ts CONTRACT_DATABASE_URL=... CONTRACT_REDIS_URL=... npm test --workspace=@blindpass/contract-tests` | P00 CT01–CT18 and CC01 against a child TypeScript SPS over HTTP, plus the TypeScript side of CV01–CV06 | Disposable PostgreSQL and Redis; run `npm run build` first |
| `node --import tsx scripts/tests/p00-base-contract.mjs` | The same HTTP cases through `SUT=base` against a separately spawned SPS | Same services as the TypeScript run |
| `SUT=rust CONTRACT_RUST_BACKEND=sqlite npm test --workspace=@blindpass/contract-tests` | Rust HTTP contract suite, including adopted CT19, compared with the TypeScript snapshot through reviewed semantic projections | Build the controller first (`cargo build -p blindpass-controller --locked`). The adapter starts it with an isolated SQLite database; hosted-user CT14 runs only against TypeScript SPS. The CV tests in this package check only the TypeScript implementations; the Rust side runs in `cargo test` |
| `SUT=rust CONTRACT_RUST_BACKEND=postgres CONTRACT_DATABASE_URL=... npm test --workspace=@blindpass/contract-tests` | Same Rust HTTP contract suite against PostgreSQL | Adapter creates and removes an isolated schema in a disposable PostgreSQL database |
| `node scripts/tests/assert-contract-progress.mjs <vitest-json> packages/contract-tests/fixtures/rust-pending.json` | Rust progress gate: every required case passes exactly once, CT14 stays excluded, and no suite fails in a hook or outside the CT cases | A Vitest JSON report from a Rust run (`-- --reporter=json --outputFile=<file>`); pair it with `scripts/tests/assert-no-vitest-skips.mjs` |
| `npm run test:contract-progress` | Unit tests of the progress gate itself | None |
| `npm run generate:api`, `npm run test:controller-openapi`, `npm run test:openapi-types --workspace=@blindpass/contract-tests` | Controller OpenAPI generation and drift, the documented-versus-mounted route inventory, and a type-checked generated-type test | Run `git diff --exit-code -- packages/contract-tests/src/generated/controller.d.ts` afterwards, as CI does |
| `SUT=rust CONTRACT_RUST_BACKEND=sqlite npm run test:p02:clients` | P02 CC02 gateway, agent-skill and OpenClaw request/exchange flows against Rust | Node.js `tsx` loader; set `CONTRACT_RUST_BACKEND=postgres CONTRACT_DATABASE_URL=...` to use PostgreSQL |
| `npm run test:p02:crash` | P02-I03 process termination/restart cases for compatibility and exchange retrieval, policy CAS and approval/audit transactions | Build a separate binary with `CARGO_TARGET_DIR=target/p02-failpoints cargo build -p blindpass-controller --features p02-test-failpoints --locked`; set `CONTRACT_RUST_BIN`, `SUT=rust`, the backend variables and, as CI does, `CONTRACT_REQUEST_TTL_SECONDS`, `CONTRACT_SUBMITTED_TTL_SECONDS` and `CONTRACT_APPROVAL_TTL_SECONDS` to `180`. Uses localhost and an isolated SQLite DB or disposable PostgreSQL schema |
| `npm run test:p05:fixture` | P05.1 HTTPS application suitability preparation: 13 HTTP cases plus a real Chromium sign-in/report/denial/copied-cookie replay case | Node/OpenSSL, loopback socket permission and the locked Playwright Chromium build; sandbox enabled. `npm test` includes the 13 HTTP cases. Does not establish helper, broker, stock-client or two-host acceptance; see [P05 harness](../../tests/browser-handoff/README.md) |
| `npm run test:p05:oauth` | P05.1 disposable issuer config/HTTP security and native Chromium form/callback regressions, three cases | Same TLS/browser prerequisites; `npm test` includes the two config/HTTP cases |
| `npm run test:p05:grafana` | P05.1 real managed Grafana account/role/report/revoke checks and live original five-minute session maximum through token rotations | `P05_GRAFANA_HOME` containing checksum-verified OSS 13.2.3 assets; disposable loopback HTTPS/Unix socket; about five minutes; application prerequisites only |
| `NODE_OPTIONS=--import=tsx SUT=rust CONTRACT_RUST_BACKEND=sqlite npm run test:p02-browser --workspace=@blindpass/console` | P02 CC02 `e2e-human.mjs` browser flow and CC03 signed/expired browser-link flows (moved from `packages/dashboard` in P04 slice 13) | Chromium and isolated SQLite controller; use `CONTRACT_RUST_BACKEND=postgres CONTRACT_DATABASE_URL=...` for PostgreSQL |
| `cargo fmt --all -- --check` | P01/P02 Rust formatting gate | Rust toolchain pinned by `rust-toolchain.toml` |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | P01/P02 Rust lint gate | Native `libsystemd`/OpenSSL development libraries |
| `cargo test --workspace --locked` | P01/P02 unit tests (including the Rust side of CV01–CV06), SQLite store, shell, admin HTTP, socket and CLI tests, transport-boundary and HPKE interop tests | Unix-socket operations; rerun outside restricted sandboxes if required. The PostgreSQL-only outage case reports ignored |
| `P02_TEST_BACKEND=<sqlite\|postgres> cargo test -p blindpass-controller --test store_transitions --locked` | P02-I01/I02 store transitions: races, expiry before sweep and after restart, lock waits, tenant isolation, sessions, operators, clock mark and reconciliation | Set `P02_TEST_POSTGRES_URL` for PostgreSQL; each run uses an isolated schema |
| `cargo test -p blindpass-controller --test shell_config --locked` | Production config, migration, clock reconciliation and test fixture shell checks | Some cases bind localhost and require socket permission; set `P02_TEST_BACKEND=postgres` and `P02_TEST_POSTGRES_URL` for the PostgreSQL variants of the seed, clock-reconciliation and pool-loss cases; the other cases always use SQLite or no database |
| `P02_TEST_BACKEND=<sqlite\|postgres> cargo test -p blindpass-controller --test admin_session --locked` | P02-I04–I06 HTTP bootstrap race, sessions, CSRF, forced password change and the admin/operator/viewer role matrix | Binds localhost; set `P02_TEST_POSTGRES_URL` for PostgreSQL |
| `P02_TEST_BACKEND=<sqlite\|postgres> cargo test -p blindpass-controller --test security_perf_regressions --locked` | Login attempt limit, hashed operator access tokens, schema migration, and idle node poll write behavior | Binds localhost; set `P02_TEST_POSTGRES_URL` for PostgreSQL. Schema version 14 removes previous operator sessions, so sign in again after migration |
| `P02_TEST_POSTGRES_URL=... cargo test -p blindpass-controller --test postgres_outage --locked -- --ignored` | P02-I07 PostgreSQL outage and reconnection without a controller restart | Ignored by default; the database role must be able to create roles, as the CI and local Compose superuser can |
| `cargo test -p blindpass-cli --locked` | CLI dispatch for migration, clock reconciliation, test fixture seeding and socket password reset, plus authenticated fleet enrollment, node rotation, token-file permissions and revoke confirmation | The controller executable must be installed beside the CLI in deployed environments; fleet CLI tests use loopback HTTP and curl |
| `npm run test:e2e --workspace=@blindpass/console` | P04 console and secret-input journeys (DR-E*, SI-E*, P04-E01/E03/I02–I05) against a real Rust controller; the console runs behind `vite preview` with a same-origin API proxy and the embedded cache profile, and the input page from its own origin. `e2e/embedded.spec.ts` (P04-E04, DR-E26, DR-E23) always uses the controller's embedded UI | Run `npm run build`, then `cargo build -p blindpass-controller --locked`, then install Chromium (`npm exec --workspace=packages/console -- playwright install chromium`). Each spec starts an isolated controller in test mode on a temporary SQLite file, or on PostgreSQL in a throwaway schema when `BLINDPASS_E2E_POSTGRES_URL` is set |
| `npm run test:e2e:embedded --workspace=@blindpass/console` | The same journeys on the embedded build: the controller serves the console at `/` and the input page for signed links (P04-D9), plus the P04-E04 spec for deep-link reloads, the CSP header without violations, cache headers and the same-origin input page | Build order matters: `npm run build` before `cargo build`, because the controller embeds `packages/console/dist` and `packages/browser-ui/dist-embedded` at compile time. The spec fails if the binary embeds no console. Set `BLINDPASS_E2E_PREVIOUS_CONTROLLER_BIN` to a build of the previous commit to run the rollback case, otherwise it reports skipped |
| `cargo test -p blindpass-controller --test embedded_ui --locked` | Embedded routing: SPA fallback only for client routes, CSP and page headers, immutable hashed assets, 404 for asset and API misses, 405 for non-GET, signed-link input page | Without a prior `npm run build` the build embeds nothing and the tests check the no-UI behaviour instead |
| `npm run test:desktop` | P04 desktop surfaces: session-store helper permissions and atomic writes, approval-app library and view suites (qmltestrunner, fake controller), widget summary reader and source inspection, and the widget under Quickshell following real helper output | Qt 6 `qmltestrunner` (default `/usr/lib/qt6/bin/qmltestrunner`, or `QMLTESTRUNNER`) and `quickshell`; exits 2 with a SKIPPED message when either is missing |
| `cargo test -p blindpass-controller --test desktop_session --locked` | P04-D3 desktop session transport: bearer login without cookies, Origin refusal, temporary-password refusal, approval-only scope, rotation and family revocation, 20-minute access cap, logout, role change, password change and removal | Binds localhost; set `P02_TEST_BACKEND=postgres` and `P02_TEST_POSTGRES_URL` for PostgreSQL |
| `cargo test -p blindpass-controller --test desktop_app_e2e --locked -- --ignored` | P04-E02 app portion and P04-I04 IPC surface: the real Quickshell approval app offscreen (curl transport, session helper) against an in-process controller holding a real pending operation approval; restart rotation, sign-out revocation, revoked-token cleanup, redirect refusal, unverified-certificate refusal | Ignored by default; needs `quickshell`, `curl`, `openssl` and `timeout`. Not a real Omarchy session |
| `./tests/fleet/p01-vm.sh` | P01 real systemd guest harness | Named QEMU/KVM runner with writable `/dev/kvm`, pinned image hash, SSH key, cloud-localds and an ISO writer; exit 78 means unsupported/blocking infrastructure |
| `./tests/fleet/p03-vm.sh --backend both` | P03 two-guest fleet authorization on SQLite and PostgreSQL, including key rotation, durable event replay, protocol-mismatch fail-stop/recovery, bounded reconnect backoff, stale signed time-reply rejection after broker restart, suspend-aware expiry, denial of an unconsumed grant after guest reboot, delayed expired-grant audit, connected revocation and recovery | Named QEMU/KVM runner, pinned Ubuntu 24.04 image, writable `/dev/kvm`, and a PostgreSQL endpoint for the PostgreSQL pass; see [fleet runner setup](../../tests/fleet/README.md#p03-fleet-authorization-runner) |

For the packaged P02 browser check, build `packages/browser-ui/Dockerfile`, run the image on a disposable loopback port and set `P02_PACKAGED_BROWSER_UI_URL` to that origin when invoking `test:p02-browser`. The suite then serves the page from nginx and adds a response-header check; it still starts the Rust controller at port 3100 and runs CC02/CC03. Stop the container after the run.

Inspect skipped-test counts. `npm run test:e2e` at the root is the frozen SPS-backed **dashboard E2E** (`packages/dashboard` is eligible for removal after P04 slice 13; its specs stay until the package is deleted), while the workspace-qualified SPS command is the PostgreSQL API suite. `npm run test:e2e:full` starts infrastructure and runs dashboard E2E; it does not mean every repository or proposed fleet suite.

Schema version 14 invalidates operator sessions and cannot be served by an older controller. The optional previous-binary rollback case in `e2e/embedded.spec.ts` still expects sessions to survive on the same database; that case must be revised to a backup-and-reauthentication rollback before it can establish rollback acceptance for version 14.

Install the browser used by the committed Playwright package when needed:

```bash
npm exec --workspace=packages/dashboard -- playwright install chromium
```

The [Playwright config](../../packages/dashboard/playwright.config.ts) starts SPS, dashboard and input-page servers and has a preflight setup project. Outside CI it may reuse existing servers, so stop incompatible dev instances first. Global setup checks PostgreSQL; the full setup/config determines additional readiness and fixture requirements. E2E enables test seed routes and body refresh tokens: keep this configuration isolated from real deployments.

## CI ownership

`.github/workflows/ci.yml` is the automatic lightweight check: it installs Node dependencies, builds the workspace, checks landing demos, and verifies generated controller API types and the contract progress gate. It does not run the workspace test suites, start database services, install a browser, or compile Rust. `.github/workflows/ci-full.yml` keeps the service-backed SPS and contract suites, workspace tests, the SQLite/PostgreSQL Rust matrix, crash/client/browser flows, the P04 console job (preview and embedded E2E, embedded routing tests) and pinned Rust format/lint/test gates available through manual dispatch. The desktop suites need Quickshell and aren't in hosted CI. P02 acceptance still requires the full suite and the separate fleet evidence; a green lightweight CI run is not a substitute. The `ci-full.yml` Rust matrix also runs the P03 fleet controller integration tests on SQLite and PostgreSQL. `.github/workflows/fleet-vm.yml` is manual-only and requires the labeled disposable QEMU/KVM runner. It runs the P01 guest, then the P03 two-guest harness on both backends, which also needs a disposable PostgreSQL endpoint in the `P03_TEST_POSTGRES_URL` secret. Hosted CI and a successful Rust job do not establish systemd VM, stock-client or fleet evidence.

## Evidence and troubleshooting

- A connection refusal: verify the intended PostgreSQL/Redis instance and configured ports. The old `dev-setup.mjs` helper can start services; it is not a read-only connectivity check.
- Missing tables: run migrations with the same `DATABASE_URL` used by the tests. The migration CLI does not import dotenv itself.
- Wrong frontend/API connection: use the intended `VITE_SPS_API_URL` at build/start time and exact CORS origins; avoid mixing `localhost` and `127.0.0.1`.
- A 429 response: test rate limits may differ from ordinary dev values; use the defined test harness rather than weakening public settings.
- A suite that skips: record it as unexecuted and run its required flag/service configuration before claiming coverage.

For code changes, run build/tests and the affected integration suites. For docs-only changes, validate links, commands and diff formatting. For release/packaging changes, run the relevant packaging regression. Record missing dependencies or unavailable services rather than inventing results.

The latest P03 VM evidence is recorded in [the P03 execution record](evidence/p03-fleet-authorization-execution.md). It covers broker-applied key rotation, protocol-mismatch fail-stop and recovery, phase-local E01/E02, partition/restart/replay, bounded reconnect recovery without systemd restarts, rejection of a captured signed time reply after broker restart, denial of a still-live unconsumed grant after a full guest reboot, grant expiry across real guest suspend and wall-clock rollback, a delayed expired-grant rejection audited exactly once, denial after an older signed policy was replayed, and durable idempotent grant revocation replay through the TLS proxy on both backends. Focused broker control-socket tests cover stale policy and grant/node revocation replay across broker restart. Controller clock rollback, other reboot cases, further transport-level policy and node-revocation replay, and the broader pilot matrix remain open.

The [Rust migration remediation record](evidence/rust-migration-remediation-2026-09-29.md) covers the 2026-09-29 security and performance fixes and their local checks.

The [P05 execution record](evidence/p05-workflows-and-clients-execution.md) covers fixture/managed Grafana prerequisites, private worker checks, the narrow systemd helper guest and official SDK/stock Unix-channel foundations. P05 and its inherited integration gates remain open.

The OpenClaw MCP entrypoint now starts the official SDK over standard newline
stdio, retaining the existing legacy tools and opt-in store tool. The MCP
package suite (108 cases, Node 26.10.0, 2026-10-02) covers older/modern transport,
broker operation metadata, cancel/EOF/SIGTERM withdrawal, callback deadlines and
fixed errors, including a real legacy caught-failure canary, plus transport
robustness, fleet legacy-surface refusal, the diagnostics sink and purpose-text
rules. The plugin suite also
checks its legacy handlers and three configured startup profiles. Staged npm,
isolated install, license inventory and MIT/AGPL boundary checks are separate
gates; details are in the [MCP package guide](../../packages/mcp-server/README.md).
These client-config launch checks do not run actual Claude/Codex browser tasks.

The P05 disposable VM also runs the packaged MCP request/status/cancel tools
against the actual production broker. It verifies signed events, ACK/restart
retry with no duplicate request, and kernel denial of another same-UID unit.
No source or controller is provisioned in this portion. Commands and scope are
in the [browser harness guide](../../tests/browser-handoff/README.md#packaged-mcp-tools-against-the-production-broker).

Use [manual demos](Manual%20Demos.md) only with dummy data. Stop the infrastructure with `make down`; PostgreSQL volumes remain until explicitly removed.

### P05 private helper checks

`npm run test:p05:helper` runs the library, private worker framing and actual
sandboxed fixture browser checks. `npm run test:p05:helper:grafana` requires
`P05_GRAFANA_HOME` pointing to the verified Grafana OSS 13.2.3 distribution from
[the browser fixture guide](../../tests/browser-handoff/README.md). Ordinary
`npm test` includes 146 helper/channel checks (Node 26.10.0, 2026-10-02), including the outside-supervisor cases; real browser and managed
application prerequisites stay in these explicit commands. The helper service
VM boundary and full broker/client workflow remain separate acceptance gates.

`npm run test:p05:stock-channel` tests the actual approved stock browser tool; its
same-UID Unix probe does not establish production workload isolation.


The P05 helper VM now exercises the actual Rust protected IPC caller and journal
SIGKILL/ENOSPC persistence probes. Local commands and precise scope are in the
[browser harness guide](../../tests/browser-handoff/README.md#native-helper-and-reconciliation-persistence-checks).
These checks do not complete broker reconciliation or stock-client acceptance.

Reverse namespace-worker identity proof is also exercised by the same P05 VM
gate. The real worker connects to a fixed Root-owned group socket, presents a
private one-use challenge, and is matched through its kernel pidfd to the exact
unit/invocation/UID before import. A same-UID wrong unit is denied without burning
the legitimate ticket, and the held proof fails after worker exit. Component
commands and scope are in the [browser harness guide](../../tests/browser-handoff/README.md#reverse-worker-identity-proof-before-import).
Production signed runtime coordination and verified cleanup remain required.


The same P05 VM now also verifies the private login helper's reverse kernel
identity on a separate fixed Root-owned group socket. A same-UID wrong unit
cannot consume its ticket; the real template proves itself, replay is denied,
and the held pidfd becomes invalid after exit. The Rust caller journals the
exact observed helper unit/invocation before sending source. Actual login checks
the durable identity against the running manager; actual ENOSPC after proof
withholds source and starts no second authentication. Commands and precise
synthetic-probe scope are in the [browser harness guide](../../tests/browser-handoff/README.md#native-helper-and-reconciliation-persistence-checks).

The journal now writes schema 4, with exact original request correlation;
schemas 2/3 remain readable without inferred owners. Fourteen journal cases cover missing/changed helper
identity, failed persistence, lost-reply restart blocking, strict new fields,
conservative schema-2 recovery and the existing transitions/retention. Six
identity cases include separate helper/browser challenge books. Five actual
worker cases cover mandatory socket proof/control framing plus existing fixture
framing/interruption. `npm run test:p05:helper` passes thirteen cases including
actual sandboxed fixture browser tests. These do not complete production grant
dispatch, integrated lost-login recovery or verified website/helper/browser cleanup.


P05 operation ownership, consumption mode, cancellation delivery flags and
controller-signed closure status share the version-5 protected broker snapshot.
`cargo test -p blindpass-broker --lib --locked -- --test-threads=1` covers durable
ownership and eight browser-cancellation cases: owner denial, local authority
withdrawal, queue pressure, failed-write fencing/retry, ACK/restart, no fresh
controller clock, untyped legacy refusal and actual control-socket signing.
Local workload identity resolution uses fixtures; the VM separately checks real
kernel/systemd identities.

`cargo test -p blindpass-controller --test fleet_browser_operations --locked
-- --test-threads=1` runs eleven HTTP cases. Set `P02_TEST_BACKEND=postgres` and
`P02_TEST_POSTGRES_URL` to a disposable database for the PostgreSQL pass. Coverage
includes cancellation before creation, concurrent creation, signed revocation of
unconsumed/consumed/expired authority, replay, approval sibling isolation,
owner mismatch and atomic rollback/retry after a database failure. The relay
regression checks persistence/ACK and canonical replay after restart:
`cargo test -p blindpass-node cancellation_survives_relay_restart_until_acknowledgement
--locked -- --test-threads=1`.

These cancellation component checks do not establish integrated MCP workflow,
retention pruning or verified website/helper/browser cleanup. Request-reply
retry evidence is described below.
Versions 1/2 cannot recover forgotten owners; version-3 owners lack a trusted
mode and cannot cancel. Older brokers cannot read version 5; rollback needs a
matching state backup. All original P05/inherited gates remain required.

`cargo test -p blindpass-controller --test fleet_browser_intents --locked
-- --test-threads=1` runs eleven new actual HTTP cases for signed version-2
browser intent, on SQLite or the same isolated PostgreSQL profile above. They
cover automatic workload-requested approval/grant, exact/concurrent replay,
strict input/identity/time, atomic receipt/operation/approval/audit/closure
rollback, failed issuance recovery, policy change, cancellation/expiry without
renewal and missing original state. The original manual suite remains separate.
The paired production broker VM verifies `request_version: 2` in real signed
events; it still provisions no controller/source in its MCP portion. HTTP and VM
component evidence does not establish the integrated browser lifecycle.


P05 browser request retries and cancellation before reply are included in the
same broker command above. Twelve additional broker cases plus two input-parser
cases cover canonical retry/ACK/restart, altered fields/recipe/invocation,
metadata under clock/queue/persistence fences, actual Unix lost reply/reconnect,
local cancellation before admission, signed cancellation after lost reply,
failed admission and withdrawal persistence, capacity, and strict snapshot
binding/duplicate parsing. The full broker suite passed 167 cases at that slice. It was not re-run for
the 2026-10-02 hardening pass: a `cargo test -p blindpass-broker --locked` check of the shared working
tree that day showed five `owner_retention` unit tests failing while another change to the broker crate
was in progress, so no current count is claimed.
`cargo test -p blindpass-core --locked` includes bounded `cancel-key` framing.
Input parser tests exercise a 512-byte UTF-8 purpose and 128-byte retry key within
the 1,536-byte encoded payload and 2,048-byte operation limits.

Versions 3/4 retain their available ownership/status metadata; version 4 can
still cancel a typed browser request by event ID. Neither contains the new
original resource/recipe binding needed for fresh browser preparation or retry
lookup. Require a new request after upgrade. The full recipe fingerprint now
also binds source destination and resource/workload allow-list; an older journal
fingerprint cannot silently match the changed recipe. Actual production runtime
reconciliation and private-helper lost-reply recovery remain unimplemented.


The [administrator revocation component checks](../../tests/browser-handoff/README.md#administrator-preflight-and-revocation-component-checks)
add actual fixture HTTPS preflight/session/account replay denial and selected
managed Grafana logout. The fixed Root native transport and exact administrator
recipe binding gate source delivery; five ordinary JS and nine broker/native
cases pass. The disposable systemd guest additionally denies source after actual
helper proof and durable identity. These do not complete the production runtime
coordinator, account reconciliation or original P05 acceptance.

P05 original workload process leases add five broker cases to the same host
command above (188 total). The disposable browser-handoff VM now proves actual
original child pidfd/manager binding, ACK retention, broker restart denial and
same-UID/unit/invocation replacement denial with correctly signed cancellation
in 86ms. It provisions no source and does not establish the full asynchronous
browser lifecycle. See [lease setup and scope](../../tests/browser-handoff/README.md#original-workload-process-lease).


## P05 asynchronous helper and closure checks

The broker library suite now passes 197 cases. Nine additions cover sealed
journal permission/lifetime locking, bounded cancellation during private I/O,
and immutable completion/replay/partial-ACK/persistence behavior. The controller
`fleet_browser_operations` command above runs 15 HTTP cases on SQLite and
PostgreSQL, including signed closure after provisional ACK, exact action/mode,
independent grant/session clocks and cleanup after cancellation. The MCP suite
passed 35 cases at that slice (108 now) and returns the safe completed metadata on both tested revisions.
The actual systemd helper VM withdraws journal permission after proof and fsync,
then verifies zero source delivery and no second authentication. These component
checks do not establish production dispatch or actual lifecycle reconciliation.
See [the dated execution evidence](evidence/p05-workflows-and-clients-execution.md#asynchronous-helper-and-immutable-closure-results--2026-10-01).


## P05 coordinator correlation checks — 2026-10-01

`cargo test -p blindpass-broker --lib --locked -- --test-threads=1` passes
216 cases on approved host execution. The new behavioral regression reproduces
closure delivery removing a different request's lease. Schema 4 persists the
exact original request key; the green regression and a legacy schema-3 case
prove a scan never guesses an owner from shared workload/recipe fields.

`node --test --test-isolation=none tests/browser-handoff/coordinator-journal.test.mjs`
runs six pure checks and is included in `npm test`. The VM driver now selects
exact nested `binding.operation_id` fields. An older closure cannot satisfy
another operation's recovery wait. Earlier failed recovery assertions do not
establish a runtime timeout. Fresh frozen-driver Node24.21.0 and Node26.10.0
systemd runs pass the signed-fixture coordinator, copied-cookie denial after
cancellation and actual SIGKILL/restart, stock browser reads/reconnection, and
the combined helper/runtime/persistence regressions. Those runs use a Root
signed issuer fixture. The later opt-in P05-PC08 profile also passes the actual
SQLite controller/unprivileged-node lifecycle on Node24.21.0 and26.10.0: enrollment, policy
and approval, signed grant/ACK/closure, local HPKE provisioning, stock report
and reconnect, cancellation and SIGKILL recovery, two logins and no recovery
re-login. Useful AI clients and complete lifetime gates remain open. The selected managed
Grafana controller/node lifecycle and combined component gate also pass on
Node24.21.0 and26.10.0. Current full workspace runs on both pinned Node
profiles passed 85 helper/channel and 36 MCP cases at that slice (earlier count; see the
current figures in the 2026-10-02 hardening section);101 SPS skips remained.
See [dated coordinator execution](evidence/p05-coordinator-2026-10-01.md).

Recipient-key custody now uses both runnable time and kernel BOOTTIME. The core
suite passes53 cases; the full Rust workspace passes468 with four inherited
ignores, and all-target Clippy passes with warnings denied. In actual RTC suspend
tests, the3-second key expires while runnable time stays below its deadline:
Node26 observes6817ms BOOTTIME/309ms runnable; Node24 observes6901ms/101ms.
This verifies the ephemeral recipient-key component, not the full
Source/grant/website lifetime matrix or P04-D4 provisioning. Generated dummy
plaintext and key material stay out of output.

All13 workspace/root manifests and their lockfile metadata declare
`^24.21.0 || ^26.10.0`; unchanged resolution/integrity/dependency metadata is
checked separately. CI contains both pinned profiles. Remote CI execution and
service-gated suites are separate checks; ordinary npm still skips101 SPS cases.

## P05 current stock tasks and delivery component — 2026-10-02

Both actual Claude Code2.1.286 and Codex CLI0.159.3 tasks pass in separate
Node26/systemd255 managed Grafana guests with actual controller/node approval,
local HPKE provisioning, report/reconnect and confirmed cancellation cleanup.
This selected API operator profile leaves GUI/URL/client UI variants open.

`npm test` now includes14 ordered delivery component and10 actual SDK stdio
cases under P05-DR01–DR07, bringing MCP cases to62 at that slice. Both Node24.21.0 and26.10.0
full build/workspace runs passed 62 MCP and 110 helper/channel cases then;101 SPS skips
remained. The router is an exported trusted embedding component. No production
provider or durable ledger is enabled by these tests. The
[delivery record](evidence/p05-delivery-2026-10-02.md) lists exact checks,
commands, plaintext limits and remaining integration. The
[coordinator record](evidence/p05-coordinator-2026-10-01.md) retains actual
stock-task logs and earlier failed attempts. Full P05 acceptance remains open.

## P05 fleet provisioning crypto contract — 2026-10-02

The separate browser-source helper and core binding add five browser-library
cases to ordinary npm tests (27 browser UI total at that slice, 30 now) and four Rust contract cases.
The full locked Rust workspace passed472 at that slice, with the three inherited desktop
ignores and PostgreSQL outage ignore; all-target Clippy passed. Default database
checks use SQLite. Both pinned Node build/workspace gates passed27 browser UI,
62 MCP and110 helper/channel cases then;101 SPS skips remained.

After `cargo build -p blindpass-core --example provisioning-hpke-probe --locked`,
run `node --test --test-isolation=none tests/browser-handoff/provisioning-hpke.test.mjs`
on an approved host. Seven actual JavaScript-library-to-Rust exchanges pass on
both profiles, including exact AAD equality and fixed actual-open denials for
changed destination/operation/offer/recipient, empty AAD and truncation.
This is an explicit crypto gate, not Chromium UI or broker admission. See
[provisioning execution](evidence/p05-provisioning-2026-10-02.md) for exact scope,
first-red corrections and remaining signed-offer/operator/relay/custody work.

### Signed recipient offer components — 2026-10-02

The [signed-offer record](evidence/p05-signed-offer-2026-10-02.md) adds native
Ed25519 offer signing and Rust/browser verification against independent trusted
enrollment/current grant/destination data. Ordinary npm now includes 30 browser
UI cases. Both pinned Node build/workspace gates pass; 101 SPS skips remain.

After building the same `provisioning-hpke-probe` example, run:

```bash
node --test tests/browser-handoff/provisioning-hpke.test.mjs tests/browser-handoff/provisioning-offer-interoperability.test.mjs tests/browser-handoff/provisioning-offer-chromium.test.mjs
```

Sixteen explicit cases pass per profile, including eight actual native-signature
exchanges and one sandboxed Chromium WebCrypto case. The Chromium test requires
approved loopback/process execution and the existing pinned Playwright browser.
It is browser engine crypto evidence, not live operator GUI or fleet admission.
The broker Unix control regression rejects offers as controller grant authority.
At this shared-signature checkpoint, broker minting and custody remained open;
the receiver section below records their later implementation. Scoped operator
links and durable relay remain open.

### Broker recipient offers and ciphertext admission — 2026-10-02

The later [broker receiver record](evidence/p05-broker-provisioning-2026-10-02.md)
implements `BROWSER_OFFER`/`PROVISION_SOURCE` under the existing control peer check.
Eleven broker host cases use real key files, HPKE and Unix frames with fixture
grant/lease authority; two core cases cover strict signed delivery metadata.
Configured key lifetime, immutable retry, controller signature, current grant,
fixed destination and one-use key consumption govern initial Source storage.
The full64KiB Source frame and invalid/partial input checks pass. No operator
GUI, controller scoped submit or durable node relay is enabled by this receiver.


## P05 controller offer HTTP gate

[Controller offer execution](evidence/p05-controller-offers-2026-10-02.md) adds versioned administrator-only
node/resource Source destinations and atomic public signed-offer ingestion from
current enrolled keys and retained original signed grants. Eleven actual HTTP
cases pass on SQLite and PostgreSQL; 500 full Rust cases pass with four
inherited ignores, and both pinned Node build/workspace gates pass with 101 SPS
skips. Scoped operator Source submission, automatic offer publication, durable
node ciphertext relay and actual GUI/systemd acceptance remain open.

Run `cargo test -p blindpass-controller --test fleet_provisioning_offers --locked
-- --test-threads=1` on an approved loopback host. Set `P02_TEST_BACKEND=postgres`
and `P02_TEST_POSTGRES_URL` for an isolated PostgreSQL pass. Schema 15 requires
matching database backup for rollback and preserves hashed sessions from 14.

## P05 review hardening — 2026-10-02

The [hardening record](evidence/p05-harness-hardening-2026-10-02.md) covers the
MCP, helper and harness fixes from the P05 review: fleet-mode removal of the legacy
exposure switches, the diagnostics sink, stdio robustness, delivery-router
recording, purpose-text rules, helper time budget and transport limits, SPKI pin
semantics, positive controls for the VM canary scans, the shipped broker unit in the
VM harness, CI and the support matrix. Current local figures (Node 26.10.0,
2026-10-02, `npm run build` and `npm test` pass): 108 MCP, 146 helper/channel, 30
browser UI cases; 80 SPS passed with 101 skips. The MCP suite also passes on Node
25.0.0. Node 24.21.0 was not available locally and was not run. VM-only changes
(guest scripts, shipped-unit start, end-of-run leak check) and the CI workflows are
statically checked only and have not run in a VM or on a runner.
