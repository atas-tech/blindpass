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
| `NODE_OPTIONS=--import=tsx SUT=rust CONTRACT_RUST_BACKEND=sqlite npm run test:p02-browser --workspace=@blindpass/dashboard` | P02 CC02 `e2e-human.mjs` browser flow and CC03 signed/expired browser-link flows | Chromium and isolated SQLite controller; use `CONTRACT_RUST_BACKEND=postgres CONTRACT_DATABASE_URL=...` for PostgreSQL |
| `cargo fmt --all -- --check` | P01/P02 Rust formatting gate | Rust toolchain pinned by `rust-toolchain.toml` |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | P01/P02 Rust lint gate | Native `libsystemd`/OpenSSL development libraries |
| `cargo test --workspace --locked` | P01/P02 unit tests (including the Rust side of CV01–CV06), SQLite store, shell, admin HTTP, socket and CLI tests, transport-boundary and HPKE interop tests | Unix-socket operations; rerun outside restricted sandboxes if required. The PostgreSQL-only outage case reports ignored |
| `P02_TEST_BACKEND=<sqlite\|postgres> cargo test -p blindpass-controller --test store_transitions --locked` | P02-I01/I02 store transitions: races, expiry before sweep and after restart, lock waits, tenant isolation, sessions, operators, clock mark and reconciliation | Set `P02_TEST_POSTGRES_URL` for PostgreSQL; each run uses an isolated schema |
| `cargo test -p blindpass-controller --test shell_config --locked` | Production config, migration, clock reconciliation and test fixture shell checks | Some cases bind localhost and require socket permission; set `P02_TEST_BACKEND=postgres` and `P02_TEST_POSTGRES_URL` for the PostgreSQL variants of the seed, clock-reconciliation and pool-loss cases; the other cases always use SQLite or no database |
| `P02_TEST_BACKEND=<sqlite\|postgres> cargo test -p blindpass-controller --test admin_session --locked` | P02-I04–I06 HTTP bootstrap race, sessions, CSRF, forced password change and the admin/operator/viewer role matrix | Binds localhost; set `P02_TEST_POSTGRES_URL` for PostgreSQL |
| `P02_TEST_POSTGRES_URL=... cargo test -p blindpass-controller --test postgres_outage --locked -- --ignored` | P02-I07 PostgreSQL outage and reconnection without a controller restart | Ignored by default; the database role must be able to create roles, as the CI and local Compose superuser can |
| `cargo test -p blindpass-cli --locked` | CLI dispatch for migration, clock reconciliation, test fixture seeding and socket password reset, plus authenticated fleet enrollment, node rotation, token-file permissions and revoke confirmation | The controller executable must be installed beside the CLI in deployed environments; fleet CLI tests use loopback HTTP and curl |
| `./tests/fleet/p01-vm.sh` | P01 real systemd guest harness | Named QEMU/KVM runner with writable `/dev/kvm`, pinned image hash, SSH key, cloud-localds and an ISO writer; exit 78 means unsupported/blocking infrastructure |
| `./tests/fleet/p03-vm.sh --backend both` | P03 two-guest fleet authorization on SQLite and PostgreSQL, including key rotation, durable event replay, protocol-mismatch fail-stop/recovery, bounded reconnect backoff, stale signed time-reply rejection after broker restart, suspend-aware expiry, delayed expired-grant audit, connected revocation and recovery | Named QEMU/KVM runner, pinned Ubuntu 24.04 image, writable `/dev/kvm`, and a PostgreSQL endpoint for the PostgreSQL pass; see [fleet runner setup](../../tests/fleet/README.md#p03-fleet-authorization-runner) |

For the packaged P02 browser check, build `packages/browser-ui/Dockerfile`, run the image on a disposable loopback port and set `P02_PACKAGED_BROWSER_UI_URL` to that origin when invoking `test:p02-browser`. The suite then serves the page from nginx and adds a response-header check; it still starts the Rust controller at port 3100 and runs CC02/CC03. Stop the container after the run.

Inspect skipped-test counts. `npm run test:e2e` at the root is **dashboard E2E**, while the workspace-qualified SPS command is the PostgreSQL API suite. `npm run test:e2e:full` starts infrastructure and runs dashboard E2E; it does not mean every repository or proposed fleet suite.

Install the browser used by the committed Playwright package when needed:

```bash
npm exec --workspace=packages/dashboard -- playwright install chromium
```

The [Playwright config](../../packages/dashboard/playwright.config.ts) starts SPS, dashboard and input-page servers and has a preflight setup project. Outside CI it may reuse existing servers, so stop incompatible dev instances first. Global setup checks PostgreSQL; the full setup/config determines additional readiness and fixture requirements. E2E enables test seed routes and body refresh tokens: keep this configuration isolated from real deployments.

## CI ownership

`.github/workflows/ci.yml` is the automatic lightweight check: it installs Node dependencies, builds the workspace, checks landing demos, and verifies generated controller API types and the contract progress gate. It does not run the workspace test suites, start database services, install a browser, or compile Rust. `.github/workflows/ci-full.yml` keeps the service-backed SPS and contract suites, workspace tests, the SQLite/PostgreSQL Rust matrix, crash/client/browser flows, and pinned Rust format/lint/test gates available through manual dispatch. P02 acceptance still requires the full suite and the separate fleet evidence; a green lightweight CI run is not a substitute. `.github/workflows/fleet-vm.yml` is manual-only and requires the labeled disposable QEMU/KVM runner; hosted CI and a successful Rust job do not establish systemd VM, stock-client or fleet evidence.

## Evidence and troubleshooting

- A connection refusal: verify the intended PostgreSQL/Redis instance and configured ports. The old `dev-setup.mjs` helper can start services; it is not a read-only connectivity check.
- Missing tables: run migrations with the same `DATABASE_URL` used by the tests. The migration CLI does not import dotenv itself.
- Wrong frontend/API connection: use the intended `VITE_SPS_API_URL` at build/start time and exact CORS origins; avoid mixing `localhost` and `127.0.0.1`.
- A 429 response: test rate limits may differ from ordinary dev values; use the defined test harness rather than weakening public settings.
- A suite that skips: record it as unexecuted and run its required flag/service configuration before claiming coverage.

For code changes, run build/tests and the affected integration suites. For docs-only changes, validate links, commands and diff formatting. For release/packaging changes, run the relevant packaging regression. Record missing dependencies or unavailable services rather than inventing results.

The latest P03 VM evidence is recorded in [the P03 execution record](evidence/p03-fleet-authorization-execution.md). It covers broker-applied key rotation, protocol-mismatch fail-stop and recovery, phase-local E01/E02, partition/restart/replay, bounded reconnect recovery without systemd restarts, rejection of a captured signed time reply after broker restart, grant expiry across real guest suspend and wall-clock rollback, and a delayed expired-grant rejection audited exactly once on both backends. Controller clock rollback, guest/node reboot cases beyond the broker-restart replay, delayed/replayed policy and revocation, and the broader pilot matrix remain open.

Use [manual demos](Manual%20Demos.md) only with dummy data. Stop the infrastructure with `make down`; PostgreSQL volumes remain until explicitly removed.
