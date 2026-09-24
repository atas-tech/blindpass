# Repository test setup

This is the current command reference. The [Linux Fleet Pilot](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/testing/Linux%20Fleet%20Pilot.md) defines proposed W0–W6 acceptance scenarios; historical phase cases remain in the Obsidian vault. A passing workspace suite does not establish the new broker, browser or deployment guarantees.

The phase acceptance index and P00–P10 plans are maintained in the Obsidian vault. P01's portable Rust checks and disposable-VM harness are in this repository. Revised P01-I01 and P01-I06 checks passed on clean committed SHA `6d41a1f6df8d90d283b53b3c7241281937702ac2` in the selected local Ubuntu 24.04/QEMU-KVM profile on 2026-09-24. W0 acceptance and remaining profile review are open. A shared self-hosted CI runner remains an explicit prerequisite and is never inferred from hosted CI.

The proposed landing-aligned dashboard rebuild and secret-input acceptance plans are maintained in the Obsidian vault. The Rust controller implementation is in progress and remains gated by the [Controller Contract Suite](Controller%20Contract%20Suite.md), an HTTP-level compatibility suite run against both servers. Current P02 execution and open acceptance items are recorded in the [P02 evidence report](evidence/p02-controller-api-migration-rerun.md) and the paired vault plan.

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
| `SUT=ts CONTRACT_DATABASE_URL=... CONTRACT_REDIS_URL=... npm test --workspace=@blindpass/contract-tests` | P00 CT01–CT18, CC01 and CV01–CV06 against a child TypeScript SPS over HTTP | Disposable PostgreSQL and Redis; run `npm run build` first |
| `SUT=rust CONTRACT_RUST_BACKEND=sqlite npm test --workspace=@blindpass/contract-tests` | Rust HTTP contract suite, including adopted CT19 | Adapter starts the controller with an isolated SQLite database; hosted-user CT14 runs only against TypeScript SPS |
| `SUT=rust CONTRACT_RUST_BACKEND=postgres CONTRACT_DATABASE_URL=... npm test --workspace=@blindpass/contract-tests` | Same Rust HTTP contract suite against PostgreSQL | Adapter creates and removes an isolated schema in a disposable PostgreSQL database |
| `SUT=rust CONTRACT_RUST_BACKEND=sqlite npm run test:p02:clients` | P02 CC02 gateway, agent-skill and OpenClaw request/exchange flows against Rust | Node.js `tsx` loader; set `CONTRACT_RUST_BACKEND=postgres CONTRACT_DATABASE_URL=...` to use PostgreSQL |
| `npm run test:p02:crash` | P02-I03 process termination/restart cases for compatibility and exchange retrieval, policy CAS and approval/audit transactions | Build a separate binary with `CARGO_TARGET_DIR=target/p02-failpoints cargo build -p blindpass-controller --features p02-test-failpoints --locked`; set `CONTRACT_RUST_BIN`, `SUT=rust` and backend vars. Uses localhost and an isolated SQLite DB or disposable PostgreSQL schema |
| `NODE_OPTIONS=--import=tsx SUT=rust CONTRACT_RUST_BACKEND=sqlite npm run test:p02-browser --workspace=@blindpass/dashboard` | P02 CC02 `e2e-human.mjs` browser flow and CC03 signed/expired browser-link flows | Chromium and isolated SQLite controller; use `CONTRACT_RUST_BACKEND=postgres CONTRACT_DATABASE_URL=...` for PostgreSQL |
| `cargo fmt --all -- --check` | P01/P02 Rust formatting gate | Rust toolchain pinned by `rust-toolchain.toml` |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | P01/P02 Rust lint gate | Native `libsystemd`/OpenSSL development libraries |
| `cargo test --workspace --locked` | P01/P02 portable unit, store, transport-boundary and HPKE interop tests | Unix-socket operations; rerun outside restricted sandboxes if required |
| `./tests/fleet/p01-vm.sh` | P01 real systemd guest harness | Named QEMU/KVM runner with writable `/dev/kvm`, pinned image hash, SSH key, cloud-localds and an ISO writer; exit 78 means unsupported/blocking infrastructure |

For the packaged P02 browser check, build `packages/browser-ui/Dockerfile`, run the image on a disposable loopback port and set `P02_PACKAGED_BROWSER_UI_URL` to that origin when invoking `test:p02-browser`. The suite then serves the page from nginx and adds a response-header check; it still starts the Rust controller at port 3100 and runs CC02/CC03. Stop the container after the run.

Inspect skipped-test counts. `npm run test:e2e` at the root is **dashboard E2E**, while the workspace-qualified SPS command is the PostgreSQL API suite. `npm run test:e2e:full` starts infrastructure and runs dashboard E2E; it does not mean every repository or proposed fleet suite.

Install the browser used by the committed Playwright package when needed:

```bash
npm exec --workspace=packages/dashboard -- playwright install chromium
```

The [Playwright config](../../packages/dashboard/playwright.config.ts) starts SPS, dashboard and input-page servers and has a preflight setup project. Outside CI it may reuse existing servers, so stop incompatible dev instances first. Global setup checks PostgreSQL; the full setup/config determines additional readiness and fixture requirements. E2E enables test seed routes and body refresh tokens: keep this configuration isolated from real deployments.

## CI ownership

`.github/workflows/ci.yml` runs the workspace build, landing workflow checks, default tests, Redis integration, PostgreSQL SPS tests, a separate P00 contract job, the Rust SQLite/PostgreSQL contract matrix, development and packaged nginx browser flows, and a separately built P02-I03 crash-failpoint matrix, plus the pinned Rust format/lint/test gates. The P00 job writes a Vitest JSON report and fails if any contract case or suite was skipped. The PostgreSQL job checks that every gated SPS test file executed passing cases. `.github/workflows/fleet-vm.yml` is manual-only and requires the labeled disposable QEMU/KVM runner; hosted CI and a successful Rust job do not establish systemd VM, stock-client or fleet evidence.

## Evidence and troubleshooting

- A connection refusal: verify the intended PostgreSQL/Redis instance and configured ports. The old `dev-setup.mjs` helper can start services; it is not a read-only connectivity check.
- Missing tables: run migrations with the same `DATABASE_URL` used by the tests. The migration CLI does not import dotenv itself.
- Wrong frontend/API connection: use the intended `VITE_SPS_API_URL` at build/start time and exact CORS origins; avoid mixing `localhost` and `127.0.0.1`.
- A 429 response: test rate limits may differ from ordinary dev values; use the defined test harness rather than weakening public settings.
- A suite that skips: record it as unexecuted and run its required flag/service configuration before claiming coverage.

For code changes, run build/tests and the affected integration suites. For docs-only changes, validate links, commands and diff formatting. For release/packaging changes, run the relevant packaging regression. Record missing dependencies or unavailable services rather than inventing results.

Use [manual demos](Manual%20Demos.md) only with dummy data. Stop the infrastructure with `make down`; PostgreSQL volumes remain until explicitly removed.
