# Repository test setup

This is the current command reference. The [Linux Fleet Pilot](Linux%20Fleet%20Pilot.md) defines proposed W0–W6 acceptance scenarios; historical phase cases remain in the Obsidian vault. A passing workspace suite does not establish the new broker, browser or deployment guarantees.

The phase acceptance index and P00–P10 plans are maintained in the Obsidian vault. Their proposed Rust/VM/controller runners must be added alongside their feature code; the commands below describe the current repository only.

The proposed landing-aligned dashboard rebuild and secret-input acceptance plans are maintained in the Obsidian vault. The proposed Rust controller port is gated by the [Controller Contract Suite](Controller%20Contract%20Suite.md), an HTTP-level compatibility suite run against both servers; it is not implemented.

The secret-input redesign plan covers the companion input-page mockup's proposed SI scenarios and keeps prototype inspection separate from product E2E evidence in the vault.

## Environment

Run commands from the repository root with Node.js 22+ and installed lockfile dependencies. Use a disposable test database: suites and demo helpers create, alter or clean up workspace/account state. Keep real secrets out of fixtures and captured outputs.

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
| `npm test` | Default workspace tests | Built shared package inputs where imported; gated DB/Redis suites can skip |
| `npm test --workspace=packages/sps-server` | SPS Vitest suite | Same gating behavior |
| `npm run test:integration` | SPS Redis integration | Redis; script sets `SPS_REDIS_INTEGRATION=1` |
| `npm run test:e2e --workspace=packages/sps-server` | SPS `tests/e2e.test.ts` | PostgreSQL and `DATABASE_URL`; script sets `SPS_PG_INTEGRATION=1` |
| `SPS_PG_INTEGRATION=1 npm test --workspace=packages/sps-server` | Wider SPS tests including PostgreSQL-gated cases | Disposable PostgreSQL database; Redis integration still has its separate flag |
| `npm run test:e2e` | Dashboard Playwright suite | PostgreSQL, Redis, Chromium and available local application ports |
| `npm run test:release-metadata` | Version, staged package files and npm entrypoint metadata | Plugin dist artifacts; test builds them if absent |
| `npm run test:skill-install` | Installer regression | See script prerequisites and generated bundle |
| `npm run test:audience-packaging` | Audience packaging paths | See script prerequisites and generated bundle |
| `npm run test:openclaw-activation` | OpenClaw activation contract harness | Defined local harness, not proof of every released OpenClaw version |

Inspect skipped-test counts. `npm run test:e2e` at the root is **dashboard E2E**, while the workspace-qualified SPS command is the PostgreSQL API suite. `npm run test:e2e:full` starts infrastructure and runs dashboard E2E; it does not mean every repository or proposed fleet suite.

Install the browser used by the committed Playwright package when needed:

```bash
npm exec --workspace=packages/dashboard -- playwright install chromium
```

The [Playwright config](../../packages/dashboard/playwright.config.ts) starts SPS, dashboard and input-page servers and has a preflight setup project. Outside CI it may reuse existing servers, so stop incompatible dev instances first. Global setup checks PostgreSQL; the full setup/config determines additional readiness and fixture requirements. E2E enables test seed routes and body refresh tokens: keep this configuration isolated from real deployments.

## Planned CI ownership

The current workflows build images and check/deploy the landing page; they do not run workspace or Rust suites. The P00.4/P01.1/P02.1 CI ownership and runner plan is maintained in the Obsidian vault. These are planned deliverables, not existing automated coverage.

## Evidence and troubleshooting

- A connection refusal: verify the intended PostgreSQL/Redis instance and configured ports. The old `dev-setup.mjs` helper can start services; it is not a read-only connectivity check.
- Missing tables: run migrations with the same `DATABASE_URL` used by the tests. The migration CLI does not import dotenv itself.
- Wrong frontend/API connection: use the intended `VITE_SPS_API_URL` at build/start time and exact CORS origins; avoid mixing `localhost` and `127.0.0.1`.
- A 429 response: test rate limits may differ from ordinary dev values; use the defined test harness rather than weakening public settings.
- A suite that skips: record it as unexecuted and run its required flag/service configuration before claiming coverage.

For code changes, run build/tests and the affected integration suites. For docs-only changes, validate links, commands and diff formatting. For release/packaging changes, run the relevant packaging regression. Record missing dependencies or unavailable services rather than inventing results.

Use [manual demos](Manual%20Demos.md) only with dummy data. Stop the infrastructure with `make down`; PostgreSQL volumes remain until explicitly removed.
