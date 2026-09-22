# Repository instructions

## Scope and sources of truth

- Read [docs/README.md](docs/README.md) for documentation ownership and current implementation limits.
- Forward work follows [Roadmap](docs/product/Roadmap.md), [Specification](docs/product/Specification.md), and [Linux Fleet Pilot](docs/testing/Linux%20Fleet%20Pilot.md). The host broker, browser session handoff, and native/container fleet parity are proposed, not shipped. [Decision records](docs/product/decisions/README.md) fix the rebuilt dashboard stack, the Rust broker/controller direction and the dependency baseline.
- Files under [docs/archive](docs/archive/README.md) are historical records. Their checkboxes, deadlines, and proposed work do not override the current roadmap or reactivate frozen features.
- Use source and executed tests to establish behavior. Do not turn a plan, source inspection, or skipped suite into a claim that a feature works.

## Workspace

This is an npm workspace monorepo. Packages are:

| Package | Responsibility |
|---|---|
| `packages/sps-server` | Fastify API, authentication, exchange policy, Redis state and PostgreSQL management data |
| `packages/gateway` | Interception, secure-link routing and agent identity helpers |
| `packages/agent-skill` | HPKE, SPS clients, runtime memory and exchange helpers |
| `packages/openclaw-plugin` | OpenClaw integration, encrypted store, resolver and MCP entry point |
| `packages/browser-ui` | Vite secret-input page and client-side encryption |
| `packages/dashboard` | React/Vite workspace administration |
| `packages/i18n` | Shared locale resources and validation |

Scripts and packaging live in `scripts/`; service templates live in `deploy/`. Read [LICENSES.md](LICENSES.md) before changing package boundaries.

## Working conventions

- Follow surrounding TypeScript/JavaScript style; TypeScript is strict ESM/NodeNext. Keep `.js` suffixes on local TypeScript imports.
- Use descriptive kebab-case filenames, camelCase values/functions, PascalCase types and UPPER_SNAKE_CASE environment variables. Avoid unrelated reformatting.
- Use relative links and paths in documentation, never machine-specific checkout paths. Update inbound links when moving or deleting documents.
- Keep credentials, `.env` files, private keys, live links and bearer tokens out of commits, chat, logs and test evidence. Use generated dummy canaries for exposure checks.
- Identify the plaintext consumer honestly. Runtime memory, encrypted-at-rest storage, service delivery and a browser session have different exposure and lifetime limits.
- For adding, upgrading, removing or reviewing software dependencies, **use the global `dependency-guard` skill before changing manifests or lockfiles** and evaluate its Socket risk signals. Stop for unresolved risk as the skill requires.

## Commands and validation

Run commands from the repository root. [Testing setup](docs/testing/README.md) covers prerequisites and environment loading; npm workspace scripts execute in their package directories, so do not assume they load the root `.env`.

| Command | Purpose |
|---|---|
| `npm ci` | Install the committed workspace dependency set |
| `npm run build` | Build all packages and the plugin bundle |
| `npm test` | Workspace unit/component suites; database-gated suites may skip |
| `npm run test:integration` | Redis integration; requires configured Redis |
| `npm run test:e2e --workspace=packages/sps-server` | PostgreSQL SPS E2E; script sets `SPS_PG_INTEGRATION=1` |
| `SPS_PG_INTEGRATION=1 npm test --workspace=packages/sps-server` | Include the wider PostgreSQL-gated SPS suites |
| `npm run test:e2e` | Dashboard Playwright E2E, not the SPS-only suite |
| `npm run test:release-metadata` | Distribution metadata/staging regression |
| `make up` / `make down` | Start/stop the local PostgreSQL and Redis test stack |
| `npm run redis:up` | Start Redis only; does not start PostgreSQL |

For implementation changes, run the workspace build/tests and relevant integration/E2E gates. Add meaningful regression coverage for behavior changes, especially authorization, secret handling, transport fallback, TTL and one-use retrieval. For documentation-only edits, check links, command accuracy and `git diff --check`; report which runtime checks were not run.

**Phase testing rule:** When planning or implementing a phase/milestone, define comprehensive E2E and integration scenarios in the corresponding plan under `docs/testing/`, and implement them alongside feature code. Preserve scenario IDs and record actual execution evidence. The Linux pilot requires real systemd VM and stock-client tests; mocks cannot establish those guarantees.

Use Conventional Commit subjects. PRs should state the behavior change, affected packages, checks run and material limits; include screenshots or message samples for visible UI/chat changes. Do not include secret values in review artifacts.
