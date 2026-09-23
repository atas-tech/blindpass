# Quick start from source

This starts the existing SPS, dashboard and encrypted secret-input page on an isolated development machine. It does not install the proposed Linux host broker or browser session-handoff pilot. See the [roadmap](../product/Roadmap.md) for that work.

## Prerequisites

- Node.js 26.x and npm compatible with the committed lockfile.
- Docker Engine with Compose for the supplied PostgreSQL/Redis harness, or equivalent services configured separately.
- Run the commands below from the repository root. Use dummy credentials and a development database.

## Install and configure

```bash
npm ci
cp .env.example .env
```

Review `.env` before loading it. The example has development signing values, database credentials, mock billing and x402 enabled. For a core provisioning/exchange exercise, set `SPS_X402_ENABLED=0`; leave payment credentials empty. Replace signing values before using anything beyond isolated dummy-data development.

Load your reviewed root environment in **each** application/migration terminal:

```bash
set -a
source .env
set +a
```

npm workspace scripts run from the package directory. SPS imports dotenv there, while the migration entry point relies on environment variables; copying a root `.env` alone does not configure every command. Exporting the reviewed environment avoids that ambiguity. Do not assume `.env.test` is loaded automatically.

## Start infrastructure and build

```bash
docker compose -f docker-compose.test.yml up -d --wait
make migrate
npm run build
```

`make up` starts the same development stack without waiting for readiness. `npm run redis:up` starts **only Redis**. The root build includes plugin bundling; check its tooling prerequisites if the bundle step cannot run.

## Start applications

In separate terminals with the environment loaded:

```bash
make dev-sps
```

```bash
make dev-dashboard
```

```bash
make dev-browser
```

| Service | Default local address |
|---|---|
| SPS | `http://127.0.0.1:3100` |
| Dashboard | `http://127.0.0.1:5173` |
| Secret input | `http://127.0.0.1:5175` |
| PostgreSQL | `127.0.0.1:5433` |
| Redis | `127.0.0.1:6380` |

Use `127.0.0.1` consistently for the frontends and API. Cookies/storage distinguish it from `localhost`. Confirm `/healthz` and `/readyz`; inspect readiness check details rather than relying on HTTP 200 alone when services can be skipped.

## Exercise a workflow

For a disposable automated provisioning/exchange smoke exercise:

```bash
node scripts/demo-a2a.mjs auto
```

The helper creates or reuses its own demo workspace/agents, directly verifies database records, rotates existing demo agent keys and prints dummy credentials/results. It is test tooling, not a secure operator onboarding path or a demonstration of model blindness. It needs an exchange policy allowing its demo secret; use the [demo instructions](../testing/Manual%20Demos.md) to seed policy and handle an existing workspace.

For normal application use, register a workspace in the dashboard, complete configured email verification, and enroll agents through the Agents page. Registration does not automatically verify an account. With no mail provider, delivery can be skipped; verification URL logging is off by default. Use configured email delivery, or the explicitly opted-in `SPS_LOG_VERIFICATION_URLS=1` development path only with dummy accounts in a trusted local terminal. Keep returned bootstrap API keys out of chat; configure the consuming integration through its protected runtime inputs.

The legacy `e2e:human` helper has known API-origin/port mismatches and is not a working quickstart step; see [demo limitations](../testing/Manual%20Demos.md#legacy-helper-limitations). Dashboard Playwright coverage is described in [test setup](../testing/README.md).

## Stop

```bash
make down
```

This stops the test-stack containers without deleting the PostgreSQL volume. Other application terminals must be stopped separately. See [self-hosting](self-hosting.md), [policy](policy.md) and the [API reference](../api/README.md) for further configuration.
