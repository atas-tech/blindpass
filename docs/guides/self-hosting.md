# Self-hosting the current SPS stack

This guide covers the repository's existing source and application-container configuration. It does not establish production readiness, image availability, or native/container fleet parity. P03 fleet code is under implementation and is not an accepted deployment profile. Those release requirements are in [W2/W3](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/Roadmap.md#sequence-and-gates).

## Deployment choices in the repository

Run SPS from source or its Dockerfile, serve the dashboard and browser-input builds, and supply PostgreSQL plus Redis. The Rust controller in `crates/` implements the P02 API for local testing but is not yet accepted or packaged; its settings are listed under [controller configuration](../architecture/README.md#controller-configuration). P03 adds a development enrollment/channel path while workload authorization and the two-host release gates remain unfinished. Existing application images are not evidence of their host identity, service delivery, non-root packaging, recovery or migration guarantees.

For source development, follow the [quick start](quickstart.md). PostgreSQL and Redis can be provided natively or externally; Docker is needed only for the supplied development harness or a chosen container deployment. [Unraid](../deployment/Unraid.md) documents the template files and image build assumptions.

## Configuration

Start from [the example environment](../../.env.example) and inject reviewed values into each process. npm workspace commands do not automatically read the root `.env`; explicitly export it in a trusted shell or use your service manager's protected environment inputs.

| Configuration | Purpose |
|---|---|
| `SPS_HMAC_SECRET`, `SPS_USER_JWT_SECRET`, `SPS_AGENT_JWT_SECRET` | Required independent signing inputs; protect and back up their configured values |
| `DATABASE_URL`, `REDIS_URL` | Management data and request/exchange store connections |
| `SPS_BASE_URL` | Explicit client/plugin API endpoint; override stale plugin defaults |
| `SPS_UI_BASE_URL` | Reachable browser-input origin used in issued links |
| `SPS_CORS_ALLOWED_ORIGINS` | Explicit dashboard and input-page origin allowlist |
| `SPS_HOSTED_MODE=1` | Workspace-scoped application/auth behavior; does not mean the server is vendor-hosted |
| `SPS_TRUST_PROXY` | Trust forwarded headers only behind a configured trusted proxy |
| `SPS_AUTH_COOKIE_DOMAIN` | Optional cookie-domain override; leave unset for host-only cookies unless a reviewed topology needs sharing |
| `VITE_SPS_API_URL` | Frontend build-time API origin, not a runtime container override |

Keep in-memory mode off for persistent operation. Configure email/Turnstile if the chosen hosted-style flows require them. Do not run public services with `NODE_ENV=test` or test seed routes enabled; test auth can expose refresh tokens in JSON.

Payment and guest expansion is frozen. The example enables mock billing and x402 for development; explicitly review these flags for your use case instead of treating example values as production defaults. Freezing roadmap work does not automatically disable deployed routes or remove existing quota enforcement.

## Startup and state

For source deployment, install the lockfile dependency set and build. Run migrations once under controlled rollout before starting the built SPS entry point:

```bash
npm ci
npm run build
npm run db:migrate --workspace=packages/sps-server
node packages/sps-server/dist/index.js
```

The environment must already be configured. Serve the frontend build outputs from the corresponding `dist` directories through your static server; Vite development commands are for local development, not the public serving contract. The [manual image workflow](../../.github/workflows/build-and-push-images.yml) and package Dockerfiles show the repository's container build paths.

The supplied Compose files are development infrastructure: published database ports, development database defaults, and Redis configured without persistence. Use protected backing services and explicitly selected persistence/backup policies for any durable deployment. PostgreSQL backup alone does not capture active Redis requests/exchanges or signing/key material. Recovery must account for all three and must not revive consumed authority; tested fleet recovery remains W2 work.

## Routing and authentication

Use configured HTTPS origins such as `sps.example.com`, `app.example.com`, and `secret.example.com`. Build both frontends for the intended API origin and list their exact origins in SPS CORS. Secure hosted cookies require an HTTPS browser connection in production. Cookie scope, browser site boundaries and proxy trust must agree with the chosen topology.

Hosted agent bootstrap uses enrolled API keys at `POST /api/v2/agents/token`; configure external JWT/JWKS providers only when needed. An external JWT alone is not OS workload attestation. See the [API auth summary](../api/README.md) and [current auth-storage limits](../security/blindpass-threat-model.md#authentication-storage).

Hosted workspace policy is stored in PostgreSQL. Environment policy values seed new/missing policy records; changing them does not rewrite existing workspace policy. Use the dashboard/API for subsequent changes. Non-hosted single-workspace operation can use env-backed policy; see [policy configuration](policy.md).

## Health and release checks

- `/healthz` establishes process liveness.
- `/readyz` reports database/Redis checks and returns 503 on a failed configured check. A skipped check is not evidence that the backing service is working.
- Current nginx templates include CSP/frame headers, but permissive `connect-src` values and missing HSTS remain review items. Verify actual deployed headers rather than assuming repository configuration matches the edge.
- Document and test upgrades, backups, key recovery and rollback for the actual deployment. Neither existing Dockerfiles nor this guide establish high availability or native/container migration parity.

See [security status](../security/README.md) before making exposure or readiness claims, and [test setup](../testing/README.md) for repository verification commands.
