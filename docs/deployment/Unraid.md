# Unraid template reference

The repository contains Unraid templates and Dockerfiles for the **existing SPS application stack**. This guide describes their configuration as inspected on 2026-09-22; it does not verify registry availability or establish the proposed fleet controller's deployment parity.

## Template set

| Component | Repository template |
|---|---|
| PostgreSQL | [blindpass-postgres.xml](../../deploy/unraid/blindpass-postgres.xml) |
| Redis | [blindpass-redis.xml](../../deploy/unraid/blindpass-redis.xml) |
| SPS API | [blindpass-sps-server.xml](../../deploy/unraid/blindpass-sps-server.xml) |
| Browser input | [blindpass-browser-ui.xml](../../deploy/unraid/blindpass-browser-ui.xml) |
| Dashboard | [blindpass-dashboard.xml](../../deploy/unraid/blindpass-dashboard.xml) |

Application templates reference `ghcr.io/atas-tech/blindpass-*`. Publish or verify the intended image/tag before installation; change the repository field if using your own registry. The [image workflow](../../.github/workflows/build-and-push-images.yml) is manually dispatched and derives the registry owner from the repository.

The workflow's frontend API default is `https://sps.atas.tech`, with a `VITE_SPS_API_URL` repository-variable override. For another deployment, build both frontends with the intended API URL. Setting that variable only at container runtime does not change a compiled bundle.

## Configure a deployment

Use one private container network for SPS and backing services. Container hostnames in `DATABASE_URL`/`REDIS_URL` must match the selected network names. Protect PostgreSQL/Redis from public exposure and review storage/persistence behavior rather than copying local test defaults.

Configure all required SPS values, including ones the template may not expose by default:

- `DATABASE_URL`, `REDIS_URL` and protected database credentials.
- `SPS_HMAC_SECRET`, `SPS_USER_JWT_SECRET` and `SPS_AGENT_JWT_SECRET` with independent strong values.
- `SPS_HOSTED_MODE=1` for workspace/dashboard behavior, and `SPS_USE_IN_MEMORY=0`.
- `SPS_UI_BASE_URL` for the input page and `SPS_CORS_ALLOWED_ORIGINS` for the exact dashboard/input origins.
- Appropriate proxy trust and optional cookie-domain configuration for your HTTPS topology. Keep test mode and seed routes disabled.

The template's optional external JWT/JWKS providers are needed only if accepting external workload issuers. API-key-enrolled agents use `POST /api/v2/agents/token`; configure their keys outside chat. SPIFFE-shaped claims alone do not provide the proposed host attestation.

Use a TLS reverse proxy for public API/frontends. Map your configured domains to the API and frontend container ports, checking the actual template port mappings. Inspect response headers and cookie behavior: current nginx files still need CSP/HSTS hardening. Do not advertise the existing SPS image as the W2 non-root fleet controller; its Dockerfile has no explicit `USER` directive.

## Policy, lifecycle and checks

Run the repository's database migrations under a controlled rollout. Hosted workspace policy is changed through the dashboard/API; env policy changes are bootstrap inputs, not updates to existing workspace rows. See [policy](../guides/policy.md).

Check `/healthz` and `/readyz`, including per-service results. Back up PostgreSQL, any deliberately persistent Redis state, and signing/trust inputs; protect backups as credential-bearing material. Existing templates do not establish tested upgrades, rollback, recovery or native/container migration. Validate those procedures for the deployed version.

If links point at the wrong page, check `SPS_UI_BASE_URL`. If frontends call the wrong API, rebuild with the correct `VITE_SPS_API_URL`. If browser requests fail, check exact CORS origins and HTTPS/cookie topology. If SPS cannot reach a backing service, check its configured container hostname, network and credentials.

The [self-hosting guide](../guides/self-hosting.md) covers common configuration limits. New controller packaging and recovery support must pass [W2](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/Roadmap.md#sequence-and-gates) and the [deployment tests](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/testing/Linux%20Fleet%20Pilot.md#controller-packaging-persistence-and-migration).
