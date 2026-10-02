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

## Rust controller candidates (P06)

The new [SQLite](../../deploy/unraid/blindpass-controller-sqlite.xml) and
[PostgreSQL](../../deploy/unraid/blindpass-controller-postgres.xml) templates
are separate from the retained SPS templates above. They select the versioned
Rust controller candidate with embedded console/input page, UID/GID 10001,
read-only root, dropped capabilities, no-new-privileges, disabled core dumps,
private runtime tmpfs and read-only keys. They publish no host port and require
a separately configured HTTPS edge on the `blindpass-edge` custom network.
Set its exact trusted IP, both HTTPS authorities and protected certificate
configuration. No Redis, broker container, Docker socket or systemd mount is
part of these controller templates.

Prepare private host state and key directories owned by `10001:10001`, mode
`0700`, with key files mode `0600`. Use a direct local pool path such as the
selected `/mnt/cache/appdata` path for SQLite; the `/mnt/user` FUSE share and
network filesystems are not a verified SQLite profile. Initialize keys and
schema explicitly before serving, following the command/credential contracts
in the [Compose candidate guide](../deploy/compose-quickstart.md). Use one
fixed chosen image/version and the same prepared mounts during initialization;
key initialization alone needs a writable keys mount, while serving requires
it read-only. Startup never generates keys or initializes the database.

The PostgreSQL template describes only the controller. Supply a separately
administered PostgreSQL 16 service on a private network and a private URL file
at `/config/database.url` (UID 10001, mode `0600`, parent `0700`). Credentials
are file inputs, not template/environment values. The existing legacy
PostgreSQL template's development defaults do not configure this profile.
Configure verified database TLS separately if the database crosses hosts.

XML rendering and actual Docker/Compose behavior cannot establish Unraid GUI,
pool-mount or lifecycle acceptance. Those checks require a real Unraid host.
Registry tags and remote publishing also need separate execution evidence.
Authenticated complete backup/recovery, external ownership/fencing and tested
migration/upgrade runbooks remain P06 requirements. Preserve these candidates'
state on removal; do not delete volumes or copy a live database as a migration.
