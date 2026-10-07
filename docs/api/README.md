# API reference

[controller.openapi.yaml](controller.openapi.yaml) is the API contract of the Rust controller. It is not a release declaration, and the handlers in the [controller routes](../../crates/blindpass-controller/src/routes) remain the implementation authority.

The legacy SPS hosted stack (`packages/sps-server`, `packages/dashboard`) was removed on 2026-10-07. Its manual OpenAPI snapshot is archived as [docs/legacy/openapi.yaml](../legacy/openapi.yaml) (see the [legacy index](../legacy/README.md)); the SPS source is in git history before the removal commit. Hosted user auth, workspace, billing, analytics and dashboard-summary routes existed only in the SPS, and the controller does not mount them.

The local server entry in the contract is an example endpoint. Configure your deployment's API URL explicitly; this documentation does not verify service availability.

## Rust controller contract

[controller.openapi.yaml](controller.openapi.yaml) keeps the P02 Rust controller contract and adds the reviewed P03 fleet API schemas and route groups. Paths marked `x-blindpass-status: planned` describe the target contract but are not mounted until their implementation slice lands. The [contract suite](../testing/Controller%20Contract%20Suite.md) checks retained P02 routes over HTTP; response bodies are not generally validated against the schema. `npm run test:controller-openapi` checks the mounted route inventory and the planned fleet security contract. The nine formerly undocumented v2 handlers were removed under P02 follow-up WI-1: agent revoke and key rotation, `GET /api/v2/audit/`, secret-request revoke, and the v2 approval read/approve/reject routes for agents and administrators. Rust agent administration, policy, approvals and audit use the documented operator-session API under `/api/v3/admin`; the removed SPS's `sps-user` bearer token is not accepted. Fleet operator APIs also require an operator session and CSRF, while node channel paths use short-lived node bearer tokens. Agent request and exchange creation also apply independent per-agent, per-tenant 60-call windows by default. The OpenAPI document uses JSON-compatible YAML 1.2 syntax so the repository-owned Node generator can produce TypeScript declarations without an added parser dependency. `npm run generate:api` updates `packages/contract-tests/src/generated/controller.d.ts`; the OpenAPI drift CI check verifies the generated file.

The broker discards a controller-signed grant only after it verifies the envelope. A redelivered grant that is already accepted, consumed, revoked or retired is settled and changes nothing. An expired grant, a grant that no longer matches the node key, policy or registration, and a grant received more than 60 seconds after issue are discarded with one durable `grant_rejected` audit event whose `reason_code` is `expired_before_receipt`, `binding_mismatch` or `stale_at_receipt`. The node relay advances the inbox cursor past each discard, so one unusable grant cannot block later revocations or policy. The controller checks the node and grant expiry against its stored grant. Missing trusted time, missing policy or registration, and persistence failures remain retryable; a reused grant ID with different signed content fails closed.

## Authentication modes

- The Rust controller's admin API uses a local operator session cookie plus a session-bound CSRF token (the console) or a desktop bearer session (the approval app). It does not accept the removed SPS's `sps-user` bearer token, and the hosted `/api/v2/auth` routes and `sps_refresh_token` cookie no longer exist.
- The console keeps no credential in web storage. See [authentication storage](../security/blindpass-threat-model.md#authentication-storage) for the session modes and their limits.
- Agent bootstrap uses `x-agent-api-key` on `POST /api/v2/agents/token`; operational routes use agent bearer JWTs. External issuer/JWKS validation is optional and does not attest local OS workload identity.
- Browser metadata/submit requests use scoped signatures; use the API origin configured into the frontend. Query-controlled `api_url` overrides are rejected by the input-page design.

Cookie behavior and JSON fields should be updated together when the route implementation changes.

## Related contracts

- [Exchange policy](../guides/policy.md): implemented RBAC, full-document replacement and optimistic concurrency.
- [Controller deployment](../deploy/README.md) and [HTTPS ingress](../deploy/controller-ingress.md): public origins, state and proxy configuration.
- [Current architecture](../architecture/README.md): provisioning and exchange boundaries.
- [Proposed product specification](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/Specification.md): new node/workload grants and browser sessions; the contract above covers only what the controller mounts or marks planned.


## P05 independent source destination and offer API

[Controller offer execution](../testing/evidence/p05-controller-offers-2026-10-02.md) adds versioned administrator-only
node/resource Source destinations and atomic public signed-offer ingestion from
current enrolled keys and retained original signed grants. Eleven actual HTTP
cases pass on SQLite and PostgreSQL; 500 full Rust cases pass with four
inherited ignores, and both pinned Node build/workspace gates passed on 2026-10-02
with 101 skips in the SPS suites (removed 2026-10-07). Scoped operator Source submission, automatic offer publication, durable
node ciphertext relay and actual GUI/systemd acceptance remain open.

`GET`/`PUT /api/v3/nodes/{node_id}/source-bindings/{resource_id}` are mounted;
`PUT` requires administrator cookie, Origin/CSRF and expected binding version.
The authenticated node event kind `recipient_offer` carries an inner signed
public offer. [OpenAPI](controller.openapi.yaml) and generated declarations
include these surfaces. No Source or provisioning link is accepted here.
