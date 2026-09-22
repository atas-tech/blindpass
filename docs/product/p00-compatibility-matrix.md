# P00 compatibility matrix

**Date:** 2026-09-22

This matrix is the implementation boundary for the baseline contract. It records what the existing TypeScript SPS keeps stable while the later Rust controller and host-broker phases are built. A row marked “excluded” is not an implementation claim.

## Package and surface disposition

| Surface | P00 disposition | Evidence or gate |
|---|---|---|
| TypeScript SPS machine API | Preserve as the reference server | `packages/sps-server` source and live CT run |
| Browser secret-input flow | Preserve signed-link, metadata, submit and HPKE client shapes | CT03–CT08, CV01/CV06, CC01 |
| Gateway and agent clients | Preserve response fields consumed by current clients | CC01; later CC02 |
| Workspace policy and admin session | Keep as the TypeScript fixture/provisioning path | Contract adapter seed + policy PATCH |
| Redis request/exchange state | Keep TTL, atomic one-use and lifecycle semantics | CT05–CT12, CT17 |
| PostgreSQL management/audit state | Keep tenant, role, policy and audit mapping | CT01, CT09–CT17 and SPS integration tests |
| Rust controller/broker | Not present; no parity claim | P02 contract gate |
| Native/container host fleet | Not present; no deployment claim | Linux Fleet Pilot W0–W6 |
| Hosted paid-tier billing branches | Excluded from the P00 controller envelope | Explicit freeze; existing SPS code remains |
| Guest intake, x402 and public-offer surfaces | Excluded from the P00 controller envelope | Existing SPS code remains; later scope decision required |

## Machine route envelope

The following 13 routes are the retained machine contract. The later controller must reproduce the TypeScript response status, content type and normalized body for the applicable scenarios.

| Route | Auth boundary | P00 scenarios |
|---|---|---|
| `POST /api/v2/secret/request` | SPS/agent access token or configured external JWKS workload token | CT02, CT03, CT15, CT16–CT18 |
| `GET /api/v2/secret/metadata/:id` | Signed browser metadata link | CT04, CT18 |
| `POST /api/v2/secret/submit/:id` | Signed browser submit link | CT05, CT18 |
| `GET /api/v2/secret/status/:id` | Requester agent access token | CT06, CT18 |
| `GET /api/v2/secret/retrieve/:id` | Owning requester agent access token | CT07, CT08, CT17–CT18 |
| `POST /api/v2/secret/exchange/request` | Requester agent access token | CT09, CT10, CT15, CT17–CT18 |
| `GET /api/v2/secret/exchange/status/:id` | Requester agent access token | CT10, CT18 |
| `POST /api/v2/secret/exchange/fulfill` | Authorized fulfiller agent access token + fulfillment token | CT11, CT17–CT18 |
| `POST /api/v2/secret/exchange/submit/:id` | Authorized fulfiller agent access token | CT11, CT17–CT18 |
| `GET /api/v2/secret/exchange/retrieve/:id` | Requester agent access token | CT10–CT12, CT17–CT18 |
| `DELETE /api/v2/secret/exchange/revoke/:id` | Requester or administrator authorization | CT12, CT17–CT18 |
| `POST /api/v2/agents/token` | Database-backed bootstrap key as Bearer or `x-agent-api-key` | CT02, CT15, CT18 |
| `POST /api/v2/auth/refresh` | Refresh credential in body/cookie | CT14, CT18 |

The browser receives only the public key and description before submission. Encrypted payloads are one-use state, and audit output is metadata-only. The client is intentionally allowed to hold the plaintext after decryption; P00 does not claim model or runtime containment.

## Identity, tenant and local administration

| Contract item | Baseline decision |
|---|---|
| Tenant mapping | Every seeded agent, policy row, exchange and audit record maps to one `workspace_id`; cross-workspace requests fail closed. |
| Roles | `workspace_admin` administers policy/agents and may perform the tested admin approval/revoke path; agent identities request, fulfill or observe according to policy. |
| Bootstrap/recovery | The existing admin session and agent bootstrap-key rotation/revocation endpoints are the P00 fixture contract. New host enrollment/recovery belongs to the controller/broker phases. |
| External workload identity | Ed25519 JWT plus configured JWKS, issuer and audience; wrong issuer/audience and malformed keys are rejected. |
| Signed browser links | HMAC-derived domain secret, request id, expiry and scope; metadata and submit scopes are not interchangeable. |
| Fulfillment token | HMAC-derived HS256 token with fixed issuer/audience semantics and exchange binding. |
| Policy decision | `allow`, `pending_approval` and `deny`, with a stable decision hash fixture; unknown secrets deny. |
| Paid tiers | Not part of the retained controller contract. Existing SPS quota/billing behavior is inventoried, not silently ported. |

## P00 execution evidence

On 2026-09-22, the TS adapter ran the contract suite over real HTTP against a child SPS process with isolated PostgreSQL schema and Redis logical database fixtures. CT01–CT18 and CC01 passed (19 tests), and CV01–CV06 passed (6 tests). The committed normalized snapshot is [ts-baseline.json](../../packages/contract-tests/fixtures/snapshots/ts-baseline.json). This is TypeScript-baseline evidence only; it is not Rust, VM, production or fleet evidence.
