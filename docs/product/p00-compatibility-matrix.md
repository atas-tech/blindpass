# P00 compatibility matrix

**Date:** 2026-09-23

**Scope corrected:** 2026-09-24 after distinguishing hosted workspace-user refresh from local operator refresh.

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
| Rust controller/broker | Controller implements the retained envelope and passes the P02 contract gate locally on SQLite and PostgreSQL; not accepted until hosted CI runs. Local broker present | P01 broker evidence; [P02 evidence](../testing/evidence/p02-controller-api-migration-rerun.md) |
| Native/container host fleet | Not present; no deployment claim | Linux Fleet Pilot W0–W6 |
| Hosted paid-tier billing branches | Excluded from the P00 controller envelope | Explicit freeze; existing SPS code remains |
| Guest intake, x402 and public-offer surfaces | Excluded from the P00 controller envelope | Existing SPS code remains; later scope decision required |

## Machine route envelope

The following 12 routes are the retained machine contract. The later controller must reproduce the TypeScript response status, content type and normalized body for the applicable scenarios. CT14 remains a TypeScript SPS hosted-user regression case; `/api/v2/auth/refresh` is outside the Rust controller because the roadmap freezes hosted user auth.

| Route | Auth boundary | P00 scenarios |
|---|---|---|
| `POST /api/v2/secret/request` | SPS/agent access token or configured external JWKS workload token | CT02, CT03, CT16–CT18 |
| `GET /api/v2/secret/metadata/:id` | Signed browser metadata link | CT04, CT18 |
| `POST /api/v2/secret/submit/:id` | Signed browser submit link | CT05, CT18 |
| `GET /api/v2/secret/status/:id` | Requester agent access token | CT06, CT18 |
| `GET /api/v2/secret/retrieve/:id` | Owning requester agent access token | CT07, CT08, CT17–CT18 |
| `POST /api/v2/secret/exchange/request` | Requester agent access token | CT09, CT10, CT17–CT18 |
| `GET /api/v2/secret/exchange/status/:id` | Requester agent access token | CT10, CT18 |
| `POST /api/v2/secret/exchange/fulfill` | Authorized fulfiller agent access token + fulfillment token | CT11, CT17–CT18 |
| `POST /api/v2/secret/exchange/submit/:id` | Authorized fulfiller agent access token | CT11, CT17–CT18 |
| `GET /api/v2/secret/exchange/retrieve/:id` | Requester agent access token | CT10–CT12, CT17–CT18 |
| `DELETE /api/v2/secret/exchange/revoke/:id` | Requester or configured external issuer's `admin: true` claim in the same asserted workspace; accepted for CT12 on 2026-09-24 | CT12, CT17–CT18 |
| `POST /api/v2/agents/token` | Database-backed bootstrap key as Bearer or `x-agent-api-key` | CT02, CT15, CT18 |

The browser receives only the public key and description before submission. Encrypted payloads are one-use state, and audit output is metadata-only. The client is intentionally allowed to hold the plaintext after decryption; P00 does not claim model or runtime containment.

## Identity, tenant and local administration

| Contract item | Baseline decision |
|---|---|
| Tenant mapping | Every seeded agent, policy row, exchange and audit record maps to one `workspace_id`; cross-workspace requests fail closed. |
| Roles | `workspace_admin` administers policy/agents and exercises approval. CT12 revocation accepts a configured external issuer's `admin: true` agent claim in the same asserted workspace, as accepted for the controller on 2026-09-24. This claim grants no local or fleet administration. |
| Bootstrap/recovery | The existing admin session and agent bootstrap-key rotation/revocation endpoints are the P00 fixture contract. New host enrollment/recovery belongs to the controller/broker phases. |
| External workload identity | Ed25519 JWT plus configured JWKS, issuer and audience; wrong issuer/audience and malformed keys are rejected. |
| Signed browser links | HMAC-derived domain secret, request id, expiry and scope; metadata and submit scopes are not interchangeable. |
| Fulfillment token | HMAC-derived HS256 token with fixed issuer/audience semantics and exchange binding. |
| Policy decision | `allow`, `pending_approval` and `deny`, with a stable decision hash fixture; unknown secrets deny. |
| Paid tiers | Not part of the retained controller contract. Existing SPS quota/billing behavior is inventoried, not silently ported. |

## P00 execution evidence

Earlier 2026-09-23 evidence recorded CT01–CT18 and CC01 over real HTTP (19 tests), CV01–CV06 (6 tests), two adapter cleanup/isolation tests, the health/readiness behavior after Redis outage/recovery, and dashboard browser E2E against spawned and base-URL SPS servers. That run preceded the review corrections below.

The last committed-SHA baseline execution is recorded in the [Controller Contract Suite](../testing/Controller%20Contract%20Suite.md): 34 TypeScript adapter tests and 19 `SUT=base` HTTP cases on `a18ecb1e26e576c8475f0e68d7e538278a5f4e0e`. The PostgreSQL SPS suite passed 179 tests with 2 Redis-gated skips; the separate Redis integration suite executed its 2 cases. Hosted PR CI is not claimed locally. These are TypeScript-baseline checks, not controller parity or fleet evidence.

On the 2026-09-23 review tree, the revised `SUT=ts` suite passed 35/35 with no skips and the harness-spawned `SUT=base` HTTP suite passed 19/19 against a disposable PostgreSQL 16/Redis 7 stack. A local CT18 snapshot mismatch and an unavailable-PostgreSQL injection each made the contract job exit nonzero; hosted PR-CI and required-check evidence remain open. The PostgreSQL SPS suite passed 179 cases with 2 Redis-gated skips; all 18 PostgreSQL-gated files executed, and the separate Redis integration suite passed 2/2. SPS E2E passed 9/9. These results do not replace a committed-SHA run or hosted PR CI evidence.

## Contract decisions for P02

- **CT12 (accepted 2026-09-24):** A configured external issuer may authorize cross-requester revoke using its `admin: true` claim and asserted `workspace_id` when that workspace matches the target. The TypeScript SPS accepts this; CT12 covers `admin: false` and foreign-workspace negatives. The claim grants no local or fleet administration.
- **CT14 (scope accepted 2026-09-24):** The TypeScript snapshot uses hosted user auth under `NODE_ENV=test`, where the refresh token appears in both the cookie and response body. Hosted production omits the body token. This is SPS regression coverage only. The Rust controller's local operator refresh is `/api/v3/admin/session/refresh` and has its own cookie/CSRF contract. The Rust API has 12 retained machine routes plus two CT19 routes.
- **CT15 (P02-D12 recorded 2026-09-24, needs reconciliation):** The recorded envelope names per-IP agent token mints and per-agent request/exchange rate windows. A 2026-09-25 source check found that neither self-hosted SPS nor the Rust controller limits requests or exchanges per agent: SPS applies workspace burst and daily quotas only in hosted mode, and both servers limit only token mints per client IP. CT15 tests that limit and its reset. Either amend the decision to the per-IP limit or add per-agent windows to the controller. Hosted paid-tier quota and billing behavior is excluded.

The full `ts-baseline.json` remains the P00 SPS snapshot. Rust derives four explicit shared projections from that file: CT01 readiness and CT18's readiness 503 compare status, `ok` and the database check because the Rust controller has no Redis check or error code; CT16 compares the allowed origin, credentials flag and relevant statuses because Axum and Fastify emit different ancillary preflight headers; CT17 compares status, content type, exact record-field shape and required event presence because the two fixture adapters emit different audit volumes. The Rust tests also reject ciphertext canaries in audit output. Every other retained case compares its full normalized TypeScript snapshot. The projection code is in `packages/contract-tests/src/snapshots.ts`; it cannot rewrite the TypeScript baseline during a Rust run.

P00 exit remains open until the CT15 record is reconciled with the implemented limit and the revised evidence runs on a committed SHA with hosted PR CI. The CT12 and CT14 decisions were accepted on 2026-09-24 and recorded in the paired P02 plans.
