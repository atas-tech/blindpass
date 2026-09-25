# Controller Contract Suite

**Proposed:** 2026-09-22

**Status:** P00 TypeScript baseline executed; the corrected retained Rust contract scope passes locally on SQLite and PostgreSQL, rerun on 2026-09-25 after the review fixes in the [P02 evidence](evidence/p02-controller-api-migration-rerun.md). P02 acceptance, hosted CI and fleet gates remain open.

**Design:** [Decision 0002](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/decisions/0002-rust-controller-and-broker.md) · [Specification](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/Specification.md) · [Linux Fleet Pilot](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/testing/Linux%20Fleet%20Pilot.md)

The Rust controller is built test-first. The CT01–CT18 baseline is written and made green against the existing TypeScript SPS before any Rust endpoint exists. CT01–CT13 and CT15–CT18 form the retained Rust compatibility gate; CT14 remains an SPS hosted-user regression case. The Rust gate covers API compatibility for machine clients. It does not cover the OS, broker or deployment guarantees, which stay in the [pilot plan](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/testing/Linux%20Fleet%20Pilot.md).

P00 owns the TypeScript baseline and P02 the Rust parity gate; their implementation and acceptance plans are maintained in the Obsidian vault. The cross-language portion of CV06 necessarily runs after Rust crypto exists. The compatibility envelope preserves selected machine behavior; frozen paid-tier/guest/hosted-signup branches have explicit exclusions, while new local administration and fleet APIs have separate phase tests.

## Why the existing suites cannot be moved

The earlier test profile counted 29 SPS files and 175 cases; P00 must inventory the actual source revision rather than treat those counts as coverage guarantees. Route suites drive Fastify in-process through `inject`; pure unit and Redis store suites exercise internals directly. Some fixtures pass registry/rules as constructor options; the source also supports `SPS_SECRET_REGISTRY_JSON` and `SPS_EXCHANGE_POLICY_JSON`, and workspace policy APIs. Use the appropriate environment/API fixture instead of assuming constructor injection is portable. Fake-timer and store-internal cases need HTTP-level equivalents for a separate binary.

| Group | Cases | Fate |
|---|---|---|
| Route cases on the 12 retained machine endpoints, policy enforcement, rate limit, health, CORS, audit, PostgreSQL E2E | about 75 | Rewritten from `inject` to `fetch`; setup moves to environment and the policy API |
| Pure unit cases: policy engine, workspace policy, crypto signing | 15 | Become fixture tables and golden vectors shared by both languages |
| Frozen surface and hosted auth: public intents, billing, x402, mailer, auth routes, members, analytics, logging, db, Redis internals | 85 | Not ported |

Two contract endpoints, secret status and exchange status, have no server test today although both clients poll them. Error bodies are asserted loosely. The suite closes both gaps.

## Harness

- The `packages/contract-tests` workspace package in TypeScript on Vitest using `fetch`. It stays TypeScript because JWKS minting and HPKE sealing fixtures already exist there, and it outlives the SPS as the controller's compatibility gate. Rust unit tests cover internals and the Rust side of the CV vectors; the CT comparison is between two servers, not two test suites.
- A server-under-test adapter selected by `SUT`: `ts` spawns the SPS entry point, `rust` spawns the controller binary, and a base URL variable targets an already running server. Both receive the same environment: HMAC secret, agent auth providers with a JWKS file, user JWT secret, in-memory or database store, base and UI URLs.
- Fixtures: adapter-specific provisioning as described below; hpke-js for sealing. Fixture data are generated dummies; canary values are used for leak scans.
- Snapshots: for every legacy compatibility case record status code, content type, selected contract/security response headers and body. Normalize only known volatile fields by key; secret names, policy hashes and opaque signed values remain visible in snapshots. Snapshots are recorded from the TypeScript server and committed; the Rust controller must reproduce them. Four reviewed projections in `packages/contract-tests/src/snapshots.ts` compare only the stable fields where Rust intentionally differs: CT01 readiness and CT18's readiness 503 (status, `ok`, database check; Rust has no Redis check or error code), CT16 CORS and CT17 audit shape. New cases are added to the baseline additively from a TypeScript run; existing records are never rewritten, and a Rust run cannot update the file.
- Time: request, submitted and revoked TTLs (180, 60 and 300 seconds) and rate-limit windows are hardcoded in the SPS. Both servers gain test-only environment overrides for these values so expiry cases run in seconds. Defaults do not change; this is the one non-security change the SPS receives during the transition.
- Concurrency: atomicity is asserted with races over HTTP, not by calling store methods.

## P00 source reconciliation

These rows record the source behavior that was reconciled while reviewing the legacy SPS tests. They do not add hosted auth to the P00 controller contract. Reopening that surface requires a separate security review.

| Surface | Source behavior | Contract-test reconciliation |
|---|---|---|
| Hosted refresh cookie and response body | Hosted auth sets `SameSite=Lax`; only `NODE_ENV=test` includes the refresh token in the JSON body. Hosted production responses rely on the HttpOnly cookie. | Cookie assertions now match the current `Lax` source behavior. Test-mode token assertions are retained for fixture setup; they do not describe production responses or approve the cookie policy for a future hosted release. |
| Email verification success | The route redirects with 302 to `/login?verified=true`; it does not return a JSON user object. | The route test asserts the redirect target and status. |
| Verification email expiry copy | The current English and Vietnamese locale strings say the link expires in one day. | The mailer assertion matches the locale copy; the former seven-day expectation was stale. |

### Provisioning fixtures

Agent credentials are not JWKS tokens. The token endpoint authenticates a database-backed bootstrap API key (`ak_<agent-row-id>_<random>`, bcrypt-hashed, sent as a Bearer token or in `x-agent-api-key`) and mints an HS256 access token with issuer `sps` and audience `sps-agent`. Provisioning is therefore adapter-specific and must yield the same fixture shape for both servers: an administrator session, a tenant identifier, named agents with bootstrap keys, and at least one rotated and one revoked key.

| Fixture | TypeScript SPS adapter | Rust controller adapter |
|---|---|---|
| Administrator session | Seed route `POST /api/v2/auth/test/seed-workspace` with `NODE_ENV=test`, seed routes enabled and the seed-token header. Requires PostgreSQL with migrations and hosted mode, as in the existing Playwright configuration; the in-memory store cannot mint agent tokens or store policy. | Test-mode seed route `POST /api/v3/admin/test/seed` with the `x-blindpass-seed-token` header; the crash suite also bootstraps a local administrator through the admin socket |
| Tenant identifier | `workspace_id` from the seed response | Controller tenant identifier |
| Agent bootstrap keys | `agents` map in the seed response, or `POST /api/v2/agents` with the administrator token | `agents` map in the controller seed response |
| Invalidated keys | `POST /api/v2/agents/:aid/rotate-key` (previous key must fail) and `DELETE /api/v2/agents/:aid` (revoked agent must fail) | Same operations on the controller |
| External-issuer agent tokens | Ed25519 JWKS file and the agent auth providers environment variable, as in the existing fixture | Same file-based provider configuration |
| Secret registry and exchange rules | Workspace policy endpoints with the administrator token or documented bootstrap environment for selected modes | The same rules through `BLINDPASS_SECRET_REGISTRY_JSON` and `BLINDPASS_EXCHANGE_POLICY_JSON` at startup; administrative path compatibility is not required |

## Contract scenarios

CT01–CT13 and CT15–CT18 run against both servers; CT14 runs against the TypeScript SPS only. Adopted CT19 runs against Rust only and exercises two browser-status routes. Each case records status, content type and body.

| ID | Scenario | Required result |
|---|---|---|
| CT01 | `GET /healthz` and `GET /readyz` with backing store up and down. | Preserve health/readiness status and top-level envelope; readiness returns 503 when a configured dependency is down. Dependency-specific checks describe the actual backend: record SPS Redis/database checks and Rust database checks separately rather than requiring a fictional Redis service. |
| CT02 | `POST /api/v2/agents/token` with a valid bootstrap key as Bearer and as `x-agent-api-key`; missing, malformed, unknown, rotated and revoked keys; exceed the per-IP limit (default 5 per minute). | 200 with `access_token`, `access_token_expires_at` and the agent record; 401 with `missing_api_key` or `invalid_api_key`; 429 with the recorded body. The hosted tier-quota 403 is recorded from the SPS but is billing behavior and not required of the controller. |
| CT03 | `POST /api/v2/secret/request` with a server-minted access token and with an external-issuer token; without a token; wrong or missing issuer and audience, expired and just-expired tokens on the external path; missing or malformed `public_key`. | 201 with `request_id`, confirmation code in the recorded format and a `secret_url` carrying `id`, `metadata_sig`, `submit_sig` and `api_url`; 401 and 400 bodies match snapshots. Expiry has no clock tolerance. |
| CT04 | `GET /api/v2/secret/metadata/:id` with the metadata signature, the submit signature, an expired signature, a tampered signature and an unknown id. | Public key and description only for the correct scope; every other case is rejected with the recorded status and no metadata. |
| CT05 | `POST /api/v2/secret/submit/:id` with the correct signature, a repeated submit, the wrong scope, and a body over the configured limit. | First submit accepted; repeat, wrong scope and oversize rejected with the recorded statuses; ciphertext never echoed. |
| CT06 | `GET /api/v2/secret/status/:id` while pending and after submit; then for an unknown id, another agent's request, a consumed request after retrieval, and an expired request. | Body is `{status}` with `pending` or `submitted` only. Unknown, foreign, consumed and expired requests all answer 410 with `{"status":"expired"}`; no ciphertext or public key appears. Fills the current coverage gap. |
| CT07 | `GET /api/v2/secret/retrieve/:id` before submission, then after submission by the owning agent twice, by another agent, and by N parallel requests. | 409 before submission; exactly one 200 with `enc` and `ciphertext`; the repeat, the other agent and the N-1 losers of the race receive 410 `{"error":"Not available"}`. |
| CT08 | Expiry with short TTL overrides: unsubmitted request, submitted but unretrieved request, revoked marker. | Preserve each route's recorded post-expiry status/body (secret status uses 410 `expired`; exchange absence uses its not-available error). No read or consumption after expiry even before the sweep; ciphertext removed within the declared retention bound. |
| CT09 | `POST /api/v2/secret/exchange/request` under rule sets for secret name, requester and fulfiller identities, purposes, rings and same-ring; unknown secret. | Decisions `allow`, `pending_approval` and `deny` and the decision hash match the fixture table (CV05); CT09 compares the allowed exchange token's policy hash with the CV05 row for the same workspace. Unknown secrets deny. |
| CT10 | `GET /api/v2/secret/exchange/status/:id` through reachable request/reserve/submit/revoke transitions, after retrieval and after expiry; repeat as fulfiller and third party. | Snapshot actual reachable wire outcomes, not every member of the internal type enum. Retrieval removes the record; absence answers not-available. Fulfiller/third-party status is denied because status is requester-only. Policy-denied requests return 403 without an exchange id, so no status request is reachable; CT09 covers denial. |
| CT11 | `POST /api/v2/secret/exchange/fulfill`, then `POST .../submit/:id`, then `GET .../retrieve/:id`: fulfiller reserves and receives an HS256 fulfillment token with issuer `sps` and audience `agent-fulfill`; another agent attempts each step; a configured issuer's token for another workspace with the requester's subject reads status, retrieves and revokes; requester retrieves before submission, twice after, and in parallel. | Ownership binding holds at every step; the foreign-workspace token gets 410 without ciphertext and the requester still retrieves once; 409 before the fulfiller submits; one-use retrieval; token claims match CV03. |
| CT12 | `DELETE /api/v2/secret/exchange/revoke/:id` by the requester in pending and reserved states, repeated after revocation, by the fulfiller, and by a configured external issuer's `admin: true` claim; test `admin: false` and foreign-workspace negatives. | Requester and issuer-asserted admin-claim revocation return `{"status":"revoked"}` in the TypeScript baseline; the fulfiller and negative claims receive not-available. The configured issuer's tenant-scoped authority was accepted for the controller on 2026-09-24 and grants no local or fleet administration. Status reports `revoked` while the marker exists; retrieval returns 409 then 410 after expiry. |
| CT13 | `pending_approval` exchanges approved and rejected by an administrator, then continued by the machine clients. | Machine-visible transitions match the snapshots. The administrative call is adapter-specific because the dashboard contract is not preserved; the machine contract is. |
| CT14 | TypeScript SPS only: `POST /api/v2/auth/refresh` with a valid, reused, expired and absent refresh credential; record cookie attributes. | Rotation and rejection behavior remain hosted regression coverage. Its body refresh token is test-only in hosted mode, while production uses the cookie. The Rust controller has no hosted users and its local operator refresh uses `/api/v3/admin/session/refresh`. |
| CT15 | Planned: retained agent/local-tenant request and exchange limits, burst throttle and window reset with short overrides; separately inventory hosted paid-tier limits. Executed: the per-IP token-mint limit from CT02 and its window reset. | Configured equivalent limits produce matching retained 429 bodies/headers and reset without fake clocks. Paid-tier behavior is excluded only through the explicit P00 compatibility matrix, not silently implemented as billing in Rust. Neither self-hosted SPS nor Rust has per-agent request/exchange windows, so recorded decision P02-D12 needs reconciliation. |
| CT16 | CORS preflight and simple requests from allowed and disallowed origins configured by environment. | Allowed origins echoed; disallowed origins receive no CORS grant. |
| CT17 | Audit entries in the fixture workspace, scanned with the generated access tokens, bootstrap keys, signed links, fulfillment tokens and ciphertext canary emitted during the run; the TypeScript run also scans its hosted refresh token. | Metadata-only entries; no plaintext, ciphertext or signed link in audit output. The scan fails if its audit response is empty. |
| CT18 | Error body shape across 400, 401, 403, 404, 409, 410, 413, 429 and 503 from the cases above. | Each retained case matches its own recorded shape, including framework validation, status-only and route-specific errors. Do not impose a uniform new envelope on the legacy machine contract. The TypeScript 503 comes from an SPS instance with failing readiness checks; the Rust 503 comes from the running controller while its persisted clock mark is ahead of the database clock, and readiness recovers once the mark is restored. |

## Additive browser-status contract

CT19 was adopted on 2026-09-24 before the controller OpenAPI contract was frozen. It adds two client-contract routes alongside the 12 retained machine routes (14 total): one exchanges the existing metadata signature for a status-scoped signature, and one reads only the request status. The capability expires no later than the metadata signature or request deadline; retrying issuance with the same live metadata signature is idempotent while the deadline is unchanged and never extends authority. A retry after submission is clamped to the shorter submitted deadline. The metadata route keeps answering after submission until the request deadline, as in SPS. A status signature cannot submit, retrieve, or call the agent-authenticated status route. Unknown, consumed, expired, invalid and wrong-scope credentials return `410 {"status":"expired"}`. CT03–CT08 remain unchanged. CT19 has no TypeScript snapshot requirement.

| Method and path | Authorization | Response |
|---|---|---|
| `POST /api/v2/secret/browser-status/:id/capability?sig=<metadata exp.sig>` | Existing metadata-scoped signature | `200 {"status_sig":"<status exp.sig>"}`; expiry is bounded by the source signature and request deadline |
| `GET /api/v2/secret/browser-status/:id?sig=<status exp.sig>` | Separate status-scoped signature bound to that request and expiry | `200 {"status":"pending"}` or `200 {"status":"submitted"}`; otherwise `410 {"status":"expired"}` |

| ID | Scenario | Required result |
|---|---|---|
| CT19 | Rust only: lose the submit response after commit; exchange the metadata signature for a status capability and query pending/submitted/consumed/expired states. Retry capability issuance; try missing, tampered, expired, foreign-request and wrong-scope credentials, including legacy metadata/submit signatures. Repeat on both stores across restart and expiry-sweep delay; ensure a status credential cannot submit/retrieve or call agent status. | The capability is idempotent and never extends the source expiry. Only the separately authorized request reveals `pending` or `submitted`; invalid, wrong-scope, foreign, consumed and expired requests return `410 {"status":"expired"}`. No plaintext, ciphertext, public key or extra identity data is disclosed; status reads do not consume the secret. No agent token in the browser, no change to CT03–CT08 or old clients. Record exact status/error bodies from the reviewed new schema and scan logs for credential/link leakage. |

## Golden vectors and fixtures

CV-series fixtures are extracted once from the TypeScript implementation and committed under `packages/contract-tests/fixtures/`. The contract package's `vectors.test.ts` checks the TypeScript implementations. On the Rust side, `blindpass-core` pins the same CV01/CV02 outputs, the controller's route unit tests read the CV03, CV04 and CV05 fixtures, and `crates/blindpass-core/tests/hpke_interop.rs` covers CV06.

| ID | Fixture | Required result |
|---|---|---|
| CV01 | Signed-link HMAC: secret, request id, expiry and scope to `exp.sig`. | Byte-identical output in both languages; verification rejects wrong scope, expired and tampered inputs. |
| CV02 | Domain-derived signing secrets from a root secret for `browser-sig` and `agent-fulfillment`. | Identical base64url output. |
| CV03 | Fulfillment JWT with fixed issued-at, expiry and secret. | Identical token; verification rejects wrong audience and expired tokens. |
| CV04 | Confirmation code format and word lists. | Same shape and dictionary. The code space of 8 x 8 x 100 is a W5 review item, not a pass. |
| CV05 | Policy decision table: rule sets and requests to decision and hash, extracted from the policy, workspace policy and enforcement tests. | Identical decisions and hashes for every row. |
| CV06 | HPKE with DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and ChaCha20-Poly1305: RFC 9180 Appendix A.2 vectors plus round trips sealed in one language and opened in the other, both directions. | Vectors pass; round trips recover the plaintext; base64 framing matches hpke-js. |

## Client contract

CC-series cases prove the TypeScript clients run unchanged.

| ID | Scenario | Required result |
|---|---|---|
| CC01 | Replay the canned server responses embedded in the agent-skill client tests and the gateway interceptor tests as schema assertions against live responses from both servers. | Every shape the clients accept is produced by the server. |
| CC02 | Run the agent-skill, gateway and OpenClaw plugin flows and the human E2E script against the Rust controller. | All pass without client code changes. |
| CC03 | Drive the input page with Playwright against the Rust controller: signed-link load, HPKE seal and submit, expired link. | The signed-link flow works against Rust; an expired link gets 410 metadata and disables entry. The hosted-user login/refresh branch remains SPS-only. The packaged nginx page and its security headers run as a separate browser gate. |

## Execution order and gates

1. Build the harness, including provisioning fixtures, and convert portable cases under P00. The TypeScript adapter runs against PostgreSQL with the authorized test seed route and selected Redis fixtures. **Gate:** applicable CT01–CT18, CV01–CV05, TypeScript CV06 vectors and CC01 green with committed snapshots. Classify failures as harness/documentation mismatches or actual server defects from evidence; never silently change a snapshot or port an unresolved security defect.
2. P02.1 scaffolds the Rust controller and its SQLite/PostgreSQL contract CI jobs. **Gate:** the suite runs red against it with the same harness and environment, with failures recorded as incomplete. CT19 is adopted and included in the Rust matrix.
3. Implement in dependency order: CT01, CT02, CT03–CT08, CT09–CT13, CT15–CT18. Each retained endpoint is done when its cases match the snapshots. Keep CT14 in the TypeScript run and explicitly exclude it from the Rust progress manifest.
4. **Gate:** CT19, all retained CT cases, CV01–CV06 including both cross-language HPKE directions, and CC01–CC03 green against the Rust controller on SQLite and PostgreSQL under P02.
5. P00.4 owns baseline workspace CI and the TS contract job, made green in P00.5. P01.1 owns the common Cargo checks and separate real-VM runner. P02.1 owns the Rust contract jobs; CI runs retained machine parity against both servers until SPS retirement, keeps hosted-user CT14 in the TypeScript job, and runs adopted CT19 against Rust only. P01 W0 exit gates P02.6 cutover and P03 start, not P02 implementation.

## Execution record

| ID | Server under test | Version and commit | Environment | Date | Outcome | Evidence |
|---|---|---|---|---|---|---|
| P00 closure gates | TypeScript SPS and contract harness (`SUT=ts`, plus `SUT=base`) | Node 26.10.0; Vitest 4.1.11; PostgreSQL 16; Redis 7; source SHA `a18ecb1e26e576c8475f0e68d7e538278a5f4e0e` (the exact tested tree was committed at this revision) | Linux; disposable containers; isolated schema and unique Redis key namespace; real HTTP child process | 2026-09-23 | 34 TS adapter tests and 19 SUT=base HTTP cases passed with no skips. P00-I06 snapshot mismatch injection passed; no-SUT failed and skip gate rejected its report. Separate SPS PostgreSQL suite: 179 passed, 2 Redis-gated skipped; Redis integration: 2 passed; SPS E2E: 9 passed; dashboard E2E: 31 passed; landing: 1 passed. | [Snapshot](../../packages/contract-tests/fixtures/snapshots/ts-baseline.json); sanitized local test outputs were not persisted |
| P00 contract rerun | TypeScript SPS and `@blindpass/contract-tests` (`SUT=ts`) | Node 26.10.0; Vitest 4.1.11; PostgreSQL 16; Redis 7; base SHA `2bd06ab8cbe78cfa921369d0c6ab9c9c844bdc3c` plus local CT18/CC01 test edits and CT18 snapshot | Linux; uniquely named disposable Compose project and volume; isolated schema and Redis namespace; real HTTP child process | 2026-09-23 | 35/35 passed with no skips; CT01–CT18/CC01 (19 HTTP cases), CV01–CV06 (6), adapter isolation (4), snapshot/fault checks (2), normalization (3), and execution guard (1). CT18 records exact `/readyz` 503 behavior; CC01 calls the real agent-skill and gateway clients. Local snapshot-mismatch and unavailable-PostgreSQL injections both failed the contract job as expected. P00 still needs CT12/CT14 contracts, CT15 quota scope/defaults, and hosted PR-CI evidence. | [Sanitized run summary](evidence/p00-controller-contract-rerun.md) |
| P02 start-gate revalidation | TypeScript SPS and `@blindpass/contract-tests` (`SUT=ts`) | Node 26.10.0; Vitest 4.1.11; PostgreSQL 16; Redis 7; base SHA `6d41a1f6df8d90d283b53b3c7241281937702ac2` plus current P00/P02 working-tree changes | Linux; repository test Compose services; isolated schema and Redis DB 15; real HTTP child process | 2026-09-24 | 36/36 passed with no skips: 19 HTTP cases, 6 CV vectors, 4 adapter-isolation, 2 snapshot recorder, 3 normalization, 1 generated OpenAPI type, and 1 execution guard. No snapshot update was enabled. This establishes the P02 TypeScript start gate on the pre-adoption schema; the test is rerun on the adopted schema below. P00 CT12/CT14/CT15 decisions and hosted PR-CI evidence remain open. | [Sanitized run summary](evidence/p00-controller-contract-rerun.md) |
| P00 base-URL HTTP rerun | TypeScript SPS through the harness `SUT=base` adapter | Node 26.10.0; Vitest 4.1.11; PostgreSQL 16; Redis 7; same base SHA and local contract-test edits as above | Linux; uniquely named disposable Compose project and volume; isolated schema/Redis namespace; separate server and test child processes | 2026-09-23 | 19/19 HTTP cases passed with no skips. This rerun exercises the CT18 readiness-503 assertion and CC01 agent-skill/gateway client calls through the base-URL adapter. | [Sanitized run summary](evidence/p00-controller-contract-rerun.md) |
| P02 review rerun | Rust controller (`SUT=rust`) on SQLite and PostgreSQL; TypeScript SPS (`SUT=ts`, `SUT=base`) | Node 26.10.0; Vitest 4.1.11; Rust 1.98.1; PostgreSQL 16; Redis 7; commit `86f3a59` plus the uncommitted 2026-09-25 review fixes | Linux development host; temporary SQLite database or isolated PostgreSQL schema per run | 2026-09-25 | Rust 38/38 on each store with no skips and 18/18 required cases; TypeScript 39/39; `SUT=base` 19/19; the injected CT01 mismatch is rejected on both stores. The TypeScript baseline gained two additive CT03 records | [P02 evidence](evidence/p02-controller-api-migration-rerun.md) |

Record each run with the server under test, controller or SPS commit, Node or Rust toolchain, operating system, date and sanitized evidence path. Snapshot files count as evidence only with the run that produced them.
