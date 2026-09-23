# Controller Contract Suite

**Proposed:** 2026-09-22

**Status:** P00 TypeScript baseline implemented and executed on 2026-09-22; Rust parity and fleet scenarios remain proposed.

**Design:** [Decision 0002](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/decisions/0002-rust-controller-and-broker.md) · [Specification](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/Specification.md) · [Linux Fleet Pilot](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/testing/Linux%20Fleet%20Pilot.md)

The Rust controller is built test-first. The CT01–CT18 compatibility baseline is written and made green against the existing TypeScript SPS before any Rust endpoint exists, then run against the Rust scaffold and driven green endpoint by endpoint. It covers API compatibility for machine clients. It does not cover the OS, broker or deployment guarantees, which stay in the [pilot plan](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/testing/Linux%20Fleet%20Pilot.md).

P00 owns the TypeScript baseline and P02 the Rust parity gate; their implementation and acceptance plans are maintained in the Obsidian vault. The cross-language portion of CV06 necessarily runs after Rust crypto exists. The compatibility envelope preserves selected machine behavior; frozen paid-tier/guest/hosted-signup branches have explicit exclusions, while new local administration and fleet APIs have separate phase tests.

## Why the existing suites cannot be moved

The earlier test profile counted 29 SPS files and 175 cases; P00 must inventory the actual source revision rather than treat those counts as coverage guarantees. Route suites drive Fastify in-process through `inject`; pure unit and Redis store suites exercise internals directly. Some fixtures pass registry/rules as constructor options; the source also supports `SPS_SECRET_REGISTRY_JSON` and `SPS_EXCHANGE_POLICY_JSON`, and workspace policy APIs. Use the appropriate environment/API fixture instead of assuming constructor injection is portable. Fake-timer and store-internal cases need HTTP-level equivalents for a separate binary.

| Group | Cases | Fate |
|---|---|---|
| Route cases on the 13 contract endpoints, policy enforcement, rate limit, health, CORS, audit, PostgreSQL E2E | about 75 | Rewritten from `inject` to `fetch`; setup moves to environment and the policy API |
| Pure unit cases: policy engine, workspace policy, crypto signing | 15 | Become fixture tables and golden vectors shared by both languages |
| Frozen surface and hosted auth: public intents, billing, x402, mailer, auth routes, members, analytics, logging, db, Redis internals | 85 | Not ported |

Two contract endpoints, secret status and exchange status, have no server test today although both clients poll them. Error bodies are asserted loosely. The suite closes both gaps.

## Harness

- The `packages/contract-tests` workspace package in TypeScript on Vitest using `fetch`. It stays TypeScript because JWKS minting and HPKE sealing fixtures already exist there, and it outlives the SPS as the controller's compatibility gate. Rust unit tests cover internals only; the comparison is between two servers, not two test suites.
- A server-under-test adapter selected by `SUT`: `ts` spawns the SPS entry point, `rust` spawns the controller binary, and a base URL variable targets an already running server. Both receive the same environment: HMAC secret, agent auth providers with a JWKS file, user JWT secret, in-memory or database store, base and UI URLs.
- Fixtures: adapter-specific provisioning as described below; hpke-js for sealing. Fixture data are generated dummies; canary values are used for leak scans.
- Snapshots: for every legacy compatibility case record status code, content type, selected contract/security response headers and body. Normalize only known volatile fields by key; secret names, policy hashes and opaque signed values remain visible in snapshots. Snapshots are recorded from the TypeScript server and committed; the Rust controller must reproduce them.
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
| Administrator session | Seed route `POST /api/v2/auth/test/seed-workspace` with `NODE_ENV=test`, seed routes enabled and the seed-token header. Requires PostgreSQL with migrations and hosted mode, as in the existing Playwright configuration; the in-memory store cannot mint agent tokens or store policy. | Local administrator bootstrap through the controller CLI or first-run API |
| Tenant identifier | `workspace_id` from the seed response | Controller tenant identifier |
| Agent bootstrap keys | `agents` map in the seed response, or `POST /api/v2/agents` with the administrator token | Enrollment through the controller API with the administrator token |
| Invalidated keys | `POST /api/v2/agents/:aid/rotate-key` (previous key must fail) and `DELETE /api/v2/agents/:aid` (revoked agent must fail) | Same operations on the controller |
| External-issuer agent tokens | Ed25519 JWKS file and the agent auth providers environment variable, as in the existing fixture | Same file-based provider configuration |
| Secret registry and exchange rules | Workspace policy endpoints with the administrator token or documented bootstrap environment for selected modes | Adapter-specific local policy API with equivalent rules; administrative path compatibility is not required |

## Contract scenarios

CT01–CT18 run against both servers; CT19 below is an optional Rust-only extension. Each case records status, content type and body.

| ID | Scenario | Required result |
|---|---|---|
| CT01 | `GET /healthz` and `GET /readyz` with backing store up and down. | Preserve health/readiness status and top-level envelope; readiness returns 503 when a configured dependency is down. Dependency-specific checks describe the actual backend: record SPS Redis/database checks and Rust database checks separately rather than requiring a fictional Redis service. |
| CT02 | `POST /api/v2/agents/token` with a valid bootstrap key as Bearer and as `x-agent-api-key`; missing, malformed, unknown, rotated and revoked keys; exceed the per-IP limit (default 5 per minute). | 200 with `access_token`, `access_token_expires_at` and the agent record; 401 with `missing_api_key` or `invalid_api_key`; 429 with the recorded body. The hosted tier-quota 403 is recorded from the SPS but is billing behavior and not required of the controller. |
| CT03 | `POST /api/v2/secret/request` with a server-minted access token and with an external-issuer token; without a token; wrong issuer, audience and expiry on the external path; missing or malformed `public_key`. | 201 with `request_id`, confirmation code in the recorded format and a `secret_url` carrying `id`, `metadata_sig`, `submit_sig` and `api_url`; 401 and 400 bodies match snapshots. |
| CT04 | `GET /api/v2/secret/metadata/:id` with the metadata signature, the submit signature, an expired signature, a tampered signature and an unknown id. | Public key and description only for the correct scope; every other case is rejected with the recorded status and no metadata. |
| CT05 | `POST /api/v2/secret/submit/:id` with the correct signature, a repeated submit, the wrong scope, and a body over the configured limit. | First submit accepted; repeat, wrong scope and oversize rejected with the recorded statuses; ciphertext never echoed. |
| CT06 | `GET /api/v2/secret/status/:id` while pending and after submit; then for an unknown id, another agent's request, a consumed request after retrieval, and an expired request. | Body is `{status}` with `pending` or `submitted` only. Unknown, foreign, consumed and expired requests all answer 410 with `{"status":"expired"}`; no ciphertext or public key appears. Fills the current coverage gap. |
| CT07 | `GET /api/v2/secret/retrieve/:id` before submission, then after submission by the owning agent twice, by another agent, and by N parallel requests. | 409 before submission; exactly one 200 with `enc` and `ciphertext`; the repeat, the other agent and the N-1 losers of the race receive 410 `{"error":"Not available"}`. |
| CT08 | Expiry with short TTL overrides: unsubmitted request, submitted but unretrieved request, revoked marker. | Preserve each route's recorded post-expiry status/body (secret status uses 410 `expired`; exchange absence uses its not-available error). No read or consumption after expiry even before the sweep; ciphertext removed within the declared retention bound. |
| CT09 | `POST /api/v2/secret/exchange/request` under rule sets for secret name, requester and fulfiller identities, purposes, rings and same-ring; unknown secret. | Decisions `allow`, `pending_approval` and `deny` and the decision hash match the fixture table (CV05); CT09 compares the allowed exchange token's policy hash with the CV05 row for the same workspace. Unknown secrets deny. |
| CT10 | `GET /api/v2/secret/exchange/status/:id` through reachable request/reserve/submit/revoke transitions, after retrieval and after expiry; repeat as fulfiller and third party. | Snapshot actual reachable wire outcomes, not every member of the internal type enum. Retrieval removes the record; absence answers not-available. Fulfiller/third-party status is denied because status is requester-only. Policy-denied requests return 403 without an exchange id, so no status request is reachable; CT09 covers denial. |
| CT11 | `POST /api/v2/secret/exchange/fulfill`, then `POST .../submit/:id`, then `GET .../retrieve/:id`: fulfiller reserves and receives an HS256 fulfillment token with issuer `sps` and audience `agent-fulfill`; another agent attempts each step; requester retrieves before submission, twice after, and in parallel. | Ownership binding holds at every step; 409 before the fulfiller submits; one-use retrieval; token claims match CV03. |
| CT12 | `DELETE /api/v2/secret/exchange/revoke/:id` by the requester in pending and reserved states, repeated after revocation, by the fulfiller, and by a configured external issuer's `admin: true` claim; test `admin: false` and foreign-workspace negatives. | Requester and issuer-asserted admin-claim revocation return `{"status":"revoked"}` in the TypeScript baseline; the fulfiller and negative claims receive not-available. This admin-claim authority is observed behavior pending an explicit controller decision. Status reports `revoked` while the marker exists; retrieval returns 409 then 410 after expiry. |
| CT13 | `pending_approval` exchanges approved and rejected by an administrator, then continued by the machine clients. | Machine-visible transitions match the snapshots. The administrative call is adapter-specific because the dashboard contract is not preserved; the machine contract is. |
| CT14 | `POST /api/v2/auth/refresh` with a valid, reused, expired and absent refresh credential; record cookie attributes. | Rotation and rejection behavior recorded from hosted test-mode SPS. Its body refresh token is test-only in hosted mode, while production uses the cookie; controller auth mode and wire shape require a decision. |
| CT15 | Retained agent/local-tenant request and exchange limits, burst throttle and window reset with short overrides; separately inventory hosted paid-tier limits. | Configured equivalent limits produce matching retained 429 bodies/headers and reset without fake clocks. Paid-tier behavior is excluded only through the explicit P00 compatibility matrix, not silently implemented as billing in Rust. |
| CT16 | CORS preflight and simple requests from allowed and disallowed origins configured by environment. | Allowed origins echoed; disallowed origins receive no CORS grant. |
| CT17 | Audit entries in the fixture workspace, scanned with the actual generated access/refresh tokens, bootstrap keys, signed links, fulfillment tokens and ciphertext canary emitted during the run. | Metadata-only entries; no plaintext, ciphertext or signed link in audit output. The scan fails if its audit response is empty. |
| CT18 | Error body shape across 400, 401, 403, 404, 409, 410, 413, 429 and 503 from the cases above. | Each retained case matches its own recorded shape, including framework validation, status-only and route-specific errors. Do not impose a uniform new envelope on the legacy machine contract. |

## Additive browser-status contract

P02.1 must record adopt/omit before freezing `docs/api/controller.openapi.yaml`. Adoption adds a fourteenth client-contract route alongside the unchanged 13 legacy routes; its exact method/path, authorization issuance, expiry and response/error schema are part of that review. CT19 has no TypeScript snapshot requirement. Omission is recorded as not applicable by decision, with SI-I02 verifying the recovery control is absent.

| ID | Scenario | Required result |
|---|---|---|
| CT19 | Rust only, if adopted: lose the submit response after commit and query the reviewed browser-authorized status route in pending/submitted/consumed/expired states; try missing, tampered, expired, foreign-request and wrong-scope credentials including legacy metadata/submit signatures. Repeat on both stores across restart and expiry-sweep delay; ensure a status credential cannot submit/retrieve or call agent status. | Only the separately authorized request reveals the reviewed minimal status; no plaintext, ciphertext, public key or extra identity data. Expiry and scope isolation enforced; status reads do not consume the secret. No agent token in the browser, no change to CT03–CT08 or old clients. Record exact status/error bodies from the reviewed new schema and scan logs for credential/link leakage. |

## Golden vectors and fixtures

CV-series fixtures are extracted once from the TypeScript implementation, committed as JSON, and consumed by both the contract suite and the Rust `core` crate's unit tests.

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
| CC02 | Run the agent-skill, gateway and OpenClaw plugin suites and the human E2E script against the Rust controller. The script currently builds the SPS in-process and needs a base URL option. | All pass without client code changes. |
| CC03 | Drive the input page with Playwright against the Rust controller: signed-link load, HPKE seal and submit, expired link. | Same behavior as against the SPS; page content security policy unchanged. |

## Execution order and gates

1. Build the harness, including provisioning fixtures, and convert portable cases under P00. The TypeScript adapter runs against PostgreSQL with the authorized test seed route and selected Redis fixtures. **Gate:** applicable CT01–CT18, CV01–CV05, TypeScript CV06 vectors and CC01 green with committed snapshots. Classify failures as harness/documentation mismatches or actual server defects from evidence; never silently change a snapshot or port an unresolved security defect.
2. P02.1 scaffolds the Rust controller and its SQLite/PostgreSQL contract CI jobs. **Gate:** the suite runs red against it with the same harness and environment, with failures recorded as incomplete. Decide browser-status adoption before schema freeze; if adopted, include CT19 in the Rust matrix.
3. Implement in dependency order: CT01, CT02, CT03–CT08, CT09–CT13, CT14, CT15–CT18. Each endpoint is done when its cases match the snapshots.
4. **Gate:** CT19 if adopted, all retained CT cases, CV01–CV06 including both cross-language HPKE directions, and CC01–CC03 green against the Rust controller on SQLite and PostgreSQL under P02.
5. P00.4 owns baseline workspace CI and the TS contract job, made green in P00.5. P01.1 owns the common Cargo checks and separate real-VM runner. P02.1 owns the Rust contract jobs; CI runs legacy parity against both servers until SPS retirement, and CT19 against Rust only if adopted. P01 W0 exit gates P02.6 cutover and P03 start, not P02 implementation.

## Execution record

| ID | Server under test | Version and commit | Environment | Date | Outcome | Evidence |
|---|---|---|---|---|---|---|
| P00 closure gates | TypeScript SPS and contract harness (`SUT=ts`, plus `SUT=base`) | Node 26.10.0; Vitest 4.1.11; PostgreSQL 16; Redis 7; source SHA `a18ecb1e26e576c8475f0e68d7e538278a5f4e0e` (the exact tested tree was committed at this revision) | Linux; disposable containers; isolated schema and unique Redis key namespace; real HTTP child process | 2026-09-23 | 34 TS adapter tests and 19 SUT=base HTTP cases passed with no skips. P00-I06 snapshot mismatch injection passed; no-SUT failed and skip gate rejected its report. Separate SPS PostgreSQL suite: 179 passed, 2 Redis-gated skipped; Redis integration: 2 passed; SPS E2E: 9 passed; dashboard E2E: 31 passed; landing: 1 passed. | [Snapshot](../../packages/contract-tests/fixtures/snapshots/ts-baseline.json); sanitized local test outputs were not persisted |

Record each run with the server under test, controller or SPS commit, Node or Rust toolchain, operating system, date and sanitized evidence path. Snapshot files count as evidence only with the run that produced them.
