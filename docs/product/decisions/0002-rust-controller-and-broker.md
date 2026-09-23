# 0002: Rust for the host broker and the new controller

**Status:** Accepted 2026-09-22 as direction. P02 starts after the P00 TypeScript contract baseline, in parallel with P01. W0 real-VM evidence in the [roadmap](../Roadmap.md#w0-host-identity-and-custody) gates P03 start and P02.6 cutover, not the controller port. If W0 fails, a Rust controller can still replace SPS for the existing product through a revised standalone cutover review. At adoption the repository contained no Rust code; the current P01 change adds the reviewed workspace/broker foundation while the real-VM gate remains open.

**Companions:** [Specification](../Specification.md) · [Linux Fleet Pilot](../../testing/Linux%20Fleet%20Pilot.md) · [Decision 0001](0001-dashboard-ui-stack.md) · [Code architecture](../../architecture/README.md)

## Context

The roadmap says to keep the TypeScript controller unprivileged and to select a broker implementation language only after checking the OS APIs required. The [specification](../Specification.md#service-credential-loader-authentication) requires the broker to authenticate peers from `SO_PEERPIDFD` and a pidfd-to-unit lookup, run as a root-owned system service with a `0600` socket, treat the abstract socket name as a routing hint only, fail closed and report an unsupported host when pidfd support is missing.

The existing API is `packages/sps-server`, a Fastify 5 service with Redis for TTL state and PostgreSQL for management data. Its size on 2026-09-22:

| Surface | Lines (non-test) | Disposition |
|---|---|---|
| Frozen: billing, x402, guest offers and intents, analytics | 5,860 | Not ported |
| Hosted SaaS auth: registration, email verification, mailer, Turnstile, members | 3,034 | Not ported; replaced by local administration (see below) |
| Core: provisioning, exchange, approvals, policy, audit, agents, quota, rate limit, Redis store, signing | about 7,600 | Ported behind the compatibility contract; the exchange route still carries x402 branches to drop |
| Tests: in-process Fastify `inject` suites | 13,431 | Not reusable as a black-box suite |

The hosted service has been dormant since 2026-03-31 and has no adopted user base ([finding F-6](../Specification.md#repository-findings)), so there is no production data to migrate.

## Decision

1. **Implement the host broker in Rust.** Node has no first-class access to `SO_PEERPIDFD` or the systemd D-Bus pidfd lookup, cannot reliably zeroize secret material under a garbage collector, and is an unsuitable footprint for a root daemon. Rust reaches these APIs through `rustix`, `zbus` or `libsystemd` FFI. A static binary remains the release target; P01's current host-native broker is dynamically linked to `libsystemd` and OpenSSL `libcrypto`, so it does not yet meet that packaging target.
2. **Implement the new controller in Rust as well,** sharing one Cargo workspace with the broker: `crates/blindpass-core` for types, HPKE, signing and the policy engine; `crates/blindpass-broker`; `crates/blindpass-controller` on an async HTTP framework; `crates/blindpass-cli` for enrollment and administration. One language server-side avoids maintaining a TypeScript controller beside a Rust broker for a one-person team.
3. **Preserve the machine-client contract exactly.** The OpenClaw plugin, agent skill, gateway and input page remain TypeScript and must run unchanged against the Rust controller.
4. **Do not port the frozen surface or hosted SaaS auth.** The controller ships with a bootstrap local administrator, local sessions and optional members. Hosted registration, email verification, Turnstile and multi-workspace signup are not carried over, consistent with the roadmap's "no mandatory hosted signup".
5. **Drop Redis.** State transitions that Redis Lua scripts make atomic today become conditional updates in the controller database with an expiry sweep. The specification already limits the product to one controller with no concurrent writers.
6. **Default to SQLite, offer PostgreSQL.** SQLite in WAL mode is the native small-fleet default; PostgreSQL remains available for the container topology. This is the proposed answer to the specification's open database-topology decision and is settled at W2.
7. **Keep the TypeScript SPS in maintenance during the transition** with security-driven dependency updates ([Decision 0003](0003-dependency-baseline-2026-09.md)) and the narrowly scoped P00 corrections below. Retire it only after the explicit P08 replacement/data/rollback review in the Obsidian vault; an elapsed pilot window or stop decision does not automatically authorize deletion.

The accepted layout also places the HTTP harness in `packages/contract-tests` and the replacement schema at `docs/api/controller.openapi.yaml`, preserving `docs/api/openapi.yaml` as the legacy snapshot. Decision 0001 fixes `packages/console`, `assets/ui`, `desktop/approval-app` and `desktop/omarchy-widget`. Root `Cargo.toml`, `Cargo.lock` and `rust-toolchain.toml`, `tests/fleet`, `tests/browser-handoff`, `tests/deployment` and the deployment paths in the accepted phase layout in the Obsidian vault complete the accepted implementation layout. Naming is settled; scaffolding, licenses and dependency selections retain their phase gates. P00 agrees shared-core interfaces; P01.1/P02.1 coordinate one workspace foundation without a W0 dependency.

### P01 implementation notes

- The broker uses narrow C FFI to the host `libsystemd` and OpenSSL `libcrypto`; no Cargo crypto or systemd crate was added. Release packaging must either deliver a static broker or explicitly select and verify the supported host library ABI. P01 VM evidence is not a packaging or minimum-version claim.
- Direct helper requests resolve unit ID and invocation ID in one `GetUnitByPIDFD` reply. Native `LoadCredential=` requests have no frame; the abstract route carries an untrusted unit/credential hint. The pinned Ubuntu 24.04/systemd 255 VM resolved the native credential-setup peer to the consuming service unit and invocation. The broker requires root UID, an exact route-to-pidfd unit match, a present invocation, and the root-owned unit/credential mapping. Different host behavior fails closed. This removes the previous unsupported assumption that PID 1 is the socket peer.
- P01's loader and provision denials close without writing text to credential streams. The direct helper client accepts arbitrary non-empty binary bytes; it does not interpret an `ERR ` prefix as a protocol status.
- The P01 broker service uses `Type=notify`, `CAP_CHOWN` only for workload-socket group ownership, the `@system-service` syscall allowlist and namespace restriction. Any host-ABI or confinement changes require the VM gate and updated evidence.

## Compatibility contract

The following paths are called by `packages/agent-skill`, `packages/gateway`, `packages/openclaw-plugin` and `packages/browser-ui` and keep their paths, methods, request and response shapes, status codes and error bodies:

```
POST /api/v2/secret/request
GET  /api/v2/secret/metadata/:id
POST /api/v2/secret/submit/:id
GET  /api/v2/secret/status/:id
GET  /api/v2/secret/retrieve/:id
POST /api/v2/secret/exchange/request
GET  /api/v2/secret/exchange/status/:id
POST /api/v2/secret/exchange/fulfill
POST /api/v2/secret/exchange/submit/:id
GET  /api/v2/secret/exchange/retrieve/:id
DELETE /api/v2/secret/exchange/revoke/:id
POST /api/v2/agents/token
POST /api/v2/auth/refresh
```

P02.1 must adopt or omit a separate browser-authorized submission-status route before freezing the controller OpenAPI. If adopted, it is the fourteenth client-contract route and receives Rust-only CT19 coverage; it does not change the 13-route TypeScript baseline, existing agent status authorization or the `metadata`/`submit` scopes. P04 consumes that decision for SI-I02.

Cryptographic and format invariants:

- HPKE per RFC 9180 with DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and ChaCha20-Poly1305, base64 ciphertext as produced by hpke-js. Interoperability with hpke-js is proven with RFC 9180 test vectors and a round trip in both directions before any endpoint is declared compatible.
- Signed browser links: HMAC-SHA256 over `requestId.exp.scope`, encoded as `exp.sig`, for the `metadata` and `submit` scopes.
- Domain-separated signing secrets: `HMAC-SHA256(root, "blindpass:<domain>")` encoded base64url. Only the `browser-sig` and `agent-fulfillment` domains are needed once guest flows are not ported.
- Fulfillment token: HS256 JWT with issuer `sps` and audience `agent-fulfill`.
- Agent authentication: the token endpoint accepts a bootstrap API key as a Bearer token or in the `x-agent-api-key` header, format `ak_<agent-row-id>_<random>`, stored as a bcrypt hash; rotation and revocation invalidate the previous key immediately. Protected endpoints accept the server-minted HS256 access token (issuer `sps`, audience `sps-agent`, subject agent id) or a token from a configured external JWKS provider.
- Status and retrieval semantics: secret status exposes only `pending` and `submitted`; unknown, foreign, consumed and expired requests all answer 410 with `{"status":"expired"}`. Retrieval answers 409 before submission and 410 after consumption or for foreign requests. Exchange status is visible to the requester only; revocation is idempotent and permitted to the requester or an administrator.
- One-use atomic retrieval; request TTL 180 s, submitted TTL 60 s, revoked marker TTL 300 s.
- Exchange status vocabulary `pending`, `reserved`, `submitted`, `retrieved`, `revoked`, `expired`, `denied`, and policy decisions `allow`, `pending_approval`, `deny` with the SHA-256 decision hash.

The dashboard contract is not preserved. The rebuilt dashboard ([Decision 0001](0001-dashboard-ui-stack.md)) is written against the new controller OpenAPI document, which also adds the fleet endpoints and a server-side pending-approvals list so the client no longer reconstructs the queue from a ten-minute audit window.

The P00 compatibility envelope in the Obsidian vault explicitly excludes frozen paid-tier/guest/hosted-signup branches. Per-backend readiness checks describe real dependencies rather than pretending Redis remains. These exclusions do not permit undocumented changes to retained client routes, auth, ownership or lifecycle semantics.

## Checkpoints before implementation and cutover

- Confirm the local-administration auth model in decision point 4. If hosted signup returns, it is a separate record.
- Complete P00 before the controller port. Complete W0 on a real VM and record the pilot identity scenarios before P03 start or P02.6 cutover; W0 failure requires a scope/cutover amendment, not abandonment of standalone controller parity.
- Review the confirmation-code space (8 x 8 x 100 combinations) under W5 before carrying the format forward.
- Assign licenses to the new crates through the [licensing matrix](../../../LICENSES.md); the specification keeps component licensing a separate decision.

## Sequence

The P00–P10 phase index in the Obsidian vault expands these checkpoints into separate review documents and acceptance plans; this record fixes direction, not execution status.

1. **Parallel broker track (P01).** `blindpass-core` and `blindpass-broker` crates after the P00 setup slice. Prove direct-helper pidfd unit/invocation binding, manager-mediated native `LoadCredential=` routing through protected mappings, denial of forged names and user-manager clients, unsupported-host behavior, and the `LoadCredentialEncrypted=` comparison. Keep the static release artifact and supported host ABI open until they are built and verified.
2. **Parallel controller track (P02).** `blindpass-controller` implements the compatibility contract and local admin bootstrap with SQLite and PostgreSQL after the P00 baseline. Gate: existing plugin E2E scripts and the input page run unchanged against it. P01 W0 evidence joins at P02.6 cutover and P03 start; P03 then adds fleet endpoints and the pending-approvals lifecycle. The shared core/workspace foundation is coordinated independently of W0 exit.
3. **Embedded UI.** Serve the rebuilt dashboard and input page from the controller. Replace the five Unraid templates with one controller template plus an optional PostgreSQL template.
4. **Retire SPS** after the P08 review with replacement coverage, actual installation/data disposition and rollback preserved.

## Testing

The port is test-first. The legacy CT01–CT18 baseline in the [Controller Contract Suite](../../testing/Controller%20Contract%20Suite.md) is written and made green against the TypeScript SPS before any Rust endpoint exists, then run red against the Rust scaffold and driven green endpoint by endpoint.

- **Existing suites are not directly movable.** The earlier profile counted 29 files/175 cases across route, unit and store tests. P00 re-inventories actual coverage; HTTP conversion replaces in-process route coupling while pure units become golden fixtures and frozen-only cases stay with legacy code. Counts are estimates, not a claim that every file uses `inject`.
- **Gaps are closed in the conversion.** The secret status and exchange status endpoints have no server tests today; error bodies are snapshotted for every case.
- **Language-neutral suite.** The suite stays TypeScript on Vitest and `fetch`, with a server-under-test adapter that spawns either server. Rust unit tests cover internals only, so the comparison is between two servers rather than two test suites.
- **P00 source and test exceptions.** Test-only timing overrides remain rejected outside `NODE_ENV=test`; `SPS_REDIS_KEY_PREFIX` is honored only in test mode and only when explicitly set. The production request logger now records the HTTP method and route template instead of the raw URL, which can contain signed-link query tokens or request identifiers; this intentionally changes log shape while leaving response contracts unchanged. The test seed route returns 404 when production flags are set. The hosted-auth tests were corrected to current source behavior: `SameSite=Lax`, refresh-token JSON only in test mode, and email verification redirects to the login page; these assertion changes do not alter the public auth routes. These are the complete SPS source and test exceptions accepted for P00.
- **Reviewed auth-test expectation changes.** The refreshed tests now match existing implementation behavior: hosted `NODE_ENV=test` auth responses expose refresh tokens to isolated fixtures, the hosted refresh cookie uses `SameSite=Lax`, email verification redirects to `/login?verified=true`, and browser input storage uses the `blindpass_refresh_token` key in `localStorage`. These test updates do not authorize changing non-test hosted token delivery. The threat model records localStorage/body-token exposure and cleanup limits; hosted cookie and redirect behavior remain regression-tested.
- **Crypto parity.** Signed links, derived secrets, fulfillment tokens and policy decisions are golden vectors; HPKE uses RFC 9180 Appendix A.2 vectors plus round trips in both directions.
- **Clients run unchanged.** The agent-skill, gateway and OpenClaw plugin suites, the human E2E script and the input page are run against the Rust controller.
- **OS and UI evidence stay elsewhere.** systemd VM scenarios follow the [pilot plan](../../testing/Linux%20Fleet%20Pilot.md); dashboard E2E follows [Decision 0001](0001-dashboard-ui-stack.md).

## Candidate crates

Observed on crates.io on 2026-09-22 and **not yet reviewed**. Every crate goes through the dependency-guard skill's Socket review for the `cargo` ecosystem before it enters `Cargo.toml`, with `build.rs` and proc-macro behavior inspected as the skill requires.

| Need | Candidate | Version seen |
|---|---|---|
| HTTP | axum | 0.8.9 |
| Database | sqlx (SQLite and PostgreSQL) or tokio-rusqlite | 0.9.0 / 0.8.0 |
| HPKE | hpke | 0.14.1 |
| JWT | jsonwebtoken | 11.1.0 |
| Peer credentials and pidfd | rustix | 1.1.5 |
| systemd lookup | zbus (D-Bus) or libsystemd (FFI) | 5.19.0 / 0.7.2 |
| Memory hygiene | zeroize | 1.9.0 |
| Embedded static assets | rust-embed | 8.12.0 |

## Risks

- One maintainer ramping on Rust while the product pivots. Mitigated by keeping clients in TypeScript and porting only the core.
- The `hpke` crate is pre-1.0. Pin it and gate on the vector tests.
- Invocation lookup depends on either a D-Bus session to `org.freedesktop.systemd1` or `libsystemd` FFI; both must be exercised on the minimum kernel and systemd matrix the specification still leaves open.
- SQLite as default means no high availability. The specification already excludes concurrent writers, but the recovery and migration scenarios at W2 must be run, not assumed.
- Dropping hosted auth removes the current multi-tenant model. Members and roles remain; tenancy becomes one operator per controller.

## Evidence

- API availability was checked on the development host on 2026-09-22: systemd 261.2 and kernel 7.2.3; `libsystemd` exports `sd_pidfd_get_unit`, `sd_pidfd_get_owner_uid`, `sd_pidfd_get_cgroup` and `sd_bus_creds_new_from_pidfd`; `org.freedesktop.systemd1` exposes `GetUnitByPIDFD`; kernel headers define `SO_PEERPIDFD`; `cargo` 1.98.1 is installed. This is a development host, not the real-VM system-scope evidence W0 requires.
- Line counts are from `wc -l` over `packages/sps-server/src` on 2026-09-22, excluding test files.
- The endpoint list is from a search of the four client packages for `/api/v2/` paths on 2026-09-22.
- The [September 12 user-scope probe](../Specification.md#service-credential-loader-authentication) demonstrated the forged abstract-name flaw that motivates the pidfd design.
