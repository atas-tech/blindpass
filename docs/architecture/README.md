# Current code architecture

**Source inspection:** 2026-09-22; Rust workspace section 2026-09-25. This page describes the existing repository, not a deployment certification. Forward design lives in the [product specification](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/Specification.md); historical phases are in the Obsidian vault.

## Components

| Component | Implementation |
|---|---|
| SPS | [Fastify bootstrap](../../packages/sps-server/src/index.ts), route authentication, policy/approval services and persistence |
| Browser input | [Request context](../../packages/browser-ui/src/request-context.js), configured API origin and [HPKE encryption](../../packages/browser-ui/src/crypto.js) |
| Dashboard | [Authentication context](../../packages/dashboard/src/auth/AuthContext.tsx), [API client](../../packages/dashboard/src/api/client.ts), workspace administration pages for hosted SPS. Eligible for removal since P04 slice 13: the console replaces it and its P02 browser runner moved to `packages/console/p02-browser`; SPS itself stays until P08 |
| Operator console | [React console](../../packages/console) for the Rust controller: cookie session with session-bound CSRF, approvals, fleet, policy, audit and operator screens. The controller embeds the built console and the input page and serves them itself; see [embedded UI](../../crates/blindpass-controller/src/embedded_ui.rs) |
| Desktop approval app | [Quickshell QML app](../../desktop/approval-app/README.md), a separate process: desktop bearer session (access token in memory, refresh token in a 0600 runtime file), controller calls through curl without redirects, approval list, detail and decisions |
| Omarchy widget | [Bar widget](../../desktop/omarchy-widget/README.md) inside `omarchy-shell`: reads the app's metadata-only summary and opens the app; no credentials or approval path |
| Agent runtime | [Runtime](../../packages/agent-skill/src/index.ts), [key manager](../../packages/agent-skill/src/key-manager.ts) and [secret store](../../packages/agent-skill/src/secret-store.ts) |
| Gateway | [Interception](../../packages/gateway/src/interceptor.ts), [identity](../../packages/gateway/src/identity.ts) and text URL filtering |
| OpenClaw integration | [Core](../../packages/openclaw-plugin/blindpass-core.mjs), SOPS backend and exec resolver; see [integration contract](../plugins/openclaw-capability-extension.md) |
| Private login helper | [Worker](../../helpers/login/README.md): pinned Playwright, fixed HTTPS recipes, capture disabled and protected framed IPC; selected real systemd fixture/managed controller-node dispatch and cancellation/restart reconciliation pass; full client/lifetime acceptance pending |
| Official MCP server | [Factory/stdio transport and wrapper](../../packages/mcp-server/README.md): official SDK, safe errors, bounded callbacks, legacy tools and opt-in broker request/status/cancel tools; packaged production-broker VM metadata/identity checks pass. Versioned browser intent creates an operation/approval automatically. Both stock AI clients pass selected Node26 controller/node/local HPKE tasks; ordered delivery component/SDK tests pass. Production human delivery, GUI provisioning and full client variants remain open |
| Shared localization | [i18n package](../../packages/i18n/package.json), locale resources and parity validation |

## Rust workspace

The [fleet provisioning receiver](../../crates/blindpass-broker/src/provisioning.rs)
adds broker-owned ephemeral signed browser offers and controller-signed one-use
Source admission through bounded Unix control commands. Source remains volatile
broker custody with its independent configured TTL. Host fixture tests cover
real key files/HPKE/framing; actual controller/operator GUI/relay and systemd
provisioning acceptance remain open. See [receiver scope and contract](../testing/evidence/p05-broker-provisioning-2026-10-02.md).

The Cargo workspace in [crates](../../crates) holds the P01 host broker and the P02 controller. The controller serves the 12 retained machine routes, the two CT19 browser-status routes and local administration against SQLite or PostgreSQL. It passes the contract suite locally on both stores, but it is not accepted, packaged or deployed; see the [P02 evidence](../testing/evidence/p02-controller-api-migration-rerun.md).

| Crate | Implementation |
|---|---|
| `blindpass-core` | Shared primitives with no crate dependencies: signed browser links and derived secrets, Ed25519 fleet documents with canonical JSON, policy evaluation and decision hashes, HPKE through OpenSSL `libcrypto`, the broker protocol, workload identity and credential custody |
| `blindpass-broker` | P01 host broker, peer-credential-checked fleet control socket and test binaries. Browser grant/source preparation and typed import validation have unit coverage; private IPC and the schema-4 session journal require a held helper reverse kernel proof and durable exact helper identity before source delivery. Schema-2 unfinished records retain metadata but stay blocked; older journal rollback needs a matching backup. The invocation proxy retains a kernel peer pidfd and passes actual guest same-UID wrong-unit/restarted-invocation denial with stock report/reconnect. The fixed socket-activated Root outside supervisor and native Rust client supply private control, bounded application TLS forwarding and an explicitly published Root-only backend while preserving the broker Unix-only/JIT-denied sandbox. Cookie import binds the complete prepared recipe. The opt-in production coordinator dispatches signed grants from the retained original kernel workload lease; signed-fixture and actual SQLite-controller/unprivileged-node guests reach private login, stock reads, cancellation and imported-session SIGKILL recovery. Selected managed controller/node lifecycle passes on both pinned Node profiles; AI-client, complete lifetime and full phase acceptance remain open. Journal schema 4 stores exact request correlation; schemas 2/3 retain available recovery metadata without guessing owners. Revocation outcomes are retained with private tombstones and completed outcome IDs in a separate private acknowledgement journal; a pre-fix broker cannot read the extended tombstone format, so rollback needs a pre-upgrade broker state backup |
| `blindpass-node` | Unprivileged fleet relay using HTTPS through `/usr/bin/curl`; it handles enrollment, signed-document delivery and a durable event outbox without access to broker key storage |
| `blindpass-controller` | axum HTTP API with the embedded console and input page (built by `npm run build` before `cargo build`, embedded by `build.rs`), sqlx store (SQLite WAL or PostgreSQL, schema version 16) and a local administration Unix socket. The version 14 migration deletes existing operator sessions because older session IDs were stored in plaintext; operators must sign in again. Version 15 adds independent node/resource Source bindings and public recipient offers, preserving sessions already hashed at14. Version 16 adds scoped Source links (`fleet_provisioning_links`) and immutable ciphertext receipts (`fleet_provisioning_receipts`); it is additive and preserves every earlier row. A provisioning table that already exists with the wrong columns, like a missing one, is damage and fails closed rather than being recreated. New browser and desktop access tokens live in browser cookies or desktop process memory and are stored only as SHA-256 digests in the database. An older controller cannot run against schema version 16; rollback requires a pre-migration database backup and operator reauthentication. Production startup requires the 32-byte issuer seed in `BLINDPASS_ISSUER_KEY_FILE`. Subcommands: `serve`, `check-config`, `migrate`, `reconcile-clock` and test-mode `seed --fixture` |
| `blindpass-cli` | `blindpass` administration CLI: migration, bootstrap, password reset, clock recovery, test seeding, and authenticated fleet enrollment/node commands. Fleet commands read the operator password from stdin, use the session/CSRF-protected controller API through curl, and remove their mode-0600 session cookie file after logout. Enrollment creation writes the one-use token to a new mode-0600 file; node rotation accepts the public metadata from `blindpass-node rotate-prepare` |

New broker browser events include signed `request_version: 2`; the controller's
[intent handler](../../crates/blindpass-controller/src/routes/browser_intent.rs)
strictly checks the authenticated node, registration, invocation, fields, observed
time, policy and TTL ceilings before creating a workload-requested operation.
Receipt, operation, approval and audit commit together. Grant issuance must finish
before ACK; exact replay resumes pending issuance without a new request/deadline.
Policy denial/change sends signed closure; missing original receipt or operation
cannot reconstruct authority. Named operator approval remains independent of
node/workload auth. Unversioned/manual and native contracts remain unchanged.
Updated broker/controller are required together; the database stays at schema 14.

Fresh browser workload admission retains the actual original process pidfd in a
bounded 16-lease book. ACK preserves that lease; restart and retry/status metadata
cannot reconstruct or replace it. Original process exit locally withdraws the
request through durable cancellation independently of signed time/outbox room.
Bounded current manager revalidation occurs outside the state mutex before
browser consumption and typed preflight/helper execution. The production
coordinator still needs to connect these gates to browser import/publication,
continuous authority and verified website/cgroup reconciliation.

### Controller configuration

The controller validates its environment at startup and refuses to start on any invalid value; `check-config` runs the same validation.

| Variable | Default and rules |
|---|---|
| `BLINDPASS_LISTEN` | `127.0.0.1:3200`; an unspecified address such as `0.0.0.0` is refused outside test mode |
| `BLINDPASS_PUBLIC_URL`, `BLINDPASS_UI_BASE_URL` | Required origins for signed links and the input page |
| `BLINDPASS_DATABASE_URL_FILE` | Required unless an explicit `BLINDPASS_DATA_DIR` supplies SQLite; private file holding a `sqlite:` or `postgres://` URL; inline `BLINDPASS_DATABASE_URL` is accepted only in test mode |
| `BLINDPASS_KEYS_DIR`, `BLINDPASS_DATA_DIR` | P06 opt-in absolute private roots (0700, owned by the service account). The keys root resolves `root-secret`, `agent-jwt-secret` and `issuer-key`; individual file settings override them. An explicit data root provides the SQLite `controller.db` URL when no URL/file is set. Validation creates no state; see [release layout](../deploy/release-layout.md) |
| `BLINDPASS_ROOT_SECRET_FILE`, `BLINDPASS_AGENT_JWT_SECRET_FILE` | Required key files of at least 32 bytes, unreadable by group and others |
| `BLINDPASS_ISSUER_KEY_FILE` | Required in production; raw 32-byte Ed25519 seed, mode 0600. Its public key, key ID and persisted recovery epoch appear in `/api/v3/capabilities`. |
| `BLINDPASS_AGENT_AUTH_PROVIDERS_JSON` | Optional external issuers. Each provider needs a `jwks_file`; `jwks_url` providers are refused. Issuers and audiences default to `gateway` and `sps`, tokens must carry `exp`, `iss` and `aud`, and expiry has no leeway |
| `BLINDPASS_SECRET_REGISTRY_JSON`, `BLINDPASS_EXCHANGE_POLICY_JSON` | Optional startup policy, validated like an administrator policy write; an unrecognized rule mode denies |
| `BLINDPASS_CORS_ALLOWED_ORIGINS` | Comma-separated exact origins |
| `BLINDPASS_TRUST_PROXY` | Comma-separated proxy IP addresses whose `X-Forwarded-For` is trusted |
| `BLINDPASS_BODY_LIMIT_BYTES` | 1 MiB (1 KiB–64 MiB); JSON bodies above 2 MiB are still refused by axum's default extractor limit |
| `BLINDPASS_AGENT_TOKEN_RATE_LIMIT` | 5 token mints per client IP per 60-second window |
| `BLINDPASS_AGENT_REQUEST_RATE_LIMIT`, `BLINDPASS_AGENT_EXCHANGE_RATE_LIMIT` | 60 secret-request creates and 60 exchange-request attempts per authenticated agent and tenant per window (1–10,000) |
| `BLINDPASS_AGENT_RATE_WINDOW_SECONDS` | 60 seconds (1–3,600); `BLINDPASS_TEST_AGENT_RATE_WINDOW_MS` can set a 1–3,600,000 ms test window only with `BLINDPASS_TEST_MODE=1` |
| `BLINDPASS_CLOCK_TOLERANCE_MS` | 2,000 ms (250–60,000); the running monitor checks database and host wall clocks against monotonic elapsed time and fences regressions or boot identity changes |
| `BLINDPASS_AUDIT_RETENTION_DAYS` | 90 (1–3,650) |
| `BLINDPASS_ADMIN_SOCKET_PATH` | `/run/blindpass-controller/admin.sock`; must be absolute |
| `BLINDPASS_LOG_FORMAT` | `json` (default) or `text` |
| `BLINDPASS_TLS_CERT_FILE`, `BLINDPASS_TLS_KEY_FILE` | Refused: TLS terminates at a reverse proxy (P02-D7) |
| `BLINDPASS_TEST_MODE=1`, `BLINDPASS_TEST_*` | Test-only TTL, window and seed-route overrides; refused without test mode and when `NODE_ENV=production` |

Agent bootstrap keys and operator passwords are stored as Argon2 hashes and refresh tokens as SHA-256 hashes. Browser cookies and desktop access tokens are stored only as SHA-256 digests; a database session identifier cannot authenticate. The CSRF secret remains session-bound. Deadlines use the database clock; a persisted clock anchor compares database and host wall time with monotonic elapsed time and the Linux boot ID. A regression beyond tolerance, changed boot ID or unreadable boot ID sets a durable fence and purges transient requests, exchanges, pending approvals, bootstrap tokens, rate windows and idempotency keys. The operator must run `blindpass admin reconcile-clock` before expiring authority is accepted again. Agent JWTs and signed links still use the host clock.

## Provisioning and exchange

The gateway/plugin creates an authenticated SPS request with a recipient public key. SPS returns a scoped signed input link. The configured human transport delivers that link, the input page fetches metadata from its configured API, and the browser encrypts the supplied value. The recipient retrieves and decrypts the ciphertext through its authenticated runtime.

HPKE uses X25519, HKDF-SHA256 and ChaCha20-Poly1305 in both browser and agent implementations. The older AES-256-GCM brainstorm is not the implemented cipher suite. Browser-input JavaScript and the recipient runtime are trusted plaintext endpoints; a compromised recipient or input page is outside the ciphertext-relay guarantee.

Agent-to-agent exchange adds requester/fulfiller identity, workspace policy, approval, reservation, fulfillment and one-use retrieval. Its implementation is in [exchange routes](../../packages/sps-server/src/routes/exchange.ts), [policy](../../packages/sps-server/src/services/policy.ts) and [Redis transitions](../../packages/sps-server/src/services/redis.ts). An exchange record authorizes its defined payload flow; it is not the proposed fleet operation grant.

## Persistence and authentication

Redis holds request/exchange lifecycle state; the in-memory implementation is for explicit development/test use. PostgreSQL holds users, workspaces, enrolled agents, policies, approvals/audit and existing commercial state. The bundled Compose files disable Redis persistence and provide development database defaults; they are not a durable production configuration.

SPS validates user bearer tokens and agent JWTs, including configured issuer/audience/JWKS providers and hosted workspace binding. Enrolled agents exchange bootstrap API keys at `POST /api/v2/agents/token`. A JWT claim or SPIFFE-shaped ID does not attest a host-local systemd workload.

Hosted auth issues refresh cookies; non-hosted/test flows can also return refresh tokens in JSON. Both frontends contain `localStorage` compatibility paths. The exact modes and remaining risks are documented once in the [current threat model](../security/blindpass-threat-model.md#authentication-storage).

Workspace policy is PostgreSQL-backed in hosted mode, with bootstrap seeding and no normal env fallback for a missing workspace row. Non-hosted policy can use startup configuration. See the [policy guide](../guides/policy.md).

## Implementation limits

- The MCP entry point still uses `Content-Length` framing and protocol `2024-11-05`, and has no URL-mode elicitation. A stock-client complete-workflow claim remains blocked.
- Receiving a secret into plugin memory does not make it available to unrelated shell/browser tools. The runtime store has no built-in TTL/use-count enforcement.
- SOPS protects stored material; the resolver intentionally emits plaintext to its consuming runtime. Service/session authority cannot be revoked by expiring an SPS handoff alone.
- Current Dockerfiles/Unraid templates package SPS and frontends. No template packages the Rust controller yet, and none implements the W2 non-root, recovery, migration and two-host parity contract.
- Billing, x402, guest intake and existing A2A code remain in the repository; new investment follows the [freeze register](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/Roadmap.md#freeze-register).

For current checks use [testing setup](../testing/README.md). The [fleet test plan](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/testing/Linux%20Fleet%20Pilot.md) defines additional tests that existing suites cannot replace.


### P05 browser authorization contract

The optional root-installed
[catalog](../../crates/blindpass-broker/src/browser_catalog.rs) admits fixed
`browser.session`/`browser_session` requests. Controller workload/policy/operation
routes now accept this exact pair with a 120-second operation ceiling and issue
controller-signed browser grants after validating broker evidence and approval.
The signed `request_event_key` correlates with the original invocation-owned
request; closures deny new handoff. Native grant wire fields remain unchanged.
The broker status path returns only opaque grant/operation IDs to that owner.
Request ownership, consumption mode, cancellation delivery flags and verified
closure status persist with outbound events in snapshot version 5, surviving
acknowledgement and restart. Admission stops at 10,000 owners, or earlier when the
1 MiB durable header would overflow (about 1,760 browser to 3,330 untyped owners).
Only provably terminal owners are evicted: a closure is recorded, any cancellation was
acknowledged, no runtime authority or unfinished journal record remains and no node
event still refers to the key (see [broker hardening](testing/evidence/p05-broker-hardening-2026-10-02.md)). Versions 1/2 load without inventing missing owners, and
version-3 owners have no trusted consumption mode and cannot authorize cancel.
Version-4 owners retain browser cancellation by event ID, but lack original
resource/recipe binding and cannot authorize a fresh login or retry lookup.
Older brokers refuse version 5; rollback needs a matching state backup.
Snapshot failure fences new authority until durable retry.

The invocation owner can send `cancel:<request_event_key>` for browser requests.
Local cancellation immediately denies new browser preparation/current authority,
even without fresh controller time or outbox space. Its durable intent queues a
broker-signed cancellation when space returns. The controller verifies original
browser request evidence and transactionally removes only that approval member,
withdraws any grant (including consumed/expired), signs revocation/closure and
records cancellation. A cancellation before operation creation prevents later
creation. Native and untyped legacy requests return cancel-unsupported.
`requested`, `cancelling` and signed `closed cancelled` are metadata: none proves
website invalidation or helper/browser cleanup. Existing active runtimes still
need the production coordinator to enforce withdrawal and reconcile cleanup.
Updated core, broker, relay and controller are required for this event kind.

Browser requests optionally include a bounded opaque `request_key`. Version-5
records bind it to the node/workload/unit/invocation, every original request
field and full administrator recipe (including the source destination).
An identical retry returns the original event ID without a new event or TTL,
even with stale controller time, queue pressure or persistence fencing. Changed
fields/recipe or another invocation are denied. Every new browser request,
including those without a retry key, must retain its original resource/recipe
binding; a changed catalog denies fresh preparation before source access.

`cancel-key:<request_key>` cancels an admitted browser request through the signed
path above. Before admission it persists a local withdrawal record, preventing
a late request from reaching approval. No cancellation is sent to the controller
without original request evidence. Withdrawal remains effective in memory if
persistence fails, with new authority fenced until durable retry. Such records
share the owner bound and are never evicted, because they are the only barrier against a
late request that reuses the withdrawn retry key. These transport
components do not establish private-login lost-reply or runtime recovery.
The synchronous native consumer refuses browser work before one-use consumption;
production asynchronous coordination, outside supervisor and reconciliation
remain to be integrated. These API/component checks establish no full browser
workflow support profile.

## Reverse worker proof

[`runtime_identity.rs`](../../crates/blindpass-broker/src/runtime_identity.rs)
captures the actual isolated worker's kernel pidfd through a challenge-bound
reverse connection. This addresses socket activation's systemd listener peer.
The worker's fixed Root-owned identity socket is restricted to the browser
runtime group. Cookie import requires a successful one-use proof, with exact
unit/invocation/UID checks and a boot-time deadline. Signed-grant/current-policy,
namespace/configuration and durable journal checks remain coordinator duties;
this component alone does not publish an authorized browser context.


The Root [administrator revoker](../../helpers/login/README.md#root-administrator-revocation-before-source-delivery)
is separately socket-activated and consumes only the mapped administrator
credential. Preparation validates its custody before source copying; online
preflight and current-authority callbacks gate actual source writes after durable
helper identity. The complete resource fingerprint binds administrator mapping
and managed user ID, which is independently checked before cookie import. Fixed
fixture HTTPS and selected managed Grafana Root Unix routes provide session/account
logout without exposing administrator material to the helper/browser/model.
The revoker acknowledgement does not establish exact cgroup termination or
account reuse safety; production dispatch and reconciliation remain pending.


## Asynchronous browser helper and closure components

The prepared helper exchange owns its one-use source job, proved private channel
and sealed journal permission. Preparation journals identity; the caller must
release journal/state locks before executing bounded I/O. Original process and
current authority remain required during source/response I/O. Journal drop,
failed writes and revocation withdraw permission; the detached capability retains
the journal's lifetime file lock until released.

Confirmed durable browser closure now publishes a distinct immutable result/audit
pair with deterministic keys and the original close time, independently of ACK
of the provisional intent. A matching protected closed record is required;
trusted cleanup observations still belong to the production coordinator. The
controller accepts `browser_session_closed` only for a signed browser grant;
native marker results cannot complete browser operations. A consumed browser
operation is not made uncertain merely because its short grant expires. Late
cleanup records preserve revoked authority. The MCP tools expose the safe
`closed`/`completed` metadata outcome.

Snapshot version 5 now permits locally verified browser `completed` closures;
the controller-signed closure protocol is unchanged. Pre-change version-5 brokers
reject that new value, so rollback requires a matching protected-state backup.
Controller database schema 14 is unchanged. Journal schema 4 adds exact original
request correlation for closure delivery retries; schemas 2/3 remain readable.
Older brokers require a matching pre-upgrade protected journal backup for rollback.
The opt-in coordinator has partial signed-fixture VM evidence; actual recovery,
actual fixture controller/node lifecycle passes; managed application, full client execution and phase acceptance remain open. See
[coordinator execution](../testing/evidence/p05-coordinator-2026-10-01.md).


## P05 controller offer ingestion

[Controller offer execution](../testing/evidence/p05-controller-offers-2026-10-02.md) adds versioned administrator-only
node/resource Source destinations and atomic public signed-offer ingestion from
current enrolled keys and retained original signed grants. Eleven actual HTTP
cases pass on SQLite and PostgreSQL; 500 full Rust cases pass with four
inherited ignores, and both pinned Node build/workspace gates pass with 101 SPS
skips. Scoped operator Source submission and the node relay are described below;
actual GUI/systemd acceptance remains open.

## P05 scoped Source link, submit and node relay

[Scoped submit execution](../testing/evidence/p05-scoped-submit-2026-10-02.md)
adds the operator-bound Source path on top of offer ingestion. One immutable link
per original browser grant belongs to the deciding operator (or, for an
automatically allowed grant, the administrator who configured the destination).
Metadata and submit use a fleet-specific capability signing domain plus that
operator's current browser session; a legacy exchange capability is refused.
Metadata is read-only and returns the original signed offer with independently
trusted expected values. The first valid submit atomically commits an immutable
receipt (ciphertext digest only), one controller-signed `provisioning_delivery`
node inbox document (envelope epoch equals the original grant issuer epoch) and a
`fleet.source_submitted` audit event; exact or concurrent retries never requeue.
Controller and node handle only HPKE ciphertext and public metadata.

Schema version 16 holds the two new tables, retained seven days past the original
offer deadline in bounded batches of 1,000 and never while live. The dedicated
delivery document may reach 128 KiB for a sealed 64 KiB Source; every other node
document keeps the 64 KiB cap at the controller inbox, node relay and broker
control socket, and a poll answers at most about 512 KiB beyond its first document.
The node asks its broker for a signed offer event (`BROWSER_OFFER_EVENT`) after
relaying a browser grant, posts it unchanged as a `recipient_offer` node event, and
hands an inbox `provisioning_delivery` to the broker's `PROVISION_SOURCE`. The
broker's browser-offer lifetime is a separate 180 second default, still capped by
the grant. Actual operator GUI, real systemd/stock-client provisioning and phase
acceptance remain open.
