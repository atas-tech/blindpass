# Current code architecture

**Source inspection:** 2026-09-22; Rust workspace section 2026-09-25. This page describes the existing repository, not a deployment certification. Forward design lives in the [product specification](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/Specification.md); historical phases are in the Obsidian vault.

## Components

| Component | Implementation |
|---|---|
| SPS | [Fastify bootstrap](../../packages/sps-server/src/index.ts), route authentication, policy/approval services and persistence |
| Browser input | [Request context](../../packages/browser-ui/src/request-context.js), configured API origin and [HPKE encryption](../../packages/browser-ui/src/crypto.js) |
| Dashboard | [Authentication context](../../packages/dashboard/src/auth/AuthContext.tsx), [API client](../../packages/dashboard/src/api/client.ts), workspace administration pages |
| Agent runtime | [Runtime](../../packages/agent-skill/src/index.ts), [key manager](../../packages/agent-skill/src/key-manager.ts) and [secret store](../../packages/agent-skill/src/secret-store.ts) |
| Gateway | [Interception](../../packages/gateway/src/interceptor.ts), [identity](../../packages/gateway/src/identity.ts) and text URL filtering |
| OpenClaw integration | [Core](../../packages/openclaw-plugin/blindpass-core.mjs), SOPS backend and exec resolver; see [integration contract](../plugins/openclaw-capability-extension.md) |
| Shared localization | [i18n package](../../packages/i18n/package.json), locale resources and parity validation |

## Rust workspace

The Cargo workspace in [crates](../../crates) holds the P01 host broker and the P02 controller. The controller serves the 12 retained machine routes, the two CT19 browser-status routes and local administration against SQLite or PostgreSQL. It passes the contract suite locally on both stores, but it is not accepted, packaged or deployed; see the [P02 evidence](../testing/evidence/p02-controller-api-migration-rerun.md).

| Crate | Implementation |
|---|---|
| `blindpass-core` | Shared primitives with no crate dependencies: signed browser links and derived secrets, Ed25519 fleet documents with canonical JSON, policy evaluation and decision hashes, HPKE through OpenSSL `libcrypto`, the broker protocol, workload identity and credential custody |
| `blindpass-broker` | P01 host broker, peer-credential-checked fleet control socket and test binaries |
| `blindpass-node` | Unprivileged fleet relay using HTTPS through `/usr/bin/curl`; it handles enrollment, signed-document delivery and a durable event outbox without access to broker key storage |
| `blindpass-controller` | axum HTTP API, sqlx store (SQLite WAL or PostgreSQL, schema version 12) and a local administration Unix socket. Production startup requires the 32-byte issuer seed in `BLINDPASS_ISSUER_KEY_FILE`. Subcommands: `serve`, `check-config`, `migrate`, `reconcile-clock` and test-mode `seed --fixture` |
| `blindpass-cli` | `blindpass` administration CLI: migration, bootstrap, password reset, clock recovery, test seeding, and authenticated fleet enrollment/node commands. Fleet commands read the operator password from stdin, use the session/CSRF-protected controller API through curl, and remove their mode-0600 session cookie file after logout. Enrollment creation writes the one-use token to a new mode-0600 file; node rotation accepts the public metadata from `blindpass-node rotate-prepare` |

### Controller configuration

The controller validates its environment at startup and refuses to start on any invalid value; `check-config` runs the same validation.

| Variable | Default and rules |
|---|---|
| `BLINDPASS_LISTEN` | `127.0.0.1:3200`; an unspecified address such as `0.0.0.0` is refused outside test mode |
| `BLINDPASS_PUBLIC_URL`, `BLINDPASS_UI_BASE_URL` | Required origins for signed links and the input page |
| `BLINDPASS_DATABASE_URL_FILE` | Required file holding a `sqlite:` or `postgres://` URL; inline `BLINDPASS_DATABASE_URL` is accepted only in test mode |
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

Agent bootstrap keys and operator passwords are stored as Argon2 hashes and refresh tokens as SHA-256 hashes. The `bp_session` cookie carries the session's database identifier and the CSRF secret is stored as issued, so read access to the database exposes live browser sessions. Deadlines use the database clock; a persisted clock anchor compares database and host wall time with monotonic elapsed time and the Linux boot ID. A regression beyond tolerance, changed boot ID or unreadable boot ID sets a durable fence and purges transient requests, exchanges, pending approvals, bootstrap tokens, rate windows and idempotency keys. The operator must run `blindpass admin reconcile-clock` before expiring authority is accepted again. Agent JWTs and signed links still use the host clock.

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
