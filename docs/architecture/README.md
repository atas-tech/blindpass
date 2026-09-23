# Current code architecture

**Source inspection:** 2026-09-22. This page describes the existing repository, not a deployment certification. Forward design lives in the [product specification](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/Specification.md); historical phases are in the Obsidian vault.

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
- Current Dockerfiles/Unraid templates package SPS and frontends. They do not implement the W2 controller's non-root, recovery, migration and two-host parity contract.
- Billing, x402, guest intake and existing A2A code remain in the repository; new investment follows the [freeze register](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/Roadmap.md#freeze-register).

For current checks use [testing setup](../testing/README.md). The [fleet test plan](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/testing/Linux%20Fleet%20Pilot.md) defines additional tests that existing suites cannot replace.
