# Phase 2A: Pull-Based Agent-to-Agent Exchange

> Historical record, archived during the 2026-09-22 documentation alignment. Dates, checkboxes, commands, and proposed decisions below describe their original review period; they do not establish current support or authorize new work. See the [current documentation](../../README.md) and [roadmap](../../product/Roadmap.md).

Implement pull-based Agent → Agent exchange without breaking the existing Human → Agent flow. This phase keeps the current local/dev trust model based on gateway-signed JWTs and adds the minimum new protocol needed for autonomous exchange.

> [!NOTE]
> **Current progress:** The repo now contains the dedicated SPS exchange routes, exchange record/store primitives, fulfillment tokens, per-agent local JWT auth, configurable multi-provider agent JWT issuer/audience/JWKS validation, optional SPIFFE-shaped claim enforcement, `secret_name` registry/classification, ring-aware exchange policy rules, explicit `allow` / `pending_approval` / `deny` policy decisions, persisted approval requests with approve/reject/status endpoints, agent requester/fulfiller runtime methods, OpenClaw transport scaffolding, OpenClaw agent-target resolution via env/runtime maps, and end-to-end stub-transport exchange coverage. Remaining work is primarily Phase 2B scope: full production transport rollout and multi-host operational hardening. SPIFFE-compatible issuers remain optional for operators who already use them.

### Goals

- Preserve all existing Human → Agent behavior and routes
- Add pull-based A2A exchange using stable `secret_name` identifiers
- Bind requester, fulfiller, policy decision, and retrieval ownership in SPS
- Make fulfiller attribution explicit in audit logs
- Prevent multi-fulfiller races with atomic reservation and submit

> [!IMPORTANT]
> **Product-scope note:** Phase 2A validates the full SPS exchange protocol via test harness. It does not ship a production agent-to-agent delivery channel. A real runtime integration (e.g., OpenClaw runtime channel) is required before autonomous A2A is usable in deployment. This ships in Phase 2B alongside hardened multi-host auth and routing.

> [!IMPORTANT]
> **Local bootstrap note:** Phase 2A agents get their SPS bearer tokens from a local gateway minting step, not from a runtime HTTP issuance endpoint. The intended dev/test flow is a CLI or harness-generated JWT per agent identity, injected via environment variable such as `SPS_AGENT_TOKEN`.

### Non-Goals

- No browser or chat UX changes for Human → Agent
- No broadcast-to-many fulfiller semantics
- No SPIFFE/SPIRE requirement in Phase 2A
- No Kubernetes or cluster control-plane dependency
- No Phase 5 capability proxy or token exchange work
- No optional `fulfiller_hint` support until agent discovery and delivery semantics are defined
- No production agent-to-agent transport — Phase 2A uses a stub transport (in-process / test harness)

### Delivery Sequence

#### Milestone 1: Shared Types and Contracts

Update the core server and agent types to represent exchanges as first-class records instead of overloading the current human request schema.

**Files**

- `packages/sps-server/src/types.ts`
- `packages/agent-skill/src/sps-client.ts`
- `packages/agent-skill/src/index.ts`

**Changes**

- Add `ExchangeStatus = "pending" | "reserved" | "submitted" | "retrieved" | "revoked" | "expired" | "denied"`
- Add `PolicyDecision` type with `mode`, `approvalRequired`, `ruleId`, `reason`, `approvalReference`
- Add `StoredExchange` type:
  - `exchangeId`
  - `requesterId`
  - `requesterPublicKey`
  - `secretName`
  - `purpose`
  - `allowedFulfillerId?`
  - `fulfilledBy?`
  - `policyDecision`
  - `status`
  - `createdAt`
  - `expiresAt`
  - `enc?`
  - `ciphertext?`
- Add client-side request/response types for:
  - `createExchangeRequest`
  - `fulfillExchange`
  - `submitExchange`
  - `getExchangeStatus`
  - `retrieveExchange`

**Acceptance**

- All new route payloads have explicit TS interfaces
- Human request types remain intact and do not regress

#### Milestone 2: SPS Storage and Atomic State Transitions

Extend the store layer so exchanges have their own Redis keys and atomic transitions.

**Files**

- `packages/sps-server/src/services/redis.ts`
- `packages/sps-server/src/types.ts`

**Changes**

- Introduce exchange key space: `sps:exchange:{id}`
- Add store methods for exchange lifecycle:
  - `setExchange()`
  - `getExchange()`
  - `revokeExchange(exchangeId)` — soft-delete: set `status: "revoked"` and reset TTL to **300s** (5-min tombstone)
  - `reserveExchange(exchangeId, fulfillerId)` atomically moves `pending -> reserved`
  - `submitExchange(exchangeId, fulfillerId, enc, ciphertext, ttlSeconds)` compare-and-set on `status=reserved` and `fulfilledBy`
  - `atomicRetrieveExchange(exchangeId, requesterId)` compare requester ownership and atomically return + delete
- Use Redis Lua for reservation, submit, and retrieve to avoid read-modify-write races
- Mirror the same semantics in `InMemoryRequestStore` for tests

**Acceptance**

- Two parallel fulfill attempts cannot both reserve the same exchange
- Non-reserved agents cannot overwrite ciphertext
- Only the requester can retrieve
- Revoked exchange persists as tombstone for 5 minutes, blocking fulfill/submit/retrieve during that window
- **No separate reservation lease** — reserved exchanges expire at the original exchange TTL. If A crashes after reserving, B waits for expiry or manually revokes. No alternate-fulfiller retry path in Phase 2A.

#### Milestone 3: SPS Token and Auth Primitives

Add SPS-signed fulfillment tokens and cleanly separate agent auth from browser signatures.

**Files**

- `packages/sps-server/src/services/crypto.ts`
- `packages/sps-server/src/middleware/auth.ts`

**Changes**

- Add fulfillment token signing and verification helpers
- Add local/dev gateway minting support for per-agent JWTs:
  - one token per agent identity
  - unique `sub` per token
  - short-lived expiration suitable for dev/test runs
  - intended bootstrap shape: CLI or harness injection via env var
- Token claims:
  - `iss`
  - `aud`
  - `exchange_id`
  - `requester_id`
  - `secret_name`
  - `purpose`
  - `exp`
  - `policy_hash`
  - `approval_reference`
- Keep Human → Agent browser signature logic unchanged
- **Refactor `requireGatewayAuth` to extract per-agent identity from JWT `sub` claim.** The current auth path accepts a single shared `role: "gateway"` token — Phase 2A must extend the gateway to issue agent-specific JWTs with unique `sub` claims (e.g., `sub: "agent:crm-bot"`) so SPS can enforce requester/fulfiller ownership. Add a new `requireAgentAuth` helper that validates `sub` and returns the authenticated agent ID to route handlers.

**Acceptance**

- SPS can mint and verify a fulfillment token without exposing requester public key until fulfillment
- Expired or tampered tokens fail cleanly
- Replayed tokens fail once the exchange is no longer `pending`
- **Two agents with different `sub` claims are distinguishable by SPS auth — a JWT for agent A cannot pass ownership checks for agent B**
- **Fulfillment with a stale `policy_hash` is rejected — if policy changes after exchange creation, the token becomes unfulfillable**
- Local/dev agents can start with distinct bearer tokens without requiring a token-minting HTTP service

#### Milestone 4: SPS Exchange Routes

Add dedicated A2A endpoints without disturbing existing Human → Agent routes.

**Files**

- `packages/sps-server/src/routes/exchange.ts` **(new file — exchange routes live in a dedicated module)**
- `packages/sps-server/src/services/audit.ts`

**Changes**

- Add `POST /api/v2/secret/exchange/request`
  - authenticate requester B
  - validate `secret_name` and `purpose`
  - require `fulfiller_hint` in Phase 2A
  - evaluate static allowlist policy and **bind policy snapshot + `policy_hash`** to the exchange record
  - persist exchange with `status=pending`
  - return `exchange_id`, `status`, `expires_at`, `fulfillment_token`, `policy`
- Add `POST /api/v2/secret/exchange/fulfill`
  - authenticate fulfiller A
  - verify token
  - **verify `policy_hash` from token matches current policy hash** — reject `409` on mismatch (B must re-request)
  - atomically reserve exchange
  - return requester metadata and `fulfilled_by`
  - replay after `reserved`, `submitted`, `revoked`, or `expired` must fail without changing state
- Add `POST /api/v2/secret/exchange/submit/:id`
  - authenticate A
  - compare-and-set `reserved -> submitted`
  - reset retrieval TTL
  - return `retrieve_by`, `fulfilled_by`
- Add `GET /api/v2/secret/exchange/retrieve/:id`
  - authenticate B
  - atomically get and delete only if requester matches
  - return `enc`, `ciphertext`, `secret_name`, `fulfilled_by`
  - return a generic not-available response for non-owner, missing, expired, revoked, or already-consumed exchanges
- Add `GET /api/v2/secret/exchange/status/:id`
  - authenticate requester
  - return current status
- Add `DELETE /api/v2/secret/exchange/revoke/:id`
  - authenticate requester or admin
  - soft-delete: set `status: "revoked"` + reset TTL to 300s tombstone
  - **authorized revoke returns `200` with `{ "status": "revoked" }`** (control-plane success signal)
  - unauthorized / non-owner probes still get generic "not available" (anti-enumeration)
- Add A2A audit events:
  - `exchange_requested`
  - `exchange_reserved`
  - `exchange_submitted`
  - `exchange_retrieved`
  - `exchange_revoked`
  - `exchange_denied`

**Acceptance**

- Human → Agent routes still pass unchanged
- Exchange routes enforce requester and fulfiller ownership
- Audit events include `exchange_id`, `secret_name`, `requester_id`, `fulfilled_by`, `policy_rule_id`, `approval_reference`

#### Milestone 5: Policy Layer for Phase 2A

Start with a static, explicit policy implementation keyed by `secret_name`.

**Files**

- `packages/sps-server/src/services/` new policy module, for example `policy.ts`
- `packages/sps-server/src/index.ts`
- configuration docs / env handling as needed

**Changes**

- Add a small local policy engine:
  - input: `requesterId`, `secretName`, `purpose`, `fulfillerHint`
  - output: `PolicyDecision`
- Start with config-driven allowlists:
  - exact `secret_name`
  - allowed requester IDs
  - allowed fulfiller IDs
  - optional same-ring shortcut if encoded in agent IDs
- Deny by default
- No free sharing across same ring

**Acceptance**

- A request for an unknown `secret_name` is denied
- A requester cannot name an arbitrary fulfiller outside the allowlist

#### Milestone 6: Agent Skill Requester Flow

Extend the runtime so an agent can request a secret from another agent using the new SPS exchange contract.

**Files**

- `packages/agent-skill/src/sps-client.ts`
- `packages/agent-skill/src/index.ts`

**Changes**

- Add client methods:
  - `createExchangeRequest()`
  - `getExchangeStatus()`
  - `retrieveExchange()`
- Extend requester polling:
  - add `reservedTimeoutMs` for stalled `reserved` exchanges
  - if status remains `reserved` longer than the timeout, fail fast locally
  - issue best-effort `DELETE /api/v2/secret/exchange/revoke/:id` as cleanup
- Add runtime orchestration for requester B:
  - generate ephemeral HPKE keypair
  - call `createExchangeRequest`
  - deliver `fulfillment_token` to target agent via **stub transport** (in-process handoff or test harness; production transport deferred to Phase 2B)
  - poll exchange status
  - retrieve and decrypt
  - store in `SecretStore` under `secret_name`
- Ensure missing secret logic still supports Human → Agent lazy re-request when no A2A policy exists

**Acceptance**

- A requester can fetch a secret from another agent without using browser UI
- Existing `requestAndStoreSecret()` Human → Agent path remains functional
- A stalled `reserved` exchange does not block requester B until full exchange expiry

#### Milestone 7: Agent Skill Fulfiller Flow

Allow an authorized agent that already holds a secret to fulfill a request safely.

**Files**

- `packages/agent-skill/src/sps-client.ts`
- `packages/agent-skill/src/index.ts`
- `packages/agent-skill/src/secret-store.ts`

**Changes**

- Add client methods:
  - `fulfillExchange()`
  - `submitExchange()`
- Add runtime orchestration for fulfiller A:
  - receive `fulfillment_token`
  - call `fulfillExchange`
  - look up `secret_name` in local in-memory store
  - if missing, fail closed with a structured error
  - encrypt to requester public key
  - submit ciphertext
- Do not allow a fulfiller to synthesize a secret from chat context; it must come from local trusted state

**Acceptance**

- A fulfiller without the secret does not degrade into Human → Agent automatically
- A fulfiller can only submit after SPS reservation succeeds

#### Milestone 8: Gateway and Transport Boundaries

Keep Gateway changes minimal in Phase 2A. Fulfillment token delivery uses a **stub transport** — production agent-to-agent transport ships in Phase 2B alongside hardened multi-host auth and routing.

**Files**

- `packages/gateway/src/identity.ts`
- `packages/gateway/src/sps-client.ts`

**Changes**

- Reuse current gateway-issued JWTs for agent auth to SPS
- Add a local/dev minting path for per-agent JWTs:
  - CLI command or harness helper
  - inject token into each agent process separately
  - no runtime HTTP issuance endpoint in Phase 2A
- No browser or human notification changes required for A2A
- Fulfillment token delivery in Phase 2A is in-process (test harness passes token directly between agent instances)
- Production transport (OpenClaw runtime channel or equivalent) deferred to Phase 2B

**Acceptance**

- Gateway JWT issuance remains compatible with both Human → Agent and A2A endpoints
- Integration tests pass the fulfillment token between agents without requiring a real transport channel
- Two local agent instances can be launched with distinct minted JWTs and complete an exchange end-to-end

### Testing Plan

#### SPS Server

- `exchange-routes.test.ts`
  - create exchange success
  - deny unknown `secret_name`
  - deny unauthorized fulfiller hint
  - fulfill reserves exchange
  - second fulfill gets `409`
  - replayed fulfillment token after `reserved` gets rejected
  - replayed fulfillment token after `submitted` or `revoked` gets rejected
  - submit by non-reserved fulfiller gets `409`
  - retrieve by non-requester gets the same generic not-available response as a missing or expired exchange
  - revoke prevents later submit and retrieve
- `exchange-store.test.ts`
  - Lua reservation semantics
  - compare-and-set submit semantics
  - atomic retrieve semantics with requester binding
- `exchange-token.test.ts`
  - sign/verify round-trip
  - tampered `secret_name`
  - expired token
  - mismatched `policy_hash`

#### Agent Skill

- requester flow success end-to-end with mocked SPS
- fulfiller flow success with local secret present
- fulfiller flow fails closed when secret missing
- requester cannot retrieve after expiration
- requester times out stalled `reserved` exchanges and performs best-effort revoke
- Human → Agent runtime still passes existing tests

#### Integration

- two agents, one SPS, one Redis (fulfillment token passed via **stub transport** — in-process handoff)
- agent B requests `stripe.api_key.prod` from agent A
- agent A reserves and submits
- agent B retrieves and decrypts
- concurrent second fulfiller attempt is rejected
- revoked exchange returns generic "not available" to non-owner probes (anti-enumeration)
- authorized revoke returns `200` with `{ "status": "revoked" }` (control-plane success)
- fulfill with stale `policy_hash` returns `409`
- reserved exchange with crashed fulfiller expires at original TTL (no separate lease)
- audit log contains `fulfilled_by`

### Suggested Work Breakdown

1. Types + token helpers
2. Redis atomic exchange primitives
3. SPS exchange routes
4. Agent requester flow
5. Agent fulfiller flow
6. Policy module
7. Tests and hardening

### Resolved Decisions

- **Exchange routes** → dedicated `routes/exchange.ts` (separate from H2A `secrets.ts`)
- **Revocation** → soft-delete with tombstone + 5-min TTL (audit log retains event permanently)
- **Transport** → stub transport (in-process) for Phase 2A; production transport deferred to Phase 2B alongside hardened multi-host auth/routing
- **Local JWT bootstrap** → per-agent JWT minted by local CLI/harness and injected into each agent; no runtime HTTP issuance endpoint in Phase 2A
- **Reserved stall handling** → requester-side `reservedTimeoutMs` with best-effort revoke cleanup; no separate reservation lease in Phase 2A

### Open Decisions Before Coding

- Whether optional `fulfiller_hint` should be revisited after transport/discovery semantics exist

---

### Security Validation

1. **Zero-knowledge**: Inspect Redis during live request — only `enc` + `ciphertext`, no plaintext
2. **TTL expiry**: Create request, wait 3+ min, verify `410 Gone`
3. **TTL reset**: Submit, verify retrieval window is 60s (not 180s)
4. **Atomic retrieve**: Two concurrent `/retrieve` calls — exactly one succeeds
5. **Egress filter**: `https://evil.com/steal` through filter → redacted
6. **Homograph filter**: `https://sеcrets.yourdomain.com` (Cyrillic е) → redacted
7. **LLM blindness**: Interceptor response contains no URL or code
8. **JWT enforcement**: `/request` without valid JWT → `401`
9. **HMAC tampering**: `/metadata` with modified `exp` in sig → `403`
10. **Oversized payload**: `/submit` with 10MB body → `413`
11. **Referrer leakage protection**: `GET /r/:id?...` and `/api/v2/secret/*` responses include `Referrer-Policy: no-referrer`

---
