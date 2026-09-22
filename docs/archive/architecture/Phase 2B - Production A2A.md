# Phase 2B: Production Networked Agent-to-Agent

> Historical record, archived during the 2026-09-22 documentation alignment. Dates, checkboxes, commands, and proposed decisions below describe their original review period; they do not establish current support or authorize new work. See the [current documentation](../../README.md) and [roadmap](../../product/Roadmap.md).

Turn the Phase 2A exchange contract into a deployable multi-host flow using a real runtime transport channel, explicit endpoint resolution, and reviewable exchange lifecycle records. Phase 2B does **not** change the core SPS wire contract. It hardens delivery, routing, and operational visibility around the protocol already implemented.

> [!NOTE]
> **Current repo state entering Phase 2B:** provider-based JWT/JWKS validation, ring-aware policy, approval request / approve / reject / status routes, OpenClaw transport scaffolding, env/runtime target resolution helpers, requester-side `request_secret_exchange` delivery via the OpenClaw transport, admin-only lifecycle inspection endpoints, and validated `prior_exchange_id` lineage are implemented. Delivery failures now best-effort revoke the pending exchange before surfacing an error. The remaining work is broader operational coverage and deployment guidance.

### Goals

- Deliver fulfillment tokens over a real agent-to-agent runtime channel instead of a stub handoff
- Resolve fulfiller agent identities to authenticated runtime targets deterministically
- Preserve the existing SPS exchange contract and fail closed when delivery or routing is ambiguous
- Make approval, revocation, and exchange refresh history reviewable through structured SPS records
- Keep the deployment model centered on one SPS coordinator, not Kubernetes or a cluster control plane

### Non-Goals

- No redesign of the HPKE exchange contract
- No broadcast-to-many fulfiller fanout
- No dashboard/UI requirement for approval history in this phase
- No mandatory SPIFFE/SPIRE deployment requirement
- No secret plaintext persistence or escrow

### Delivery Sequence

#### Milestone 1: Production Transport Wiring

Replace the in-process fulfillment-token handoff with a real OpenClaw runtime delivery path.

**Files**

- `packages/openclaw-plugin/index.mjs`
- `packages/openclaw-plugin/agent-transport.mjs`
- `packages/openclaw-plugin/sps-bridge.mjs`
- `packages/agent-skill/src/index.ts`
- `packages/agent-skill/src/transport.ts`

**Changes**

- Route requester-side `request_secret_exchange` through the OpenClaw transport helper by default when a runtime transport is available
- Deliver the SPS `fulfillment_token` to the resolved fulfiller target over the runtime channel
- Require explicit delivery success/failure results from the runtime transport instead of assuming handoff success
- Preserve the Phase 2A stub transport path for tests and local harnesses
- Fail closed when a target cannot be resolved or the runtime rejects delivery

**Acceptance**

- Agent B can create an exchange and deliver the fulfillment token to Agent A over the OpenClaw runtime channel
- Delivery failures surface as structured requester-side errors without reserving or mutating SPS exchange state
- Stub transport remains available for local tests

#### Milestone 2: Target Resolution and Routing Safety

Define the runtime contract that maps stable SPS agent IDs to concrete OpenClaw session targets.

**Files**

- `packages/openclaw-plugin/agent-transport.mjs`
- `packages/openclaw-plugin/index.mjs`
- `packages/openclaw-plugin/tests/index.test.mjs`

**Changes**

- Standardize target resolution precedence: explicit map, runtime resolver hook, runtime directory, then compatibility fallback
- Document the expected runtime shape for `resolveAgentTarget()` and equivalent session-directory hooks
- Add strict fail-closed behavior for duplicate, missing, or ambiguous target matches
- Emit structured audit/debug metadata for target selection decisions without logging secrets or tokens

**Acceptance**

- A stable agent ID resolves to one concrete runtime target
- Ambiguous or missing targets cause delivery failure before fulfillment begins
- Compatibility fallback behavior is clearly documented and can be disabled for stricter deployments

#### Milestone 3: Lifecycle Records and Audit Artifacts

Turn approvals, revocations, and refresh events into first-class SPS records that operators can inspect.

**Files**

- `packages/sps-server/src/routes/exchange.ts`
- `packages/sps-server/src/services/audit.ts`
- `packages/sps-server/src/services/approval.ts`
- `packages/sps-server/src/services/redis.ts`
- `packages/sps-server/src/types.ts`

**Changes**

- Persist approval decision records with approver identity, timestamp, decision, and exchange linkage
- Persist revocation records with actor identity, timestamp, and prior exchange state
- Add an optional `prior_exchange_id` request field and store a validated single-hop `supersedes_exchange_id` backlink for refresh / re-request lineage
- Expose admin-only SPS endpoints for approval history and exchange lifecycle inspection
- Keep these records metadata-only; no plaintext or recoverable secret material is stored

> [!NOTE]
> **Implemented:** approval history is stored and exposed through admin-only review endpoints, exchange lifecycle records persist request / reserve / submit / retrieve / revoke transitions, and lineage is recorded through validated single-hop backlinks.

**Acceptance**

- An operator can inspect who approved or rejected an exchange and when
- An operator can inspect who revoked an exchange and from which state
- Re-requested or rotated exchanges can be linked together for audit review through a validated single-hop backlink

#### Milestone 4: Phase 2B Test and Ops Coverage

Cover the production transport path and lifecycle records with targeted tests and deployment notes.

**Files**

- `packages/openclaw-plugin/tests/index.test.mjs`
- `packages/sps-server/tests/exchange-routes.test.ts`
- `packages/sps-server/tests/routes.test.ts`
- `docs/deployment/Unraid.md`

**Changes**

- Add end-to-end runtime transport tests for success, delivery failure, ambiguous target resolution, and unreachable targets
- Add SPS route tests for approval history, revocation history, and exchange-lineage retrieval
- Update deployment docs to describe the preferred auth-provider config and runtime target mapping expectations

**Acceptance**

- Production transport success and failure paths are covered by automated tests
- Lifecycle inspection endpoints are covered by automated tests
- Deployment docs explain the minimum runtime requirements for multi-host A2A

### Suggested Work Breakdown

1. Finish requester-side runtime transport wiring
2. Lock down target resolution precedence and fail-closed behavior
3. Add approval / revocation / lineage storage and routes
4. Extend tests for transport and lifecycle inspection
5. Finalize deployment and operator docs

### Resolved Decisions

- **Transport** → Phase 2B centers on a real runtime delivery channel; auth-provider support is already landed and is not the main remaining feature
- **Routing** → stable SPS agent IDs remain the source-of-truth identity; runtime targets are a delivery-layer mapping
- **Audit artifacts** → Phase 2B means structured SPS records and review endpoints, not a dashboard requirement
- **Lifecycle endpoint access** → Phase 2B lifecycle inspection endpoints are admin-only
- **Lineage model** → requester may send optional `prior_exchange_id`; SPS validates same requester + `secret_name` and stores one `supersedes_exchange_id` backlink
- **Legacy auth env vars** → `SPS_GATEWAY_JWKS_URL` and `SPS_GATEWAY_JWKS_FILE` have been removed; all deployments must use `SPS_AGENT_AUTH_PROVIDERS_JSON`

### Open Decisions Before Coding

- Whether requester-side retry semantics should attempt alternate fulfiller targets in a future phase, or remain single-target fail-closed

### Security Validation

1. **Delivery failure isolation**: runtime delivery failure does not reserve or mutate the exchange
2. **Target ambiguity rejection**: duplicate or ambiguous runtime targets fail before token delivery
3. **Approval history integrity**: approval records are immutable once written and linked to the correct exchange
4. **Revocation history integrity**: revocation records capture actor identity and prior exchange state
5. **Lineage visibility**: a re-requested exchange can be traced back to the prior logical request without exposing plaintext
6. **No token leakage**: runtime logs and audit records do not persist raw fulfillment tokens
