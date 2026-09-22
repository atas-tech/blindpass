# Hosted Workspace Policy Foundation

> Historical record, archived during the 2026-09-22 documentation alignment. Dates, checkboxes, commands, and proposed decisions below describe their original review period; they do not establish current support or authorize new work. See the [current documentation](../../README.md) and [roadmap](../../product/Roadmap.md).

This shared hosted milestone moves secret registry and exchange policy resolution off the process-global `SPS_SECRET_REGISTRY_JSON` / `SPS_EXCHANGE_POLICY_JSON` path and into workspace-scoped PostgreSQL state.

It is intentionally tracked outside Phase 3E because:

- Phase 3C guest offers depend on workspace-scoped `secret_name` / `secret_alias` resolution
- guest intent logic should not be built on a temporary env-backed hosted policy path
- Phase 3E still depends on the same foundation for later analytics, governance, and launch work

> [!IMPORTANT]
> This milestone must land before **Phase 3C** in hosted mode.

## Current Status

Implementation snapshot as of `2026-03-18`:

- milestone implementation is **complete** in `packages/sps-server` and `packages/dashboard`
- implemented:
  - versioned PostgreSQL workspace policy storage and validation
  - hosted startup seeding for existing workspaces missing policy rows
  - hosted registration-time bootstrap policy creation for new workspaces
  - workspace policy management API (`GET`, `PATCH`, `POST /validate`)
  - audit events for policy validate/update actions
  - hosted exchange enforcement resolving policy from workspace-scoped PostgreSQL state
  - hosted fail-closed behavior when a workspace policy row is missing after rollout
  - dashboard policy-management UI with admin edit/validate/save flows and operator read-only inspection
  - PostgreSQL-backed integration verification for storage, routes, seeding, and enforcement
- follow-up hardening still worth adding later:
  - broader dashboard E2E coverage beyond the focused page tests

## Prerequisites

- Phase 3A hosted platform is complete
- Phase 3B dashboard shell and hosted human auth are complete

## Scope

### Hosted Policy Source Of Truth

- `workspace_admin` manages a workspace-scoped secret registry and exchange policy document
- policy is stored in PostgreSQL and versioned per workspace
- SPS resolves and caches compiled policy by `workspace_id`
- environment variables remain valid only as self-hosted bootstrap/default configuration, not as the hosted per-workspace control plane

### Hosted Rollout Migration Strategy

The rollout strategy for hosted mode is **auto-seed, then DB-only**:

- during rollout, a migration or startup backfill seeds each existing hosted workspace with a PostgreSQL policy row copied from the current hosted env-backed policy inputs
- after seeding, hosted SPS resolves policy from PostgreSQL for that workspace and does **not** keep a long-lived DB-first-with-env-fallback chain for normal hosted requests
- new hosted workspaces created after rollout initialize their first policy row from the platform bootstrap/default policy template at creation time
- self-hosted deployments may continue using env-backed policy directly if they do not enable the hosted workspace policy model

The current implementation has completed the rollout strategy: startup backfill and new-workspace bootstrap are implemented, hosted exchange enforcement reads workspace policy from PostgreSQL, and hosted runtime now fails closed if a workspace policy row is unexpectedly missing instead of silently falling back to bootstrap policy.

> [!NOTE]
> If the hosted env-backed bootstrap policy is invalid or missing at migration time, the rollout should fail closed rather than silently creating empty hosted workspace policy state.

### [NEW] `packages/sps-server/src/services/workspace-policy.ts`

Workspace-scoped policy persistence and validation:

- store `secret_registry_json`, `exchange_policy_json`, `version`, `updated_by_user_id`, `created_at`, `updated_at`
- validate that every policy rule references a declared `secretName`
- reject duplicate `ruleId` values within a workspace
- limit list sizes and field lengths to avoid pathological payloads
- compile and cache an `ExchangePolicyEngine` per `(workspace_id, version)`

### [NEW] `packages/sps-server/src/routes/workspace-policy.ts`

| Endpoint | Auth | Behavior |
|----------|------|----------|
| `GET /api/v2/workspace/policy` | User JWT (admin/operator) | Return the current workspace policy document and metadata |
| `PATCH /api/v2/workspace/policy` | User JWT (admin) | Replace the workspace policy document after validation and optimistic concurrency checks |
| `POST /api/v2/workspace/policy/validate` | User JWT (admin) | Validate a draft policy without persisting it |

### Dashboard Policy Management

This milestone also includes the first hosted policy-management UI so operators do not need to edit server env vars.

Suggested dashboard additions:

```text
packages/dashboard/
  src/pages/
    Policy.tsx                    # [NEW] Workspace policy editor and validator
```

Admin-editable policy fields are limited to business-policy inputs:

- secret registry entries: `secretName`, `classification`, `description`
- exchange rules: `ruleId`, `secretName`, requester/fulfiller identities or rings, `purposes`, `mode`, `reason`, same-ring constraints

Fields that remain platform-controlled and must not be workspace-admin-editable:

- `workspace_id`, approval references, policy hashes, fulfillment reservations, and other runtime-generated state
- workload identity trust settings such as issuer, audience, JWKS, or SPIFFE requirements
- cross-workspace tenancy rules
- TTL, quota, rate-limit, billing, cryptography, and audit-retention controls

## Acceptance

- [x] hosted workspaces no longer require editing `SPS_SECRET_REGISTRY_JSON` or `SPS_EXCHANGE_POLICY_JSON` for per-workspace policy changes
- [x] existing hosted workspaces are auto-seeded from the current env-backed hosted policy during rollout
- [x] after seeding, hosted policy reads come from PostgreSQL rather than a runtime env fallback chain
- [x] `GET /api/v2/workspace/policy` returns only caller-workspace policy state
- [x] `PATCH /api/v2/workspace/policy` is admin-only, validates drafts, and records audit events
- [x] policy changes affect only the target workspace and are reflected in later exchange lifecycle checks
- [x] dashboard policy management works for `workspace_admin` and exposes read-only inspection for `workspace_operator`

## Verification Plan

Detailed E2E and integration scenarios for this milestone live in `docs/testing/Hosted Workspace Policy Foundation.md`.

## Relationship To Later Phases

- **Phase 3C** depends on this milestone for guest offer resolution and hosted policy enforcement
- **Phase 3E** builds on this milestone for analytics, ecosystem work, and launch hardening
