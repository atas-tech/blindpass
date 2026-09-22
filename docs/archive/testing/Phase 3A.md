# Phase 3A Test Plan: Hosted Managed Platform

> Historical record, archived during the 2026-09-22 documentation alignment. Dates, checkboxes, commands, and proposed decisions below describe their original review period; they do not establish current support or authorize new work. See the [current documentation](../../README.md) and [roadmap](../../product/Roadmap.md).

This document outlines the End-to-End (E2E) testing scenarios for Phase 3A of the Agent BlindPass project.

## How To Run

Phase 3A E2E coverage is PostgreSQL-backed and is skipped unless `DATABASE_URL` and `SPS_PG_INTEGRATION=1` are set.

1. Start local dependencies:
   `docker compose up -d redis postgres`
2. Export the PostgreSQL connection string:
   `export DATABASE_URL=postgresql://blindpass:localdev@127.0.0.1:5433/blindpass`
3. Run the SPS E2E suite:
   `npm run test:e2e --workspace=packages/sps-server`

Useful companion commands:
- `npm run test:db --workspace=packages/sps-server`
- `npm run test:rate-limit --workspace=packages/sps-server`
- `npm test --workspace=packages/sps-server`

## Milestone 1-3: Foundation & Core Identity
- [x] Covered by unit and integration tests in `tests/db.test.ts`, `tests/auth-routes.test.ts`, `tests/exchange-routes.test.ts`

## Milestone 4: Agent Enrollment, Bootstrap Auth & RBAC

- [x] **Agent Enrollment Lifecycle**
    - [x] Human registers, verifies email, and logs in.
    - [x] Human creates an agent named `test-agent`.
    - [x] Human receives the bootstrap API key.
    - [x] Agent uses the API key to exchange for a short-lived JWT.
    - [x] Agent uses the JWT to store and retrieve a secret.
    - [x] Agent bootstrap key rotation invalidates the old key and activates the new key.
    - [x] Revoked agent credentials can no longer mint JWTs.
    - [x] A revoked `agent_id` can be re-enrolled in the same workspace.

- [x] **RBAC & Member Management**
    - [x] Admin creates an `operator` user.
    - [x] Operator logs in and successfully enrolls a new agent.
    - [x] Operator attempts an admin-only member-management action and fails.
    - [x] Admin demotes Operator to `viewer`.
    - [x] Viewer attempts to enroll an agent and fails with `403 Forbidden`.
    - [x] Verify last-admin lockout prevention (an admin cannot demote/delete themselves if they are the only active admin).

- [x] **Workspace Isolation**
    - [x] Workspace A enrolls `agent-A`.
    - [x] Workspace B enrolls `agent-B`.
    - [x] Workspace B agent tries to retrieve a secret from Workspace A (should fail).
    - [x] Cross-workspace exchange/fulfillment denial remains covered in `tests/exchange-routes.test.ts`.

- [x] **Token Refresh & Access Control**
    - [x] Human logs out (revokes session).
    - [x] Human refresh token becomes unusable after logout.
    - [x] An already-issued access token remains valid until TTL expiry after logout.
    - [x] Unverified workspace owner is blocked from high-risk actions such as agent enrollment.

## Milestone 5: Billing & Stripe Integration

- [x] **Subscription Upgrade Flow**
    - [x] Workspace admin creates a Stripe Checkout session.
    - [x] Simulate successful payment via Stripe webhook (`checkout.session.completed`).
    - [x] Verify workspace tier is upgraded to `standard` and subscription status is `active`.

- [x] **Subscription Downgrade & Cancellation**
    - [x] Simulate subscription deletion via Stripe webhook (`customer.subscription.deleted`).
    - [x] Verify workspace tier reverts to `free` and subscription status is `canceled`.
    - [x] Verify features restricted to `standard` tier (A2A exchange) are blocked again after downgrade.

- [x] **Quota Enforcement (Free Tier)**
    - [x] Send 10 secret requests (success).
    - [x] Send 11th secret request (should fail with `429 Too Many Requests`).
    - [x] Enroll 5 agents (success).
    - [x] Attempt to enroll 6th agent (should fail with quota exceeded error).

- [x] **Webhook Security**
    - [x] Send an invalidly signed webhook payload.
    - [x] Verify the server rejects the payload with `400` (`invalid_stripe_signature`).
    - [x] Verify duplicate Stripe customer/subscription identifiers across workspaces are rejected.

## Milestone 6: Abuse Controls & Hardening

- [x] **Rate Limiting**
    - [x] Auth endpoints: Send >10 login attempts in 1 minute from the same IP (should fail with `429`).
    - [x] Register endpoint: Send >3 signup attempts in 1 minute from the same IP (should fail with `429`).
    - [x] Token generation: Send >5 `POST /api/v2/agents/token` requests in 1 minute (should fail with `429`).
    - [x] Verify `Retry-After` headers are present and correct.

- [x] **Audit Logging (Workspace Scoped)**
    - [x] Perform various actions (enroll agent, read secret, change member role).
    - [x] Operator calls `GET /api/v2/audit`. Verify all actions are logged accurately.
    - [x] Verify audit records do not contain bootstrap API keys, temporary passwords, or ciphertext payloads.
    - [x] Workspace A attempts to read Workspace B's audit logs (returns no cross-workspace records).
    - [x] `GET /api/v2/audit/exchange/:id` returns only the caller workspace exchange lifecycle records.
    - [x] Retention cleanup removes expired audit rows on schedule.

- [x] Covered by PostgreSQL integration tests in `tests/rate-limit.test.ts`
