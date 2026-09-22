# Hosted Workspace Policy Foundation Test Plan

> Historical record, archived during the 2026-09-22 documentation alignment. Dates, checkboxes, commands, and proposed decisions below describe their original review period; they do not establish current support or authorize new work. See the [current documentation](../../README.md) and [roadmap](../../product/Roadmap.md).

This document defines the integration and dashboard verification scenarios for the shared hosted milestone that moves workspace policy from global env vars into PostgreSQL-backed workspace state.

## How To Run

This milestone spans `packages/sps-server` and `packages/dashboard`.

1. Start local dependencies:
   `docker compose up -d redis postgres`
2. Export the PostgreSQL connection string and enable hosted integration coverage:
   `export DATABASE_URL=postgresql://blindpass:localdev@127.0.0.1:5433/blindpass`
   `export SPS_PG_INTEGRATION=1`
3. Run the server test suites:
   `npm test --workspace=packages/sps-server`
4. Run the dashboard test suites:
   `npm test --workspace=packages/dashboard`

## Scope

- workspace policy API and storage
- workspace policy validation
- policy enforcement against later exchange lifecycle checks
- dashboard policy management UX

## Integration Scenarios

- [x] `GET /api/v2/workspace/policy` returns only the caller workspace's current policy document and metadata
- [x] `PATCH /api/v2/workspace/policy` is restricted to `workspace_admin`
- [x] `workspace_operator` can read policy but cannot update it
- [x] policy documents persist in PostgreSQL with versioning and `updated_by_user_id`
- [x] policy audit events do not leak secret values or bootstrap credentials
- [x] rollout auto-seeds each existing hosted workspace from the current env-backed hosted policy inputs
- [x] after auto-seed, hosted SPS resolves policy from PostgreSQL even if the env-backed hosted defaults later change
- [x] newly created hosted workspaces receive an initial DB-backed policy row from the hosted bootstrap/default template
- [x] invalid or missing hosted bootstrap policy causes the migration/backfill path to fail closed rather than silently creating empty workspace policy state
- [x] reject a rule whose `secretName` is missing from the secret registry
- [x] reject duplicate `ruleId` values inside one workspace policy document
- [x] reject oversized payloads or field values beyond the documented limits
- [x] reject invalid optimistic-concurrency updates when another admin has already saved a newer version
- [x] `POST /api/v2/workspace/policy/validate` returns structured validation failures without persisting state
- [x] updating workspace A policy never changes exchange behavior for workspace B
- [x] a newly added `pending_approval` rule affects the next matching exchange request immediately
- [x] a removed or changed rule causes stale fulfillments to fail with the expected policy-changed conflict
- [x] existing exchange lifecycle checks continue to enforce same-workspace isolation after policy edits
- [x] hosted mode no longer requires editing `SPS_SECRET_REGISTRY_JSON` or `SPS_EXCHANGE_POLICY_JSON` for per-workspace policy changes

## Dashboard Scenarios

- [x] a `workspace_admin` can add, edit, and remove secret registry entries from the dashboard
- [x] a `workspace_admin` can add, edit, and remove exchange rules from the dashboard
- [x] draft validation errors render clearly before save
- [x] the dashboard shows current policy version and last-updated metadata
- [x] `workspace_operator` can inspect current policy in read-only mode if the route is exposed

## Exit Criteria

- [x] hosted policy is workspace-scoped, validated, and persisted in PostgreSQL
- [x] hosted rollout preserves current behavior by auto-seeding existing workspaces before switching hosted policy reads to PostgreSQL
- [x] exchange behavior reflects the saved workspace policy rather than process-global env vars
- [x] the dashboard exposes a usable policy-management surface for admins without leaking sensitive runtime state

## Latest Verification

Verification snapshot as of `2026-03-18`:

- [x] focused dashboard policy tests passed
- [x] focused `sps-server` workspace-policy tests passed
- [x] PostgreSQL-backed workspace-policy integration suite passed with `SPS_PG_INTEGRATION=1`
- [x] invalid-bootstrap and pending-approval PostgreSQL integration regressions are covered
