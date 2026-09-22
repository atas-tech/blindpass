# Dashboard redesign acceptance plan

**Status:** Proposed scenarios, 2026-09-22. Dashboard implementation has not started. No scenario below is passed by the design preview.

**Design:** [Dashboard redesign](../product/dashboard-redesign.md) · **Environment and commands:** [Testing setup](README.md) · **Product limits:** [Roadmap](../product/Roadmap.md)

## Harness and evidence

Implement these scenarios alongside their stage's feature work. Preserve the `DR-` IDs in test titles/evidence, and retain existing test identities such as approvals scenarios 403/404. Extend current [dashboard E2E](../../packages/dashboard/e2e), component suites and SPS integration tests rather than replacing backend checks with mockup clicks.

Use disposable PostgreSQL/Redis, seeded admin/operator/viewer accounts in two workspaces, deterministic expiry fixtures, known quota limits, long labels and generated dummy canaries. Record commit, date, package/browser versions, service configuration without credentials, command, pass/fail/skip counts, scenario IDs and sanitized artifact locations. Mock network failures only for UI recovery tests; use real backend state for auth, permissions, decisions, TTL and one-use retrieval.

Test English and Vietnamese at 320, 390, 768, 1024 and 1440 CSS pixels. Include keyboard-only use, 200% zoom, reduced motion, touch targets, long translated strings and loading/empty/error/forbidden states. Screenshot fixtures contain no bootstrap keys, bearer tokens, live input links or provider secrets. Use generated canaries for dedicated exposure checks with redacted evidence.

## Shell, visual system and authentication

| ID | Stage / level | Scenario and required outcome |
|---|---|---|
| DR-E01 | D1 / E2E | Admin visits every existing canonical route and the audit exchange deep link, refreshes, and uses back/forward. Correct content, active navigation and permission checks persist. |
| DR-E02 | D1 / E2E + API | Operator/viewer use allowed routes, forbidden direct URLs and corresponding APIs in both workspaces. UI visibility matches server enforcement; billing/member/admin pages remain protected. No cross-workspace data appears. |
| DR-E03 | D1 / E2E + visual | Open/close mobile navigation with pointer and keyboard; navigate, return, resize and zoom. Focus is visible and predictable; content is not hidden behind chrome; no page-wide horizontal overflow. |
| DR-E04 | D1/D3 / E2E | Complete login/logout, registration, expired session, forgot/reset password and forced password change using existing harness. Return locations and cookie/session behavior remain correct; error and pending states do not reveal credentials. |
| DR-E05 | D1/D3 / component + E2E | Exercise email-verification banner/resend, Turnstile enabled/disabled/error/expiry, suspended workspace and rejected credentials. Existing gates remain effective and messages accurately describe outcomes. |
| DR-E06 | D1/D3 / E2E + visual | Switch English/Vietnamese across auth and protected screens, reload and sign out/in. Existing locale persistence holds; labels, validation, dates and menus fit. No hardcoded new English-only strings. |
| DR-E07 | D1/D4 / visual + accessibility | Check every route and relevant state at the declared widths, keyboard-only and 200% zoom. Contrast, labels, status meaning beyond color, table semantics, dialog focus/Escape/return focus, touch targets and reduced-motion behavior are usable. |
| DR-I01 | D1 / integration | Exercise expired/missing credentials, CSRF failures, frame guards and refresh behavior against the existing auth contract. No styling or shared-shell change weakens protection or leaks tokens into URLs. |

## Daily operations

| ID | Stage / level | Scenario and required outcome |
|---|---|---|
| DR-E08 | D2 / E2E | Seed zero, one and multiple pending approvals with varied purpose lengths and expiry. Overview links open the correct queue detail; partial-source counts are explicitly scoped and never imply complete totals. |
| DR-E09 | D2 / E2E + API | Admin and operator approve and reject valid requests. Exactly the intended reference changes; pending controls prevent double submission; queue/count/audit reconcile. Approval is not reported as completed delivery. Extend scenario 403 beyond merely enabled buttons. |
| DR-E10 | D2 / E2E + API | Viewer opens pending detail and attempts a direct decision request. Read-only UI and server denial remain; preserve scenario 404. |
| DR-E11 | D2 / E2E + integration | Expire a selected request, decide concurrently in a second session, revoke eligibility, and interrupt a decision response. No stale approval succeeds or unsupported success is shown; reload reconciles authoritative state and preserves useful context. |
| DR-E12 | D2 / E2E | Enroll, rotate, cancel/revoke and paginate/filter agents. Correct target is used, errors are recoverable and selection stays coherent. “Active” describes enrollment rather than reachability. |
| DR-E13 | D2 / E2E + exposure | Reveal a generated bootstrap/replacement key once, close, navigate and reload. Existing reveal lifetime/copy/confirmation behavior is retained; key is absent from subsequent lists, ordinary logs, toasts and artifacts. |
| DR-E14 | D2 / E2E + API | Admin edits valid registry/rules; operator remains read-only; invalid/duplicate/missing-field rules receive useful errors. Cancel and failed saves preserve existing policy, concurrent version behavior follows the server contract, and complete policy semantics survive round-trip. |
| DR-E15 | D2 / E2E | Filter and paginate audit records, open exchange timeline/deep link, handle unknown/forbidden exchange IDs and long/untrusted metadata. Correct workspace/events/order, safe text rendering, no silent duplicate/lost rows or secret values. |
| DR-E16 | D2 / component + E2E | Independently fail overview summary, approvals, policy and audit reads; test loading, empty and 403/429/500/network states. Failed data never becomes zero/success and targeted retry restores the correct panel. |
| DR-I02 | D2 / PostgreSQL integration | Verify route and mutation RBAC, workspace scoping, audit linkage, agent key rotation/revocation, member protection and policy validation using real persisted state. UI hiding is not sufficient evidence. |
| DR-I03 | D2 / Redis + API integration | Run relevant exchange policy allow/deny/pending, TTL, rejected/expired approval and one-use retrieval cases after UI workflow changes. Successful retrieval consumes once; replay/expiry fail under existing contracts. |
| DR-I04 | D2 / integration | Reconcile approval reconstruction across audit ordering/pagination, already-decided references, expiry boundaries and duplicate events. Do not infer a complete queue from one bounded audit page. Record any backend limitation before shipping an overview total. |
| DR-I05 | D2/D4 / exposure | Use generated canaries in success, failure, validation, audit and credential-reveal paths. Inspect rendered UI, console and sanitized test artifacts for unintended exposure; distinguish intended one-time reveal/recipient access from accidental disclosure. |

## Remaining routes and regression

| ID | Stage / level | Scenario and required outcome |
|---|---|---|
| DR-E17 | D3 / E2E + API | Invite/update/remove members including cancellation, duplicate invitations, expired or failed operations, role changes and the final active admin. Current authorization and last-admin protections hold. |
| DR-E18 | D3 / E2E | Navigate role-aware usage/analytics/billing, vary periods, empty data, quota boundaries and disabled entitlements. Operators access analytics only; admins retain billing. Values and units match APIs with no invented pricing, health or trend claims. |
| DR-E19 | D3 / E2E + integration | Existing checkout/portal flows return success, cancellation and provider failure using test fixtures. Correct redirects, entitlements and availability remain; no real payments. |
| DR-E20 | D3 / E2E | Edit current settings, validate/save/cancel/error, reload and inspect persistence. Account/password forms retain existing validation and redaction behavior. |
| DR-E21 | D3 / E2E + integration | Exercise existing public-offer/guest/x402 enabled and disabled configurations using current suites. Existing routes/permissions remain; the redesign does not enable or expand frozen features. |
| DR-E22 | D3/D4 / E2E + visual | Walk all routes and dialogs with keyboard and realistic long data, compare landing mark/font/color family, check responsive auth and credential reveal. No dead controls, clipped text, inaccessible status or unstyled legacy screen remains. |
| DR-I06 | D4 / build + regression | Workspace build and unit suites, existing i18n validation, PostgreSQL/Redis gates and dashboard E2E complete. Record skips explicitly; investigate regressions and identify unrelated baseline failures before claiming readiness. |
| DR-E23 | D4 / release smoke | Deploy and roll back the frontend against the same test backend, revisit deep links and auth flows, and confirm no schema or secret-state migration is needed. No stale mixed assets or broken route fallback. |

## Execution gates

Use [testing setup](README.md) for disposable service configuration and environment loading. Run from the repository root:

```bash
npm run build
npm test
npm run validate --workspace=packages/i18n
npm run test:integration
npm run test:e2e --workspace=packages/sps-server
SPS_PG_INTEGRATION=1 npm test --workspace=packages/sps-server
npm run test:e2e
git diff --check
```

Implement focused component cases for selection, stale/error state and a11y before running full gates. Preserve useful existing E2E suites for approvals, audit, policy, management, routing, auth, billing, analytics, guest exchange and locale persistence. If release metadata or packaging changes, add the corresponding packaging regression. No dependency installation is needed for the current documentation/mockup deliverable.

Linux broker, systemd identity, stock-client browser handoff and controller packaging are outside this UI plan. Their real-VM and stock-client evidence remains in [Linux Fleet Pilot](Linux%20Fleet%20Pilot.md); this dashboard suite cannot establish those guarantees.

## Execution record

| Date | Scope | Evidence / result |
|---|---|---|
| 2026-09-22 | Design-only deliverable | Documentation and an isolated sample-data mockup created. Application build, unit suites, PostgreSQL/Redis integration and product E2E not run; no feature implementation changed. Prototype/layout checks are recorded separately below. |
| 2026-09-22 | Prototype only; not a DR scenario pass | In-app Chromium browser inspection: overview, request detail, approve/reject with queue count and audit feedback, agent status filtering, policy/members/usage/settings navigation and mobile navigation. Desktop overview measured 1024px without horizontal overflow; mobile approval view measured 320px without horizontal overflow. A narrower 305px overview also fit. Fixed a mobile header overflow during review. No warning/error entries returned from the inspected browser log. |
| 2026-09-22 | Prototype accessibility correction; not a DR scenario pass | Control borders moved from the `#27302a` divider token to `#5a6a60`, computed at 3.38/3.22/3.05:1 against background, panel and raised surfaces (WCAG 1.4.11 needs 3:1). Muted text aligned to the landing `#9ca59d` at 7.65/7.28/6.90:1. The `pointer: coarse` 44px rule was losing to higher-specificity in-table and quiet button rules, leaving those targets at 30px; the coarse selectors now match. Ratios are computed, not measured in a browser; DR-E07 still owns the real check. |
| 2026-09-22 | Static deliverable checks | `node --check` passed for extracted prototype JavaScript; fragment rendered with the visualization renderer; 49 relative documentation link targets resolved; `git diff --check` passed. No manifests, lockfiles or runtime source changed. |

Append actual execution evidence with the stable IDs as stages are implemented. Do not convert planned cases or prototype interactions into product test passes.
