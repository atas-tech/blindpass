# Dashboard redesign

**Status:** Proposed design, 2026-09-22. Mockup review precedes implementation. No application behavior or API has changed.

**Companions:** [Landing page](../../landing/README.md) · [Dashboard acceptance plan](../testing/Dashboard%20Redesign.md) · [Roadmap](Roadmap.md) · [Current dashboard maintenance](../architecture/dashboard-maintainability.md)

## Outcome

Make the platform dashboard feel like the new BlindPass landing page while helping an operator quickly understand who is requesting an exchange, decide with context, and inspect the resulting audit history. The redesign covers every existing dashboard and authentication screen, including loading, empty, error, read-only, and responsive states.

This is a presentation and workflow redesign of existing encrypted provisioning. The [roadmap](Roadmap.md) still owns product scope: host enrollment, verified Linux workloads, browser session handoff, native/container parity, and session revocation are proposed work. They must not appear as functioning dashboard capabilities. Frozen payment and guest features retain their existing behavior and regression coverage without expansion.

## Visual direction

Use the authored [landing stylesheet](../../landing/dist/styles.css) and [landing markup](../../landing/dist/index.html) as the brand reference.

| Element | Proposed dashboard treatment |
|---|---|
| Palette | Charcoal `#0b0e0d`, panel `#101512`, raised panel `#151b17`, lime `#c5f277`, off-white `#f0f3ed`, muted `#9ca59d`, quiet divider `#27302a`, control border `#5a6a60` |
| Contrast | `#27302a` is a decorative divider only. Interactive boundaries (inputs, selects, bordered buttons) use `#5a6a60`, which clears WCAG 1.4.11 at 3:1 against background, panel and raised surfaces. Do not border a control with the divider token. |
| Identity | Existing four-part lime mark and lowercase `blindpass.` wordmark |
| Type | Existing local Inter asset; moderate-weight headings, monospaced identifiers and small section labels |
| Hierarchy | Compact page heading, one main action, useful operational summaries, then task content |
| Surfaces | Opaque panels, fine borders, approximately 4–6px corners; remove the existing cyan/purple gradients and glow |
| Feedback | Lime for primary action/selection, distinct labeled amber and red states; do not rely on color alone |
| Density | Comfortable default with approximately 44–60px data rows; evaluate compact spacing in the mockup before deciding whether a product preference is warranted |
| Responsive layout | Persistent desktop sidebar, collapsible mobile navigation, stacked approval details, contained scrolling only for genuinely wide tables |
| Touch targets | Controls reach 44px under `pointer: coarse`, including in-table and quiet buttons. Keep the coarse-pointer rules at or above the specificity of any compact variant they must override. |

Use larger editorial typography sparingly on overview and auth pages. Daily operation screens need short headings, visible metadata, and stable action placement. The initial direction is the landing page's dark appearance; a light theme is outside this redesign. Mockup spacing/radius controls are design exploration, not promised product settings.

## First mockup

The [saved interactive mockup](../design/dashboard-redesign/README.md) preserves the conversation preview for later review. Open its [standalone browser export](../design/dashboard-redesign/index.html); the editable source is stored alongside it.

The preview illustrates an administrator's sample workspace. It includes an overview, approval queue/detail, agents, exchange policy, audit log, and lightweight members, usage/billing, and settings views. All names, counts, identifiers, timestamps, and actions are fictional. The sample clock is fixed; approval/rejection updates only local preview data.

Review these choices first:

1. Charcoal/lime brand translation, wordmark, typography, panel geometry, and density.
2. An overview led by pending decisions rather than decorative charts.
3. A queue with an adjacent approval detail pane on large screens and a stacked view on smaller screens.
4. Grouping administration separately from the daily access-control workflow.

Enrollment, key management, policy editing, billing checkout, authentication, and optional public-offer workflows are not implemented in the mockup. Preview notices are design annotations and must not ship as substitutes for those workflows.

## Information architecture and screen coverage

Preserve canonical routes and existing deep links. Labels and grouping can change independently of route names. Keep role visibility and direct-route authorization consistent with the server, and retain navigation test IDs where practical.

| Area | Current route(s) | Redesign |
|---|---|---|
| Overview | `/` | Pending approvals in latest results, active-agent count, quota usage, recent audit metadata, current policy summary. Admin-only access remains. |
| Approvals | `/approvals` | Expiry-ordered queue, selected request detail, requester/fulfiller/purpose/rule/reference, explicit decision feedback. Viewers remain read-only. |
| Agents | `/agents` | Clear status table, enrollment flow, separate rotate/revoke confirmations, existing one-time key reveal. Active means enrolled, not online. |
| Exchange policy | `/policy` | Scannable registry/rule overview and validated editor; preserve complete rule semantics and operator read-only access. |
| Audit | `/audit`, `/audit/exchange/:exchangeId` | Filterable metadata list and exchange timeline, visible actor/resource/time, shareable existing deep links. |
| Analytics | `/analytics` | Shared usage entry with billing; retain the operator-accessible analytics route, defined periods, empty/error states and truthful axes. |
| Members | `/members` | Role-first list, invitations and member management, last-admin protections, admin-only access. |
| Billing | `/billing` | Shared usage entry with analytics, admin-only billing destination, current quotas/entitlements/checkout behavior. No new pricing assumptions. |
| Settings | `/settings` | Clear profile, account and workspace groups; retain current settings and locale controls. |
| Optional public offers | `/public-offers` | Retain existing route, visibility rules, feature availability and regression behavior. Use a secondary navigation entry where available; do not activate disabled payment/intake paths. |
| Authentication | `/login`, `/register`, `/forgot-password`, `/reset-password`, `/change-password` | Shared landing-aligned auth shell with concise form content, existing verification/Turnstile/password behavior and validation feedback. |

The prototype's “Usage & billing” entry is a navigation proposal. Implementation must offer analytics to operators without exposing admin-only billing; use separate child destinations or role-aware entry routing. Do not broaden access to make the grouping easier.

## Data and behavior contracts

- Reuse [dashboard summary](../../packages/dashboard/src/api/dashboard.ts), current policy, agent, audit, analytics, and approval contracts. Add view models only where needed to share derivation between overview and detail screens.
- The existing approvals screen derives exchange requests from a bounded audit result and uses a ten-minute approval window. The overview must say “pending in latest results,” or omit an aggregate, until complete server-backed totals exist. Never present a partial audit window as the authoritative pending queue. Confirm ordering, expiry and reconciliation against API behavior before implementing.
- No new “live,” “connected,” “healthy,” “verified workload,” “active sessions,” or “access revoked” indicator without a corresponding reliable contract. Agent registration status does not establish liveness.
- Approval authorizes the exchange; purpose is policy metadata, not enforcement of a recipient's subsequent activity. Expiry is the request/approval window, not provider credential expiry. Revoking an agent does not revoke copies of provider credentials.
- Keep one-use retrieval and one-time bootstrap/replacement-key reveal intact. Keep secret plaintext, tokens, and live secure links out of lists, audit detail, notifications, fixtures and captured artifacts.
- Preserve auth cookies/storage behavior, CSRF and frame protection, verification gating, forced password change, workspace isolation, and server-side permissions. A visual refresh is not an authorization migration.
- Preserve all existing locale resources and preference persistence. Update English and Vietnamese together; do not add locales.
- Distinguish load failure from zero records. Retry only failed reads; disable duplicate pending writes and reconcile uncertain/stale decisions from authoritative state. Do not optimistically claim an exchange completed after approval.

## Delivery sequence

Each stage includes its matching [acceptance scenarios](../testing/Dashboard%20Redesign.md). Estimates should follow design review and contract inspection; no delivery date is implied.

| Stage | Work | Exit gate |
|---|---|---|
| D0 — Design review | Review this mockup, confirm navigation and density, inventory every route/role/state, capture a current baseline with dummy data | Agreed visual direction and route/state matrix; unresolved API requirements recorded |
| D1 — Foundation and shell | Landing-aligned design tokens; reusable brand, page header, buttons, form controls, status, table and dialog styles; local font; responsive layout and auth shell | Shell, keyboard/focus, navigation, localization and auth regression scenarios pass |
| D2 — Daily workflow | Overview, approvals queue/detail, agent management, policy editor, audit list/timeline; preserve complete existing mutations and reveal flows | Role, stale-decision, policy validation, audit pagination, secret-boundary and API integration scenarios pass |
| D3 — Complete coverage | Members, billing, analytics, settings, optional public offers, auth/account states, responsive and translated variants | Every existing route and relevant state uses the new system; no unfinished placeholder controls |
| D4 — Release verification | Full workspace build/tests, applicable PostgreSQL/Redis integration and dashboard E2E, visual checks and docs | Recorded executed evidence, no unexplained skips, rollback instructions and screenshots with dummy data |

Do not introduce a new UI framework or dependency solely for this redesign. React, the existing styling pipeline, and Lucide already cover the design. Any dependency change follows the global dependency-guard skill before manifests or lockfiles change.

## Implementation boundaries

Primary work belongs in `packages/dashboard/src/styles`, `components`, `pages`, and existing hooks/API adapters; changed strings belong in `packages/i18n/locales`. Preserve local `.js` import suffixes and shared translation conventions. Do not couple the application build to the standalone landing directory; decide a deliberate asset location or documented copy for the existing font and mark. Package boundaries and licenses remain unchanged.

Migrate shared primitives first, then coherent route groups. Retain compatible component APIs/test IDs where useful and update meaningful assertions when semantics intentionally change. Avoid a permanent second component system. Ship small reversible commits and keep visual changes separable from any independently justified API correction. Rollback is a frontend release/commit rollback; no data migration is proposed.

## Open items carried from design review

Raised during the 2026-09-22 mockup review and deliberately deferred. The mockup is a preview, so none of these are defects in it; each becomes a real decision the moment product code is written. Do not resolve one by copying the prototype's current behavior.

| Item | Why it matters at implementation | Owner stage |
|---|---|---|
| Font source | The mockup loads Inter from `fonts.googleapis.com`; this document and D1 both specify the existing local Inter asset. Copying token/typography rules out of the prototype will silently import the CDN link and add a third-party request to an authenticated dashboard. | D1 |
| Prototype CDN scripts | The mockup pulls `lucide`, `@floating-ui/core`, `@floating-ui/dom` and Google Fonts from `unpkg.com`/Google, version-pinned but without integrity attributes, under an `unsafe-eval` preview CSP. These are preview-only conveniences. Lucide already exists in the application; do not carry the CDN loads across, and route any genuinely new package through the dependency-guard skill before touching manifests or lockfiles. | D1 |
| Mockup export format | [index.html](../design/dashboard-redesign/index.html) is a single escaped-`srcdoc` export and [source.html](../design/dashboard-redesign/source.html) is the editable fragment. They match today only because each revision has updated both by hand. Every future tweak produces an unreviewable diff and can drift unnoticed. Generate the export from the source, or add a sync check, before the mockup is revised again. | D0, before the next mockup revision |
| Contrast and touch-target regressions | `#27302a` is a divider token and fails WCAG 1.4.11 as a control boundary; `#5a6a60` is the control border. Compact button variants must not out-specify the `pointer: coarse` 44px rule. Both were corrected in the prototype by inspection only. DR-E07 owns the measured check. | D1, verified at D4 |

## Definition of done

All current routes, role-specific entry points and relevant states are redesigned; deep links and authorization still work; visual checks cover desktop/mobile and both existing locales; sensitive values remain excluded from ordinary UI artifacts; backend-connected approval, policy, management, billing and audit regressions pass where applicable. The mockup alone satisfies none of these runtime gates. Evidence lives in the acceptance plan, not in screenshots or design claims.
