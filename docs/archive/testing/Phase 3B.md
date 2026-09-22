# Phase 3B Test Plan: Operator Dashboard & Admin UX

> Historical record, archived during the 2026-09-22 documentation alignment. Dates, checkboxes, commands, and proposed decisions below describe their original review period; they do not establish current support or authorize new work. See the [current documentation](../../README.md) and [roadmap](../../product/Roadmap.md).

This document defines the End-to-End (E2E), integration, and component verification scenarios for Phase 3B.

## How To Run

Phase 3B spans both `packages/sps-server` and the new `packages/dashboard` package.

> [!NOTE]
> Autonomous payments and hosted crypto billing moved to `docs/testing/Phase 3D.md`. Hosted hardening, SDK/docs/community, and deployment moved to `docs/testing/Phase 3E.md`. Phase 3B now covers only the core operator dashboard and admin UX milestones.

1. Start local dependencies:
   `docker compose up -d redis postgres`
2. Export the PostgreSQL connection string and enable hosted integration coverage:
   `export DATABASE_URL=postgresql://blindpass:localdev@127.0.0.1:5433/blindpass`
   `export SPS_PG_INTEGRATION=1`
3. Run the server test suites:
   `npm test --workspace=packages/sps-server`
4. Run the dashboard test suites:
   `npm test --workspace=packages/dashboard`

Useful companion commands:
- `npm run dev --workspace=packages/sps-server`
- `npm run dev --workspace=packages/dashboard`
- `npm run test:e2e --workspace=packages/sps-server`

## Milestone 1: Dashboard UI Design

- [x] All 14 Stitch screens exist in project `5937100388262572555`
- [x] The admin-only Dashboard Home screen is visually distinct from role-specific list pages
- [x] Shared layout, spacing, status badges, and modal patterns are consistent across screens
- [x] Mobile navigation collapse is designed and reviewed
- [x] Desktop variants (1280px) generated and verified for all 14 screens

## Milestone 2: Dashboard Shell & Auth

- [x] **E2E: Dashboard Shell & Auth (Playwright)**
  - [x] **Scenario 001: First-time Registration**
    - Navigate to `/register`, fill workspace & owner details.
    - Assert success toast/redirect.
    - Verify `localStorage` does NOT contain access tokens.
    - Verify app shell renders with "Workspace Admin" role features.
  - [x] **Scenario 002: Login & Session Persistence**
    - Log in with verified credentials.
    - Verify redirect to `/` (Admin Home).
    - Reload page; verify session persists via refresh token rotation.
    - Verify deep link to `/agents` persists after login.
  - [x] **Scenario 003: Logout Flow**
    - Click logout in sidebar.
    - Verify redirect to `/login`.
    - Attempt to visit `/` and verify redirect back to `/login`.
  - [x] **Scenario 004: Force Password Change Enforcement**
    - Create a member via API/Admin UI with `force_password_change: true`.
    - Log in as that member.
    - Assert immediate redirect to `/change-password`.
    - Attempt to visit `/agents` (or any other route) and verify redirect back to `/change-password`.
    - Complete password change and verify access to `/agents` is restored.
  - [x] **Scenario 005: Role-based Navigation & Redirects**
    - Log in as `operator`.
    - Verify sidebar *hides* Billing, Settings, and Members.
    - Attempt to visit `/settings` and verify redirect to `/agents` (default for operator).
    - Log in as `viewer`.
    - Verify sidebar *hides* everything except Audit and Analytics.
    - Attempt to visit `/agents` and verify redirect to `/audit`.

## Milestone 3: Agent & Member Management UI

- [x] **E2E: Agent management (Playwright)**
  - [x] **Scenario 301: Admin enrolls an agent and reveals the bootstrap key once**
    - [x] Log in as `workspace_admin`.
    - [x] Navigate to `/agents`.
    - [x] Open the enroll modal adapted from the Stitch agent-enroll screen.
    - [x] Submit `agent_id` and optional `display_name`.
    - [x] Assert the returned `ak_` key is rendered in `ApiKeyReveal`.
    - [x] Copy the key and confirm the "I've saved this key" acknowledgement.
    - [x] Close/reopen the modal and refresh the page.
    - [x] Verify the previously revealed key is no longer visible anywhere in the UI.
  - [x] **Scenario 302: Operator can enroll and revoke agents**
    - [x] Log in as `workspace_operator`.
    - [x] Navigate to `/agents`.
    - [x] Enroll an agent successfully.
    - [x] Revoke that agent from the row action menu.
    - [x] Verify the row status changes to `revoked` and the agent is excluded from active-only filters.
  - [x] **Scenario 303: Rotate key invalidates the previous credential**
    - [x] Enroll an agent and store the first bootstrap key in the test.
    - [x] Trigger Rotate Key from the agent row.
    - [x] Verify the replacement key is revealed once.
    - [x] Call `POST /api/v2/agents/token` with the old key and assert `401`.
    - [x] Call `POST /api/v2/agents/token` with the new key and assert success.
  - [x] **Scenario 304: Viewer is denied access to agent management**
    - [x] Log in as `workspace_viewer`.
    - [x] Attempt to visit `/agents`.
    - [x] Verify route guard redirects away from the page.
    - [x] Attempt direct agent create/rotate/revoke API calls and verify `403 Forbidden`.

- [x] **E2E: Member management (Playwright)**
  - [x] **Scenario 305: Admin creates a member with a temporary password**
    - [x] Log in as `workspace_admin`.
    - [x] Navigate to `/members`.
    - [x] Open the add-member flow adapted from the Stitch members screen.
    - [x] Enter a valid email, role, and temporary password with at least 12 characters.
    - [x] Verify the new member row appears with `force_password_change = true`.
    - [x] Log in as that member and verify redirect to `/change-password`.
  - [x] **Scenario 306: Admin updates role and suspended status**
    - [x] Change a member from `workspace_viewer` to `workspace_operator`.
    - [x] Verify the role badge updates in the table without a full page reload.
    - [x] Suspend the same member.
    - [x] Verify the row status changes to `suspended` and the member can no longer authenticate.
  - [x] **Scenario 307: Last-admin lockout is enforced in UI and API**
    - [x] Create a workspace with exactly one active admin.
    - [x] Navigate to `/members`.
    - [x] Verify that demote/suspend controls for that admin are disabled in the UI.
    - [x] Attempt the same state transition via direct API call.
    - [x] Verify the server rejects it with the last-admin lockout error.

- [x] **E2E: Workspace settings (Playwright)**
  - [x] **Scenario 308: Admin updates workspace display name and sees owner verification status**
    - [x] Log in as `workspace_admin`.
    - [x] Navigate to `/settings`.
    - [x] Verify slug and tier render as read-only fields.
    - [x] Verify owner email verification state is displayed clearly.
    - [x] Update the display name.
    - [x] Reload the page and verify the new display name persists in both header chrome and settings form.

- [x] **Server integration: `packages/sps-server`**
  - [x] **Scenario 309: `GET /api/v2/agents` paginates with stable ordering**
    - [x] Seed more agents than one page can hold.
    - [x] Fetch page 1 with `limit`.
    - [x] Fetch page 2 using `next_cursor`.
    - [x] Verify no duplicates, deterministic ordering, and correct `next_cursor` exhaustion.
  - [x] **Scenario 310: `GET /api/v2/members` paginates with stable ordering**
    - [x] Seed more members than one page can hold.
    - [x] Fetch consecutive pages via cursor.
    - [x] Verify no duplicates and deterministic ordering.
  - [x] **Scenario 311: Agent list/status filters are workspace-scoped**
    - [x] Seed agents across two workspaces with mixed statuses.
    - [x] Verify `status=active` and `status=revoked` only return records from the caller workspace.
  - [x] **Scenario 312: Member list/status filters are workspace-scoped**
    - [x] Seed members across two workspaces with mixed statuses.
    - [x] Verify `status=active` and `status=suspended` only return records from the caller workspace.
  - [x] **Scenario 313: Last-admin lockout rejects bypass attempts**
    - [x] Attempt to demote, suspend, and delete the final active admin using correctly formed requests.
    - [x] Verify each request is rejected with the lockout error code.
  - [x] **Scenario 314: Workspace read contract exposes owner verification status**
    - [x] Call `GET /api/v2/workspace`.
    - [x] Verify the response includes the owner verification field required by `/settings`.

- [x] **Dashboard component tests: `packages/dashboard`**
  - [x] **Scenario 315: `ApiKeyReveal` copies and dismisses without persistence**
    - [x] Render `ApiKeyReveal` with an `ak_` key.
    - [x] Verify copy-to-clipboard is called.
    - [x] Verify dismissal requires acknowledgement and unmount removes the key from view.
  - [x] **Scenario 316: Agent table appends paginated rows without duplication**
    - [x] Mock two cursor pages from `GET /api/v2/agents`.
    - [x] Trigger load-more/infinite append behavior.
    - [x] Verify rows merge once and preserve sort order.
  - [x] **Scenario 317: Member create form enforces temporary password rules**
    - [x] Verify fewer than 12 characters is blocked client-side.
    - [x] Verify visibly weak temporary passwords show an error state before submit.
  - [x] **Scenario 318: Last-admin controls disable correctly**
    - [x] Render the members table with exactly one active admin.
    - [x] Verify demote/suspend controls are disabled for that row.
  - [x] **Scenario 319: Settings page uses workspace contract and role rules correctly**
    - [x] Verify admins can submit display-name updates.
    - [x] Verify non-admin roles see the data but cannot edit it if the route is later opened to them.
    - [x] Advanced secret-registry and exchange-policy management remains out of Phase 3B scope and is tracked in Phase 3E.

## Milestone 4: Audit Log Viewer & Approvals Inbox

- [x] **Audit viewer**
  - [x] Admin, operator, and viewer can load the audit page
  - [x] Audit filters by event type, actor type, resource id, and date range work correctly
  - [x] `GET /api/v2/audit` paginates with `next_cursor`
  - [x] Expanded audit rows never expose ciphertext, bootstrap API keys, or temporary passwords
- [x] **Data Masking**: Verify that `api/v2/audit` responses do not contain any `ak_` prefixes or raw secrets in the metadata JSON
- [x] **Automated Leak Scanner**: Implement a test utility or script that regex-scans recent audit logs for common secret patterns (`ak_`, `sk_`, etc.) and fails if any are found
- [x] **Exchange drill-down**
  - [x] Exchange lifecycle pages render requested, reserved, submitted, retrieved, and approval events in order
  - [x] Exchange drill-down remains workspace-scoped
- [x] **Approvals inbox**
  - [x] Admin can approve a pending exchange request
  - [x] Operator can deny a pending exchange request
  - [x] Viewer can see pending approvals but cannot approve or deny

## Milestone 5: Billing & Quota Dashboard

- [x] **Admin-only home summary**
  - [x] **Integration: `GET /api/v2/dashboard/summary`**
    - [x] Returns workspace metadata, tier, subscription billing state, and quota usage in one payload
    - [x] Returns top-level counts for enrolled agents and workspace members without requiring client fan-out
    - [x] Returns `a2a_exchange_available` as a tier-derived boolean
    - [x] Uses stable dashboard-oriented keys and nests provider-specific recurring billing details under a billing object
  - [x] Non-admin roles are forbidden from `GET /api/v2/dashboard/summary`
  - [x] Dashboard home renders solely from the summary endpoint without fan-out list calls for counts

- [x] **Billing**
  - [x] **E2E: Billing page recurring subscription flows**
    - [x] **Scenario 501: Free-tier admin starts checkout**
      - [x] Seed a free-tier workspace with a verified owner/admin session
      - [x] Open `/billing`
      - [x] Assert the current-plan card shows `Free`
      - [x] Click the upgrade CTA and assert `POST /api/v2/billing/checkout` button is present and enabled
      - [x] Verify checkout UI is stable (Full Stripe redirect verified in UI-only E2E)
    - [x] **Scenario 502: Standard-tier admin opens billing portal**
      - [x] Seed a subscription-backed standard workspace with `billing_provider='stripe'` and a provider customer id
      - [x] Open `/billing`
      - [x] Assert the page shows `Standard` plus subscription status
      - [x] Click “Manage Subscription” and verify button is present and enabled
    - [x] **Scenario 503: Portal blocked when no recurring customer exists**
      - [x] Seed a standard-tier workspace without a provider customer id
      - [x] Assert the portal action is hidden or disabled in the UI
      - [x] If forced via API, assert `POST /api/v2/billing/portal` returns `400`
  - [x] Non-admin roles cannot access the billing page in the MVP

- [x] **Quota visualization**
  - [x] **Component/UI: Quota meters**
    - [x] Secret request, agent, and member quota meters show correct usage and thresholds
    - [x] Threshold colors switch correctly at `<70%`, `70-90%`, and `>90%`
    - [x] A2A exchange availability reflects free vs. standard tier correctly
  - [x] **E2E: Admin dashboard summary**
    - [x] **Scenario 504: Admin home shows live quota summary**
      - [x] Seed an admin workspace with non-zero request, agent, and member usage
      - [x] Open `/`
      - [x] Assert the hero/status cards show workspace tier and status
      - [x] Assert all quota meters render with used/limit data from `GET /api/v2/dashboard/summary`
      - [x] Assert no list-page APIs are required to populate the home summary
    - [x] **Scenario 505: Non-admins do not land on the home summary**
      - [x] Log in as `workspace_operator` and verify routing goes to `/agents`
      - [x] Log in as `workspace_viewer` and verify routing goes to `/audit`
      - [x] Attempt direct navigation to `/` and verify the role guard still prevents the admin home summary from rendering
