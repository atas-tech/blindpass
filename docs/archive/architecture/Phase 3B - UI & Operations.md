# Phase 3B: Operator Dashboard & Admin UX

> Historical record, archived during the 2026-09-22 documentation alignment. Dates, checkboxes, commands, and proposed decisions below describe their original review period; they do not establish current support or authorize new work. See the [current documentation](../../README.md) and [roadmap](../../product/Roadmap.md).

Phase 3B transitions the focus from building the underlying hosted SaaS primitives (completed in Phase 3A) to shipping the core human-facing control plane. This phase introduces the persistent Operator Dashboard, completes the main admin workflows, and lands the recurring billing and quota surfaces needed for day-to-day workspace management.

**Prerequisite**: All 6 Phase 3A milestones are complete — PostgreSQL-backed workspaces, human auth, workspace-scoped SPS, agent enrollment, Stripe billing, rate limiting, and durable audit are all in place.

**Development strategy**: Local-first. All dashboard and backend work is developed and tested locally before any production deployment. Hosted deployment and domain cutover are tracked separately in Phase 3E.

**Frontend stack**: The Operator Dashboard is a new `packages/dashboard` package using **Vite + React** (TypeScript). The existing `packages/browser-ui` (vanilla JS zero-knowledge sandbox) remains a separate, isolated package — it must never share runtime code or session state with the dashboard.

**Design workflow**: Dashboard screens are designed first using **Stitch** (via MCP), then implemented by extracting HTML/CSS from the generated designs and adapting them into React components. **Crucially, while Stitch provides the layout and UX patterns, all implementations must override colors and gradients to stay 100% consistent with the BlindPass Design System (Deep Navy, Cyan/Purple gradients).**

**Theming & Color Consistency**: To maintain visual identity, all dashboard components must exclusively use the CSS variables defined in `src/styles/index.css`. Ad-hoc color utilities or hardcoded hex values from Stitch exports must be replaced with theme variables (e.g., `--bg`, `--primary`, `--purple`) to ensure any future system-wide theme changes (like a Light Mode) can be applied automatically.

> [!IMPORTANT]
> This plan is divided into **5 incremental milestones**, each independently deployable. The order is: UI Design (Stitch) → Dashboard Shell & Auth → Agent & Member Management → Audit & Approvals → Billing & Quotas.

## Progress

- `2026-03-12`: Milestone 1 complete — All 14 dashboard screens designed in Stitch (Project ID: `5937100388262572555`). Ready for implementation.
- `2026-03-13`: Milestone 2 frontend implementation landed in `packages/dashboard` using Stitch HTML exports as the layout reference. Auth flows, refresh persistence, force-password-change routing, role-aware sidebar navigation, and responsive placeholder routes for the full shell are now in place. Later CRUD pages remain scaffolded until Milestones 3-5 wire their APIs.
- `2026-03-13`: Milestone 3 complete — Agent & Member management landed. CRUD interfaces for agents and members are fully operational with paginated backend support and enforced last-admin lockout. E2E and component verification complete.
- `2026-03-13`: Milestone 4 complete — Audit Log Viewer and Approvals Inbox landed. Paginated audit log with filtering, exchange lifecycle drill-down, and A2A approval inbox are fully operational and verified. Data leak scanning confirms no sensitive keys exist in audit metadata.
- `2026-03-14`: Milestone 5 complete — Billing & Quota Dashboard landed. Live quota summary (secret requests, agents, members), subscription management UI with Stripe integration (checkout/portal), and provider-agnostic billing service abstraction are fully operational and verified via E2E tests.
- `2026-03-17`: Phase 3B scope tightened to the completed dashboard/admin UX slice. Follow-on analytics, ecosystem, and launch work now live in Phase 3E.

---

## Proposed Changes

### New Project Structure Additions

```
packages/dashboard/                       # [NEW] Operator Dashboard SPA
  package.json
  vite.config.ts
  tsconfig.json
  tailwind.config.ts
  postcss.config.js
  index.html
  src/
    main.tsx                              # React entry point
    App.tsx                               # Root component + router
    api/
      client.ts                           # Typed fetch wrapper for SPS API (base URL, auth headers, refresh interceptor)
    auth/
      AuthContext.tsx                      # React context for session state (user, workspace, tokens)
      useAuth.ts                          # Hook: login, logout, refresh, isAuthenticated
      ProtectedRoute.tsx                  # Route guard: redirect to /login if unauthenticated, block if fpc=true, enforce allowed roles
    pages/
      Login.tsx                           # Email + password login
      Register.tsx                        # Signup: email, password, workspace slug, display name
      ForgotPassword.tsx                  # Placeholder — wired when SMTP lands
      ChangePassword.tsx                  # Force-change on first login when fpc=true
      Dashboard.tsx                       # Admin-only home: workspace overview, quota summary, quick actions
      Agents.tsx                          # List agents, enroll new, rotate key, revoke
      Members.tsx                         # List users, create with temp password, change role
      Audit.tsx                           # Paginated audit log viewer with filters
      Approvals.tsx                       # Pending A2A approval inbox
      Billing.tsx                         # Current tier, quota meters, Billing provider portal link
      Settings.tsx                        # Workspace display name, slug (read-only in MVP); advanced policy management deferred to Phase 3E
    components/
      Layout.tsx                          # App shell: role-aware sidebar nav, header, content area
      ApiKeyReveal.tsx                    # One-time display of ak_ key with copy button
      QuotaMeter.tsx                      # Visual gauge for daily usage vs limit
      DataTable.tsx                       # Reusable sortable/filterable table
      StatusBadge.tsx                     # Colored badge for agent/exchange/subscription status
      EmptyState.tsx                      # Friendly zero-state illustrations
      ConfirmDialog.tsx                   # Destructive action confirmation modal
    styles/
      index.css                           # Tailwind layers + design tokens + global styles
      theme.ts                            # Dark/light theme config
    hooks/
      usePagination.ts                    # Cursor pagination for audit, agents, members
      useQuota.ts                         # Fetch + cache workspace quota state

packages/sps-server/src/
  routes/
    dashboard.ts                          # [NEW] Dashboard summary endpoint
  services/
    dashboard.ts                          # [NEW] Workspace overview + quota summary aggregation
```

---

### Milestone 1: Dashboard UI Design (Stitch)

Design all dashboard screens using **Stitch via MCP** before writing any React code. This creates a visual contract to implement against and avoids designing in code.

#### Screens to Design

| Screen | Description | Key Elements |
|--------|------------|--------------|
| **Login** | Email + password form | Branded header, form fields, "Register" link, Turnstile placeholder |
| **Register** | Signup form | Email, password, workspace slug, display name fields, validation hints |
| **Change Password** | Force-change on first login | Current password, new password, confirm, guidance text |
| **Dashboard Home** | Admin-only workspace overview | Quota meters (requests, agents, members), quick action cards, workspace name/tier badge |
| **Agents** | Agent management | Data table with Status badge, "Enroll Agent" button, row actions (rotate/revoke) |
| **Agent Enroll Modal** | Bootstrap key reveal | Agent ID input, generated `ak_` key display with copy button, "I've saved this" checkbox |
| **Members** | Member management | Data table, "Add Member" button, role dropdown per row, last-admin lockout indicator |
| **Audit Log** | Event stream | Filter bar (event type, actor, date range), paginated data table, row expansion for metadata |
| **Exchange Timeline** | Drill-down from audit | Vertical timeline of lifecycle events with approval history interleaved |
| **Approvals Inbox** | Pending A2A approvals | Approval cards with agent details, purpose, Approve/Deny action buttons |
| **Billing** | Subscription management | Current tier card, feature comparison, upgrade CTA / Billing portal link |
| **Analytics** | Workspace metrics | Request volume bar chart, exchange outcome chart, active agents counter, error rate trend (implemented later in Phase 3E) |
| **Settings** | Workspace configuration | Display name edit, slug (read-only), owner verification status; workspace policy editing explicitly deferred to Phase 3E |
| **App Shell / Layout** | Sidebar + header | Navigation sidebar, workspace name, user dropdown, responsive collapse |

#### Design Process

1. Create a Stitch project for the dashboard
2. Design each screen with realistic sample data (not placeholder text)
3. Use a consistent dark-mode-first aesthetic (BlindPass Design System): deep navy backgrounds (`#060a14`), cyan/purple gradients (`#00f5d4` to `#7b61ff`), glassmorphism cards, Inter typography
4. Review and iterate on designs before implementation, ensuring they match existing authenticated screens.
5. Export finalized HTML/CSS from Stitch as the implementation reference, mapping all color hexes back to the `--primary`, `--bg`, and `--purple` CSS variables.

#### Design Constraints

- **Dark-mode-first** with optional light mode toggle later
- **Typography**: Inter (Google Fonts), system-ui fallback
- **Color palette**: MUST use shared tokens from `index.css`:
    - Background: `--bg` (#060a14)
    - Primary: `--primary` (#00f5d4, Cyan)
    - Accent: `--purple` (#7b61ff)
    - Gradients: `linear-gradient(135deg, var(--primary) 0%, var(--primary-strong) 50%, var(--purple) 100%)`
- **Components**: Glassmorphism cards with `backdrop-filter`, smooth `200ms` hover transitions, subtle micro-animations on state changes
- **Spacing**: 4px base grid, consistent border-radius tokens (`4px`, `8px`, `12px`)
- **Responsive**: Collapsible sidebar below 768px breakpoint
- **Brand**: "agent-BlindPass" branding consistent with `blindpass.atas.tech` landing page. Layouts follow Stitch, but aesthetics follow the BlindPass Brand.

**Acceptance**: All 14 screens designed in Stitch. Visual design reviewed and approved before Milestone 2 begins.

---

### Milestone 2: Dashboard Shell & Authentication UI (Self-service Signup)

Bootstrap the React dashboard and implement auth flows. Adapt HTML/CSS from the Stitch designs in Milestone 1 into React components. This milestone establishes the **self-service human signup** foundation.

#### [NEW] `packages/dashboard` package

Initialize with Vite + React + TypeScript:

```bash
npx -y create-vite@latest ./ --template react-ts
```

Key dependencies: `react-router-dom` (routing) and Tailwind CSS for adapting Stitch output into reusable React components while keeping shared design tokens in `styles/index.css`.

#### Core Architecture

- **`api/client.ts`**: Typed fetch wrapper. In local dev, configured with `VITE_SPS_API_URL` (default `http://localhost:3100`). Automatically attaches `Authorization: Bearer <accessToken>` from `AuthContext`. Implements a 401-interceptor that attempts a single `POST /api/v2/auth/refresh` before redirecting to `/login`.
- **`auth/AuthContext.tsx`**: Stores `{ user, workspace, accessToken, refreshToken }` in React context. Persists refresh token in `localStorage` (access token in memory only). Exposes `login()`, `logout()`, `refresh()`, `isAuthenticated`.
- **`auth/ProtectedRoute.tsx`**: Wraps routes that require auth. Redirects to `/login` if unauthenticated, to `/change-password` if `fpc === true` in the access token claims, and to the caller's first allowed route when role-gated pages are not permitted.
- **`components/Layout.tsx`**: App shell adapted from Stitch design with role-aware sidebar navigation. `workspace_admin` sees Dashboard, Agents, Members, Audit, Approvals, Billing, Analytics, Settings; `workspace_operator` lands on Agents; `workspace_viewer` lands on Audit.

#### Auth Pages

| Page | Route | Consumes API |
|------|-------|-------------|
| `Login.tsx` | `/login` | `POST /api/v2/auth/login` |
| `Register.tsx` | `/register` | `POST /api/v2/auth/register` |
| `ChangePassword.tsx` | `/change-password` | `POST /api/v2/auth/change-password` |
| `ForgotPassword.tsx` | `/forgot-password` | Placeholder — shows "contact admin" until SMTP lands |

#### Design Adaptation Process

1. Extract HTML structure and CSS from Stitch-generated screens
2. Decompose into React components following the project structure
3. Replace static values with React state / props
4. Wire up API calls to the SPS backend
5. Verify visual fidelity against the Stitch designs

**Acceptance**: User can run `npm run dev --workspace=packages/dashboard`, navigate to `localhost:5173`, register a new workspace, log in, see the dashboard shell with role-aware sidebar nav, log out, and refresh the page without losing the session. Force-password-change redirect works for admin-created users, and non-admin roles are redirected to their first allowed route. Visual output matches Stitch designs.

---

### Milestone 3: Agent & Member Management UI (Bindings & Onboarding)

Build the CRUD interfaces for the two most common workspace admin tasks: **Agent onboarding paths** and **Owner/team member bindings**.

#### Milestone 3 execution plan

This milestone should be implemented as a thin vertical slice over the Phase 3A APIs that already exist, not as a dashboard-only mock layer. The backend already ships the write paths for agents, members, and workspace display name updates:

- `POST /api/v2/agents`
- `POST /api/v2/agents/:aid/rotate-key`
- `DELETE /api/v2/agents/:aid`
- `POST /api/v2/members`
- `PATCH /api/v2/members/:uid`
- `GET /api/v2/workspace`
- `PATCH /api/v2/workspace`

The main backend gaps for Milestone 3 are the paginated read contracts and one settings-read field for the owner verification indicator.

#### Stitch adaptation map

Milestone 3 must continue the same design workflow used in Milestone 2: extract layout structure from Stitch, then adapt it into React components while replacing exported color values with dashboard theme variables from `packages/dashboard/src/styles/index.css`.

- Primary desktop references:
  - `Desktop Agents Management`
  - `Enroll Agent Modal Screen`
  - `Desktop Members Management`
  - `Desktop Workspace Settings Overview`
- Mobile parity references:
  - `agent-BlindPass Agents Management`
  - `Enroll Agent Modal Screen`
  - `agent-BlindPass Members Management`
  - `Workspace Settings Overview`
- Rule: keep Stitch spacing, panel hierarchy, modal composition, and responsive breakpoints; do not copy raw Stitch hex colors or one-off gradients into the React code.

#### Recommended implementation order

1. **Finalize read-model contracts in `sps-server`**
   - Extend `GET /api/v2/agents` to accept `limit`, `cursor`, and optional `status`, returning `{ agents, next_cursor }`
   - Extend `GET /api/v2/members` to accept `limit`, `cursor`, and optional `status`, returning `{ members, next_cursor }`
   - Add owner verification status to the workspace read contract used by `/settings`
   - Keep ordering stable and cursor-safe: use `created_at` plus a deterministic tie-breaker such as `id`

2. **Add dashboard primitives before page wiring**
   - Implement reusable `StatusBadge`, `DataTable`, `ConfirmDialog`, `EmptyState`, and `ApiKeyReveal`
   - Add a small cursor-pagination hook instead of duplicating fetch/append state in each page
   - Add a temporary-password strength indicator for the member create form

3. **Implement `/agents` from the Stitch management + modal screens**
   - Replace the placeholder page with a live list view, status badges, and row actions
   - Wire enroll and rotate flows to the one-time `ApiKeyReveal` modal
   - Keep the revealed `ak_` key only in transient component state; never persist it to storage, URL params, or logs
   - Allow operators and admins to access this page; viewers remain blocked by route guards and backend RBAC

4. **Implement `/members` from the Stitch member-management screen**
   - Replace the placeholder with a paginated member table
   - Wire add-member modal/form, inline role updates, and suspend actions
   - Mirror backend last-admin protection in the UI by disabling demote/suspend controls when only one active admin remains
   - Preserve the backend as the final authority: UI disablement is advisory, API rejection remains mandatory

5. **Implement `/settings` from the Stitch settings screen**
   - Replace the placeholder with a read-mostly workspace settings page
   - Show slug and tier as read-only
   - Allow admin-only inline edit of display name
   - Surface owner email verification as an explicit status indicator so admin/operator confusion is avoided

6. **Land tests with each slice**
   - `packages/sps-server`: pagination, filtering, RBAC, and last-admin lockout regression coverage
   - `packages/dashboard`: component tests for reveal modal, member controls, pagination append behavior, and settings edit state
   - End-to-end: admin and operator happy paths plus viewer denial paths

#### Agent Enrollment Page (`/agents`)

- **Agent list table**: columns — Agent ID, Display Name, Status (active/revoked), Created At, Actions
- **"Enroll Agent" flow**: form with `agent_id` + optional `display_name` → calls `POST /api/v2/agents` → on success, renders `ApiKeyReveal` component showing the `ak_...` key **once** with a copy-to-clipboard button and a "I've saved this key" confirmation checkbox that dismisses the modal
- **Rotate Key**: confirmation dialog → `POST /api/v2/agents/:aid/rotate-key` → shows new key via `ApiKeyReveal`
- **Revoke Agent**: `ConfirmDialog` → `DELETE /api/v2/agents/:aid`
- RBAC: only `workspace_admin` and `workspace_operator` roles see this page

#### Member Management Page (`/members`)

- **Member list table**: columns — Email, Role, Status, Created At, Actions
- **"Add Member" flow**: form with email + role selector + temporary password input (min 12 chars, with strength indicator) → `POST /api/v2/members`
- **Change Role**: inline dropdown → `PATCH /api/v2/members/:uid`
- **Suspend Member**: `ConfirmDialog` → `PATCH /api/v2/members/:uid` with `status: suspended`
- Last-admin warning: disable demotion/suspension controls when only one active admin remains
- RBAC: only `workspace_admin` sees this page

#### Workspace Settings Page (`/settings`)

- Read-only display of workspace slug, display name, tier
- `workspace_admin` can edit display name via `PATCH /api/v2/workspace`
- Owner email verification status indicator
- Secret registry and exchange policy management are intentionally out of Phase 3B scope and move to Phase 3E

#### [MODIFY] Backend list endpoints for dashboard pagination

| Endpoint | Auth | Behavior |
|----------|------|----------|
| `GET /api/v2/agents` | User JWT (admin/operator) | Add `limit`, `cursor`, optional `status`; return paginated agent rows plus `next_cursor` |
| `GET /api/v2/members` | User JWT (admin) | Add `limit`, `cursor`, optional `status`; return paginated member rows plus `next_cursor` |
| `GET /api/v2/workspace` | User JWT (admin/operator/viewer) | Include owner verification status so `/settings` can render the verification badge without client-side guesswork |

**Acceptance**: Workspace admin can enroll an agent and see the bootstrap key exactly once, rotate keys, revoke agents, and page through the agent list. Admin can create workspace members with temporary passwords, manage roles, and page through the member list. Last-admin lockout protection is visually enforced.

---

### Milestone 4: Audit Log Viewer & Approvals Inbox

Surface the existing Phase 3A audit and approval endpoints in the dashboard.

#### Audit Log Page (`/audit`)

- **`DataTable`** bound to `GET /api/v2/audit` with backend pagination
- **Filter bar**: event type dropdown, actor type (user/agent/system), resource ID text input, date range picker
- **Row expansion**: click a row to see full metadata JSON (sanitized — no ciphertext, no tokens)
- **Exchange drill-down**: click an exchange-related event → navigate to exchange detail view calling `GET /api/v2/audit/exchange/:id`, showing the full lifecycle timeline (requested → reserved → submitted → retrieved) with approval history interleaved
- RBAC: all roles (`workspace_admin`, `workspace_operator`, `workspace_viewer`) can view audit; viewer is read-only throughout the entire dashboard

#### [MODIFY] Backend: audit pagination contract

| Endpoint | Auth | Behavior |
|----------|------|----------|
| `GET /api/v2/audit` | User JWT (admin/operator/viewer) | Add `cursor` alongside existing filters and `limit`; return `records` plus `next_cursor` |

#### Approvals Inbox Page (`/approvals`)

- Displays pending A2A exchange approval requests for the current workspace
- Each pending approval card shows: requester agent, fulfiller agent, secret name, purpose, requested at, policy rule that triggered approval
- **Approve / Deny** buttons → call existing `POST /api/v2/secret/exchange/admin/approval/:id/approve` or `/reject`
- RBAC: `workspace_admin` and `workspace_operator` can approve/deny; `workspace_viewer` sees the inbox read-only

> [!NOTE]
> The approvals inbox consumes the existing Phase 2B approval endpoints. No new backend routes are needed — only the UI to surface them.

**Acceptance**: All workspace roles can view the audit log with filters and pagination. Exchange lifecycle timeline renders correctly. Admin/operator can approve or deny pending A2A exchanges from the inbox.

---

### Milestone 5: Billing & Quota Dashboard

Give workspace admins visibility into their subscription and usage. Milestone 5 also ships the **subscription billing abstraction** and the **billing portal endpoint**.

#### Milestone 5 execution plan

This milestone should be implemented as another thin vertical slice over the existing Phase 3A billing system, not as a dashboard-only mock. Stripe-backed recurring billing already exists in `sps-server`, and the dashboard package already has the authenticated shell plus route placeholders. The work now is to expose a compact admin summary contract, wire the live billing page, and adapt the Dashboard home from its static Milestone 2 placeholder into an admin operations overview.

The main backend additions for Milestone 5 are:

- `GET /api/v2/dashboard/summary`
- provider-aware hardening of the existing `POST /api/v2/billing/portal`
- a small read-model layer that aggregates workspace counts plus quota usage without forcing the dashboard to fan out to multiple list endpoints

#### Stitch adaptation map

Milestone 5 should keep the same workflow as Milestones 2-4: use Stitch screens as the layout contract, then adapt them into React components while replacing any exported colors with the dashboard theme variables from `packages/dashboard/src/styles/index.css`.

- Primary desktop references:
  - `Desktop Billing Management`
  - `Desktop Dashboard Operator Variant`
  - `Desktop Billing Operator Variant`
- Mobile parity references:
  - `agent-BlindPass Billing Screen`
  - `agent-BlindPass Dashboard Home`
  - `agent-BlindPass Billing Variant`
- Rule: preserve Stitch spacing, card hierarchy, responsive breakpoints, and information density; replace raw hex colors, gradients, and badges with BlindPass design tokens
- Rule: the billing surface must now show recurring workspace subscription state (`Free` / `Standard`, checkout, billing portal) without collapsing future non-subscription payment products into the same card. Agent x402 and hosted crypto checkout are tracked separately in Phase 3D.

#### Recommended implementation order

1. **Finalize the admin summary contract in `sps-server`**
   - Add `GET /api/v2/dashboard/summary` for `workspace_admin`
   - Return a single payload containing workspace display metadata, tier, subscription status, quota usage, and top-level counts
   - Keep the response dashboard-oriented: stable keys, no provider-specific field names at the top level except inside the nested billing object

2. **Wire quota aggregation on the backend**
   - Reuse the existing quota limits from Phase 3A rather than duplicating constants in the dashboard
   - Return both `used` and `limit` for secret requests, agents, and members
   - Return `a2a_exchange_available` as a boolean derived from tier so the UI does not duplicate entitlement logic

3. **Harden the recurring billing read model**
   - Keep `billing_provider` scoped to recurring subscription providers only
   - Ensure `POST /api/v2/billing/portal` only succeeds for subscription-backed workspaces with a provider customer id
   - Keep checkout + portal responses provider-agnostic on the wire even though Stripe is the only implementation today

4. **Add dashboard primitives before page wiring**
   - Implement `QuotaMeter` as a reusable presentational component with threshold states
   - Add a dashboard summary hook or API helper instead of duplicating fetch state across `/` and `/billing`
   - Keep loading, empty, and error states visually aligned with the existing Stitch-inspired cards

5. **Implement admin Dashboard home from the Stitch dashboard screens**
   - Replace the static hero metrics with live summary data
   - Add quota meters for secret requests, agents, and members
   - Show A2A exchange availability and subscription state in the admin overview without requiring navigation to `/billing`
   - Preserve operator/viewer routing behavior from Milestone 2: only admins land on the home route

6. **Implement `/billing` from the Stitch billing screens**
   - Replace the placeholder page with a live current-plan card, feature comparison, and subscription status
   - Wire the Free-tier CTA to `POST /api/v2/billing/checkout`
   - Wire the Standard-tier portal action to `POST /api/v2/billing/portal`
   - Keep non-subscription payment products out of the live recurring billing card for this milestone; if mentioned at all, present them as future capabilities tracked in Phase 3D

7. **Land tests with each slice**
   - `packages/sps-server`: summary contract, RBAC, billing portal edge cases, and provider-agnostic response shape
   - `packages/dashboard`: `QuotaMeter`, summary rendering, admin-only billing access, and checkout/portal CTA states
   - End-to-end: admin home summary, Stripe checkout handoff, and portal launch behavior

#### Recurring Billing Architecture

The Milestone 5 billing backend stays focused on the recurring workspace subscription surface:

1. **`SubscriptionProvider` interface (e.g., Stripe, Lemonsqueezy):**
   Handles human checkout, recurring workspace subscriptions, customer portal sessions, and asynchronous webhook events.
   ```typescript
   interface SubscriptionProvider {
     readonly name: string;
     createCheckoutSession(input: CreateCheckoutInput): Promise<CheckoutResult>;
     createPortalSession(input: CreatePortalInput): Promise<PortalResult>;
     handleWebhookEvent(payload: string | Buffer, signature: string): Promise<WebhookResult>;
   }
   ```

Autonomous request payments and hosted crypto checkout are tracked separately in [Phase 3D - Autonomous Payments & Crypto Billing](Phase%203D%20-%20Autonomous%20Payments%20%26%20Crypto%20Billing.md).

##### DB schema changes (migration `007_billing_provider`)

- Renamed `stripe_customer_id` → `billing_provider_customer_id`
- Renamed `stripe_subscription_id` → `billing_provider_subscription_id`
- Added `billing_provider TEXT` column for the recurring subscription provider (for example `'stripe'`, later `'lemonsqueezy'`)
- PostgreSQL `RENAME COLUMN` preserves existing unique indexes from `005_billing.sql`
- Existing Stripe rows are backfilled with `billing_provider = 'stripe'`
- non-subscription payment state is stored separately and does not set workspace `billing_provider`

##### API response shape change

All billing API responses now return provider-agnostic field names:

```json
{
  "billing_provider": "stripe",
  "provider_customer_id": "cus_...",
  "provider_subscription_id": "sub_...",
  "subscription_status": "active"
}
```

#### Billing Page (`/billing`)

- **Current plan card**: shows Free or Standard tier with feature comparison table
- **Upgrade button** (Free tier only): calls `POST /api/v2/billing/checkout` → redirects to Payment Checkout
- **Manage subscription link** (Subscription-backed Standard tier): opens Billing Provider Portal using an auto-generated portal session URL
- **Subscription status badge**: active, past_due, canceled, etc.
- If the workspace later gains a non-subscription paid product, show that separately from the recurring subscription card instead of forcing portal semantics onto recurring billing
- RBAC: only `workspace_admin` can access this page in the MVP

#### Quota Usage Section (on Dashboard home page)

- Admin-only. `workspace_operator` and `workspace_viewer` do not land on the home route.
- **`QuotaMeter` components** showing daily usage vs. limits for:
  - Secret requests (10/day free, 1,000/day standard)
  - Enrolled agents (5 free, 50 standard)
  - Workspace members (1 free, 10 standard)
  - A2A exchange availability (❌ free, ✅ standard)
- Gauges use color coding: green (<70%), amber (70-90%), red (>90%)
- Data source: prefer a dedicated admin-only summary endpoint so the home page does not fan out across multiple list endpoints for counts and quota state

#### [NEW] Backend: dashboard summary + Billing Portal Session

| Endpoint | Auth | Behavior |
|----------|------|----------|
| `GET /api/v2/dashboard/summary` | User JWT (admin) | Return workspace display info, tier, billing status, quota usage, and top-level counts for the home page |
| `POST /api/v2/billing/portal` | User JWT (admin) | Create Billing Provider Portal session → return URL. Returns `400` if workspace has no billing customer. |

**Acceptance**: Free-tier admin sees the upgrade CTA and completes a test Payment Checkout flow. Subscription-backed Standard-tier admin can access the Billing portal. The admin-only home dashboard renders from `GET /api/v2/dashboard/summary`, and quota meters display accurate counts. Billing API responses use provider-agnostic field names.

---

### Follow-On Phase Split

Phase 3B ends at the recurring billing and quota dashboard. Follow-on work is intentionally tracked elsewhere:

- **Phase 3D**: autonomous request payments and hosted crypto billing
- **Phase 3E**: analytics and abuse hardening, SDK/docs/community work, and hosted deployment + domain cutover

---

## Verification Plan

Detailed E2E and integration scenarios for this phase live in `docs/testing/Phase 3B.md`.

### Automated Tests

All tests use **Vitest**. Run from project root:

```bash
npm test
npm test --workspace=packages/sps-server
npm test --workspace=packages/dashboard
```

#### Milestone 1: Manual visual review
- Stitch designs reviewed for consistency, completeness, and brand alignment
- All 14 screens approved before Milestone 2

#### Milestone 2: `dashboard` component tests
- `AuthContext` stores token on login and clears on logout
- `ProtectedRoute` redirects unauthenticated users to `/login`
- `ProtectedRoute` redirects `fpc=true` users to `/change-password`
- Non-admin users are redirected away from the admin-only home route after login
- Login page submits credentials and stores returned tokens
- Register page creates workspace and redirects to dashboard
- API client attaches auth header and retries on 401

#### Milestone 3: `dashboard` component tests
- Agent enrollment flow renders `ApiKeyReveal` on success
- `ApiKeyReveal` copy-to-clipboard works and dismisses on confirmation
- Last-admin lockout disables demotion controls correctly
- Member creation enforces minimum 12-character temporary password
- Paginated agent/member table fetches append rows correctly from `next_cursor`

#### Milestone 4: `dashboard` component tests
- Audit table renders paginated results with correct filters
- Exchange timeline renders lifecycle events in chronological order
- Approve/Deny buttons call correct API endpoints
- `workspace_viewer` sees approve/deny buttons as disabled

#### Milestone 5: `billing-portal.test.ts` (sps-server)
- `GET /api/v2/dashboard/summary` returns admin-only workspace overview and quota state
- `POST /api/v2/billing/portal` returns provider portal URL for subscription-backed standard-tier workspace
- `POST /api/v2/billing/portal` returns `400` for workspace without billing provider customer
- Billing API responses use `billing_provider`, `provider_customer_id`, `provider_subscription_id`
- Quota meter component renders correct percentages and color states

### Manual Verification

1. **Design review** (Milestone 1): Review all Stitch designs in the Stitch project for visual consistency, completeness, and brand alignment
2. **Auth flow** (Milestone 2): Run dashboard locally → Register → redirected to dashboard → see sidebar nav → log out → log back in
3. **Agent enrollment** (Milestone 3): Enroll an agent → see `ak_` key → dismiss → verify key is no longer visible → use key to mint JWT → hit SPS endpoint
4. **Audit viewing** (Milestone 4): Perform several secret requests → open audit page → verify events appear with correct filters → drill into exchange lifecycle
5. **Billing flow** (Milestone 5): Free-tier workspace → click upgrade → complete Payment test checkout → verify tier badge changes → click "Manage Subscription" → verify Billing portal opens

---

## Resolved Decisions

- **Dashboard framework** → Vite + React (TypeScript) in a new `packages/dashboard` package; not merged with `browser-ui`
- **Dashboard CSS** → **Tailwind CSS** is approved for the dashboard to accelerate UI development and component styling.
- **Design workflow** → All screens designed first in Stitch (MCP), then implemented by extracting HTML/Tailwind CSS and adapting into React components
- **Dashboard home** → admin-only. Operators land on Agents; viewers land on Audit.
- **Browser-UI isolation** → `browser-ui` (zero-knowledge sandbox) and `dashboard` (control plane) are separate packages, separate containers, separate domains; they share no runtime code or session state
- **Recurring billing architecture** → `SubscriptionProvider` handles recurring workspace subscriptions (Stripe today) and webhooks. Provider-facing wire fields stay provider-agnostic (`billing_provider_*`). Autonomous payments and hosted crypto checkout are tracked in Phase 3D.
- **Dashboard auth token storage** → refresh token in `localStorage`, access token in memory only; accept the XSS trade-off for MVP simplicity with CSP headers as mitigation. **Note: We must revisit this and evaluate migrating to `httpOnly` cookies before wide / GA go-live.**
- **Force-password-change UX** → dashboard redirects to `/change-password` before allowing any other navigation when `fpc=true`
- **Phase boundary** → Phase 3B ends once the core operator dashboard and recurring billing admin UX are complete. Hardening, ecosystem, and launch work live in Phase 3E.

### Suggested Work Breakdown

1. Design all dashboard screens in Stitch (MCP)
2. Dashboard shell + auth pages adapted from Stitch designs
3. Agent enrollment + member management + settings UI
4. Audit log viewer + exchange timeline + approvals inbox
5. Billing page + quota meters + Stripe portal integration
