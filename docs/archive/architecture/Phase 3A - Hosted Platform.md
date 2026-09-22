# Phase 3A: Hosted Managed Platform

> Historical record, archived during the 2026-09-22 documentation alignment. Dates, checkboxes, commands, and proposed decisions below describe their original review period; they do not establish current support or authorize new work. See the [current documentation](../../README.md) and [roadmap](../../product/Roadmap.md).

Build the first hosted SaaS layer on top of the existing SPS core. Multiple customer workspaces share one control plane. Each workspace is the tenant boundary for identity, policy, audit, quotas, and billing.

**Deployment strategy**: app-code first targeting Unraid (PostgreSQL + Redis in Docker). Cloud portability (GCP, Supabase) deferred.

**Database choice**: PostgreSQL via `pg` (node-postgres) with a simple file-based migration runner. PostgreSQL works everywhere: Docker on Unraid today, GCP Cloud SQL or Supabase (which is built on Postgres) later. Redis continues to handle ephemeral secret/exchange state.

**Auth model**: Self-rolled JWT sessions with `bcrypt` password hashing for humans. Hosted agents enroll with bootstrap API keys that mint short-lived SPS agent JWTs carrying `workspace_id`. OAuth providers can be added later.

**Billing model**: Two tiers — **Free** and **Standard** ($9/month). The free tier is intentionally limited, but is not labeled "trial". Stripe Checkout + webhooks handle subscription management.

> [!IMPORTANT]
> This plan is divided into **6 incremental milestones**, each independently deployable. The order is: Database Foundation → Human Auth → Workspace-Scoped SPS → Agent Enrollment + RBAC → Billing → Abuse Controls.

## Progress

- `2026-03-12`: Milestone 1 implemented in `packages/sps-server` with PostgreSQL pool wiring, migration runner, initial workspace schema/service/routes, and coverage in `tests/db.test.ts`
- `2026-03-12`: Milestone 2 auth foundation implemented with `users` + `user_sessions` migrations, user/session service, auth routes (`register`, `login`, `refresh`, `logout`, `change-password`, `verify-email`, `me`), and coverage in `tests/auth-routes.test.ts`
- `2026-03-12`: Milestone 3 implemented with hosted-mode `workspace_id` enforcement for agent JWTs, workspace-scoped secret/exchange ownership checks, fulfillment token workspace binding, workspace-aware approval hashing, and hosted/local regression coverage in route tests
- `2026-03-12`: Milestone 4 implemented with the `enrolled_agents` migration, hosted agent bootstrap API key enrollment and JWT minting routes, workspace member management, shared RBAC helpers, owner-verification gating for higher-risk hosted actions, and PostgreSQL integration coverage in `tests/agents-routes.test.ts`
- `2026-03-12`: Milestone 5 implemented with the `005_billing.sql` workspace billing state migration, Stripe-backed checkout/webhook routes, mocked Stripe integration coverage in `tests/billing.test.ts`, and free-vs-standard quota enforcement for secret requests, enrolled agents, workspace members, and exchange availability
- `2026-03-12`: Milestone 6 implemented with reusable per-IP rate limiting for register/login/hosted token minting, durable PostgreSQL-backed audit persistence and query routes, scheduled audit retention cleanup, and PostgreSQL integration coverage in `tests/rate-limit.test.ts`
- The 6 planned Phase 3A core milestones are now complete. All follow-on operational, UI, deployment, guest-intake, payment hardening, and ecosystem work has been explicitly moved to **Phase 3B**, **Phase 3C**, **Phase 3D**, and **Phase 3E**.

---

## Proposed Changes

### New Project Structure Additions

```
packages/sps-server/
  src/
    db/
      index.ts                # PostgreSQL connection pool (pg)
      migrate.ts              # Simple file-based migration runner
      migrations/
        001_workspaces.sql
        002_users.sql
        003_user_sessions.sql
        004_agents.sql
        005_billing.sql
        006_audit_log.sql
    routes/
      workspace.ts            # [NEW] Workspace CRUD
      auth.ts                 # [NEW] Signup / login / verify / refresh
      agents.ts               # [NEW] Agent enrollment & credential management
      members.ts              # [NEW] Workspace user CRUD + role management
      audit.ts                # [NEW] Workspace-scoped audit queries
      billing.ts              # [NEW] Stripe webhooks + subscription endpoints
    services/
      agent.ts                # [NEW] Enrolled agent credential management
      workspace.ts            # [NEW] Workspace business logic
      user.ts                 # [NEW] User management + password hashing + session handling
      rbac.ts                 # [NEW] Role-based access control
      quota.ts                # [NEW] Rate limiting + tier-based quotas
      billing.ts              # [NEW] Stripe integration
    middleware/
      auth.ts                 # [MODIFY] Add user session JWT validation alongside existing agent JWT
      workspace.ts            # [NEW] Workspace resolution from auth context
      rate-limit.ts           # [NEW] Per-workspace rate limiting
```

---

### Milestone 1: Database Foundation & Workspace Model

Add PostgreSQL as a durable store for workspace, user, and agent records. Redis continues for ephemeral secret state.

#### [NEW] [db/index.ts](../../../packages/sps-server/src/db/index.ts)

- PostgreSQL connection pool using `pg` (`Pool`)
- Configured via `DATABASE_URL` env var (default: `postgresql://localhost:5432/blindpass`)
- Connection pool size from `DB_POOL_SIZE` (default: 10)
- Graceful shutdown on `onClose` hook

#### [NEW] [db/migrate.ts](../../../packages/sps-server/src/db/migrate.ts)

- Reads `*.sql` files from `migrations/` directory in order
- Tracks applied migrations in a `_migrations` table
- Runs each migration file inside a PostgreSQL transaction; a failed file rolls back entirely before the runner exits
- Run via `npx tsx src/db/migrate.ts` or called on server startup in dev mode
- Idempotent — safe to re-run

#### [NEW] [db/migrations/001_workspaces.sql](../../../packages/sps-server/src/db/migrations/001_workspaces.sql)

```sql
CREATE TABLE workspaces (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  slug          TEXT NOT NULL
    CHECK (slug = lower(btrim(slug)))
    CHECK (slug ~ '^[a-z0-9-]{3,40}$'), -- human-readable workspace identifier
  display_name  TEXT NOT NULL,
  tier          TEXT NOT NULL DEFAULT 'free' CHECK (tier IN ('free', 'standard')),
  status        TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'deleted')),
  owner_user_id UUID,                          -- constrained after users table exists
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX idx_workspaces_slug_unique ON workspaces(slug);
```

#### [NEW] [services/workspace.ts](../../../packages/sps-server/src/services/workspace.ts)

- `createWorkspace(slug, displayName, ownerUserId)` → insert + return workspace
- `getWorkspace(id)` → by UUID
- `getWorkspaceBySlug(slug)` → by slug
- `updateWorkspaceTier(id, tier)` → for billing upgrades
- `owner_user_id` must reference a user in the same workspace; enforce this with the DB foreign key added after `users` exists
- Always filter workspace reads used for auth/access by `status = 'active'`; suspended/deleted workspaces fail closed
- Soft-deleted workspaces continue to reserve their slug in Phase 3A; slug reclamation is deferred to a future purge workflow, not normal soft-delete behavior
- Enforce unique slug, validate format (`^[a-z0-9-]{3,40}$`)

#### [NEW] [routes/workspace.ts](../../../packages/sps-server/src/routes/workspace.ts)

| Endpoint | Auth | Behavior |
|----------|------|----------|
| `GET /api/v2/workspace` | User JWT | Return caller's workspace |
| `PATCH /api/v2/workspace` | User JWT (admin) | Update display name |

**Workspace membership model**: In Phase 3A, each user belongs to exactly one workspace. There is no cross-workspace membership or workspace switching yet.

#### [MODIFY] [docker-compose.yml](../../../docker-compose.yml)

- Add `postgres` service (`postgres:16-alpine`)
- Add `blindpass` database with configurable credentials
- Add volume mount for data persistence

#### [MODIFY] [index.ts](../../../packages/sps-server/src/index.ts)

- Initialize PostgreSQL pool on startup
- Run migrations in dev mode
- Pass `db` pool to route registrations that need it
- Add `onClose` hook for pool shutdown
- Configure Fastify proxy trust correctly for hosted deployments so rate limiting and audit IPs use the real client IP instead of the reverse proxy address
- Start a simple application-level daily cleanup timer in hosted mode for audit retention; external schedulers or DB extensions are deferred

**Acceptance**: PostgreSQL runs alongside Redis in Docker. Workspace records persist across restarts. SPS ephemeral operations still use Redis unchanged.

---

### Milestone 2: Human Authentication & Signup

Simple email + password auth with JWT sessions. One user creates one workspace during signup.

#### [NEW] [db/migrations/002_users.sql](../../../packages/sps-server/src/db/migrations/002_users.sql)

```sql
CREATE TABLE users (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email           TEXT NOT NULL CHECK (email = lower(btrim(email))),
  password_hash   TEXT NOT NULL,
  force_password_change BOOLEAN NOT NULL DEFAULT false,
  email_verified  BOOLEAN NOT NULL DEFAULT false,
  verification_token TEXT,
  workspace_id    UUID NOT NULL REFERENCES workspaces(id),
  role            TEXT NOT NULL DEFAULT 'workspace_admin' CHECK (role IN ('workspace_admin', 'workspace_operator', 'workspace_viewer')),
  status          TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'deleted')),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX idx_users_email_unique ON users(email);
CREATE UNIQUE INDEX idx_users_id_workspace_unique ON users(id, workspace_id);
CREATE UNIQUE INDEX idx_users_verification_token_unique
  ON users(verification_token)
  WHERE verification_token IS NOT NULL;

ALTER TABLE workspaces
  ADD CONSTRAINT fk_workspaces_owner_user_same_workspace
  FOREIGN KEY (owner_user_id, id)
  REFERENCES users(id, workspace_id)
  DEFERRABLE INITIALLY IMMEDIATE;
```

Each user belongs to exactly one workspace in Phase 3A. Additional workspaces per user are deferred.

#### [NEW] [db/migrations/003_user_sessions.sql](../../../packages/sps-server/src/db/migrations/003_user_sessions.sql)

```sql
CREATE TABLE user_sessions (
  id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id            UUID NOT NULL,
  workspace_id       UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  refresh_token_hash TEXT NOT NULL,
  user_agent         TEXT,
  ip_address         INET,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_used_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at         TIMESTAMPTZ NOT NULL,
  revoked_at         TIMESTAMPTZ
);

-- This composite FK intentionally enforces that a session cannot reference
-- a different workspace than the owning user, even though users.id is already globally unique.
ALTER TABLE user_sessions
  ADD CONSTRAINT fk_user_sessions_user_workspace
  FOREIGN KEY (user_id, workspace_id)
  REFERENCES users(id, workspace_id)
  ON DELETE CASCADE;

CREATE INDEX idx_user_sessions_user ON user_sessions(user_id, created_at DESC);
CREATE INDEX idx_user_sessions_workspace ON user_sessions(workspace_id, created_at DESC);
CREATE UNIQUE INDEX idx_user_sessions_refresh_token_hash_unique ON user_sessions(refresh_token_hash);
```

#### [NEW] [services/user.ts](../../../packages/sps-server/src/services/user.ts)

- `registerUser(email, password, workspaceSlug, displayName)` — creates workspace + owner user in one transaction
- `createWorkspaceUser(workspaceId, email, temporaryPassword, role)` — admin creates a same-workspace user with `force_password_change = true`
- `verifyEmail(token)` — marks `email_verified = true`
- `authenticateUser(email, password)` — bcrypt verify → create session row + mint JWT pair
- `refreshSession(refreshToken)` — validate session + rotate refresh token hash
- `logoutSession(sessionId)` — revoke the current session identified by access-token `sid`
- `changePassword(userId, currentPassword, nextPassword)` — updates password and clears `force_password_change`
- Treat `users.status` and `workspaces.status` as hard gates for auth and access: suspended/deleted users cannot log in; suspended/deleted workspaces block all user and agent activity
- Normalize emails aggressively on register/login/member creation: trim and lowercase before uniqueness checks and lookup
- `user_sessions.workspace_id` is DB-enforced to match the owning user's `workspace_id`
- Soft-deleted users continue to reserve their email in Phase 3A; email reclamation is deferred to a future purge workflow, not normal soft-delete behavior
- Password hashing: `bcrypt` with cost factor 12
- JWT access token: 15 min TTL, claims `{ sub, email, workspace_id, role, sid, fpc }`
- JWT refresh token: 7 day TTL, claims `{ sub, workspace_id, sid, typ: "refresh" }`, stored hashed in `user_sessions` for revocation

**Email verification**:

- Local/dev: log verification URLs to console for developer convenience
- Hosted/prod: never log raw verification URLs or tokens; until SMTP lands, verification is manual/operator-assisted for early customers
- `email_verified = false` does not block login in Phase 3A, but it should block higher-risk actions such as agent enrollment, member creation, and billing changes until the workspace owner is verified
- Provide a small internal admin script/CLI to mark early hosted accounts verified without requiring raw SQL during the pre-SMTP period

#### [NEW] [routes/auth.ts](../../../packages/sps-server/src/routes/auth.ts)

| Endpoint | Auth | Behavior |
|----------|------|----------|
| `POST /api/v2/auth/register` | None | Create workspace + user, return JWT pair |
| `POST /api/v2/auth/login` | None | Verify credentials, return JWT pair |
| `POST /api/v2/auth/refresh` | Refresh token | Rotate refresh token + issue new access token |
| `POST /api/v2/auth/logout` | Access token (`sid`) | Revoke current session |
| `POST /api/v2/auth/change-password` | Access token | Change password and clear `force_password_change` |
| `GET /api/v2/auth/verify-email/:token` | None | Mark email verified |
| `GET /api/v2/auth/me` | Access token | Return user + workspace info |

**Refresh rotation behavior**: Phase 3A uses strict single-use refresh token rotation. If two tabs refresh the same session concurrently, one may succeed and the other may be forced to re-authenticate. Grace-window handling is deferred.

**Admin-created users**: For Phase 3A simplicity, workspace admins set a temporary password when creating a user. The new user must change it after first login (`force_password_change = true`). Invite-link onboarding is deferred.

#### [MODIFY] [middleware/auth.ts](../../../packages/sps-server/src/middleware/auth.ts)

- Add `requireUserAuth(req, reply)` — validates user session JWT (separate signing key `SPS_USER_JWT_SECRET`)
- Add `requireUserRole(minRole)` — factory for role-based middleware
- Existing `requireGatewayAuth` / `requireAgentAuth` remain unchanged
- User JWT uses `iss: "sps"`, `aud: "sps-user"` to distinguish from agent JWTs
- User access tokens remain stateless in Phase 3A: middleware verifies signature/claims locally and does not hit PostgreSQL on every request
- Session revocation is enforced on refresh/logout boundaries; a revoked access token may continue to work until its 15-minute TTL expires
- When `force_password_change = true`, mint access tokens with `fpc: true`; non-auth protected user routes should reject access based on that claim until `POST /api/v2/auth/change-password` succeeds
- Suspended/deleted users and suspended/deleted workspaces should return explicit auth/access errors rather than falling through as generic invalid credentials

**Acceptance**: A human can sign up, get a workspace, log in, refresh/logout via session-backed JWTs, and hit protected endpoints. Agent auth paths remain unaffected until Milestone 4.

---

### Milestone 3: Workspace-Scoped SPS Identity

Make all SPS operations workspace-aware. Agent identity becomes `(workspace_id, sub)`. Policy and audit are evaluated within workspace scope.

#### [MODIFY] [types.ts](../../../packages/sps-server/src/types.ts)

- Add optional `workspaceId` field to `StoredRequest`, `StoredExchange`, `StoredApprovalRequest`
- Add `workspaceId` to `AuthenticatedAgentClaims`

#### [MODIFY] [middleware/auth.ts](../../../packages/sps-server/src/middleware/auth.ts)

- Extract `workspace_id` from agent JWT claims when present
- In hosted mode (`SPS_HOSTED_MODE=1`), require `workspace_id` on all agent JWTs
- In local/dev mode, `workspace_id` remains optional (backward compatible)

#### [MODIFY] [routes/secrets.ts](../../../packages/sps-server/src/routes/secrets.ts)

- Store `workspaceId` on request records when present in auth context
- Scope retrieve/status/revoke ownership checks by `(workspaceId, agentId)` in hosted mode

#### [MODIFY] [routes/exchange.ts](../../../packages/sps-server/src/routes/exchange.ts)

- Store `workspaceId` on exchange records
- Enforce `workspace_id` match on fulfillment token validation
- A2A restricted to same workspace in Phase 3A

#### [MODIFY] [services/policy.ts](../../../packages/sps-server/src/services/policy.ts)

- Policy evaluation scoped by workspace when `workspaceId` is present
- Trust rings evaluated inside workspace boundary, never cross-workspace

#### [MODIFY] [services/audit.ts](../../../packages/sps-server/src/services/audit.ts)

- Include `workspaceId` in all audit log entries when present

**Acceptance**: In hosted mode, every SPS operation is workspace-scoped. Two workspaces with identically-named agents cannot interfere. Local/dev mode continues to work without `workspace_id` (backward compatible).

---

### Milestone 4: Agent Enrollment, Bootstrap Auth & RBAC

Workspace admins register agent identities and manage workspace user roles. Agents receive bootstrap API keys (hashed, shown once at enrollment), then exchange them for short-lived hosted JWTs before calling normal SPS routes.

#### [NEW] [db/migrations/004_agents.sql](../../../packages/sps-server/src/db/migrations/004_agents.sql)

```sql
CREATE TABLE enrolled_agents (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id    UUID NOT NULL REFERENCES workspaces(id),
  agent_id        TEXT NOT NULL,              -- stable agent identity
  display_name    TEXT,
  status          TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked', 'deleted')),
  api_key_hash    TEXT,                        -- hashed API key for agent auth
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at      TIMESTAMPTZ,
  CHECK (
    (status = 'active' AND api_key_hash IS NOT NULL)
    OR (status IN ('revoked', 'deleted'))
  )
);

CREATE UNIQUE INDEX idx_enrolled_agents_active_unique
  ON enrolled_agents(workspace_id, agent_id)
  WHERE status = 'active';

CREATE INDEX idx_enrolled_agents_workspace_status
  ON enrolled_agents(workspace_id, status, created_at DESC);
```

#### [NEW] [routes/agents.ts](../../../packages/sps-server/src/routes/agents.ts)

| Endpoint | Auth | Behavior |
|----------|------|----------|
| `POST /api/v2/agents` | User JWT (admin/operator) | Enroll agent, return bootstrap API key (shown once, format `ak_<random>`) |
| `POST /api/v2/agents/token` | Agent API key | Mint short-lived hosted agent JWT with `workspace_id` + `sub` |
| `GET /api/v2/agents` | User JWT (admin/operator) | List enrolled agents |
| `POST /api/v2/agents/:aid/rotate-key` | User JWT (admin/operator) | Rotate bootstrap API key |
| `DELETE /api/v2/agents/:aid` | User JWT (admin/operator) | Revoke agent credentials |

User-facing agent management routes derive `workspace_id` from the authenticated user context instead of taking a `:wid` path parameter.

#### [NEW] [routes/members.ts](../../../packages/sps-server/src/routes/members.ts)

| Endpoint | Auth | Behavior |
|----------|------|----------|
| `GET /api/v2/members` | User JWT (admin) | List workspace users |
| `POST /api/v2/members` | User JWT (admin) | Create a user in the caller's workspace with an admin-supplied temporary password; never echo the password back |
| `PATCH /api/v2/members/:uid` | User JWT (admin) | Change role or suspend a user in the caller's workspace |

Temporary password policy:

- Enforce minimum length 12 characters on admin-supplied temporary passwords
- Reject obviously weak values used for temporary onboarding (for example exact matches like `password123`)
- Encourage generated passwords/passphrases because delivery is out-of-band in Phase 3A

#### [MODIFY] [middleware/auth.ts](../../../packages/sps-server/src/middleware/auth.ts)

- Add hosted agent JWT verification using `SPS_AGENT_JWT_SECRET` with `iss: "sps"` and `aud: "sps-agent"`
- Keep existing external JWKS/JWT provider validation for backward compatibility and dedicated deployments
- `requireAgentAuth` / `requireGatewayAuth` should accept either hosted SPS-minted agent JWTs or the existing external JWKS-validated JWTs; first successful validation path wins
- `POST /api/v2/agents/token` authenticates the bootstrap API key, resolves enrolled agent identity, and mints a short-lived JWT with `workspace_id` + stable `sub`
- Hosted agent JWT TTL: 15 minutes to match user access tokens and minimize blast radius; agents can mint replacements non-interactively with their bootstrap API key
- Bootstrap API key format: prefixed string like `ak_<random>` so it is easy to distinguish from JWTs and easier to detect in leak scans

#### [NEW] [services/rbac.ts](../../../packages/sps-server/src/services/rbac.ts)

- Role hierarchy: `workspace_admin > workspace_operator > workspace_viewer`
- `workspace_admin`: full access — manage agents, approve exchanges, manage billing
- `workspace_operator`: manage agents, approve exchanges, view audit
- `workspace_viewer`: read-only audit and status
- Roles are workspace-local; a user never carries access to more than one workspace in Phase 3A
- Agent revocation is a soft-delete/history-preserving operation; a previously revoked/deleted `agent_id` may be re-enrolled later in the same workspace
- Active agents must retain a non-null bootstrap credential hash; revoked/deleted rows may clear it later if desired
- Prevent last-admin lockout: the final active `workspace_admin` in a workspace cannot be demoted, suspended, or deleted until another active admin exists
- `checkPermission(userRole, requiredRole)` → boolean

**Acceptance**: Workspace admin can enroll agents, get a bootstrap API key, have the agent mint a short-lived JWT, and then authenticate to SPS with that JWT. Workspace admins can assign operator/viewer roles inside their workspace. RBAC enforces role-based access.

---

### Milestone 5: Billing — Stripe Integration

Simple two-tier billing: **Free** and **Standard**.

| Feature | Free | Standard ($9/mo) |
|---------|------|-------------------|
| Secret requests / day | 10 | 1,000 |
| Enrolled agents | 5 | 50 |
| A2A exchange | ❌ | ✅ |
| Workspace members | 1 | 10 |

#### [NEW] [db/migrations/005_billing.sql](../../../packages/sps-server/src/db/migrations/005_billing.sql)

```sql
ALTER TABLE workspaces
  ADD COLUMN stripe_customer_id TEXT,
  ADD COLUMN stripe_subscription_id TEXT,
  ADD COLUMN subscription_status TEXT DEFAULT 'none'
    CHECK (subscription_status IN ('none', 'active', 'past_due', 'canceled', 'unpaid', 'incomplete', 'incomplete_expired', 'trialing'));

CREATE UNIQUE INDEX idx_workspaces_stripe_customer_unique
  ON workspaces(stripe_customer_id)
  WHERE stripe_customer_id IS NOT NULL;

CREATE UNIQUE INDEX idx_workspaces_stripe_subscription_unique
  ON workspaces(stripe_subscription_id)
  WHERE stripe_subscription_id IS NOT NULL;
```

#### [NEW] [services/billing.ts](../../../packages/sps-server/src/services/billing.ts)

- `createCheckoutSession(workspaceId, priceId)` → Stripe Checkout session URL
- `handleWebhook(event)` → process `checkout.session.completed`, `invoice.paid`, `customer.subscription.deleted`
- On successful payment: update workspace `tier = 'standard'`, set `subscription_status = 'active'`
- On cancellation: revert to `tier = 'free'`
- Stripe customer/subscription IDs are unique across workspaces at the DB layer

#### [NEW] [routes/billing.ts](../../../packages/sps-server/src/routes/billing.ts)

| Endpoint | Auth | Behavior |
|----------|------|----------|
| `POST /api/v2/billing/checkout` | User JWT (admin) | Create Stripe Checkout session |
| `POST /api/v2/webhook/stripe` | Stripe signature | Handle Stripe webhook events using the raw request body for signature verification |
| `GET /api/v2/billing` | User JWT (admin) | Return current subscription status |

**Stripe webhook handling**: Fastify must preserve the raw request body for `/api/v2/webhook/stripe` so the Stripe SDK can verify `Stripe-Signature` before JSON parsing.

#### [NEW] [services/quota.ts](../../../packages/sps-server/src/services/quota.ts)

- `checkQuota(workspaceId, action)` → enforce tier limits using Redis counters with daily TTL
- Actions: `secret_request`, `agent_enroll`, `exchange_request`
- Free tier daily counters reset at midnight UTC
- Counters are advisory/best-effort in MVP; Redis loss/reset may clear counters early, but does not change the billing source of truth for workspace tier

**Acceptance**: Workspace admin can upgrade from free to standard via Stripe Checkout. Webhook updates workspace tier. Best-effort quotas are enforced — free tier is blocked after 10 requests/day under normal Redis operation.

---

### Milestone 6: Abuse Controls & Hardening

Rate limiting, basic signup abuse controls, and durable workspace audit visibility.

#### [NEW] [middleware/rate-limit.ts](../../../packages/sps-server/src/middleware/rate-limit.ts)

- Per-IP rate limiting for auth endpoints (10 req/min for login, 3 req/min for register)
- Aggressive per-IP rate limiting for `POST /api/v2/agents/token` (for example 5 req/min) because it mints hosted JWTs from bootstrap credentials
- Per-workspace hosted usage caps continue to be enforced through the quota service from Milestone 5
- Uses Redis `INCR` with key TTL
- Best-effort only in MVP; not a durable billing ledger

#### [NEW] [db/migrations/006_audit_log.sql](../../../packages/sps-server/src/db/migrations/006_audit_log.sql)

```sql
CREATE TABLE audit_log (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id    UUID REFERENCES workspaces(id),
  event_type      TEXT NOT NULL,
  actor_id        TEXT,
  actor_type      TEXT,                   -- 'user' | 'agent' | 'system'
  resource_id     TEXT,
  metadata        JSONB,
  ip_address      INET,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_workspace_time ON audit_log(workspace_id, created_at DESC);
CREATE INDEX idx_audit_event_time ON audit_log(event_type, created_at DESC);
```

#### [MODIFY] [services/audit.ts](../../../packages/sps-server/src/services/audit.ts)

- Dual-write: structured JSON log (existing) + PostgreSQL `audit_log` table (new)
- Workspace-scoped queries: an operator can only see their own workspace's audit history
- Metadata-minimized: no secret plaintext, no ciphertext, no raw tokens
- Never log raw email verification URLs, refresh tokens, or bootstrap API keys
- Add a basic retention cleanup path in Phase 3A so `audit_log` does not grow forever; tier-specific retention can come later

**Audit retention**: Start with one simple retention policy for all workspaces in Phase 3A (for example 30 days). Implement cleanup with a small application-level scheduled job in the SPS server process; tier-specific retention windows and external schedulers are deferred.

**Physical deletion model**: Phase 3A application behavior uses soft deletes, not hard deletes. Most foreign keys intentionally fail closed on physical deletion attempts so accidental `DELETE` operations do not silently cascade through tenant data. Any future purge/GDPR workflow should run as an explicit, transactional admin path with ordered cleanup/anonymization rules.

#### [NEW] [routes/audit.ts](../../../packages/sps-server/src/routes/audit.ts)

| Endpoint | Auth | Behavior |
|----------|------|----------|
| `GET /api/v2/audit` | User JWT (admin/operator/viewer) | Paginated audit stream for the caller workspace with filters (`event_type`, `actor_type`, `resource_id`, `from`, `to`, `limit`) |
| `GET /api/v2/audit/exchange/:id` | User JWT (admin/operator/viewer) | Return caller-workspace exchange lifecycle + approval history for one exchange |

**Acceptance**: Excessive requests are rate-limited. Basic signup abuse controls are in place. Audit events persist in PostgreSQL and are visible through workspace-scoped customer audit endpoints.

---

## Infrastructure Changes

#### [MODIFY] [docker-compose.yml](../../../docker-compose.yml)

```yaml
services:
  postgres:
    image: postgres:16-alpine
    container_name: blindpass-postgres
    environment:
      POSTGRES_DB: blindpass
      POSTGRES_USER: blindpass
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-localdev}
    ports:
      - "5433:5432"
    volumes:
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U blindpass -d blindpass"]
      interval: 1s
      timeout: 3s
      retries: 30

  redis:
    # ... existing config unchanged

volumes:
  pgdata:
```

#### [MODIFY] [packages/sps-server/package.json](../../../packages/sps-server/package.json)

New dependencies: `pg`, `bcrypt`, `stripe`, `@types/pg`, `@types/bcrypt`

#### Unraid Deployment

- New Unraid template for PostgreSQL container
- SPS server template gets `DATABASE_URL`, `SPS_USER_JWT_SECRET`, `SPS_AGENT_JWT_SECRET`, `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET` env vars
- Update [Unraid.md](../../deployment/Unraid.md)

---

## Verification Plan

### Automated Tests

All tests use **Vitest**. Run from project root:

```bash
npm test
npm test --workspace=packages/sps-server
```

#### Milestone 1: `db.test.ts`
- PostgreSQL pool connects and runs simple query
- Migration runner applies migrations idempotently
- Failed migration rolls back the whole file transaction
- Workspace CRUD: create, get by slug, enforce unique slug
- Workspace owner FK rejects an owner user from a different workspace
- Reverse-proxy aware client IP extraction works when `trustProxy` is enabled

#### Milestone 2: `auth-routes.test.ts`
- Register → creates workspace + user → returns JWT pair
- Register/login normalize email casing and surrounding whitespace
- Register with duplicate email → `409`
- Duplicate email differing only by case → `409`
- Login with correct credentials → JWT pair
- Login with wrong password → `401`
- Unverified user can log in but cannot perform higher-risk verified-only actions
- Admin-created user with temporary password must change password before using protected routes
- Access token includes `fpc: true` when `force_password_change = true`
- Access token validates on protected route
- Expired access token → `401`
- Refresh token → rotated refresh token + new access token
- Logout → current `sid` session revoked
- Revoked session cannot refresh, but an already-issued access token remains valid until TTL expiry

#### Milestone 3: extend `exchange-routes.test.ts` + `routes.test.ts`
- Hosted mode: agent JWT without `workspace_id` → `401`
- Hosted mode: exchange between different workspaces → denied
- Local mode: operations work without `workspace_id` (backward compat)

#### Milestone 4: `agents-routes.test.ts` + `e2e.test.ts`
- Enroll agent → get bootstrap API key
- Re-enroll previously revoked/deleted `agent_id` in the same workspace → success
- Agent exchanges API key for short-lived JWT → success
- Agent auth with minted JWT → success
- Hosted JWT path and legacy external JWKS path both authenticate through `requireAgentAuth`
- `POST /api/v2/agents/token` is rate-limited after repeated attempts
- Rotate agent bootstrap key → old key fails, new key succeeds
- Revoke agent → auth fails
- Active agent row cannot exist with `api_key_hash = NULL`
- Owner verification gate blocks high-risk actions until workspace owner email is verified
- RBAC: `workspace_operator` can manage agents, but member-management routes stay admin-only
- RBAC: `workspace_viewer` cannot enroll agents → `403`
- Member role update: `workspace_admin` can demote/promote same-workspace users
- Last active `workspace_admin` cannot be demoted or suspended
- Logout revokes refresh capability, but an already-issued access token remains valid until TTL expiry

#### Milestone 5: `billing.test.ts`
- Create checkout session → returns Stripe URL
- Stripe webhook signature verification uses raw request body and rejects mutated payloads
- Webhook `checkout.session.completed` → workspace tier upgraded
- Webhook `customer.subscription.deleted` → tier downgraded
- Duplicate Stripe customer/subscription IDs across workspaces are rejected by DB constraints
- Quota enforcement: 11th request on free tier → `429`
- Quota enforcement: 6th active enrolled agent on free tier → `429`

#### Milestone 6: `rate-limit.test.ts`
- 11th login attempt in 1 minute → `429`
- 4th register attempt in 1 minute → `429`
- 6th `POST /api/v2/agents/token` attempt in 1 minute → `429`
- Audit endpoint returns only caller workspace records and excludes bootstrap keys / ciphertext
- Exchange audit endpoint returns only caller-workspace lifecycle records
- Application-level audit retention cleanup removes expired records on schedule

> [!NOTE]
> Tests that need PostgreSQL use an isolated schema under the configured test database, and Stripe paths continue to use a mocked SDK.

### Manual Verification

1. `docker compose up` starts PostgreSQL + Redis + SPS server
2. `curl` to register → login → refresh → logout → get workspace info
3. Create agent via API → mint 15-minute hosted JWT from API key → use JWT to hit SPS endpoints
4. Two workspaces with same agent name cannot see each other's secrets
5. Create Stripe test checkout → complete → verify tier upgrade
6. Fetch workspace audit stream → verify only same-workspace events are returned
7. Hit login endpoint 11 times rapidly → verify `429` response

---

### Resolved Decisions

- **Email delivery** → local/dev may log verification URLs, but hosted/prod must not; SMTP (Zoho or other) is deferred, so early hosted verification is manual/operator-assisted
- **Workspace membership** → each user belongs to exactly one workspace in Phase 3A; no cross-workspace membership or switching yet
- **Soft-delete identifier reuse** → deleted workspaces and users continue to reserve their slug/email in Phase 3A; reclamation requires a future purge workflow, not ordinary soft delete
- **Admin-created users** → workspace admins set a temporary password and new users must change it on first login; invite-link onboarding is deferred
- **Email normalization** → user emails are trimmed + lowercased before storage and lookup; case variants do not create separate accounts
- **Temporary password policy** → minimum length 12, reject obviously weak values, never echo back in API responses
- **Agent auth** → API keys are bootstrap-only and mint short-lived hosted JWTs carrying `workspace_id`; normal SPS routes continue to use bearer JWTs
- **Agent auth compatibility** → hosted SPS-minted JWTs and existing external JWKS-validated JWTs both remain valid inputs to `requireAgentAuth`
- **Agent JWT lifetime** → 15 minutes; agents renew non-interactively via the bootstrap API key
- **Bootstrap API key format** → `ak_<random>` prefix for operator clarity and leak detection
- **Agent re-enrollment semantics** → revoked/deleted agents are retained for history but may be re-enrolled later under the same `agent_id`
- **Billing tiers** → Free + Standard ($9/mo) with quotas as defined above; `free` is the entry-tier label, not `trial`
- **Workspace lifecycle model** → current implementation uses `active/suspended/deleted` status plus `free/standard` billing tier; separate `free-tier` / `verified` / `paid` workspace lifecycle states are deferred
- **Post-payment activation** → Stripe webhooks upgrade the billing tier automatically, but there is no separate post-payment workspace activation state yet
- **Customer audit visibility** → caller-workspace audit endpoints ship in Phase 3A
- **Email verification gating** → unverified accounts may log in, but verified-only actions stay blocked until manual verification or future SMTP flow completes
- **Signup abuse controls** → current Phase 3A ships per-IP rate limiting and owner-verification gates for higher-risk actions; CAPTCHA/challenge/risk-review flows are deferred
- **Refresh rotation semantics** → strict single-use rotation in Phase 3A; concurrent refresh races may force one tab/client to re-authenticate
- **Access token revocation model** → access tokens are stateless and not checked against PostgreSQL on every request; logout/revocation blocks refresh immediately and existing access tokens age out within 15 minutes
- **Force-password-change enforcement** → encoded as `fpc` in the access token so protected-route checks stay stateless
- **Status enforcement** → suspended/deleted users and workspaces are hard-blocked across auth and runtime access paths
- **Last-admin safety** → the final active workspace admin cannot be removed without assigning another active admin first
- **Hosted policy model** → current Phase 3A ships explicit requester/fulfiller and ring-based policy rules; owner/team abstractions are deferred
- **Hosted onboarding scope** → current Phase 3A covers workspace signup and admin-enrolled agents; guided `free-tier` onboarding, discovery, and deeper MCP/OpenClaw packaging are deferred
- **Proxy-aware IP handling** → hosted deployments must configure Fastify `trustProxy` correctly for rate limiting and audit IP accuracy
- **Stripe webhook verification** → `/api/v2/webhook/stripe` uses raw-body verification before JSON parsing
- **Audit retention** → Phase 3A includes a simple application-level scheduled cleanup policy (for example 30 days for all workspaces); tier-specific retention is deferred
- **Physical deletion model** → normal Phase 3A behavior is soft delete; hard deletes are explicit admin/purge operations and FKs intentionally fail closed by default
- **Quotas and rate limits** → advisory/best-effort in MVP, not durable usage accounting
- **Database** → PostgreSQL via `pg` (node-postgres) with file-based migrations
- **Deployment** → Unraid-first with Docker Compose; GCP/Supabase portability deferred

### Suggested Work Breakdown

1. PostgreSQL setup + migrations + workspace model
2. Human auth (register, login, JWT sessions)
3. Workspace-scoped SPS identity + backward compat
4. Agent enrollment + bootstrap API key flow + RBAC
5. Stripe billing integration + quota enforcement
6. Rate limiting + abuse controls + durable audit
