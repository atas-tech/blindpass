# Stabilizing E2E Tests: Root Cause Analysis & Implementation Plan

> Historical record, archived during the 2026-09-22 documentation alignment. Dates, checkboxes, commands, and proposed decisions below describe their original review period; they do not establish current support or authorize new work. See the [current documentation](../../README.md) and [roadmap](../../product/Roadmap.md).

This plan outlines a comprehensive approach to eliminate flakiness, speed up the E2E test suite, and resolve database bloat. It supersedes the previous plan with deeper root cause analysis covering all 14 spec files.

---

## Root Cause Analysis

### 🔴 RC-1: Inconsistent Setup Patterns (Critical)

There are **4 different setup patterns** scattered across 14 spec files:

| Pattern | Used By | Issues |
|---|---|---|
| Shared `setup.ts` → `setupWorkspace(page, prefix)` | `management`, `billing`, `analytics`, `routing`, `guest-exchange`, `x402`, `policy` | Returns `workspaceId: "unknown-mock"` — tests needing real IDs work only by accident |
| Inline `setupWorkspace` with DB verification | `approvals.spec.ts`, `audit.spec.ts` | Duplicated code, manual `pg.Client` lifecycle |
| Direct UI registration inline | `auth.spec.ts` | No shared helper at all |
| API-only registration | `email-locale.spec.ts` | Uses `request.post`, no UI |

**Impact**: The shared `setup.ts` returns `workspaceId: "unknown-mock"` (line 44), yet tests like `x402.spec.ts` check `if (!workspaceId) throw new Error("workspaceId missing")` — this only works because auto-verification via `test-` prefix emails silently sets `email_verified=true` in the DB, and the dashboard resolves the ID from the session. If auto-verify timing is off, or `page.reload()` in setup doesn't complete before the test continues, **the entire test fails**.

### 🔴 RC-2: UI-Driven Registration is Inherently Flaky (Critical)

Every non-`auth.spec` test spends 5–15 seconds on UI registration. This involves:
1. `page.goto("/register")` — Vite HMR cold-start latency
2. `waitForSelector('[data-testid="register-button"]')` — Note: `auth.spec.ts` uses `register-submit` while `setup.ts` uses `register-button` — **these are different selectors**
3. Form fill (5 fields)
4. Click submit
5. Wait for 302 redirect
6. `page.reload()` + `waitForLoadState("networkidle")` + `waitForTimeout(2000)` — **hardcoded waits**

With ~30 tests each doing full UI registration, any single timeout cascades into failure.

### 🔴 RC-3: Database Connection Leaks (Critical)

Multiple specs create raw `pg.Client` or `pg.Pool` instances:

| File | Pattern | Risk |
|---|---|---|
| `approvals.spec.ts` | 4× `new pg.Client()` in different scopes | Connection leak on assertion failure |
| `audit.spec.ts` | `new pg.Client()` inside inline `setupWorkspace` | Leak if `client.end()` never called |
| `routing.spec.ts` | `new Pool()` in `beforeAll` | Pool cleanup depends on `afterAll` running |
| `billing.spec.ts` | `new pg.Pool()` in `beforeAll` | Same |
| `x402.spec.ts` | `new pg.Pool()` in `beforeAll` | Same |
| `guest-exchange.spec.ts` | `new pg.Pool()` in `beforeAll` | Same |

With `workers: 1` and `fullyParallel: false`, these run sequentially. But if a test times out or crashes, `finally` blocks may not execute and connections leak. After 30+ tests, the PG connection pool may be exhausted.

### 🟡 RC-4: Mock Facilitator Port Conflicts (Medium)

Both `x402.spec.ts` and `guest-exchange.spec.ts` start an HTTP server on **port 3101** in `beforeAll`. If the first file's `afterAll` doesn't execute (timeout), port 3101 stays bound and the second file's `beforeAll` fails with `EADDRINUSE`.

### 🟡 RC-5: Inconsistent `data-testid` Names (Medium)

| Element | `auth.spec.ts` | `setup.ts` (shared) |
|---|---|---|
| Register button | `register-submit` | `register-button` |
| Terms checkbox | `register-terms` (checked) | Not checked |

**Confirmed via codebase review:** The DOM uses `register-submit` and strictly requires the `register-terms` to be checked. Because `setup.ts` waits for `register-button` and skips checking the terms, it guarantees a 15-second timeout waiting for a non-existent UI state. This is the primary driver of the suite's cascading flakiness.

### 🟡 RC-6: No Database Cleanup Between Runs (Medium)

The database grows indefinitely. Timestamp-based unique emails prevent collisions, but `users`, `workspaces`, `user_sessions`, `audit_log` tables grow without bound, degrading query performance.

### 🟠 RC-7: `setupWorkspace` Returns Mock IDs (Low–Medium)

```typescript
return {
  adminEmail: workspaceData.email,
  password: workspaceData.password,
  workspaceId: "unknown-mock",   // ← Useless
  workspaceSlug: workspaceData.workspace,
  userId: "unknown-mock"          // ← Useless
};
```

Tests that need real `workspaceId` for direct DB queries work only by coincidence.

### 🟡 RC-8: Hosted-Mode Refresh Token Delivery Race (Medium)

The `SPS_HOSTED_MODE=1` config in `playwright.config.ts` changes how refresh tokens are delivered. In hosted mode, the server stores the refresh token in an **HttpOnly cookie** with `Path=/api/v2/auth`. For test mode specifically, it _also_ emits `refresh_token` in the JSON body (lines 260–262 of `auth.ts`).

However, the dashboard's `AuthContext.tsx` reads the refresh token from `localStorage` key `blindpass_refresh_token` (line 91) and sends it as a body field in the `/refresh` request (line 98). This means:

- **UI-based registration** works because `AuthContext.applyAuth()` saves `payload.refresh_token` to `localStorage` (line 61) when it's present in the response.
- **API-based seed route** (new Phase 1) will also return `refresh_token` in the JSON body thanks to the `NODE_ENV === "test"` special case, so injecting it into `localStorage` will work correctly.
- **Cross-origin flows** (dashboard → browser-ui) extract from `localStorage` and re-inject — this works because both use the `blindpass_refresh_token` key.

> [!NOTE]
> No code change needed for RC-8 — the existing `NODE_ENV=test` special case in `buildAuthResponse()` ensures the seed route will include `refresh_token` in the body. The new `setup.ts` correctly injects it into `blindpass_refresh_token` localStorage. Documenting this here to prevent future regression if someone changes the hosted-mode token delivery.

### 🟠 RC-9: No Pre-Flight Validation (Low–Medium)

Currently, Playwright relies entirely on the `webServer` config to start services. If any infrastructure dependency fails (PostgreSQL not running, port 5433 unreachable, migrations not applied), the failure surfaces **deep inside tests** as cryptic API 500 errors or connection timeouts, not as a clear "your infra is down" message.

---

## User Review Required

> [!IMPORTANT]
> This plan introduces a new API route `POST /api/v2/auth/test/seed-workspace` that is highly privileged. It bypasses email verification and rate limits for tests. The route will be protected by three layers:
> - registered only when `NODE_ENV === "test"` and `SPS_ENABLE_TEST_SEED_ROUTES === "1"`
> - returns `404` when either guard is missing
> - requires a matching `x-blindpass-e2e-seed-token` header backed by `SPS_E2E_SEED_TOKEN`
>
> Please review to ensure you're comfortable with this E2E-only backend pattern.

> [!WARNING]
> **Database truncation**: `preflight.setup.ts` will `TRUNCATE ... CASCADE` all tables after `webServer` starts and before the real spec files run. This means:
> - You cannot run the test suite against a production or staging database
> - Any manually seeded data will be wiped
> - `fullyParallel: false` must remain since we clean once at start

---

## Phase 0: Pre-Run Infrastructure Checks

The startup flow is intentionally split across three stages so each step does only the work it can safely do:

| Stage | File / System | Runs | Responsibilities |
|---|---|---|---|
| 1 | `global-setup.ts` | Before `webServer` | PostgreSQL connectivity only |
| 2 | `webServer` | Playwright built-in | Starts SPS (auto-migrates), Dashboard, Browser-UI |
| 3 | `preflight.setup.ts` | After `webServer`, before specs | Migration verification, `TRUNCATE`, health probes, seed-route probe |

If any stage fails, the suite aborts immediately with a clear, actionable error message instead of timing out deep inside the spec files.

### Checks to Implement Across Startup Stages

#### 1. PostgreSQL Connectivity & Readiness
```typescript
// Verify PG is reachable and accepting queries
const client = new pg.Client({ connectionString: DB_URL });
await client.connect(); // Fails fast with ECONNREFUSED if Docker is down
await client.query("SELECT 1"); // Verifies the connection is usable
```
**Why**: If the `docker-compose.test.yml` services aren't running, the current suite starts all 3 web servers (SPS, Dashboard, Browser-UI), waits 240s for each, and only then fails. This wastes 4+ minutes before producing a useful error.

> [!IMPORTANT]
> **Ordering constraint**: `globalSetup` runs _before_ Playwright's `webServer` starts the SPS server. This means `globalSetup` cannot verify migrations or truncate tables — the schema may not exist yet on a fresh database. Therefore, `globalSetup` is limited to PG connectivity only. All schema-dependent checks (migration count, TRUNCATE) are deferred to `preflight.setup.ts`, which runs _after_ `webServer` starts (and SPS auto-applies migrations).

#### 2. Port Availability Check
```typescript
// Verify required ports aren't already bound by stale processes
for (const port of [3100, 5173, 5175]) {
  const inUse = await isPortInUse(port);
  if (inUse) {
    throw new Error(
      `Port ${port} is already in use. Kill stale processes: lsof -ti :${port} | xargs kill`
    );
  }
}
```
**Why**: `reuseExistingServer: true` in `playwright.config.ts` means Playwright will silently connect to a stale SPS/Vite instance that may have different env vars or stale code. If the stale server is missing any of the E2E seed-route guards, the seed route will 404 and every test fails.

> [!WARNING]
> `reuseExistingServer: true` is deliberately set for developer convenience (avoid restarting servers during TDD). However, this is a double-edged sword: it can mask env var mismatches. The behaviour should differ by environment:
> - **In CI** (`process.env.CI`): **hard-fail** if any port is in use. A stale process in CI guarantees non-deterministic results.
> - **Locally**: **warn** and ask the developer to verify the running server's env.

#### 3. SPS Server Health & Configuration Probe
After webServer starts, before any spec runs:
```typescript
// Verify SPS is running with the expected E2E auth config
const healthResponse = await fetch("http://localhost:3100/healthz");
if (!healthResponse.ok) {
  throw new Error("SPS server /healthz failed — server did not start correctly.");
}

// Verify seed route is accessible with the E2E header/token guard
const seedProbe = await fetch("http://localhost:3100/api/v2/auth/test/seed-workspace", {
  method: "POST",
  headers: {
    "content-type": "application/json",
    "x-blindpass-e2e-seed-token": process.env.SPS_E2E_SEED_TOKEN ?? "blindpass-e2e-seed-token"
  },
  body: JSON.stringify({ prefix: "probe" })
});
if (seedProbe.status === 404) {
  throw new Error(
    "Seed route returned 404 — SPS is missing one of the E2E seed-route guards. " +
    "Check playwright.config.ts webServer env or kill stale processes."
  );
}
```
**Why**: Most critical pre-flight check. If the seed route isn't available, _every_ test that uses `setupWorkspace()` will fail. Better to catch this in 1 second than discover it 5 minutes into the suite.

#### 4. Browser-UI Availability
```typescript
const browserUiResponse = await fetch("http://localhost:5175/");
if (!browserUiResponse.ok) {
  throw new Error("Browser-UI (port 5175) is not responding. Required by guest-exchange.spec.ts.");
}
```
**Why**: `guest-exchange.spec.ts` navigates to `http://localhost:5175` for the fulfillment flow. If Browser-UI isn't running, the test hangs for 120s on a network timeout.

### Recommended Architecture: Playwright Setup Project

Since `globalSetup` runs _before_ `webServer`, it can't probe the SPS server. The correct Playwright pattern is a **setup project** that runs after servers start but before test specs:

```typescript
// playwright.config.ts
export default defineConfig({
  globalSetup: "./e2e/global-setup.ts",  // PG connectivity only
  projects: [
    {
      name: "setup",
      testMatch: /preflight\.setup\.ts/,
    },
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
      dependencies: ["setup"],  // Wait for setup to pass
    },
  ],
  // ...
});
```

```typescript
// e2e/preflight.setup.ts
import { test, expect } from "@playwright/test";

const E2E_SEED_TOKEN = process.env.SPS_E2E_SEED_TOKEN ?? "blindpass-e2e-seed-token";

test("Pre-flight: SPS health & seed route", async ({ request }) => {
  // 1. Health check
  const health = await request.get("http://localhost:3100/healthz");
  expect(health.ok(), "SPS /healthz failed").toBeTruthy();

  // 2. Seed route probe
  const seed = await request.post("http://localhost:3100/api/v2/auth/test/seed-workspace", {
    headers: {
      "x-blindpass-e2e-seed-token": E2E_SEED_TOKEN
    },
    data: { prefix: "preflight" }
  });
  expect(seed.status(), "Seed route not available — NODE_ENV may not be 'test'").toBe(201);

  // 3. Browser-UI probe
  const browserUi = await request.get("http://localhost:5175/");
  expect(browserUi.ok(), "Browser-UI (port 5175) not responding").toBeTruthy();

  // 4. Dashboard probe
  const dashboard = await request.get("http://localhost:5173/");
  expect(dashboard.ok(), "Dashboard (port 5173) not responding").toBeTruthy();
});
```

> [!TIP]
> The preflight test creates one workspace (`test-preflight-*`) which also serves as a warmup for the SPS server's connection pool, bcrypt hashing, and Vite's initial compile. This eliminates cold-start latency for the first real test.
>
> Accepted tradeoff: the suite no longer starts from a literally empty post-truncate state. This is intentional and acceptable for the E2E suite as long as the preflight workspace remains the only warmup artifact created before spec execution.

---

## Phase 1: API-Based Seed Route (Backend)

By replacing UI automation with a direct backend API call, we skip flaky browser interactions for setting up tests.

### [MODIFY] [auth.ts](../../../packages/sps-server/src/routes/auth.ts)

Add a `POST /test/seed-workspace` route handler:

- Register the route only when `NODE_ENV === "test"` and `SPS_ENABLE_TEST_SEED_ROUTES === "1"`
- Require header `x-blindpass-e2e-seed-token` to match `SPS_E2E_SEED_TOKEN`
- Accept body payload `{ prefix: string }`
- Auto-generate workspace slug, email, and password from prefix + timestamp
- Call existing `registerUser()` backend function directly
- Execute `UPDATE users SET email_verified = true WHERE id = $1` to bypass verification
- Return full auth response including **real `workspaceId`**, **real `userId`**, tokens, email, and password

```typescript
const seedRoutesEnabled =
  process.env.NODE_ENV === "test" &&
  process.env.SPS_ENABLE_TEST_SEED_ROUTES === "1" &&
  typeof process.env.SPS_E2E_SEED_TOKEN === "string" &&
  process.env.SPS_E2E_SEED_TOKEN.length > 0;

if (seedRoutesEnabled) {
  app.post("/test/seed-workspace", async (req, reply) => {
    if (req.headers["x-blindpass-e2e-seed-token"] !== process.env.SPS_E2E_SEED_TOKEN) {
      return reply.code(404).send();
    }

    const { prefix } = req.body;
    const ts = Date.now();
    const rand = crypto.randomBytes(4).toString("hex");
    const email = `test-${prefix}-${ts}-${rand}@example.com`;
    const password = "LongPassword123!";
    const slug = `test-${prefix}-${ts}-${rand}`;
    const displayName = `${prefix.toUpperCase()} E2E Space`;

    const result = await registerUser(db, email, password, slug, displayName, "en", {});
    await db.query("UPDATE users SET email_verified = true WHERE id = $1", [result.user.id]);

    return reply.code(201).send({
      access_token: result.tokens.accessToken,
      refresh_token: result.tokens.refreshToken,
      access_token_expires_at: result.tokens.accessTokenExpiresAt,
      refresh_token_expires_at: result.tokens.refreshTokenExpiresAt,
      workspace_id: result.workspace.id,
      user_id: result.user.id,
      email,
      password,
      workspace_slug: slug
    });
  });
}
```

---

## Phase 2: Unified Test Fixtures & Setup

### [MODIFY] [setup.ts](../../../packages/dashboard/e2e/setup.ts)

Complete rewrite — replace all UI interactions with an API call + token injection:

- Remove all `page.goto('/register')`, `waitForSelector`, `.fill()`, and `.click()` commands
- Make an API call to `http://localhost:3100/api/v2/auth/test/seed-workspace` using an isolated Playwright `APIRequestContext`
- Extract real IDs (`workspace_id`, `user_id`) and tokens from the JSON response
- Use `page.evaluate()` to inject the refresh token into `localStorage` under key `blindpass_refresh_token` (must match `AuthContext.tsx` line 91 exactly)
- Reload once and wait for the sidebar to confirm session hydration
- Remove `waitForTimeout` and `waitForLoadState("networkidle")` hacks

```typescript
import { expect, request as playwrightRequest, type Page } from "@playwright/test";

const API_URL = "http://localhost:3100";
const E2E_SEED_TOKEN = process.env.SPS_E2E_SEED_TOKEN ?? "blindpass-e2e-seed-token";

export interface WorkspaceFixture {
  adminEmail: string;
  password: string;
  workspaceId: string;
  workspaceSlug: string;
  userId: string;
  accessToken: string;
  refreshToken: string;
}

export async function setupWorkspace(page: Page, prefix = "default"): Promise<WorkspaceFixture> {
  // Append worker index for parallel-safety (future-proofing)
  const workerPrefix = `${prefix}-w${process.env.TEST_WORKER_INDEX ?? "0"}`;

  const api = await playwrightRequest.newContext();
  let data: any;
  try {
    const response = await api.post(`${API_URL}/api/v2/auth/test/seed-workspace`, {
      headers: {
        "x-blindpass-e2e-seed-token": E2E_SEED_TOKEN
      },
      data: { prefix: workerPrefix }
    });
    expect(response.status()).toBe(201);
    data = await response.json();
  } finally {
    await api.dispose();
  }

  // Fail fast if seed route returns garbage IDs
  expect(data.workspace_id, "Seed route returned invalid workspace_id").toMatch(/^[0-9a-f-]{36}$/);
  expect(data.user_id, "Seed route returned invalid user_id").toMatch(/^[0-9a-f-]{36}$/);

  await page.goto("/");

  // Use an isolated request context so the seed call does not share browser cookies.
  // That preserves test coverage for flows that intentionally clear localStorage or
  // verify logout behavior without a stale hosted-mode refresh cookie masking bugs.
  await page.evaluate(({ refreshToken }) => {
    localStorage.setItem("blindpass_refresh_token", refreshToken);
  }, { refreshToken: data.refresh_token });

  await page.reload();
  await expect(page.getByTestId("nav-sidebar")).toBeVisible({ timeout: 15000 });

  return {
    adminEmail: data.email,
    password: data.password,
    workspaceId: data.workspace_id,
    workspaceSlug: data.workspace_slug,
    userId: data.user_id,
    accessToken: data.access_token,
    refreshToken: data.refresh_token
  };
}
```

### [NEW] [fixtures.ts](../../../packages/dashboard/e2e/fixtures.ts)

Introduce Playwright custom fixtures to wrap `pg.Pool` usage, eliminating manual connection lifecycle management across specs. Playwright automatically manages the fixture teardown even on assertion failures.

```typescript
import { test as base } from "@playwright/test";
import pg from "pg";

const DB_URL = process.env.DATABASE_URL || "postgresql://blindpass:localdev@127.0.0.1:5433/blindpass";

export const test = base.extend<{ db: pg.Pool }>({
  db: async ({}, use) => {
    const pool = new pg.Pool({ connectionString: DB_URL, max: 3 });
    await use(pool);
    await pool.end();
  }
});

export { expect } from "@playwright/test";
```

---

## Phase 3: Database Isolation & Cleanup

### [NEW] [global-setup.ts](../../../packages/dashboard/e2e/global-setup.ts)

A minimal Playwright `globalSetup` that runs **before** `webServer`. Its only job is to verify PostgreSQL is reachable — if Docker isn't running, the suite aborts in ~1 second with a clear error instead of wasting 4+ minutes starting web servers that will all fail.

> [!NOTE]
> `globalSetup` intentionally does NOT truncate tables or check migrations. It runs before `webServer`, so the SPS server hasn't started yet and the schema may not exist on a fresh database. All schema-dependent work is deferred to `preflight.setup.ts`.

```typescript
import pg from "pg";

const DB_URL = process.env.DATABASE_URL || "postgresql://blindpass:localdev@127.0.0.1:5433/blindpass";

export default async function globalSetup() {
  const client = new pg.Client({ connectionString: DB_URL });
  try {
    await client.connect();
    await client.query("SELECT 1");
    console.log("[E2E globalSetup] PostgreSQL is reachable.");
  } catch (err) {
    throw new Error(
      `[E2E Pre-flight FAILED] Cannot connect to PostgreSQL at ${DB_URL}.\n` +
      `Ensure Docker is running: docker compose -f docker-compose.test.yml up -d\n` +
      `Original error: ${err instanceof Error ? err.message : err}`
    );
  } finally {
    await client.end();
  }
}
```

### [NEW] [preflight.setup.ts](../../../packages/dashboard/e2e/preflight.setup.ts)

A Playwright **setup project** that runs _after_ `webServer` starts but _before_ any test spec. It performs all schema-dependent work (migration verification, TRUNCATE) and validates all three servers are healthy and correctly configured.

```typescript
import { test, expect } from "@playwright/test";
import pg from "pg";

const DB_URL = process.env.DATABASE_URL || "postgresql://blindpass:localdev@127.0.0.1:5433/blindpass";
const E2E_SEED_TOKEN = process.env.SPS_E2E_SEED_TOKEN ?? "blindpass-e2e-seed-token";

test("Pre-flight: Database state", async () => {
  const client = new pg.Client({ connectionString: DB_URL });
  await client.connect();
  try {
    // 1. Verify migrations are applied (SPS auto-migrates on startup)
    const migrationCheck = await client.query(
      "SELECT COUNT(*)::int AS count FROM information_schema.tables " +
      "WHERE table_schema = 'public' AND table_name = '_migrations'"
    );
    expect(
      migrationCheck.rows[0].count,
      "_migrations table not found — SPS server may not have started correctly"
    ).toBeGreaterThan(0);

    const appliedCount = await client.query("SELECT COUNT(*)::int AS count FROM _migrations");
    if (appliedCount.rows[0].count < 17) {
      console.warn(
        `[E2E Pre-flight WARNING] Only ${appliedCount.rows[0].count}/17 migrations applied.`
      );
    }

    // 2. Truncate all data tables for a clean slate
    await client.query(`
      TRUNCATE
        users, workspaces, user_sessions, user_tokens,
        audit_log, enrolled_agents, agent_allowances,
        workspace_policy_documents, workspace_exchange_usage, public_offers,
        x402_transactions, x402_inflight, guest_payments, guest_intents
      CASCADE
    `);
    console.log("[E2E preflight] Database truncated successfully.");
  } finally {
    await client.end();
  }
});

test("Pre-flight: Server readiness", async ({ request }) => {
  // 1. SPS server health
  const health = await request.get("http://localhost:3100/healthz");
  expect(health.ok(), "SPS /healthz failed — server did not start").toBeTruthy();

  // 2. Seed route is available (proves the E2E-only guards are enabled)
  const seed = await request.post("http://localhost:3100/api/v2/auth/test/seed-workspace", {
    headers: {
      "x-blindpass-e2e-seed-token": E2E_SEED_TOKEN
    },
    data: { prefix: "preflight" }
  });
  expect(
    seed.status(),
    `Seed route returned ${seed.status()} — SPS may be missing NODE_ENV=test, ` +
    `SPS_ENABLE_TEST_SEED_ROUTES=1, or a matching SPS_E2E_SEED_TOKEN. ` +
    `Kill stale processes: lsof -ti :3100 | xargs kill -9`
  ).toBe(201);

  // 3. Dashboard Vite server
  const dashboard = await request.get("http://localhost:5173/");
  expect(dashboard.ok(), "Dashboard (port 5173) not responding").toBeTruthy();

  // 4. Browser-UI Vite server
  const browserUi = await request.get("http://localhost:5175/");
  expect(browserUi.ok(), "Browser-UI (port 5175) not responding").toBeTruthy();
});
```

### [MODIFY] [playwright.config.ts](../../../packages/dashboard/playwright.config.ts)

- Register `globalSetup` for the PG connectivity check
- Add setup project for post-server pre-flight checks
- All spec projects depend on setup project
- Add explicit E2E seed-route env vars to the SPS webServer config

```diff
 export default defineConfig({
+  globalSetup: "./e2e/global-setup.ts",
   testDir: "./e2e",
   fullyParallel: false,
   // ...
   projects: [
+    {
+      name: "setup",
+      testMatch: /preflight\.setup\.ts/,
+    },
     {
       name: "chromium",
       use: { ...devices["Desktop Chrome"] },
+      dependencies: ["setup"],
     },
   ],
+  webServer: [
+    // ...
+    {
+      command: "npm run dev",
+      url: "http://localhost:3100/healthz",
+      env: {
+        NODE_ENV: "test",
+        SPS_ENABLE_TEST_SEED_ROUTES: "1",
+        SPS_E2E_SEED_TOKEN: "blindpass-e2e-seed-token",
+      }
+    }
+  ],
```

---

## Phase 4: Migrate All Spec Files

Remove duplicated setup patterns and raw `pg.Client` usage across all specs.

### Files requiring migration:

| File | Changes Needed |
|---|---|
| `approvals.spec.ts` | Replace inline `setupWorkspace` with shared import. Replace 4× `new pg.Client()` with `db` fixture from `fixtures.ts`. |
| `audit.spec.ts` | Replace inline `setupWorkspace` with shared import. Remove manual `pg.Client`. |
| `management.spec.ts` | Already uses shared setup — add missing `prefix` arg to `setupWorkspace(page)` calls. |
| `policy.spec.ts` | Same — add missing `prefix` arg. |
| `routing.spec.ts` | Replace `new Pool()` with `db` fixture. |
| `billing.spec.ts` | Replace `new pg.Pool()` with `db` fixture. |
| `x402.spec.ts` | Replace `new pg.Pool()` with `db` fixture. Adopt the agreed facilitator-port strategy instead of hardcoding `3101` in the spec. |
| `guest-exchange.spec.ts` | Replace `new pg.Pool()` with `db` fixture. Adopt the agreed facilitator-port strategy instead of hardcoding `3101` in the spec. |
| `auth.spec.ts` | **Keep UI-based registration** (this IS what it tests). Fix `data-testid` selector consistency. |
| `locale-persistence.spec.ts` | No changes needed (no setup/DB). |
| `browser-ui-locale.spec.ts` | No changes needed (no setup/DB). |
| `email-locale.spec.ts` | No changes needed (API-only, no UI setup). |
| `analytics.spec.ts` | Already uses shared setup — add missing `prefix` arg if needed. |

---

## Resolved Initial Questions

> [!NOTE]
> **Parallel execution**: Truncating tables in `preflight.setup.ts` cleans the database once at the start of the suite. Because we want a fast 35-test execution run with stable predictability, keeping `fullyParallel: false` is highly recommended. Test speed will improve enough via API-based seeding that parallelization is unnecessary right now.

> [!IMPORTANT]
> **`data-testid` mismatch**: Codebase review confirmed that `Register.tsx` uses `register-submit` and requires checking `register-terms`. `setup.ts` has been silently timing out for 15 seconds consistently because of this mismatch. Removing `setup.ts` UI automation entirely (Phase 1) avoids this class of bugs.

1. **Table list for truncation**: A scan of `.sql` migrations corrected the tables. `agents` is actually `enrolled_agents`; `x402_payment_ledger` does not exist (it's `x402_transactions` and `x402_inflight`); and `guest_payments`, `guest_intents`, and `workspace_policy_documents` were added to the payload. Migrations `013_audit_guest_actor`, `014_guest_agent_delivery_state`, and `017_user_preferred_locale` are all `ALTER TABLE` statements on existing tables (`audit_log`, `guest_intents`, `users`) — no new tables to add. `_migrations` is **never** truncated to avoid re-running migrations on every suite start.

2. **Mock facilitator port deconfliction**: **Decision: keep port 3101 + resilient cleanup.** The SPS server is configured at startup with `SPS_X402_FACILITATOR_URL=http://localhost:3101`, so dynamic ports would require a runtime reconfiguration endpoint — unnecessary complexity for serial execution. Instead, each spec's `beforeAll` will attempt to bind port 3101, and on `EADDRINUSE`, force-kill the stale process before retrying. This handles the only real failure mode (a previous `afterAll` not executing due to timeout).

3. **Additional seed route safeguards**: The seed route will not rely on `NODE_ENV` alone. It must be both explicitly enabled (`SPS_ENABLE_TEST_SEED_ROUTES=1`) and called with a matching `x-blindpass-e2e-seed-token` header backed by `SPS_E2E_SEED_TOKEN`. Missing any guard returns `404`.

4. **Workspace slug collisions**: The seed route appends both `Date.now()` and `crypto.randomBytes(4).toString('hex')` to the slug, making collisions statistically impossible even with parallel workers. `setup.ts` also appends the Playwright worker index (`TEST_WORKER_INDEX`) to the prefix for additional isolation.

5. **ID validation**: `setup.ts` asserts that `workspace_id` and `user_id` match UUID format immediately after the seed API returns. This catches seed route regressions before any spec runs.

---

## Verification Plan

### Automated Tests
1. Run `npm run test:e2e --workspace=packages/dashboard` completely.
2. Verify the **preflight setup project** passes first and produces clear errors if any infra is down.
3. Verify that no tests timeout on `register-button` / `register-submit` selectors.
4. Check total execution time — expect **50%+ reduction** from eliminating UI registrations.
5. Run the suite **twice consecutively** to verify database cleanup works across runs.
6. Verify the database does not exhaust connections by checking PG logs.

### Pre-Flight Validation Matrix

| Check | Where | Fails When |
|---|---|---|
| PG connectivity | `global-setup.ts` | Docker not running (`docker compose up -d`) |
| `_migrations` table exists | `preflight.setup.ts` | DB is completely empty or SPS did not auto-migrate |
| Migration count ≥ 17 | `preflight.setup.ts` | Schema partially applied (warning only) |
| SPS `/healthz` | `preflight.setup.ts` | Server crashed on startup or port conflict |
| Seed route returns 201 | `preflight.setup.ts` | Missing `NODE_ENV=test`, missing `SPS_ENABLE_TEST_SEED_ROUTES=1`, or invalid `SPS_E2E_SEED_TOKEN` |
| Dashboard responds | `preflight.setup.ts` | Vite build error or port 5173 conflict |
| Browser-UI responds | `preflight.setup.ts` | Vite build error or port 5175 conflict |

### Security Verification
- Confirm the seed route returns **404** when `NODE_ENV !== "test"`.
- Confirm the seed route returns **404** when `SPS_ENABLE_TEST_SEED_ROUTES !== "1"`.
- Confirm the seed route returns **404** when `x-blindpass-e2e-seed-token` is missing or incorrect.
- Review Playwright HTML report for zero flaky retries.
