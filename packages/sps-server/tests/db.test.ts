import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { SignJWT } from "jose";
import type { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createDbPool } from "../src/db/index.js";
import { runMigrations } from "../src/db/migrate.js";
import { buildApp } from "../src/index.js";
import { createWorkspace, getWorkspaceBySlug } from "../src/services/workspace.js";

const runPgIntegration = process.env.SPS_PG_INTEGRATION === "1";
const describePg = runPgIntegration ? describe : describe.skip;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const migrationsDir = path.resolve(__dirname, "../src/db/migrations");

let adminPool: Pool | null = null;

function randomSchema(prefix: string): string {
  return `${prefix}_${Math.random().toString(16).slice(2, 10)}`;
}

function withSearchPath(databaseUrl: string, schema: string): string {
  const url = new URL(databaseUrl);
  url.searchParams.set("options", `-c search_path=${schema}`);
  return url.toString();
}

async function createIsolatedPool(): Promise<{ pool: Pool; schema: string }> {
  if (!adminPool) {
    throw new Error("admin pool not initialized");
  }

  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl) {
    throw new Error("DATABASE_URL must be set for PostgreSQL integration tests");
  }

  const schema = randomSchema("sps");
  await adminPool.query(`CREATE SCHEMA "${schema}"`);
  const pool = createDbPool({
    connectionString: withSearchPath(databaseUrl, schema),
    max: 1
  });

  return { pool, schema };
}

async function disposeIsolatedPool(pool: Pool, schema: string): Promise<void> {
  await pool.end();
  await adminPool?.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`);
}

async function signUserToken(workspaceId: string, role: "workspace_admin" | "workspace_operator" | "workspace_viewer") {
  const secret = new TextEncoder().encode("test-user-jwt-secret");
  return new SignJWT({
    email: "owner@example.com",
    workspace_id: workspaceId,
    role
  })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuer("sps")
    .setAudience("sps-user")
    .setSubject("user-1")
    .setExpirationTime("15m")
    .sign(secret);
}

describe("proxy trust", () => {
  it("uses the forwarded client IP when trustProxy is enabled", async () => {
    const app = await buildApp({
      trustProxy: true,
      useInMemoryStore: true,
      hmacSecret: "test-hmac-secret"
    });

    app.get("/__ip", async (req) => ({ ip: req.ip }));

    const response = await app.inject({
      method: "GET",
      url: "/__ip",
      headers: {
        "x-forwarded-for": "203.0.113.10, 10.0.0.5"
      }
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ ip: "203.0.113.10" });

    await app.close();
  });
});

describePg("database foundation", () => {
  beforeAll(() => {
    if (!process.env.DATABASE_URL) {
      throw new Error("DATABASE_URL must be set for PostgreSQL integration tests");
    }

    process.env.SPS_USER_JWT_SECRET = "test-user-jwt-secret";
    adminPool = createDbPool({
      connectionString: process.env.DATABASE_URL,
      max: 1
    });
  });

  afterAll(async () => {
    await adminPool?.end();
    adminPool = null;
  });

  it("connects and runs a simple query", async () => {
    const { pool, schema } = await createIsolatedPool();

    try {
      const result = await pool.query<{ value: number }>("SELECT 1 AS value");
      expect(result.rows[0]?.value).toBe(1);
    } finally {
      await disposeIsolatedPool(pool, schema);
    }
  });

  it("applies migrations idempotently", async () => {
    const { pool, schema } = await createIsolatedPool();

    try {
      const firstRun = await runMigrations(pool, { migrationsDir });
      const secondRun = await runMigrations(pool, { migrationsDir });

      expect(firstRun).toEqual([
        "001_workspaces.sql",
        "002_users.sql",
        "003_user_sessions.sql",
        "004_agents.sql",
        "005_billing.sql",
        "006_audit_log.sql",
        "007_billing_provider.sql",
        "008_x402.sql",
        "009_workspace_policy.sql",
        "010_public_offers.sql",
        "011_guest_intents.sql",
        "012_guest_payments.sql",
        "013_audit_guest_actor.sql",
        "014_guest_agent_delivery_state.sql",
        "015_user_tokens.sql",
        "016_drop_users_verification_token.sql",
        "017_user_preferred_locale.sql"
      ]);
      expect(secondRun).toEqual([]);

      const table = await pool.query<{ regclass: string | null }>("SELECT to_regclass('workspaces') AS regclass");
      expect(table.rows[0]?.regclass).toBe("workspaces");
    } finally {
      await disposeIsolatedPool(pool, schema);
    }
  });

  it("rolls back a failed migration file", async () => {
    const { pool, schema } = await createIsolatedPool();
    const tempDir = await mkdtemp(path.join(os.tmpdir(), "sps-migrations-"));

    try {
      await writeFile(path.join(tempDir, "001_ok.sql"), "CREATE TABLE ok_table (id INT PRIMARY KEY);\n", "utf8");
      await writeFile(
        path.join(tempDir, "002_fail.sql"),
        "CREATE TABLE should_rollback (id INT PRIMARY KEY);\nINSERT INTO missing_table VALUES (1);\n",
        "utf8"
      );

      await expect(runMigrations(pool, { migrationsDir: tempDir })).rejects.toThrow("002_fail.sql");

      const okTable = await pool.query<{ regclass: string | null }>("SELECT to_regclass('ok_table') AS regclass");
      const rolledBackTable = await pool.query<{ regclass: string | null }>("SELECT to_regclass('should_rollback') AS regclass");
      const applied = await pool.query<{ filename: string }>("SELECT filename FROM _migrations ORDER BY filename");

      expect(okTable.rows[0]?.regclass).toBe("ok_table");
      expect(rolledBackTable.rows[0]?.regclass).toBeNull();
      expect(applied.rows.map((row) => row.filename)).toEqual(["001_ok.sql"]);
    } finally {
      await rm(tempDir, { recursive: true, force: true });
      await disposeIsolatedPool(pool, schema);
    }
  });

  it("creates and reads workspaces by slug and enforces unique slugs", async () => {
    const { pool, schema } = await createIsolatedPool();

    try {
      await runMigrations(pool, { migrationsDir });

      const created = await createWorkspace(pool, "acme-inc", "Acme Inc");
      const fetched = await getWorkspaceBySlug(pool, "acme-inc");

      expect(fetched).not.toBeNull();
      expect(fetched?.id).toBe(created.id);
      expect(fetched?.displayName).toBe("Acme Inc");

      await expect(createWorkspace(pool, "acme-inc", "Another Name")).rejects.toMatchObject({
        code: "23505"
      });
    } finally {
      await disposeIsolatedPool(pool, schema);
    }
  });

  it("serves and updates the caller workspace over user JWT auth", async () => {
    const { pool, schema } = await createIsolatedPool();

    try {
      await runMigrations(pool, { migrationsDir });
      const workspace = await createWorkspace(pool, "hosted-acme", "Hosted Acme");
      const token = await signUserToken(workspace.id, "workspace_admin");
      const app = await buildApp({
        db: pool,
        useInMemoryStore: true
      });

      const getResponse = await app.inject({
        method: "GET",
        url: "/api/v2/workspace",
        headers: {
          authorization: `Bearer ${token}`
        }
      });

      expect(getResponse.statusCode).toBe(200);
      expect(getResponse.json()).toMatchObject({
        workspace: {
          id: workspace.id,
          slug: "hosted-acme",
          display_name: "Hosted Acme",
          owner_email_verified: false
        }
      });

      const patchResponse = await app.inject({
        method: "PATCH",
        url: "/api/v2/workspace",
        headers: {
          authorization: `Bearer ${token}`
        },
        payload: {
          display_name: "Hosted Acme Updated"
        }
      });

      expect(patchResponse.statusCode).toBe(200);
      expect(patchResponse.json()).toMatchObject({
        workspace: {
          id: workspace.id,
          display_name: "Hosted Acme Updated",
          owner_email_verified: false
        }
      });

      await app.close();
    } finally {
      await disposeIsolatedPool(pool, schema);
    }
  });
});
