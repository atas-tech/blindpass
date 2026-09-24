import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { Pool } from "pg";
import Redis from "ioredis";
import { startAdapter, withSearchPath } from "../src/adapter.js";

if (process.env.SUT === "ts") {
  describe("P00 adapter isolation", () => {
  const databaseUrl = process.env.CONTRACT_DATABASE_URL || process.env.DATABASE_URL;
  const redisUrl = process.env.CONTRACT_REDIS_URL || process.env.REDIS_URL || "redis://127.0.0.1:6380";
  const redisDb = Number(process.env.CONTRACT_REDIS_DB ?? 15);

  it("P00-I01 drops its schema when Redis setup fails", async () => {
    if (!databaseUrl) throw new Error("P00-I01 requires a disposable PostgreSQL URL");
    const pool = new Pool({ connectionString: databaseUrl });
    const schemas = async () => (await pool.query<{ nspname: string }>(
      "SELECT nspname FROM pg_namespace WHERE nspname LIKE $1 ORDER BY nspname",
      [`contract_${process.pid}_%`]
    )).rows.map((row) => row.nspname);
    const before = await schemas();
    const prior = process.env.CONTRACT_REDIS_URL;
    try {
      process.env.CONTRACT_REDIS_URL = "redis://127.0.0.1:1";
      await expect(startAdapter()).rejects.toThrow();
      const after = await schemas();
      expect(after.every((schema) => before.includes(schema))).toBe(true);
    } finally {
      if (prior === undefined) delete process.env.CONTRACT_REDIS_URL;
      else process.env.CONTRACT_REDIS_URL = prior;
      await pool.end();
    }
  }, 20_000);

  it("P00-I03 configures only the isolated schema in PostgreSQL search_path", async () => {
    if (!databaseUrl) throw new Error("P00-I03 requires a disposable PostgreSQL URL");
    const schema = `contract_path_${process.pid}_${randomBytes(5).toString("hex")}`;
    const publicTable = `contract_public_fallback_${process.pid}_${randomBytes(5).toString("hex")}`;
    const quote = (identifier: string) => `"${identifier.replaceAll('"', '""')}"`;
    const adminPool = new Pool({ connectionString: databaseUrl });
    const isolatedPool = new Pool({ connectionString: withSearchPath(databaseUrl, schema) });
    try {
      await adminPool.query(`CREATE SCHEMA ${quote(schema)}`);
      await adminPool.query(`CREATE TABLE public.${quote(publicTable)} (id integer)`);
      const result = await isolatedPool.query<{ schemas: string[] }>(
        "SELECT current_schemas(false)::text[] AS schemas"
      );
      expect(result.rows[0]?.schemas).toEqual([schema]);
      await expect(isolatedPool.query(`SELECT * FROM ${quote(publicTable)}`))
        .rejects.toMatchObject({ code: "42P01" });
    } finally {
      await isolatedPool.end();
      await adminPool.query(`DROP TABLE IF EXISTS public.${quote(publicTable)}`);
      await adminPool.query(`DROP SCHEMA IF EXISTS ${quote(schema)} CASCADE`);
      await adminPool.end();
    }
  }, 20_000);

  it("P00-I02 sweeps an orphan schema and preserves a concurrently active schema", async () => {
    if (!databaseUrl) throw new Error("P00-I02 requires a disposable PostgreSQL URL");
    const pool = new Pool({ connectionString: databaseUrl });
    const orphanSchema = `contract_orphan_${process.pid}_${randomBytes(5).toString("hex")}`;
    const unmarkedSchema = `contract_unmarked_${process.pid}_${randomBytes(5).toString("hex")}`;
    const quote = (identifier: string) => `"${identifier.replaceAll('"', '""')}"`;
    let first: Awaited<ReturnType<typeof startAdapter>> = null;
    let second: Awaited<ReturnType<typeof startAdapter>> = null;

    try {
      await pool.query("CREATE EXTENSION IF NOT EXISTS pgcrypto");
      await pool.query(`CREATE SCHEMA ${quote(orphanSchema)}`);
      await pool.query(`COMMENT ON SCHEMA ${quote(orphanSchema)} IS 'blindpass-contract-schema:v1:0'`);
      await pool.query(`CREATE SCHEMA ${quote(unmarkedSchema)}`);
      first = await startAdapter();
      expect(first).not.toBeNull();
      const orphan = await pool.query<{ exists: boolean }>(
        "SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = $1) AS exists",
        [orphanSchema]
      );
      expect(orphan.rows[0]?.exists).toBe(false);
      const unmarked = await pool.query<{ exists: boolean }>(
        "SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = $1) AS exists",
        [unmarkedSchema]
      );
      expect(unmarked.rows[0]?.exists).toBe(true);
      const activeSchemas = (await pool.query<{ nspname: string }>(
        "SELECT nspname FROM pg_namespace WHERE left(nspname, length($1)) = $1 ORDER BY nspname",
        [`contract_${process.pid}_`]
      )).rows.map((row) => row.nspname);
      expect(activeSchemas.length).toBeGreaterThan(0);

      second = await startAdapter();
      const afterSecondStart = (await pool.query<{ nspname: string }>(
        "SELECT nspname FROM pg_namespace WHERE left(nspname, length($1)) = $1 ORDER BY nspname",
        [`contract_${process.pid}_`]
      )).rows.map((row) => row.nspname);
      expect(afterSecondStart).toEqual(expect.arrayContaining(activeSchemas));
    } finally {
      await second?.close();
      await first?.close();
      await pool.query(`DROP SCHEMA IF EXISTS ${quote(orphanSchema)} CASCADE`);
      await pool.query(`DROP SCHEMA IF EXISTS ${quote(unmarkedSchema)} CASCADE`);
      await pool.end();
    }
  }, 90_000);

  it("P00-E02 leaves unrelated Redis keys intact", async () => {
    if (!databaseUrl) throw new Error("P00-E02 requires a disposable PostgreSQL URL");
    const url = new URL(redisUrl);
    url.pathname = `/${redisDb}`;
    const redis = new Redis(url.toString());
    const key = `p00-sentinel-${randomBytes(8).toString("hex")}`;
    try {
      await redis.set(key, "outside-adapter", "EX", 60);
      const adapter = await startAdapter();
      try {
        expect(adapter).not.toBeNull();
      } finally {
        await adapter?.close();
      }
      expect(await redis.get(key)).toBe("outside-adapter");
    } finally {
      await redis.del(key);
      await redis.quit();
    }
  }, 30_000);
  });
}

if (process.env.SUT === "rust") {
  describe("P02 Rust adapter isolation", () => {
    it("P02-I07 starts isolated Rust instances with live readiness and the adopted browser-status feature", async () => {
      const first = await startAdapter();
      const second = await startAdapter();
      expect(first).not.toBeNull();
      expect(second).not.toBeNull();
      expect(first?.baseUrl).not.toBe(second?.baseUrl);
      try {
        for (const adapter of [first, second]) {
          const health = await fetch(`${adapter?.baseUrl}/healthz`);
          expect(health.status).toBe(200);
          expect(await health.json()).toEqual({ ok: true });

          const readiness = await fetch(`${adapter?.baseUrl}/readyz`);
          expect(readiness.status).toBe(200);
          expect(await readiness.json()).toEqual({ ok: true, checks: { database: "up" } });

          const capabilities = await fetch(`${adapter?.baseUrl}/api/v3/capabilities`);
          expect(capabilities.status).toBe(200);
          expect(await capabilities.json()).toMatchObject({ features: { browser_status: true } });
        }
      } finally {
        await second?.close();
        await first?.close();
      }
    }, 60_000);
  });
}
