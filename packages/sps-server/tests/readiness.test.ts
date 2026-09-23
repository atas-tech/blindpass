import { afterEach, describe, expect, it } from "vitest";
import { InMemoryRequestStore } from "../src/services/redis.js";
import { buildApp } from "../src/index.js";

const priorNodeEnv = process.env.NODE_ENV;

afterEach(() => {
  if (priorNodeEnv === undefined) delete process.env.NODE_ENV;
  else process.env.NODE_ENV = priorNodeEnv;
});

describe("readiness route", () => {
  it("returns 503 when configured database and Redis checks fail", async () => {
    process.env.NODE_ENV = "test";
    const app = await buildApp({
      store: new InMemoryRequestStore(),
      useInMemoryStore: true,
      hmacSecret: "readiness-test-only-secret",
      readinessChecks: {
        db: async () => { throw new Error("database unavailable"); },
        redis: async () => { throw new Error("redis unavailable"); }
      }
    });

    try {
      const response = await app.inject({ method: "GET", url: "/readyz" });
      expect(response.statusCode).toBe(503);
      expect(response.json()).toEqual({
        ok: false,
        code: "service_unavailable",
        checks: { database: "down", redis: "down" }
      });
    } finally {
      await app.close();
    }
  });
});
