import type { Pool } from "pg";
import { afterEach, describe, expect, it } from "vitest";
import { InMemoryRequestStore } from "../src/services/redis.js";
import { buildApp } from "../src/index.js";

const ENV_NAMES = [
  "NODE_ENV",
  "SPS_HMAC_SECRET",
  "SPS_USER_JWT_SECRET",
  "SPS_AGENT_JWT_SECRET",
  "SPS_HOSTED_MODE",
  "SPS_BILLING_MOCK",
  "SPS_USE_IN_MEMORY",
  "SPS_ENABLE_TEST_SEED_ROUTES",
  "SPS_E2E_SEED_TOKEN",
  "SPS_TEST_REQUEST_TTL_SECONDS",
  "SPS_TEST_SUBMITTED_TTL_SECONDS",
  "SPS_TEST_REVOKED_TTL_SECONDS",
  "SPS_TEST_APPROVAL_TTL_SECONDS",
  "SPS_TEST_RATE_LIMIT_WINDOW_MS",
  "SPS_TEST_LONG_RATE_LIMIT_WINDOW_MS",
  "SPS_TEST_AGENT_TOKEN_RATE_WINDOW_MS",
  "SPS_TEST_WORKSPACE_BURST_WINDOW_MS",
  "SPS_TEST_WORKSPACE_THROTTLE_WINDOW_MS",
  "SPS_TEST_REFRESH_TOKEN_TTL_SECONDS",
  "SPS_TEST_ACCESS_TOKEN_TTL_SECONDS"
] as const;

const originalEnvironment = new Map(ENV_NAMES.map((name) => [name, process.env[name]]));

afterEach(() => {
  for (const name of ENV_NAMES) {
    const value = originalEnvironment.get(name);
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
});

describe("production test-seed route guard", () => {
  it("returns 404 when seed-route environment flags are enabled in production", async () => {
    process.env.NODE_ENV = "production";
    process.env.SPS_HMAC_SECRET = "production-guard-hmac";
    process.env.SPS_USER_JWT_SECRET = "production-guard-user-jwt";
    process.env.SPS_AGENT_JWT_SECRET = "production-guard-agent-jwt";
    process.env.SPS_HOSTED_MODE = "";
    process.env.SPS_BILLING_MOCK = "1";
    process.env.SPS_USE_IN_MEMORY = "0";
    process.env.SPS_ENABLE_TEST_SEED_ROUTES = "1";
    process.env.SPS_E2E_SEED_TOKEN = "production-guard-seed-canary";
    for (const name of ENV_NAMES) {
      if (name.startsWith("SPS_TEST_")) delete process.env[name];
    }

    const db = { query: async () => ({ rows: [] }) } as unknown as Pool;
    const app = await buildApp({
      db,
      store: new InMemoryRequestStore(),
      hmacSecret: "production-guard-hmac",
      corsAllowedOrigins: ["https://seed-guard.test"]
    });

    try {
      const response = await app.inject({
        method: "POST",
        url: "/api/v2/auth/test/seed-workspace",
        headers: { "x-blindpass-e2e-seed-token": "production-guard-seed-canary" },
        payload: { prefix: "production-guard" }
      });
      expect(response.statusCode).toBe(404);
    } finally {
      await app.close();
    }
  });
});
