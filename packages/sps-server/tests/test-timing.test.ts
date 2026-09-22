import { afterEach, describe, expect, it } from "vitest";
import { buildApp } from "../src/index.js";

const OVERRIDE_NAMES = [
  "SPS_TEST_REQUEST_TTL_SECONDS",
  "SPS_TEST_SUBMITTED_TTL_SECONDS",
  "SPS_TEST_REVOKED_TTL_SECONDS",
  "SPS_TEST_APPROVAL_TTL_SECONDS",
  "SPS_TEST_RATE_LIMIT_WINDOW_MS",
  "SPS_TEST_AGENT_TOKEN_RATE_WINDOW_MS",
  "SPS_TEST_WORKSPACE_BURST_WINDOW_MS",
  "SPS_TEST_WORKSPACE_THROTTLE_WINDOW_MS",
  "SPS_TEST_REFRESH_TOKEN_TTL_SECONDS",
  "SPS_TEST_ACCESS_TOKEN_TTL_SECONDS"
] as const;

const originalNodeEnv = process.env.NODE_ENV;
const originalValues = new Map(OVERRIDE_NAMES.map((name) => [name, process.env[name]]));

afterEach(() => {
  process.env.NODE_ENV = originalNodeEnv;
  for (const name of OVERRIDE_NAMES) {
    const value = originalValues.get(name);
    if (value === undefined) {
      delete process.env[name];
    } else {
      process.env[name] = value;
    }
  }
});

describe("test-only timing controls", () => {
  it("accepts overrides only in NODE_ENV=test", async () => {
    process.env.NODE_ENV = "test";
    process.env.SPS_TEST_REQUEST_TTL_SECONDS = "2";
    process.env.SPS_TEST_SUBMITTED_TTL_SECONDS = "3";
    process.env.SPS_TEST_REVOKED_TTL_SECONDS = "4";
    process.env.SPS_TEST_APPROVAL_TTL_SECONDS = "5";

    const app = await buildApp({ useInMemoryStore: true, hmacSecret: "timing-test-secret" });
    const response = await app.inject({ method: "GET", url: "/readyz" });
    expect(response.statusCode).toBe(200);
    await app.close();
  });

  it("fails closed when a test override is present outside test mode", async () => {
    process.env.NODE_ENV = "production";
    process.env.SPS_TEST_REQUEST_TTL_SECONDS = "2";

    await expect(buildApp({ useInMemoryStore: true, hmacSecret: "timing-test-secret" })).rejects.toThrow(
      "Test-only timing overrides are disabled"
    );
  });

  it("rejects malformed override values", async () => {
    process.env.NODE_ENV = "test";
    process.env.SPS_TEST_REQUEST_TTL_SECONDS = "not-a-duration";

    await expect(buildApp({ useInMemoryStore: true, hmacSecret: "timing-test-secret" })).rejects.toThrow(
      "SPS_TEST_REQUEST_TTL_SECONDS must be a positive integer"
    );
  });
});
