import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { Pool } from "pg";
import { startAdapter, withSearchPath } from "../src/adapter.js";

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
