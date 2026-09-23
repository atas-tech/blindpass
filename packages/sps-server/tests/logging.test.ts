import { afterEach, describe, expect, it, vi } from "vitest";
import { logAudit } from "../src/services/audit.js";
import { logVerificationUrl } from "../src/services/user.js";
import { requestLogSummary } from "../src/utils/request-logging.js";

const originalNodeEnv = process.env.NODE_ENV;
const originalAuditFlag = process.env.SPS_LOG_AUDIT_EVENTS;
const originalVerificationFlag = process.env.SPS_LOG_VERIFICATION_URLS;
const originalBaseUrl = process.env.SPS_BASE_URL;

afterEach(() => {
  process.env.NODE_ENV = originalNodeEnv;
  process.env.SPS_LOG_AUDIT_EVENTS = originalAuditFlag;
  process.env.SPS_LOG_VERIFICATION_URLS = originalVerificationFlag;
  process.env.SPS_BASE_URL = originalBaseUrl;
  vi.restoreAllMocks();
});

describe("sensitive logging defaults", () => {
  it("does not put signed query strings or path tokens in request logs", () => {
    const summary = requestLogSummary({
      method: "GET",
      routeOptions: { url: "/api/v2/secret/metadata/:id" },
      url: "/api/v2/secret/metadata/secret-id?sig=live-link-canary"
    } as Parameters<typeof requestLogSummary>[0]);
    expect(summary).toEqual({ method: "GET", route: "/api/v2/secret/metadata/:id" });
    expect(JSON.stringify(summary)).not.toContain("live-link-canary");
    expect(JSON.stringify(summary)).not.toContain("secret-id");
  });
  it("suppresses audit payload logging unless explicitly enabled", async () => {
    delete process.env.SPS_LOG_AUDIT_EVENTS;
    const info = vi.spyOn(console, "info").mockImplementation(() => {});

    await logAudit(null, {
      event: "exchange_requested",
      exchangeId: "exchange-123",
      requestId: "request-456",
      workspaceId: "workspace-789",
      secretName: "prod-api-key",
      approvalReference: "approval-999",
      action: "requested",
      ip: "10.0.0.1",
      metadata: { reviewer: "alice@example.com" }
    });

    expect(info).not.toHaveBeenCalled();
  });

  it("logs only redacted audit summaries when enabled", async () => {
    process.env.SPS_LOG_AUDIT_EVENTS = "1";
    const info = vi.spyOn(console, "info").mockImplementation(() => {});

    await logAudit(null, {
      event: "exchange_requested",
      exchangeId: "exchange-123",
      requestId: "request-456",
      workspaceId: "workspace-789",
      secretName: "prod-api-key",
      approvalReference: "approval-999",
      action: "requested",
      ip: "10.0.0.1",
      metadata: { reviewer: "alice@example.com" }
    });

    expect(info).toHaveBeenCalledTimes(1);
    const message = info.mock.calls[0]?.[0];
    expect(typeof message).toBe("string");
    expect(message).not.toContain("exchange-123");
    expect(message).not.toContain("request-456");
    expect(message).not.toContain("workspace-789");
    expect(message).not.toContain("prod-api-key");
    expect(message).not.toContain("approval-999");
    expect(message).not.toContain("10.0.0.1");
    expect(message).not.toContain("alice@example.com");
    expect(JSON.parse(message as string)).toMatchObject({
      event: "exchange_requested",
      action: "requested",
      resource_kind: "exchange",
      has_metadata: true
    });
  });

  it("does not print verification URLs unless explicitly enabled", () => {
    process.env.NODE_ENV = "development";
    delete process.env.SPS_LOG_VERIFICATION_URLS;
    process.env.SPS_BASE_URL = "https://sps.example.com";
    const info = vi.spyOn(console, "info").mockImplementation(() => {});

    logVerificationUrl("owner@example.com", "verify-token-123");

    expect(info).toHaveBeenCalledTimes(1);
    const message = info.mock.calls[0]?.[0];
    expect(message).toContain("Email verification issued for owner@example.com.");
    expect(message).toContain("SPS_LOG_VERIFICATION_URLS=1");
    expect(message).not.toContain("verify-token-123");
    expect(message).not.toContain("https://sps.example.com");
  });

  it("prints verification URLs only with explicit local opt-in", () => {
    process.env.NODE_ENV = "development";
    process.env.SPS_LOG_VERIFICATION_URLS = "1";
    process.env.SPS_BASE_URL = "https://sps.example.com";
    const info = vi.spyOn(console, "info").mockImplementation(() => {});

    logVerificationUrl("owner@example.com", "verify-token-123");

    expect(info).toHaveBeenCalledWith(
      "Email verification URL for owner@example.com: https://sps.example.com/api/v2/auth/verify-email/verify-token-123"
    );
  });
});
