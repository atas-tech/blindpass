import "dotenv/config";
import { config } from "dotenv";
config({ path: ".env.test" });

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  sendVerificationEmail,
  sendPasswordResetEmail,
  MailerServiceError
} from "../src/services/mailer.js";

describe("MailerService", () => {
  const originalEnv = process.env;

  beforeEach(() => {
    vi.resetModules();
    process.env = { ...originalEnv };
    vi.stubGlobal("fetch", vi.fn());
  });

  afterEach(() => {
    process.env = originalEnv;
    vi.restoreAllMocks();
  });

  it("sends a verification email when RESEND_API_KEY is set", async () => {
    process.env.RESEND_API_KEY = "re_test_key";
    process.env.SPS_EMAIL_FROM = "verify@blindpass.test";
    process.env.SPS_BASE_URL = "https://sps.test";

    const fetchMock = vi.mocked(fetch);
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({ id: "123" }), { status: 200 }));

    const result = await sendVerificationEmail("user@example.com", "ver_token");

    expect(result).toEqual({
      mode: "sent",
      provider: "resend"
    });

    expect(fetchMock).toHaveBeenCalledWith("https://api.resend.com/emails", expect.objectContaining({
      method: "POST",
      headers: {
        authorization: "Bearer re_test_key",
        "content-type": "application/json"
      }
    }));

    const lastCall = fetchMock.mock.calls.at(-1)!;
    const body = JSON.parse(lastCall[1]!.body as string);
    expect(body).toMatchObject({
      from: "verify@blindpass.test",
      to: ["user@example.com"],
      subject: "Verify your email address",
      text: expect.stringContaining("https://sps.test/api/v2/auth/verify-email/ver_token")
    });
    expect(body.html).toContain("https://sps.test/api/v2/auth/verify-email/ver_token");
    expect(body.html).toContain('<html lang="en">');
    expect(body.html).toContain("Email Verification");
    expect(body.text).toContain("Hello,");
  });

  it("sends a password reset email when RESEND_API_KEY is set", async () => {
    process.env.RESEND_API_KEY = "re_test_key";
    process.env.SPS_EMAIL_FROM = "verify@blindpass.test";
    process.env.SPS_UI_BASE_URL = "https://app.test";

    const fetchMock = vi.mocked(fetch);
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({ id: "123" }), { status: 200 }));

    const result = await sendPasswordResetEmail("user@example.com", "rst_token");

    expect(result).toEqual({
      mode: "sent",
      provider: "resend"
    });

    expect(fetchMock).toHaveBeenCalledWith("https://api.resend.com/emails", expect.objectContaining({
      method: "POST",
      headers: {
        authorization: "Bearer re_test_key",
        "content-type": "application/json"
      }
    }));

    const lastCall = fetchMock.mock.calls.at(-1)!;
    const body = JSON.parse(lastCall[1]!.body as string);
    expect(body).toMatchObject({
      from: "verify@blindpass.test",
      to: ["user@example.com"],
      subject: "Reset your password",
      text: expect.stringContaining("https://app.test/reset-password?token=rst_token")
    });
    expect(body.html).toContain("https://app.test/reset-password?token=rst_token");
    expect(body.html).toContain('<html lang="en">');
    expect(body.html).toContain("Password Reset");
    expect(body.text).toContain("Hello,");
  });

  it("renders verification email copy in Vietnamese when locale is vi", async () => {
    process.env.RESEND_API_KEY = "re_test_key";
    process.env.SPS_EMAIL_FROM = "verify@blindpass.test";
    process.env.SPS_BASE_URL = "https://sps.test";

    const fetchMock = vi.mocked(fetch);
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({ id: "123" }), { status: 200 }));

    await sendVerificationEmail("user@example.com", "ver_token", "vi");

    const lastCall = fetchMock.mock.calls.at(-1)!;
    const body = JSON.parse(lastCall[1]!.body as string);

    expect(body.subject).toBe("Xác minh địa chỉ email của bạn");
    expect(body.html).toContain('<html lang="vi">');
    expect(body.html).toContain("Xác minh email");
    expect(body.html).toContain("Liên kết này sẽ hết hạn sau 1 ngày.");
    expect(body.text).toContain("Xin chào,");
  });

  it("renders password reset copy in Vietnamese when locale is vi", async () => {
    process.env.RESEND_API_KEY = "re_test_key";
    process.env.SPS_EMAIL_FROM = "verify@blindpass.test";
    process.env.SPS_UI_BASE_URL = "https://app.test";

    const fetchMock = vi.mocked(fetch);
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({ id: "123" }), { status: 200 }));

    await sendPasswordResetEmail("user@example.com", "rst_token", "vi");

    const lastCall = fetchMock.mock.calls.at(-1)!;
    const body = JSON.parse(lastCall[1]!.body as string);

    expect(body.subject).toBe("Đặt lại mật khẩu của bạn");
    expect(body.html).toContain('<html lang="vi">');
    expect(body.html).toContain("Đặt lại mật khẩu");
    expect(body.html).toContain("Liên kết này sẽ hết hạn sau 1 giờ.");
    expect(body.text).toContain("Xin chào,");
  });

  it("falls back to local log when RESEND_API_KEY is missing (non-production)", async () => {
    delete process.env.RESEND_API_KEY;
    process.env.NODE_ENV = "test";
    process.env.SPS_LOG_VERIFICATION_URLS = "1";

    const infoSpy = vi.spyOn(console, "info").mockImplementation(() => {});
    const result = await sendVerificationEmail("user@example.com", "ver_token");

    expect(result).toEqual({
      mode: "logged",
      provider: "local-log"
    });
    expect(infoSpy).toHaveBeenCalledWith(expect.stringContaining("user@example.com"));
    expect(infoSpy).toHaveBeenCalledWith(expect.stringContaining("ver_token"));
  });

  it("throws misconfigured error in production when RESEND_API_KEY is missing", async () => {
    delete process.env.RESEND_API_KEY;
    process.env.NODE_ENV = "production";

    await expect(sendVerificationEmail("user@example.com", "ver_token"))
      .rejects.toThrow("Transactional email is not configured for this environment");
  });

  it("handles 429 rate limits as retryable error", async () => {
    process.env.RESEND_API_KEY = "re_test_key";
    process.env.SPS_EMAIL_FROM = "verify@blindpass.test";

    const fetchMock = vi.mocked(fetch);
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({ error: "too many requests" }), { status: 429 }));

    try {
      await sendVerificationEmail("user@example.com", "ver_token");
      throw new Error("Should have thrown");
    } catch (error) {
      expect(error).toBeInstanceOf(MailerServiceError);
      const mailerError = error as MailerServiceError;
      expect(mailerError.statusCode).toBe(503);
      expect(mailerError.code).toBe("mailer_unavailable");
      expect(mailerError.retryable).toBe(true);
    }
  });

  it("handles 400 bad request as fatal error", async () => {
    process.env.RESEND_API_KEY = "re_test_key";
    process.env.SPS_EMAIL_FROM = "verify@blindpass.test";

    const fetchMock = vi.mocked(fetch);
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({ error: "invalid bounce" }), { status: 400 }));

    try {
      await sendVerificationEmail("user@example.com", "ver_token");
      throw new Error("Should have thrown");
    } catch (error) {
      expect(error).toBeInstanceOf(MailerServiceError);
      const mailerError = error as MailerServiceError;
      expect(mailerError.statusCode).toBe(502);
      expect(mailerError.code).toBe("mailer_rejected");
      expect(mailerError.retryable).toBe(false);
    }
  });

  it("handles network failure as retryable error", async () => {
    process.env.RESEND_API_KEY = "re_test_key";
    process.env.SPS_EMAIL_FROM = "verify@blindpass.test";

    const fetchMock = vi.mocked(fetch);
    fetchMock.mockRejectedValueOnce(new Error("Network Error"));

    try {
      await sendVerificationEmail("user@example.com", "ver_token");
      throw new Error("Should have thrown");
    } catch (error) {
      expect(error).toBeInstanceOf(MailerServiceError);
      const mailerError = error as MailerServiceError;
      expect(mailerError.statusCode).toBe(503);
      expect(mailerError.code).toBe("mailer_unavailable");
      expect(mailerError.retryable).toBe(true);
    }
  });
});
