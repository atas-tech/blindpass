import crypto from "node:crypto";
import type { FastifyInstance, FastifyPluginOptions, FastifyReply, FastifyRequest } from "fastify";
import { DEFAULT_LOCALE, type SupportedLocale } from "@blindpass/i18n";
import type { Pool } from "pg";
import { requireUserAuth, type AuthenticatedUserClaims } from "../middleware/auth.js";
import { rateLimitKeyByIp, sendRateLimited, type RateLimitService } from "../middleware/rate-limit.js";
import {
  authenticateUser,
  changePassword,
  getUserContext,
  logoutSession,
  requestPasswordReset,
  refreshSession,
  registerUser,
  resetPasswordWithToken,
  retriggerEmailVerification,
  updateUserPreferredLocale,
  UserServiceError,
  verifyEmail
} from "../services/user.js";
import { MailerServiceError } from "../services/mailer.js";
import { TurnstileServiceError, verifyTurnstileToken } from "../services/turnstile.js";
import type { AuthResult, UserRecord } from "../services/user.js";
import type { WorkspaceRecord } from "../services/workspace.js";
import { enrollAgent } from "../services/agent.js";
import { longRateLimitWindowMs, rateLimitWindowMs } from "../utils/test-timing.js";

export interface AuthRoutesOptions extends FastifyPluginOptions {
  db: Pool;
  rateLimitService?: RateLimitService;
}

const REFRESH_COOKIE_NAME = "sps_refresh_token";
const REFRESH_COOKIE_PATH = "/api/v2/auth";

function isHostedModeEnabled(): boolean {
  const raw = process.env.SPS_HOSTED_MODE?.trim().toLowerCase();
  return raw === "1" || raw === "true" || raw === "yes";
}

function isProductionEnv(): boolean {
  return process.env.NODE_ENV === "production";
}

function parseCookies(header: string | undefined): Record<string, string> {
  if (!header) {
    return {};
  }

  const cookies: Record<string, string> = {};
  for (const entry of header.split(";")) {
    const separatorIndex = entry.indexOf("=");
    if (separatorIndex <= 0) {
      continue;
    }

    const key = entry.slice(0, separatorIndex).trim();
    const value = entry.slice(separatorIndex + 1).trim();
    if (!key) {
      continue;
    }

    cookies[key] = decodeURIComponent(value);
  }

  return cookies;
}

function requestIsHttps(req: FastifyRequest): boolean {
  if (req.protocol === "https") {
    return true;
  }

  const forwardedProto = req.headers["x-forwarded-proto"];
  if (Array.isArray(forwardedProto)) {
    return forwardedProto.some((value) => value.includes("https"));
  }

  return typeof forwardedProto === "string" && forwardedProto.includes("https");
}

function shouldUseSecureCookies(req: FastifyRequest): boolean {
  return isProductionEnv() || requestIsHttps(req);
}

function authCookieDomain(): string | null {
  const domain = process.env.SPS_AUTH_COOKIE_DOMAIN?.trim();
  return domain ? domain : null;
}

function serializeCookie(name: string, value: string, attributes: {
  path: string;
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: "Strict" | "Lax" | "None";
  domain?: string | null;
  expires?: Date;
  maxAge?: number;
}): string {
  const parts = [`${name}=${encodeURIComponent(value)}`];
  parts.push(`Path=${attributes.path}`);

  if (attributes.domain) {
    parts.push(`Domain=${attributes.domain}`);
  }

  if (attributes.expires) {
    parts.push(`Expires=${attributes.expires.toUTCString()}`);
  }

  if (typeof attributes.maxAge === "number") {
    parts.push(`Max-Age=${Math.max(0, Math.floor(attributes.maxAge))}`);
  }

  if (attributes.httpOnly) {
    parts.push("HttpOnly");
  }

  if (attributes.secure) {
    parts.push("Secure");
  }

  if (attributes.sameSite) {
    parts.push(`SameSite=${attributes.sameSite}`);
  }

  return parts.join("; ");
}

function setRefreshTokenCookie(req: FastifyRequest, reply: FastifyReply, token: string, expiresAtEpochSeconds: number): void {
  if (isHostedModeEnabled() && isProductionEnv() && !shouldUseSecureCookies(req)) {
    throw new UserServiceError(500, "insecure_cookie_config", "Hosted auth requires HTTPS for refresh cookies");
  }

  const maxAge = Math.max(0, expiresAtEpochSeconds - Math.floor(Date.now() / 1000));
  reply.header("Set-Cookie", serializeCookie(REFRESH_COOKIE_NAME, token, {
    path: REFRESH_COOKIE_PATH,
    domain: authCookieDomain(),
    expires: new Date(expiresAtEpochSeconds * 1000),
    maxAge,
    httpOnly: true,
    sameSite: "Lax",
    secure: shouldUseSecureCookies(req)
  }));
}

function clearRefreshTokenCookie(req: FastifyRequest, reply: FastifyReply): void {
  reply.header("Set-Cookie", serializeCookie(REFRESH_COOKIE_NAME, "", {
    path: REFRESH_COOKIE_PATH,
    domain: authCookieDomain(),
    expires: new Date(0),
    maxAge: 0,
    httpOnly: true,
    sameSite: "Lax",
    secure: shouldUseSecureCookies(req)
  }));
}

function getRefreshTokenFromRequest(req: FastifyRequest): string | null {
  // Check body first - this is more reliable for our E2E cross-origin token injection
  if (req.body && typeof req.body === "object" && "refresh_token" in req.body) {
    const refreshToken = (req.body as { refresh_token?: unknown }).refresh_token;
    if (typeof refreshToken === "string" && refreshToken.trim()) {
      return refreshToken;
    }
  }

  const cookieHeader = req.headers.cookie;
  const normalizedCookieHeader = Array.isArray(cookieHeader) ? cookieHeader.join("; ") : cookieHeader;
  const cookieToken = parseCookies(normalizedCookieHeader)[REFRESH_COOKIE_NAME];
  if (cookieToken) {
    return cookieToken;
  }

  return null;
}

function userAgentFromHeaders(header: string | string[] | undefined): string | null {
  if (Array.isArray(header)) {
    return header[0] ?? null;
  }

  return header ?? null;
}

function toUserResponse(user: UserRecord) {
  return {
    id: user.id,
    email: user.email,
    role: user.role,
    status: user.status,
    email_verified: user.emailVerified,
    preferred_locale: user.preferredLocale,
    force_password_change: user.forcePasswordChange,
    workspace_id: user.workspaceId,
    created_at: user.createdAt.toISOString(),
    updated_at: user.updatedAt.toISOString()
  };
}

function toWorkspaceResponse(workspace: WorkspaceRecord) {
  return {
    id: workspace.id,
    slug: workspace.slug,
    display_name: workspace.displayName,
    tier: workspace.tier,
    status: workspace.status,
    owner_user_id: workspace.ownerUserId,
    created_at: workspace.createdAt.toISOString(),
    updated_at: workspace.updatedAt.toISOString()
  };
}

function sessionContextForRequest(ip: string, userAgent: string | null) {
  return {
    ipAddress: ip,
    userAgent
  };
}

function preferredLocaleFromHeader(header: string | string[] | undefined): SupportedLocale {
  const raw = Array.isArray(header) ? header[0] : header;
  if (!raw) {
    return DEFAULT_LOCALE;
  }

  const primary = raw.split(",")[0]?.split(";")[0]?.trim().toLowerCase();
  if (!primary) {
    return DEFAULT_LOCALE;
  }

  if (primary === "vi" || primary.startsWith("vi-")) {
    return "vi";
  }

  return "en";
}

function buildAuthResponse(
  req: FastifyRequest,
  reply: FastifyReply,
  result: AuthResult
) {
  const payload = {
    access_token: result.tokens.accessToken,
    access_token_expires_at: result.tokens.accessTokenExpiresAt,
    refresh_token_expires_at: result.tokens.refreshTokenExpiresAt,
    user: toUserResponse(result.user),
    workspace: toWorkspaceResponse(result.workspace)
  } as {
    access_token: string;
    access_token_expires_at: number;
    refresh_token?: string;
    refresh_token_expires_at: number;
    user: ReturnType<typeof toUserResponse>;
    workspace: ReturnType<typeof toWorkspaceResponse>;
    verification_email_delivery?: AuthResult["verificationEmailDelivery"];
  };

  if (isHostedModeEnabled()) {
    setRefreshTokenCookie(req, reply, result.tokens.refreshToken, result.tokens.refreshTokenExpiresAt);
    payload.verification_email_delivery = result.verificationEmailDelivery;
    if (process.env.NODE_ENV === "test") {
      payload.refresh_token = result.tokens.refreshToken;
    }
    return payload;
  }

  payload.refresh_token = result.tokens.refreshToken;
  payload.verification_email_delivery = result.verificationEmailDelivery;
  return payload;
}

function sendServiceError(reply: FastifyReply, error: unknown) {
  if (error instanceof UserServiceError) {
    return reply.code(error.statusCode).send({ error: error.message, code: error.code });
  }

  if (error instanceof MailerServiceError) {
    return reply.code(error.statusCode).send({ error: error.message, code: error.code, retryable: error.retryable });
  }

  if (error instanceof TurnstileServiceError) {
    return reply.code(error.statusCode).send({ error: error.message, code: error.code });
  }

  if (error instanceof Error && (
    error.message.includes("slug") ||
    error.message.includes("displayName") ||
    error.message.includes("blank")
  )) {
    return reply.code(400).send({ error: error.message, code: "invalid_input" });
  }

  throw error;
}

async function requireCurrentUser(req: FastifyRequest, reply: FastifyReply): Promise<AuthenticatedUserClaims | null> {
  return requireUserAuth(req, reply, { allowForcePasswordChange: true });
}

function authRateLimitFromEnv(name: string, fallback: number): number {
  const raw = Number.parseInt(process.env[name] ?? "", 10);
  if (!Number.isFinite(raw) || raw <= 0) {
    return fallback;
  }

  return raw;
}

function authDurationFromEnv(name: string, fallbackMs: number): number {
  const raw = Number.parseInt(process.env[name] ?? "", 10);
  if (!Number.isFinite(raw) || raw < 0) {
    return fallbackMs;
  }

  return raw;
}

async function enforceIpRateLimit(
  req: FastifyRequest,
  reply: FastifyReply,
  service: RateLimitService | undefined,
  key: string,
  limit: number,
  windowMs: number,
  message: string
): Promise<boolean> {
  if (!service) {
    return true;
  }

  const rateLimit = await service.consume(rateLimitKeyByIp(req, key), limit, windowMs);
  if (rateLimit.allowed) {
    return true;
  }

  await sendRateLimited(reply, rateLimit, message);
  return false;
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

async function withMinimumDuration<T>(fn: () => Promise<T>, minimumMs: number): Promise<T> {
  const startedAt = Date.now();
  try {
    return await fn();
  } finally {
    const elapsed = Date.now() - startedAt;
    if (elapsed < minimumMs) {
      await delay(minimumMs - elapsed);
    }
  }
}

function forgotPasswordMinimumResponseMs(): number {
  return authDurationFromEnv("SPS_AUTH_MIN_RESET_RESPONSE_MS", 300);
}

export async function registerAuthRoutes(app: FastifyInstance, opts: AuthRoutesOptions): Promise<void> {
  app.post<{ Body: { email: string; password: string; workspace_slug: string; display_name: string; preferred_locale?: SupportedLocale; cf_turnstile_response?: string } }>(
    "/register",
    {
      schema: {
        body: {
          type: "object",
          nullable: true,
          additionalProperties: false,
          required: ["email", "password", "workspace_slug", "display_name"],
          properties: {
            email: { type: "string", minLength: 3, maxLength: 320 },
            password: { type: "string", minLength: 8, maxLength: 200 },
            workspace_slug: { type: "string", minLength: 3, maxLength: 40 },
            display_name: { type: "string", minLength: 1, maxLength: 160 },
            preferred_locale: { type: "string", enum: ["en", "vi"] },
            cf_turnstile_response: { type: "string", minLength: 1, maxLength: 4096 }
          }
        }
      }
    },
    async (req, reply) => {
      if (!await enforceIpRateLimit(
        req,
        reply,
        opts.rateLimitService,
        "auth:register",
        authRateLimitFromEnv("SPS_AUTH_REGISTRATION_LIMIT", 3),
        rateLimitWindowMs(),
        "Too many registration attempts"
      )) {
        return;
      }

      try {
        await verifyTurnstileToken(req.body?.cf_turnstile_response, req.ip);
        const result = await registerUser(
          opts.db,
          req.body.email,
          req.body.password,
          req.body.workspace_slug,
          req.body.display_name,
          req.body.preferred_locale ?? preferredLocaleFromHeader(req.headers["accept-language"]),
          sessionContextForRequest(req.ip, userAgentFromHeaders(req.headers["user-agent"]))
        );

        return reply.code(201).send(buildAuthResponse(req, reply, result));
      } catch (error) {
        return sendServiceError(reply, error);
      }
    }
  );

  app.post<{ Body: { email: string; password: string; cf_turnstile_response?: string } }>(
    "/login",
    {
      schema: {
        body: {
          type: "object",
          nullable: true,
          additionalProperties: false,
          required: ["email", "password"],
          properties: {
            email: { type: "string", minLength: 3, maxLength: 320 },
            password: { type: "string", minLength: 1, maxLength: 200 },
            cf_turnstile_response: { type: "string", minLength: 1, maxLength: 4096 }
          }
        }
      }
    },
    async (req, reply) => {
      if (!await enforceIpRateLimit(
        req,
        reply,
        opts.rateLimitService,
        "auth:login",
        authRateLimitFromEnv("SPS_AUTH_LOGIN_LIMIT", 10),
        rateLimitWindowMs(),
        "Too many login attempts"
      )) {
        return;
      }

      try {
        await verifyTurnstileToken(req.body?.cf_turnstile_response, req.ip);
        const result = await authenticateUser(
          opts.db,
          req.body.email,
          req.body.password,
          sessionContextForRequest(req.ip, userAgentFromHeaders(req.headers["user-agent"]))
        );

        return reply.send(buildAuthResponse(req, reply, result));
      } catch (error) {
        return sendServiceError(reply, error);
      }
    }
  );

  app.post<{ Body: { refresh_token?: string } }>(
    "/refresh",
    {
      schema: {
        body: {
          type: "object",
          nullable: true,
          additionalProperties: false,
          properties: {
            refresh_token: { type: "string", minLength: 20, maxLength: 4096 }
          }
        }
      }
    },
    async (req, reply) => {
      try {
        const refreshToken = getRefreshTokenFromRequest(req);
        if (!refreshToken) {
          clearRefreshTokenCookie(req, reply);
          return reply.code(401).send({ error: "Invalid refresh token", code: "invalid_refresh_token" });
        }

        const result = await refreshSession(
          opts.db,
          refreshToken,
          sessionContextForRequest(req.ip, userAgentFromHeaders(req.headers["user-agent"]))
        );

        return reply.send(buildAuthResponse(req, reply, result));
      } catch (error) {
        if (error instanceof UserServiceError && error.code === "invalid_refresh_token") {
          clearRefreshTokenCookie(req, reply);
        }
        return sendServiceError(reply, error);
      }
    }
  );

  app.post("/logout", async (req, reply) => {
    const currentUser = await requireCurrentUser(req, reply);
    if (!currentUser) {
      clearRefreshTokenCookie(req, reply);
      return;
    }

    if (!currentUser.sid) {
      clearRefreshTokenCookie(req, reply);
      return reply.code(401).send({ error: "Session id missing from token", code: "invalid_token" });
    }

    await logoutSession(opts.db, currentUser.sub, currentUser.workspaceId, currentUser.sid);
    clearRefreshTokenCookie(req, reply);
    return reply.code(204).send();
  });

  app.post<{ Body: { current_password: string; next_password: string } }>(
    "/change-password",
    {
      schema: {
        body: {
          type: "object",
          nullable: true,
          additionalProperties: false,
          required: ["current_password", "next_password"],
          properties: {
            current_password: { type: "string", minLength: 1, maxLength: 200 },
            next_password: { type: "string", minLength: 8, maxLength: 200 }
          }
        }
      }
    },
    async (req, reply) => {
      const currentUser = await requireCurrentUser(req, reply);
      if (!currentUser) {
        return;
      }

      if (!currentUser.sid) {
        return reply.code(401).send({ error: "Session id missing from token", code: "invalid_token" });
      }

      try {
        const result = await changePassword(
          opts.db,
          currentUser.sub,
          currentUser.workspaceId,
          req.body.current_password,
          req.body.next_password,
          currentUser.sid
        );

        return reply.send({
          access_token: result.accessToken,
          access_token_expires_at: result.accessTokenExpiresAt,
          user: toUserResponse(result.user)
        });
      } catch (error) {
        return sendServiceError(reply, error);
      }
    }
  );

  app.post<{ Body: { email: string; cf_turnstile_response?: string } }>(
    "/forgot-password",
    {
      schema: {
        body: {
          type: "object",
          nullable: true,
          additionalProperties: false,
          required: ["email"],
          properties: {
            email: { type: "string", minLength: 3, maxLength: 320 },
            cf_turnstile_response: { type: "string", minLength: 1, maxLength: 4096 }
          }
        }
      }
    },
    async (req, reply) => {
      if (!await enforceIpRateLimit(
        req,
        reply,
        opts.rateLimitService,
        "auth:forgot-password",
        authRateLimitFromEnv("SPS_AUTH_FORGOT_PASSWORD_LIMIT", 3),
        longRateLimitWindowMs(),
        "Too many password reset requests"
      )) {
        return;
      }

      try {
        await withMinimumDuration(async () => {
          await verifyTurnstileToken(req.body?.cf_turnstile_response, req.ip);
          await requestPasswordReset(opts.db, req.body?.email ?? "", preferredLocaleFromHeader(req.headers["accept-language"]));
        }, forgotPasswordMinimumResponseMs());

        return reply.code(200).send({
          message: "If the account exists, password reset instructions have been issued."
        });
      } catch (error) {
        return sendServiceError(reply, error);
      }
    }
  );

  app.post<{ Body: { token: string; next_password: string } }>(
    "/reset-password",
    {
      schema: {
        body: {
          type: "object",
          nullable: true,
          additionalProperties: false,
          required: ["token", "next_password"],
          properties: {
            token: { type: "string", minLength: 10, maxLength: 4096 },
            next_password: { type: "string", minLength: 8, maxLength: 200 }
          }
        }
      }
    },
    async (req, reply) => {
      try {
        await resetPasswordWithToken(opts.db, req.body?.token ?? "", req.body?.next_password ?? "");
        clearRefreshTokenCookie(req, reply);
        return reply.code(200).send({ message: "Password reset complete" });
      } catch (error) {
        return sendServiceError(reply, error);
      }
    }
  );

  app.get<{ Params: { token: string } }>("/verify-email/:token", async (req, reply) => {
    try {
      await verifyEmail(opts.db, req.params.token);
      const dashboardUrl = (process.env.SPS_DASHBOARD_URL?.trim() || process.env.SPS_UI_BASE_URL?.trim() || "http://localhost:5173").replace(/\/$/, "");
      return reply.redirect(`${dashboardUrl}/login?verified=true`);
    } catch (error) {
      return sendServiceError(reply, error);
    }
  });

  app.post<{ Body: { cf_turnstile_response?: string } }>("/retrigger-verification", {
    schema: {
      body: {
        type: "object",
        nullable: true,
        additionalProperties: false,
        properties: {
          cf_turnstile_response: { type: "string", minLength: 1, maxLength: 4096 }
        }
      }
    }
  }, async (req, reply) => {
    const currentUser = await requireCurrentUser(req, reply);
    if (!currentUser) {
      return;
    }

    if (!await enforceIpRateLimit(
      req,
      reply,
      opts.rateLimitService,
      "auth:retrigger-verification",
      authRateLimitFromEnv("SPS_AUTH_RETRIGGER_VERIFICATION_LIMIT", 3),
      longRateLimitWindowMs(),
      "Too many verification resend requests"
    )) {
      return;
    }

    if (opts.rateLimitService) {
      const userLimit = await opts.rateLimitService.consume(
        `auth:retrigger-verification:user:${currentUser.sub}`,
        authRateLimitFromEnv("SPS_AUTH_RETRIGGER_VERIFICATION_PER_USER_LIMIT", 3),
        longRateLimitWindowMs()
      );
      if (!userLimit.allowed) {
        return sendRateLimited(reply, userLimit, "Too many verification resend requests");
      }
    }

    try {
      await verifyTurnstileToken(req.body?.cf_turnstile_response, req.ip);
      const delivery = await retriggerEmailVerification(opts.db, currentUser.sub);
      return reply.code(200).send({
        message: delivery.mode === "sent" ? "Verification email sent" : "Verification link logged for local delivery",
        delivery
      });
    } catch (error) {
      return sendServiceError(reply, error);
    }
  });

  app.patch<{ Body: { preferred_locale: SupportedLocale } }>("/locale", {
    schema: {
      body: {
        type: "object",
        nullable: true,
        additionalProperties: false,
        required: ["preferred_locale"],
        properties: {
          preferred_locale: { type: "string", enum: ["en", "vi"] }
        }
      }
    }
  }, async (req, reply) => {
    const currentUser = await requireCurrentUser(req, reply);
    if (!currentUser) {
      return;
    }

    try {
      const user = await updateUserPreferredLocale(
        opts.db,
        currentUser.sub,
        currentUser.workspaceId,
        req.body.preferred_locale
      );
      return reply.send({ user: toUserResponse(user) });
    } catch (error) {
      return sendServiceError(reply, error);
    }
  });

  app.get("/me", async (req, reply) => {
    const currentUser = await requireCurrentUser(req, reply);
    if (!currentUser) {
      return;
    }

    const context = await getUserContext(opts.db, currentUser.sub);
    if (!context) {
      return reply.code(404).send({ error: "User not found", code: "user_not_found" });
    }

    return reply.send({
      user: toUserResponse(context.user),
      workspace: toWorkspaceResponse(context.workspace)
    });
  });

  const seedRoutesEnabled =
    process.env.NODE_ENV === "test" &&
    process.env.SPS_ENABLE_TEST_SEED_ROUTES === "1" &&
    typeof process.env.SPS_E2E_SEED_TOKEN === "string" &&
    process.env.SPS_E2E_SEED_TOKEN.length > 0;

  if (seedRoutesEnabled) {
    app.post<{ Body: { prefix: string; role?: string; agents?: string[]; initial_usage?: number; tier?: "free" | "standard" } }>(
      "/test/seed-workspace",
      {
        schema: {
          body: {
            type: "object",
            nullable: false,
            properties: {
              prefix: { type: "string", minLength: 1, maxLength: 64 },
              role: { type: "string", enum: ["workspace_admin", "workspace_operator", "workspace_viewer"] },
              agents: { type: "array", items: { type: "string" } },
              initial_usage: { type: "integer", minimum: 0 },
              tier: { type: "string", enum: ["free", "standard"] }
            },
            required: ["prefix"]
          }
        }
      },
      async (req, reply) => {
        if (req.headers["x-blindpass-e2e-seed-token"] !== process.env.SPS_E2E_SEED_TOKEN) {
          return reply.code(404).send();
        }

        const { prefix, role = "workspace_admin", agents = [], initial_usage = 0, tier = "free" } = req.body;
        const shortTs = Date.now().toString().slice(-6); // Last 6 digits
        const rand = crypto.randomBytes(3).toString("hex"); // 6 chars
        const email = `test-${prefix}-${shortTs}-${rand}@example.com`;
        const password = "LongPassword123!";
        const slug = `test-${prefix.slice(0, 20)}-${shortTs}-${rand}`;
        const displayName = `${prefix.toUpperCase()} E2E Space`;

        try {
          const result = await registerUser(
            opts.db,
            email,
            password,
            slug,
            displayName,
            "en",
            sessionContextForRequest(req.ip, userAgentFromHeaders(req.headers["user-agent"]))
          );

          // Bypass email verification and set requested role
          await opts.db.query(
            "UPDATE users SET email_verified = true, role = $1 WHERE id = $2",
            [role, result.user.id]
          );

          if (tier !== "free") {
            await opts.db.query("UPDATE workspaces SET tier = $1 WHERE id = $2", [tier, result.workspace.id]);
          }

          if (initial_usage > 0) {
            const now = new Date();
            const usageMonth = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1));
            await opts.db.query(
              `INSERT INTO workspace_exchange_usage (workspace_id, usage_month, free_exchange_used, updated_at)
               VALUES ($1, $2, $3, now())
               ON CONFLICT (workspace_id, usage_month) DO UPDATE SET free_exchange_used = EXCLUDED.free_exchange_used, updated_at = now()`,
              [result.workspace.id, usageMonth, initial_usage]
            );
          }

          // Enroll requested agents
          const enrolledAgents: Record<string, string> = {};
          for (const agentId of agents) {
            const { apiKey } = await enrollAgent(opts.db, result.workspace.id, agentId, `${agentId} Display`);
            enrolledAgents[agentId] = apiKey;
          }

          return reply.code(201).send({
            access_token: result.tokens.accessToken,
            refresh_token: result.tokens.refreshToken,
            access_token_expires_at: result.tokens.accessTokenExpiresAt,
            refresh_token_expires_at: result.tokens.refreshTokenExpiresAt,
            workspace_id: result.workspace.id,
            user_id: result.user.id,
            email,
            password,
            workspace_slug: slug,
            agents: enrolledAgents
          });
        } catch (error) {
          return sendServiceError(reply, error);
        }
      }
    );
  }
}
