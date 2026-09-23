import "dotenv/config";
import cors from "@fastify/cors";
import Fastify, { type FastifyInstance } from "fastify";
import type { Pool } from "pg";
import { createDbPool } from "./db/index.js";
import { runMigrations } from "./db/migrate.js";
import { registerAgentRoutes } from "./routes/agents.js";
import { registerAnalyticsRoutes } from "./routes/analytics.js";
import { registerAuditRoutes } from "./routes/audit.js";
import { registerAuthRoutes } from "./routes/auth.js";
import { registerBillingRoutes } from "./routes/billing.js";
import { registerExchangeRoutes } from "./routes/exchange.js";
import { registerMemberRoutes } from "./routes/members.js";
import { registerPublicIntentRoutes } from "./routes/public-intents.js";
import { registerPublicOfferRoutes } from "./routes/public-offers.js";
import { registerSecretRoutes } from "./routes/secrets.js";
import { registerWorkspacePolicyRoutes } from "./routes/workspace-policy.js";
import { registerWorkspaceRoutes } from "./routes/workspace.js";
import { InMemoryRateLimitService, RedisRateLimitService, type RateLimitService } from "./middleware/rate-limit.js";
import { cleanupExpiredAuditRecords } from "./services/audit.js";
import { StripeBillingProvider, MockBillingProvider, createStripeClient, type BillingProvider } from "./services/billing.js";
import type { ExchangePolicyRule, SecretRegistryEntry } from "./services/policy.js";
import { InMemoryQuotaService, RedisQuotaService, type QuotaService } from "./services/quota.js";
import { InMemoryRequestStore, RedisRequestStore, createRedisClient } from "./services/redis.js";
import {
  listWorkspaceIdsMissingPolicy,
  loadBootstrapWorkspacePolicyFromEnv,
  seedMissingWorkspacePolicies,
  WorkspacePolicyResolver
} from "./services/workspace-policy.js";
import { HttpX402Provider, type X402Provider, x402ConfigFromEnv } from "./services/x402.js";
import type { RequestStore } from "./types.js";
import { resolveRequiredSecret } from "./utils/secrets.js";
import { requestLogSummary } from "./utils/request-logging.js";
import {
  approvalTtlSeconds,
  assertTestOnlyTimingOverridesSafe,
  requestTtlSeconds,
  revokedTtlSeconds,
  submittedTtlSeconds
} from "./utils/test-timing.js";

type ReadinessStatus = "up" | "down" | "skipped";

export interface BuildAppOptions {
  store?: RequestStore;
  quotaService?: QuotaService;
  rateLimitService?: RateLimitService;
  billingProvider?: BillingProvider;
  db?: Pool | null;
  hmacSecret?: string;
  baseUrl?: string;
  uiBaseUrl?: string; // Add this for consistency
  corsAllowedOrigins?: string[];
  useInMemoryStore?: boolean;
  secretRegistry?: SecretRegistryEntry[];
  exchangePolicyRules?: ExchangePolicyRule[];
  x402Provider?: X402Provider;
  runMigrations?: boolean;
  closeDbOnClose?: boolean;
  trustProxy?: boolean;
  readinessChecks?: {
    db?: () => Promise<void>;
    redis?: () => Promise<void>;
  };
}

function trustProxyFromEnv(): boolean {
  const raw = process.env.SPS_TRUST_PROXY?.trim().toLowerCase();
  return raw === "1" || raw === "true" || raw === "yes";
}

function auditRetentionDaysFromEnv(): number {
  const raw = Number(process.env.SPS_AUDIT_RETENTION_DAYS ?? 30);
  if (!Number.isFinite(raw) || raw <= 0) {
    return 30;
  }

  return Math.floor(raw);
}

function auditCleanupIntervalMsFromEnv(): number {
  const raw = Number(process.env.SPS_AUDIT_CLEANUP_INTERVAL_MS ?? 24 * 60 * 60 * 1000);
  if (!Number.isFinite(raw) || raw <= 0) {
    return 24 * 60 * 60 * 1000;
  }

  return Math.floor(raw);
}

function isHostedModeEnabled(): boolean {
  const raw = process.env.SPS_HOSTED_MODE?.trim().toLowerCase();
  return raw === "1" || raw === "true" || raw === "yes";
}

function normalizeOrigin(rawOrigin: string): string | null {
  const trimmed = rawOrigin.trim();
  if (!trimmed) {
    return null;
  }

  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return null;
    }

    return parsed.origin;
  } catch {
    return null;
  }
}

function parseCorsOriginList(rawValue: string | undefined): string[] {
  if (!rawValue) {
    return [];
  }

  return rawValue
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function isLoopbackHostname(hostname: string): boolean {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1" || hostname === "[::1]";
}

function resolveCorsAllowedOrigins(options: BuildAppOptions): Set<string> {
  const configuredOrigins = new Set<string>();
  const candidates = [
    ...(options.corsAllowedOrigins ?? []),
    ...parseCorsOriginList(process.env.SPS_CORS_ALLOWED_ORIGINS),
    options.uiBaseUrl,
    process.env.SPS_UI_BASE_URL
  ];

  for (const candidate of candidates) {
    if (!candidate) {
      continue;
    }

    const normalized = normalizeOrigin(candidate);
    if (!normalized) {
      throw new Error(`Invalid CORS origin configuration: ${candidate}`);
    }

    configuredOrigins.add(normalized);
  }

  if (process.env.NODE_ENV === "production" && configuredOrigins.size === 0) {
    throw new Error("Configure SPS_CORS_ALLOWED_ORIGINS or SPS_UI_BASE_URL before enabling production CORS.");
  }

  return configuredOrigins;
}

export async function buildApp(options: BuildAppOptions = {}): Promise<FastifyInstance> {
  assertTestOnlyTimingOverridesSafe();

  if (options.db && options.runMigrations) {
    await runMigrations(options.db);
  }

  if (process.env.NODE_ENV !== "test") {
    resolveRequiredSecret("SPS_HMAC_SECRET", options.hmacSecret);
    if (options.db) {
      resolveRequiredSecret("SPS_USER_JWT_SECRET");
      resolveRequiredSecret("SPS_AGENT_JWT_SECRET");
    }
  }

  const app = Fastify({
    logger: process.env.NODE_ENV === "test" ? false : {
      serializers: { req: requestLogSummary }
    },
    bodyLimit: Number(process.env.SPS_BODY_LIMIT ?? 1024 * 1024),
    trustProxy: options.trustProxy ?? trustProxyFromEnv(),
    ajv: {
      customOptions: {
        removeAdditional: false
      }
    }
  });

  app.addHook("onSend", async (_req, reply, payload) => {
    reply.header("Referrer-Policy", "no-referrer");
    return payload;
  });

  const hmacSecret = resolveRequiredSecret("SPS_HMAC_SECRET", options.hmacSecret);
  const shouldUseInMemoryStore = options.useInMemoryStore ?? process.env.SPS_USE_IN_MEMORY === "1";

  if (process.env.NODE_ENV === "production" && shouldUseInMemoryStore) {
    throw new Error("In-memory store is disabled in production. Configure Redis instead.");
  }

  const allowedCorsOrigins = resolveCorsAllowedOrigins(options);
  const allowLoopbackCorsOrigins = process.env.NODE_ENV !== "production";

  await app.register(cors, {
    origin(requestOrigin, callback) {
      if (!requestOrigin) {
        callback(null, true);
        return;
      }

      const normalizedOrigin = normalizeOrigin(requestOrigin);
      if (!normalizedOrigin) {
        callback(null, false);
        return;
      }

      let isAllowed = allowedCorsOrigins.has(normalizedOrigin);
      if (!isAllowed && allowLoopbackCorsOrigins) {
        try {
          isAllowed = isLoopbackHostname(new URL(normalizedOrigin).hostname);
        } catch {
          isAllowed = false;
        }
      }

      callback(null, isAllowed);
    },
    credentials: true,
    allowedHeaders: ["Content-Type", "Authorization", "Payment-Signature", "Payment-Identifier", "Payment-Required", "Accept"]
  });

  let store = options.store;
  let quotaService = options.quotaService;
  let rateLimitService = options.rateLimitService;
  let storeMode: "in-memory" | "redis" | "custom" = store
    ? (store instanceof RedisRequestStore ? "redis" : "custom")
    : "custom";
  if (!store) {
    const testEnvironmentUsesInMemoryStore = process.env.NODE_ENV === "test" && process.env.SPS_USE_IN_MEMORY !== "0";
    if (shouldUseInMemoryStore || testEnvironmentUsesInMemoryStore) {
      store = new InMemoryRequestStore();
      storeMode = "in-memory";
      quotaService ??= new InMemoryQuotaService();
      rateLimitService ??= new InMemoryRateLimitService();
    } else {
      const client = createRedisClient();
      await client.connect();
      store = new RedisRequestStore(client);
      storeMode = "redis";
      quotaService ??= new RedisQuotaService(client);
      rateLimitService ??= new RedisRateLimitService(client);
      app.addHook("onClose", async () => {
        await client.quit();
      });
    }
  }

  quotaService ??= new InMemoryQuotaService();
  rateLimitService ??= new InMemoryRateLimitService();

  const dbReadinessCheck = options.readinessChecks?.db ?? (options.db
    ? async () => {
        await options.db!.query("SELECT 1");
      }
    : undefined);
  const redisReadinessCheck = options.readinessChecks?.redis ?? (store instanceof RedisRequestStore
    ? async () => {
        await store.ping();
      }
    : undefined);

  const bootstrapWorkspacePolicy = loadBootstrapWorkspacePolicyFromEnv();
  if (options.db && isHostedModeEnabled()) {
    await seedMissingWorkspacePolicies(options.db, bootstrapWorkspacePolicy, {
      source: "env_seed"
    });

    const remainingMissingPolicies = await listWorkspaceIdsMissingPolicy(options.db);
    if (remainingMissingPolicies.length > 0) {
      throw new Error("Hosted workspace policy bootstrap did not initialize all workspaces");
    }
  }

  const policyResolver = new WorkspacePolicyResolver({
    db: options.db,
    bootstrapPolicy: bootstrapWorkspacePolicy,
    overridePolicy: (options.secretRegistry || options.exchangePolicyRules)
      ? {
          secretRegistry: options.secretRegistry ?? bootstrapWorkspacePolicy.secretRegistry,
          exchangePolicyRules: options.exchangePolicyRules ?? bootstrapWorkspacePolicy.exchangePolicyRules
        }
      : null
  });

  if (options.db && options.closeDbOnClose) {
    app.addHook("onClose", async () => {
      await options.db?.end();
    });
  }

  await app.register(async (secretRoutesApp) => {
    await registerSecretRoutes(secretRoutesApp, {
      store,
      db: options.db,
      quotaService,
      rateLimitService,
      hmacSecret,
      requestTtlSeconds: requestTtlSeconds(),
      submittedTtlSeconds: submittedTtlSeconds(),
      uiBaseUrl: options.uiBaseUrl ?? options.baseUrl ?? process.env.SPS_UI_BASE_URL ?? "http://localhost:5173",
      baseUrl: options.baseUrl ?? process.env.SPS_BASE_URL ?? "http://localhost:3100"
    });
  }, { prefix: "/api/v2/secret" });

  await app.register(async (exchangeRoutesApp) => {
    const x402Config = x402ConfigFromEnv();
    await registerExchangeRoutes(exchangeRoutesApp, {
      store,
      db: options.db,
      quotaService,
      x402Provider: options.x402Provider ?? (
        x402Config.enabled && x402Config.facilitatorUrl
          ? new HttpX402Provider(x402Config.facilitatorUrl, x402Config.providerTimeoutMs)
          : undefined
      ),
      hmacSecret,
      policyResolver,
      requestTtlSeconds: requestTtlSeconds(),
      submittedTtlSeconds: submittedTtlSeconds(),
      revokedTtlSeconds: revokedTtlSeconds(),
      approvalTtlSeconds: approvalTtlSeconds()
    });
  }, { prefix: "/api/v2/secret/exchange" });

  if (options.db) {
    await app.register(async (auditRoutesApp) => {
      await registerAuditRoutes(auditRoutesApp, { db: options.db! });
    }, { prefix: "/api/v2/audit" });

    await app.register(async (analyticsRoutesApp) => {
      await registerAnalyticsRoutes(analyticsRoutesApp, { db: options.db! });
    }, { prefix: "/api/v2/analytics" });

    await app.register(async (authRoutesApp) => {
      await registerAuthRoutes(authRoutesApp, {
        db: options.db!,
        rateLimitService
      });
    }, { prefix: "/api/v2/auth" });

    await app.register(async (workspaceRoutesApp) => {
      await registerWorkspaceRoutes(workspaceRoutesApp, { db: options.db! });
    }, { prefix: "/api/v2/workspace" });

    await app.register(async (workspacePolicyRoutesApp) => {
      await registerWorkspacePolicyRoutes(workspacePolicyRoutesApp, { db: options.db! });
    }, { prefix: "/api/v2/workspace/policy" });

    await app.register(async (publicOfferRoutesApp) => {
      await registerPublicOfferRoutes(publicOfferRoutesApp, {
        db: options.db!,
        policyResolver
      });
    }, { prefix: "/api/v2/public/offers" });

    await app.register(async (publicIntentRoutesApp) => {
      const x402Config = x402ConfigFromEnv();
      await registerPublicIntentRoutes(publicIntentRoutesApp, {
        db: options.db!,
        store,
        hmacSecret,
        uiBaseUrl: options.uiBaseUrl ?? options.baseUrl ?? process.env.SPS_UI_BASE_URL ?? "http://localhost:5173",
        apiBaseUrl: options.baseUrl ?? process.env.SPS_BASE_URL ?? "http://localhost:3100",
        requestTtlSeconds: requestTtlSeconds(),
        revokedTtlSeconds: revokedTtlSeconds(),
        rateLimitService,
        x402Provider: options.x402Provider ?? (
          x402Config.enabled && x402Config.facilitatorUrl
            ? new HttpX402Provider(x402Config.facilitatorUrl, x402Config.providerTimeoutMs)
            : undefined
        )
      });
    }, { prefix: "/api/v2/public/intents" });

    await app.register(async (agentRoutesApp) => {
      await registerAgentRoutes(agentRoutesApp, {
        db: options.db!,
        rateLimitService
      });
    }, { prefix: "/api/v2/agents" });

    await app.register(async (memberRoutesApp) => {
      await registerMemberRoutes(memberRoutesApp, { db: options.db! });
    }, { prefix: "/api/v2/members" });

    const billingProvider = options.billingProvider 
      ?? (process.env.SPS_BILLING_MOCK === "1" ? new MockBillingProvider() : new StripeBillingProvider(createStripeClient()));
    await app.register(async (billingRoutesApp) => {
      await registerBillingRoutes(billingRoutesApp, {
        db: options.db!,
        provider: billingProvider,
        quotaService
      });
    }, { prefix: "/api/v2" });

    const intervalMs = auditCleanupIntervalMsFromEnv();
    const retentionDays = auditRetentionDaysFromEnv();
    const cleanupTimer = setInterval(() => {
      void cleanupExpiredAuditRecords(options.db!, { retentionDays }).catch((error) => {
        app.log.error({ err: error }, "failed to clean up expired audit records");
      });
    }, intervalMs);
    cleanupTimer.unref();

    app.addHook("onClose", async () => {
      clearInterval(cleanupTimer);
    });
  }

  app.get("/healthz", async () => ({ ok: true }));

  app.get("/readyz", async (_req, reply) => {
    const checks: Record<"database" | "redis", ReadinessStatus> = {
      database: "skipped",
      redis: "skipped"
    };

    if (dbReadinessCheck) {
      try {
        await dbReadinessCheck();
        checks.database = "up";
      } catch (error) {
        checks.database = "down";
        app.log.warn({ err: error }, "database readiness check failed");
      }
    }

    if (redisReadinessCheck) {
      try {
        await redisReadinessCheck();
        checks.redis = "up";
      } catch (error) {
        checks.redis = "down";
        app.log.warn({ err: error }, "redis readiness check failed");
      }
    } else if (storeMode === "in-memory") {
      checks.redis = "skipped";
    }

    const isReady = checks.database !== "down" && checks.redis !== "down";
    if (!isReady) {
      return reply.code(503).send({
        ok: false,
        code: "service_unavailable",
        checks
      });
    }

    return {
      ok: true,
      checks
    };
  });

  return app;
}

async function start(): Promise<void> {
  const db = createDbPool();
  const app = await buildApp({
    db,
    closeDbOnClose: true,
    runMigrations: process.env.SPS_RUN_MIGRATIONS === "1" || (process.env.NODE_ENV !== "production" && process.env.SPS_RUN_MIGRATIONS !== "0")
  });
  const host = process.env.SPS_HOST ?? "127.0.0.1";
  const port = Number(process.env.PORT ?? 3100);
  await app.listen({ host, port });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  start().catch((err) => {
    // eslint-disable-next-line no-console
    console.error(err);
    process.exit(1);
  });
}
