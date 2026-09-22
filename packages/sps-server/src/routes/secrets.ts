import type { FastifyInstance, FastifyPluginOptions } from "fastify";
import type { Pool } from "pg";
import type { RateLimitService } from "../middleware/rate-limit.js";
import { requireBrowserSig, requireGatewayAuth, requireUserAuth } from "../middleware/auth.js";
import { logAudit } from "../services/audit.js";
import { getGuestIntentById } from "../services/guest-intent.js";
import { dailyQuotaLimit, type QuotaService } from "../services/quota.js";
import { createSecretRequest } from "../services/secret-request.js";
import { getWorkspace } from "../services/workspace.js";
import type { RequestStore, StoredRequest } from "../types.js";
import { workspaceBurstWindowMs, workspaceThrottleWindowMs } from "../utils/test-timing.js";

const REQUEST_ID_PATTERN = "^[a-f0-9]{64}$";
const SIG_PATTERN = "^[0-9]{10,13}\\.[A-Za-z0-9_-]{43}$";
const BASE64_PATTERN = "^[A-Za-z0-9+/]+={0,2}$";

const requestParamsSchema = {
  type: "object",
  additionalProperties: false,
  required: ["id"],
  properties: {
    id: { type: "string", pattern: REQUEST_ID_PATTERN }
  }
} as const;

const sigQuerySchema = {
  type: "object",
  additionalProperties: false,
  required: ["sig"],
  properties: {
    sig: { type: "string", pattern: SIG_PATTERN }
  }
} as const;

export interface SecretRoutesOptions extends FastifyPluginOptions {
  store: RequestStore;
  hmacSecret: string;
  requestTtlSeconds?: number;
  submittedTtlSeconds?: number;
  uiBaseUrl?: string;
  baseUrl?: string;
  db?: Pool | null;
  quotaService?: QuotaService;
  rateLimitService?: RateLimitService;
}

const WORKSPACE_BURST_MULTIPLIER = 5;
const WORKSPACE_THROTTLE_LIMIT = 1;

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

function isHostedModeEnabled(): boolean {
  const raw = process.env.SPS_HOSTED_MODE?.trim().toLowerCase();
  return raw === "1" || raw === "true" || raw === "yes";
}

function requestOwnedByAgent(
  request: { requesterId?: string; workspaceId?: string },
  agent: { sub: string; workspaceId?: string | null }
): boolean {
  if (request.requesterId && request.requesterId !== agent.sub) {
    return false;
  }

  if (isHostedModeEnabled()) {
    return !!request.workspaceId && !!agent.workspaceId && request.workspaceId === agent.workspaceId;
  }

  if (request.workspaceId && agent.workspaceId && request.workspaceId !== agent.workspaceId) {
    return false;
  }

  return true;
}

async function guestBackedRequestAvailable(
  db: Pool | null | undefined,
  record: StoredRequest
): Promise<boolean> {
  if (!db || !record.guestIntentId) {
    return true;
  }

  const intent = await getGuestIntentById(db, record.guestIntentId);
  if (!intent) {
    return false;
  }

  if (intent.requestId !== record.requestId) {
    return false;
  }

  if (intent.status !== "activated" || intent.revokedAt || intent.expiresAt.getTime() <= Date.now()) {
    return false;
  }

  return true;
}

export async function registerSecretRoutes(app: FastifyInstance, opts: SecretRoutesOptions): Promise<void> {
  const requestTtl = opts.requestTtlSeconds ?? 180;
  const submittedTtl = opts.submittedTtlSeconds ?? 60;
  const uiBaseUrl = opts.uiBaseUrl ?? process.env.SPS_UI_BASE_URL ?? "http://localhost:5173";

  app.post<{ Body: { public_key: string; description: string } }>(
    "/request",
    {
      schema: {
        body: {
          type: "object",
          additionalProperties: false,
          required: ["public_key", "description"],
          properties: {
            public_key: { type: "string", minLength: 4, maxLength: 2048, pattern: BASE64_PATTERN },
            description: { type: "string", minLength: 1, maxLength: 512 }
          }
        }
      }
    },
    async (req, reply) => {
      const payload = await requireGatewayAuth(req, reply);
      if (!payload) {
        return;
      }

      if (!req.body.description.trim()) {
        return reply.code(400).send({ error: "description must not be blank" });
      }

      if (opts.db && payload.workspaceId) {
        const workspace = await getWorkspace(opts.db, payload.workspaceId, { activeOnly: true });
        if (!workspace) {
          return reply.code(404).send({ error: "Workspace not found", code: "workspace_not_found" });
        }

        if (isHostedModeEnabled() && opts.rateLimitService) {
          const burstThreshold = dailyQuotaLimit("secret_request", workspace.tier) * WORKSPACE_BURST_MULTIPLIER;
          const burst = await opts.rateLimitService.consumeWorkspaceBurst(
            `workspace:burst:${payload.workspaceId}:secret_request`,
            burstThreshold,
            workspaceBurstWindowMs(),
            WORKSPACE_THROTTLE_LIMIT,
            workspaceThrottleWindowMs()
          );

          if (burst.triggerAlert) {
            await logAudit(opts.db, {
              event: "abuse_alert",
              workspaceId: payload.workspaceId,
              actorType: "system",
              resourceId: payload.workspaceId,
              metadata: {
                scope: "secret_request",
                tier: workspace.tier,
                threshold: burst.threshold,
                used: burst.windowUsed,
                throttle_limit: burst.throttleLimit,
                throttle_window_seconds: Math.floor(workspaceThrottleWindowMs() / 1000),
                window_seconds: Math.floor(workspaceBurstWindowMs() / 1000),
                ip: req.ip
              },
              action: "workspace_burst_detected",
              ip: req.ip
            });
          }

          if (burst.throttled) {
            reply.header("Retry-After", String(burst.retryAfterSeconds));
            return reply.code(429).send({
              error: "Workspace is temporarily throttled due to burst activity",
              code: "abuse_throttled",
              retry_after_seconds: burst.retryAfterSeconds,
              limit: burst.throttleLimit,
              used: burst.throttleUsed,
              threshold: burst.threshold,
              window_used: burst.windowUsed
            });
          }
        }

        if (opts.quotaService) {
          const quota = await opts.quotaService.consumeDailyQuota(payload.workspaceId, "secret_request", workspace.tier);
          if (!quota.allowed) {
            return reply.code(429).send({
              error: "Secret request quota exceeded",
              code: "quota_exceeded",
              limit: quota.limit,
              used: quota.used,
              reset_at: quota.resetAt
            });
          }
        }
      }

      const created = await createSecretRequest(opts.store, {
        publicKey: req.body.public_key,
        description: req.body.description,
        requesterId: payload.sub,
        workspaceId: payload.workspaceId ?? undefined,
        requestTtlSeconds: requestTtl,
        hmacSecret: opts.hmacSecret,
        uiBaseUrl,
        apiBaseUrl: opts.baseUrl ?? process.env.SPS_BASE_URL ?? "http://localhost:3100",
        requestedByActorType: "agent"
      });

      await logAudit(opts.db, {
        event: "request_created",
        requestId: created.record.requestId,
        agentId: payload.sub,
        workspaceId: payload.workspaceId ?? null,
        action: "request",
        ip: req.ip
      });

      return reply.code(201).send({
        request_id: created.record.requestId,
        confirmation_code: created.record.confirmationCode,
        secret_url: created.secretUrl
      });
    }
  );

  app.get<{ Params: { id: string }; Querystring: { sig?: string } }>(
    "/metadata/:id",
    {
      schema: {
        params: requestParamsSchema,
        querystring: sigQuerySchema
      }
    },
    async (req, reply) => {
      const auth = requireBrowserSig(req, reply, "metadata", opts.hmacSecret);
      if (!auth) {
        return;
      }

      const record = await opts.store.getRequest(req.params.id);
      if (!record) {
        return reply.code(410).send({ error: "Request expired" });
      }

      if (!await guestBackedRequestAvailable(opts.db, record)) {
        return reply.code(410).send({ error: "Request expired" });
      }

      if (record.requireUserAuth) {
        const user = await requireUserAuth(req, reply);
        if (!user) {
          return;
        }

        if (record.requiredUserWorkspaceId && user.workspaceId !== record.requiredUserWorkspaceId) {
          return reply.code(403).send({ error: "Request is not available in this workspace", code: "workspace_mismatch" });
        }
      }

      return reply.send({
        public_key: record.publicKey,
        description: record.description,
        confirmation_code: record.confirmationCode,
        expiry: auth.exp
      });
    }
  );

  app.post<{ Params: { id: string }; Querystring: { sig?: string }; Body: { enc: string; ciphertext: string } }>(
    "/submit/:id",
    {
      schema: {
        params: requestParamsSchema,
        querystring: sigQuerySchema,
        body: {
          type: "object",
          additionalProperties: false,
          required: ["enc", "ciphertext"],
          properties: {
            enc: { type: "string", minLength: 4, maxLength: 4096, pattern: BASE64_PATTERN },
            ciphertext: { type: "string", minLength: 4, maxLength: 524288, pattern: BASE64_PATTERN }
          }
        }
      }
    },
    async (req, reply) => {
      const auth = requireBrowserSig(req, reply, "submit", opts.hmacSecret);
      if (!auth) {
        return;
      }

      const record = await opts.store.getRequest(req.params.id);
      if (!record) {
        return reply.code(410).send({ error: "Request expired" });
      }

      if (!await guestBackedRequestAvailable(opts.db, record)) {
        return reply.code(410).send({ error: "Request expired" });
      }

      let submitterUserId: string | null = null;
      let submitterWorkspaceId: string | null = null;
      if (record.requireUserAuth) {
        const user = await requireUserAuth(req, reply);
        if (!user) {
          return;
        }

        if (record.requiredUserWorkspaceId && user.workspaceId !== record.requiredUserWorkspaceId) {
          return reply.code(403).send({ error: "Request is not available in this workspace", code: "workspace_mismatch" });
        }

        submitterUserId = user.sub;
        submitterWorkspaceId = user.workspaceId;
      }

      if (record.status === "submitted") {
        return reply.code(409).send({ error: "Already submitted" });
      }

      const next = await opts.store.updateRequest(
        req.params.id,
        {
          status: "submitted",
          enc: req.body.enc,
          ciphertext: req.body.ciphertext,
          expiresAt: nowSeconds() + submittedTtl
        },
        submittedTtl,
        "pending"
      );

      if (!next) {
        const current = await opts.store.getRequest(req.params.id);
        if (current?.status === "submitted") {
          return reply.code(409).send({ error: "Already submitted" });
        }
        return reply.code(410).send({ error: "Request expired" });
      }

      await logAudit(opts.db, {
        event: "secret_submitted",
        requestId: req.params.id,
        actorId: submitterUserId,
        actorType: submitterUserId ? "user" : undefined,
        workspaceId: submitterWorkspaceId || record.workspaceId,
        action: "submit",
        ip: req.ip
      });

      return reply.code(201).send({ status: "submitted" });
    }
  );

  app.get<{ Params: { id: string } }>(
    "/retrieve/:id",
    {
      schema: {
        params: requestParamsSchema
      }
    },
    async (req, reply) => {
      const payload = await requireGatewayAuth(req, reply);
      if (!payload) {
        return;
      }

      const current = await opts.store.getRequest(req.params.id);
      if (!current) {
        return reply.code(410).send({ error: "Not available" });
      }

      if (!requestOwnedByAgent(current, payload)) {
        return reply.code(410).send({ error: "Not available" });
      }

      if (current.status !== "submitted") {
        return reply.code(409).send({ error: "Not submitted yet" });
      }

      const retrieved = await opts.store.atomicRetrieveAndDelete(
        req.params.id,
        current.requesterId ?? payload.sub,
        current.workspaceId ?? payload.workspaceId ?? undefined
      );
      if (!retrieved || !retrieved.enc || !retrieved.ciphertext) {
        return reply.code(410).send({ error: "Not available" });
      }

      await logAudit(opts.db, {
        event: "secret_retrieved",
        requestId: req.params.id,
        agentId: payload.sub,
        workspaceId: payload.workspaceId ?? null,
        action: "retrieve",
        ip: req.ip
      });

      return reply.send({
        enc: retrieved.enc,
        ciphertext: retrieved.ciphertext
      });
    }
  );

  app.get<{ Params: { id: string } }>(
    "/status/:id",
    {
      schema: {
        params: requestParamsSchema
      }
    },
    async (req, reply) => {
      const payload = await requireGatewayAuth(req, reply);
      if (!payload) {
        return;
      }

      const record = await opts.store.getRequest(req.params.id);
      if (!record) {
        return reply.code(410).send({ status: "expired" });
      }

      if (!requestOwnedByAgent(record, payload)) {
        return reply.code(410).send({ status: "expired" });
      }

      return reply.send({ status: record.status });
    }
  );

  app.delete<{ Params: { id: string } }>(
    "/revoke/:id",
    {
      schema: {
        params: requestParamsSchema
      }
    },
    async (req, reply) => {
      const payload = await requireGatewayAuth(req, reply);
      if (!payload) {
        return;
      }

      const deleted = await opts.store.deleteRequest(
        req.params.id,
        payload.sub,
        payload.workspaceId ?? undefined
      );
      if (!deleted) {
        return reply.code(410).send({ error: "Not available" });
      }

      await logAudit(opts.db, {
        event: "request_revoked",
        requestId: req.params.id,
        agentId: payload.sub,
        workspaceId: payload.workspaceId ?? null,
        action: "revoke",
        ip: req.ip
      });

      return reply.code(204).send();
    }
  );
}
