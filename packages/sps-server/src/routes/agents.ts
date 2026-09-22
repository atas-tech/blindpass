import type { FastifyInstance, FastifyPluginOptions, FastifyReply } from "fastify";
import type { Pool } from "pg";
import { requireUserRole } from "../middleware/auth.js";
import { rateLimitKeyByIp, sendRateLimited, type RateLimitService } from "../middleware/rate-limit.js";
import { logAudit } from "../services/audit.js";
import {
  authenticateAgentApiKey,
  AgentServiceError,
  countActiveAgents,
  enrollAgent,
  listAgents,
  mintAgentAccessToken,
  revokeAgent,
  rotateAgentApiKey,
  type EnrolledAgentRecord
} from "../services/agent.js";
import { activeAgentLimit } from "../services/quota.js";
import { ensureWorkspaceOwnerVerified, UserServiceError } from "../services/user.js";
import { getWorkspace } from "../services/workspace.js";
import { agentTokenRateLimitWindowMs } from "../utils/test-timing.js";

const AGENT_ID_PATTERN = "^[A-Za-z0-9._:@-]{1,160}$";

export interface AgentRoutesOptions extends FastifyPluginOptions {
  db: Pool;
  rateLimitService?: RateLimitService;
}

function toAgentResponse(agent: EnrolledAgentRecord) {
  return {
    id: agent.id,
    workspace_id: agent.workspaceId,
    agent_id: agent.agentId,
    display_name: agent.displayName,
    status: agent.status,
    created_at: agent.createdAt.toISOString(),
    revoked_at: agent.revokedAt?.toISOString() ?? null
  };
}

function sendServiceError(reply: FastifyReply, error: unknown) {
  if (error instanceof AgentServiceError || error instanceof UserServiceError) {
    return reply.code(error.statusCode).send({ error: error.message, code: error.code });
  }

  throw error;
}

function agentApiKeyFromRequest(headers: Record<string, unknown>): string | null {
  const authHeader = headers.authorization;
  if (typeof authHeader === "string") {
    const [scheme, token] = authHeader.split(" ");
    if (scheme?.toLowerCase() === "bearer" && token?.trim()) {
      return token.trim();
    }
  }

  const headerKey = headers["x-agent-api-key"];
  if (typeof headerKey === "string" && headerKey.trim()) {
    return headerKey.trim();
  }

  return null;
}

export async function registerAgentRoutes(app: FastifyInstance, opts: AgentRoutesOptions): Promise<void> {
  app.post<{ Body: { agent_id: string; display_name?: string } }>(
    "/",
    {
      schema: {
        body: {
          type: "object",
          additionalProperties: false,
          required: ["agent_id"],
          properties: {
            agent_id: { type: "string", pattern: AGENT_ID_PATTERN },
            display_name: { type: "string", minLength: 1, maxLength: 160 }
          }
        }
      }
    },
    async (req, reply) => {
      const user = await requireUserRole("workspace_operator")(req, reply);
      if (!user) {
        return;
      }

      try {
        await ensureWorkspaceOwnerVerified(opts.db, user.workspaceId);
        const workspace = await getWorkspace(opts.db, user.workspaceId, { activeOnly: true });
        if (!workspace) {
          return reply.code(404).send({ error: "Workspace not found", code: "workspace_not_found" });
        }

        const activeAgents = await countActiveAgents(opts.db, user.workspaceId);
        const limit = activeAgentLimit(workspace.tier);
        if (activeAgents >= limit) {
          return reply.code(429).send({
            error: "Agent quota exceeded",
            code: "quota_exceeded",
            limit,
            used: activeAgents
          });
        }

        const result = await enrollAgent(opts.db, user.workspaceId, req.body.agent_id, req.body.display_name);
        await logAudit(opts.db, {
          event: "agent_enrolled",
          workspaceId: user.workspaceId,
          actorId: user.sub,
          actorType: "user",
          resourceId: result.agent.agentId,
          metadata: {
            agent_id: result.agent.agentId,
            display_name: result.agent.displayName
          },
          action: "agent_enroll",
          ip: req.ip
        });

        return reply.code(201).send({
          agent: toAgentResponse(result.agent),
          bootstrap_api_key: result.apiKey
        });
      } catch (error) {
        return sendServiceError(reply, error);
      }
    }
  );

  app.get<{ Querystring: { limit?: number; cursor?: string; status?: "active" | "revoked" | "deleted" } }>(
    "/",
    {
      schema: {
        querystring: {
          type: "object",
          additionalProperties: false,
          properties: {
            limit: { type: "integer", minimum: 1, maximum: 100 },
            cursor: { type: "string", minLength: 1, maxLength: 512 },
            status: {
              type: "string",
              enum: ["active", "revoked", "deleted"]
            }
          }
        }
      }
    },
    async (req, reply) => {
      const user = await requireUserRole("workspace_operator")(req, reply);
      if (!user) {
        return;
      }

      try {
        const agents = await listAgents(opts.db, user.workspaceId, req.query);
        return reply.send({
          agents: agents.agents.map(toAgentResponse),
          next_cursor: agents.nextCursor
        });
      } catch (error) {
        return sendServiceError(reply, error);
      }
    }
  );

  app.post("/token", async (req, reply) => {
    if (opts.rateLimitService) {
      const limit = Number(process.env.SPS_AGENT_TOKEN_RATE_LIMIT) || 5;
      const rateLimit = await opts.rateLimitService.consume(
        rateLimitKeyByIp(req, "agents:token"),
        limit,
        agentTokenRateLimitWindowMs()
      );
      if (!rateLimit.allowed) {
        return sendRateLimited(reply, rateLimit, "Too many token requests");
      }
    }

    const apiKey = agentApiKeyFromRequest(req.headers as Record<string, unknown>);
    if (!apiKey) {
      return reply.code(401).send({ error: "Missing agent API key", code: "missing_api_key" });
    }

    try {
      const agent = await authenticateAgentApiKey(opts.db, apiKey);

      const workspace = await getWorkspace(opts.db, agent.workspaceId, { activeOnly: true });
      if (workspace) {
        const activeAgents = await countActiveAgents(opts.db, agent.workspaceId);
        const limit = activeAgentLimit(workspace.tier);
        if (activeAgents > limit) {
          return reply.code(403).send({
            error: "Workspace is over its agent quota. Please upgrade or remove agents.",
            code: "quota_exceeded",
            limit,
            used: activeAgents
          });
        }
      }

      const token = await mintAgentAccessToken(agent);
      await logAudit(opts.db, {
        event: "agent_token_minted",
        workspaceId: agent.workspaceId,
        agentId: agent.agentId,
        actorType: "agent",
        resourceId: agent.id,
        metadata: {
          minted_via: "bootstrap_api_key"
        },
        action: "agent_token_mint",
        ip: req.ip
      });
      return reply.send({
        access_token: token.accessToken,
        access_token_expires_at: token.accessTokenExpiresAt,
        agent: toAgentResponse(token.agent)
      });
    } catch (error) {
      return sendServiceError(reply, error);
    }
  });

  app.post<{ Params: { aid: string } }>(
    "/:aid/rotate-key",
    {
      schema: {
        params: {
          type: "object",
          additionalProperties: false,
          required: ["aid"],
          properties: {
            aid: { type: "string", pattern: AGENT_ID_PATTERN }
          }
        }
      }
    },
    async (req, reply) => {
      const user = await requireUserRole("workspace_operator")(req, reply);
      if (!user) {
        return;
      }

      try {
        await ensureWorkspaceOwnerVerified(opts.db, user.workspaceId);
        const result = await rotateAgentApiKey(opts.db, user.workspaceId, req.params.aid);
        await logAudit(opts.db, {
          event: "agent_api_key_rotated",
          workspaceId: user.workspaceId,
          actorId: user.sub,
          actorType: "user",
          resourceId: result.agent.agentId,
          metadata: {
            agent_id: result.agent.agentId
          },
          action: "agent_rotate_api_key",
          ip: req.ip
        });

        return reply.send({
          agent: toAgentResponse(result.agent),
          bootstrap_api_key: result.apiKey
        });
      } catch (error) {
        return sendServiceError(reply, error);
      }
    }
  );

  app.delete<{ Params: { aid: string } }>(
    "/:aid",
    {
      schema: {
        params: {
          type: "object",
          additionalProperties: false,
          required: ["aid"],
          properties: {
            aid: { type: "string", pattern: AGENT_ID_PATTERN }
          }
        }
      }
    },
    async (req, reply) => {
      const user = await requireUserRole("workspace_operator")(req, reply);
      if (!user) {
        return;
      }

      try {
        await ensureWorkspaceOwnerVerified(opts.db, user.workspaceId);
        const agent = await revokeAgent(opts.db, user.workspaceId, req.params.aid);
        await logAudit(opts.db, {
          event: "agent_revoked",
          workspaceId: user.workspaceId,
          actorId: user.sub,
          actorType: "user",
          resourceId: agent.agentId,
          metadata: {
            agent_id: agent.agentId
          },
          action: "agent_revoke",
          ip: req.ip
        });

        return reply.send({ agent: toAgentResponse(agent) });
      } catch (error) {
        return sendServiceError(reply, error);
      }
    }
  );
}
