import { createPrivateKey, randomBytes } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { spawn, type ChildProcess } from "node:child_process";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createExternalJwtIdentity, signExternalJwt, type ExternalJwtIdentity } from "./signing.js";
import { httpRequest, jsonRequestBody, waitForHttp, withBearer } from "./http.js";
import { AGENT_IDS, fixtureCanaries, POLICY_DOCUMENT, SECRET_NAMES, type AgentId, type ContractAgent, type ContractFixture } from "./fixtures.js";

const PACKAGE_DIR = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(PACKAGE_DIR, "../../..");

type SupportedSut = "ts" | "base" | "rust";

interface ExternalPrivateJwk {
  [key: string]: string;
  kty: string;
}

interface PgPoolLike {
  query<T = unknown>(text: string, values?: unknown[]): Promise<{ rows: T[] }>;
  connect(): Promise<PgClientLike>;
  end(): Promise<void>;
}

interface PgClientLike {
  query<T = unknown>(text: string, values?: unknown[]): Promise<{ rows: T[] }>;
  release(): void;
}

interface RedisLike {
  ping(): Promise<string>;
  scan(cursor: string, match: "MATCH", pattern: string, count: "COUNT", size: number): Promise<[string, string[]]>;
  unlink(...keys: string[]): Promise<number>;
  quit(): Promise<string>;
}

interface ServerAdapter {
  baseUrl: string;
  fixture: ContractFixture;
  externalJwt(claims?: Record<string, unknown>, nowSeconds?: number): string;
  close(): Promise<void>;
}

function sutFromEnvironment(): SupportedSut | null {
  const raw = process.env.SUT?.trim().toLowerCase();
  if (raw === "ts" || raw === "base" || raw === "rust") {
    return raw;
  }

  if (process.env.CONTRACT_BASE_URL) {
    return "base";
  }

  return null;
}

function randomIdentifier(prefix: string): string {
  return `${prefix}_${process.pid}_${randomBytes(5).toString("hex")}`.slice(0, 60);
}

function quoteIdentifier(identifier: string): string {
  return `"${identifier.replaceAll('"', '""')}"`;
}

export function withSearchPath(databaseUrl: string, schema: string): string {
  const url = new URL(databaseUrl);
  url.searchParams.set("options", `-c search_path=${schema}`);
  return url.toString();
}

function withRedisDatabase(redisUrl: string, database: number): string {
  const url = new URL(redisUrl);
  url.pathname = `/${database}`;
  return url.toString();
}

async function freeTcpPort(): Promise<number> {
  const server = net.createServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen({ host: "127.0.0.1", port: 0 }, () => resolve());
  });
  const address = server.address();
  if (!address || typeof address === "string") {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    throw new Error("Could not resolve a free TCP port");
  }
  const port = address.port;
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  return port;
}

async function loadPgPool(connectionString: string, max: number): Promise<PgPoolLike> {
  const pg = await import("pg");
  return new pg.Pool({ connectionString, max }) as unknown as PgPoolLike;
}

function schemaLockKey(schema: string): string {
  return `blindpass-contract-schema:${schema}`;
}

async function loadRedis(connectionString: string): Promise<RedisLike> {
  const redisModule = await import("ioredis");
  const RedisConstructor = redisModule.Redis;
  const client = new RedisConstructor(connectionString, {
    maxRetriesPerRequest: 1,
    retryStrategy: () => null,
    connectTimeout: 1_000
  });
  client.on("error", () => undefined);
  return client as unknown as RedisLike;
}

function childExit(child: ChildProcess): Promise<void> {
  return new Promise((resolve) => {
    if (child.exitCode !== null || child.signalCode !== null) {
      resolve();
      return;
    }
    child.once("exit", () => resolve());
  });
}

async function stopChild(child: ChildProcess): Promise<void> {
  if (child.exitCode === null && child.signalCode === null) {
    child.kill("SIGTERM");
    await Promise.race([
      childExit(child),
      new Promise<void>((resolve) => setTimeout(resolve, 3_000))
    ]);
  }

  if (child.exitCode === null && child.signalCode === null) {
    child.kill("SIGKILL");
    await childExit(child);
  }
}

async function seedFixture(
  baseUrl: string,
  seedToken: string,
  hmacSecret: string
): Promise<ContractFixture> {
  const seed = await httpRequest<{
    access_token: string;
    refresh_token: string;
    workspace_id: string;
    user_id: string;
    agents: Record<string, string>;
  }>(baseUrl, "/api/v2/auth/test/seed-workspace", {
    ...jsonRequestBody({
      prefix: "contract",
      role: "workspace_admin",
      tier: "standard",
      agents: Object.values(AGENT_IDS)
    }),
    headers: {
      "content-type": "application/json",
      "x-blindpass-e2e-seed-token": seedToken
    }
  });

  if (seed.status !== 201 || !seed.body) {
    throw new Error(`Contract fixture seed failed with ${seed.status}: ${seed.text.slice(0, 500)}`);
  }

  const adminAccessToken = seed.body.access_token;
  const policy = await httpRequest(baseUrl, "/api/v2/workspace/policy", withBearer(adminAccessToken, {
    ...jsonRequestBody({
      expected_version: 1,
      ...POLICY_DOCUMENT
    }),
    method: "PATCH"
  }));
  if (policy.status !== 200) {
    throw new Error(`Contract fixture policy setup failed with ${policy.status}: ${policy.text.slice(0, 500)}`);
  }

  const agents = {} as Record<AgentId, ContractAgent>;
  for (const [agentId, apiKey] of Object.entries(seed.body.agents)) {
    const token = await httpRequest<{
      access_token: string;
      access_token_expires_at: number;
    }>(baseUrl, "/api/v2/agents/token", {
      method: "POST",
      headers: {
        authorization: `Bearer ${apiKey}`,
        "x-forwarded-for": `198.51.100.${Object.keys(agents).length + 10}`
      }
    });
    if (token.status !== 200 || !token.body) {
      throw new Error(`Contract fixture token mint failed for ${agentId}: ${token.status}: ${token.text.slice(0, 500)}`);
    }

    const key = (Object.entries(AGENT_IDS).find(([, value]) => value === agentId)?.[0] ?? agentId) as AgentId;
    agents[key] = {
      agentId,
      apiKey,
      accessToken: token.body.access_token,
      accessTokenExpiresAt: token.body.access_token_expires_at
    };
  }

  const canaries = fixtureCanaries();
  canaries.push(adminAccessToken, seed.body.refresh_token);
  for (const value of Object.values(agents)) {
    canaries.push(value.apiKey, value.accessToken);
  }

  return {
    workspaceId: seed.body.workspace_id,
    userId: seed.body.user_id,
    adminAccessToken,
    adminRefreshToken: seed.body.refresh_token,
    agents,
    baseUrl,
    hmacSecret,
    seedToken,
    canaries: [...canaries, hmacSecret, seedToken]
  };
}

const CONTRACT_SCHEMA_COMMENT_PREFIX = "blindpass-contract-schema:v1:";
const STALE_SCHEMA_AGE_MS = 60 * 60 * 1000;

class TsServerAdapter implements ServerAdapter {
  baseUrl = "";
  fixture!: ContractFixture;
  private child: ChildProcess | null = null;
  private adminPool: PgPoolLike | null = null;
  private schemaLockClient: PgClientLike | null = null;
  private redis: RedisLike | null = null;
  private redisKeyPrefix = "";
  private schema = "";
  private tempDir = "";
  private externalIdentity!: ExternalJwtIdentity;

  async start(): Promise<void> {
    try {
      await this.startIsolated();
    } catch (error) {
      await this.close();
      throw error;
    }
  }

  private async startIsolated(): Promise<void> {
    const databaseUrl = process.env.CONTRACT_DATABASE_URL?.trim() || process.env.DATABASE_URL?.trim();
    if (!databaseUrl) {
      throw new Error("SUT=ts requires CONTRACT_DATABASE_URL or DATABASE_URL");
    }

    const redisUrl = process.env.CONTRACT_REDIS_URL?.trim() || process.env.REDIS_URL?.trim() || "redis://127.0.0.1:6380";
    const redisDb = Number(process.env.CONTRACT_REDIS_DB ?? 15);
    if (!Number.isInteger(redisDb) || redisDb < 0 || redisDb > 15) {
      throw new Error("CONTRACT_REDIS_DB must be an integer from 0 through 15");
    }

    this.schema = randomIdentifier("contract");
    this.adminPool = await loadPgPool(databaseUrl, 3);
    this.schemaLockClient = await this.adminPool.connect();
    await this.schemaLockClient.query(
      "SELECT pg_advisory_lock(hashtextextended($1, 0))",
      [schemaLockKey(this.schema)]
    );
    await this.removeStaleSchemas();
    await this.adminPool.query(`CREATE SCHEMA ${quoteIdentifier(this.schema)}`);
    await this.adminPool.query(
      `COMMENT ON SCHEMA ${quoteIdentifier(this.schema)} IS '${CONTRACT_SCHEMA_COMMENT_PREFIX}${Date.now()}'`
    );

    this.redisKeyPrefix = `${randomIdentifier("contract")}:`;
    this.redis = await loadRedis(withRedisDatabase(redisUrl, redisDb));
    await this.redis.ping();

    this.tempDir = await mkdtemp(path.join(os.tmpdir(), "blindpass-contract-"));
    this.externalIdentity = createExternalJwtIdentity();
    const jwksPath = path.join(this.tempDir, "jwks.json");
    await writeFile(jwksPath, JSON.stringify({ keys: [this.externalIdentity.publicJwk] }), { mode: 0o600 });

    const port = await freeTcpPort();
    this.baseUrl = `http://127.0.0.1:${port}`;
    const hmacSecret = `contract-hmac-${randomBytes(24).toString("hex")}`;
    const seedToken = `contract-seed-${randomBytes(24).toString("hex")}`;
    const childEnv: NodeJS.ProcessEnv = {
      ...process.env,
      NODE_ENV: "test",
      SPS_HOST: "127.0.0.1",
      PORT: String(port),
      SPS_BASE_URL: this.baseUrl,
      SPS_UI_BASE_URL: process.env.CONTRACT_UI_BASE_URL?.trim() || "http://127.0.0.1:5175",
      SPS_CORS_ALLOWED_ORIGINS: "http://allowed.contract.test",
      DATABASE_URL: withSearchPath(databaseUrl, this.schema),
      REDIS_URL: withRedisDatabase(redisUrl, redisDb),
      SPS_REDIS_KEY_PREFIX: this.redisKeyPrefix,
      SPS_RUN_MIGRATIONS: "1",
      SPS_USE_IN_MEMORY: "0",
      SPS_HOSTED_MODE: "1",
      SPS_TRUST_PROXY: "1",
      SPS_BILLING_MOCK: "1",
      SPS_X402_ENABLED: "0",
      SPS_HMAC_SECRET: hmacSecret,
      SPS_USER_JWT_SECRET: `contract-user-${randomBytes(24).toString("hex")}`,
      SPS_AGENT_JWT_SECRET: `contract-agent-${randomBytes(24).toString("hex")}`,
      SPS_E2E_SEED_TOKEN: seedToken,
      SPS_ENABLE_TEST_SEED_ROUTES: "1",
      SPS_AGENT_AUTH_PROVIDERS_JSON: JSON.stringify([
        {
          name: "contract-jwks",
          jwks_file: jwksPath,
          issuer: "contract-gateway",
          audience: "contract-sps"
        }
      ]),
      SPS_SECRET_REGISTRY_JSON: JSON.stringify(POLICY_DOCUMENT.secret_registry),
      SPS_EXCHANGE_POLICY_JSON: JSON.stringify(POLICY_DOCUMENT.exchange_policy),
      SPS_AGENT_TOKEN_RATE_LIMIT: "5",
      SPS_AGENT_LIMIT_FREE: "20",
      SPS_EXCHANGE_LIMIT_STANDARD: "1000",
      SPS_TEST_REQUEST_TTL_SECONDS: process.env.CONTRACT_REQUEST_TTL_SECONDS ?? "8",
      SPS_TEST_SUBMITTED_TTL_SECONDS: process.env.CONTRACT_SUBMITTED_TTL_SECONDS ?? "3",
      SPS_TEST_REVOKED_TTL_SECONDS: process.env.CONTRACT_REVOKED_TTL_SECONDS ?? "4",
      SPS_TEST_APPROVAL_TTL_SECONDS: process.env.CONTRACT_APPROVAL_TTL_SECONDS ?? "20",
      SPS_TEST_REFRESH_TOKEN_TTL_SECONDS: process.env.CONTRACT_REFRESH_TOKEN_TTL_SECONDS ?? "10",
      SPS_TEST_RATE_LIMIT_WINDOW_MS: process.env.CONTRACT_RATE_LIMIT_WINDOW_MS ?? "1000",
      SPS_TEST_AGENT_TOKEN_RATE_WINDOW_MS: process.env.CONTRACT_AGENT_TOKEN_RATE_WINDOW_MS ?? "1000",
      SPS_LOG_AUDIT_EVENTS: "0",
      SPS_LOG_VERIFICATION_URLS: "0",
      SPS_LOG_PASSWORD_RESET_URLS: "0"
    };

    this.child = spawn(process.execPath, ["--import", "tsx", path.join(REPO_ROOT, "packages/sps-server/src/index.ts")], {
      cwd: REPO_ROOT,
      env: childEnv,
      stdio: ["ignore", "pipe", "pipe"]
    });

    let childOutput = "";
    this.child.stdout?.on("data", (chunk: Buffer) => {
      childOutput = `${childOutput}${chunk.toString()}`.slice(-4_000);
    });
    this.child.stderr?.on("data", (chunk: Buffer) => {
      childOutput = `${childOutput}${chunk.toString()}`.slice(-4_000);
    });

    try {
      await waitForHttp(this.baseUrl);
      this.fixture = await seedFixture(this.baseUrl, seedToken, hmacSecret);
    } catch (error) {
      await this.close();
      throw new Error(`${error instanceof Error ? error.message : String(error)}\nSPS output:\n${childOutput}`);
    }
  }

  externalJwt(claims: Record<string, unknown> = {}, nowSeconds?: number): string {
    const token = signExternalJwt(this.externalIdentity, {
      role: "gateway",
      sub: "contract-external/ring/blue",
      workspace_id: this.fixture.workspaceId,
      workload_mode: "external",
      ...claims
    }, nowSeconds);
    this.fixture?.canaries.push(token);
    return token;
  }

  exportExternalJwtPrivateJwk(): JsonWebKey {
    return this.externalIdentity.privateKey.export({ format: "jwk" }) as JsonWebKey;
  }

  async close(): Promise<void> {
    if (this.child) {
      await stopChild(this.child);
      this.child = null;
    }

    if (this.redis) {
      await this.cleanupRedisKeys().catch(() => undefined);
      await this.redis.quit().catch(() => undefined);
      this.redis = null;
    }

    if (this.adminPool) {
      if (this.schema) {
        await this.adminPool.query(`DROP SCHEMA IF EXISTS ${quoteIdentifier(this.schema)} CASCADE`).catch(() => undefined);
      }
      if (this.schemaLockClient) {
        await this.schemaLockClient.query(
          "SELECT pg_advisory_unlock(hashtextextended($1, 0))",
          [schemaLockKey(this.schema)]
        ).catch(() => undefined);
        this.schemaLockClient.release();
        this.schemaLockClient = null;
      }
      await this.adminPool.end().catch(() => undefined);
      this.adminPool = null;
    }

    if (this.tempDir) {
      await rm(this.tempDir, { recursive: true, force: true });
      this.tempDir = "";
    }
  }

  private async cleanupRedisKeys(): Promise<void> {
    if (!this.redis || !this.redisKeyPrefix) return;
    let cursor = "0";
    const matching = new Set<string>();
    do {
      const [next, keys] = await this.redis.scan(cursor, "MATCH", `${this.redisKeyPrefix}*`, "COUNT", 100);
      for (const key of keys) matching.add(key);
      cursor = next;
    } while (cursor !== "0");
    const keys = [...matching];
    for (let index = 0; index < keys.length; index += 100) {
      await this.redis.unlink(...keys.slice(index, index + 100));
    }
  }

  private async removeStaleSchemas(): Promise<void> {
    if (!this.adminPool) return;
    const lockClient = await this.adminPool.connect();
    try {
      const result = await lockClient.query<{ nspname: string; schema_comment: string | null }>(
        "SELECT nspname, obj_description(oid, 'pg_namespace') AS schema_comment FROM pg_namespace WHERE left(nspname, 9) = 'contract_' ORDER BY nspname"
      );
      for (const { nspname, schema_comment } of result.rows) {
        if (!schema_comment?.startsWith(CONTRACT_SCHEMA_COMMENT_PREFIX)) continue;
        const createdAt = Number(schema_comment.slice(CONTRACT_SCHEMA_COMMENT_PREFIX.length));
        if (!Number.isFinite(createdAt) || Date.now() - createdAt < STALE_SCHEMA_AGE_MS) continue;

        const lockKey = schemaLockKey(nspname);
        const lock = await lockClient.query<{ acquired: boolean }>(
          "SELECT pg_try_advisory_lock(hashtextextended($1, 0)) AS acquired",
          [lockKey]
        );
        if (!lock.rows[0]?.acquired) continue;

        try {
          await this.adminPool.query(`DROP SCHEMA IF EXISTS ${quoteIdentifier(nspname)} CASCADE`);
        } finally {
          await lockClient.query(
            "SELECT pg_advisory_unlock(hashtextextended($1, 0))",
            [lockKey]
          );
        }
      }
    } finally {
      lockClient.release();
    }
  }
}

class BaseUrlAdapter implements ServerAdapter {
  baseUrl: string;
  fixture!: ContractFixture;
  private externalIdentity!: ExternalJwtIdentity;

  constructor(baseUrl: string) {
    this.baseUrl = baseUrl.replace(/\/$/, "");
  }

  async start(): Promise<void> {
    await waitForHttp(this.baseUrl);
    this.externalIdentity = createExternalJwtIdentity();
    const fixtureFile = process.env.CONTRACT_FIXTURE_FILE?.trim();
    if (fixtureFile) {
      this.fixture = JSON.parse(await readFile(fixtureFile, "utf8")) as ContractFixture;
      const externalPrivateJwk = (this.fixture as ContractFixture & { externalJwtPrivateJwk?: ExternalPrivateJwk })
        .externalJwtPrivateJwk;
      if (externalPrivateJwk) {
        this.externalIdentity = {
          privateKey: createPrivateKey({ key: externalPrivateJwk, format: "jwk" }),
          publicJwk: {}
        };
      }
      return;
    }

    const seedToken = process.env.CONTRACT_SEED_TOKEN?.trim();
    const hmacSecret = process.env.CONTRACT_HMAC_SECRET?.trim();
    if (!seedToken || !hmacSecret) {
      throw new Error("SUT=base requires CONTRACT_FIXTURE_FILE or CONTRACT_SEED_TOKEN plus CONTRACT_HMAC_SECRET");
    }

    this.fixture = await seedFixture(this.baseUrl, seedToken, hmacSecret);
  }

  externalJwt(claims: Record<string, unknown> = {}, nowSeconds?: number): string {
    const token = signExternalJwt(this.externalIdentity, {
      role: "gateway",
      sub: "contract-external/ring/blue",
      workspace_id: this.fixture.workspaceId,
      workload_mode: "external",
      ...claims
    }, nowSeconds);
    this.fixture?.canaries.push(token);
    return token;
  }

  async close(): Promise<void> {
    // A base URL belongs to the caller. The fixture file/base server is not mutated here.
  }
}

export async function startAdapter(): Promise<ServerAdapter | null> {
  const sut = sutFromEnvironment();
  if (!sut) {
    return null;
  }

  if (sut === "ts") {
    const adapter = new TsServerAdapter();
    await adapter.start();
    return adapter;
  }

  if (sut === "base") {
    const adapter = new BaseUrlAdapter(process.env.CONTRACT_BASE_URL ?? "");
    await adapter.start();
    return adapter;
  }

  const rustBaseUrl = process.env.RUST_BASE_URL?.trim();
  if (rustBaseUrl) {
    const adapter = new BaseUrlAdapter(rustBaseUrl);
    await adapter.start();
    return adapter;
  }

  throw new Error("SUT=rust is reserved for P02; provide RUST_BASE_URL until the Rust launcher is implemented");
}

export async function startTsServerForBaseContract(): Promise<{
  baseUrl: string;
  fixture: ContractFixture;
  externalJwtPrivateJwk: JsonWebKey;
  close(): Promise<void>;
}> {
  const adapter = new TsServerAdapter();
  await adapter.start();
  return {
    baseUrl: adapter.baseUrl,
    fixture: adapter.fixture,
    externalJwtPrivateJwk: adapter.exportExternalJwtPrivateJwk(),
    close: () => adapter.close()
  };
}

export type { ServerAdapter, SupportedSut };
