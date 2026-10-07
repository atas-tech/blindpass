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

type SupportedSut = "rust";

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

interface ClockAnchorSnapshot {
  lastObservedMs: number;
  bootId: string | null;
  boottimeMs: number | null;
  hostWallMs: number | null;
  fencedAt: number | null;
}

interface ClockAnchorRow {
  last_observed_ms: number | string;
  boot_id: string | null;
  boottime_ms: number | string | null;
  host_wall_ms: number | string | null;
  fenced_at: number | string | null;
}

interface ServerAdapter {
  baseUrl: string;
  fixture: ContractFixture;
  externalJwt(claims?: Record<string, unknown>, nowSeconds?: number, omitClaims?: ReadonlyArray<"iss" | "aud">): string;
  restartController?(): Promise<void>;
  withReadinessFailure?<T>(run: () => Promise<T>): Promise<T>;
  close(): Promise<void>;
}

export interface RustCrashTestAdapter extends ServerAdapter {
  startWithFailpoint(name: string): Promise<void>;
  assertCrashAndRestart(): Promise<void>;
  bootstrapAdminSession(): Promise<{ cookie: string; csrfToken: string }>;
}

function sutFromEnvironment(): SupportedSut | null {
  const raw = process.env.SUT?.trim().toLowerCase();
  if (!raw) {
    return null;
  }
  if (raw !== "rust") {
    throw new Error(`SUT=${raw} is not supported: the TypeScript SPS comparison was retired; use SUT=rust`);
  }
  return raw;
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

function childExit(child: ChildProcess): Promise<void> {
  return new Promise((resolve) => {
    if (child.exitCode !== null || child.signalCode !== null) {
      resolve();
      return;
    }
    child.once("exit", () => resolve());
  });
}

function childExitStatus(child: ChildProcess): Promise<{ code: number | null; signal: NodeJS.Signals | null }> {
  if (child.exitCode !== null || child.signalCode !== null) {
    return Promise.resolve({ code: child.exitCode, signal: child.signalCode });
  }
  return new Promise((resolve) => {
    child.once("exit", (code, signal) => resolve({ code, signal }));
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

async function seedRustFixture(
  baseUrl: string,
  seedToken: string,
  hmacSecret: string,
  rootSecret: string,
  adminSession: { cookie: string; csrfToken: string },
  policy: { secret_registry: readonly unknown[]; exchange_policy: readonly unknown[] }
): Promise<ContractFixture> {
  const seed = await httpRequest<{
    workspace_id: string;
    user_id: string;
    agents: Record<string, string>;
  }>(baseUrl, "/api/v3/admin/test/seed", {
    ...jsonRequestBody({ agents: Object.values(AGENT_IDS), policy }),
    headers: {
      "content-type": "application/json",
      "x-blindpass-seed-token": seedToken
    }
  });
  if (seed.status !== 200 || !seed.body) {
    throw new Error(`Rust contract fixture seed failed with ${seed.status}: ${seed.text.slice(0, 500)}`);
  }

  const listed = await httpRequest<{ items: Array<{ id: string; agent_id: string }> }>(baseUrl, "/api/v3/admin/agents", {
    headers: { cookie: adminSession.cookie }
  });
  if (listed.status !== 200 || !listed.body) {
    throw new Error(`Rust contract fixture agent listing failed with ${listed.status}: ${listed.text.slice(0, 500)}`);
  }
  const agentRecordIds = Object.fromEntries(listed.body.items.map(({ id, agent_id }) => [agent_id, id]));

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
      throw new Error(`Rust fixture agent token failed for ${agentId}: ${token.status}: ${token.text.slice(0, 500)}`);
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
  canaries.push(seedToken, hmacSecret, rootSecret);
  for (const agent of Object.values(agents)) {
    canaries.push(agent.apiKey, agent.accessToken);
  }
  return {
    workspaceId: seed.body.workspace_id,
    userId: seed.body.user_id,
    adminSession,
    agentRecordIds,
    agents,
    baseUrl,
    hmacSecret,
    seedToken,
    canaries
  };
}

const CONTRACT_SCHEMA_COMMENT_PREFIX = "blindpass-contract-schema:v1:";
const STALE_SCHEMA_AGE_MS = 60 * 60 * 1000;

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

    throw new Error("RUST_BASE_URL requires CONTRACT_FIXTURE_FILE (scripts/tests/rust-base-contract.mjs writes one)");
  }

  externalJwt(claims: Record<string, unknown> = {}, nowSeconds?: number, omitClaims: ReadonlyArray<"iss" | "aud"> = []): string {
    const token = signExternalJwt(this.externalIdentity, {
      role: "gateway",
      sub: "contract-external/ring/blue",
      workspace_id: this.fixture.workspaceId,
      workload_mode: "external",
      ...claims
    }, nowSeconds, omitClaims);
    this.fixture?.canaries.push(token);
    return token;
  }

  async close(): Promise<void> {
    // A base URL belongs to the caller. The fixture file/base server is not mutated here.
  }
}

class RustServerAdapter implements RustCrashTestAdapter {
  baseUrl = "";
  fixture!: ContractFixture;
  private child: ChildProcess | null = null;
  private adminPool: PgPoolLike | null = null;
  private schemaLockClient: PgClientLike | null = null;
  private schema = "";
  private tempDir = "";
  private externalIdentity!: ExternalJwtIdentity;
  private executable = "";
  private childEnv: NodeJS.ProcessEnv = {};
  private adminSession: { cookie: string; csrfToken: string } | null = null;

  async start(): Promise<void> {
    try {
      await this.startIsolated();
    } catch (error) {
      await this.close();
      throw error;
    }
  }

  private async startIsolated(): Promise<void> {
    const backend = process.env.CONTRACT_RUST_BACKEND?.trim().toLowerCase();
    if (backend !== "sqlite" && backend !== "postgres") {
      throw new Error("SUT=rust requires CONTRACT_RUST_BACKEND=sqlite or postgres");
    }

    this.executable = process.env.CONTRACT_RUST_BIN?.trim()
      || path.join(process.env.CARGO_TARGET_DIR ? path.resolve(REPO_ROOT, process.env.CARGO_TARGET_DIR) : path.join(REPO_ROOT, "target"), "debug", process.platform === "win32" ? "blindpass-controller.exe" : "blindpass-controller");
    this.tempDir = await mkdtemp(path.join(os.tmpdir(), "blindpass-rust-contract-"));

    let databaseUrl: string;
    if (backend === "sqlite") {
      const databasePath = path.join(this.tempDir, "controller.db");
      databaseUrl = `sqlite://${databasePath}?mode=rwc`;
    } else {
      const parentDatabaseUrl = process.env.CONTRACT_DATABASE_URL?.trim() || process.env.DATABASE_URL?.trim();
      if (!parentDatabaseUrl) {
        throw new Error("SUT=rust with the postgres backend requires CONTRACT_DATABASE_URL or DATABASE_URL");
      }
      this.schema = randomIdentifier("contract_rust");
      this.adminPool = await loadPgPool(parentDatabaseUrl, 2);
      this.schemaLockClient = await this.adminPool.connect();
      await this.schemaLockClient.query(
        "SELECT pg_advisory_lock(hashtextextended($1, 0))",
        [schemaLockKey(this.schema)]
      );
      await this.adminPool.query(`CREATE SCHEMA ${quoteIdentifier(this.schema)}`);
      await this.adminPool.query(
        `COMMENT ON SCHEMA ${quoteIdentifier(this.schema)} IS '${CONTRACT_SCHEMA_COMMENT_PREFIX}${Date.now()}'`
      );
      databaseUrl = withSearchPath(parentDatabaseUrl, this.schema);
    }

    const jwksPath = path.join(this.tempDir, "jwks.json");
    this.externalIdentity = createExternalJwtIdentity();
    await writeFile(jwksPath, JSON.stringify({ keys: [this.externalIdentity.publicJwk] }), { mode: 0o600 });
    const rootSecretPath = path.join(this.tempDir, "root.secret");
    const agentSecretPath = path.join(this.tempDir, "agent-jwt.secret");
    const issuerSeedPath = path.join(this.tempDir, "issuer.seed");
    const rootSecret = randomBytes(32).toString("base64url");
    const agentSecret = randomBytes(32).toString("base64url");
    const seedToken = `contract-rust-seed-${randomBytes(32).toString("hex")}`;
    const rustPolicy = {
      secret_registry: POLICY_DOCUMENT.secret_registry,
      exchange_policy: POLICY_DOCUMENT.exchange_policy.map((rule) => rule.ruleId === "contract-approval"
        ? { ...rule, approverIds: ["p02-admin"] }
        : rule)
    };
    await writeFile(rootSecretPath, rootSecret, { mode: 0o600 });
    await writeFile(agentSecretPath, agentSecret, { mode: 0o600 });
    await writeFile(issuerSeedPath, randomBytes(32), { mode: 0o600 });

    const configuredPort = process.env.CONTRACT_RUST_PORT?.trim();
    const port = configuredPort ? Number(configuredPort) : await freeTcpPort();
    if (!Number.isInteger(port) || port < 1 || port > 65_535) {
      throw new Error("CONTRACT_RUST_PORT must be a valid TCP port");
    }
    this.baseUrl = `http://127.0.0.1:${port}`;
    const uiBaseUrl = process.env.CONTRACT_UI_BASE_URL?.trim() || "http://127.0.0.1:5175";
    const allowedOrigins = [...new Set([
      new URL(uiBaseUrl).origin,
      "http://allowed.contract.test"
    ])].join(",");
    this.childEnv = {
      PATH: process.env.PATH,
      TMPDIR: process.env.TMPDIR,
      LANG: process.env.LANG,
      TZ: process.env.TZ,
      NODE_ENV: "test",
      RUST_LOG: "warn",
      BLINDPASS_LISTEN: `127.0.0.1:${port}`,
      BLINDPASS_ADMIN_SOCKET_PATH: path.join(this.tempDir, "admin.sock"),
      BLINDPASS_PUBLIC_URL: this.baseUrl,
      BLINDPASS_UI_BASE_URL: uiBaseUrl,
      BLINDPASS_DATABASE_URL: databaseUrl,
      BLINDPASS_ROOT_SECRET_FILE: rootSecretPath,
      BLINDPASS_AGENT_JWT_SECRET_FILE: agentSecretPath,
      BLINDPASS_ISSUER_KEY_FILE: issuerSeedPath,
      BLINDPASS_AGENT_AUTH_PROVIDERS_JSON: JSON.stringify([{
        name: "contract-jwks",
        jwks_file: jwksPath,
        issuer: "contract-gateway",
        audience: "contract-sps"
      }, {
        name: "contract-jwks-alt",
        jwks_file: jwksPath,
        issuer: "contract-gateway-alt",
        audience: "contract-sps"
      }]),
      BLINDPASS_CORS_ALLOWED_ORIGINS: allowedOrigins,
      BLINDPASS_BODY_LIMIT_BYTES: "1048576",
      BLINDPASS_AGENT_TOKEN_RATE_LIMIT: "5",
      BLINDPASS_AGENT_REQUEST_RATE_LIMIT: process.env.CONTRACT_AGENT_REQUEST_RATE_LIMIT ?? "60",
      BLINDPASS_AGENT_EXCHANGE_RATE_LIMIT: process.env.CONTRACT_AGENT_EXCHANGE_RATE_LIMIT
        ?? process.env.CONTRACT_AGENT_REQUEST_RATE_LIMIT
        ?? "60",
      BLINDPASS_TRUST_PROXY: "127.0.0.1",
      BLINDPASS_SECRET_REGISTRY_JSON: JSON.stringify(rustPolicy.secret_registry),
      BLINDPASS_EXCHANGE_POLICY_JSON: JSON.stringify(rustPolicy.exchange_policy),
      BLINDPASS_LOG_FORMAT: "json",
      BLINDPASS_TEST_MODE: "1",
      BLINDPASS_TEST_SEED_TOKEN: seedToken,
      BLINDPASS_TEST_REQUEST_TTL_SECONDS: process.env.CONTRACT_REQUEST_TTL_SECONDS ?? "8",
      BLINDPASS_TEST_SUBMITTED_TTL_SECONDS: process.env.CONTRACT_SUBMITTED_TTL_SECONDS ?? "3",
      BLINDPASS_TEST_REVOKED_TTL_SECONDS: process.env.CONTRACT_REVOKED_TTL_SECONDS ?? "4",
      BLINDPASS_TEST_APPROVAL_TTL_SECONDS: process.env.CONTRACT_APPROVAL_TTL_SECONDS ?? "20",
      BLINDPASS_TEST_REFRESH_TOKEN_TTL_SECONDS: process.env.CONTRACT_REFRESH_TOKEN_TTL_SECONDS ?? "180",
      BLINDPASS_TEST_AGENT_TOKEN_RATE_WINDOW_MS: process.env.CONTRACT_AGENT_TOKEN_RATE_WINDOW_MS ?? "1000",
      BLINDPASS_TEST_AGENT_RATE_WINDOW_MS: process.env.CONTRACT_AGENT_RATE_WINDOW_MS ?? "1000"
    };

    try {
      await this.launchController();
      const adminSession = await this.bootstrapAdminSession();
      this.fixture = await seedRustFixture(this.baseUrl, seedToken, rootSecret, rootSecret, adminSession, rustPolicy);
    } catch {
      await this.close();
      throw new Error("Rust controller failed to become healthy; check its config and process startup without exposing credentials");
    }
  }

  externalJwt(claims: Record<string, unknown> = {}, nowSeconds?: number, omitClaims: ReadonlyArray<"iss" | "aud"> = []): string {
    const token = signExternalJwt(this.externalIdentity, {
      role: "gateway",
      sub: "contract-external/ring/blue",
      workspace_id: this.fixture.workspaceId,
      workload_mode: "external",
      ...claims
    }, nowSeconds, omitClaims);
    this.fixture?.canaries.push(token);
    return token;
  }

  async startWithFailpoint(name: string): Promise<void> {
    if (this.child) {
      await stopChild(this.child);
      this.child = null;
    }
    await this.launchController(name);
  }

  async restartController(): Promise<void> {
    if (this.child) {
      await stopChild(this.child);
      this.child = null;
    }
    await this.launchController();
  }

  // The controller fails closed while its persisted clock mark is ahead of the
  // database clock (P02-D9). Moving the mark an hour ahead gives CT18 the real
  // Rust readiness failure on either store without stopping the shared
  // database; the previous mark is restored afterwards.
  async withReadinessFailure<T>(run: () => Promise<T>): Promise<T> {
    const previous = await this.replaceClockMark(Date.now() + 3_600_000);
    try {
      return await run();
    } finally {
      await this.restoreClockAnchor(previous);
    }
  }

  private async replaceClockMark(value: number): Promise<ClockAnchorSnapshot> {
    if (this.adminPool) {
      const table = `${quoteIdentifier(this.schema)}.controller_clock`;
      const result = await this.adminPool.query<ClockAnchorRow>(
        `WITH previous AS (SELECT last_observed_ms, boot_id, boottime_ms, host_wall_ms, fenced_at FROM ${table} WHERE id = 1 FOR UPDATE)
        UPDATE ${table} SET last_observed_ms = $1 FROM previous WHERE ${table}.id = 1
        RETURNING previous.last_observed_ms, previous.boot_id, previous.boottime_ms,
          previous.host_wall_ms, previous.fenced_at`,
        [value]
      );
      if (result.rows.length !== 1) {
        throw new Error("Rust controller clock mark is missing");
      }
      const row = result.rows[0]!;
      return {
        lastObservedMs: Number(row.last_observed_ms),
        bootId: row.boot_id,
        boottimeMs: row.boottime_ms === null ? null : Number(row.boottime_ms),
        hostWallMs: row.host_wall_ms === null ? null : Number(row.host_wall_ms),
        fencedAt: row.fenced_at === null ? null : Number(row.fenced_at)
      };
    }
    const { DatabaseSync } = await import("node:sqlite");
    const database = new DatabaseSync(path.join(this.tempDir, "controller.db"));
    try {
      database.exec("PRAGMA busy_timeout = 5000");
      database.exec("BEGIN IMMEDIATE");
      try {
        const row = database.prepare(
          "SELECT last_observed_ms, boot_id, boottime_ms, host_wall_ms, fenced_at FROM controller_clock WHERE id = 1"
        ).get() as ClockAnchorRow | undefined;
        if (!row) {
          throw new Error("Rust controller clock mark is missing");
        }
        database.prepare("UPDATE controller_clock SET last_observed_ms = ? WHERE id = 1").run(value);
        database.exec("COMMIT");
        return {
          lastObservedMs: Number(row.last_observed_ms),
          bootId: row.boot_id,
          boottimeMs: row.boottime_ms === null ? null : Number(row.boottime_ms),
          hostWallMs: row.host_wall_ms === null ? null : Number(row.host_wall_ms),
          fencedAt: row.fenced_at === null ? null : Number(row.fenced_at)
        };
      } catch (error) {
        database.exec("ROLLBACK");
        throw error;
      }
    } finally {
      database.close();
    }
  }

  private async restoreClockAnchor(anchor: ClockAnchorSnapshot): Promise<void> {
    if (this.adminPool) {
      const table = `${quoteIdentifier(this.schema)}.controller_clock`;
      await this.adminPool.query(
        `UPDATE ${table} SET last_observed_ms = $1, boot_id = $2, boottime_ms = $3,
          host_wall_ms = $4, fenced_at = $5 WHERE id = 1`,
        [anchor.lastObservedMs, anchor.bootId, anchor.boottimeMs, anchor.hostWallMs, anchor.fencedAt]
      );
      return;
    }
    const { DatabaseSync } = await import("node:sqlite");
    const database = new DatabaseSync(path.join(this.tempDir, "controller.db"));
    try {
      database.exec("PRAGMA busy_timeout = 5000");
      database.prepare(
        "UPDATE controller_clock SET last_observed_ms = ?, boot_id = ?, boottime_ms = ?, host_wall_ms = ?, fenced_at = ? WHERE id = 1"
      ).run(anchor.lastObservedMs, anchor.bootId, anchor.boottimeMs, anchor.hostWallMs, anchor.fencedAt);
    } finally {
      database.close();
    }
  }

  async assertCrashAndRestart(): Promise<void> {
    if (!this.child) {
      throw new Error("Rust crash test adapter has no controller process to inspect");
    }
    const crashedChild = this.child;
    let timeoutHandle: NodeJS.Timeout | undefined;
    const timeout = new Promise<never>((_, reject) => {
      timeoutHandle = setTimeout(() => reject(new Error("Rust controller did not exit at the armed P02 failpoint")), 10_000);
    });
    let result: { code: number | null; signal: NodeJS.Signals | null };
    try {
      result = await Promise.race([childExitStatus(crashedChild), timeout]);
    } finally {
      if (timeoutHandle) clearTimeout(timeoutHandle);
    }
    if (result.code !== 86) {
      throw new Error(`Rust controller exited unexpectedly at the P02 failpoint (code=${result.code}, signal=${result.signal})`);
    }
    this.child = null;
    await this.launchController();
  }

  async bootstrapAdminSession(): Promise<{ cookie: string; csrfToken: string }> {
    if (this.adminSession) {
      return this.adminSession;
    }
    const socketPath = path.join(this.tempDir, "admin.sock");
    const socketResponse = await new Promise<Record<string, unknown>>((resolve, reject) => {
      const socket = net.createConnection(socketPath);
      let response = "";
      socket.once("connect", () => socket.write('{"command":"bootstrap-token"}\n'));
      socket.on("data", (chunk: Buffer) => { response += chunk.toString(); });
      socket.once("error", reject);
      socket.once("end", () => {
        try {
          resolve(JSON.parse(response) as Record<string, unknown>);
        } catch {
          reject(new Error("Rust local admin socket returned an invalid bootstrap response"));
        }
      });
    });
    const bootstrapToken = socketResponse.bootstrap_token;
    if (typeof bootstrapToken !== "string") {
      throw new Error("Rust local admin socket did not issue a bootstrap capability");
    }
    const origin = "http://allowed.contract.test";
    const response = await httpRequest<Record<string, unknown>>(this.baseUrl, "/api/v3/admin/bootstrap", {
      ...jsonRequestBody({ username: "p02-admin", display_name: "P02 test admin", password: "p02-local-test-password-2026" }),
      headers: {
        "content-type": "application/json",
        "x-blindpass-bootstrap-token": bootstrapToken,
        origin
      }
    });
    const csrfToken = response.body?.csrf_token;
    if (response.status !== 201 || typeof csrfToken !== "string") {
      throw new Error(`Rust local admin bootstrap failed with ${response.status}`);
    }
    const cookieHeaders = (response.headers as Headers & { getSetCookie?: () => string[] }).getSetCookie?.()
      ?? [response.headers.get("set-cookie") ?? ""];
    const cookies = cookieHeaders
      .map((value) => value.split(";", 1)[0] ?? "")
      .filter((value) => value.startsWith("bp_session=") || value.startsWith("bp_csrf="));
    if (!cookies.some((value) => value.startsWith("bp_session=")) || !cookies.some((value) => value.startsWith("bp_csrf="))) {
      throw new Error("Rust local admin bootstrap did not return session and CSRF cookies");
    }
    this.adminSession = { cookie: cookies.join("; "), csrfToken };
    return this.adminSession;
  }

  private async launchController(failpoint?: string): Promise<void> {
    const env = failpoint
      ? { ...this.childEnv, BLINDPASS_TEST_FAILPOINT: failpoint }
      : this.childEnv;
    this.child = spawn(this.executable, ["serve"], {
      cwd: REPO_ROOT,
      env,
      stdio: ["ignore", "ignore", "pipe"]
    });
    this.child.stderr?.on("data", () => undefined);
    await waitForHttp(this.baseUrl);
  }

  exportExternalJwtPrivateJwk(): JsonWebKey {
    return this.externalIdentity.privateKey.export({ format: "jwk" }) as JsonWebKey;
  }

  async close(): Promise<void> {
    if (this.child) {
      await stopChild(this.child);
      this.child = null;
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
}

export async function startAdapter(): Promise<ServerAdapter | null> {
  if (!sutFromEnvironment()) {
    return null;
  }

  const rustBaseUrl = process.env.RUST_BASE_URL?.trim();
  if (rustBaseUrl) {
    const adapter = new BaseUrlAdapter(rustBaseUrl);
    await adapter.start();
    return adapter;
  }

  const adapter = new RustServerAdapter();
  await adapter.start();
  return adapter;
}

export async function startRustCrashTestAdapter(): Promise<RustCrashTestAdapter> {
  if (sutFromEnvironment() !== "rust" || process.env.RUST_BASE_URL?.trim()) {
    throw new Error("P02 crash-recovery tests require a harness-spawned Rust controller");
  }
  const adapter = new RustServerAdapter();
  await adapter.start();
  return adapter;
}

// Starts the Rust controller exactly as SUT=rust does and hands its address and fixture to a caller that runs the
// suite against the base URL (scripts/tests/rust-base-contract.mjs). The suite then holds only an HTTP address,
// so cases that need harness control of the server (readiness failure, restart, a second rate-limited instance)
// are not part of that run.
export async function startRustServerForBaseContract(): Promise<{
  baseUrl: string;
  fixture: ContractFixture;
  externalJwtPrivateJwk: JsonWebKey;
  close(): Promise<void>;
}> {
  const adapter = new RustServerAdapter();
  await adapter.start();
  return {
    baseUrl: adapter.baseUrl,
    fixture: adapter.fixture,
    externalJwtPrivateJwk: adapter.exportExternalJwtPrivateJwk(),
    close: () => adapter.close()
  };
}

export type { ServerAdapter, SupportedSut };
