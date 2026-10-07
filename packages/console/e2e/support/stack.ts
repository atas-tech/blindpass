// Starts an isolated Rust controller (SQLite, test mode, fleet issuer key)
// and serves the built console from `vite preview` with a same-origin API
// proxy, mirroring the embedded deployment. With `embedded`, the controller
// serves the console itself from the assets it was built with (P04-D9).
// Generated secrets stay in a private temp directory removed on stop().
// BLINDPASS_E2E_POSTGRES_URL runs the controller on PostgreSQL in a
// throwaway schema instead of a temporary SQLite file.
import { spawn, type ChildProcess } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";

export const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../..");
const CONSOLE_DIR = path.join(REPO_ROOT, "packages/console");
const VITE = path.join(REPO_ROOT, "node_modules/vite/bin/vite.js");

export const SECRET_NAMES = {
  approval: "e2e.approval_api_key",
  allowed: "e2e.allowed_api_key"
} as const;

export const AGENT_IDS = {
  requester: "e2e-requester",
  fulfiller: "e2e-fulfiller"
} as const;

export const ADMIN = { username: "e2e-admin", display_name: "E2E Administrator", password: "e2e-admin-password-2026" };

export interface StackOptions {
  /** Start with no administrator so /setup is reachable. */
  fresh?: boolean;
  fleet?: boolean;
  /** Turn on cross-workload fulfillment (BLINDPASS_FULFILLMENTS_ENABLED=1); off by default as in production. */
  fulfillments?: boolean;
  approvalTtlSeconds?: number;
  refreshTtlSeconds?: number;
  requestTtlSeconds?: number;
  /** Extra origin allowed by CORS/Origin checks (the input page). */
  uiBaseUrl?: string;
  consoleDist?: string;
  /**
   * Use the console the controller embeds instead of `vite preview`. Defaults
   * to BLINDPASS_E2E_EMBEDDED=1 for stacks without a separate input origin,
   * so `npm run test:e2e:embedded` runs the console journeys on the embedded
   * build.
   */
  embedded?: boolean;
}

interface PgPool {
  query(text: string): Promise<unknown>;
  end(): Promise<void>;
}

/** A throwaway schema, as the contract adapter does (hoisted `pg`, search_path). */
async function postgresSchema(databaseUrl: string): Promise<{ url: string; drop: () => Promise<void> }> {
  const pg = (await import("pg")) as unknown as { default: { Pool: new (options: { connectionString: string; max: number }) => PgPool } };
  const pool = new pg.default.Pool({ connectionString: databaseUrl, max: 1 });
  const schema = `console_e2e_${process.pid}_${randomBytes(5).toString("hex")}`;
  await pool.query(`CREATE SCHEMA "${schema}"`);
  const url = new URL(databaseUrl);
  url.searchParams.set("options", `-c search_path=${schema}`);
  return {
    url: url.toString(),
    drop: async () => {
      await pool.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`).catch(() => undefined);
      await pool.end();
    }
  };
}

export async function freePort(): Promise<number> {
  const server = net.createServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen({ host: "127.0.0.1", port: 0 }, resolve);
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("no port");
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return address.port;
}

async function waitFor(url: string, child: ChildProcess, output: () => string, timeoutMs = 30_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`process exited early (${child.exitCode}): ${output()}`);
    try {
      const response = await fetch(url);
      if (response.status < 500) return;
    } catch {
      // not listening yet
    }
    await delay(100);
  }
  throw new Error(`timed out waiting for ${url}: ${output()}`);
}

async function stop(child: ChildProcess | null): Promise<void> {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  const exited = new Promise<void>((resolve) => child.once("exit", () => resolve()));
  child.kill("SIGTERM");
  await Promise.race([exited, delay(3_000)]);
  if (child.exitCode === null && child.signalCode === null) {
    child.kill("SIGKILL");
    await exited;
  }
}

export class Stack {
  controllerUrl = "";
  consoleUrl = "";
  readonly seedToken = `e2e-seed-${randomBytes(24).toString("hex")}`;
  private tempDir = "";
  private controller: ChildProcess | null = null;
  private preview: ChildProcess | null = null;
  private controllerOutput = "";
  private previewOutput = "";
  private env: NodeJS.ProcessEnv = {};
  private dropSchema: (() => Promise<void>) | null = null;

  static async start(options: StackOptions = {}): Promise<Stack> {
    const stack = new Stack();
    try {
      await stack.boot(options);
    } catch (error) {
      await stack.stop();
      throw error;
    }
    return stack;
  }

  /** The private temporary directory holding the SQLite file (absent for PostgreSQL) and secrets. */
  get dataDirectory(): string {
    return this.tempDir;
  }

  /** Whether this stack's database is a PostgreSQL schema rather than a SQLite file. */
  get usesPostgres(): boolean {
    return this.dropSchema !== null;
  }

  /** The tail of the controller's own stdout/stderr, for leak scans. */
  controllerLog(): string {
    return this.controllerOutput;
  }

  get adminSocket(): string {
    return path.join(this.tempDir, "admin.sock");
  }

  private async boot(options: StackOptions): Promise<void> {
    const embedded = options.embedded ?? (process.env.BLINDPASS_E2E_EMBEDDED === "1" && !options.uiBaseUrl);
    this.tempDir = await mkdtemp(path.join(os.tmpdir(), "blindpass-console-e2e-"));
    const controllerPort = await freePort();
    const consolePort = await freePort();
    this.controllerUrl = `http://127.0.0.1:${controllerPort}`;
    this.consoleUrl = embedded ? this.controllerUrl : `http://127.0.0.1:${consolePort}`;
    const rootSecret = path.join(this.tempDir, "root.secret");
    const agentSecret = path.join(this.tempDir, "agent-jwt.secret");
    await writeFile(rootSecret, randomBytes(32).toString("base64url"), { mode: 0o600 });
    await writeFile(agentSecret, randomBytes(32).toString("base64url"), { mode: 0o600 });
    const issuer = path.join(this.tempDir, "issuer.seed");
    if (options.fleet !== false) await writeFile(issuer, randomBytes(32), { mode: 0o600 });

    const registry = [
      { secretName: SECRET_NAMES.approval, classification: "sensitive", description: "Dummy approval canary for console E2E." },
      { secretName: SECRET_NAMES.allowed, classification: "internal", description: "Dummy allowed canary for console E2E." }
    ];
    const policy = [
      {
        ruleId: "e2e-approval",
        secretName: SECRET_NAMES.approval,
        requesterIds: [AGENT_IDS.requester],
        fulfillerIds: [AGENT_IDS.fulfiller],
        approverIds: [ADMIN.username, "e2e-operator"],
        mode: "pending_approval",
        reason: "Console E2E approval fixture"
      },
      {
        ruleId: "e2e-allow",
        secretName: SECRET_NAMES.allowed,
        requesterIds: [AGENT_IDS.requester],
        fulfillerIds: [AGENT_IDS.fulfiller],
        mode: "allow",
        reason: "Console E2E allow fixture"
      }
    ];
    const uiBase = options.uiBaseUrl ?? this.consoleUrl;
    let databaseUrl = `sqlite://${path.join(this.tempDir, "controller.db")}?mode=rwc`;
    if (process.env.BLINDPASS_E2E_POSTGRES_URL) {
      const schema = await postgresSchema(process.env.BLINDPASS_E2E_POSTGRES_URL);
      this.dropSchema = schema.drop;
      databaseUrl = schema.url;
    }
    this.env = {
      PATH: process.env.PATH,
      TMPDIR: process.env.TMPDIR,
      LANG: process.env.LANG,
      RUST_LOG: "warn",
      BLINDPASS_LISTEN: `127.0.0.1:${controllerPort}`,
      BLINDPASS_ADMIN_SOCKET_PATH: this.adminSocket,
      BLINDPASS_PUBLIC_URL: this.controllerUrl,
      BLINDPASS_UI_BASE_URL: uiBase,
      BLINDPASS_CORS_ALLOWED_ORIGINS: [...new Set([this.consoleUrl, uiBase])].join(","),
      BLINDPASS_DATABASE_URL: databaseUrl,
      BLINDPASS_ROOT_SECRET_FILE: rootSecret,
      BLINDPASS_AGENT_JWT_SECRET_FILE: agentSecret,
      ...(options.fleet !== false ? { BLINDPASS_ISSUER_KEY_FILE: issuer } : {}),
      ...(options.fulfillments ? { BLINDPASS_FULFILLMENTS_ENABLED: "1" } : {}),
      BLINDPASS_BODY_LIMIT_BYTES: "1048576",
      BLINDPASS_TRUST_PROXY: "127.0.0.1",
      BLINDPASS_SECRET_REGISTRY_JSON: JSON.stringify(registry),
      BLINDPASS_EXCHANGE_POLICY_JSON: JSON.stringify(policy),
      BLINDPASS_LOG_FORMAT: "json",
      BLINDPASS_TEST_MODE: "1",
      BLINDPASS_TEST_SEED_TOKEN: this.seedToken,
      BLINDPASS_TEST_REQUEST_TTL_SECONDS: String(options.requestTtlSeconds ?? 180),
      BLINDPASS_TEST_SUBMITTED_TTL_SECONDS: "60",
      BLINDPASS_TEST_REVOKED_TTL_SECONDS: "60",
      BLINDPASS_TEST_APPROVAL_TTL_SECONDS: String(options.approvalTtlSeconds ?? 600),
      BLINDPASS_TEST_REFRESH_TOKEN_TTL_SECONDS: String(options.refreshTtlSeconds ?? 3600),
      BLINDPASS_AGENT_TOKEN_RATE_LIMIT: "50",
      BLINDPASS_AGENT_REQUEST_RATE_LIMIT: "200",
      BLINDPASS_AGENT_EXCHANGE_RATE_LIMIT: "200"
    };
    await this.startController();
    if (embedded) return;

    this.preview = spawn(process.execPath, [VITE, "preview", "--host", "127.0.0.1", "--port", String(consolePort), "--strictPort", ...(options.consoleDist ? ["--outDir", options.consoleDist] : [])], {
      cwd: CONSOLE_DIR,
      env: { ...process.env, BLINDPASS_CONTROLLER_URL: this.controllerUrl },
      stdio: ["ignore", "pipe", "pipe"]
    });
    this.preview.stdout?.on("data", (chunk: Buffer) => (this.previewOutput = `${this.previewOutput}${chunk}`.slice(-4000)));
    this.preview.stderr?.on("data", (chunk: Buffer) => (this.previewOutput = `${this.previewOutput}${chunk}`.slice(-4000)));
    await waitFor(this.consoleUrl, this.preview, () => this.previewOutput);
  }

  /** Start the controller; `binary` swaps in another artifact on the same database. */
  async startController(binary = process.env.CONTRACT_RUST_BIN ?? path.join(REPO_ROOT, "target/debug/blindpass-controller")): Promise<void> {
    this.controllerOutput = "";
    this.controller = spawn(binary, ["serve"], { env: this.env, stdio: ["ignore", "pipe", "pipe"] });
    this.controller.stdout?.on("data", (chunk: Buffer) => (this.controllerOutput = `${this.controllerOutput}${chunk}`.slice(-4000)));
    this.controller.stderr?.on("data", (chunk: Buffer) => (this.controllerOutput = `${this.controllerOutput}${chunk}`.slice(-4000)));
    await waitFor(`${this.controllerUrl}/readyz`, this.controller, () => this.controllerOutput);
  }

  async stopController(): Promise<void> {
    await stop(this.controller);
    this.controller = null;
  }

  async stop(): Promise<void> {
    await stop(this.preview);
    await stop(this.controller);
    await this.dropSchema?.();
    if (this.tempDir) await rm(this.tempDir, { recursive: true, force: true });
  }

  /** One-use setup capability from the private administration socket. */
  async bootstrapToken(): Promise<string> {
    const response = await new Promise<Record<string, unknown>>((resolve, reject) => {
      const socket = net.createConnection(this.adminSocket);
      let body = "";
      socket.once("connect", () => socket.write('{"command":"bootstrap-token"}\n'));
      socket.on("data", (chunk: Buffer) => (body += chunk.toString()));
      socket.once("error", reject);
      socket.once("end", () => {
        try {
          resolve(JSON.parse(body) as Record<string, unknown>);
        } catch {
          reject(new Error("admin socket returned invalid JSON"));
        }
      });
    });
    if (typeof response.bootstrap_token !== "string") throw new Error("no bootstrap token issued");
    return response.bootstrap_token;
  }

  /** Test-mode seed: create agents and return their one-time API keys. */
  async seedAgents(agents: string[]): Promise<Record<string, string>> {
    const response = await fetch(`${this.controllerUrl}/api/v3/admin/test/seed`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-blindpass-seed-token": this.seedToken },
      body: JSON.stringify({ agents })
    });
    if (response.status !== 200) throw new Error(`seed failed: ${response.status} ${await response.text()}`);
    return ((await response.json()) as { agents: Record<string, string> }).agents;
  }

  async agentToken(apiKey: string): Promise<string> {
    const response = await fetch(`${this.controllerUrl}/api/v2/agents/token`, {
      method: "POST",
      headers: { authorization: `Bearer ${apiKey}` }
    });
    if (response.status !== 200) throw new Error(`agent token failed: ${response.status}`);
    return ((await response.json()) as { access_token: string }).access_token;
  }

  /** An agent asks for the approval-gated secret; the controller creates a pending approval. */
  async requestExchange(agentAccessToken: string, purpose: string, secretName: string = SECRET_NAMES.approval) {
    const response = await fetch(`${this.controllerUrl}/api/v2/secret/exchange/request`, {
      method: "POST",
      headers: { authorization: `Bearer ${agentAccessToken}`, "content-type": "application/json" },
      body: JSON.stringify({ public_key: "ZTJlLXB1YmxpYy1rZXk=", secret_name: secretName, purpose, fulfiller_hint: AGENT_IDS.fulfiller })
    });
    // An approval-gated request answers 403 with the pending approval
    // reference; an allowed one answers 201 with the exchange.
    const body = (await response.json()) as { exchange_id?: string; approval_status?: string; policy: { approval_reference: string | null; mode: string } };
    const pending = response.status === 403 && body.approval_status === "pending" && body.policy?.approval_reference;
    if (response.status !== 201 && !pending) throw new Error(`exchange request failed: ${response.status}`);
    return body;
  }
}

/** Minimal cookie-carrying admin client for arranging state outside the UI. */
export class AdminClient {
  private cookies = new Map<string, string>();
  csrf = "";

  constructor(private readonly stack: Stack) {}

  private cookieHeader(): string {
    return [...this.cookies.entries()].map(([key, value]) => `${key}=${value}`).join("; ");
  }

  private absorb(response: Response): void {
    for (const header of response.headers.getSetCookie()) {
      const [pair] = header.split(";");
      const [key, ...rest] = (pair ?? "").split("=");
      if (!key) continue;
      const value = rest.join("=");
      if (/Max-Age=0/i.test(header) || !value) this.cookies.delete(key.trim());
      else this.cookies.set(key.trim(), value);
    }
  }

  async call<T = unknown>(method: string, route: string, body?: unknown, headers: Record<string, string> = {}): Promise<{ status: number; body: T }> {
    const response = await fetch(`${this.stack.controllerUrl}${route}`, {
      method,
      headers: {
        origin: this.stack.consoleUrl,
        cookie: this.cookieHeader(),
        ...(this.csrf ? { "x-csrf-token": this.csrf } : {}),
        ...(body === undefined ? {} : { "content-type": "application/json" }),
        ...headers
      },
      body: body === undefined ? undefined : JSON.stringify(body)
    });
    this.absorb(response);
    const text = await response.text();
    return { status: response.status, body: (text ? JSON.parse(text) : undefined) as T };
  }

  async bootstrap(credentials = ADMIN): Promise<void> {
    const token = await this.stack.bootstrapToken();
    const result = await this.call<{ csrf_token: string }>("POST", "/api/v3/admin/bootstrap", credentials, { "x-blindpass-bootstrap-token": token });
    if (result.status !== 201) throw new Error(`bootstrap failed: ${result.status}`);
    this.csrf = result.body.csrf_token;
  }

  async login(username: string, password: string): Promise<number> {
    const pre = randomBytes(16).toString("hex");
    this.cookies.set("bp_csrf", pre);
    this.csrf = pre;
    const result = await this.call<{ csrf_token: string }>("POST", "/api/v3/admin/session/login", { username, password });
    if (result.status === 200) this.csrf = result.body.csrf_token;
    return result.status;
  }

  /** Create an operator and return the password it was created with. */
  async createOperator(username: string, role: "admin" | "operator" | "viewer", display_name = username): Promise<{ id: string; password: string }> {
    const password = `pw-${randomBytes(12).toString("hex")}`;
    const result = await this.call<{ id: string }>("POST", "/api/v3/admin/operators", { username, display_name, role, password });
    if (result.status !== 201) throw new Error(`operator create failed: ${result.status}`);
    return { id: result.body.id, password };
  }
}
