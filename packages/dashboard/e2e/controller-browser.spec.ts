import { expect, test } from "@playwright/test";
import { spawn, type ChildProcess } from "node:child_process";
import net from "node:net";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { decrypt, destroyKeyPair, generateKeyPair } from "../../agent-skill/src/key-manager.js";
import { startAdapter } from "../../contract-tests/src/adapter.js";
import { httpRequest, jsonRequestBody, withBearer } from "../../contract-tests/src/http.js";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const browserUiDirectory = path.join(repositoryRoot, "packages/browser-ui");
const viteEntry = path.join(repositoryRoot, "node_modules/vite/bin/vite.js");
const humanE2eEntry = path.join(repositoryRoot, "scripts/e2e-human.mjs");

type StartedAdapter = NonNullable<Awaited<ReturnType<typeof startAdapter>>>;

let adapter: StartedAdapter;
let browserUiUrl = "";
let browserUiProcess: ChildProcess | undefined;
let browserUiOutput = "";

async function freePort(): Promise<number> {
  const server = net.createServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen({ host: "127.0.0.1", port: 0 }, resolve);
  });
  const address = server.address();
  if (!address || typeof address === "string") {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    throw new Error("could not reserve a browser test port");
  }
  const port = address.port;
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  return port;
}

async function waitForBrowserUi(timeoutMs = 30_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(browserUiUrl);
      if (response.ok) return;
    } catch {
      // The Vite process may not have opened its port yet.
    }
    await delay(100);
  }
  throw new Error(`browser UI did not start at ${browserUiUrl}; output: ${browserUiOutput}`);
}

async function stopBrowserUi(): Promise<void> {
  const child = browserUiProcess;
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  const exited = new Promise<void>((resolve) => child.once("exit", () => resolve()));
  child.kill("SIGTERM");
  await Promise.race([exited, delay(3_000)]);
  if (child.exitCode === null && child.signalCode === null) {
    child.kill("SIGKILL");
    await exited;
  }
}

function waitForExit(child: ChildProcess, timeoutMs: number): Promise<{ code: number | null; signal: NodeJS.Signals | null }> {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error("human E2E process did not exit after browser submission")), timeoutMs);
    child.once("exit", (code, signal) => {
      clearTimeout(timeout);
      resolve({ code, signal });
    });
    child.once("error", (error) => {
      clearTimeout(timeout);
      reject(error);
    });
  });
}

function findHumanLink(output: string): string | null {
  const clean = output.replace(/\u001b\[[0-9;]*m/g, "");
  const marker = "If not, open this URL manually:";
  const markerIndex = clean.indexOf(marker);
  if (markerIndex < 0) return null;
  return clean.slice(markerIndex + marker.length).match(/https?:\/\/[^\s]+/)?.[0] ?? null;
}

async function createBrowserRequest(description: string) {
  const keyPair = await generateKeyPair();
  const requester = adapter.fixture.agents.requester;
  const created = await httpRequest<{
    request_id: string;
    secret_url: string;
  }>(adapter.baseUrl, "/api/v2/secret/request", withBearer(requester.accessToken, jsonRequestBody({
    public_key: keyPair.publicKey,
    description
  })));

  if (created.status !== 201 || !created.body) {
    destroyKeyPair(keyPair);
    throw new Error(`Rust controller request creation failed: ${created.status}: ${created.text}`);
  }

  return {
    keyPair,
    requestId: created.body.request_id,
    requesterToken: requester.accessToken,
    secretUrl: created.body.secret_url
  };
}

test.beforeAll(async () => {
  if (process.env.SUT !== "rust") {
    throw new Error("CC03 requires SUT=rust");
  }

  const packagedUrl = process.env.P02_PACKAGED_BROWSER_UI_URL?.trim();
  const port = packagedUrl ? null : await freePort();
  browserUiUrl = packagedUrl || `http://127.0.0.1:${port}`;
  process.env.CONTRACT_UI_BASE_URL = browserUiUrl;
  process.env.CONTRACT_REQUEST_TTL_SECONDS = "8";
  process.env.CONTRACT_RUST_PORT = "3100";

  const started = await startAdapter();
  if (!started) throw new Error("Rust controller adapter did not start");
  adapter = started;

  if (packagedUrl) {
    await waitForBrowserUi();
    return;
  }

  browserUiProcess = spawn(
    process.execPath,
    [viteEntry, "--host", "127.0.0.1", "--port", String(port), "--strictPort"],
    {
      cwd: browserUiDirectory,
      env: { ...process.env, VITE_SPS_API_URL: adapter.baseUrl },
      stdio: ["ignore", "ignore", "pipe"]
    }
  );
  browserUiProcess.stderr?.on("data", (chunk: Buffer) => {
    browserUiOutput = `${browserUiOutput}${chunk.toString()}`.slice(-2_000);
  });

  try {
    await waitForBrowserUi();
  } catch (error) {
    await stopBrowserUi();
    await adapter.close();
    throw error;
  }
});

test.afterAll(async () => {
  await stopBrowserUi();
  await adapter?.close();
});

if (process.env.P02_PACKAGED_BROWSER_UI_URL) {
  test("CC03 packaged nginx serves the page with security headers", async ({ request }) => {
    const response = await request.get(browserUiUrl);
    expect(response.status()).toBe(200);
    expect(response.headers()["content-security-policy"]).toContain("connect-src 'self' http://127.0.0.1:3100");
    expect(response.headers()["permissions-policy"]).toContain("camera=()");
    expect(response.headers()["referrer-policy"]).toBe("no-referrer");
    expect(response.headers()["x-content-type-options"]).toBe("nosniff");
    expect(response.headers()["x-frame-options"]).toBe("DENY");
  });
}

test("CC02 runs scripts/e2e-human.mjs against Rust through the browser UI", async ({ page }) => {
  const bearerToken = adapter.externalJwt({
    sub: "e2e-human-agent",
    workspace_id: adapter.fixture.workspaceId,
    workload_mode: "external"
  });
  let humanOutput = "";
  const child = spawn(process.execPath, [humanE2eEntry], {
    cwd: repositoryRoot,
    env: {
      ...process.env,
      SPS_E2E_BASE_URL: adapter.baseUrl,
      SPS_E2E_BEARER_TOKEN: bearerToken,
      SPS_E2E_SKIP_BROWSER: "1",
      VITE_SPS_API_URL: adapter.baseUrl,
      VITE_SPS_UI_URL: browserUiUrl
    },
    stdio: ["ignore", "pipe", "pipe"]
  });
  child.stdout?.on("data", (chunk: Buffer) => {
    humanOutput = `${humanOutput}${chunk.toString()}`.slice(-20_000);
  });
  child.stderr?.on("data", (chunk: Buffer) => {
    humanOutput = `${humanOutput}${chunk.toString()}`.slice(-20_000);
  });

  const exited = waitForExit(child, 45_000);
  try {
    let secretUrl: string | null = null;
    const deadline = Date.now() + 15_000;
    while (!secretUrl && Date.now() < deadline) {
      secretUrl = findHumanLink(humanOutput);
      if (!secretUrl) await delay(50);
    }
    expect(secretUrl).toBeTruthy();
    await page.goto(secretUrl!);
    await expect(page.getByTestId("submit-btn")).toBeEnabled();
    await page.getByTestId("secret-input").fill("dummy-cc02-human-client");
    await page.getByTestId("submit-btn").click();
    await expect(page.getByTestId("success-message")).toBeVisible();

    const result = await exited;
    expect(result.code).toBe(0);
    expect(humanOutput).toContain("E2E Test Complete!");
    expect(humanOutput).toContain("PASS — second retrieve correctly returned 410 Gone");
  } finally {
    if (child.exitCode === null && child.signalCode === null) {
      child.kill("SIGTERM");
      await waitForExit(child, 3_000).catch(() => undefined);
    }
  }
});

test("CC03 loads a signed link, seals input in the page, and submits to Rust", async ({ page }) => {
  const request = await createBrowserRequest("P02 CC03 signed browser flow");
  const plaintext = "dummy-cc03-browser-secret";
  try {
    await page.goto(request.secretUrl);
    await expect(page.locator('meta[http-equiv="Content-Security-Policy"]')).toHaveAttribute("content", /connect-src[^;]*http:\/\/127\.0\.0\.1:3100/);
    await expect(page.getByTestId("submit-btn")).toBeEnabled();
    await page.getByTestId("secret-input").fill(plaintext);
    await page.getByTestId("submit-btn").click();
    await expect(page.getByTestId("success-message")).toBeVisible();

    const retrieved = await httpRequest<{
      enc: string;
      ciphertext: string;
    }>(adapter.baseUrl, `/api/v2/secret/retrieve/${request.requestId}`, withBearer(request.requesterToken));
    expect(retrieved.status).toBe(200);
    expect(retrieved.body).toBeTruthy();
    const opened = await decrypt(request.keyPair.privateKey, retrieved.body!.enc, retrieved.body!.ciphertext);
    expect(opened.toString("utf8")).toBe(plaintext);
  } finally {
    destroyKeyPair(request.keyPair);
  }
});

test("CC03 disables entry when a signed browser link has expired", async ({ page }) => {
  const request = await createBrowserRequest("P02 CC03 expired browser flow");
  try {
    await delay(8_300);
    await page.goto(request.secretUrl);
    await expect(page.getByTestId("submit-btn")).toBeDisabled();
  } finally {
    destroyKeyPair(request.keyPair);
  }
});
