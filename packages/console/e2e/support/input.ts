// The P04 secret-input page against a real Rust controller. By default the
// page is built for the controller's origin and served from its own origin,
// the separately hosted compatibility profile. With `embedded`, the
// controller serves its embedded same-origin copy (P04-D9).
import { spawn, type ChildProcess } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { AeadId, CipherSuite, KdfId, KemId } from "hpke-js";
import { freePort, REPO_ROOT, Stack, type StackOptions } from "./stack.js";

const INPUT_DIR = path.join(REPO_ROOT, "packages/browser-ui");
const VITE = path.join(REPO_ROOT, "node_modules/vite/bin/vite.js");
const suite = new CipherSuite({ kem: KemId.DhkemX25519HkdfSha256, kdf: KdfId.HkdfSha256, aead: AeadId.Chacha20Poly1305 });

function run(args: string[], env: NodeJS.ProcessEnv): Promise<string> {
  return new Promise((resolve, reject) => {
    let output = "";
    const child = spawn(process.execPath, args, { cwd: INPUT_DIR, env: { ...process.env, ...env }, stdio: ["ignore", "pipe", "pipe"] });
    child.stdout?.on("data", (chunk: Buffer) => (output += chunk));
    child.stderr?.on("data", (chunk: Buffer) => (output += chunk));
    child.once("exit", (code) => (code === 0 ? resolve(output) : reject(new Error(`vite ${args.join(" ")} failed (${code}): ${output}`))));
  });
}

async function stopChild(child: ChildProcess | null): Promise<void> {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  const exited = new Promise<void>((resolve) => child.once("exit", () => resolve()));
  child.kill("SIGTERM");
  await Promise.race([exited, new Promise((resolve) => setTimeout(resolve, 3000))]);
  if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
}

function bytes(base64: string): ArrayBuffer {
  return Uint8Array.from(Buffer.from(base64, "base64")).buffer;
}

export interface SecretRequest {
  requestId: string;
  confirmationCode: string;
  secretUrl: string;
  /** Opens a retrieved payload with the requester's private key. */
  open: (payload: { enc: string; ciphertext: string }) => Promise<Uint8Array>;
}

export class InputStack {
  stack!: Stack;
  inputUrl = "";
  private preview: ChildProcess | null = null;
  private outDir = "";
  private requesterToken = "";
  private otherToken = "";

  static async start(options: StackOptions = {}): Promise<InputStack> {
    const input = new InputStack();
    try {
      await input.boot(options);
    } catch (error) {
      await input.stop();
      throw error;
    }
    return input;
  }

  private async boot(options: StackOptions): Promise<void> {
    if (options.embedded) {
      this.stack = await Stack.start(options);
      this.inputUrl = this.stack.controllerUrl;
      await this.seed();
      return;
    }
    const port = await freePort();
    this.inputUrl = `http://127.0.0.1:${port}`;
    this.stack = await Stack.start({ ...options, uiBaseUrl: this.inputUrl });
    this.outDir = await mkdtemp(path.join(os.tmpdir(), "blindpass-input-e2e-"));
    const env = { VITE_BLINDPASS_API_ORIGIN: this.stack.controllerUrl, VITE_SPS_API_URL: "" };
    await run([VITE, "build", "--outDir", this.outDir, "--emptyOutDir"], env);
    let output = "";
    this.preview = spawn(process.execPath, [VITE, "preview", "--host", "127.0.0.1", "--port", String(port), "--strictPort", "--outDir", this.outDir], { cwd: INPUT_DIR, env: { ...process.env, ...env }, stdio: ["ignore", "pipe", "pipe"] });
    this.preview.stdout?.on("data", (chunk: Buffer) => (output = `${output}${chunk}`.slice(-4000)));
    this.preview.stderr?.on("data", (chunk: Buffer) => (output = `${output}${chunk}`.slice(-4000)));
    const deadline = Date.now() + 30_000;
    for (;;) {
      try {
        if ((await fetch(this.inputUrl)).ok) break;
      } catch {
        // not listening yet
      }
      if (Date.now() > deadline) throw new Error(`input preview did not start: ${output}`);
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    await this.seed();
  }

  private async seed(): Promise<void> {
    const keys = await this.stack.seedAgents(["e2e-input-requester", "e2e-input-other"]);
    this.requesterToken = await this.stack.agentToken(keys["e2e-input-requester"]!);
    this.otherToken = await this.stack.agentToken(keys["e2e-input-other"]!);
  }

  async stop(): Promise<void> {
    await stopChild(this.preview);
    await this.stack?.stop();
    if (this.outDir) await rm(this.outDir, { recursive: true, force: true });
  }

  /** A real signed request whose public key the test holds. */
  async createRequest(description: string): Promise<SecretRequest> {
    const pair = await suite.kem.generateKeyPair();
    const publicKey = Buffer.from(new Uint8Array(await suite.kem.serializePublicKey(pair.publicKey))).toString("base64");
    const response = await fetch(`${this.stack.controllerUrl}/api/v2/secret/request`, {
      method: "POST",
      headers: { authorization: `Bearer ${this.requesterToken}`, "content-type": "application/json" },
      body: JSON.stringify({ public_key: publicKey, description })
    });
    if (response.status !== 201) throw new Error(`secret request failed: ${response.status} ${await response.text()}`);
    const body = (await response.json()) as { request_id: string; confirmation_code: string; secret_url: string };
    return {
      requestId: body.request_id,
      confirmationCode: body.confirmation_code,
      secretUrl: body.secret_url,
      open: async (payload) => new Uint8Array(await suite.open({ recipientKey: pair.privateKey, enc: bytes(payload.enc) }, bytes(payload.ciphertext)))
    };
  }

  async retrieve(requestId: string, as: "requester" | "other" = "requester"): Promise<{ status: number; body: { enc: string; ciphertext: string } | null }> {
    const response = await fetch(`${this.stack.controllerUrl}/api/v2/secret/retrieve/${requestId}`, { headers: { authorization: `Bearer ${as === "requester" ? this.requesterToken : this.otherToken}` } });
    return { status: response.status, body: response.status === 200 ? ((await response.json()) as { enc: string; ciphertext: string }) : null };
  }

  async agentStatus(requestId: string): Promise<number> {
    return (await fetch(`${this.stack.controllerUrl}/api/v2/secret/status/${requestId}`, { headers: { authorization: `Bearer ${this.requesterToken}` } })).status;
  }
}

/** Replace one query parameter of a signed link, for tampering tests. */
export function withParam(url: string, name: string, value: string | null): string {
  const parsed = new URL(url);
  if (value === null) parsed.searchParams.delete(name);
  else parsed.searchParams.set(name, value);
  return parsed.toString();
}
