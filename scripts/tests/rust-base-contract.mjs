import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { startRustServerForBaseContract } from "../../packages/contract-tests/src/adapter.ts";

// Runs the contract suite against a controller the suite does not own: the harness starts the Rust controller
// (CONTRACT_RUST_BACKEND=sqlite|postgres, default sqlite), writes the fixture, and the suite then sees only a base
// URL. This replaces the retired SPS base launcher (P08-D7). Cases that need harness control of the server (a forced
// readiness failure, a restart, a second rate-limited instance) cannot run this way and are listed here by name; the
// spawned `SUT=rust` run covers them.
const NEEDS_HARNESS_CONTROL = ["CT15\\.request\\.agent-limit", "CT15\\.exchange\\.agent-limit", "CT18\\.error\\.503", "CT19"];

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
process.env.CONTRACT_RUST_BACKEND ||= "sqlite";
process.env.SUT = "rust";
const tempDir = await mkdtemp(path.join(os.tmpdir(), "blindpass-rust-base-"));
const fixturePath = path.join(tempDir, "contract-fixture.json");
let server;
let child;

function runBaseContract(baseUrl, fixtureFile) {
  return new Promise((resolve, reject) => {
    child = spawn("npm", [
      "test",
      "--workspace=@blindpass/contract-tests",
      "--",
      "tests/http-contract.test.ts",
      "--testNamePattern",
      `^(?!.*(${NEEDS_HARNESS_CONTROL.join("|")})).*$`
    ], {
      cwd: repositoryRoot,
      env: {
        ...process.env,
        SUT: "rust",
        RUST_BASE_URL: baseUrl,
        CONTRACT_FIXTURE_FILE: fixtureFile,
        CONTRACT_SNAPSHOT_SUBSET: "1"
      },
      stdio: "inherit"
    });
    child.once("error", reject);
    child.once("exit", (code, signal) => {
      if (signal) reject(new Error(`base contract run terminated by ${signal}`));
      else resolve(code ?? 1);
    });
  });
}

try {
  server = await startRustServerForBaseContract();
  await writeFile(fixturePath, JSON.stringify({
    ...server.fixture,
    externalJwtPrivateJwk: server.externalJwtPrivateJwk
  }), { mode: 0o600 });
  process.exitCode = await runBaseContract(server.baseUrl, fixturePath);
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
} finally {
  if (child && child.exitCode === null) {
    child.kill("SIGTERM");
    await new Promise((resolve) => child.once("exit", resolve));
  }
  await server?.close();
  await rm(tempDir, { recursive: true, force: true });
}
