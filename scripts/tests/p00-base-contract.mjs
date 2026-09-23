import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { startTsServerForBaseContract } from "../../packages/contract-tests/src/adapter.ts";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const tempDir = await mkdtemp(path.join(os.tmpdir(), "blindpass-p00-base-"));
const fixturePath = path.join(tempDir, "contract-fixture.json");
let server;
let child;

function runBaseContract(baseUrl, fixtureFile) {
  return new Promise((resolve, reject) => {
    child = spawn("npm", [
      "test",
      "--workspace=@blindpass/contract-tests",
      "--",
      "tests/http-contract.test.ts"
    ], {
      cwd: repositoryRoot,
      env: {
        ...process.env,
        SUT: "base",
        CONTRACT_BASE_URL: baseUrl,
        CONTRACT_FIXTURE_FILE: fixtureFile
      },
      stdio: "inherit"
    });
    child.once("error", reject);
    child.once("exit", (code, signal) => {
      if (signal) reject(new Error(`SUT=base contract run terminated by ${signal}`));
      else resolve(code ?? 1);
    });
  });
}

try {
  server = await startTsServerForBaseContract();
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
