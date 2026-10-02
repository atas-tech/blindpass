import { spawnSync } from "node:child_process";
import { readFile, readdir } from "node:fs/promises";
import path from "node:path";

const packagesDir = path.resolve("packages");
const workspaces = [];
for (const entry of await readdir(packagesDir, { withFileTypes: true })) {
  if (!entry.isDirectory()) continue;
  const packageFile = path.join(packagesDir, entry.name, "package.json");
  let pkg;
  try {
    pkg = JSON.parse(await readFile(packageFile, "utf8"));
  } catch (error) {
    if (error?.code === "ENOENT") continue;
    throw error;
  }
  if (pkg.name !== "@blindpass/contract-tests" && pkg.scripts?.test) {
    workspaces.push(`--workspace=${pkg.name}`);
  }
}

if (workspaces.length === 0) throw new Error("No ordinary test workspaces found");
const run = spawnSync("npm", ["run", "test", ...workspaces], { stdio: "inherit" });
if (run.error) throw run.error;
if (run.status !== 0) process.exit(run.status ?? 1);

// The phase fixture HTTP contract needs no database or stock AI client. Chromium UI
// acceptance stays in the explicit test:p05:fixture command with its browser prerequisite.
const fixture = spawnSync(process.execPath,
  ['--test', '--test-isolation=none', 'tests/browser-handoff/fixture-app/app.test.mjs'], { stdio: 'inherit' });
if (fixture.error) throw fixture.error;
if (fixture.status !== 0) process.exit(fixture.status ?? 1);
const oauth = spawnSync(process.execPath,
  ['--test', '--test-isolation=none', '--test-name-pattern=rejects unsafe|fixed redirect',
    'tests/browser-handoff/oauth-fixture.test.mjs'], { stdio: 'inherit' });
if (oauth.error) throw oauth.error;
if (oauth.status !== 0) process.exit(oauth.status ?? 1);
const notices = spawnSync(process.execPath,
  ['--test', '--test-isolation=none', 'scripts/tests/mcp-bundle-notices.test.mjs', 'scripts/tests/node-runtime.test.mjs'], { stdio: 'inherit' });
if (notices.error) throw notices.error;
if (notices.status !== 0) process.exit(notices.status ?? 1);
const helper = spawnSync(process.execPath,
  ['--test', '--test-isolation=none', 'tests/browser-handoff/private-login.test.mjs',
    'tests/browser-handoff/private-login-worker.test.mjs', 'tests/browser-handoff/browser-transport.test.mjs',
    'tests/browser-handoff/isolated-browser.test.mjs', 'tests/browser-handoff/runtime-identity-client.test.mjs',
    'tests/browser-handoff/session-revoker.test.mjs', 'tests/browser-handoff/browser-supervisor.test.mjs', 'tests/browser-handoff/browser-supervisor-worker.test.mjs', 'tests/browser-handoff/runtime-manager.test.mjs',
    'tests/browser-handoff/isolated-browser-agent.test.mjs', 'tests/browser-handoff/coordinator-journal.test.mjs', 'tests/browser-handoff/guest-workload.test.mjs', 'tests/browser-handoff/fleet-controller-fixture.test.mjs',
    'tests/browser-handoff/guest-browser-profile.test.mjs', 'tests/browser-handoff/managed-grafana-process.test.mjs', 'tests/browser-handoff/runtime-cleanup.test.mjs', 'tests/browser-handoff/client-protocol-metadata.test.mjs',
    'tests/browser-handoff/ai-client-bridge.test.mjs', 'tests/browser-handoff/stock-mcp-client.test.mjs', 'tests/browser-handoff/json-frame-reader.test.mjs', 'tests/browser-handoff/ai-client-agent.test.mjs', 'tests/browser-handoff/ai-client-pipe.test.mjs', 'tests/browser-handoff/ai-task-observer.test.mjs', 'tests/browser-handoff/fixture-app/revocation.test.mjs',
    'tests/browser-handoff/certificate-pins.test.mjs', 'tests/browser-handoff/journal-canary-scan.test.mjs',
    'tests/browser-handoff/shipped-broker-unit.test.mjs', 'tests/browser-handoff/private-helper-leak-check.test.mjs'], { stdio: 'inherit' });
if (helper.error) throw helper.error;
process.exit(helper.status ?? 1);
