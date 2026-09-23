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
process.exit(run.status ?? 1);
