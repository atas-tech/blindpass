import { readFile, readdir } from "node:fs/promises";
import path from "node:path";

const reportPath = process.argv[2];
if (!reportPath) {
  process.stderr.write("Usage: node scripts/tests/assert-pg-vitest-gate.mjs <vitest-json-report>\n");
  process.exit(2);
}

const report = JSON.parse(await readFile(reportPath, "utf8"));
const results = Array.isArray(report.testResults) ? report.testResults : [];
const testDir = path.resolve("packages/sps-server/tests");
const gatedFiles = [];
for (const filename of await readdir(testDir)) {
  if (!filename.endsWith(".test.ts")) continue;
  const source = await readFile(path.join(testDir, filename), "utf8");
  if (source.includes('process.env.SPS_PG_INTEGRATION === "1"')) gatedFiles.push(filename);
}

if (gatedFiles.length === 0) {
  throw new Error("No PostgreSQL-gated SPS files found; review the gate matcher");
}
for (const filename of gatedFiles) {
  const suite = results.find((entry) => entry.name && path.basename(entry.name) === filename);
  const assertions = suite?.assertionResults ?? [];
  if (!assertions.some((entry) => entry.status === "passed") ||
      assertions.some((entry) => entry.status === "failed")) {
    throw new Error(`PostgreSQL gate did not execute successfully: ${filename}`);
  }
}
process.stdout.write(`PostgreSQL gate executed in ${gatedFiles.length} SPS test files.\n`);
