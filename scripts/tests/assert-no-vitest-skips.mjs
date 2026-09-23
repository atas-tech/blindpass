import { readFile } from "node:fs/promises";

const reportPath = process.argv[2];
if (!reportPath) {
  process.stderr.write("Usage: node scripts/tests/assert-no-vitest-skips.mjs <vitest-json-report>\n");
  process.exit(2);
}

const report = JSON.parse(await readFile(reportPath, "utf8"));
const testResults = Array.isArray(report.testResults) ? report.testResults : [];
if (typeof report.numPendingTests !== "number" || typeof report.numPendingTestSuites !== "number") {
  process.stderr.write("Vitest report does not include pending-test counts; refusing to claim a skip-free run.\n");
  process.exit(1);
}
const pendingCounts = [report.numPendingTests, report.numPendingTestSuites, report.numTodoTests]
  .filter((value) => typeof value === "number");
const skippedAssertions = testResults.flatMap((suite) => suite.assertionResults ?? [])
  .filter((assertion) => /^(?:pending|skip|skipped|todo)$/i.test(assertion.status));

if (!Number.isInteger(report.numTotalTests) || report.numTotalTests < 1 || testResults.length === 0) {
  process.stderr.write("Vitest report has no executed tests; refusing a vacuous contract pass.\n");
  process.exit(1);
}

if (pendingCounts.some((count) => count > 0) || skippedAssertions.length > 0) {
  const names = skippedAssertions.map((assertion) => assertion.fullName ?? assertion.title ?? "unnamed test");
  process.stderr.write(`Vitest contract run contains skipped tests: ${names.join(", ") || "pending suite"}\n`);
  process.exit(1);
}

process.stdout.write(`No skipped tests in ${report.numTotalTests} Vitest cases.\n`);
