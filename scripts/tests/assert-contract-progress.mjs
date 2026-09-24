import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

async function main() {
  const reportPath = process.argv[2];
  const manifestPath = process.argv[3];
  if (!reportPath || !manifestPath) {
    process.stderr.write("Usage: node scripts/tests/assert-contract-progress.mjs <vitest-json-report> <rust-pending.json>\n");
    process.exit(2);
  }

  const report = JSON.parse(await readFile(reportPath, "utf8"));
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  try {
    const progress = compareProgress(report, manifest);
    process.stdout.write(`Rust contract progress: ${progress.passed.length}/${manifest.requiredIds.length} cases passed; ${progress.pending.length} remain explicitly incomplete.\n`);
    if (progress.pending.length > 0) {
      process.stdout.write(`Known incomplete cases: ${progress.pending.join(", ")}\n`);
    }
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  }
}

export function compareProgress(reportValue, manifestValue) {
  const requiredIds = validateIds(manifestValue.requiredIds, "requiredIds");
  const pendingIds = validateIds(manifestValue.pendingIds, "pendingIds");
  const excludedIds = validateIds(manifestValue.excludedIds, "excludedIds");
  const required = new Set(requiredIds);
  const pending = new Set(pendingIds);
  const excluded = new Set(excludedIds);
  if ([...pending].some((id) => !required.has(id))) {
    throw new Error("Pending contract IDs must be listed in requiredIds.");
  }
  const overlapping = excludedIds.filter((id) => required.has(id));
  if (overlapping.length > 0) {
    throw new Error(`Excluded contract IDs must be outside requiredIds: ${overlapping.join(", ")}.`);
  }

  const reasons = manifestValue.pendingReasons;
  for (const id of pendingIds) {
    if (typeof reasons?.[id] !== "string" || reasons[id].trim() === "") {
      throw new Error(`Missing pending reason for ${id}.`);
    }
  }
  const extraReasons = Object.keys(reasons ?? {}).filter((id) => !pending.has(id));
  if (extraReasons.length > 0) {
    throw new Error(`Pending reasons have no pending ID: ${extraReasons.join(", ")}.`);
  }
  const excludedReasons = manifestValue.excludedReasons;
  for (const id of excludedIds) {
    if (typeof excludedReasons?.[id] !== "string" || excludedReasons[id].trim() === "") {
      throw new Error(`Missing excluded reason for ${id}.`);
    }
  }
  const extraExcludedReasons = Object.keys(excludedReasons ?? {}).filter((id) => !excluded.has(id));
  if (extraExcludedReasons.length > 0) {
    throw new Error(`Excluded reasons have no excluded ID: ${extraExcludedReasons.join(", ")}.`);
  }

  if (!Array.isArray(reportValue.testResults) || reportValue.testResults.length === 0) {
    throw new Error("Vitest report contains no executed suites.");
  }
  if (!Number.isInteger(reportValue.numTotalTests) || reportValue.numTotalTests < 1) {
    throw new Error("Vitest report contains no executed tests.");
  }
  if ([reportValue.numPendingTests, reportValue.numPendingTestSuites, reportValue.numTodoTests]
    .some((value) => typeof value === "number" && value > 0)) {
    throw new Error("Vitest report contains skipped or todo tests.");
  }

  const observed = new Map();
  for (const suite of reportValue.testResults) {
    for (const assertion of suite.assertionResults ?? []) {
      const name = assertion.fullName ?? assertion.title ?? "";
      for (const match of name.matchAll(/\bCT\d{2}\b/g)) {
        const id = match[0];
        if (!required.has(id)) {
          throw new Error(`Unexpected contract case ${id} appeared in the report.`);
        }
        const previous = observed.get(id);
        if (previous) {
          throw new Error(`Duplicate result for ${id}: ${previous.name} and ${name}.`);
        }
        observed.set(id, { name, status: assertion.status });
      }
    }
  }

  const missing = requiredIds.filter((id) => !observed.has(id));
  if (missing.length > 0) {
    throw new Error(`Missing required contract cases: ${missing.join(", ")}.`);
  }

  const passed = [];
  const incomplete = [];
  for (const id of requiredIds) {
    const result = observed.get(id);
    if (pending.has(id)) {
      if (result.status === "passed") {
        throw new Error(`Unexpected pass for pending case ${id}; remove it from rust-pending.json.`);
      }
      if (result.status !== "failed") {
        throw new Error(`Pending case ${id} has non-executed status ${result.status}.`);
      }
      incomplete.push(id);
      continue;
    }

    if (result.status !== "passed") {
      throw new Error(`Unexpected failure for ${id}: status ${result.status}.`);
    }
    passed.push(id);
  }

  return { passed, pending: incomplete };
}

function validateIds(value, field) {
  if (!Array.isArray(value) || (field === "requiredIds" && value.length === 0) || value.some((id) => typeof id !== "string" || !/^CT\d{2}$/.test(id))) {
    throw new Error(`${field} must be a list of CT identifiers${field === "requiredIds" ? " with at least one entry" : ""}.`);
  }
  const duplicates = value.filter((id, index) => value.indexOf(id) !== index);
  if (duplicates.length > 0) {
    throw new Error(`${field} contains duplicate IDs: ${[...new Set(duplicates)].join(", ")}.`);
  }
  return [...value].sort();
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main();
}
