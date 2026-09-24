import assert from "node:assert/strict";
import test from "node:test";
import { compareProgress } from "./assert-contract-progress.mjs";

const requiredIds = ["CT01", "CT02", "CT19"];
const baseManifest = {
  requiredIds,
  pendingIds: ["CT02", "CT19"],
  excludedIds: ["CT14"],
  excludedReasons: { CT14: "Hosted user auth stays in the TypeScript SPS." },
  pendingReasons: {
    CT02: "Agent token route is not implemented yet.",
    CT19: "Browser status routes are not implemented yet."
  }
};

function report(statuses) {
  const assertions = Object.entries(statuses).map(([id, status]) => ({
    fullName: `controller suite ${id} case`,
    title: `${id} case`,
    status
  }));
  return {
    numTotalTests: assertions.length,
    numPendingTests: 0,
    numPendingTestSuites: 0,
    numTodoTests: 0,
    testResults: [{ assertionResults: assertions }]
  };
}

test("contract progress accepts only the documented red cases", () => {
  const progress = compareProgress(report({ CT01: "passed", CT02: "failed", CT19: "failed" }), baseManifest);
  assert.deepEqual(progress, { passed: ["CT01"], pending: ["CT02", "CT19"] });
});

test("contract progress rejects an unexpected pass until its pending entry is removed", () => {
  assert.throws(
    () => compareProgress(report({ CT01: "passed", CT02: "passed", CT19: "failed" }), baseManifest),
    /unexpected pass.*CT02/i
  );
});

test("contract progress rejects an unexpected failure", () => {
  assert.throws(
    () => compareProgress(report({ CT01: "failed", CT02: "failed", CT19: "failed" }), baseManifest),
    /unexpected failure.*CT01/i
  );
});

test("contract progress rejects missing, duplicate and skipped case results", () => {
  assert.throws(
    () => compareProgress(report({ CT01: "passed", CT02: "failed" }), baseManifest),
    /missing.*CT19/i
  );
  const duplicate = report({ CT01: "passed", CT02: "failed", CT19: "failed" });
  duplicate.testResults[0].assertionResults.push({ fullName: "second CT01", status: "passed" });
  duplicate.numTotalTests += 1;
  assert.throws(() => compareProgress(duplicate, baseManifest), /duplicate.*CT01/i);
  const skipped = report({ CT01: "passed", CT02: "failed", CT19: "failed" });
  skipped.numPendingTests = 1;
  assert.throws(() => compareProgress(skipped, baseManifest), /skipped or todo/i);
});

test("contract progress requires a reason for every pending ID", () => {
  const manifest = { ...baseManifest, pendingReasons: { CT02: "not ready" } };
  assert.throws(
    () => compareProgress(report({ CT01: "passed", CT02: "failed", CT19: "failed" }), manifest),
    /pending reason.*CT19/i
  );
});

test("contract progress requires a reason for every excluded ID and keeps it outside the Rust run", () => {
  const missingReason = { ...baseManifest, excludedReasons: {} };
  assert.throws(
    () => compareProgress(report({ CT01: "passed", CT02: "failed", CT19: "failed" }), missingReason),
    /excluded reason.*CT14/i
  );
  const overlapping = { ...baseManifest, excludedIds: ["CT02"], excludedReasons: { CT02: "invalid" } };
  assert.throws(
    () => compareProgress(report({ CT01: "passed", CT02: "failed", CT19: "failed" }), overlapping),
    /excluded.*required.*CT02/i
  );
  assert.throws(
    () => compareProgress(report({ CT01: "passed", CT02: "failed", CT14: "passed", CT19: "failed" }), baseManifest),
    /unexpected contract case CT14/i
  );
});
