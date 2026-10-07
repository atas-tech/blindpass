// P07-D6: the release bundle checker proves itself on planted cases and
// fails closed on an empty scan.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const script = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../release/check-bundles-for-localhost.sh");
const run = (...args) => spawnSync("bash", [script, ...args], { encoding: "utf8" });

test("the checker's own planted-case self-test passes", () => {
  const result = run("--self-test");
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stdout, /self-test passed/);
});

test("a directory with a development origin fails and one without passes", () => {
  const directory = mkdtempSync(path.join(tmpdir(), "bundle-check-"));
  try {
    mkdirSync(path.join(directory, "bad"));
    mkdirSync(path.join(directory, "good"));
    writeFileSync(path.join(directory, "bad", "app.js"), 'fetch("http://127.0.0.1:3100/api")\n');
    writeFileSync(path.join(directory, "good", "app.js"), 'fetch("/api")\n');
    assert.equal(run(path.join(directory, "bad")).status, 1);
    assert.equal(run(path.join(directory, "good")).status, 0);
    assert.equal(run(path.join(directory, "absent")).status, 2);
    assert.equal(run().status, 2);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
