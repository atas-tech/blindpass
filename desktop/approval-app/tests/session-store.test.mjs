// SPDX-License-Identifier: AGPL-3.0-only
// P04-D3 storage helper: 0700 directory, 0600 files, atomic replace,
// refusal of symlinks and loose permissions, size limit, stdin-only input.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, test } from "node:test";
import { fileURLToPath } from "node:url";

const helper = path.join(path.dirname(fileURLToPath(import.meta.url)), "../bin/blindpass-session-store");
const canary = "bp-canary-refresh-" + Math.random().toString(36).slice(2);
let root;
let runtime;

function run(command, input, env = {}) {
  return spawnSync(helper, [command], { input, env: { PATH: process.env.PATH, XDG_RUNTIME_DIR: runtime, ...env }, encoding: "utf8" });
}

function mode(file) {
  return (lstatSync(file).mode & 0o777).toString(8);
}

beforeEach(() => {
  root = mkdtempSync(path.join(os.tmpdir(), "bp-session-store-"));
  runtime = path.join(root, "run");
  mkdirSync(runtime, { mode: 0o700 });
  chmodSync(runtime, 0o700);
});

afterEach(() => rmSync(root, { recursive: true, force: true }));

test("write creates a 0700 directory and a 0600 file and read returns the exact bytes", () => {
  const record = JSON.stringify({ v: 1, refresh_token: canary }) + "\n";
  const written = run("write", record);
  assert.equal(written.status, 0, written.stderr);
  assert.equal(mode(path.join(runtime, "blindpass")), "700");
  assert.equal(mode(path.join(runtime, "blindpass/session")), "600");
  const read = run("read");
  assert.equal(read.status, 0, read.stderr);
  assert.equal(read.stdout, record);
  assert.deepEqual(readdirSync(path.join(runtime, "blindpass")), ["session"], "no temporary file is left behind");
  assert.ok(!written.stderr.includes(canary) && !read.stderr.includes(canary));
});

test("a second write replaces the record by rename", () => {
  assert.equal(run("write", "first-record-value").status, 0);
  const before = statSync(path.join(runtime, "blindpass/session")).ino;
  assert.equal(run("write", "second-record-value").status, 0);
  assert.equal(run("read").stdout, "second-record-value");
  assert.notEqual(statSync(path.join(runtime, "blindpass/session")).ino, before, "replaced, not rewritten in place");
});

test("delete removes the record and read then reports none", () => {
  assert.equal(run("write", canary).status, 0);
  assert.equal(run("delete").status, 0);
  assert.equal(existsSync(path.join(runtime, "blindpass/session")), false);
  assert.equal(run("read").status, 5);
  assert.equal(run("delete").status, 0, "deleting nothing succeeds");
});

test("read with no directory or file exits 5 without creating anything", () => {
  assert.equal(run("read").status, 5);
  assert.equal(existsSync(path.join(runtime, "blindpass")), false);
});

test("symlinks are refused, not followed", () => {
  const elsewhere = path.join(root, "elsewhere");
  mkdirSync(elsewhere, { mode: 0o700 });
  symlinkSync(elsewhere, path.join(runtime, "blindpass"));
  assert.notEqual(run("write", canary).status, 0);
  assert.deepEqual(readdirSync(elsewhere), []);
  rmSync(path.join(runtime, "blindpass"));
  mkdirSync(path.join(runtime, "blindpass"), { mode: 0o700 });
  const target = path.join(root, "target");
  writeFileSync(target, "outside", { mode: 0o600 });
  symlinkSync(target, path.join(runtime, "blindpass/session"));
  assert.notEqual(run("read").status, 0);
  assert.notEqual(run("write", canary).status, 0);
  assert.equal(spawnSync("cat", [target], { encoding: "utf8" }).stdout, "outside");
});

test("loose permissions are refused rather than repaired", () => {
  assert.equal(run("write", canary).status, 0);
  chmodSync(path.join(runtime, "blindpass/session"), 0o644);
  const read = run("read");
  assert.equal(read.status, 3);
  assert.match(read.stderr, /not 0600/);
  assert.ok(!read.stdout.includes(canary));
  chmodSync(path.join(runtime, "blindpass/session"), 0o600);
  chmodSync(path.join(runtime, "blindpass"), 0o755);
  assert.equal(run("read").status, 3);
  assert.equal(run("write", canary).status, 3);
  chmodSync(path.join(runtime, "blindpass"), 0o700);
  chmodSync(runtime, 0o755);
  assert.equal(run("write", canary).status, 2);
});

test("empty and oversized records are refused and leave the old record", () => {
  assert.equal(run("write", "kept-record").status, 0);
  assert.equal(run("write", "").status, 4);
  assert.equal(run("write", "x".repeat(4097)).status, 4);
  assert.equal(run("read").stdout, "kept-record");
  assert.deepEqual(readdirSync(path.join(runtime, "blindpass")), ["session"]);
  assert.equal(run("write", "y".repeat(4096)).status, 0);
});

test("the runtime directory is required", () => {
  assert.equal(run("write", canary, { XDG_RUNTIME_DIR: "" }).status, 2);
  assert.equal(run("write", canary, { XDG_RUNTIME_DIR: "relative/dir" }).status, 2);
  assert.equal(run("write", canary, { XDG_RUNTIME_DIR: path.join(root, "missing") }).status, 2);
});

test("summary writes a separate 0600 file", () => {
  const summary = JSON.stringify({ v: 1, state: "ready", pending: 2, updated_at: 1 });
  assert.equal(run("summary", summary).status, 0);
  assert.equal(mode(path.join(runtime, "blindpass/summary.json")), "600");
  assert.equal(run("read").status, 5, "the summary is not the session record");
});

test("unknown commands are refused", () => {
  assert.equal(spawnSync(helper, [], { env: { PATH: process.env.PATH, XDG_RUNTIME_DIR: runtime } }).status, 64);
  assert.equal(run("cat").status, 64);
});
