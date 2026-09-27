// SPDX-License-Identifier: AGPL-3.0-only
// P04-I04/E02 widget portion under Quickshell: the widget follows the
// summary written by the approval app's helper, marks a stale summary as
// "not running", and its only action runs the configured open command.
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const helper = path.join(here, "../../approval-app/bin/blindpass-session-store");
const available = spawnSync("sh", ["-c", "command -v quickshell"]).status === 0;

function writeSummary(runtime, summary) {
  const result = spawnSync(helper, ["summary"], { input: JSON.stringify(summary), env: { PATH: process.env.PATH, XDG_RUNTIME_DIR: runtime } });
  assert.equal(result.status, 0, String(result.stderr));
}

function waitFor(lines, predicate, step, from = 0, timeout = 15000) {
  return new Promise((resolve, reject) => {
    const started = Date.now();
    const timer = setInterval(() => {
      const found = lines.slice(from).find(predicate);
      if (found) {
        clearInterval(timer);
        resolve(found);
      } else if (Date.now() - started > timeout) {
        clearInterval(timer);
        reject(new Error("timed out waiting for " + step + "; " + lines.length + " lines; last:\n" + lines.filter(Boolean).slice(-6).join("\n")));
      }
    }, 50);
  });
}

test("the widget follows the app's summary and only opens the app", { skip: available ? false : "quickshell is not installed" }, async () => {
  const root = mkdtempSync("/tmp/bpw.");
  const runtime = path.join(root, "run");
  mkdirSync(runtime);
  chmodSync(runtime, 0o700);
  const env = { ...process.env, QT_QPA_PLATFORM: "offscreen", QT_FORCE_STDERR_LOGGING: "1", XDG_RUNTIME_DIR: runtime, E2E_CLICK: "0" };
  delete env.WAYLAND_DISPLAY;
  const lines = [];
  const child = spawn("quickshell", ["-p", path.join(here, "../e2e.qml")], { env, stdio: ["ignore", "pipe", "pipe"] });
  const collect = (chunk) => lines.push(...String(chunk).split("\n").map((line) => line.replace(/\x1b\[[0-9;]*m/g, "")));
  child.stdout.on("data", collect);
  child.stderr.on("data", collect);
  try {
    await waitFor(lines, (line) => line.includes('E2E VIEW {"state":"not_running","pending":null}'), "step 1");
    let mark = lines.length;
    writeSummary(runtime, { v: 1, state: "ready", pending: 3, updated_at: Date.now() });
    await waitFor(lines, (line) => line.includes('E2E VIEW {"state":"ready","pending":3}'), "step 2", mark);
    mark = lines.length;
    writeSummary(runtime, { v: 1, state: "locked", pending: 1, updated_at: Date.now(), refresh_token: "bp-canary-widget-token" });
    await waitFor(lines, (line) => line.includes('E2E VIEW {"state":"locked","pending":1}'), "step 3", mark);
    mark = lines.length;
    writeSummary(runtime, { v: 1, state: "ready", pending: 3, updated_at: Date.now() - 120000 });
    await waitFor(lines, (line) => line.includes('E2E VIEW {"state":"not_running","pending":null}'), "step 4: a stale summary reads as not running", mark);
    mark = lines.length;
    writeSummary(runtime, { v: 1, state: "signed_out", pending: null, updated_at: Date.now() });
    await waitFor(lines, (line) => line.includes('E2E VIEW {"state":"signed_out","pending":null}'), "step 5", mark);
    assert.ok(!lines.some((line) => line.includes("bp-canary-widget-token")), "extra summary fields never reach the widget's state or logs");
    assert.ok(!lines.some((line) => line.includes("E2E RUN")), "nothing runs without a click");
  } finally {
    child.kill("SIGTERM");
  }
  const clickEnv = { ...env, E2E_CLICK: "1" };
  const clickLines = [];
  const clicker = spawn("quickshell", ["-p", path.join(here, "../e2e.qml")], { env: clickEnv, stdio: ["ignore", "pipe", "pipe"] });
  clicker.stdout.on("data", (chunk) => clickLines.push(...String(chunk).split("\n")));
  clicker.stderr.on("data", (chunk) => clickLines.push(...String(chunk).split("\n")));
  try {
    const run = await waitFor(clickLines, (line) => line.includes("E2E RUN "), "step 6");
    assert.match(run, /E2E RUN blindpass-approvals --from-widget$/);
  } finally {
    clicker.kill("SIGTERM");
    rmSync(root, { recursive: true, force: true });
  }
});
