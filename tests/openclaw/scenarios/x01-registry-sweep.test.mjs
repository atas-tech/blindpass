// Registry-versus-native sweep: for every credential path in the vendored matrix, does the installed
// OpenClaw's own `secrets apply --dry-run` accept a plan for it? The accepted set is pinned in a fixture
// so a runtime change shows up as a diff, not as a silent behaviour change.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { OPENCLAW, PLUGIN_ROOT, RELEASE, evidence } from "./lib.mjs";
import { loadRegistry } from "../../../packages/openclaw-plugin/src/migrate/registry.mjs";
import { buildApplyPlan } from "../../../packages/openclaw-plugin/src/migrate/plan.mjs";

const FIXTURE = new URL("./fixtures/sweep-2026.8.35.json", import.meta.url);

test("X01 which matrix targets the installed OpenClaw accepts (per-target native dry run)", { timeout: 1200000 }, async () => {
    const registry = loadRegistry(RELEASE);
    const root = await mkdtemp(path.join(os.homedir(), "p09-sweep-"));
    const verdicts = {};
    try {
        for (const target of registry.configTargets) {
            const segments = target.path.split(".").map((segment) => (segment === "*" ? "x" : segment));
            const dir = path.join(root, String(Object.keys(verdicts).length));
            await mkdir(dir, { mode: 0o700 });
            const config = {};
            let node = config;
            for (const segment of segments.slice(0, -1)) {
                node = (node[segment] ??= {});
            }
            node[segments.at(-1)] = "P09-CANARY-SWEEP-0123456789ab";
            await writeFile(path.join(dir, "openclaw.json"), JSON.stringify(config, null, 2), { mode: 0o600 });
            const plan = buildApplyPlan({
                targets: [{ path: segments.join("."), registryId: target.id, segments, ref: { source: "exec", provider: "blindpass", id: "openclaw.sweep" } }],
                providerAlias: "blindpass", resolverCommand: "/bin/true", storePath: "/nonexistent/store.json",
            });
            await writeFile(path.join(dir, "plan.json"), JSON.stringify(plan), { mode: 0o600 });
            const run = spawnSync(OPENCLAW, ["secrets", "apply", "--from", path.join(dir, "plan.json"), "--dry-run", "--json"], {
                encoding: "utf8",
                env: { PATH: process.env.PATH, HOME: process.env.HOME, OPENCLAW_STATE_DIR: dir, OPENCLAW_CONFIG_PATH: path.join(dir, "openclaw.json") },
            });
            const text = `${run.stdout}\n${run.stderr}`;
            verdicts[target.id] = run.status === 0 ? "accepted"
                : /Invalid secrets plan file|Invalid plan target/.test(text) ? "plan-rejected"
                    : /config is invalid/.test(text) ? "config-invalid" : "other";
        }
    } finally {
        await rm(root, { recursive: true, force: true });
    }
    const counts = {};
    for (const verdict of Object.values(verdicts)) {
        counts[verdict] = (counts[verdict] ?? 0) + 1;
    }
    assert.equal(counts.other ?? 0, 0, "every outcome is one of the three understood verdicts");
    const accepted = Object.keys(verdicts).filter((id) => verdicts[id] === "accepted").sort();
    const expected = JSON.parse(await readFile(FIXTURE, "utf8")).accepted;
    assert.deepEqual(accepted, expected, "the set of targets 2026.8.35 accepts matches the reviewed fixture");
    for (const core of ["gateway.auth.token", "skills.entries.*.apiKey", "channels.telegram.botToken"]) {
        assert.ok(accepted.includes(core), core);
    }
    evidence("X01", `matrix ${registry.configTargets.length} config targets vs the real runtime: ${counts.accepted ?? 0} accepted, ${counts["plan-rejected"] ?? 0} rejected as unknown to the installed runtime/plugins, ${counts["config-invalid"] ?? 0} not testable in isolation (minimal config invalid); plugin root ${path.basename(PLUGIN_ROOT)}`);
});
