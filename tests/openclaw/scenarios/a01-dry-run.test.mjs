// Pilot A01 / P09-I01 (real runtime): the dry run on a real installation changes nothing, matches the
// native audit, never creates OpenClaw state, and discloses no value.
import assert from "node:assert/strict";
import { cp, mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import path from "node:path";
import test from "node:test";
import { snapshotTree } from "../../../packages/openclaw-plugin/tests/migrate/helpers.mjs";
import {
    OPENCLAW, RELEASE, assertNoWindows, destroyRig, evidence, initStore, makeRig, migrate,
} from "./lib.mjs";

async function withRig(fn, options) {
    const rig = await makeRig(options);
    try {
        await fn(rig);
    } finally {
        await destroyRig(rig);
    }
}

test("A01 dry run on a real installation is read-only, deterministic and value-free", async () => {
    await withRig(async (rig) => {
        await mkdir(path.join(rig.state, "agents", "main", "agent"), { recursive: true, mode: 0o700 });
        await writeFile(path.join(rig.state, "agents", "main", "agent", "models.json"), JSON.stringify({ providers: { mockai: { apiKey: rig.secrets.model } } }), { mode: 0o600 });
        const canaries = Object.values(rig.secrets);

        const before = await snapshotTree(rig.state);
        const first = migrate(rig, ["--dry-run", "--config-dir", rig.state, "--json"]);
        const second = migrate(rig, ["--dry-run", "--config-dir", rig.state, "--json"]);
        const text = migrate(rig, ["--dry-run", "--config-dir", rig.state]);
        assert.equal(first.code, 0, first.stderr);
        assert.equal(first.stdout, second.stdout, "the plan is deterministic");
        assert.deepEqual(await snapshotTree(rig.state), before, "no file, mode or timestamp changed");
        assert.ok(!(await readdir(rig.state)).includes("state"), "the dry run created no OpenClaw state directory or SQLite database");
        const plan = JSON.parse(first.stdout);
        assert.equal(plan.summary.migratable, 4);
        assert.equal(plan.summary.residual >= 2, true, "the .env copy and the models.json copy are reported as residual plaintext");
        assertNoWindows(assert, first.stdout + first.stderr + text.stdout + text.stderr, canaries, "dry-run output");
        evidence("A01", `dry run of a real installation: ${plan.summary.migratable} migratable, ${plan.summary.residual} residual, tree unchanged, no state/ directory created, output value-free`);

        // Cross-check against the native audit, on a copy so the audit's own state creation stays out of the rig.
        const copy = path.join(rig.root, "audit-copy");
        await cp(rig.state, copy, { recursive: true });
        const audit = spawnSync(OPENCLAW, ["secrets", "audit", "--json"], {
            encoding: "utf8",
            env: { PATH: process.env.PATH, HOME: process.env.HOME, OPENCLAW_STATE_DIR: copy, OPENCLAW_CONFIG_PATH: path.join(copy, "openclaw.json") },
        });
        const findings = JSON.parse(audit.stdout).findings
            .filter((finding) => finding.code === "PLAINTEXT_FOUND" && finding.file.endsWith("openclaw.json"))
            .map((finding) => finding.jsonPath).sort();
        const ours = plan.rows.filter((row) => row.file === "openclaw.json" && row.status === "migratable").map((row) => row.keyPath).sort();
        assert.deepEqual(ours, findings, "the dry run and `openclaw secrets audit` agree on the plaintext fields of openclaw.json");
        evidence("A01", `dry-run inventory equals the native audit's plaintext findings for openclaw.json (${ours.length} fields)`);
    });
});

test("A01 dry run with a named store reports key and backup state through real sops, read-only", async () => {
    await withRig(async (rig) => {
        const missing = migrate(rig, ["--dry-run", "--config-dir", rig.state, "--store", rig.storePath, "--json"]);
        assert.ok(JSON.parse(missing.stdout).warnings.some((warning) => warning.startsWith("store-missing")));
        assert.ok(!(await readdir(rig.store)).length, "the dry run did not create a store, key or config");

        assert.equal(initStore(rig).code, 0);
        const before = await snapshotTree(rig.store);
        const pending = migrate(rig, ["--dry-run", "--config-dir", rig.state, "--store", rig.storePath, "--json"]);
        const plan = JSON.parse(pending.stdout);
        assert.equal(plan.store.state, "ready");
        assert.equal(plan.store.backupPending, true);
        assert.ok(plan.warnings.some((warning) => warning.startsWith("bootstrap-backup-pending")));
        assert.deepEqual(await snapshotTree(rig.store), before, "reading the store did not change it");
        evidence("A01", "dry run with --store reports store-missing, then bootstrap-backup-pending against a real sops/age store without changing it");
    });
});

test("P09-I01 the real dry run refuses a symlinked config directory and loose permissions", async () => {
    await withRig(async (rig) => {
        const { symlink, chmod } = await import("node:fs/promises");
        const alias = path.join(rig.root, "alias");
        await symlink(rig.state, alias);
        const viaLink = migrate(rig, ["--dry-run", "--config-dir", alias]);
        assert.equal(viaLink.code, 3);
        assert.match(viaLink.stderr, /refused: symlink/);
        await chmod(path.join(rig.state, "openclaw.json"), 0o666);
        const loose = migrate(rig, ["--dry-run", "--config-dir", rig.state]);
        assert.equal(loose.code, 3);
        assert.equal(loose.stdout, "");
        assertNoWindows(assert, loose.stderr, Object.values(rig.secrets), "refusal output");
        assert.equal(RELEASE, "2026.8.35");
        evidence("P09-I01", "symlinked config directory and group/other-writable config file refused with exit 3 on the real installation");
    });
});
