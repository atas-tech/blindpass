// P09-I02: SIGKILL the migration at every journal boundary of every stage, then prove that a rerun
// finishes it and that rollback restores the original, with protected originals and unrelated state kept.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { readFile, readdir, writeFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import {
    IS_LINUX, RELEASE, TARGET_PATHS, assertNoLeak, withInstallation as scenario,
} from "./helpers.mjs";
import { getAt } from "../../src/migrate/config-edit.mjs";
import { migrationStatus, rollbackMigration, runMigration } from "../../src/migrate/migrate.mjs";
import { inspectStore } from "../../src/migrate/store.mjs";

const opts = { skip: !IS_LINUX && "Linux-only", timeout: 240000 };
const RUNNER = path.join(path.dirname(new URL(import.meta.url).pathname), "crash-runner.mjs");
const STAGES = ["inventory", "backup", "import", "rewrite", "commit"];
const POINTS = STAGES.flatMap((stage) => [`${stage}:after-intent`, `${stage}:after-effect`]);

function crashRun(spec) {
    return new Promise((resolve, reject) => {
        const child = spawn(process.execPath, [RUNNER, JSON.stringify(spec)], { stdio: ["ignore", "pipe", "pipe"], env: { PATH: process.env.PATH, HOME: process.env.HOME } });
        let stdout = "";
        let stderr = "";
        child.stdout.on("data", (chunk) => { stdout += chunk; });
        child.stderr.on("data", (chunk) => { stderr += chunk; });
        child.on("error", reject);
        child.on("close", (code, signal) => resolve({ code, signal, stdout, stderr }));
    });
}

const readJson = async (file) => JSON.parse(await readFile(file, "utf8"));

function noRefsToProvider(config) {
    return !JSON.stringify(config).includes('"provider":"blindpass"');
}

test("P09-I02 a rerun completes the migration after a kill at every stage boundary", opts, async () => {
    for (const point of POINTS) {
        await scenario(async (ctx) => {
            const crashed = await crashRun({ action: "apply", options: ctx.options, crashAt: point });
            assert.equal(crashed.signal, "SIGKILL", `${point}: expected the child to be killed, got ${JSON.stringify(crashed)}`);
            const interrupted = await migrationStatus({ configDir: ctx.configDir });
            assert.equal(interrupted.status, "in-progress", point);
            const id = interrupted.migrationId;

            const result = await runMigration(ctx.options);
            assert.equal(result.status, "committed", point);
            assert.equal(result.migrationId, id, `${point}: the rerun resumes the same migration`);
            const config = await readJson(ctx.configFile);
            for (const p of TARGET_PATHS) {
                assert.deepEqual(getAt(config, p.split(".")), { source: "exec", provider: "blindpass", id: `openclaw.${p}` }, `${point}: ${p}`);
            }
            assert.equal(config.gateway.port, 18789);
            assert.equal(config.custom.note, "operator-owned");
            assert.deepEqual((await inspectStore({ storePath: ctx.storePath })).names, TARGET_PATHS.map((p) => `openclaw.${p}`).sort(), point);
            const backups = await readdir(path.join(ctx.configDir, ".blindpass-backup"));
            assert.deepEqual(backups, [id], `${point}: exactly one backup`);
            assert.deepEqual(await readFile(path.join(ctx.configDir, ".blindpass-backup", id, "openclaw.json")), ctx.original, `${point}: the backup is the original`);
            assert.ok(!(await readdir(ctx.configDir)).includes(".blindpass-migrate.lock"), `${point}: stale lock must not remain`);
            assert.ok(!(await readdir(ctx.configDir)).includes(".blindpass-migrate.plan.json"), point);
            assertNoLeak(assert, await readFile(path.join(ctx.configDir, ".blindpass-migrate.journal.json"), "utf8"), Object.values(ctx.secrets), `${point}: journal`);
        });
    }
});

test("P09-I02 rollback restores the original after a kill at every stage boundary", opts, async () => {
    for (const point of POINTS) {
        await scenario(async (ctx) => {
            const crashed = await crashRun({ action: "apply", options: ctx.options, crashAt: point });
            assert.equal(crashed.signal, "SIGKILL", point);
            const rolled = await rollbackMigration({ configDir: ctx.configDir });
            assert.equal(rolled.status, "rolled-back", point);
            assert.deepEqual(await readJson(ctx.configFile), ctx.config, `${point}: config restored`);
            assert.ok(noRefsToProvider(await readJson(ctx.configFile)), `${point}: no orphaned reference`);
            if (["inventory", "backup", "import"].includes(point.split(":")[0]) || point === "rewrite:after-intent") {
                assert.deepEqual(await readFile(ctx.configFile), ctx.original, `${point}: byte-identical, the config was never rewritten`);
            }
            const stored = (await inspectStore({ storePath: ctx.storePath })).names;
            const beforeImport = point.startsWith("inventory") || point.startsWith("backup") || point === "import:after-intent";
            assert.equal(stored.length, beforeImport ? 0 : 4, `${point}: store entries are kept once imported`);
            assert.equal((await migrationStatus({ configDir: ctx.configDir })).status, "rolled-back", point);
            assert.ok(!(await readdir(ctx.configDir)).includes(".blindpass-migrate.lock"), point);
            assert.ok(!(await readdir(ctx.configDir)).includes(".blindpass-migrate.plan.json"), point);
            assert.equal((await rollbackMigration({ configDir: ctx.configDir })).status, "already-rolled-back");
        });
    }
});

test("P09-I02 a kill during rollback is finished by running rollback again", opts, async () => {
    for (const point of ["rollback:after-intent", "rollback:after-restore"]) {
        await scenario(async (ctx) => {
            await runMigration(ctx.options);
            const crashed = await crashRun({ action: "rollback", options: { configDir: ctx.configDir }, crashAt: point });
            assert.equal(crashed.signal, "SIGKILL", point);
            assert.equal((await migrationStatus({ configDir: ctx.configDir })).status, "rollback-in-progress", point);
            const rolled = await rollbackMigration({ configDir: ctx.configDir });
            assert.equal(rolled.status, "rolled-back", point);
            assert.deepEqual(await readFile(ctx.configFile), ctx.original, point);
            assert.equal((await inspectStore({ storePath: ctx.storePath })).names.length, 4, point);
        });
    }
});

test("P09-I02 concurrent store and config edits while a stage is killed are not lost on resume or rollback", opts, async () => {
    await scenario(async (ctx) => {
        const crashed = await crashRun({ action: "apply", options: ctx.options, crashAt: "import:after-effect" });
        assert.equal(crashed.signal, "SIGKILL");
        const config = await readJson(ctx.configFile);
        config.custom.editedWhileDown = true;
        await writeFile(ctx.configFile, `${JSON.stringify(config, null, 2)}\n`);

        const result = await runMigration(ctx.options);
        assert.equal(result.status, "committed");
        assert.equal((await readJson(ctx.configFile)).custom.editedWhileDown, true);
        await rollbackMigration({ configDir: ctx.configDir });
        const final = await readJson(ctx.configFile);
        assert.equal(final.custom.editedWhileDown, true);
        assert.equal(final.gateway.auth.token, ctx.secrets.gateway);
    });
});
