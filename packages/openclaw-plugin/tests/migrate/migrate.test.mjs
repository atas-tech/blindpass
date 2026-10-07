// P09-I02 (non-crash half): the migration orchestrator against the fake sops/age/openclaw toolbox.
// Real-runtime behaviour is covered separately in tests/openclaw/scenarios inside the VM guest.
import assert from "node:assert/strict";
import { chmod, readFile, readdir, rm, symlink, writeFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import {
    IS_LINUX, RELEASE, TARGET_PATHS, assertNoLeak, snapshotTree, withInstallation as scenario,
} from "./helpers.mjs";
import { PreflightError } from "../../src/migrate/errors.mjs";
import { getAt } from "../../src/migrate/config-edit.mjs";
import { Journal } from "../../src/migrate/journal.mjs";
import { migrationStatus, rollbackMigration, runMigration } from "../../src/migrate/migrate.mjs";
import { openTrustedRoot, UnsafePathError } from "../../src/migrate/safe-fs.mjs";
import { importEntries, inspectStore } from "../../src/migrate/store.mjs";

const opts = { skip: !IS_LINUX && "Linux-only" };

const readJson = async (file) => JSON.parse(await readFile(file, "utf8"));
const calls = async (ctx) => (await readFile(ctx.log, "utf8").catch(() => "")).split("\n");
const refFor = (p) => ({ source: "exec", provider: "blindpass", id: `openclaw.${p}` });

async function expectReason(promise, reason) {
    await assert.rejects(promise, (error) => {
        assert.ok(error instanceof PreflightError, `expected PreflightError, got ${error?.constructor?.name}: ${error?.message}`);
        assert.equal(error.reason, reason, error.message);
        return true;
    });
}

// Everything under the config and store directories, by content: proves a refusal changed nothing.
async function state(ctx) {
    return {
        config: await snapshotTree(ctx.configDir, { ignoreDirMtime: true }),
        store: await snapshotTree(ctx.storeDir, { ignoreDirMtime: true }),
    };
}

function expectedMigratedConfig(ctx, skip = []) {
    const config = structuredClone(ctx.config);
    for (const p of TARGET_PATHS.filter((entry) => !skip.includes(entry))) {
        const segments = p.split(".");
        let node = config;
        for (const segment of segments.slice(0, -1)) {
            node = node[segment];
        }
        node[segments.at(-1)] = refFor(p);
    }
    return config;
}

function withoutProvider(config) {
    const copy = structuredClone(config);
    delete copy.secrets;
    delete copy.meta;
    return copy;
}

test("P09-I02 apply migrates every credential, keeps unrelated config, and leaks nothing", opts, async () => {
    await scenario(async (ctx) => {
        const result = await runMigration(ctx.options);
        assert.equal(result.status, "committed");
        assert.deepEqual(result.migrated.map((entry) => entry.path).sort(), TARGET_PATHS);

        const config = await readJson(ctx.configFile);
        assert.deepEqual(withoutProvider(config), expectedMigratedConfig(ctx));
        assert.equal(config.secrets.providers.blindpass.command, ctx.resolver);
        assert.deepEqual(config.secrets.providers.blindpass.args, ["--store", ctx.storePath]);

        const store = await inspectStore({ storePath: ctx.storePath });
        assert.deepEqual(store.names, TARGET_PATHS.map((p) => `openclaw.${p}`).sort());

        const backup = path.join(ctx.configDir, result.backupDir, "openclaw.json");
        assert.deepEqual(await readFile(backup), ctx.original);
        assert.equal((await readFile(path.join(ctx.configDir, ".blindpass-migrate.journal.json"), "utf8")).includes('"committed"'), true);
        assert.ok(!(await readdir(ctx.configDir)).includes(".blindpass-migrate.plan.json"), "the apply plan file is removed on commit");
        assert.ok(!(await readdir(ctx.configDir)).includes(".blindpass-migrate.lock"), "the lock is released");

        assert.deepEqual(result.residual.sort(), [".env", "agents/main/agent/models.json", "openclaw.json.bak"]);
        assert.deepEqual(result.warnings, [], "the provider and meta the native write adds are expected, not reported");
        assert.ok(result.nextSteps.some((step) => /reload/i.test(step)));

        // Native order: schema dry run, then the resolvability dry run with --allow-exec, then the write.
        const native = (await calls(ctx)).filter((line) => line.startsWith("openclaw apply"));
        const writeAt = native.findIndex((line) => line.includes("dry-run=0"));
        assert.ok(writeAt > 0 && native[writeAt].includes("allow-exec=1"), native.join("\n"));
        assert.ok(native.slice(0, writeAt).some((line) => line.includes("dry-run=1 allow-exec=1")), native.join("\n"));

        const canaries = Object.values(ctx.secrets);
        assertNoLeak(assert, JSON.stringify(result), canaries, "result");
        assertNoLeak(assert, await readFile(path.join(ctx.configDir, ".blindpass-migrate.journal.json"), "utf8"), canaries, "journal");
        assertNoLeak(assert, (await calls(ctx)).join("\n"), canaries, "tool log");
        assertNoLeak(assert, await readFile(ctx.configFile, "utf8"), canaries, "migrated config");
    });
});

test("P09-D5 every refusal happens before any change and before the native write", opts, async () => {
    const refusals = [
        ["store-missing", async (ctx) => { await rm(ctx.storePath); }],
        ["key-unavailable", async (ctx) => { await rm(path.join(ctx.storeDir, ".age-key.txt")); }],
        ["resolver-untrusted", async (ctx) => {
            const shim = path.join(path.dirname(ctx.resolver), "shim");
            await symlink(ctx.resolver, shim);
            ctx.options.resolverCommand = shim;
        }],
        ["native-version", async (ctx) => { await ctx.toolbox.configure({ openclawVersion: "2026.9.8", log: ctx.log }); }],
        ["provider-alias-conflict", async (ctx) => {
            const config = structuredClone(ctx.config);
            config.secrets = { providers: { blindpass: { source: "exec", command: "/usr/bin/other", args: [] } } };
            await writeFile(ctx.configFile, `${JSON.stringify(config, null, 2)}\n`);
        }],
        ["store-name-conflict", async (ctx) => {
            await importEntries({ storePath: ctx.storePath, entries: [{ name: "openclaw.gateway.auth.token", value: "a-different-value", source: "test" }], migrationId: "m-20261007T000000Z-00000000" });
        }],
    ];
    for (const [reason, arrange] of refusals) {
        await scenario(async (ctx) => {
            await arrange(ctx);
            const before = await state(ctx);
            await expectReason(runMigration(ctx.options), reason);
            assert.deepEqual(await state(ctx), before, `${reason} must not change any file`);
            const lines = await calls(ctx);
            assert.ok(!lines.some((line) => line.includes("dry-run=0")), `${reason} reached the native write`);
        });
    }
});

test("P09-D5 a store whose backup is not acknowledged blocks mutation", opts, async () => {
    await scenario(async (ctx) => {
        const before = await state(ctx);
        await expectReason(runMigration(ctx.options), "key-backup-pending");
        assert.deepEqual(await state(ctx), before);
    }, { store: { acknowledge: false } });
});

test("P09-D3 an unsafe config directory is refused before any step", opts, async () => {
    await scenario(async (ctx) => {
        await chmod(ctx.configDir, 0o777);
        await assert.rejects(runMigration(ctx.options), (error) => error instanceof UnsafePathError);
        await chmod(ctx.configDir, 0o700);
        const link = path.join(ctx.base, "link");
        await symlink(ctx.configDir, link);
        await assert.rejects(runMigration({ ...ctx.options, configDir: link }), (error) => error instanceof UnsafePathError);
        assert.deepEqual(await readFile(ctx.configFile), ctx.original);
    });
});

test("P09-D2 targets the installed runtime does not accept stay plaintext, are reported, and are never imported", opts, async () => {
    await scenario(async (ctx) => {
        const result = await runMigration(ctx.options);
        assert.equal(result.status, "committed");
        assert.deepEqual(result.migrated.map((entry) => entry.path).sort(), ["gateway.auth.token", "models.providers.mockai.apiKey", "skills.entries.demo.apiKey"]);
        assert.deepEqual(result.unsupported.filter((entry) => entry.path === "channels.telegram.botToken").map((entry) => entry.reason), ["runtime-does-not-accept-target"]);
        const config = await readJson(ctx.configFile);
        assert.equal(config.channels.telegram.botToken, ctx.secrets.telegram, "an unaccepted target is left exactly as it was");
        const store = await inspectStore({ storePath: ctx.storePath });
        assert.ok(!store.names.includes("openclaw.channels.telegram.botToken"));
        assert.deepEqual(withoutProvider(config), expectedMigratedConfig(ctx, ["channels.telegram.botToken"]));
    }, { fake: { reject: ["channels.telegram.botToken"] } });
});

test("P09-I02 nothing to migrate changes nothing and leaves no journal", opts, async () => {
    await scenario(async (ctx) => {
        await writeFile(ctx.configFile, `${JSON.stringify({ gateway: { port: 1 } }, null, 2)}\n`);
        const before = await state(ctx);
        const result = await runMigration(ctx.options);
        assert.equal(result.status, "nothing-to-migrate");
        assert.deepEqual(await state(ctx), before);
    });
});

test("P09-I02 a runtime that accepts none of the targets leaves no journal either", opts, async () => {
    await scenario(async (ctx) => {
        const before = await state(ctx);
        const result = await runMigration(ctx.options);
        assert.equal(result.status, "nothing-to-migrate");
        assert.deepEqual(await state(ctx), before);
    }, { fake: { reject: ["channels.telegram.botToken", "gateway.auth.token", "models.providers.*.apiKey", "skills.entries.*.apiKey"] } });
});

test("P09-I02 resolver mismatch fails the import stage before any reference is rewritten", opts, async () => {
    await scenario(async (ctx) => {
        // A resolver that answers with the wrong values must stop the migration with the config untouched.
        const broken = path.join(path.dirname(ctx.resolver), "broken-resolver");
        await writeFile(broken, "#!/usr/bin/env node\nprocess.stdin.resume();process.stdin.on('end',()=>process.stdout.write(JSON.stringify({protocolVersion:1,values:{}})));\n", { mode: 0o755 });
        await chmod(broken, 0o755);
        await expectReason(runMigration({ ...ctx.options, resolverCommand: broken }), "resolver-unresolved");
        assert.deepEqual(await readFile(ctx.configFile), ctx.original);
        const status = await migrationStatus({ configDir: ctx.configDir });
        assert.equal(status.status, "failed");
        assert.equal(status.failure.stage, "import");
        assert.equal(status.failure.reason, "resolver-unresolved");
        assert.ok(!(await calls(ctx)).some((line) => line.includes("dry-run=0")));
        assertNoLeak(assert, JSON.stringify(status), Object.values(ctx.secrets), "status");
    });
});

test("P09-I02 a failed native write leaves the config unchanged and the run resumable", opts, async () => {
    await scenario(async (ctx) => {
        await ctx.toolbox.configure({ failWrite: true, log: ctx.log });
        await expectReason(runMigration(ctx.options), "native-apply-failed");
        assert.deepEqual(await readFile(ctx.configFile), ctx.original);
        assert.equal((await migrationStatus({ configDir: ctx.configDir })).status, "failed");

        await ctx.toolbox.configure({ log: ctx.log });
        const result = await runMigration(ctx.options);
        assert.equal(result.status, "committed");
        assert.equal(result.migrated.length, 4);
        assert.equal((await readdir(path.join(ctx.configDir, ".blindpass-backup"))).length, 1, "the resumed run reuses the backup");
    });
});

test("P09-I02 native crash around the config rename is reconciled on rerun, and rollback still works", opts, async () => {
    for (const crash of ["before-rename", "after-rename"]) {
        await scenario(async (ctx) => {
            await ctx.toolbox.configure({ crash, log: ctx.log });
            await expectReason(runMigration(ctx.options), "native-apply-failed");
            const afterCrash = await readJson(ctx.configFile);
            assert.equal(getAt(afterCrash, ["gateway", "auth", "token"]) === ctx.secrets.gateway, crash === "before-rename");

            await ctx.toolbox.configure({ log: ctx.log });
            const result = await runMigration(ctx.options);
            assert.equal(result.status, "committed");
            assert.deepEqual(withoutProvider(await readJson(ctx.configFile)), expectedMigratedConfig(ctx));
            const rolled = await rollbackMigration({ configDir: ctx.configDir });
            assert.equal(rolled.status, "rolled-back");
            assert.deepEqual(await readJson(ctx.configFile), ctx.config);
        });
    }
});

test("P09-I02 a rerun after commit reports nothing to migrate and a new secret starts a second migration", opts, async () => {
    await scenario(async (ctx) => {
        const first = await runMigration(ctx.options);
        assert.equal(first.status, "committed");
        assert.equal((await runMigration(ctx.options)).status, "nothing-to-migrate");

        const config = await readJson(ctx.configFile);
        const extra = "P09-CANARY-LATE-0123456789ab";
        config.channels.discord = { token: extra };
        await writeFile(ctx.configFile, `${JSON.stringify(config, null, 2)}\n`);
        const second = await runMigration(ctx.options);
        assert.equal(second.status, "committed");
        assert.notEqual(second.migrationId, first.migrationId);
        assert.deepEqual(second.migrated.map((entry) => entry.path), ["channels.discord.token"]);
        const names = await readdir(ctx.configDir);
        assert.ok(names.includes(`.blindpass-migrate.journal.${first.migrationId}.json`), "the first journal is archived, not lost");

        // Rolling back the first migration restores its paths only; the second migration's reference survives.
        const rolled = await rollbackMigration({ configDir: ctx.configDir, migrationId: first.migrationId });
        assert.equal(rolled.status, "rolled-back");
        const final = await readJson(ctx.configFile);
        assert.equal(getAt(final, ["gateway", "auth", "token"]), ctx.secrets.gateway);
        assert.deepEqual(getAt(final, ["channels", "discord", "token"]), { source: "exec", provider: "blindpass", id: "openclaw.channels.discord.token" });
        assert.ok(getAt(final, ["secrets", "providers", "blindpass"]), "the provider stays while a reference to it remains");
    });
});

test("P09-I02 rollback restores the original byte for byte, keeps store entries and residue, and is idempotent", opts, async () => {
    await scenario(async (ctx) => {
        const result = await runMigration(ctx.options);
        const residueBefore = await readFile(path.join(ctx.configDir, "openclaw.json.bak"));
        const rolled = await rollbackMigration({ configDir: ctx.configDir });
        assert.equal(rolled.status, "rolled-back");
        assert.equal(rolled.method, "byte-for-byte");
        assert.deepEqual(await readFile(ctx.configFile), ctx.original);
        assert.deepEqual(await readFile(path.join(ctx.configDir, "openclaw.json.bak")), residueBefore, "OpenClaw's own .bak is not ours to touch");
        assert.equal((await inspectStore({ storePath: ctx.storePath })).names.length, 4, "encrypted store entries are kept");
        assert.ok((await readdir(path.join(ctx.configDir, ".blindpass-backup"))).includes(result.migrationId), "the plaintext backup is retained for the operator");
        assert.equal((await migrationStatus({ configDir: ctx.configDir })).status, "rolled-back");
        assert.equal((await rollbackMigration({ configDir: ctx.configDir })).status, "already-rolled-back");
        assertNoLeak(assert, JSON.stringify(rolled), Object.values(ctx.secrets), "rollback result");
    });
});

test("P09-I02 rollback with no migration is a refusal", opts, async () => {
    await scenario(async (ctx) => {
        await expectReason(rollbackMigration({ configDir: ctx.configDir }), "no-migration");
    });
});

test("P09-I02 unrelated config edits made during and after the migration survive rollback", opts, async () => {
    await scenario(async (ctx) => {
        const edit = async (mutate) => {
            const config = await readJson(ctx.configFile);
            mutate(config);
            await writeFile(ctx.configFile, `${JSON.stringify(config, null, 2)}\n`);
        };
        let edited = false;
        const result = await runMigration({
            ...ctx.options,
            hooks: {
                async at(point) {
                    if (point === "backup:after-effect" && !edited) {
                        edited = true;
                        await edit((config) => { config.custom.addedDuringMigration = true; });
                    }
                },
            },
        });
        assert.equal(result.status, "committed");
        assert.equal((await readJson(ctx.configFile)).custom.addedDuringMigration, true, "an unrelated edit made mid-migration is preserved by the native write");

        await edit((config) => { config.custom.addedAfterMigration = "later"; });
        const rolled = await rollbackMigration({ configDir: ctx.configDir });
        assert.equal(rolled.method, "per-path");
        const final = await readJson(ctx.configFile);
        assert.equal(final.custom.addedDuringMigration, true);
        assert.equal(final.custom.addedAfterMigration, "later");
        for (const p of TARGET_PATHS) {
            assert.equal(getAt(final, p.split(".")), getAt(ctx.config, p.split(".")), `${p} is restored`);
        }
        assert.equal(final.secrets, undefined, "the provider this migration added is removed once nothing references it");
    });
});

test("P09-I02 a credential rotated during the migration is not overwritten", opts, async () => {
    await scenario(async (ctx) => {
        const rotated = "P09-CANARY-ROTATED-aabbccddeeff";
        await assert.rejects(runMigration({
            ...ctx.options,
            hooks: {
                async at(point) {
                    if (point === "import:after-effect") {
                        const config = await readJson(ctx.configFile);
                        config.gateway.auth.token = rotated;
                        await writeFile(ctx.configFile, `${JSON.stringify(config, null, 2)}\n`);
                    }
                },
            },
        }), (error) => error instanceof PreflightError && error.reason === "config-changed");
        assert.equal((await readJson(ctx.configFile)).gateway.auth.token, rotated);
        const rolled = await rollbackMigration({ configDir: ctx.configDir });
        assert.equal(rolled.status, "rolled-back");
        assert.equal((await readJson(ctx.configFile)).gateway.auth.token, rotated, "rollback must not resurrect the backed-up value");
        assertNoLeak(assert, JSON.stringify(await migrationStatus({ configDir: ctx.configDir })), [...Object.values(ctx.secrets), rotated], "status");
    });
});

test("P09-I02 store entries added concurrently survive the import and the rollback", opts, async () => {
    await scenario(async (ctx) => {
        await runMigration({
            ...ctx.options,
            hooks: {
                async at(point) {
                    if (point === "import:after-effect") {
                        await importEntries({ storePath: ctx.storePath, entries: [{ name: "operator.entry", value: "operator-value-1234", source: "test" }], migrationId: "m-20261007T000000Z-00000001" });
                    }
                },
            },
        });
        await rollbackMigration({ configDir: ctx.configDir });
        const names = (await inspectStore({ storePath: ctx.storePath })).names;
        assert.ok(names.includes("operator.entry"));
        assert.equal(names.length, 5);
    });
});

test("P09-D4 a live lock stops a second migration without changing anything", opts, async () => {
    await scenario(async (ctx) => {
        await writeFile(path.join(ctx.configDir, ".blindpass-migrate.lock"), `${JSON.stringify({ pid: process.pid, startTicks: null, token: "x", startedAt: new Date().toISOString() })}\n`, { mode: 0o600 });
        const before = await state(ctx);
        await assert.rejects(runMigration(ctx.options), (error) => error.name === "LockHeldError");
        assert.deepEqual(await state(ctx), before);
    });
});

test("P09-D4 an unfinished journal from different settings is refused, and a stale one is flagged", opts, async () => {
    await scenario(async (ctx) => {
        const dir = await openTrustedRoot(ctx.configDir);
        try {
            const journal = await Journal.create(dir, { release: RELEASE, providerAlias: "other", storePath: ctx.storePath, resolverCommand: ctx.resolver, now: () => new Date(Date.now() - 3 * 24 * 3600 * 1000) });
            await journal.stageIntent("inventory", new Date(Date.now() - 3 * 24 * 3600 * 1000));
        } finally {
            await dir.close();
        }
        const status = await migrationStatus({ configDir: ctx.configDir });
        assert.match(status.warnings.join("\n"), /journal-stale/);
        await expectReason(runMigration(ctx.options), "journal-mismatch");
        assert.deepEqual(await readFile(ctx.configFile), ctx.original);
    });
});

test("P09-D6 status reports stages, backup location and residual files without any value", opts, async () => {
    await scenario(async (ctx) => {
        const result = await runMigration(ctx.options);
        const status = await migrationStatus({ configDir: ctx.configDir });
        assert.equal(status.migrationId, result.migrationId);
        assert.equal(status.status, "committed");
        assert.equal(status.backupDir, result.backupDir);
        assert.deepEqual(Object.keys(status.stages).sort(), ["backup", "commit", "import", "inventory", "rewrite"]);
        assert.deepEqual(status.residual.sort(), [".env", "agents/main/agent/models.json", "openclaw.json.bak"]);
        assertNoLeak(assert, JSON.stringify(status), Object.values(ctx.secrets), "status");
        assert.equal((await migrationStatus({ configDir: path.join(ctx.base, "store") })).status, "none");
    });
});
