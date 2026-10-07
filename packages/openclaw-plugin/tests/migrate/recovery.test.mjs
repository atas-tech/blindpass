// P09-I03: missing/wrong age key, unavailable or unusable key backup, the bootstrap warning, and
// restoring the correct key. A migration never succeeds without the key, and there is no plaintext
// fallback.
import assert from "node:assert/strict";
import { chmod, copyFile, mkdir, readFile, readdir, rm, symlink, writeFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import {
    IS_LINUX, TARGET_PATHS, assertNoLeak, snapshotTree, withInstallation as scenario,
} from "./helpers.mjs";
import { EXIT, main } from "../../src/migrate/cli.mjs";
import { PreflightError } from "../../src/migrate/errors.mjs";
import { runMigration } from "../../src/migrate/migrate.mjs";
import { acknowledgeKeyBackup, inspectStore } from "../../src/migrate/store.mjs";

const opts = { skip: !IS_LINUX && "Linux-only" };

function capture() {
    const out = { stdout: "", stderr: "" };
    return {
        out,
        streams: {
            stdout: { write(chunk) { out.stdout += chunk; } },
            stderr: { write(chunk) { out.stderr += chunk; } },
        },
    };
}

async function expectReason(promise, reason) {
    await assert.rejects(promise, (error) => {
        assert.ok(error instanceof PreflightError, `expected PreflightError, got ${error?.constructor?.name}: ${error?.message}`);
        assert.equal(error.reason, reason, error.message);
        return true;
    });
}

const WRONG_KEY = "# created: 2026-10-07T00:00:00Z\n# public key: age1wrongwrongwrongwrongwrongwrongwrongwrongwrongwrongwrongwrongq\nAGE-SECRET-KEY-1WRONGWRONGWRONGWRONGWRONGWRONGWRONGWRONGWRONGWRONGWRONGQ\n";

// A private directory with a copy of the live key, the way an operator keeps an offline backup.
async function keyBackup(ctx, name = "backup-key.txt") {
    const dir = path.join(ctx.base, "offline");
    await mkdir(dir, { recursive: true, mode: 0o700 });
    const file = path.join(dir, name);
    await copyFile(path.join(ctx.storeDir, ".age-key.txt"), file);
    await chmod(file, 0o600);
    return file;
}

async function liveSecretKey(ctx) {
    const text = await readFile(path.join(ctx.storeDir, ".age-key.txt"), "utf8");
    return text.split("\n").find((line) => line.startsWith("AGE-SECRET-KEY-"));
}

const logText = async (ctx) => readFile(ctx.log, "utf8").catch(() => "");

const noMutation = async (ctx, before) => {
    assert.deepEqual(await snapshotTree(ctx.configDir, { ignoreDirMtime: true }), before.config);
};

test("P09-I03 a missing or wrong key is an explicit unavailable state, never a plaintext fallback", opts, async () => {
    for (const arrange of [
        async (ctx) => { await rm(path.join(ctx.storeDir, ".age-key.txt")); },
        async (ctx) => { await writeFile(path.join(ctx.storeDir, ".age-key.txt"), WRONG_KEY, { mode: 0o600 }); },
    ]) {
        await scenario(async (ctx) => {
            await arrange(ctx);
            const before = { config: await snapshotTree(ctx.configDir, { ignoreDirMtime: true }), store: await snapshotTree(ctx.storeDir, { ignoreDirMtime: true }) };
            const logged = (await logText(ctx)).length;
            await expectReason(runMigration(ctx.options), "key-unavailable");
            await expectReason(inspectStore({ storePath: ctx.storePath }), "key-unavailable");
            await noMutation(ctx, before);
            assert.deepEqual(await snapshotTree(ctx.storeDir, { ignoreDirMtime: true }), before.store);
            assert.deepEqual(await readFile(ctx.configFile), ctx.original, "the config still holds its original plaintext, which is reported, not hidden");
            assert.ok(!/dry-run=0|sops encrypt/.test((await logText(ctx)).slice(logged)), "no write was attempted");
        });
    }
});

test("P09-I03 restoring the correct key from a backup lets the migration complete", opts, async () => {
    await scenario(async (ctx) => {
        const backup = await keyBackup(ctx);
        await rm(path.join(ctx.storeDir, ".age-key.txt"));
        await expectReason(runMigration(ctx.options), "key-unavailable");
        await copyFile(backup, path.join(ctx.storeDir, ".age-key.txt"));
        await chmod(path.join(ctx.storeDir, ".age-key.txt"), 0o600);
        const result = await runMigration(ctx.options);
        assert.equal(result.status, "committed");
        assert.equal(result.migrated.length, TARGET_PATHS.length);
    });
});

test("P09-I03 --ack-backup proves the backup can decrypt the store before it clears the pending flag", opts, async () => {
    await scenario(async (ctx) => {
        const backup = await keyBackup(ctx);
        await expectReason(runMigration(ctx.options), "key-backup-pending");

        const { out, streams } = capture();
        assert.equal(await main(["--ack-backup", backup, "--store", ctx.storePath], streams), EXIT.OK);
        assert.match(out.stdout, /acknowledged/i);
        assert.match(out.stdout, /decrypt/i, "the report says what was proven");
        assert.equal((await inspectStore({ storePath: ctx.storePath })).backupPending, false);
        assertNoLeak(assert, out.stdout + out.stderr, [await liveSecretKey(ctx)], "ack output");

        const again = capture();
        assert.equal(await main(["--ack-backup", backup, "--store", ctx.storePath], again.streams), EXIT.OK);
        assert.match(again.out.stdout, /already/i);

        assert.equal((await runMigration(ctx.options)).status, "committed");
    }, { store: { acknowledge: false } });
});

test("P09-I03 an unavailable, unusable or unsafe key backup is refused and the flag stays pending", opts, async () => {
    await scenario(async (ctx) => {
        const offline = path.join(ctx.base, "offline");
        await mkdir(offline, { recursive: true, mode: 0o700 });
        const good = await keyBackup(ctx);
        const cases = [];

        cases.push(["key-backup-unavailable", path.join(offline, "does-not-exist")]);

        const wrong = path.join(offline, "wrong-key.txt");
        await writeFile(wrong, WRONG_KEY, { mode: 0o600 });
        cases.push(["key-backup-unusable", wrong]);

        const notAKey = path.join(offline, "notes.txt");
        await writeFile(notAKey, "just some text\n", { mode: 0o600 });
        cases.push(["key-backup-unusable", notAKey]);

        const loose = path.join(offline, "loose-key.txt");
        await copyFile(good, loose);
        await chmod(loose, 0o644);
        cases.push(["key-backup-unsafe", loose]);

        const link = path.join(offline, "link-key.txt");
        await symlink(good, link);
        cases.push(["key-backup-unsafe", link]);

        cases.push(["key-backup-is-live-key", path.join(ctx.storeDir, ".age-key.txt")]);

        for (const [reason, backupPath] of cases) {
            await expectReason(acknowledgeKeyBackup({ storePath: ctx.storePath, backupPath }), reason);
            assert.equal((await inspectStore({ storePath: ctx.storePath })).backupPending, true, `${reason}: the flag must stay pending`);
            await expectReason(runMigration(ctx.options), "key-backup-pending");
        }
        assert.deepEqual(await readFile(ctx.configFile), ctx.original);

        const relative = capture();
        assert.equal(await main(["--ack-backup", "relative.txt", "--store", ctx.storePath], relative.streams), EXIT.USAGE);
        const refused = capture();
        assert.equal(await main(["--ack-backup", wrong, "--store", ctx.storePath], refused.streams), EXIT.REFUSED);
        assert.match(refused.out.stderr, /key-backup-unusable/);
        assertNoLeak(assert, refused.out.stderr, [await liveSecretKey(ctx)], "refusal output");
    }, { store: { acknowledge: false } });
});

test("P09-I03 acknowledging with a missing store or a store the live key cannot read is refused", opts, async () => {
    await scenario(async (ctx) => {
        const backup = await keyBackup(ctx);
        await expectReason(acknowledgeKeyBackup({ storePath: path.join(ctx.storeDir, "nothing.json"), backupPath: backup }), "store-missing");
        await rm(path.join(ctx.storeDir, ".age-key.txt"));
        await expectReason(acknowledgeKeyBackup({ storePath: ctx.storePath, backupPath: backup }), "key-unavailable");
    }, { store: { acknowledge: false } });
});

test("P09-I03 the dry run surfaces the bootstrap warning and an unavailable key when a store is named, and spawns nothing otherwise", opts, async () => {
    await scenario(async (ctx) => {
        const logged = (await logText(ctx)).length;
        const named = capture();
        assert.equal(await main(["--dry-run", "--config-dir", ctx.configDir, "--store", ctx.storePath, "--json"], named.streams), EXIT.OK);
        const plan = JSON.parse(named.out.stdout);
        assert.ok(plan.warnings.some((warning) => warning.startsWith("bootstrap-backup-pending")), plan.warnings.join("|"));
        assert.equal(plan.store.state, "ready");
        assert.equal(plan.store.backupPending, true);
        assert.ok(!/age-keygen|sops encrypt/.test((await logText(ctx)).slice(logged)), "the store check is read-only");

        const unnamed = capture();
        const before = (await readFile(ctx.log, "utf8").catch(() => "")).length;
        assert.equal(await main(["--dry-run", "--config-dir", ctx.configDir, "--json"], unnamed.streams), EXIT.OK);
        assert.equal(JSON.parse(unnamed.out.stdout).store, undefined);
        assert.equal((await readFile(ctx.log, "utf8").catch(() => "")).length, before, "no store check without --store");

        await rm(path.join(ctx.storeDir, ".age-key.txt"));
        const lost = capture();
        assert.equal(await main(["--dry-run", "--config-dir", ctx.configDir, "--store", ctx.storePath, "--json"], lost.streams), EXIT.OK);
        const lostPlan = JSON.parse(lost.out.stdout);
        assert.ok(lostPlan.warnings.some((warning) => warning.startsWith("key-unavailable")));
        assert.equal(lostPlan.store.state, "unavailable");

        const text = capture();
        await main(["--dry-run", "--config-dir", ctx.configDir, "--store", path.join(ctx.storeDir, "gone.json")], text.streams);
        assert.match(text.out.stdout, /store-missing/);
        assertNoLeak(assert, named.out.stdout + lost.out.stdout + text.out.stdout, Object.values(ctx.secrets), "dry-run output");
        assert.deepEqual(await readdir(ctx.configDir).then((names) => names.sort()), [".env", "agents", "openclaw.json"]);
    }, { store: { acknowledge: false } });
});
