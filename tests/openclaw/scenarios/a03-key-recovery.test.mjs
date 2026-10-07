// Pilot A03 / P09-I03 (real sops and age): key loss, wrong key, bootstrap warning, backup acknowledgement
// and restoring the correct key. A migration never succeeds without the key.
import assert from "node:assert/strict";
import { chmod, copyFile, readFile, rm, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import path from "node:path";
import test from "node:test";
import { snapshotTree } from "../../../packages/openclaw-plugin/tests/migrate/helpers.mjs";
import {
    applyArgs, assertNoWindows, authed, backupKey, destroyRig, evidence, initStore, makeRig, migrate,
    startGateway,
} from "./lib.mjs";

test("A03 key loss, wrong key, backup acknowledgement and recovery with real sops/age", { timeout: 600000 }, async () => {
    const rig = await makeRig({ telegram: false });
    try {
        assert.equal(initStore(rig).code, 0);
        await backupKey(rig);
        const liveKey = await readFile(path.join(rig.store, ".age-key.txt"), "utf8");
        const secretKeyLine = liveKey.split("\n").find((line) => line.startsWith("AGE-SECRET-KEY-"));

        // Bootstrap warning blocks mutation until the backup is acknowledged.
        const pending = migrate(rig, applyArgs(rig));
        assert.equal(pending.code, 3);
        assert.match(pending.stderr, /key-backup-pending/);
        assert.deepEqual(await readFile(rig.configFile), rig.original);
        evidence("A03", "bootstrap_backup_pending blocks --apply (exit 3) and leaves openclaw.json untouched");

        // Bad backups are refused by the real sops check; the flag stays pending.
        const stranger = spawnSync("age-keygen", { encoding: "utf8" });
        const strangerFile = path.join(rig.offline, "stranger-key.txt");
        await writeFile(strangerFile, stranger.stdout, { mode: 0o600 });
        const wrong = migrate(rig, ["--ack-backup", strangerFile, "--store", rig.storePath]);
        assert.equal(wrong.code, 3);
        assert.match(wrong.stderr, /key-backup-unusable/);
        const loose = path.join(rig.offline, "loose-key.txt");
        await copyFile(rig.keyBackup, loose);
        await chmod(loose, 0o644);
        assert.match(migrate(rig, ["--ack-backup", loose, "--store", rig.storePath]).stderr, /key-backup-unsafe/);
        assert.match(migrate(rig, ["--ack-backup", path.join(rig.store, ".age-key.txt"), "--store", rig.storePath]).stderr, /key-backup-is-live-key/);
        assert.match(migrate(rig, ["--ack-backup", path.join(rig.offline, "missing.txt"), "--store", rig.storePath]).stderr, /key-backup-unavailable/);
        const stillPending = JSON.parse(migrate(rig, ["--dry-run", "--config-dir", rig.state, "--store", rig.storePath, "--json"]).stdout);
        assert.equal(stillPending.store.backupPending, true);
        evidence("A03", "a stranger's key, a group-readable file, the live key and a missing file are all refused by --ack-backup; the flag stays pending");

        // A valid backup: proven by decrypting the real store with only that key, then acknowledged.
        const ack = migrate(rig, ["--ack-backup", rig.keyBackup, "--store", rig.storePath]);
        assert.equal(ack.code, 0, ack.stderr);
        assertNoWindows(assert, ack.stdout + ack.stderr, [secretKeyLine], "ack output");
        evidence("A03", "--ack-backup decrypted the real sops store with only the backup key, then cleared the flag; key material never printed");

        // Key loss: refused before any change, no plaintext fallback.
        await rm(path.join(rig.store, ".age-key.txt"));
        const before = await snapshotTree(rig.state);
        const lost = migrate(rig, applyArgs(rig));
        assert.equal(lost.code, 3);
        assert.match(lost.stderr, /key-unavailable/);
        assert.deepEqual(await snapshotTree(rig.state), before, "nothing in the config directory changed");
        const dry = JSON.parse(migrate(rig, ["--dry-run", "--config-dir", rig.state, "--store", rig.storePath, "--json"]).stdout);
        assert.equal(dry.store.state, "unavailable");
        evidence("A03", "with the key file deleted --apply refuses (exit 3, key-unavailable) with no change; the dry run reports the store unavailable");

        // Wrong key in place of the lost one: also unavailable.
        await writeFile(path.join(rig.store, ".age-key.txt"), stranger.stdout, { mode: 0o600 });
        assert.match(migrate(rig, applyArgs(rig)).stderr, /key-unavailable/);
        evidence("A03", "a different (wrong) age key at the store's key path is refused as key-unavailable");

        // Restore the correct key and complete the migration; real use proves the restore.
        await copyFile(rig.keyBackup, path.join(rig.store, ".age-key.txt"));
        await chmod(path.join(rig.store, ".age-key.txt"), 0o600);
        const applied = migrate(rig, applyArgs(rig));
        assert.equal(applied.code, 0, applied.stderr);
        await startGateway(rig);
        assert.equal(authed(rig, rig.secrets.gateway), true);
        evidence("A03", "after restoring the correct key from the backup the migration completed and the real gateway authenticated with the store-resolved token");
    } finally {
        await destroyRig(rig);
    }
});
