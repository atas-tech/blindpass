// Pilot A02 (rollback half) / P09-E02: roll a real migration back, repeat the original task, and inspect
// logs and artifacts. Originals are removed only by a separate explicit action, never by this tool.
import assert from "node:assert/strict";
import { readFile, readdir, stat } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import {
    applyArgs, assertNoWindows, authed, destroyRig, evidence, filesHolding, makeCanary, makeRig, migrate,
    readyStore, startGateway,
} from "./lib.mjs";

test("E02 rollback restores the original behaviour on the real gateway and exposes nothing new", { timeout: 600000 }, async () => {
    const rig = await makeRig({ telegram: false });
    const canaries = Object.values(rig.secrets);
    try {
        const original = await startGateway(rig);
        assert.equal(authed(rig, rig.secrets.gateway), true, "baseline: the original task works");
        await original.stop();

        await readyStore(rig);
        const applied = migrate(rig, applyArgs(rig));
        assert.equal(applied.code, 0, applied.stderr);

        const migrated = await startGateway(rig);
        assert.equal(authed(rig, rig.secrets.gateway), true, "on the migrated config the same token works (resolved from the store)");
        await migrated.stop();

        const rolled = migrate(rig, ["--rollback", "--config-dir", rig.state]);
        assert.equal(rolled.code, 0, rolled.stderr);
        assert.match(rolled.stdout, /rolled back/i);
        assert.deepEqual(await readFile(rig.configFile), rig.original, "openclaw.json is byte-identical to the original");
        evidence("E02", `rollback restored openclaw.json byte for byte (${/byte-for-byte/.test(rolled.stdout) ? "byte-for-byte" : "per-path"} restore)`);

        const again = await startGateway(rig);
        assert.equal(authed(rig, rig.secrets.gateway), true, "the original task is repeated successfully after rollback");
        assert.equal(authed(rig, makeCanary("WRONG")), false);
        evidence("E02", "after rollback the real gateway authenticates with the original plaintext token again");
        await again.stop();

        // Nothing is removed implicitly: backup, OpenClaw's .bak and the store survive the rollback.
        const names = await readdir(rig.state);
        assert.ok(names.includes(".blindpass-backup"), "the protected backup is kept");
        assert.ok(names.some((name) => /^openclaw\.json\.bak/.test(name)), "OpenClaw's own .bak is not deleted");
        assert.ok((await stat(rig.storePath)).isFile(), "the encrypted store is kept");
        const status = JSON.parse(migrate(rig, ["--status", "--config-dir", rig.state, "--json"]).stdout);
        assert.equal(status.status, "rolled-back");
        evidence("E02", "after rollback the protected backup, openclaw.json.bak and the encrypted store are all still present; removal is a separate operator action");

        // Exposure inspection of logs and artifacts.
        const logs = (await Promise.all(rig.gatewayLogs.map((file) => readFile(file, "utf8")))).join("\n");
        assertNoWindows(assert, logs + rig.outputs.join("\n"), canaries, "gateway logs and tool output");
        const journal = await readFile(path.join(rig.state, ".blindpass-migrate.journal.json"), "utf8");
        assertNoWindows(assert, journal, canaries, "journal");
        const stray = await filesHolding([rig.root, "/tmp/openclaw"], canaries, {
            skip: (file) => file.includes("/.blindpass-backup/") || /\.bak(\.\d+)?$/.test(file) || /\/gateway-\d+\.log$/.test(file),
        });
        // openclaw.json.last-good is the gateway's own last-known-good copy of the config it just started on (the
        // restored plaintext config here); like .bak it is OpenClaw's file, and the migration's residual scan lists it.
        assert.deepEqual(
            stray.map((file) => path.relative(rig.root, file)).sort(),
            ["state/.env", "state/openclaw.json", "state/openclaw.json.last-good"],
            `unexpected plaintext locations: ${stray.join(", ")}`,
        );
        evidence("E02", "artifact scan: plaintext exists only in the restored openclaw.json, the untouched .env, the protected backup, OpenClaw's .bak and its last-good copy; none in the journal, the store ciphertext, the plan, tool output or logs");
    } finally {
        await destroyRig(rig);
    }
});
