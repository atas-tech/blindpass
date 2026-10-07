// P09-I02 (real runtime): SIGKILL the migration at every journal boundary of every stage against the real
// OpenClaw CLI, sops and age, then resume or roll back, and prove the real gateway still works.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import {
    CRASH_RUNNER, OPENCLAW, RELEASE, authed, destroyRig, evidence, makeRig, migrate, readJson, readyStore,
    startGateway,
} from "./lib.mjs";

const STAGES = ["inventory", "backup", "import", "rewrite", "commit"];
const POINTS = STAGES.flatMap((stage) => [`${stage}:after-intent`, `${stage}:after-effect`]);

function options(rig) {
    return { configDir: rig.state, release: RELEASE, providerAlias: "blindpass", resolverCommand: rig.resolver, storePath: rig.storePath, openclawBin: OPENCLAW };
}

function crash(rig, spec) {
    return new Promise((resolve, reject) => {
        const child = spawn(process.execPath, [CRASH_RUNNER, JSON.stringify(spec)], { stdio: ["ignore", "pipe", "pipe"], env: { PATH: process.env.PATH, HOME: process.env.HOME } });
        let stderr = "";
        child.stderr.on("data", (chunk) => { stderr += chunk; });
        child.on("error", reject);
        child.on("close", (code, signal) => resolve({ code, signal, stderr }));
    });
}

test("I02 real runtime: a kill at every stage boundary is completed by a rerun and the gateway authenticates", { timeout: 3600000 }, async () => {
    for (const point of POINTS) {
        const rig = await makeRig({ telegram: false });
        try {
            await readyStore(rig);
            const killed = await crash(rig, { action: "apply", options: options(rig), crashAt: point });
            assert.equal(killed.signal, "SIGKILL", `${point}: ${killed.stderr.slice(0, 200)}`);
            const status = JSON.parse(migrate(rig, ["--status", "--config-dir", rig.state, "--json"]).stdout);
            assert.equal(status.status, "in-progress", point);

            const resumed = migrate(rig, ["--apply", "--config-dir", rig.state, "--store", rig.storePath, "--resolver-command", rig.resolver, "--openclaw-bin", OPENCLAW, "--json"]);
            assert.equal(resumed.code, 0, `${point}: ${resumed.stderr.slice(0, 300)}`);
            const result = JSON.parse(resumed.stdout);
            assert.equal(result.migrationId, status.migrationId, `${point}: same migration resumed`);
            assert.equal((await readdir(path.join(rig.state, ".blindpass-backup"))).length, 1, `${point}: one backup`);
            const config = await readJson(rig.configFile);
            assert.equal(config.gateway.auth.token.source, "exec", point);

            await startGateway(rig);
            assert.equal(authed(rig, rig.secrets.gateway), true, `${point}: authenticated use after resume`);
            evidence("I02", `real kill at ${point}: rerun resumed the same migration, one backup, real gateway authenticated with the store-resolved token`);
        } finally {
            await destroyRig(rig);
        }
    }
});

test("I02 real runtime: rollback after a kill at every stage boundary restores the original task", { timeout: 3600000 }, async () => {
    for (const point of POINTS) {
        const rig = await makeRig({ telegram: false });
        try {
            await readyStore(rig);
            const killed = await crash(rig, { action: "apply", options: options(rig), crashAt: point });
            assert.equal(killed.signal, "SIGKILL", point);
            const rolled = migrate(rig, ["--rollback", "--config-dir", rig.state]);
            assert.equal(rolled.code, 0, `${point}: ${rolled.stderr.slice(0, 300)}`);
            const restored = await readJson(rig.configFile);
            assert.deepEqual(restored.gateway, rig.config.gateway, `${point}: gateway section restored`);
            assert.deepEqual(restored.skills, rig.config.skills, `${point}: skills restored`);
            assert.equal(restored.secrets, undefined, `${point}: no leftover provider or reference`);
            assert.ok(!JSON.stringify(restored).includes('"provider": "blindpass"') && !JSON.stringify(restored).includes('"provider":"blindpass"'), point);
            await startGateway(rig);
            assert.equal(authed(rig, rig.secrets.gateway), true, `${point}: the original task works after rollback`);
            evidence("I02", `real kill at ${point}: rollback restored the original config; the real gateway authenticated with the original plaintext token`);
        } finally {
            await destroyRig(rig);
        }
    }
});
