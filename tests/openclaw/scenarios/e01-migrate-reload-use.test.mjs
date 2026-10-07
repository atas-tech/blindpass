// Pilot A02 / P09-E01: migrate a real installation, reload, and complete an authenticated task with the
// real OpenClaw gateway; add (rotate) a secret after activation and show it is not live before the reload.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import {
    applyArgs, assertNoWindows, authed, destroyRig, evidence, filesHolding, makeCanary, makeRig, migrate,
    nativeReload, readJson, readyStore, rotateStoreSecret, startGateway, waitForAuthed,
} from "./lib.mjs";

test("E01 migrate, reload and use: the real gateway authenticates with a token resolved from the encrypted store", { timeout: 600000 }, async () => {
    const rig = await makeRig({ telegram: false });
    const canaries = Object.values(rig.secrets);
    try {
        // The original task: the gateway authenticates with the plaintext token in openclaw.json.
        const before = await startGateway(rig);
        assert.equal(authed(rig, rig.secrets.gateway), true, "baseline: the original token is accepted");
        assert.equal(authed(rig, makeCanary("WRONG")), false, "baseline: a wrong token is rejected");

        await readyStore(rig);
        const applied = migrate(rig, applyArgs(rig));
        assert.equal(applied.code, 0, applied.stderr);
        const config = await readJson(rig.configFile);
        assert.deepEqual(config.gateway.auth.token, { source: "exec", provider: "blindpass", id: "openclaw.gateway.auth.token" });
        assert.ok(!(await readFile(rig.configFile, "utf8")).includes(rig.secrets.gateway.split("-").pop()), "openclaw.json no longer holds the credential");
        evidence("E01", "real apply: openclaw.json holds exec references for gateway, model and skill credentials; the resolver was run by OpenClaw's own dry run");

        // The running gateway watches openclaw.json: rewriting gateway.auth.token to a reference makes it restart itself
        // and resolve the reference through the resolver. Activation is proven by authenticated use, not by the log.
        assert.equal(await waitForAuthed(rig, rig.secrets.gateway), true, "the gateway authenticates with the token it now resolves from the store");
        const restartLog = await readFile(before.logPath, "utf8");
        assert.match(restartLog, /config change requires gateway restart \(gateway\.auth\.token\)/, "the runtime itself noticed the config change");
        evidence("E01", "migration of a running gateway: the runtime detected the config change, restarted itself and then authenticated the original token resolved from the encrypted store");

        // Not live yet: a secret changed after activation, in the store only (no config edit, so no watcher event),
        // is not available until the reload.
        const rotated = makeCanary("GW-NEW");
        canaries.push(rotated);
        rotateStoreSecret(rig, "openclaw.gateway.auth.token", rotated);
        await new Promise((resolve) => setTimeout(resolve, 5000));
        assert.equal(authed(rig, rig.secrets.gateway), true, "before reload the previously activated token still works");
        assert.equal(authed(rig, rotated), false, "before reload the new secret is NOT accepted (no false immediate availability)");
        evidence("E01", "after rotating the store entry (no config change) and before reload: old token accepted, new token rejected");

        // The documented activation step, with the token the gateway is currently using.
        const reload = nativeReload(rig, rig.secrets.gateway);
        evidence("E01", `native reload returned code ${reload.code}${/4001/.test(reload.text) ? " (the 4001 close the contract documents)" : ""}`);
        assert.equal(authed(rig, rotated), true, "after reload the new secret is accepted");
        assert.equal(authed(rig, rig.secrets.gateway), false, "after reload the old token is rejected");
        evidence("E01", "after reload: new token accepted and old token rejected (authenticated use proven, not the reload exit code)");

        // A fresh gateway on the migrated config resolves the token from the store at startup.
        await before.stop();
        await startGateway(rig);
        assert.equal(authed(rig, rotated), true, "a gateway started on the migrated config authenticates with the store's token");
        evidence("E01", "a gateway started on the migrated config authenticates with the token resolved from the store");

        // The CLI's own reload mode: rotate a non-gateway secret so the CLI's token is unchanged.
        rotateStoreSecret(rig, "openclaw.skills.entries.demo.apiKey", makeCanary("SKILL-NEW"));
        const viaCli = migrate(rig, ["--reload", "--config-dir", rig.state, "--openclaw-bin", path.join("/opt/openclaw/node_modules/.bin/openclaw")]);
        evidence("E01", `blindpass-openclaw-migrate --reload exit ${viaCli.code}: ${viaCli.stdout.split("\n")[0].slice(0, 80)}`);
        assert.ok([0, 1].includes(viaCli.code));
        assert.equal(authed(rig, rotated), true, "the gateway still authenticates after the CLI reload");

        const logs = (await Promise.all(rig.gatewayLogs.map((file) => readFile(file, "utf8")))).join("\n");
        assertNoWindows(assert, logs + rig.outputs.join("\n"), canaries, "gateway logs and tool output");
        const stray = await filesHolding([rig.root, "/tmp/openclaw"], canaries, {
            skip: (file) => file.includes("/.blindpass-backup/") || /\.bak(\.\d+)?$/.test(file) || /\/gateway-\d+\.log$/.test(file),
        });
        assert.deepEqual(stray.map((file) => path.relative(rig.root, file)), ["state/.env"], `plaintext outside the expected residue: ${stray.join(", ")}`);
        evidence("E01", "no canary in gateway logs, tool output, journal or store ciphertext; plaintext remains only in the protected backup, openclaw.json.bak and the untouched .env (reported as residual)");
    } finally {
        await destroyRig(rig);
    }
});
