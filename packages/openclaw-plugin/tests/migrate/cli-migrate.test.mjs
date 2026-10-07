// P09 CLI surface for the mutating modes: exit codes, output rules and a run through main().
import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { IS_LINUX, TARGET_PATHS, assertNoLeak, snapshotTree, withInstallation as scenario } from "./helpers.mjs";
import { EXIT, main } from "../../src/migrate/cli.mjs";

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

function applyArgs(ctx, ...extra) {
    return [
        "--apply",
        "--config-dir", ctx.configDir,
        "--store", ctx.storePath,
        "--resolver-command", ctx.resolver,
        "--openclaw-bin", ctx.toolbox.openclaw,
        ...extra,
    ];
}

test("P09 CLI --apply prints a masked summary, exits 0, and a second run changes nothing", opts, async () => {
    await scenario(async (ctx) => {
        const { out, streams } = capture();
        assert.equal(await main(applyArgs(ctx), streams), EXIT.OK);
        assert.match(out.stdout, /committed/);
        for (const p of TARGET_PATHS) {
            assert.ok(out.stdout.includes(p), p);
        }
        assert.match(out.stdout, /openclaw secrets reload/);
        assert.match(out.stdout, /\.blindpass-backup\/m-/);
        assertNoLeak(assert, out.stdout + out.stderr, Object.values(ctx.secrets), "cli output");

        const after = await snapshotTree(ctx.configDir, { ignoreDirMtime: true });
        const again = capture();
        assert.equal(await main(applyArgs(ctx), again.streams), EXIT.OK);
        assert.match(again.out.stdout, /nothing to migrate/i);
        assert.deepEqual(await snapshotTree(ctx.configDir, { ignoreDirMtime: true }), after);
    });
});

test("P09 CLI --apply --json is machine-readable and value-free", opts, async () => {
    await scenario(async (ctx) => {
        const { out, streams } = capture();
        assert.equal(await main(applyArgs(ctx, "--json"), streams), EXIT.OK);
        const result = JSON.parse(out.stdout);
        assert.equal(result.status, "committed");
        assert.equal(result.migrated.length, 4);
        assertNoLeak(assert, out.stdout + out.stderr, Object.values(ctx.secrets), "json output");
    });
});

test("P09 CLI usage errors exit 2 and name the problem", opts, async () => {
    await scenario(async (ctx) => {
        for (const [argv, pattern] of [
            [["--apply", "--config-dir", ctx.configDir], /--resolver-command/],
            [["--apply", "--config-dir", ctx.configDir, "--resolver-command", ctx.resolver], /--openclaw-bin/],
            [["--apply", "--rollback", "--config-dir", ctx.configDir], /exactly one mode/],
            [["--status"], /--config-dir is required/],
            [["--apply", "--config-dir", ctx.configDir, "--resolver-command", "rel/resolver", "--openclaw-bin", ctx.toolbox.openclaw], /absolute/],
            [["--rollback", "--migration-id", "../x", "--config-dir", ctx.configDir], /migration id/],
        ]) {
            const { out, streams } = capture();
            assert.equal(await main(argv, streams), EXIT.USAGE, argv.join(" "));
            assert.match(out.stderr, pattern, argv.join(" "));
        }
        assert.deepEqual(await readFile(ctx.configFile), ctx.original);
    });
});

test("P09 CLI refusals exit 3 before any change; failures after changes start exit 1 and stay redacted", opts, async () => {
    await scenario(async (ctx) => {
        const before = await snapshotTree(ctx.configDir, { ignoreDirMtime: true });
        const { out, streams } = capture();
        assert.equal(await main(applyArgs(ctx, "--store", path.join(ctx.storeDir, "missing.json")), streams), EXIT.REFUSED);
        assert.match(out.stderr, /store-missing/);
        assert.deepEqual(await snapshotTree(ctx.configDir, { ignoreDirMtime: true }), before);
    });
    await scenario(async (ctx) => {
        const { out, streams } = capture();
        assert.equal(await main(applyArgs(ctx), streams), EXIT.FAILED);
        assert.match(out.stderr, /native-apply-failed/);
        assert.match(out.stderr, /rewrite/);
        assertNoLeak(assert, out.stdout + out.stderr, Object.values(ctx.secrets), "failure output");
        const status = capture();
        assert.equal(await main(["--status", "--config-dir", ctx.configDir, "--json"], status.streams), EXIT.OK);
        assert.equal(JSON.parse(status.out.stdout).status, "failed");
        assertNoLeak(assert, status.out.stdout, Object.values(ctx.secrets), "status output");
        assertNoLeak(assert, await readFile(path.join(ctx.configDir, ".blindpass-migrate.journal.json"), "utf8"), Object.values(ctx.secrets), "journal");
    }, { fake: { failWrite: "echo" } });
});

test("P09 CLI --status and --rollback", opts, async () => {
    await scenario(async (ctx) => {
        const none = capture();
        assert.equal(await main(["--status", "--config-dir", ctx.configDir], none.streams), EXIT.OK);
        assert.match(none.out.stdout, /no migration/i);

        const missing = capture();
        assert.equal(await main(["--rollback", "--config-dir", ctx.configDir], missing.streams), EXIT.REFUSED);
        assert.match(missing.out.stderr, /no-migration/);

        await main(applyArgs(ctx), capture().streams);
        const status = capture();
        assert.equal(await main(["--status", "--config-dir", ctx.configDir], status.streams), EXIT.OK);
        assert.match(status.out.stdout, /committed/);
        assert.match(status.out.stdout, /openclaw\.json\.bak/);

        const rolled = capture();
        assert.equal(await main(["--rollback", "--config-dir", ctx.configDir], rolled.streams), EXIT.OK);
        assert.match(rolled.out.stdout, /rolled back/i);
        assert.deepEqual(await readFile(ctx.configFile), ctx.original);
        assertNoLeak(assert, rolled.out.stdout + rolled.out.stderr + status.out.stdout, Object.values(ctx.secrets), "cli output");
        assert.ok((await readdir(path.join(ctx.configDir, ".blindpass-backup"))).length === 1);
    });
});

test("P09 CLI --init-store is explicit, idempotent and reports the key-backup step", opts, async () => {
    await scenario(async (ctx) => {
        const fresh = path.join(ctx.base, "second-store", "secrets.enc.json");
        const first = capture();
        assert.equal(await main(["--init-store", "--store", fresh], first.streams), EXIT.OK);
        assert.match(first.out.stdout, /created/i);
        assert.match(first.out.stdout, /--ack-backup/);
        const second = capture();
        assert.equal(await main(["--init-store", "--store", fresh], second.streams), EXIT.OK);
        assert.match(second.out.stdout, /already/i);
    });
});

test("P09 CLI --reload runs the native reload and reports an unverified result honestly", opts, async () => {
    await scenario(async (ctx) => {
        const ok = capture();
        assert.equal(await main(["--reload", "--config-dir", ctx.configDir, "--openclaw-bin", ctx.toolbox.openclaw], ok.streams), EXIT.OK);
        assert.match(ok.out.stdout, /reload/i);
        assert.ok((await readFile(ctx.log, "utf8")).includes("openclaw reload"));
        assert.match(ok.out.stdout, /authenticated/i, "the report must say activation is verified by use, not by the reload exit");
    });
});
