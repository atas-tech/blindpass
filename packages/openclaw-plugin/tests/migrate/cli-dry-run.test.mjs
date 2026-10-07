import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { chmod, mkdir, readdir, rm, symlink, writeFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { IS_LINUX, assertNoLeak, makeCanary, makeTempRoot, snapshotTree } from "./helpers.mjs";

const opts = { skip: !IS_LINUX && "Linux-only" };
const BIN = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "bin", "blindpass-openclaw-migrate");

function run(args, { env = {} } = {}) {
    return new Promise((resolve) => {
        const child = spawn(process.execPath, [BIN, ...args], { env: { ...process.env, ...env }, stdio: ["ignore", "pipe", "pipe"] });
        let stdout = "";
        let stderr = "";
        child.stdout.on("data", (chunk) => { stdout += chunk; });
        child.stderr.on("data", (chunk) => { stderr += chunk; });
        child.on("close", (code) => resolve({ code, stdout, stderr }));
    });
}

// Executables that record being run. A dry run must invoke none of them.
async function sentinelBin(base) {
    const bin = path.join(base, "sentinel-bin");
    const marker = path.join(base, "sentinel-invoked");
    await mkdir(bin);
    for (const name of ["sops", "age-keygen", "age", "openclaw", "blindpass-resolver", "node-gyp"]) {
        await writeFile(path.join(bin, name), `#!/bin/sh\necho "${name} $*" >> "${marker}"\nexit 1\n`, { mode: 0o755 });
    }
    return { bin, marker };
}

async function installation(canaries) {
    const base = await makeTempRoot();
    const dir = path.join(base, "openclaw");
    await mkdir(dir, { mode: 0o700 });
    await writeFile(
        path.join(dir, "openclaw.json"),
        JSON.stringify({ gateway: { auth: { token: canaries[0] } }, models: { providers: { mockai: { apiKey: canaries[1] } } } }, null, 2),
        { mode: 0o600 },
    );
    await writeFile(path.join(dir, ".env"), `OPENAI_API_KEY=${canaries[2]}\n`, { mode: 0o600 });
    return { base, dir };
}

test("P09-I01 CLI dry run prints a masked table, changes nothing and spawns nothing", opts, async () => {
    const canaries = [makeCanary("gw"), makeCanary("model"), makeCanary("env")];
    const { base, dir } = await installation(canaries);
    try {
        const { bin, marker } = await sentinelBin(base);
        const before = await snapshotTree(dir);
        const result = await run(["--dry-run", "--config-dir", dir], { env: { PATH: `${bin}:${process.env.PATH}` } });
        assert.equal(result.code, 0, result.stderr);
        assert.match(result.stdout, /gateway\.auth\.token\s+\[REDACTED\]\s+migratable\s+exec:blindpass:openclaw\.gateway\.auth\.token/);
        assert.match(result.stdout, /This was a dry run/);
        assertNoLeak(assert, result.stdout, canaries, "stdout");
        assertNoLeak(assert, result.stderr, canaries, "stderr");
        assert.deepEqual(await snapshotTree(dir), before);
        assert.deepEqual((await readdir(base)).sort(), ["openclaw", "sentinel-bin"], "nothing may be created beside the config directory");
        await assert.rejects(readdir(marker), /ENOTDIR|ENOENT/, "sops, age-keygen, openclaw or the resolver was invoked");
    } finally {
        await rm(base, { recursive: true, force: true });
    }
});

test("P09-I01 CLI --json emits the same plan, deterministically", opts, async () => {
    const canaries = [makeCanary("gw"), makeCanary("model"), makeCanary("env")];
    const { base, dir } = await installation(canaries);
    try {
        const first = await run(["--dry-run", "--config-dir", dir, "--json"]);
        const second = await run(["--dry-run", "--config-dir", dir, "--json"]);
        assert.equal(first.code, 0, first.stderr);
        assert.equal(first.stdout, second.stdout);
        const plan = JSON.parse(first.stdout);
        assert.equal(plan.summary.migratable, 2);
        assert.equal(plan.rows.find((row) => row.keyPath === "$env.OPENAI_API_KEY").status, "unsupported");
        assertNoLeak(assert, first.stdout + first.stderr, canaries, "json output");
        assert.equal(first.stderr, "");
    } finally {
        await rm(base, { recursive: true, force: true });
    }
});

test("P09-I01 CLI refuses unsafe paths with exit 3 and no values", opts, async () => {
    const canaries = [makeCanary("gw"), makeCanary("model"), makeCanary("env")];
    const { base, dir } = await installation(canaries);
    try {
        const alias = path.join(base, "alias");
        await symlink(dir, alias);
        const viaSymlink = await run(["--dry-run", "--config-dir", alias]);
        assert.equal(viaSymlink.code, 3);
        assert.match(viaSymlink.stderr, /refused: symlink/);

        await chmod(path.join(dir, "openclaw.json"), 0o666);
        const loose = await run(["--dry-run", "--config-dir", dir]);
        assert.equal(loose.code, 3);
        assert.match(loose.stderr, /refused: unsafe-permissions/);
        assert.equal(loose.stdout, "");
        assertNoLeak(assert, loose.stderr, canaries, "stderr");

        const relative = await run(["--dry-run", "--config-dir", "relative/dir"]);
        assert.equal(relative.code, 3);
        assert.match(relative.stderr, /refused: relative-path/);

        const release = await run(["--dry-run", "--config-dir", dir, "--release", "2026.9.8"]);
        assert.equal(release.code, 3);
        assert.match(release.stderr, /Unsupported OpenClaw release/);
    } finally {
        await rm(base, { recursive: true, force: true });
    }
});

test("P09-I01 CLI usage errors exit 2 and never run a mode implicitly", opts, async () => {
    const { base, dir } = await installation([makeCanary("a"), makeCanary("b"), makeCanary("c")]);
    try {
        for (const args of [[], ["--config-dir", dir], ["--dry-run"], ["--dry-run", "--config-dir"], ["--dry-run", "--config-dir", dir, "--bogus"], ["--config-dir", dir, "--json"]]) {
            const result = await run(args);
            assert.equal(result.code, 2, args.join(" "));
            assert.match(result.stderr, /usage|Usage/i);
            assert.equal(result.stdout, "");
        }
        const help = await run(["--help"]);
        assert.equal(help.code, 0);
        assert.match(help.stdout, /--dry-run/);
    } finally {
        await rm(base, { recursive: true, force: true });
    }
});
