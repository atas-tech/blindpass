import assert from "node:assert/strict";
import { chmod, link, mkdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { IS_LINUX, assertNoLeak, makeCanary, makeResolverCommand, makeTempRoot, withFakeTools } from "./helpers.mjs";
import { PreflightError } from "../../src/migrate/errors.mjs";
import { createBackup, loadBackup } from "../../src/migrate/backup.mjs";
import { applyPlan, assertSupportedNative, nativeAudit } from "../../src/migrate/native.mjs";
import { buildApplyPlan } from "../../src/migrate/plan.mjs";
import { checkResolverCommand } from "../../src/migrate/resolver-trust.mjs";
import { openTrustedRoot } from "../../src/migrate/safe-fs.mjs";

const opts = { skip: !IS_LINUX && "Linux-only" };

async function expectReason(promise, reason) {
    await assert.rejects(promise, (error) => {
        assert.ok(error instanceof PreflightError, `expected PreflightError, got ${error?.constructor?.name}: ${error?.message}`);
        assert.equal(error.reason, reason, error.message);
        return true;
    });
}

const target = (p, id = p) => ({
    path: p,
    registryId: id,
    segments: p.split("."),
    ref: { source: "exec", provider: "blindpass", id: `openclaw.${p}` },
});

test("P09-D2 apply plan uses the runtime's own schema and disables both scrubs", () => {
    const plan = buildApplyPlan({
        targets: [target("skills.entries.demo.apiKey", "skills.entries.*.apiKey"), target("gateway.auth.token")],
        providerAlias: "blindpass",
        resolverCommand: "/opt/blindpass/blindpass-resolver",
        storePath: "/home/u/.openclaw/blindpass/secrets.enc.json",
    });
    assert.deepEqual(plan, {
        version: 1,
        protocolVersion: 1,
        scrubEnv: false,
        scrubAuthProfilesForProviderTargets: false,
        providerUpserts: {
            blindpass: {
                source: "exec",
                command: "/opt/blindpass/blindpass-resolver",
                args: ["--store", "/home/u/.openclaw/blindpass/secrets.enc.json"],
                passEnv: ["PATH"],
                jsonOnly: true,
            },
        },
        targets: [
            {
                type: "gateway.auth.token",
                path: "gateway.auth.token",
                pathSegments: ["gateway", "auth", "token"],
                ref: { source: "exec", provider: "blindpass", id: "openclaw.gateway.auth.token" },
            },
            {
                type: "skills.entries.*.apiKey",
                path: "skills.entries.demo.apiKey",
                pathSegments: ["skills", "entries", "demo", "apiKey"],
                ref: { source: "exec", provider: "blindpass", id: "openclaw.skills.entries.demo.apiKey" },
            },
        ],
    });
    assert.ok(!JSON.stringify(plan).includes("P09-CANARY"));
});

test("P09-D2 apply plan rejects anything the runtime contract would reject or that could mislead", () => {
    const base = { targets: [target("gateway.auth.token")], providerAlias: "blindpass", resolverCommand: "/r/resolver", storePath: "/s/x.json" };
    for (const [override, reason] of [
        [{ providerAlias: "Bad Alias" }, "invalid-provider-alias"],
        [{ providerAlias: "1abc" }, "invalid-provider-alias"],
        [{ resolverCommand: "relative/resolver" }, "invalid-plan"],
        [{ storePath: "relative.json" }, "invalid-plan"],
        [{ targets: [] }, "invalid-plan"],
        [{ targets: [target("gateway.auth.token"), target("gateway.auth.token")] }, "invalid-plan"],
        [{ targets: [{ ...target("gateway.auth.token"), ref: { source: "exec", provider: "other", id: "x" } }] }, "invalid-plan"],
        [{ targets: [{ ...target("gateway.auth.token"), ref: { source: "exec", provider: "blindpass", id: "bad id" } }] }, "invalid-plan"],
    ]) {
        assert.throws(() => buildApplyPlan({ ...base, ...override }), (error) => error instanceof PreflightError && error.reason === reason, JSON.stringify(override).slice(0, 60));
    }
});

test("P09-D5 resolver command must be an absolute, real, owned, non-writable executable", opts, async () => {
    const base = await makeTempRoot();
    try {
        const dir = path.join(base, "bin");
        await mkdir(dir, { mode: 0o700 });
        const good = await makeResolverCommand(dir);
        assert.deepEqual(await checkResolverCommand(good), { path: good });

        await expectReason(checkResolverCommand("blindpass-resolver"), "resolver-untrusted");
        await expectReason(checkResolverCommand(path.join(dir, "missing")), "resolver-untrusted");

        await symlink(good, path.join(dir, "shim"));
        await expectReason(checkResolverCommand(path.join(dir, "shim")), "resolver-untrusted");

        await chmod(good, 0o775);
        await expectReason(checkResolverCommand(good), "resolver-untrusted");
        await chmod(good, 0o755);

        const plain = path.join(dir, "not-executable");
        await writeFile(plain, "#!/bin/sh\n", { mode: 0o644 });
        await expectReason(checkResolverCommand(plain), "resolver-untrusted");

        await expectReason(checkResolverCommand(good, { uid: process.geteuid() + 1 }), "resolver-untrusted");

        const openDir = path.join(base, "open");
        await mkdir(openDir, { mode: 0o700 });
        const inOpen = await makeResolverCommand(openDir);
        await chmod(openDir, 0o777);
        await expectReason(checkResolverCommand(inOpen), "resolver-untrusted");
    } finally {
        await rm(base, { recursive: true, force: true });
    }
});

test("P09-D4 backup is private, hash-verified, plaintext-bearing by design and never overwritten", opts, async () => {
    const base = await makeTempRoot();
    try {
        const root = path.join(base, "cfg");
        await mkdir(root, { mode: 0o700 });
        const dir = await openTrustedRoot(root);
        const secret = makeCanary("backup");
        const bytes = Buffer.from(JSON.stringify({ gateway: { auth: { token: secret } } }));
        const { createHash } = await import("node:crypto");
        const sha256 = createHash("sha256").update(bytes).digest("hex");

        const created = await createBackup(dir, { migrationId: "m-20261007T100000Z-aaaaaaaa", release: "2026.8.35", files: [{ name: "openclaw.json", bytes, sha256 }] });
        assert.equal(created.relDir, ".blindpass-backup/m-20261007T100000Z-aaaaaaaa");
        assert.deepEqual(created.files, { "openclaw.json": { sha256 } });

        const backupRoot = await dir.openDir(".blindpass-backup");
        assert.equal((await dir.statName(".blindpass-backup")).mode & 0o777, 0o700);
        const inner = await backupRoot.openDir("m-20261007T100000Z-aaaaaaaa");
        assert.equal((await backupRoot.statName("m-20261007T100000Z-aaaaaaaa")).mode & 0o777, 0o700);
        assert.equal((await inner.statName("openclaw.json")).mode & 0o777, 0o600);
        const manifest = (await inner.readFile("MANIFEST.json", { maxBytes: 65536 })).bytes.toString("utf8");
        assertNoLeak(assert, manifest, [secret], "manifest");
        assert.match(manifest, /plaintext/);

        // Re-running with identical content verifies and reuses the backup (resume); altered content is refused.
        const again = await createBackup(dir, { migrationId: "m-20261007T100000Z-aaaaaaaa", release: "2026.8.35", files: [{ name: "openclaw.json", bytes, sha256 }] });
        assert.deepEqual(again.files, created.files);
        const other = Buffer.from("{}");
        await assert.rejects(
            createBackup(dir, { migrationId: "m-20261007T100000Z-aaaaaaaa", release: "2026.8.35", files: [{ name: "openclaw.json", bytes: other, sha256: createHash("sha256").update(other).digest("hex") }] }),
            (error) => error instanceof PreflightError && error.reason === "backup-conflict",
        );

        const loaded = await loadBackup(dir, created.relDir);
        assert.equal(loaded.files["openclaw.json"].bytes.toString(), bytes.toString());

        await inner.close();
        await backupRoot.close();
        await writeFile(path.join(root, ".blindpass-backup", "m-20261007T100000Z-aaaaaaaa", "openclaw.json"), "tampered", { mode: 0o600 });
        await assert.rejects(loadBackup(dir, created.relDir), (error) => error instanceof PreflightError && error.reason === "backup-damaged");
        await dir.close();
    } finally {
        await rm(base, { recursive: true, force: true });
    }
});

async function nativeFixture(config) {
    const base = await makeTempRoot();
    const configDir = path.join(base, "openclaw");
    await mkdir(configDir, { mode: 0o700 });
    await writeFile(path.join(configDir, "openclaw.json"), JSON.stringify(config, null, 2), { mode: 0o600 });
    return { base, configDir, log: path.join(base, "tool.log") };
}

test("P09-D2 native wrapper verifies release and config location and isolates the environment", opts, async () => {
    const { base, configDir, log } = await nativeFixture({});
    try {
        process.env.P09_TEST_SECRET = makeCanary("env");
        await withFakeTools(async (tools) => {
            await assertSupportedNative(tools.openclaw, { configDir, release: "2026.8.35" });
            const calls = await readFile(log, "utf8");
            assert.ok(!calls.includes("P09_TEST_SECRET"), "the operator's environment must not reach the openclaw CLI");
            assert.match(calls, /OPENCLAW_CONFIG_PATH/);
            assert.match(calls, /OPENCLAW_STATE_DIR/);
        }, { log });
        await withFakeTools(async (tools) => {
            await expectReason(assertSupportedNative(tools.openclaw, { configDir, release: "2026.8.35" }), "native-version");
        }, { openclawVersion: "2026.9.8" });
        await expectReason(assertSupportedNative("openclaw", { configDir, release: "2026.8.35" }), "native-version");
        await expectReason(assertSupportedNative(path.join(base, "missing"), { configDir, release: "2026.8.35" }), "native-version");
    } finally {
        delete process.env.P09_TEST_SECRET;
        await rm(base, { recursive: true, force: true });
    }
});

test("P09-D2 native apply: dry run validates, write needs --allow-exec, rejected targets are classified", opts, async () => {
    const secret = makeCanary("native");
    const { base, configDir, log } = await nativeFixture({ gateway: { auth: { token: secret } }, skills: { entries: { demo: { apiKey: secret } } } });
    try {
        const resolver = await makeResolverCommand(base);
        const plan = buildApplyPlan({
            targets: [target("gateway.auth.token")],
            providerAlias: "blindpass",
            resolverCommand: resolver,
            storePath: path.join(base, "store.enc.json"),
        });
        const planPath = path.join(base, "plan.json");
        await writeFile(planPath, JSON.stringify(plan), { mode: 0o600 });

        await withFakeTools(async (tools) => {
            const dry = await applyPlan(tools.openclaw, planPath, { configDir, dryRun: true, allowExec: false, redact: [secret] });
            assert.equal(dry.mode, "dry-run");
            assert.equal(JSON.parse(await readFile(path.join(configDir, "openclaw.json"), "utf8")).gateway.auth.token, secret, "dry run must not write");

            await expectReason(applyPlan(tools.openclaw, planPath, { configDir, dryRun: false, allowExec: false, redact: [secret] }), "native-apply-failed");
        }, { log });

        await withFakeTools(async (tools) => {
            await expectReason(applyPlan(tools.openclaw, planPath, { configDir, dryRun: true, allowExec: false, redact: [secret] }), "native-plan-rejected");
        }, { reject: ["gateway.auth.token"] });

        await writeFile(path.join(configDir, "openclaw.json"), "{ broken", { mode: 0o600 });
        await withFakeTools(async (tools) => {
            await expectReason(applyPlan(tools.openclaw, planPath, { configDir, dryRun: true, allowExec: false, redact: [secret] }), "native-config-invalid");
        });
    } finally {
        await rm(base, { recursive: true, force: true });
    }
});

test("P09-D2 native audit parses the report and never surfaces CLI text", opts, async () => {
    const secret = makeCanary("audit");
    const { base, configDir } = await nativeFixture({ gateway: { auth: { token: secret } } });
    try {
        await withFakeTools(async (tools) => {
            const report = await nativeAudit(tools.openclaw, { configDir, allowExec: false });
            assert.equal(report.status, "findings");
            assert.deepEqual(report.findings.map((f) => f.jsonPath), ["gateway.auth.token"]);
            assertNoLeak(assert, JSON.stringify(report), [secret], "audit report");
        });
    } finally {
        await rm(base, { recursive: true, force: true });
    }
});
