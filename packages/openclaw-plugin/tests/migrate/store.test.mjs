import assert from "node:assert/strict";
import { chmod, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { IS_LINUX, assertNoLeak, makeCanary, makeResolverCommand, makeTempRoot, snapshotTree, withFakeTools } from "./helpers.mjs";
import { PreflightError } from "../../src/migrate/errors.mjs";
import { importEntries, initStore, inspectStore, verifyViaResolver } from "../../src/migrate/store.mjs";

const opts = { skip: !IS_LINUX && "Linux-only" };

async function workspace() {
    const base = await makeTempRoot();
    const storeDir = path.join(base, "store");
    await mkdir(storeDir, { mode: 0o700 });
    const log = path.join(base, "tool.log");
    return { base, storeDir, storePath: path.join(storeDir, "secrets.enc.json"), log };
}

async function expectReason(promise, reason) {
    await assert.rejects(promise, (error) => {
        assert.ok(error instanceof PreflightError, `expected PreflightError, got ${error?.constructor?.name}: ${error?.message}`);
        assert.equal(error.reason, reason);
        return true;
    });
}

const quiet = { write() { } };

test("P09-D5 inspecting a missing store creates nothing and never calls age-keygen or sops encrypt", opts, async () => {
    const { base, storeDir, storePath, log } = await workspace();
    try {
        await withFakeTools(async () => {
            const before = await snapshotTree(storeDir);
            const state = await inspectStore({ storePath });
            assert.deepEqual(state, { state: "missing" });
            assert.deepEqual(await snapshotTree(storeDir), before);
            const calls = await readFile(log, "utf8").catch(() => "");
            assert.ok(!/age-keygen|sops encrypt/.test(calls), calls);
        }, { log });
    } finally {
        await rm(base, { recursive: true, force: true });
    }
});

test("P09-D5 init is a distinct explicit action and is idempotent", opts, async () => {
    const { base, storeDir, storePath } = await workspace();
    try {
        await withFakeTools(async () => {
            const first = await initStore({ storePath, stderr: quiet });
            assert.equal(first.created, true);
            const names = (await readdir(storeDir)).sort();
            assert.deepEqual(names, [".age-key.txt", ".sops.yaml", "secrets.enc.json"]);
            for (const line of (await readFile(path.join(storeDir, ".age-key.txt"), "utf8")).split("\n").filter(Boolean)) {
                assert.match(line, /^(#|AGE-SECRET-KEY-)/);
            }
            const second = await initStore({ storePath, stderr: quiet });
            assert.equal(second.created, false);
            const state = await inspectStore({ storePath });
            assert.deepEqual(state, { state: "ready", backupPending: true, names: [] });
        });
    } finally {
        await rm(base, { recursive: true, force: true });
    }
});

test("P09-D5 a missing or wrong key is an explicit unavailable state, not a plaintext fallback", opts, async () => {
    const { base, storeDir, storePath } = await workspace();
    try {
        await withFakeTools(async () => {
            await initStore({ storePath, stderr: quiet });
            const keyPath = path.join(storeDir, ".age-key.txt");
            const original = await readFile(keyPath, "utf8");

            await writeFile(keyPath, "# created: x\n# public key: age1other\nAGE-SECRET-KEY-1OTHER\n", { mode: 0o600 });
            await expectReason(inspectStore({ storePath }), "key-unavailable");

            await rm(keyPath);
            await expectReason(inspectStore({ storePath }), "key-unavailable");

            await writeFile(keyPath, original, { mode: 0o600 });
            assert.equal((await inspectStore({ storePath })).state, "ready");
        });
    } finally {
        await rm(base, { recursive: true, force: true });
    }
});

test("P09-D5 corrupt stores, missing sops and old sops are distinct preflight failures", opts, async () => {
    const { base, storeDir, storePath } = await workspace();
    try {
        await withFakeTools(async () => {
            await initStore({ storePath, stderr: quiet });
            await writeFile(storePath, "not json at all", { mode: 0o600 });
            await expectReason(inspectStore({ storePath }), "key-unavailable");
        });
        await withFakeTools(async () => {
            await expectReason(inspectStore({ storePath }), "tool-missing");
        }, { path: "/nonexistent-p09" });
        await withFakeTools(async () => {
            await expectReason(inspectStore({ storePath }), "tool-version");
        }, { sopsVersion: "3.8.1" });
        assert.ok((await readdir(storeDir)).includes("secrets.enc.json"));
    } finally {
        await rm(base, { recursive: true, force: true });
    }
});

test("P09-D4 import writes in one atomic batch, is idempotent and refuses to overwrite a different value", opts, async () => {
    const { base, storePath } = await workspace();
    try {
        await withFakeTools(async () => {
            await initStore({ storePath, stderr: quiet });
            const a = makeCanary("a");
            const b = makeCanary("b");
            const entries = [
                { name: "openclaw.gateway.auth.token", value: a, source: "openclaw.json:gateway.auth.token" },
                { name: "openclaw.skills.entries.demo.apiKey", value: b, source: "openclaw.json:skills.entries.demo.apiKey" },
            ];
            const first = await importEntries({ storePath, entries, migrationId: "m-20261007T100000Z-aaaaaaaa" });
            assert.deepEqual(first.written.sort(), entries.map((e) => e.name).sort());
            const again = await importEntries({ storePath, entries, migrationId: "m-20261007T100000Z-aaaaaaaa" });
            assert.deepEqual(again.written, []);
            assert.deepEqual(again.unchanged.sort(), entries.map((e) => e.name).sort());

            const before = await readFile(storePath, "utf8");
            const clash = [
                { name: "openclaw.skills.entries.demo.apiKey", value: makeCanary("different"), source: "x" },
                { name: "openclaw.brand.new", value: makeCanary("new"), source: "y" },
            ];
            await assert.rejects(importEntries({ storePath, entries: clash, migrationId: "m-20261007T100000Z-aaaaaaaa" }), (error) => {
                assert.ok(error instanceof PreflightError);
                assert.equal(error.reason, "store-name-conflict");
                assert.deepEqual(error.names, ["openclaw.skills.entries.demo.apiKey"]);
                assertNoLeak(assert, `${error.message} ${JSON.stringify(error.names)}`, clash.map((c) => c.value).concat([a, b]), "error");
                return true;
            });
            assert.equal(await readFile(storePath, "utf8"), before, "a rejected batch must not change the store");
            await expectReason(importEntries({ storePath, entries: [{ name: "bad name", value: "x", source: "z" }], migrationId: "m-20261007T100000Z-aaaaaaaa" }), "invalid-store-name");
        });
    } finally {
        await rm(base, { recursive: true, force: true });
    }
});

test("P09-D5 import refuses a store that does not exist instead of bootstrapping one", opts, async () => {
    const { base, storeDir, storePath } = await workspace();
    try {
        await withFakeTools(async () => {
            await expectReason(importEntries({ storePath, entries: [{ name: "openclaw.a", value: "v".repeat(10), source: "s" }], migrationId: "m-20261007T100000Z-aaaaaaaa" }), "store-missing");
            assert.deepEqual(await readdir(storeDir), []);
        });
    } finally {
        await rm(base, { recursive: true, force: true });
    }
});

test("P09-D4 imported values are verified through the real resolver command exactly as OpenClaw runs it", opts, async () => {
    const { base, storePath } = await workspace();
    try {
        await withFakeTools(async () => {
            await initStore({ storePath, stderr: quiet });
            const entries = [{ name: "openclaw.gateway.auth.token", value: makeCanary("gw"), source: "s" }];
            await importEntries({ storePath, entries, migrationId: "m-20261007T100000Z-aaaaaaaa" });
            const resolverCommand = await makeResolverCommand(base);
            await verifyViaResolver({ resolverCommand, storePath, entries });

            await importEntries({ storePath, entries: [{ name: "openclaw.other", value: makeCanary("other"), source: "s" }], migrationId: "m-20261007T100000Z-aaaaaaaa" });
            await assert.rejects(
                verifyViaResolver({ resolverCommand, storePath, entries: [{ name: "openclaw.other", value: makeCanary("not-the-stored-one"), source: "s" }] }),
                (error) => {
                    assert.ok(error instanceof PreflightError);
                    assert.equal(error.reason, "resolver-mismatch");
                    assert.ok(!error.message.includes("P09-CANARY"));
                    return true;
                },
            );
            await expectReason(
                verifyViaResolver({ resolverCommand, storePath, entries: [{ name: "openclaw.missing", value: "x".repeat(10), source: "s" }] }),
                "resolver-unresolved",
            );
        });
    } finally {
        await rm(base, { recursive: true, force: true });
    }
});
