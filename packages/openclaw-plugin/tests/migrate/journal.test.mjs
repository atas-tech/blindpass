import assert from "node:assert/strict";
import { mkdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { IS_LINUX, assertNoLeak, makeCanary, makeTempRoot } from "./helpers.mjs";
import { Journal, JournalError, acquireMigrationLock, LockHeldError } from "../../src/migrate/journal.mjs";
import { openTrustedRoot } from "../../src/migrate/safe-fs.mjs";

const opts = { skip: !IS_LINUX && "Linux-only" };

async function openDir() {
    const base = await makeTempRoot();
    const root = path.join(base, "cfg");
    await mkdir(root, { mode: 0o700 });
    return { base, root, dir: await openTrustedRoot(root) };
}

const meta = { release: "2026.8.35", providerAlias: "blindpass", storePath: "/s/secrets.enc.json", resolverCommand: "/r/resolver" };

test("P09-D4 journal records intent before completion for each stage, durably and privately", opts, async () => {
    const { base, root, dir } = await openDir();
    try {
        const journal = await Journal.create(dir, { ...meta, now: () => new Date("2026-10-07T10:00:00Z") });
        assert.match(journal.state.migrationId, /^m-20261007T100000Z-[0-9a-f]{8}$/);
        assert.equal(journal.state.status, "in-progress");
        await journal.stageIntent("backup");
        assert.ok(journal.state.stages.backup.intent);
        assert.equal(journal.state.stages.backup.done, undefined);
        await journal.stageDone("backup");
        assert.ok(journal.state.stages.backup.done);

        const info = await dir.statName(".blindpass-migrate.journal.json");
        assert.equal(info.mode & 0o777, 0o600);
        const reloaded = await Journal.load(dir);
        assert.deepEqual(reloaded.state, journal.state);
        assert.ok(!(await dir.listNames()).some((n) => n.endsWith(".tmp")));
        await dir.close();
    } finally {
        await rm(base, { recursive: true, force: true });
    }
});

test("P09-D4 a second journal cannot overwrite an unfinished one and unknown stages are rejected", opts, async () => {
    const { base, dir } = await openDir();
    try {
        const journal = await Journal.create(dir, meta);
        await assert.rejects(Journal.create(dir, meta), (e) => e instanceof JournalError && e.reason === "journal-exists");
        await assert.rejects(journal.stageIntent("bogus"), (e) => e instanceof JournalError && e.reason === "unknown-stage");
        await dir.close();
    } finally {
        await rm(base, { recursive: true, force: true });
    }
});

test("P09-D4 a journal edited by another writer is detected instead of overwritten", opts, async () => {
    const { base, root, dir } = await openDir();
    try {
        const journal = await Journal.create(dir, meta);
        await writeFile(path.join(root, ".blindpass-migrate.journal.json"), JSON.stringify({ ...journal.state, tampered: true }), { mode: 0o600 });
        await assert.rejects(journal.stageIntent("backup"), (e) => e.reason === "source-changed");
        await dir.close();
    } finally {
        await rm(base, { recursive: true, force: true });
    }
});

test("P09-D4 load rejects malformed, oversize, future-version and symlinked journals", opts, async () => {
    const { base, root, dir } = await openDir();
    try {
        assert.equal(await Journal.load(dir), null, "no journal yet");
        const file = path.join(root, ".blindpass-migrate.journal.json");
        for (const [content, reason] of [
            ["not json", "journal-corrupt"],
            ["[]", "journal-corrupt"],
            [JSON.stringify({ version: 99, migrationId: "m-x" }), "journal-version-unsupported"],
            [JSON.stringify({ version: 1, migrationId: "../evil", status: "in-progress", stages: {}, files: {}, targets: [] }), "journal-corrupt"],
            [JSON.stringify({ version: 1, migrationId: "m-20261007T100000Z-aaaaaaaa", status: "bogus", stages: {}, files: {}, targets: [] }), "journal-corrupt"],
            ["x".repeat(2 * 1024 * 1024), "journal-corrupt"],
        ]) {
            await rm(file, { force: true });
            await writeFile(file, content, { mode: 0o600 });
            await assert.rejects(Journal.load(dir), (e) => e instanceof JournalError && e.reason === reason, `${reason}: ${content.slice(0, 20)}`);
        }
        await rm(file, { force: true });
        await symlink(path.join(base, "elsewhere"), file);
        await assert.rejects(Journal.load(dir), (e) => e.reason === "symlink");
        await dir.close();
    } finally {
        await rm(base, { recursive: true, force: true });
    }
});

test("P09-D4 staleness warning after 24 hours since the last stage", opts, async () => {
    const { base, dir } = await openDir();
    try {
        const journal = await Journal.create(dir, { ...meta, now: () => new Date("2026-10-07T00:00:00Z") });
        await journal.stageIntent("inventory", new Date("2026-10-07T01:00:00Z"));
        assert.equal(journal.staleness(new Date("2026-10-08T00:59:59Z")), null);
        assert.match(journal.staleness(new Date("2026-10-08T01:00:01Z")), /last stage activity was 24h/);
        await dir.close();
    } finally {
        await rm(base, { recursive: true, force: true });
    }
});

test("P09-D4 the journal never holds secret values, only paths, names and file hashes", opts, async () => {
    const { base, root, dir } = await openDir();
    try {
        const secret = makeCanary("journal");
        const journal = await Journal.create(dir, meta);
        await journal.setFiles({ "openclaw.json": { preSha256: "a".repeat(64) } });
        await journal.setTargets([{ path: "gateway.auth.token", registryId: "gateway.auth.token", storeName: "openclaw.gateway.auth.token" }]);
        assertNoLeak(assert, await readFile(path.join(root, ".blindpass-migrate.journal.json"), "utf8"), [secret], "journal");
        await dir.close();
    } finally {
        await rm(base, { recursive: true, force: true });
    }
});

test("P09-D3 the migration lock is exclusive, stale-aware and released only by its owner", opts, async () => {
    const { base, root, dir } = await openDir();
    try {
        const lock = await acquireMigrationLock(dir);
        await assert.rejects(acquireMigrationLock(dir), (e) => e instanceof LockHeldError);
        const info = await dir.statName(".blindpass-migrate.lock");
        assert.equal(info.mode & 0o777, 0o600);
        await lock.release();
        assert.equal(await dir.statName(".blindpass-migrate.lock"), null);

        // A lock left by a process that no longer exists is broken once, with a note.
        await writeFile(path.join(root, ".blindpass-migrate.lock"), JSON.stringify({ pid: 2 ** 22 - 1, startTicks: "1", token: "dead" }), { mode: 0o600 });
        const taken = await acquireMigrationLock(dir);
        assert.match(taken.note ?? "", /stale lock/);
        await taken.release();

        // A lock whose pid is alive but whose start time differs is a recycled pid, so it is stale.
        await writeFile(path.join(root, ".blindpass-migrate.lock"), JSON.stringify({ pid: process.pid, startTicks: "1", token: "recycled" }), { mode: 0o600 });
        const recycled = await acquireMigrationLock(dir);
        assert.match(recycled.note ?? "", /stale lock/);
        // Releasing someone else's replacement lock must not delete it.
        await writeFile(path.join(root, ".blindpass-migrate.lock"), JSON.stringify({ pid: process.pid, startTicks: "x", token: "other" }), { mode: 0o600 });
        await recycled.release();
        assert.ok(await dir.statName(".blindpass-migrate.lock"));
        await dir.close();
    } finally {
        await rm(base, { recursive: true, force: true });
    }
});
