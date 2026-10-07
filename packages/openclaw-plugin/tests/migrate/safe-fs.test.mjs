import assert from "node:assert/strict";
import { chmod, link, mkdir, rename, rm, symlink, writeFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import path from "node:path";
import test from "node:test";
import { IS_LINUX, makeTempRoot } from "./helpers.mjs";
import { UnsafePathError, openTrustedRoot } from "../../src/migrate/safe-fs.mjs";

const opts = { skip: !IS_LINUX && "Linux-only: path safety relies on /proc/self/fd" };
const me = process.geteuid();

async function expectReason(promise, reason) {
    await assert.rejects(promise, (error) => {
        assert.ok(error instanceof UnsafePathError, `expected UnsafePathError, got ${error?.constructor?.name}: ${error?.message}`);
        assert.equal(error.reason, reason);
        return true;
    });
}

async function fixtureRoot() {
    const base = await makeTempRoot();
    const root = path.join(base, "cfg");
    await mkdir(root, { mode: 0o700 });
    return { base, root };
}

test("P09-D3 reads a regular owned file and reports content identity", opts, async () => {
    const { base, root } = await fixtureRoot();
    try {
        await writeFile(path.join(root, "openclaw.json"), '{"a":1}', { mode: 0o600 });
        const dir = await openTrustedRoot(root);
        const file = await dir.readFile("openclaw.json", { maxBytes: 1024 });
        assert.equal(file.bytes.toString("utf8"), '{"a":1}');
        assert.match(file.sha256, /^[0-9a-f]{64}$/);
        assert.deepEqual(await dir.listNames(), ["openclaw.json"]);
        await dir.close();
    } finally {
        await rm(base, { recursive: true, force: true });
    }
});

test("P09-D3 refuses relative, non-canonical and symlinked roots and ancestors", opts, async () => {
    const { base, root } = await fixtureRoot();
    try {
        await expectReason(openTrustedRoot("relative/dir"), "relative-path");
        await expectReason(openTrustedRoot(`${root}/../cfg`), "non-canonical-path");
        await expectReason(openTrustedRoot(`${root}/`), "non-canonical-path");

        const alias = path.join(base, "alias");
        await symlink(root, alias);
        await expectReason(openTrustedRoot(alias), "symlink");

        await mkdir(path.join(root, "nested"), { mode: 0o700 });
        const viaParent = path.join(base, "parent-link");
        await symlink(base, viaParent);
        await expectReason(openTrustedRoot(path.join(viaParent, "cfg")), "symlink");
    } finally {
        await rm(base, { recursive: true, force: true });
    }
});

test("P09-D3 refuses a root or ancestor that other users can write", opts, async () => {
    const { base, root } = await fixtureRoot();
    try {
        await chmod(root, 0o770);
        await expectReason(openTrustedRoot(root), "unsafe-permissions");
        await chmod(root, 0o700);

        const shared = path.join(base, "shared");
        await mkdir(shared, { mode: 0o700 });
        await chmod(shared, 0o777);
        const under = path.join(shared, "cfg");
        await mkdir(under, { mode: 0o700 });
        await expectReason(openTrustedRoot(under), "unsafe-ancestor");

        await chmod(shared, 0o1777);
        const ok = await openTrustedRoot(under);
        await ok.close();
        await chmod(shared, 0o700);

        await expectReason(openTrustedRoot(root, { uid: me + 1, ancestorUids: [0, me] }), "wrong-owner");
    } finally {
        await rm(base, { recursive: true, force: true });
    }
});

test("P09-D3 refuses leaf symlinks, hard links, devices, FIFOs and directories without blocking", opts, async () => {
    const { base, root } = await fixtureRoot();
    try {
        const outside = path.join(base, "outside.json");
        await writeFile(outside, '{"outside":true}', { mode: 0o600 });
        await symlink(outside, path.join(root, "linked.json"));
        await writeFile(path.join(root, "hard.json"), "{}", { mode: 0o600 });
        await link(path.join(root, "hard.json"), path.join(root, "hard-copy.json"));
        execFileSync("mkfifo", [path.join(root, "pipe.json")]);
        await mkdir(path.join(root, "dir.json"), { mode: 0o700 });
        await writeFile(path.join(root, "loose.json"), "{}", { mode: 0o600 });
        await chmod(path.join(root, "loose.json"), 0o666);

        const dir = await openTrustedRoot(root);
        await expectReason(dir.readFile("linked.json", { maxBytes: 1024 }), "symlink");
        await expectReason(dir.readFile("hard.json", { maxBytes: 1024 }), "hard-linked");
        await expectReason(dir.readFile("pipe.json", { maxBytes: 1024 }), "not-a-regular-file");
        await expectReason(dir.readFile("dir.json", { maxBytes: 1024 }), "not-a-regular-file");
        await expectReason(dir.readFile("loose.json", { maxBytes: 1024 }), "unsafe-permissions");
        await expectReason(dir.readFile("missing.json", { maxBytes: 1024 }), "not-found");
        await expectReason(dir.readFile("../escape", { maxBytes: 1024 }), "invalid-name");
        await expectReason(dir.readFile("a/b", { maxBytes: 1024 }), "invalid-name");
        await expectReason(dir.readFile("..", { maxBytes: 1024 }), "invalid-name");
        await dir.close();
    } finally {
        await rm(base, { recursive: true, force: true });
    }
});

test("P09-D3 refuses an unreadable file and an oversize file with distinct reasons", opts, async () => {
    const { base, root } = await fixtureRoot();
    try {
        await writeFile(path.join(root, "secret.json"), "{}", { mode: 0o600 });
        await chmod(path.join(root, "secret.json"), 0o000);
        await writeFile(path.join(root, "big.json"), Buffer.alloc(2049, 0x61), { mode: 0o600 });
        const dir = await openTrustedRoot(root);
        if (me !== 0) {
            await expectReason(dir.readFile("secret.json", { maxBytes: 1024 }), "permission-denied");
        }
        await expectReason(dir.readFile("big.json", { maxBytes: 2048 }), "too-large");
        await dir.close();
    } finally {
        await chmod(path.join(root, "secret.json"), 0o600).catch(() => { });
        await rm(base, { recursive: true, force: true });
    }
});

test("P09-D3 a parent swapped for a symlink after open cannot redirect reads", opts, async () => {
    const { base, root } = await fixtureRoot();
    try {
        await writeFile(path.join(root, "openclaw.json"), '{"real":true}', { mode: 0o600 });
        const attacker = path.join(base, "attacker");
        await mkdir(attacker, { mode: 0o700 });
        await writeFile(path.join(attacker, "openclaw.json"), '{"attacker":true}', { mode: 0o600 });

        const dir = await openTrustedRoot(root);
        await rename(root, path.join(base, "moved"));
        await symlink(attacker, root);
        const file = await dir.readFile("openclaw.json", { maxBytes: 1024 });
        assert.equal(file.bytes.toString("utf8"), '{"real":true}');
        await dir.close();
    } finally {
        await rm(base, { recursive: true, force: true });
    }
});

test("P09-D3 a leaf swapped for a symlink between listing and reading is refused", opts, async () => {
    const { base, root } = await fixtureRoot();
    try {
        const outside = path.join(base, "outside.json");
        await writeFile(outside, '{"outside":true}', { mode: 0o600 });
        await writeFile(path.join(root, "openclaw.json"), '{"real":true}', { mode: 0o600 });
        const dir = await openTrustedRoot(root);
        await dir.listNames();
        await rm(path.join(root, "openclaw.json"));
        await symlink(outside, path.join(root, "openclaw.json"));
        await expectReason(dir.readFile("openclaw.json", { maxBytes: 1024 }), "symlink");
        await dir.close();
    } finally {
        await rm(base, { recursive: true, force: true });
    }
});

test("P09-D3 a file edited while it is being read is reported, not returned", opts, async () => {
    const { base, root } = await fixtureRoot();
    try {
        const file = path.join(root, "openclaw.json");
        await writeFile(file, '{"v":1}', { mode: 0o600 });
        const dir = await openTrustedRoot(root);
        dir.hooks.afterStat = async () => {
            await writeFile(file, '{"v":2222}');
        };
        await expectReason(dir.readFile("openclaw.json", { maxBytes: 1024 }), "source-changed");
        await dir.close();
    } finally {
        await rm(base, { recursive: true, force: true });
    }
});

test("P09-D3 creates private files and directories and replaces atomically", opts, async () => {
    const { base, root } = await fixtureRoot();
    try {
        const dir = await openTrustedRoot(root);
        await dir.createFileExclusive("journal.json", '{"n":1}');
        await expectReason(dir.createFileExclusive("journal.json", "x"), "already-exists");
        await dir.replaceFile("journal.json", '{"n":2}');
        assert.equal((await dir.readFile("journal.json", { maxBytes: 1024 })).bytes.toString(), '{"n":2}');
        const sub = await dir.makePrivateDir("backups");
        await sub.createFileExclusive("a.bak", "x");
        const info = await sub.statName("a.bak");
        assert.equal(info.mode & 0o777, 0o600);
        assert.equal((await dir.statName("backups")).mode & 0o777, 0o700);
        assert.ok(!(await dir.listNames()).some((name) => name.includes(".tmp")), "no temp file may be left behind");
        await sub.close();
        await dir.close();
    } finally {
        await rm(base, { recursive: true, force: true });
    }
});

test("P09-D3 replaceFile refuses when the target changed since it was read", opts, async () => {
    const { base, root } = await fixtureRoot();
    try {
        const file = path.join(root, "openclaw.json");
        await writeFile(file, '{"v":1}', { mode: 0o600 });
        const dir = await openTrustedRoot(root);
        const first = await dir.readFile("openclaw.json", { maxBytes: 1024 });
        await writeFile(file, '{"v":1,"concurrent":true}');
        await expectReason(dir.replaceFile("openclaw.json", '{"v":2}', { expectedSha256: first.sha256 }), "source-changed");
        assert.equal((await dir.readFile("openclaw.json", { maxBytes: 1024 })).bytes.toString(), '{"v":1,"concurrent":true}');
        await dir.close();
    } finally {
        await rm(base, { recursive: true, force: true });
    }
});
