// Path-safe file access for the migration (P09-D3).
//
// A leaf-only O_NOFOLLOW check does not stop a swapped parent directory or a rename between check
// and use. Instead one directory is opened once with O_NOFOLLOW at every component, validated by
// fstat, and everything afterwards is resolved *beneath that descriptor* through
// /proc/self/fd/<fd>/<single name>. The kernel resolves that magic link to the directory object that
// was opened, not to whatever the original path names now, and a single-component name cannot
// traverse. Linux only: anywhere else this fails closed instead of claiming portability.
import { createHash, randomBytes } from "node:crypto";
import { constants as C } from "node:fs";
import { access, lstat, mkdir, open, readdir, rename, unlink } from "node:fs/promises";
import path from "node:path";

const CLOEXEC = C.O_CLOEXEC ?? 0;
const OPEN_DIR = C.O_RDONLY | C.O_DIRECTORY | C.O_NOFOLLOW | CLOEXEC;
// O_NONBLOCK keeps an open of a FIFO from blocking; the fstat check then rejects it.
const OPEN_READ = C.O_RDONLY | C.O_NOFOLLOW | CLOEXEC | C.O_NONBLOCK;
const OPEN_CREATE = C.O_WRONLY | C.O_CREAT | C.O_EXCL | C.O_NOFOLLOW | CLOEXEC;
const MAX_NAME_BYTES = 255;

export class UnsafePathError extends Error {
    constructor(reason, detail) {
        super(detail ? `${reason}: ${detail}` : reason);
        this.name = "UnsafePathError";
        this.code = "UNSAFE_PATH";
        this.reason = reason;
    }
}

function assertName(name) {
    if (
        typeof name !== "string"
        || name === ""
        || name === "."
        || name === ".."
        || name.includes("/")
        || name.includes("\0")
        || Buffer.byteLength(name) > MAX_NAME_BYTES
    ) {
        throw new UnsafePathError("invalid-name");
    }
}

async function assertPlatform() {
    if (process.platform !== "linux") {
        throw new UnsafePathError("unsupported-platform", `${process.platform} (Linux /proc/self/fd is required)`);
    }
    try {
        await access("/proc/self/fd");
    } catch {
        throw new UnsafePathError("unsupported-platform", "/proc/self/fd is not available");
    }
}

function procPath(fd, name) {
    return `/proc/self/fd/${fd}/${name}`;
}

async function mapOpenError(error, display, { directory = false, fd, name } = {}) {
    switch (error?.code) {
        case "ENOENT":
            return new UnsafePathError("not-found", display);
        case "ELOOP":
            return new UnsafePathError("symlink", display);
        case "ENOTDIR": {
            if (directory && fd !== undefined) {
                const info = await lstat(procPath(fd, name)).catch(() => null);
                if (info?.isSymbolicLink()) {
                    return new UnsafePathError("symlink", display);
                }
            }
            return new UnsafePathError("not-a-directory", display);
        }
        case "EACCES":
        case "EPERM":
            return new UnsafePathError("permission-denied", display);
        case "EEXIST":
            return new UnsafePathError("already-exists", display);
        case "ENXIO":
            return new UnsafePathError("not-a-regular-file", display);
        default:
            return error;
    }
}

function sha256(bytes) {
    return createHash("sha256").update(bytes).digest("hex");
}

function sameIdentity(a, b) {
    return a.dev === b.dev
        && a.ino === b.ino
        && a.size === b.size
        && a.mtimeNs === b.mtimeNs
        && a.ctimeNs === b.ctimeNs;
}

export class TrustedDir {
    #handle;

    constructor(handle, { uid, displayPath, warnings = [] }) {
        this.#handle = handle;
        this.uid = uid;
        this.path = displayPath;
        this.warnings = warnings;
        // Test seam only (never set by the CLI): runs after the identity snapshot, before the read.
        this.hooks = {};
    }

    get fd() {
        return this.#handle.fd;
    }

    #p(name) {
        assertName(name);
        return procPath(this.fd, name);
    }

    #warn(message) {
        if (!this.warnings.includes(message)) {
            this.warnings.push(message);
        }
    }

    #assertRegular(stat, name, uid) {
        if (!stat.isFile()) {
            throw new UnsafePathError("not-a-regular-file", name);
        }
        if (stat.uid !== uid) {
            throw new UnsafePathError("wrong-owner", name);
        }
        if (stat.nlink > 1) {
            throw new UnsafePathError("hard-linked", name);
        }
        if ((stat.mode & 0o022) !== 0) {
            throw new UnsafePathError("unsafe-permissions", `${name} is writable by group or others`);
        }
        if ((stat.mode & 0o044) !== 0) {
            this.#warn(`readable-by-others: ${name}`);
        }
    }

    async listNames() {
        return (await readdir(`/proc/self/fd/${this.fd}`)).sort();
    }

    async statName(name) {
        try {
            return await lstat(this.#p(name));
        } catch (error) {
            if (error?.code === "ENOENT") {
                return null;
            }
            throw error;
        }
    }

    async readFile(name, { maxBytes, uid = this.uid } = {}) {
        if (!Number.isInteger(maxBytes) || maxBytes < 0) {
            throw new TypeError("readFile requires an integer maxBytes");
        }
        let handle;
        try {
            handle = await open(this.#p(name), OPEN_READ);
        } catch (error) {
            throw await mapOpenError(error, name);
        }
        try {
            const before = await handle.stat({ bigint: true });
            const beforeNumber = await handle.stat();
            this.#assertRegular(beforeNumber, name, uid);
            if (beforeNumber.size > maxBytes) {
                throw new UnsafePathError("too-large", `${name} exceeds ${maxBytes} bytes`);
            }
            await this.hooks.afterStat?.(name);
            const bytes = Buffer.alloc(beforeNumber.size + 1);
            let total = 0;
            for (;;) {
                const { bytesRead } = await handle.read(bytes, total, bytes.length - total, total);
                if (bytesRead === 0) {
                    break;
                }
                total += bytesRead;
                if (total >= bytes.length) {
                    break;
                }
            }
            const after = await handle.stat({ bigint: true });
            if (total !== beforeNumber.size || !sameIdentity(before, after)) {
                throw new UnsafePathError("source-changed", `${name} changed while it was read`);
            }
            const content = bytes.subarray(0, total);
            return { bytes: content, stat: beforeNumber, sha256: sha256(content) };
        } finally {
            await handle.close();
        }
    }

    async createFileExclusive(name, data, { mode = 0o600 } = {}) {
        let handle;
        try {
            handle = await open(this.#p(name), OPEN_CREATE, mode);
        } catch (error) {
            throw await mapOpenError(error, name);
        }
        try {
            await handle.writeFile(data);
            await handle.sync();
        } finally {
            await handle.close();
        }
        await this.syncDir();
    }

    async replaceFile(name, data, { mode = 0o600, expectedSha256 } = {}) {
        let expectedStat;
        if (expectedSha256) {
            const current = await this.readFile(name, { maxBytes: Number.MAX_SAFE_INTEGER });
            if (current.sha256 !== expectedSha256) {
                throw new UnsafePathError("source-changed", `${name} changed since it was read`);
            }
            expectedStat = current.stat;
        }
        const temp = `.${name}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
        await this.createFileExclusive(temp, data, { mode });
        try {
            if (expectedStat) {
                const now = await this.statName(name);
                if (!now || now.ino !== expectedStat.ino || now.mtimeMs !== expectedStat.mtimeMs || now.size !== expectedStat.size) {
                    throw new UnsafePathError("source-changed", `${name} changed since it was read`);
                }
            }
            await rename(this.#p(temp), this.#p(name));
        } catch (error) {
            await unlink(this.#p(temp)).catch(() => { });
            throw error;
        }
        await this.syncDir();
    }

    // Renames within this directory; never replaces an existing name.
    async renameFile(name, newName) {
        assertName(newName);
        if ((await this.statName(newName)) !== null) {
            throw new UnsafePathError("already-exists", newName);
        }
        await rename(this.#p(name), this.#p(newName));
        await this.syncDir();
    }

    // Moves a file into another directory opened through this layer (same filesystem).
    async moveFileTo(name, target, targetName = name) {
        assertName(targetName);
        await rename(this.#p(name), procPath(target.fd, targetName));
        await this.syncDir();
        await target.syncDir();
    }

    async removeFile(name) {
        try {
            await unlink(this.#p(name));
        } catch (error) {
            if (error?.code !== "ENOENT") {
                throw error;
            }
        }
        await this.syncDir();
    }

    async makePrivateDir(name) {
        try {
            await mkdir(this.#p(name), { mode: 0o700 });
        } catch (error) {
            throw await mapOpenError(error, name);
        }
        await this.syncDir();
        return this.openDir(name);
    }

    async openDir(name) {
        let handle;
        try {
            handle = await open(this.#p(name), OPEN_DIR);
        } catch (error) {
            throw await mapOpenError(error, name, { directory: true, fd: this.fd, name });
        }
        try {
            const info = await handle.stat();
            if (!info.isDirectory()) {
                throw new UnsafePathError("not-a-directory", name);
            }
            if (info.uid !== this.uid) {
                throw new UnsafePathError("wrong-owner", name);
            }
            if ((info.mode & 0o022) !== 0) {
                throw new UnsafePathError("unsafe-permissions", `${name} is writable by group or others`);
            }
            return new TrustedDir(handle, {
                uid: this.uid,
                displayPath: path.posix.join(this.path, name),
                warnings: this.warnings,
            });
        } catch (error) {
            await handle.close();
            throw error;
        }
    }

    async syncDir() {
        await this.#handle.sync();
    }

    async close() {
        await this.#handle.close();
    }
}

export async function openTrustedRoot(absPath, { uid = process.geteuid(), ancestorUids = [0, uid], rootUids = [uid] } = {}) {
    await assertPlatform();
    if (typeof absPath !== "string" || !path.isAbsolute(absPath)) {
        throw new UnsafePathError("relative-path", "the config directory must be an absolute path");
    }
    if (absPath !== "/" && (absPath.endsWith("/") || path.posix.normalize(absPath) !== absPath)) {
        throw new UnsafePathError("non-canonical-path", "remove ., .., repeated or trailing slashes");
    }
    const components = absPath.split("/").filter(Boolean);
    const warnings = [];

    let handle = await open("/", OPEN_DIR);
    try {
        const checkAncestor = (info, display) => {
            if (!info.isDirectory()) {
                throw new UnsafePathError("not-a-directory", display);
            }
            if (!ancestorUids.includes(info.uid)) {
                throw new UnsafePathError("unsafe-ancestor", `${display} is owned by another user`);
            }
            if ((info.mode & 0o022) !== 0 && (info.mode & 0o1000) === 0) {
                throw new UnsafePathError("unsafe-ancestor", `${display} is writable by group or others`);
            }
        };

        if (components.length === 0) {
            throw new UnsafePathError("unsafe-permissions", "refusing to use / as the config directory");
        }
        checkAncestor(await handle.stat(), "/");

        for (let i = 0; i < components.length; i += 1) {
            const name = components[i];
            const display = `/${components.slice(0, i + 1).join("/")}`;
            let child;
            try {
                child = await open(procPath(handle.fd, name), OPEN_DIR);
            } catch (error) {
                throw await mapOpenError(error, display, { directory: true, fd: handle.fd, name });
            }
            await handle.close();
            handle = child;
            const info = await handle.stat();
            if (i < components.length - 1) {
                checkAncestor(info, display);
                continue;
            }
            if (!info.isDirectory()) {
                throw new UnsafePathError("not-a-directory", display);
            }
            if (!rootUids.includes(info.uid)) {
                throw new UnsafePathError("wrong-owner", display);
            }
            if ((info.mode & 0o022) !== 0) {
                throw new UnsafePathError("unsafe-permissions", `${display} is writable by group or others`);
            }
            if ((info.mode & 0o055) !== 0) {
                warnings.push(`directory-accessible-by-others: ${display}`);
            }
        }
        return new TrustedDir(handle, { uid, displayPath: absPath, warnings });
    } catch (error) {
        await handle.close().catch(() => { });
        throw error;
    }
}
