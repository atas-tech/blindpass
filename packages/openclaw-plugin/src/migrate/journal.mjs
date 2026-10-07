// Migration journal and lock (P09-D4, P09-D3).
//
// The journal records, per stage, a durable *intent* before any effect and a *completion* after, so a
// rerun can reconcile real file and store state instead of trusting it. It holds paths, names and
// whole-file hashes only; never a secret value or a per-value hash. Mode 0600, replaced atomically.
import { randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import { JOURNAL_NAME, LOCK_NAME, STALE_JOURNAL_MS, archivedJournalName } from "./constants.mjs";
import { UnsafePathError } from "./safe-fs.mjs";

export const STAGES = Object.freeze(["inventory", "backup", "import", "rewrite", "commit"]);
const STATUSES = new Set(["in-progress", "committed", "rollback-in-progress", "rolled-back", "failed"]);
const MIGRATION_ID = /^m-\d{8}T\d{6}Z-[0-9a-f]{8}$/;
const MAX_JOURNAL_BYTES = 1024 * 1024;

export const isMigrationId = (value) => typeof value === "string" && MIGRATION_ID.test(value);

export class JournalError extends Error {
    constructor(reason, detail) {
        super(detail ? `${reason}: ${detail}` : reason);
        this.name = "JournalError";
        this.reason = reason;
    }
}

export class LockHeldError extends Error {
    constructor(detail) {
        super(`migration-lock-held: ${detail}`);
        this.name = "LockHeldError";
    }
}

function compactUtc(date) {
    return date.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z");
}

function validate(state) {
    if (state === null || typeof state !== "object" || Array.isArray(state)) {
        throw new JournalError("journal-corrupt");
    }
    if (state.version !== 1) {
        throw new JournalError("journal-version-unsupported", String(state.version));
    }
    if (
        typeof state.migrationId !== "string"
        || !MIGRATION_ID.test(state.migrationId)
        || !STATUSES.has(state.status)
        || state.stages === null || typeof state.stages !== "object" || Array.isArray(state.stages)
        || state.files === null || typeof state.files !== "object" || Array.isArray(state.files)
        || !Array.isArray(state.targets)
    ) {
        throw new JournalError("journal-corrupt");
    }
    return state;
}

const FIELDS = new Set(["backupDir", "rejected", "afterSha256", "residual", "warnings", "failure", "rollback", "unsupported"]);

export class Journal {
    #dir;
    #sha;
    #name;

    constructor(dir, state, sha, name = JOURNAL_NAME) {
        this.#dir = dir;
        this.state = state;
        this.#sha = sha;
        this.#name = name;
    }

    static async create(dir, { release, providerAlias, storePath, resolverCommand, now = () => new Date() }) {
        const at = now();
        const state = {
            version: 1,
            migrationId: `m-${compactUtc(at)}-${randomBytes(4).toString("hex")}`,
            release,
            providerAlias,
            storePath,
            resolverCommand,
            status: "in-progress",
            startedAt: at.toISOString(),
            updatedAt: at.toISOString(),
            stages: {},
            files: {},
            targets: [],
            importedNames: [],
            notes: [],
        };
        const bytes = `${JSON.stringify(state, null, 2)}\n`;
        try {
            await dir.createFileExclusive(JOURNAL_NAME, bytes);
        } catch (error) {
            if (error instanceof UnsafePathError && error.reason === "already-exists") {
                throw new JournalError("journal-exists", "an unfinished migration journal is present; resume or roll it back");
            }
            throw error;
        }
        const { sha256 } = await dir.readFile(JOURNAL_NAME, { maxBytes: MAX_JOURNAL_BYTES });
        return new Journal(dir, state, sha256);
    }

    static async load(dir, name = JOURNAL_NAME) {
        let file;
        try {
            file = await dir.readFile(name, { maxBytes: MAX_JOURNAL_BYTES });
        } catch (error) {
            if (error instanceof UnsafePathError && error.reason === "not-found") {
                return null;
            }
            if (error instanceof UnsafePathError && error.reason === "too-large") {
                throw new JournalError("journal-corrupt", "too large");
            }
            throw error;
        }
        let state;
        try {
            state = JSON.parse(file.bytes.toString("utf8"));
        } catch {
            throw new JournalError("journal-corrupt");
        }
        return new Journal(dir, validate(state), file.sha256, name);
    }

    get name() {
        return this.#name;
    }

    // Moves this journal aside under its migration ID so a later migration can start fresh while this
    // one stays available to --rollback <id>.
    async archive() {
        const archived = archivedJournalName(this.state.migrationId);
        await this.#dir.renameFile(this.#name, archived);
        this.#name = archived;
    }

    async remove() {
        await this.#dir.removeFile(this.#name);
    }

    async setField(field, value, at) {
        if (!FIELDS.has(field)) {
            throw new JournalError("journal-corrupt", "unknown field");
        }
        await this.#write((next) => {
            next[field] = value;
        }, at);
    }

    async #write(mutate, at = new Date()) {
        const next = structuredClone(this.state);
        mutate(next, at);
        next.updatedAt = at.toISOString();
        const bytes = `${JSON.stringify(next, null, 2)}\n`;
        await this.#dir.replaceFile(this.#name, bytes, { expectedSha256: this.#sha });
        const { sha256 } = await this.#dir.readFile(this.#name, { maxBytes: MAX_JOURNAL_BYTES });
        this.state = next;
        this.#sha = sha256;
    }

    #assertStage(stage) {
        if (!STAGES.includes(stage)) {
            throw new JournalError("unknown-stage", String(stage).slice(0, 40));
        }
    }

    async stageIntent(stage, at) {
        this.#assertStage(stage);
        await this.#write((next, when) => {
            next.stages[stage] = { intent: when.toISOString() };
        }, at);
    }

    async stageDone(stage, at) {
        this.#assertStage(stage);
        await this.#write((next, when) => {
            next.stages[stage] = { ...next.stages[stage], done: when.toISOString() };
        }, at);
    }

    async setFiles(files, at) {
        await this.#write((next) => {
            next.files = { ...next.files, ...files };
        }, at);
    }

    async setTargets(targets, at) {
        await this.#write((next) => {
            next.targets = targets;
        }, at);
    }

    async setImported(names, at) {
        await this.#write((next) => {
            next.importedNames = names;
        }, at);
    }

    async setStatus(status, at) {
        if (!STATUSES.has(status)) {
            throw new JournalError("journal-corrupt", "unknown status");
        }
        await this.#write((next) => {
            next.status = status;
        }, at);
    }

    async addNote(note, at) {
        await this.#write((next) => {
            next.notes.push(note);
        }, at);
    }

    staleness(now = new Date()) {
        const age = now.getTime() - Date.parse(this.state.updatedAt);
        if (Number.isFinite(age) && age > STALE_JOURNAL_MS) {
            return `journal-stale: last stage activity was ${Math.floor(age / 3600000)}h ago`;
        }
        return null;
    }
}

async function startTicks(pid) {
    try {
        const stat = await readFile(`/proc/${pid}/stat`, "utf8");
        return stat.slice(stat.lastIndexOf(")") + 2).split(" ")[19] ?? null;
    } catch {
        return null;
    }
}

async function lockIsLive(existing) {
    if (!Number.isInteger(existing?.pid) || existing.pid < 1) {
        return true;
    }
    try {
        process.kill(existing.pid, 0);
    } catch (error) {
        if (error?.code === "ESRCH") {
            return false;
        }
    }
    const current = await startTicks(existing.pid);
    // A different start time means the pid was recycled by an unrelated process.
    return !(current !== null && typeof existing.startTicks === "string" && current !== existing.startTicks);
}

export async function acquireMigrationLock(dir) {
    const token = randomBytes(8).toString("hex");
    const body = `${JSON.stringify({ pid: process.pid, startTicks: await startTicks(process.pid), token, startedAt: new Date().toISOString() })}\n`;
    let note;
    try {
        await dir.createFileExclusive(LOCK_NAME, body);
    } catch (error) {
        if (!(error instanceof UnsafePathError) || error.reason !== "already-exists") {
            throw error;
        }
        let existing = null;
        try {
            existing = JSON.parse((await dir.readFile(LOCK_NAME, { maxBytes: 4096 })).bytes.toString("utf8"));
        } catch {
            throw new LockHeldError("the lock file is unreadable; remove it only if no migration is running");
        }
        if (await lockIsLive(existing)) {
            throw new LockHeldError(`another migration (pid ${existing.pid}) is running`);
        }
        await dir.removeFile(LOCK_NAME);
        note = `stale lock from pid ${existing.pid} was removed`;
        try {
            await dir.createFileExclusive(LOCK_NAME, body);
        } catch {
            throw new LockHeldError("another migration took the lock first");
        }
    }
    return {
        note,
        token,
        async release() {
            try {
                const current = JSON.parse((await dir.readFile(LOCK_NAME, { maxBytes: 4096 })).bytes.toString("utf8"));
                if (current.token === token) {
                    await dir.removeFile(LOCK_NAME);
                }
            } catch {
                // Already gone or replaced: never delete a lock this process does not own.
            }
        },
    };
}
