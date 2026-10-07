// Destination-store operations for the migration (P09-D5). Wraps the existing SOPS/age store: the
// read-only inspection is kept apart from the explicit init and from the batch import, because the
// store's own write path bootstraps a key as a side effect and a migration must never do that.
import { spawn } from "node:child_process";
import { access, stat } from "node:fs/promises";
import path from "node:path";
import {
    acknowledgeManagedStoreBackup,
    bootstrapManagedStore,
    importManagedSecrets,
    readManagedSecretStore,
} from "../../encrypted-store.mjs";
import { PreflightError } from "./errors.mjs";
import { UnsafePathError, openTrustedRoot } from "./safe-fs.mjs";

const RESOLVER_TIMEOUT_MS = 15000;

function mapStoreError(error) {
    if (error instanceof PreflightError) {
        return error;
    }
    const message = String(error?.message ?? "");
    if (error?.code === "STORE_MISSING") {
        return new PreflightError("store-missing", "the destination store does not exist; run --init-store first");
    }
    if (error?.code === "INVALID_STORE_NAME") {
        return new PreflightError("invalid-store-name", "an import name is not a valid resolver id");
    }
    if (error?.code === "STORE_NAME_CONFLICT") {
        return new PreflightError(
            "store-name-conflict",
            `${error.names.length} store name(s) already hold a different value`,
            { names: error.names },
        );
    }
    if (/requires the `sops` CLI/.test(message)) {
        return new PreflightError("tool-missing", "sops is not on PATH");
    }
    if (/requires sops \d/.test(message)) {
        return new PreflightError("tool-version", message.replace(/\.$/, ""));
    }
    if (/^exit=\d+/.test(message)) {
        return new PreflightError("key-unavailable", "sops could not decrypt the store with the available key");
    }
    if (error instanceof SyntaxError) {
        return new PreflightError("store-corrupt", "the decrypted store is not valid JSON");
    }
    return error;
}

async function exists(file) {
    try {
        await access(file);
        return true;
    } catch {
        return false;
    }
}

// Read-only. Creates no key, config or store; the only programs it runs are `sops --version` and
// `sops --decrypt`, and only when a store already exists.
export async function inspectStore({ storePath, check = [] }) {
    const selected = path.resolve(storePath);
    if (!(await exists(selected))) {
        return { state: "missing" };
    }
    try {
        const { document } = await readManagedSecretStore({ storePath: selected, execFileFn: spawn });
        const result = {
            state: "ready",
            backupPending: document.metadata?.bootstrap_backup_pending === true,
            names: Object.keys(document.secrets ?? {}).sort(),
        };
        if (check.length > 0) {
            // Names that already hold a different value; compared in memory, never reported by value.
            result.conflicts = check
                .filter((entry) => {
                    const existing = document.secrets?.[entry.name];
                    return existing && typeof existing === "object" && existing.value !== entry.value;
                })
                .map((entry) => entry.name)
                .sort();
        }
        return result;
    } catch (error) {
        throw mapStoreError(error);
    }
}

export async function initStore({ storePath, stderr = process.stderr }) {
    try {
        const result = await bootstrapManagedStore({ storePath, stderr });
        return { created: result.bootstrapped, ageKeyPath: result.ageKeyPath, sopsConfigPath: result.sopsConfigPath };
    } catch (error) {
        throw mapStoreError(error);
    }
}

export async function importEntries({ storePath, entries, migrationId }) {
    try {
        return await importManagedSecrets({
            storePath,
            entries: entries.map((entry) => ({
                name: entry.name,
                value: entry.value,
                metadata: { source: entry.source, migration_id: migrationId, migrated_by: "blindpass-openclaw-migrate" },
            })),
        });
    } catch (error) {
        throw mapStoreError(error);
    }
}

// Runs the resolver command exactly as OpenClaw will (absolute path, PATH-only environment, protocol
// v1 on stdin) and compares what it returns with the values we imported, in memory only.
export async function verifyViaResolver({ resolverCommand, storePath, entries, providerAlias = "blindpass" }) {
    const request = JSON.stringify({ protocolVersion: 1, provider: providerAlias, ids: entries.map((entry) => entry.name) });
    const { code, stdout } = await new Promise((resolve, reject) => {
        const child = spawn(resolverCommand, ["--store", path.resolve(storePath)], {
            env: { PATH: process.env.PATH ?? "" },
            stdio: ["pipe", "pipe", "ignore"],
        });
        let output = "";
        const timer = setTimeout(() => child.kill("SIGKILL"), RESOLVER_TIMEOUT_MS);
        child.stdout.on("data", (chunk) => { output += chunk; });
        child.on("error", (error) => { clearTimeout(timer); reject(error); });
        child.on("close", (exit) => { clearTimeout(timer); resolve({ code: exit, stdout: output }); });
        child.stdin.end(request);
    });
    let response;
    try {
        response = JSON.parse(stdout);
    } catch {
        throw new PreflightError("resolver-failed", `the resolver exited ${code} without a protocol response`);
    }
    const unresolved = [];
    const mismatched = [];
    for (const entry of entries) {
        const value = response?.values?.[entry.name];
        if (typeof value !== "string") {
            unresolved.push(entry.name);
        } else if (value !== entry.value) {
            mismatched.push(entry.name);
        }
    }
    if (unresolved.length > 0) {
        throw new PreflightError("resolver-unresolved", `${unresolved.length} entr${unresolved.length === 1 ? "y" : "ies"} did not resolve`, { names: unresolved });
    }
    if (mismatched.length > 0) {
        throw new PreflightError("resolver-mismatch", `${mismatched.length} resolved value(s) differ from the imported value(s)`, { names: mismatched });
    }
}

const MAX_KEY_BACKUP_BYTES = 4096;
const AGE_SECRET_KEY_LINE = /^AGE-SECRET-KEY-[A-Z0-9]+[ \t]*$/m;

// Opens the operator's key backup through the same descriptor-relative layer as the config, with the
// extra rule that a key file must not be readable by group or others. Returns the verified absolute
// path; the key material is never kept, printed or copied.
async function checkKeyBackupFile(backupPath, storePath) {
    if (typeof backupPath !== "string" || !path.isAbsolute(backupPath)) {
        throw new PreflightError("key-backup-unavailable", "the key backup path must be absolute");
    }
    const uid = process.geteuid();
    let dir;
    try {
        dir = await openTrustedRoot(path.dirname(backupPath), { uid, ancestorUids: [0, uid], rootUids: [0, uid] });
    } catch (error) {
        if (error instanceof UnsafePathError) {
            throw new PreflightError(error.reason === "not-found" ? "key-backup-unavailable" : "key-backup-unsafe", `its directory cannot be used (${error.reason})`);
        }
        throw error;
    }
    try {
        const name = path.basename(backupPath);
        const info = await dir.statName(name);
        if (info === null) {
            throw new PreflightError("key-backup-unavailable", "the key backup file does not exist");
        }
        if (info.isSymbolicLink() || !info.isFile()) {
            throw new PreflightError("key-backup-unsafe", "the key backup must be a regular file, not a link");
        }
        if (info.uid !== uid || (info.mode & 0o077) !== 0) {
            throw new PreflightError("key-backup-unsafe", "the key backup must be owned by you and not readable by group or others");
        }
        let file;
        try {
            file = await dir.readFile(name, { maxBytes: MAX_KEY_BACKUP_BYTES });
        } catch (error) {
            if (error instanceof UnsafePathError) {
                throw new PreflightError(error.reason === "too-large" ? "key-backup-unusable" : "key-backup-unsafe", `the key backup cannot be read (${error.reason})`);
            }
            throw error;
        }
        if (!AGE_SECRET_KEY_LINE.test(file.bytes.toString("utf8"))) {
            throw new PreflightError("key-backup-unusable", "the file does not contain an age identity");
        }
        const live = await stat(path.join(path.dirname(storePath), ".age-key.txt")).catch(() => null);
        if (live && live.ino === info.ino && live.dev === info.dev) {
            throw new PreflightError("key-backup-is-live-key", "this is the live key file, not a backup of it");
        }
        return backupPath;
    } finally {
        await dir.close();
    }
}

// Decrypts the real store with ONLY the backup key: a minimal environment (no ambient key variables,
// no default key file) so the result cannot come from anything but the backup. The decrypted output is
// drained and discarded.
function decryptWithOnlyBackupKey(storePath, backupPath) {
    return new Promise((resolve, reject) => {
        const child = spawn("sops", ["--decrypt", "--output-type", "json", path.resolve(storePath)], {
            env: {
                PATH: process.env.PATH ?? "",
                HOME: "/nonexistent",
                XDG_CONFIG_HOME: "/nonexistent",
                SOPS_AGE_KEY_FILE: backupPath,
            },
            stdio: ["ignore", "pipe", "ignore"],
        });
        const timer = setTimeout(() => child.kill("SIGKILL"), RESOLVER_TIMEOUT_MS);
        child.stdout.resume();
        child.on("error", (error) => { clearTimeout(timer); reject(error); });
        child.on("close", (code) => { clearTimeout(timer); resolve(code === 0); });
    });
}

// Clears bootstrap_backup_pending only after the backup is shown to work: the live store must decrypt,
// and the backup key alone must decrypt the same store. An acknowledgement without that proves nothing
// about restorability.
export async function acknowledgeKeyBackup({ storePath, backupPath }) {
    const store = await inspectStore({ storePath });
    if (store.state === "missing") {
        throw new PreflightError("store-missing", "the destination store does not exist; run --init-store first");
    }
    if (!store.backupPending) {
        return { updated: false, reason: "already-acknowledged" };
    }
    const verified = await checkKeyBackupFile(backupPath, path.resolve(storePath));
    let restorable;
    try {
        restorable = await decryptWithOnlyBackupKey(storePath, verified);
    } catch {
        throw new PreflightError("tool-missing", "sops is not on PATH");
    }
    if (!restorable) {
        throw new PreflightError("key-backup-unusable", "the backup key cannot decrypt the store; it is not a usable backup of this store's key");
    }
    try {
        const result = await acknowledgeManagedStoreBackup({ env: { ...process.env, BLINDPASS_STORE_PATH: path.resolve(storePath) } });
        return { updated: result.updated === true, reason: result.reason };
    } catch (error) {
        throw mapStoreError(error);
    }
}

// Read-only store state for the dry run: what an operator needs to know before --apply, without
// creating or changing anything.
export async function describeStore({ storePath, migratable = [] }) {
    try {
        const state = await inspectStore({
            storePath,
            check: migratable.map((target) => ({ name: target.ref.id, value: target.value })),
        });
        if (state.state === "missing") {
            return { store: { state: "missing" }, warnings: ["store-missing: run --init-store before --apply"] };
        }
        const warnings = [];
        if (state.backupPending) {
            warnings.push("bootstrap-backup-pending: run --ack-backup <key backup file> before --apply");
        }
        if ((state.conflicts ?? []).length > 0) {
            warnings.push(`store-name-conflict: ${state.conflicts.length} store name(s) already hold a different value`);
        }
        return { store: { state: "ready", backupPending: state.backupPending, entries: state.names.length }, warnings };
    } catch (error) {
        if (!(error instanceof PreflightError)) {
            throw error;
        }
        return { store: { state: "unavailable", reason: error.reason }, warnings: [`${error.reason}: ${error.message.replace(/^[a-z-]+: /, "")}`] };
    }
}
