// Destination-store operations for the migration (P09-D5). Wraps the existing SOPS/age store: the
// read-only inspection is kept apart from the explicit init and from the batch import, because the
// store's own write path bootstraps a key as a side effect and a migration must never do that.
import { spawn } from "node:child_process";
import { access } from "node:fs/promises";
import path from "node:path";
import {
    bootstrapManagedStore,
    importManagedSecrets,
    readManagedSecretStore,
} from "../../encrypted-store.mjs";
import { PreflightError } from "./errors.mjs";

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
export async function verifyViaResolver({ resolverCommand, storePath, entries }) {
    const request = JSON.stringify({ protocolVersion: 1, provider: "blindpass", ids: entries.map((entry) => entry.name) });
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
