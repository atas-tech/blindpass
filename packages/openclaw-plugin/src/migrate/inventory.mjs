// Read-only inventory and dry run (P09.2). Nothing here creates, locks, writes, spawns a process or
// calls the openclaw CLI: on 2026.8.35 even `openclaw secrets audit` creates state/openclaw.sqlite.
import { classifySecretInput } from "./classify.mjs";
import { DEFAULT_PROVIDER_ALIAS, JOURNAL_NAME, LOCK_NAME, MAX_FILE_BYTES } from "./constants.mjs";
import { parseDotenv } from "./dotenv.mjs";
import { storeNameFor } from "./names.mjs";
import { REDACTED, renderPlanJson, renderPlanText } from "./render.mjs";
import { enumerateConfigTargets, loadRegistry } from "./registry.mjs";
import { UnsafePathError, openTrustedRoot } from "./safe-fs.mjs";
import { describeStore } from "./store.mjs";

export { renderPlanJson, renderPlanText };

const MIN_SCANNABLE_LENGTH = 8;
const MAX_AGENT_DIRS = 64;
const CREDENTIAL_ENV_NAME = /API_?KEY|TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE_?KEY|CREDENTIAL|AUTH/i;
const FILE_ORDER = { "openclaw.json": 0, ".env": 1, "state/openclaw.sqlite": 2 };

const STATUS_BY_KIND = {
    plaintext: "migratable",
    secretref: "already-reference",
    "env-shorthand": "env-reference",
    empty: "empty",
};

function compare(a, b) {
    return a < b ? -1 : a > b ? 1 : 0;
}

async function readBounded(dir, name) {
    try {
        const file = await dir.readFile(name, { maxBytes: MAX_FILE_BYTES });
        return { state: "ok", file };
    } catch (error) {
        if (error instanceof UnsafePathError && error.reason === "too-large") {
            return { state: "unsupported", reason: "too-large" };
        }
        throw error;
    }
}

function parseStrictJson(bytes) {
    let text;
    try {
        text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch {
        return { reason: "not-strict-json" };
    }
    let value;
    try {
        // The parser's own error message quotes the source, so it is never surfaced.
        value = JSON.parse(text);
    } catch {
        return { reason: "not-strict-json" };
    }
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        return { reason: "not-an-object" };
    }
    return { value };
}

function containsValue(bytes, value) {
    const escaped = JSON.stringify(value).slice(1, -1);
    return bytes.includes(Buffer.from(value, "utf8")) || bytes.includes(Buffer.from(escaped, "utf8"));
}

export async function scanResidual(dir, values, warnings, { includeEnv = false } = {}) {
    const residual = [];
    const scan = async (target, label, name) => {
        try {
            const { file } = await readBounded(target, name).then((result) => (result.file ? result : { file: null }));
            if (file && values.some((value) => containsValue(file.bytes, value))) {
                residual.push({ file: label, reason: "holds-copy-of-migratable-value" });
            }
        } catch (error) {
            if (!(error instanceof UnsafePathError) || error.reason === "not-found") {
                if (!(error instanceof UnsafePathError)) {
                    throw error;
                }
                return;
            }
            warnings.push(`residual-scan-skipped: ${label} (${error.reason})`);
        }
    };

    const names = await dir.listNames();
    if (values.length > 0) {
        for (const name of names) {
            if (name.startsWith("openclaw.json.") || name.startsWith(".env.") || (includeEnv && name === ".env")) {
                await scan(dir, name, name);
            }
        }
        if (names.includes("agents")) {
            try {
                const agents = await dir.openDir("agents");
                try {
                    const ids = (await agents.listNames()).slice(0, MAX_AGENT_DIRS);
                    for (const id of ids) {
                        try {
                            const agentDir = await agents.openDir(id);
                            try {
                                const inner = await agentDir.openDir("agent");
                                try {
                                    await scan(inner, `agents/${id}/agent/models.json`, "models.json");
                                } finally {
                                    await inner.close();
                                }
                            } finally {
                                await agentDir.close();
                            }
                        } catch (error) {
                            if (!(error instanceof UnsafePathError)) {
                                throw error;
                            }
                            if (error.reason !== "not-found" && error.reason !== "not-a-directory") {
                                warnings.push(`residual-scan-skipped: agents/${id} (${error.reason})`);
                            }
                        }
                    }
                } finally {
                    await agents.close();
                }
            } catch (error) {
                if (!(error instanceof UnsafePathError)) {
                    throw error;
                }
                warnings.push(`residual-scan-skipped: agents (${error.reason})`);
            }
        }
    }
    return residual.sort((a, b) => compare(a.file, b.file));
}

// Collects everything the dry run reports. `migratable` carries the raw values for later stages and
// must never be serialised or printed; `plan` is the only structure that leaves this module.
export async function collectInventory({ dir, configDir, release, providerAlias = DEFAULT_PROVIDER_ALIAS }) {
    const registry = loadRegistry(release);
    const rows = [];
    const warnings = [];
    const files = [];
    const migratable = [];
    const names = await dir.listNames();

    // openclaw.json
    let configSha256 = null;
    let configValue = null;
    if (!names.includes("openclaw.json")) {
        files.push({ file: "openclaw.json", state: "absent" });
        warnings.push("openclaw.json-absent");
    } else {
        const read = await readBounded(dir, "openclaw.json");
        if (read.state === "unsupported") {
            files.push({ file: "openclaw.json", state: "unsupported", reason: read.reason });
        } else {
            configSha256 = read.file.sha256;
            const parsed = parseStrictJson(read.file.bytes);
            if (parsed.reason) {
                files.push({ file: "openclaw.json", state: "unsupported", reason: parsed.reason });
            } else {
                files.push({ file: "openclaw.json", state: "ok" });
                const config = parsed.value;
                configValue = config;
                const touched = config.meta?.lastTouchedVersion;
                if (typeof touched === "string" && touched !== release) {
                    warnings.push(`config-last-touched-by-other-release: ${touched}`);
                }
                const { targets, problems } = enumerateConfigTargets(config, registry);
                for (const target of targets) {
                    const result = classifySecretInput(target.value);
                    const status = STATUS_BY_KIND[result.kind] ?? "unsupported";
                    const row = {
                        file: "openclaw.json",
                        keyPath: target.path,
                        value: REDACTED,
                        proposedRef: null,
                        status,
                    };
                    if (status === "unsupported") {
                        row.reason = result.reason ?? result.kind;
                    }
                    if (status === "migratable") {
                        row.proposedRef = {
                            source: "exec",
                            provider: providerAlias,
                            id: storeNameFor(target.path),
                        };
                        migratable.push({ ...target, ref: row.proposedRef });
                        if (target.value.length < MIN_SCANNABLE_LENGTH) {
                            warnings.push(`short-value-not-scanned: ${target.path}`);
                        }
                    }
                    rows.push(row);
                }
                for (const problem of problems) {
                    rows.push({
                        file: "openclaw.json",
                        keyPath: problem.path,
                        value: REDACTED,
                        proposedRef: null,
                        status: "unsupported",
                        reason: problem.reason,
                    });
                }
            }
        }
    }

    // .env
    let envSha256 = null;
    let envNonCredential = 0;
    if (!names.includes(".env")) {
        files.push({ file: ".env", state: "absent" });
    } else {
        const read = await readBounded(dir, ".env");
        if (read.state === "unsupported") {
            files.push({ file: ".env", state: "unsupported", reason: read.reason });
        } else {
            envSha256 = read.file.sha256;
            files.push({ file: ".env", state: "ok" });
            const parsed = parseDotenv(read.file.bytes.toString("utf8"));
            for (const problem of parsed.problems) {
                warnings.push(`dotenv-line-ignored: line ${problem.line} (${problem.reason})`);
            }
            for (const key of parsed.duplicates) {
                warnings.push(`dotenv-duplicate-key: ${key}`);
            }
            const configValues = new Set(migratable.map((target) => target.value));
            for (const key of [...parsed.effective.keys()].sort(compare)) {
                const value = parsed.effective.get(key);
                if (value !== "" && configValues.has(value)) {
                    rows.push({ file: ".env", keyPath: `$env.${key}`, value: REDACTED, proposedRef: null, status: "residual", reason: "copy-of-migratable-value" });
                } else if (value !== "" && CREDENTIAL_ENV_NAME.test(key)) {
                    rows.push({
                        file: ".env",
                        keyPath: `$env.${key}`,
                        value: REDACTED,
                        proposedRef: null,
                        status: "unsupported",
                        reason: "env-credential-has-no-structured-reference",
                    });
                } else {
                    envNonCredential += 1;
                }
            }
        }
    }

    // state/openclaw.sqlite: presence only. The database is never opened.
    let sqlitePresent = false;
    if (names.includes("state")) {
        try {
            const state = await dir.openDir("state");
            try {
                sqlitePresent = (await state.statName("openclaw.sqlite")) !== null;
            } finally {
                await state.close();
            }
        } catch (error) {
            if (!(error instanceof UnsafePathError)) {
                throw error;
            }
            warnings.push(`state-directory-skipped: ${error.reason}`);
        }
    }
    files.push({ file: "state/openclaw.sqlite", state: sqlitePresent ? "present-not-inspected" : "absent" });
    if (sqlitePresent) {
        rows.push({
            file: "state/openclaw.sqlite",
            keyPath: "auth-profiles.*",
            value: REDACTED,
            proposedRef: null,
            status: "unsupported",
            reason: "auth-profile-store-not-inspected",
        });
    }

    const residual = await scanResidual(dir, migratable.map((t) => t.value).filter((v) => v.length >= MIN_SCANNABLE_LENGTH), warnings);

    if (names.includes(JOURNAL_NAME)) {
        warnings.push("unfinished-migration-journal");
    }
    if (names.includes(LOCK_NAME)) {
        warnings.push("migration-lock-present");
    }
    for (const warning of dir.warnings) {
        warnings.push(warning);
    }

    rows.sort((a, b) => (FILE_ORDER[a.file] - FILE_ORDER[b.file]) || compare(a.keyPath, b.keyPath));
    const count = (status) => rows.filter((row) => row.status === status).length;
    const plan = {
        version: 1,
        mode: "dry-run",
        release,
        configDir,
        files,
        rows,
        residual,
        warnings: [...new Set(warnings)].sort(compare),
        summary: {
            migratable: count("migratable"),
            alreadyReference: count("already-reference"),
            envReference: count("env-reference"),
            empty: count("empty"),
            unsupported: count("unsupported"),
            residual: count("residual") + residual.length,
            envNonCredential,
        },
    };
    return { plan, migratable, configSha256, envSha256, config: configValue };
}

// `storePath` is optional and explicit: only when the operator names a store does the dry run read it
// (`sops --decrypt`, read-only) to report key availability, the backup-pending flag and name conflicts.
export async function runDryRun({ configDir, release, providerAlias, uid, storePath }) {
    loadRegistry(release);
    const dir = await openTrustedRoot(configDir, uid === undefined ? {} : { uid });
    try {
        const { plan, migratable } = await collectInventory({ dir, configDir, release, providerAlias });
        if (storePath) {
            const { store, warnings } = await describeStore({ storePath, migratable });
            plan.store = store;
            plan.warnings = [...new Set([...plan.warnings, ...warnings])].sort(compare);
        }
        return { plan };
    } finally {
        await dir.close();
    }
}
