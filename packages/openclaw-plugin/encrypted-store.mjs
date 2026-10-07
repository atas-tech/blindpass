import { access, mkdir, mkdtemp, open, readFile, rename, rm, writeFile } from "node:fs/promises";
import { constants as fsConstants } from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";

const SUPPORTED_BACKEND = "sops";
const STORE_FILE_NAME = "secrets.enc.json";
const LOCK_FILE_SUFFIX = ".lock";
const DEFAULT_LOCK_TIMEOUT_MS = 5000;
const DEFAULT_LOCK_RETRY_MS = 100;
const DEFAULT_COMMAND_TIMEOUT_MS = 15000;
const BOOTSTRAP_IDENTITY_FILE = ".age-key.txt";
const BOOTSTRAP_SOPS_CONFIG_FILE = ".sops.yaml";

const _storeWriteQueues = new Map();

function parseBooleanEnv(rawValue, defaultValue = false) {
    if (rawValue == null || rawValue === "") {
        return defaultValue;
    }
    const normalized = String(rawValue).trim().toLowerCase();
    if (normalized === "1" || normalized === "true" || normalized === "yes" || normalized === "on") {
        return true;
    }
    if (normalized === "0" || normalized === "false" || normalized === "no" || normalized === "off") {
        return false;
    }
    return defaultValue;
}

function normalizeRuntimeMode(rawValue) {
    if (typeof rawValue !== "string") {
        return "";
    }
    const normalized = rawValue.trim().toLowerCase();
    if (normalized === "openclaw" || normalized === "mcp") {
        return normalized;
    }
    return "";
}

function normalizeStoreDocument(data) {
    if (!data || typeof data !== "object" || Array.isArray(data)) {
        return {
            version: 1,
            secrets: {},
            metadata: {},
        };
    }

    if (!data.secrets || typeof data.secrets !== "object" || Array.isArray(data.secrets)) {
        data.secrets = {};
    }
    if (!data.metadata || typeof data.metadata !== "object" || Array.isArray(data.metadata)) {
        data.metadata = {};
    }
    if (data.version == null) {
        data.version = 1;
    }

    return data;
}

async function runCommand(execFileFn, command, args, options = {}) {
    const timeoutMs = options.timeoutMs ?? DEFAULT_COMMAND_TIMEOUT_MS;
    const stdin = options.stdin ?? null;
    const commandEnv = options.commandEnv;

    return new Promise((resolve, reject) => {
        const spawnOptions = { stdio: ["pipe", "pipe", "pipe"] };
        if (commandEnv && typeof commandEnv === "object") {
            spawnOptions.env = {
                ...process.env,
                ...commandEnv,
            };
        }
        const child = execFileFn(command, args, spawnOptions);
        let stdout = "";
        let stderr = "";
        let finished = false;

        const timer = setTimeout(() => {
            if (!finished) {
                child.kill("SIGKILL");
            }
        }, timeoutMs);

        child.stdout?.on("data", (chunk) => {
            stdout += String(chunk);
        });
        child.stderr?.on("data", (chunk) => {
            stderr += String(chunk);
        });

        child.on("error", (err) => {
            if (finished) return;
            finished = true;
            clearTimeout(timer);
            reject(err);
        });

        child.on("close", (code) => {
            if (finished) return;
            finished = true;
            clearTimeout(timer);
            if (code === 0) {
                resolve({ stdout, stderr, code });
            } else {
                reject(new Error(`exit=${code} stderr=${stderr.trim() || "(empty)"}`));
            }
        });

        if (stdin != null) {
            child.stdin?.write(stdin);
        }
        child.stdin?.end();
    });
}

async function fileExists(filePath) {
    try {
        await access(filePath, fsConstants.F_OK);
        return true;
    } catch {
        return false;
    }
}

function toPathRegexLiteral(fileName) {
    return fileName.replace(/[|\\{}()[\]^$+*?.-]/g, "\\$&");
}

function sleep(ms) {
    return new Promise((resolve) => {
        setTimeout(resolve, ms);
    });
}

function defaultPidStatus(pid) {
    if (!Number.isInteger(pid) || pid <= 0) {
        return "unknown";
    }
    try {
        process.kill(pid, 0);
        return "alive";
    } catch (err) {
        if (err?.code === "ESRCH") {
            return "stale";
        }
        if (err?.code === "EPERM") {
            return "unknown";
        }
        return "unknown";
    }
}

function normalizePidStatus(rawStatus, pid) {
    if (typeof rawStatus === "string") {
        const normalized = rawStatus.trim().toLowerCase();
        if (normalized === "alive" || normalized === "stale" || normalized === "unknown") {
            return normalized;
        }
        return "unknown";
    }

    if (typeof rawStatus === "boolean") {
        return rawStatus ? "alive" : "stale";
    }

    if (rawStatus == null) {
        return defaultPidStatus(pid);
    }

    return "unknown";
}

function enqueueStoreWrite(storePath, operation) {
    const existing = _storeWriteQueues.get(storePath) ?? Promise.resolve();
    const next = existing.then(operation, operation);
    const cleanup = next.finally(() => {
        if (_storeWriteQueues.get(storePath) === cleanup) {
            _storeWriteQueues.delete(storePath);
        }
    });
    _storeWriteQueues.set(storePath, cleanup);
    return cleanup;
}

async function readLockOwnerPid(lockPath) {
    try {
        const raw = await readFile(lockPath, "utf8");
        const parsed = JSON.parse(raw);
        const pid = Number.parseInt(String(parsed?.pid ?? ""), 10);
        if (!Number.isInteger(pid) || pid <= 0) {
            return null;
        }
        return pid;
    } catch (err) {
        if (err?.code === "ENOENT") {
            return null;
        }
        return null;
    }
}

async function tryBreakStaleLock(lockPath, pidCheckFn) {
    const ownerPid = await readLockOwnerPid(lockPath);
    if (ownerPid == null) {
        return false;
    }

    const rawStatus = await pidCheckFn(ownerPid);
    const status = normalizePidStatus(rawStatus, ownerPid);
    if (status !== "stale") {
        return false;
    }

    await rm(lockPath, { force: true }).catch(() => { });
    return true;
}

async function acquireStoreLock(storePath, options = {}) {
    const timeoutMs = options.timeoutMs ?? DEFAULT_LOCK_TIMEOUT_MS;
    const retryMs = options.retryMs ?? DEFAULT_LOCK_RETRY_MS;
    const pidCheckFn = options.pidCheckFn ?? defaultPidStatus;
    const lockPath = `${storePath}${LOCK_FILE_SUFFIX}`;
    const startedAt = Date.now();
    await mkdir(path.dirname(lockPath), { recursive: true, mode: 0o700 });

    while ((Date.now() - startedAt) <= timeoutMs) {
        try {
            const handle = await open(lockPath, "wx", 0o600);
            const payload = JSON.stringify({
                pid: process.pid,
                created_at: new Date().toISOString(),
            });
            await handle.writeFile(`${payload}\n`);
            await handle.close();
            return lockPath;
        } catch (err) {
            if (err?.code !== "EEXIST") {
                throw err;
            }

            const staleLockBroken = await tryBreakStaleLock(lockPath, pidCheckFn);
            if (staleLockBroken) {
                continue;
            }

            await sleep(retryMs);
        }
    }

    throw new Error(
        `Managed-store write lock is currently held for '${storePath}'. Could not acquire within ${timeoutMs}ms.`,
    );
}

async function releaseStoreLock(lockPath) {
    await rm(lockPath, { force: true }).catch(() => { });
}

async function withStoreWriteLock(storePath, options, action) {
    const lockPath = await acquireStoreLock(storePath, options);
    try {
        return await action();
    } finally {
        await releaseStoreLock(lockPath);
    }
}

const MIN_SOPS_VERSION = [3, 9, 0];

function sopsVersionIsSupported(versionText) {
    const match = /(\d+)\.(\d+)\.(\d+)/.exec(String(versionText ?? ""));
    if (!match) {
        return true;
    }
    const found = match.slice(1, 4).map(Number);
    for (let i = 0; i < MIN_SOPS_VERSION.length; i += 1) {
        if (found[i] !== MIN_SOPS_VERSION[i]) {
            return found[i] > MIN_SOPS_VERSION[i];
        }
    }
    return true;
}

async function ensureSopsAvailable(execFileFn) {
    let versionOutput;
    try {
        versionOutput = await runCommand(execFileFn, "sops", ["--version"], { timeoutMs: 5000 });
    } catch (err) {
        throw new Error(
            "BLINDPASS_AUTO_PERSIST=true requires the `sops` CLI on PATH. Install sops or set BLINDPASS_AUTO_PERSIST=false."
        );
    }
    // Encryption uses the `sops encrypt` subcommand so the plaintext can arrive on stdin.
    if (!sopsVersionIsSupported(versionOutput.stdout)) {
        throw new Error(
            `The managed store requires sops ${MIN_SOPS_VERSION.join(".")} or newer; upgrade the \`sops\` CLI on PATH.`
        );
    }
}

function parseAgeMaterial(rawText) {
    const lines = String(rawText ?? "").split(/\r?\n/);
    let publicKey = "";
    let secretLine = "";

    for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed) {
            continue;
        }
        if (trimmed.startsWith("# public key:")) {
            publicKey = trimmed.slice("# public key:".length).trim();
            continue;
        }
        if (trimmed.startsWith("age1") && !publicKey) {
            publicKey = trimmed;
            continue;
        }
        if (trimmed.startsWith("AGE-SECRET-KEY-")) {
            secretLine = trimmed;
        }
    }

    return {
        publicKey,
        secretLine,
    };
}

async function ensureAgeIdentityFile(storePath, execFileFn) {
    const storeDir = path.dirname(storePath);
    const ageKeyPath = path.join(storeDir, BOOTSTRAP_IDENTITY_FILE);

    if (await fileExists(ageKeyPath)) {
        const raw = await readFile(ageKeyPath, "utf8");
        const parsed = parseAgeMaterial(raw);
        if (parsed.publicKey) {
            return {
                ageKeyPath,
                agePublicKey: parsed.publicKey,
                created: false,
            };
        }

        try {
            const { stdout } = await runCommand(execFileFn, "age-keygen", ["-y", ageKeyPath], { timeoutMs: 5000 });
            const derivedKey = stdout.trim();
            if (!derivedKey.startsWith("age1")) {
                throw new Error("age-keygen did not return a valid public key.");
            }
            return {
                ageKeyPath,
                agePublicKey: derivedKey,
                created: false,
            };
        } catch (err) {
            throw new Error(
                `Managed-store identity file exists but public key derivation failed at '${ageKeyPath}': ${err?.message ?? String(err)}.`,
            );
        }
    }

    let generationOutput = "";
    let identityText = "";
    try {
        const { stdout, stderr } = await runCommand(execFileFn, "age-keygen", [], { timeoutMs: 10000 });
        generationOutput = `${stdout}\n${stderr}`;
        // age-keygen prints a "Public key:" line on stderr when stdout is not a terminal. It is
        // not valid identity-file syntax and makes sops reject the whole file, so keep only the
        // comment and AGE-SECRET-KEY lines that stdout carries.
        identityText = stdout
            .split(/\r?\n/)
            .map((line) => line.trim())
            .filter((line) => line.startsWith("#") || line.startsWith("AGE-SECRET-KEY-"))
            .join("\n");
    } catch (err) {
        throw new Error(
            "SOPS bootstrap requires `age-keygen` on PATH to generate .age-key.txt for BlindPass managed store.",
        );
    }

    const parsed = parseAgeMaterial(generationOutput);
    if (!parsed.secretLine || !parsed.publicKey) {
        throw new Error("age-keygen output did not contain a usable age identity and public key.");
    }

    if (!parseAgeMaterial(identityText).secretLine) {
        throw new Error("age-keygen output did not contain a usable age identity and public key.");
    }
    await writeFile(ageKeyPath, `${identityText}\n`, { mode: 0o600, flag: "wx" });

    return {
        ageKeyPath,
        agePublicKey: parsed.publicKey,
        created: true,
    };
}

async function ensureSopsConfigFile(storePath, agePublicKey) {
    const storeDir = path.dirname(storePath);
    const sopsConfigPath = path.join(storeDir, BOOTSTRAP_SOPS_CONFIG_FILE);
    if (await fileExists(sopsConfigPath)) {
        return {
            sopsConfigPath,
            created: false,
        };
    }

    const fileNameRegex = toPathRegexLiteral(path.basename(storePath));
    const content = [
        "creation_rules:",
        `  - path_regex: '^${fileNameRegex}$'`,
        `    age: '${agePublicKey}'`,
        "",
    ].join("\n");
    await writeFile(sopsConfigPath, content, { mode: 0o600 });
    return {
        sopsConfigPath,
        created: true,
    };
}

function writeBootstrapRecoveryGuidance(stderr, params) {
    const stream = stderr && typeof stderr.write === "function" ? stderr : process.stderr;
    const lines = [
        "[blindpass] Managed store bootstrap initialized.",
        `[blindpass] store: ${params.storePath}`,
        `[blindpass] age_identity: ${params.ageKeyPath}`,
        `[blindpass] age_public_key: ${params.agePublicKey}`,
        "[blindpass] backup_required: keep .age-key.txt safe. Losing this key makes stored secrets unrecoverable.",
        "[blindpass] reminder: set BLINDPASS_BACKUP_ACKNOWLEDGED=true after backup to stop startup reminders.",
        "",
    ];
    stream.write(`${lines.join("\n")}\n`);
}

export async function deriveSopsCommandEnv(storePath, env = process.env) {
    const storeDir = path.dirname(storePath);
    const derivedEnv = {};

    if (!env.SOPS_CONFIG) {
        const candidate = path.join(storeDir, ".sops.yaml");
        if (await fileExists(candidate)) {
            derivedEnv.SOPS_CONFIG = candidate;
        }
    }

    if (!env.SOPS_AGE_KEY_FILE) {
        const candidate = path.join(storeDir, ".age-key.txt");
        if (await fileExists(candidate)) {
            derivedEnv.SOPS_AGE_KEY_FILE = candidate;
        }
    }

    return derivedEnv;
}

async function readEncryptedStore(storePath, execFileFn) {
    return readEncryptedStoreWithEnv(storePath, execFileFn, process.env);
}

async function readEncryptedStoreWithEnv(storePath, execFileFn, env = process.env) {
    if (!(await fileExists(storePath))) {
        return normalizeStoreDocument({});
    }

    const commandEnv = await deriveSopsCommandEnv(storePath, env);
    const { stdout } = await runCommand(execFileFn, "sops", ["--decrypt", "--output-type", "json", storePath], {
        commandEnv,
    });
    const parsed = JSON.parse(stdout);
    return normalizeStoreDocument(parsed);
}

async function writeEncryptedStore(storePath, data, execFileFn) {
    return writeEncryptedStoreWithEnv(storePath, data, execFileFn, process.env);
}

async function writeEncryptedStoreWithEnv(storePath, data, execFileFn, env = process.env) {
    const resolvedStorePath = path.resolve(storePath);
    const storeDir = path.dirname(resolvedStorePath);
    await mkdir(storeDir, { recursive: true });

    const encryptedPath = `${resolvedStorePath}.tmp`;
    const plaintext = JSON.stringify(data, null, 2);
    let privateDir = null;

    try {
        const commandEnv = await deriveSopsCommandEnv(resolvedStorePath, env);
        // The store's .sops.yaml creation rule matches the store file name, so sops needs
        // --filename-override: the input is not the store file. The plaintext document reaches
        // sops on stdin (`sops encrypt` with no path: `/dev/stdin` cannot be opened when the
        // child's stdin is a socket) and never touches argv or disk. Only Windows, where this
        // is unverified, goes through a file in a private (0700) directory removed afterwards.
        let inputPath = null;
        let stdin = plaintext;
        if (process.platform === "win32") {
            privateDir = await mkdtemp(path.join(os.tmpdir(), "blindpass-store-"));
            inputPath = path.join(privateDir, "plain.json");
            await writeFile(inputPath, plaintext, { mode: 0o600 });
            stdin = null;
        }
        const { stdout } = await runCommand(
            execFileFn,
            "sops",
            [
                "encrypt",
                "--filename-override",
                resolvedStorePath,
                "--input-type",
                "json",
                "--output-type",
                "json",
                ...(inputPath ? [inputPath] : []),
            ],
            {
                timeoutMs: 20000,
                commandEnv,
                stdin,
            },
        );

        await writeFile(encryptedPath, stdout, { mode: 0o600 });
        await rename(encryptedPath, resolvedStorePath);
    } finally {
        if (privateDir) {
            await rm(privateDir, { recursive: true, force: true }).catch(() => { });
        }
        await rm(encryptedPath, { force: true }).catch(() => { });
    }
}

export function resolveDefaultStorePath(env = process.env, platform = process.platform) {
    return resolveDefaultStorePathWithRuntime(env, platform, {});
}

function resolveOpenClawGatewayConfigDir(env = process.env) {
    const candidates = [
        env.BLINDPASS_OPENCLAW_CONFIG_DIR,
        env.OPENCLAW_GATEWAY_CONFIG_DIR,
        env.OPENCLAW_CONFIG_DIR,
    ];

    for (const candidate of candidates) {
        if (typeof candidate === "string" && candidate.trim()) {
            return candidate.trim();
        }
    }

    if (typeof env.HOME === "string" && env.HOME.trim()) {
        return path.join(env.HOME.trim(), ".openclaw");
    }

    return "";
}

function resolveDefaultStorePathWithRuntime(env = process.env, platform = process.platform, options = {}) {
    const runtimeMode = normalizeRuntimeMode(options.runtimeMode || env.BLINDPASS_RUNTIME_MODE);
    if (runtimeMode === "openclaw") {
        const configDir = resolveOpenClawGatewayConfigDir(env);
        if (configDir) {
            return path.join(configDir, "blindpass", STORE_FILE_NAME);
        }
    }

    if (platform === "win32") {
        const localAppData = env.LOCALAPPDATA?.trim();
        const homeDir = env.USERPROFILE?.trim() || os.homedir();
        const base = localAppData || path.join(homeDir, "AppData", "Local");
        return path.join(base, "blindpass", STORE_FILE_NAME);
    }

    const homeDir = env.HOME?.trim() || os.homedir();
    return path.join(homeDir, ".blindpass", STORE_FILE_NAME);
}

export function resolveManagedStoreConfig(env = process.env, platform = process.platform, options = {}) {
    const runtimeMode = normalizeRuntimeMode(options.runtimeMode || env.BLINDPASS_RUNTIME_MODE);
    const autoPersist = parseBooleanEnv(env.BLINDPASS_AUTO_PERSIST, false);
    const backend = env.BLINDPASS_STORE_BACKEND?.trim().toLowerCase() || SUPPORTED_BACKEND;
    const storePath = env.BLINDPASS_STORE_PATH?.trim() || resolveDefaultStorePathWithRuntime(env, platform, {
        runtimeMode,
    });
    return {
        autoPersist,
        backend,
        storePath,
        runtimeMode: runtimeMode || "mcp",
    };
}

function assertSupportedBackend(backend) {
    if (backend !== SUPPORTED_BACKEND) {
        throw new Error(
            `Unsupported managed-store backend '${backend}'. Configure BLINDPASS_STORE_BACKEND=${SUPPORTED_BACKEND}.`,
        );
    }
}

function shouldAcknowledgeBackup(env = process.env) {
    return parseBooleanEnv(env.BLINDPASS_BACKUP_ACKNOWLEDGED, false);
}

function clearBootstrapBackupPendingFlag(document, now) {
    if (document?.metadata?.bootstrap_backup_pending !== true) {
        return false;
    }

    document.metadata.bootstrap_backup_pending = false;
    document.metadata.bootstrap_backup_acknowledged_at = now.toISOString();
    document.metadata.updated_at = now.toISOString();
    return true;
}

async function ensureSopsBootstrap(options) {
    const {
        storePath,
        execFileFn,
        env = process.env,
        now = new Date(),
        stderr = process.stderr,
    } = options;

    const storeDir = path.dirname(storePath);
    await mkdir(storeDir, { recursive: true, mode: 0o700 });

    const identity = await ensureAgeIdentityFile(storePath, execFileFn);
    const sopsConfig = await ensureSopsConfigFile(storePath, identity.agePublicKey);

    const storeAlreadyExists = await fileExists(storePath);
    if (storeAlreadyExists) {
        return {
            bootstrapped: false,
            ageKeyPath: identity.ageKeyPath,
            agePublicKey: identity.agePublicKey,
            sopsConfigPath: sopsConfig.sopsConfigPath,
        };
    }

    const backupPending = !shouldAcknowledgeBackup(env);
    const initializedAt = now.toISOString();
    const initialDocument = normalizeStoreDocument({
        version: 1,
        secrets: {},
        metadata: {
            backend: SUPPORTED_BACKEND,
            updated_at: initializedAt,
            bootstrap_initialized_at: initializedAt,
            bootstrap_public_key: identity.agePublicKey,
            bootstrap_backup_pending: backupPending,
        },
    });

    await writeEncryptedStoreWithEnv(storePath, initialDocument, execFileFn, env);

    if (backupPending) {
        writeBootstrapRecoveryGuidance(stderr, {
            storePath,
            ageKeyPath: identity.ageKeyPath,
            agePublicKey: identity.agePublicKey,
        });
    }

    return {
        bootstrapped: true,
        ageKeyPath: identity.ageKeyPath,
        agePublicKey: identity.agePublicKey,
        sopsConfigPath: sopsConfig.sopsConfigPath,
    };
}

export async function acknowledgeManagedStoreBackup(options = {}) {
    const {
        env = process.env,
        platform = process.platform,
        runtimeMode,
        execFileFn = spawn,
        now = new Date(),
        lockTimeoutMs = DEFAULT_LOCK_TIMEOUT_MS,
        lockRetryMs = DEFAULT_LOCK_RETRY_MS,
        pidCheckFn = defaultPidStatus,
    } = options;

    const config = resolveManagedStoreConfig(env, platform, { runtimeMode });
    if (config.backend !== SUPPORTED_BACKEND) {
        throw new Error(
            `Unsupported managed-store backend '${config.backend}'. Configure BLINDPASS_STORE_BACKEND=${SUPPORTED_BACKEND}.`,
        );
    }

    if (!(await fileExists(config.storePath))) {
        return {
            updated: false,
            storePath: config.storePath,
            backend: config.backend,
            reason: "store-missing",
        };
    }

    await ensureSopsAvailable(execFileFn);

    return enqueueStoreWrite(config.storePath, async () => withStoreWriteLock(
        config.storePath,
        {
            timeoutMs: lockTimeoutMs,
            retryMs: lockRetryMs,
            pidCheckFn,
        },
        async () => {
            const document = await readEncryptedStoreWithEnv(config.storePath, execFileFn, env);
            const updated = clearBootstrapBackupPendingFlag(document, now);
            if (!updated) {
                return {
                    updated: false,
                    storePath: config.storePath,
                    backend: config.backend,
                    reason: "already-acknowledged",
                };
            }

            await writeEncryptedStoreWithEnv(config.storePath, document, execFileFn, env);
            return {
                updated: true,
                storePath: config.storePath,
                backend: config.backend,
            };
        },
    ));
}

const IMPORT_NAME_PATTERN = /^[A-Za-z0-9._-]{1,128}$/;

// Explicit store setup for tools that must not create keys as a side effect of a write: generates
// the age identity, .sops.yaml and an empty store only when they are missing.
export async function bootstrapManagedStore(options = {}) {
    const {
        storePath,
        env = process.env,
        execFileFn = spawn,
        now = new Date(),
        stderr = process.stderr,
        lockTimeoutMs = DEFAULT_LOCK_TIMEOUT_MS,
        lockRetryMs = DEFAULT_LOCK_RETRY_MS,
        pidCheckFn = defaultPidStatus,
    } = options;
    if (typeof storePath !== "string" || storePath.trim() === "") {
        throw new Error("A store path is required to bootstrap the managed store.");
    }
    const selectedPath = path.resolve(storePath);
    return enqueueStoreWrite(selectedPath, async () => withStoreWriteLock(
        selectedPath,
        { timeoutMs: lockTimeoutMs, retryMs: lockRetryMs, pidCheckFn },
        async () => {
            await ensureSopsAvailable(execFileFn);
            return ensureSopsBootstrap({ storePath: selectedPath, execFileFn, env, now, stderr });
        },
    ));
}

// Batch import into an existing store in one decrypt/encrypt cycle: all entries or none. Never
// bootstraps, and never replaces an existing entry that holds a different value.
export async function importManagedSecrets(options = {}) {
    const {
        entries,
        storePath,
        env = process.env,
        execFileFn = spawn,
        now = new Date(),
        lockTimeoutMs = DEFAULT_LOCK_TIMEOUT_MS,
        lockRetryMs = DEFAULT_LOCK_RETRY_MS,
        pidCheckFn = defaultPidStatus,
    } = options;
    if (!Array.isArray(entries) || entries.length === 0) {
        throw new Error("At least one entry is required for a managed-store import.");
    }
    for (const entry of entries) {
        if (typeof entry?.name !== "string" || !IMPORT_NAME_PATTERN.test(entry.name) || typeof entry.value !== "string") {
            throw Object.assign(new Error("invalid import entry"), { code: "INVALID_STORE_NAME" });
        }
    }
    const selectedPath = path.resolve(storePath);
    return enqueueStoreWrite(selectedPath, async () => withStoreWriteLock(
        selectedPath,
        { timeoutMs: lockTimeoutMs, retryMs: lockRetryMs, pidCheckFn },
        async () => {
            await ensureSopsAvailable(execFileFn);
            if (!(await fileExists(selectedPath))) {
                throw Object.assign(new Error("The managed store does not exist."), { code: "STORE_MISSING" });
            }
            const document = await readEncryptedStoreWithEnv(selectedPath, execFileFn, env);
            const written = [];
            const unchanged = [];
            const conflicts = [];
            for (const entry of entries) {
                const existing = document.secrets[entry.name];
                if (existing && typeof existing === "object") {
                    (existing.value === entry.value ? unchanged : conflicts).push(entry.name);
                } else {
                    written.push(entry.name);
                }
            }
            if (conflicts.length > 0) {
                throw Object.assign(new Error("Managed-store entries already hold different values."), {
                    code: "STORE_NAME_CONFLICT",
                    names: conflicts.sort(),
                });
            }
            for (const entry of entries) {
                if (written.includes(entry.name)) {
                    document.secrets[entry.name] = {
                        value: entry.value,
                        updated_at: now.toISOString(),
                        ...(entry.metadata ?? {}),
                    };
                }
            }
            if (written.length > 0) {
                document.metadata.updated_at = now.toISOString();
                await writeEncryptedStoreWithEnv(selectedPath, document, execFileFn, env);
            }
            return {
                written: written.sort(),
                unchanged: unchanged.sort(),
                storePath: selectedPath,
                bootstrapBackupPending: document.metadata.bootstrap_backup_pending === true,
            };
        },
    ));
}

export async function emitManagedStoreBootstrapReminder(options = {}) {
    const {
        env = process.env,
        platform = process.platform,
        runtimeMode,
        execFileFn = spawn,
        stderr = process.stderr,
        now = new Date(),
        lockTimeoutMs = DEFAULT_LOCK_TIMEOUT_MS,
        lockRetryMs = DEFAULT_LOCK_RETRY_MS,
        pidCheckFn = defaultPidStatus,
    } = options;

    const config = resolveManagedStoreConfig(env, platform, { runtimeMode });
    if (!config.autoPersist) {
        return { emitted: false, reason: "auto-persist-disabled" };
    }
    if (config.backend !== SUPPORTED_BACKEND) {
        return { emitted: false, reason: "unsupported-backend" };
    }

    await ensureSopsAvailable(execFileFn);

    if (shouldAcknowledgeBackup(env)) {
        const result = await acknowledgeManagedStoreBackup({
            env,
            platform,
            runtimeMode,
            execFileFn,
            now,
            lockTimeoutMs,
            lockRetryMs,
            pidCheckFn,
        });
        return {
            emitted: false,
            acknowledged: result.updated,
            storePath: config.storePath,
        };
    }

    if (!(await fileExists(config.storePath))) {
        return { emitted: false, reason: "store-missing" };
    }

    const store = await readManagedSecretStore({
        env,
        platform,
        execFileFn,
        storePath: config.storePath,
        backend: config.backend,
    });

    if (store.document?.metadata?.bootstrap_backup_pending === true) {
        const stream = stderr && typeof stderr.write === "function" ? stderr : process.stderr;
        stream.write(
            [
                "[blindpass] Managed store backup is still pending.",
                `[blindpass] store: ${config.storePath}`,
                `[blindpass] age_public_key: ${store.document.metadata.bootstrap_public_key ?? "(unknown)"}`,
                "[blindpass] action: backup .age-key.txt and then set BLINDPASS_BACKUP_ACKNOWLEDGED=true.",
                "",
            ].join("\n") + "\n",
        );
        return { emitted: true, storePath: config.storePath };
    }

    return { emitted: false, reason: "no-pending-backup", storePath: config.storePath };
}

export async function persistManagedSecret(options) {
    const {
        name,
        value,
        env = process.env,
        platform = process.platform,
        runtimeMode,
        execFileFn = spawn,
        now = new Date(),
        stderr = process.stderr,
        lockTimeoutMs = DEFAULT_LOCK_TIMEOUT_MS,
        lockRetryMs = DEFAULT_LOCK_RETRY_MS,
        pidCheckFn = defaultPidStatus,
    } = options;

    const config = resolveManagedStoreConfig(env, platform, { runtimeMode });
    if (!config.autoPersist) {
        return { persisted: false, storage: "runtime" };
    }

    return storeManagedSecret({
        name,
        value,
        env,
        platform,
        execFileFn,
        now,
        stderr,
        lockTimeoutMs,
        lockRetryMs,
        pidCheckFn,
    });
}

export async function readManagedSecretStore(options = {}) {
    const {
        env = process.env,
        platform = process.platform,
        runtimeMode,
        execFileFn = spawn,
        storePath,
        backend,
    } = options;

    const config = resolveManagedStoreConfig(env, platform, { runtimeMode });
    const selectedBackend = (backend || config.backend || "").trim().toLowerCase() || SUPPORTED_BACKEND;
    const selectedPath = storePath?.trim() || config.storePath;

    assertSupportedBackend(selectedBackend);

    await ensureSopsAvailable(execFileFn);
    const document = await readEncryptedStoreWithEnv(selectedPath, execFileFn, env);

    return {
        backend: selectedBackend,
        storePath: selectedPath,
        document,
    };
}

export async function storeManagedSecret(options = {}) {
    const {
        name,
        value,
        env = process.env,
        platform = process.platform,
        runtimeMode,
        execFileFn = spawn,
        now = new Date(),
        stderr = process.stderr,
        lockTimeoutMs = DEFAULT_LOCK_TIMEOUT_MS,
        lockRetryMs = DEFAULT_LOCK_RETRY_MS,
        pidCheckFn = defaultPidStatus,
        storePath,
    } = options;

    if (typeof name !== "string" || name.trim() === "") {
        throw new Error("Secret name is required for managed-store write.");
    }

    const config = resolveManagedStoreConfig(env, platform, { runtimeMode });
    const selectedPath = storePath?.trim() || config.storePath;
    assertSupportedBackend(config.backend);

    return enqueueStoreWrite(selectedPath, async () => withStoreWriteLock(
        selectedPath,
        {
            timeoutMs: lockTimeoutMs,
            retryMs: lockRetryMs,
            pidCheckFn,
        },
        async () => {
            await ensureSopsAvailable(execFileFn);
            const bootstrap = await ensureSopsBootstrap({
                storePath: selectedPath,
                execFileFn,
                env,
                now,
                stderr,
            });
            const document = await readEncryptedStoreWithEnv(selectedPath, execFileFn, env);

            if (shouldAcknowledgeBackup(env)) {
                clearBootstrapBackupPendingFlag(document, now);
            }

            const secretValue = Buffer.isBuffer(value) ? value.toString("utf8") : Buffer.from(value).toString("utf8");
            document.secrets[name.trim()] = {
                value: secretValue,
                updated_at: now.toISOString(),
            };
            document.metadata.updated_at = now.toISOString();
            document.metadata.backend = config.backend;

            await writeEncryptedStoreWithEnv(selectedPath, document, execFileFn, env);

            return {
                persisted: true,
                storage: "managed",
                backend: config.backend,
                storePath: selectedPath,
                bootstrapped: bootstrap.bootstrapped,
                bootstrapBackupPending: document.metadata.bootstrap_backup_pending === true,
            };
        },
    ));
}

export async function listManagedSecretNames(options = {}) {
    const {
        env = process.env,
        platform = process.platform,
        runtimeMode,
        execFileFn = spawn,
        storePath,
    } = options;

    const config = resolveManagedStoreConfig(env, platform, { runtimeMode });
    const selectedPath = storePath?.trim() || config.storePath;
    assertSupportedBackend(config.backend);

    await ensureSopsAvailable(execFileFn);
    if (!(await fileExists(selectedPath))) {
        return {
            backend: config.backend,
            storePath: selectedPath,
            names: [],
        };
    }

    const document = await readEncryptedStoreWithEnv(selectedPath, execFileFn, env);
    const names = Object.keys(document.secrets ?? {}).sort((a, b) => a.localeCompare(b));

    return {
        backend: config.backend,
        storePath: selectedPath,
        names,
    };
}

export async function deleteManagedSecret(options = {}) {
    const {
        name,
        env = process.env,
        platform = process.platform,
        runtimeMode,
        execFileFn = spawn,
        now = new Date(),
        lockTimeoutMs = DEFAULT_LOCK_TIMEOUT_MS,
        lockRetryMs = DEFAULT_LOCK_RETRY_MS,
        pidCheckFn = defaultPidStatus,
        storePath,
    } = options;

    if (typeof name !== "string" || name.trim() === "") {
        throw new Error("Secret name is required for managed-store delete.");
    }

    const config = resolveManagedStoreConfig(env, platform, { runtimeMode });
    const selectedPath = storePath?.trim() || config.storePath;
    const trimmedName = name.trim();
    assertSupportedBackend(config.backend);

    if (!(await fileExists(selectedPath))) {
        return {
            deleted: false,
            reason: "store-missing",
            backend: config.backend,
            storePath: selectedPath,
            name: trimmedName,
        };
    }

    return enqueueStoreWrite(selectedPath, async () => withStoreWriteLock(
        selectedPath,
        {
            timeoutMs: lockTimeoutMs,
            retryMs: lockRetryMs,
            pidCheckFn,
        },
        async () => {
            await ensureSopsAvailable(execFileFn);
            const document = await readEncryptedStoreWithEnv(selectedPath, execFileFn, env);
            if (shouldAcknowledgeBackup(env)) {
                clearBootstrapBackupPendingFlag(document, now);
            }

            if (!Object.prototype.hasOwnProperty.call(document.secrets, trimmedName)) {
                return {
                    deleted: false,
                    reason: "not-found",
                    backend: config.backend,
                    storePath: selectedPath,
                    name: trimmedName,
                };
            }

            delete document.secrets[trimmedName];
            document.metadata.updated_at = now.toISOString();
            document.metadata.backend = config.backend;

            await writeEncryptedStoreWithEnv(selectedPath, document, execFileFn, env);

            return {
                deleted: true,
                backend: config.backend,
                storePath: selectedPath,
                name: trimmedName,
            };
        },
    ));
}
