import { createHash, randomBytes } from "node:crypto";
import { mkdtemp, readFile, readdir, lstat, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

export const IS_LINUX = process.platform === "linux";

// Generated per call, so a leak in any output is attributable and nothing here looks like a real secret.
export function makeCanary(label) {
    return `P09-CANARY-${label}-${randomBytes(6).toString("hex")}`;
}

// The unique, random part of a canary, split into windows: disclosing any 6-character window of
// it (a prefix, suffix, fragment) counts as a leak, not just the whole value.
export function leakWindows(canary) {
    const unique = canary.split("-").pop();
    const windows = [canary];
    for (let i = 0; i + 6 <= unique.length; i += 1) {
        windows.push(unique.slice(i, i + 6));
    }
    return windows;
}

export function assertNoLeak(assert, haystack, canaries, where) {
    for (const canary of canaries) {
        for (const window of leakWindows(canary)) {
            assert.ok(!haystack.includes(window), `${where} leaked part of a secret (${window.length} chars)`);
        }
    }
}

export async function makeTempRoot(prefix = "p09-migrate-") {
    return mkdtemp(path.join(os.tmpdir(), prefix));
}

// Digest of every entry (type, mode, size, content hash, mtime) so tests can prove nothing changed.
export async function snapshotTree(root, { ignoreDirMtime = false } = {}) {
    const out = {};
    const walk = async (dir, rel) => {
        for (const name of (await readdir(dir)).sort()) {
            const full = path.join(dir, name);
            const info = await lstat(full);
            const key = path.posix.join(rel, name);
            if (info.isDirectory()) {
                out[key] = { type: "dir", mode: info.mode & 0o7777, ...(ignoreDirMtime ? {} : { mtimeMs: info.mtimeMs }) };
                await walk(full, key);
            } else if (info.isFile()) {
                out[key] = {
                    type: "file",
                    mode: info.mode & 0o7777,
                    size: info.size,
                    mtimeMs: info.mtimeMs,
                    sha256: createHash("sha256").update(await readFile(full)).digest("hex"),
                };
            } else {
                out[key] = { type: info.isSymbolicLink() ? "symlink" : "other" };
            }
        }
    };
    await walk(root, "");
    return out;
}

import { chmod, copyFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const FAKES_DIR = path.join(HERE, "fakes");
export const PLUGIN_ROOT = path.resolve(HERE, "..", "..");

// A private copy of the fake sops/age-keygen/age/openclaw with its settings in fakes.json beside
// the scripts. The native wrapper deliberately passes the openclaw CLI a minimal environment, so
// settings travel in a file, not in environment variables.
export async function makeToolbox(options = {}) {
    const dir = await mkdtemp(path.join(os.tmpdir(), "p09-toolbox-"));
    for (const name of ["sops", "age-keygen", "age", "openclaw"]) {
        await copyFile(path.join(FAKES_DIR, name), path.join(dir, name));
        await chmod(path.join(dir, name), 0o755);
    }
    await writeFile(path.join(dir, "fakes.json"), JSON.stringify({ pluginRoot: PLUGIN_ROOT, ...options }));
    return { dir, openclaw: path.join(dir, "openclaw"), configure: (next) => writeFile(path.join(dir, "fakes.json"), JSON.stringify({ pluginRoot: PLUGIN_ROOT, ...options, ...next })) };
}

// Runs fn with a fresh toolbox first on PATH (or `path` verbatim), restoring the environment after.
export async function withFakeTools(fn, options = {}) {
    const toolbox = await makeToolbox(options);
    const previous = process.env.PATH;
    process.env.PATH = options.path ?? `${toolbox.dir}:${previous}`;
    try {
        return await fn(toolbox);
    } finally {
        process.env.PATH = previous;
        await rm(toolbox.dir, { recursive: true, force: true });
    }
}

// A real executable resolver (absolute path, owned by us, mode 755) the way OpenClaw would run it.
export async function makeResolverCommand(dir) {
    const file = path.join(dir, "blindpass-resolver");
    await writeFile(
        file,
        `#!/usr/bin/env node\nimport { main } from ${JSON.stringify(path.join(PLUGIN_ROOT, "blindpass-resolver.mjs"))};\nawait main();\n`,
        { mode: 0o755 },
    );
    await chmod(file, 0o755);
    return file;
}

import { mkdir } from "node:fs/promises";
import { acknowledgeManagedStoreBackup } from "../../encrypted-store.mjs";
import { initStore } from "../../src/migrate/store.mjs";

export const RELEASE = "2026.8.35";
export const TARGET_PATHS = [
    "channels.telegram.botToken",
    "gateway.auth.token",
    "models.providers.mockai.apiKey",
    "skills.entries.demo.apiKey",
];

// A disposable OpenClaw-like installation: canonical-format openclaw.json holding four generated
// plaintext credentials, a .env and a generated models.json that repeat some of them, and an
// untouched store directory. Nothing here resembles a real credential.
export async function makeInstallation() {
    const base = await makeTempRoot();
    const configDir = path.join(base, "openclaw");
    const storeDir = path.join(base, "store");
    const binDir = path.join(base, "bin");
    for (const dir of [configDir, storeDir, binDir]) {
        await mkdir(dir, { mode: 0o700 });
    }
    const secrets = {
        gateway: makeCanary("GW"),
        model: makeCanary("MODEL"),
        skill: makeCanary("SKILL"),
        telegram: makeCanary("TG"),
    };
    const config = {
        gateway: { port: 18789, auth: { mode: "token", token: secrets.gateway } },
        models: { providers: { mockai: { baseUrl: "http://127.0.0.1:9/v1", apiKey: secrets.model } } },
        skills: { entries: { demo: { enabled: true, apiKey: secrets.skill } } },
        channels: { telegram: { enabled: true, botToken: secrets.telegram } },
        agents: { defaults: { model: "mockai/test" } },
        custom: { note: "operator-owned" },
    };
    const original = Buffer.from(`${JSON.stringify(config, null, 2)}\n`);
    await writeFile(path.join(configDir, "openclaw.json"), original, { mode: 0o600 });
    await writeFile(path.join(configDir, ".env"), `OPENCLAW_GATEWAY_TOKEN=${secrets.gateway}\nLOG_LEVEL=info\n`, { mode: 0o600 });
    await mkdir(path.join(configDir, "agents", "main", "agent"), { recursive: true, mode: 0o700 });
    await writeFile(path.join(configDir, "agents", "main", "agent", "models.json"), JSON.stringify({ providers: { mockai: { apiKey: secrets.model } } }), { mode: 0o600 });
    return {
        base,
        configDir,
        storeDir,
        storePath: path.join(storeDir, "secrets.enc.json"),
        resolver: await makeResolverCommand(binDir),
        secrets,
        config,
        original,
        log: path.join(base, "tool.log"),
        configFile: path.join(configDir, "openclaw.json"),
    };
}

const quietStream = { write() { } };

// Creates the store and key through the explicit init action, then clears the backup-pending flag
// the way an operator who has stored the key would.
export async function readyStore(installation, { acknowledge = true } = {}) {
    await initStore({ storePath: installation.storePath, stderr: quietStream });
    if (acknowledge) {
        await acknowledgeManagedStoreBackup({ env: { ...process.env, BLINDPASS_STORE_PATH: installation.storePath } });
    }
}

// Runs fn with a fresh installation, an acknowledged store, a toolbox on PATH and ready-made options.
export async function withInstallation(fn, { fake = {}, store = {} } = {}) {
    const installation = await makeInstallation();
    try {
        await withFakeTools(async (toolbox) => {
            await readyStore(installation, store);
            const options = {
                configDir: installation.configDir,
                release: RELEASE,
                providerAlias: "blindpass",
                resolverCommand: installation.resolver,
                storePath: installation.storePath,
                openclawBin: toolbox.openclaw,
            };
            await fn({ ...installation, toolbox, options });
        }, { log: installation.log, ...fake });
    } finally {
        await rm(installation.base, { recursive: true, force: true });
    }
}
