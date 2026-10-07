// Shared guest-side helpers for the P09 real-runtime scenarios. Everything here runs inside the
// disposable guest against the real OpenClaw gateway, sops and age; credentials are generated dummies.
import { spawn, spawnSync } from "node:child_process";
import { closeSync, openSync } from "node:fs";
import { chmod, copyFile, mkdir, mkdtemp, readFile, readdir, rm, writeFile, lstat } from "node:fs/promises";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { makeCanary, leakWindows } from "../../../packages/openclaw-plugin/tests/migrate/helpers.mjs";

export { makeCanary, leakWindows };

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const PLUGIN_ROOT = path.resolve(HERE, "..", "..", "..", "packages", "openclaw-plugin");
export const MIGRATE_BIN = path.join(PLUGIN_ROOT, "bin", "blindpass-openclaw-migrate");
export const CRASH_RUNNER = path.join(PLUGIN_ROOT, "tests", "migrate", "crash-runner.mjs");
export const RELEASE = process.env.P09_RELEASE ?? "2026.8.35";

export function onPath(name) {
    for (const dir of (process.env.PATH ?? "").split(":")) {
        const candidate = path.join(dir, name);
        const probe = spawnSync("test", ["-x", candidate]);
        if (probe.status === 0) {
            return candidate;
        }
    }
    throw new Error(`${name} is not on PATH in the guest`);
}

export const OPENCLAW = onPath("openclaw");

export function evidence(id, fact) {
    // One line per proven fact, collected into the repository evidence record. Never a value.
    console.log(`P09-EVIDENCE ${id} ${fact}`);
}

async function freePort() {
    return new Promise((resolve, reject) => {
        const server = net.createServer();
        server.on("error", reject);
        server.listen(0, "127.0.0.1", () => {
            const { port } = server.address();
            server.close(() => resolve(port));
        });
    });
}

const cleanEnv = (extra = {}) => ({ PATH: process.env.PATH, HOME: process.env.HOME, ...extra });

export async function makeRig({ telegram = true, residue = true } = {}) {
    const root = await mkdtemp(path.join(os.homedir(), "p09-"));
    await chmod(root, 0o700);
    const dirs = { state: path.join(root, "state"), store: path.join(root, "store"), bin: path.join(root, "bin"), offline: path.join(root, "offline") };
    for (const dir of Object.values(dirs)) {
        await mkdir(dir, { mode: 0o700 });
    }
    const port = await freePort();
    const secrets = { gateway: makeCanary("GW"), model: makeCanary("MODEL"), skill: makeCanary("SKILL"), telegram: makeCanary("TG") };
    const config = {
        gateway: { port, auth: { mode: "token", token: secrets.gateway } },
        models: { providers: { mockai: { baseUrl: "http://127.0.0.1:9/v1", apiKey: secrets.model, api: "openai-completions", models: [{ id: "mock-1", name: "Mock 1" }] } } },
        skills: { entries: { demo: { apiKey: secrets.skill } } },
        ...(telegram ? { channels: { telegram: { botToken: secrets.telegram } } } : {}),
    };
    const original = Buffer.from(`${JSON.stringify(config, null, 2)}\n`);
    const configFile = path.join(dirs.state, "openclaw.json");
    await writeFile(configFile, original, { mode: 0o600 });
    if (residue) {
        await writeFile(path.join(dirs.state, ".env"), `OPENCLAW_GATEWAY_TOKEN=${secrets.gateway}\nLOG_LEVEL=info\n`, { mode: 0o600 });
    }
    const resolver = path.join(dirs.bin, "blindpass-resolver");
    await writeFile(resolver, `#!/usr/bin/env node\nimport { main } from ${JSON.stringify(path.join(PLUGIN_ROOT, "blindpass-resolver.mjs"))};\nawait main();\n`, { mode: 0o755 });
    await chmod(resolver, 0o755);
    const rig = {
        root, ...dirs, port, secrets, config, original, configFile, resolver,
        storePath: path.join(dirs.store, "secrets.enc.json"),
        keyBackup: path.join(dirs.offline, "key-backup.txt"),
        gatewayLogs: [],
        outputs: [],
        gateways: [],
    };
    return rig;
}

export async function destroyRig(rig) {
    for (const gateway of rig.gateways) {
        await gateway.stop().catch(() => { });
    }
    await rm(rig.root, { recursive: true, force: true });
}

export function migrate(rig, args) {
    const result = spawnSync(process.execPath, [MIGRATE_BIN, ...args], { encoding: "utf8", env: cleanEnv(), timeout: 600000 });
    const out = { code: result.status, signal: result.signal, stdout: result.stdout ?? "", stderr: result.stderr ?? "" };
    rig?.outputs.push(`${out.stdout}\n${out.stderr}`);
    return out;
}

export const applyArgs = (rig, ...extra) => [
    "--apply", "--config-dir", rig.state, "--store", rig.storePath,
    "--resolver-command", rig.resolver, "--openclaw-bin", OPENCLAW, ...extra,
];

export function initStore(rig) {
    return migrate(rig, ["--init-store", "--store", rig.storePath]);
}

export async function backupKey(rig) {
    await copyFile(path.join(rig.store, ".age-key.txt"), rig.keyBackup);
    await chmod(rig.keyBackup, 0o600);
}

export async function readyStore(rig) {
    const init = initStore(rig);
    if (init.code !== 0) {
        throw new Error(`--init-store failed (${init.code}): ${init.stderr.slice(0, 300)}`);
    }
    await backupKey(rig);
    const ack = migrate(rig, ["--ack-backup", rig.keyBackup, "--store", rig.storePath]);
    if (ack.code !== 0) {
        throw new Error(`--ack-backup failed (${ack.code}): ${ack.stderr.slice(0, 300)}`);
    }
}

export async function readJson(file) {
    return JSON.parse(await readFile(file, "utf8"));
}

export async function startGateway(rig) {
    const logPath = path.join(rig.root, `gateway-${rig.gateways.length + 1}.log`);
    const fd = openSync(logPath, "w", 0o600);
    const child = spawn(OPENCLAW, ["gateway", "run", "--port", String(rig.port), "--allow-unconfigured"], {
        env: cleanEnv({ OPENCLAW_STATE_DIR: rig.state, OPENCLAW_CONFIG_PATH: rig.configFile }),
        stdio: ["ignore", fd, fd],
    });
    closeSync(fd);
    let exited = null;
    child.on("exit", (code, signal) => { exited = { code, signal }; });
    const deadline = Date.now() + 120000;
    for (;;) {
        const text = await readFile(logPath, "utf8").catch(() => "");
        if (/\[gateway\] ready/.test(text)) {
            break;
        }
        if (exited || Date.now() > deadline) {
            child.kill("SIGKILL");
            throw new Error(`the gateway did not become ready (${exited ? `exited ${exited.code ?? exited.signal}` : "timeout"}); log tail: ${text.slice(-600).replace(/P09-CANARY-[A-Za-z0-9-]+/g, "<canary>")}`);
        }
        await new Promise((resolve) => setTimeout(resolve, 500));
    }
    const gateway = {
        logPath,
        async stop() {
            if (exited) {
                return;
            }
            child.kill("SIGTERM");
            await new Promise((resolve) => {
                const timer = setTimeout(() => { child.kill("SIGKILL"); }, 15000);
                child.on("exit", () => { clearTimeout(timer); resolve(); });
            });
        },
    };
    rig.gatewayLogs.push(logPath);
    rig.gateways.push(gateway);
    return gateway;
}

// Authenticated use: a real gateway RPC that only succeeds with the gateway's active token.
export function authed(rig, token) {
    const result = spawnSync(OPENCLAW, ["gateway", "call", "health", "--url", `ws://127.0.0.1:${rig.port}`, "--token", token, "--json"], {
        encoding: "utf8", env: cleanEnv(), timeout: 60000,
    });
    return result.status === 0;
}

export function nativeReload(rig, activeToken) {
    const result = spawnSync(OPENCLAW, ["secrets", "reload", "--url", `ws://127.0.0.1:${rig.port}`, "--token", activeToken, "--json"], {
        encoding: "utf8", env: cleanEnv({ OPENCLAW_STATE_DIR: rig.state, OPENCLAW_CONFIG_PATH: rig.configFile }), timeout: 120000,
    });
    return { code: result.status, text: `${result.stdout}\n${result.stderr}` };
}

// Rotates a store entry through the existing store API, as an operator would after activation.
export function rotateStoreSecret(rig, name, value) {
    const script = `import { storeManagedSecret } from ${JSON.stringify(path.join(PLUGIN_ROOT, "encrypted-store.mjs"))};
await storeManagedSecret({ name: ${JSON.stringify(name)}, value: ${JSON.stringify(value)}, storePath: ${JSON.stringify(rig.storePath)}, stderr: { write() {} } });`;
    const result = spawnSync(process.execPath, ["--input-type=module", "-e", script], { encoding: "utf8", env: cleanEnv(), timeout: 60000 });
    if (result.status !== 0) {
        throw new Error(`rotating ${name} failed: ${result.stderr.slice(0, 200)}`);
    }
}

export function assertNoWindows(assert, text, canaries, where) {
    for (const canary of canaries) {
        for (const window of leakWindows(canary)) {
            assert.ok(!text.includes(window), `${where} leaked part of a secret (${window.length} chars)`);
        }
    }
}

// Files under `roots` that contain a full canary (or its 12-character random part). The allowed
// locations hold plaintext by design: the protected backup, OpenClaw's own .bak files and the
// original config and .env.
export async function filesHolding(roots, canaries, { skip = () => false } = {}) {
    const needles = canaries.flatMap((canary) => [canary, canary.split("-").pop()]);
    const found = [];
    const walk = async (dir) => {
        let entries;
        try {
            entries = await readdir(dir, { withFileTypes: true });
        } catch {
            return;
        }
        for (const entry of entries) {
            const full = path.join(dir, entry.name);
            if (skip(full)) {
                continue;
            }
            if (entry.isDirectory()) {
                await walk(full);
            } else if (entry.isFile()) {
                const info = await lstat(full);
                if (info.size > 64 * 1024 * 1024) {
                    continue;
                }
                const bytes = await readFile(full).catch(() => null);
                if (bytes && needles.some((needle) => bytes.includes(needle))) {
                    found.push(full);
                }
            }
        }
    };
    for (const root of roots) {
        await walk(root);
    }
    return found.sort();
}

export async function waitForAuthed(rig, token, { timeoutMs = 90000 } = {}) {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
        if (authed(rig, token)) {
            return true;
        }
        if (Date.now() > deadline) {
            return false;
        }
        await new Promise((resolve) => setTimeout(resolve, 1000));
    }
}
