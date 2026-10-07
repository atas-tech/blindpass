// Thin wrapper around the pinned release's `openclaw` CLI. The CLI is run with a minimal environment
// (never the operator's), pointed explicitly at the selected config directory, with its output parsed
// and reduced to a stable reason: CLI text is never echoed, since it is not ours to vouch for.
import { spawn } from "node:child_process";
import path from "node:path";
import { PreflightError } from "./errors.mjs";

const OUTPUT_LIMIT = 4 * 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 180000;

function nativeEnv(configDir) {
    const env = {
        PATH: process.env.PATH ?? "",
        HOME: process.env.HOME ?? "",
        OPENCLAW_STATE_DIR: configDir,
        OPENCLAW_CONFIG_PATH: path.join(configDir, "openclaw.json"),
    };
    for (const name of ["LANG", "LC_ALL", "TMPDIR", "TZ"]) {
        if (process.env[name]) {
            env[name] = process.env[name];
        }
    }
    return env;
}

function run(bin, args, { configDir, timeoutMs = DEFAULT_TIMEOUT_MS }) {
    return new Promise((resolve, reject) => {
        const child = spawn(bin, args, { env: nativeEnv(configDir), stdio: ["ignore", "pipe", "pipe"] });
        let stdout = "";
        let stderr = "";
        let tooMuch = false;
        const timer = setTimeout(() => child.kill("SIGKILL"), timeoutMs);
        const collect = (stream, assign) => stream.on("data", (chunk) => {
            if (stdout.length + stderr.length > OUTPUT_LIMIT) {
                tooMuch = true;
                child.kill("SIGKILL");
                return;
            }
            assign(String(chunk));
        });
        collect(child.stdout, (text) => { stdout += text; });
        collect(child.stderr, (text) => { stderr += text; });
        child.on("error", (error) => { clearTimeout(timer); reject(error); });
        child.on("close", (code, signal) => {
            clearTimeout(timer);
            resolve({ code, signal, stdout, stderr, tooMuch });
        });
    });
}

function redactAll(text, values) {
    let result = text;
    for (const value of values ?? []) {
        if (typeof value === "string" && value.length > 0) {
            result = result.split(value).join("[REDACTED]");
            const escaped = JSON.stringify(value).slice(1, -1);
            if (escaped !== value) {
                result = result.split(escaped).join("[REDACTED]");
            }
        }
    }
    return result;
}

function firstLine(text, redact) {
    return redactAll(text, redact).split("\n").find((line) => line.trim() !== "")?.trim().slice(0, 160) ?? "";
}

function parseJson(text) {
    try {
        return JSON.parse(text);
    } catch {
        return null;
    }
}

export async function assertSupportedNative(bin, { configDir, release }) {
    if (typeof bin !== "string" || !path.isAbsolute(bin)) {
        throw new PreflightError("native-version", "--openclaw-bin must be an absolute path to the openclaw executable");
    }
    let version;
    try {
        version = await run(bin, ["--version"], { configDir, timeoutMs: 30000 });
    } catch {
        throw new PreflightError("native-version", "the openclaw executable could not be run");
    }
    const found = /OpenClaw\s+(\d{4}\.\d+\.\d+)/.exec(version.stdout)?.[1];
    if (version.code !== 0 || found !== release) {
        throw new PreflightError("native-version", `expected OpenClaw ${release}, found ${found ?? "an unrecognised version"}`);
    }
    const located = await run(bin, ["config", "file"], { configDir, timeoutMs: 30000 });
    const home = process.env.HOME ?? "";
    const reported = located.stdout.trim().replace(/^~(?=\/)/, home);
    if (located.code !== 0 || reported !== path.join(configDir, "openclaw.json")) {
        throw new PreflightError("native-config-mismatch", "openclaw would operate on a different config file than the selected directory");
    }
}

export async function applyPlan(bin, planPath, { configDir, dryRun, allowExec, redact = [] }) {
    const args = ["secrets", "apply", "--from", planPath];
    if (dryRun) {
        args.push("--dry-run");
    }
    if (allowExec) {
        args.push("--allow-exec");
    }
    args.push("--json");
    const result = await run(bin, args, { configDir });
    if (result.code === 0) {
        const parsed = parseJson(result.stdout);
        if (parsed && typeof parsed === "object") {
            return parsed;
        }
        throw new PreflightError("native-apply-failed", "openclaw returned no JSON result");
    }
    const text = `${result.stdout}\n${result.stderr}`;
    if (/Invalid secrets plan file|Invalid plan target path/.test(text)) {
        throw new PreflightError("native-plan-rejected", "the installed OpenClaw rejected the plan");
    }
    if (/config is invalid/.test(text)) {
        throw new PreflightError("native-config-invalid", "the installed OpenClaw reports its current config as invalid");
    }
    throw new PreflightError(
        "native-apply-failed",
        `openclaw exited ${result.code ?? result.signal}${firstLine(text, redact) ? `: ${firstLine(text, redact)}` : ""}`,
    );
}

export async function nativeAudit(bin, { configDir, allowExec = false, redact = [] }) {
    const args = ["secrets", "audit", "--json"];
    if (allowExec) {
        args.push("--allow-exec");
    }
    const result = await run(bin, args, { configDir });
    const parsed = parseJson(result.stdout);
    if (!parsed || typeof parsed !== "object" || result.code > 1) {
        throw new PreflightError("native-audit-failed", firstLine(`${result.stdout}\n${result.stderr}`, redact));
    }
    return parsed;
}

// `secrets reload` closes its own connection when the gateway's auth changes and then reports
// ok:false (4001) even though the swap succeeded, so a failure here is "unverified", not "failed".
export async function nativeReload(bin, { configDir }) {
    const result = await run(bin, ["secrets", "reload", "--json"], { configDir, timeoutMs: 60000 });
    const parsed = parseJson(result.stdout);
    if (result.code === 0 && parsed?.ok === true) {
        return { state: "ok" };
    }
    if (/4001|gateway auth changed/i.test(`${result.stdout}\n${result.stderr}`)) {
        return { state: "unverified", detail: "the gateway closed the connection because its auth changed; verify by authenticated use" };
    }
    return { state: "failed", detail: firstLine(`${result.stdout}\n${result.stderr}`, []) };
}
