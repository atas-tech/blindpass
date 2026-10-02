import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { access, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = path.resolve(TEST_DIR, "..", "..");
const INSTALL_SCRIPT_PATH = path.join(ROOT_DIR, "scripts", "install_skill.sh");
const DIST_DIR = path.join(ROOT_DIR, "packages", "openclaw-plugin", "dist");

const REQUIRED_DIST_ARTIFACTS = [
    "blindpass.mjs",
    "index.mjs",
    "mcp-server.mjs",
    "blindpass-resolver.mjs",
    "openclaw.plugin.json",
    "skills/blindpass/SKILL.md",
    "LICENSE",
];

async function pathExists(targetPath) {
    try {
        await access(targetPath);
        return true;
    } catch {
        return false;
    }
}

async function runCommand(command, args, options = {}) {
    const {
        cwd = ROOT_DIR,
        env = {},
        stdin = "",
    } = options;

    return new Promise((resolve, reject) => {
        const child = spawn(command, args, {
            cwd,
            env: {
                ...process.env,
                ...env,
            },
            stdio: ["pipe", "pipe", "pipe"],
        });

        let stdout = "";
        let stderr = "";

        child.stdout.on("data", (chunk) => {
            stdout += chunk.toString("utf8");
        });
        child.stderr.on("data", (chunk) => {
            stderr += chunk.toString("utf8");
        });
        child.on("error", (err) => {
            reject(err);
        });
        child.on("close", (exitCode) => {
            resolve({ exitCode, stdout, stderr });
        });

        child.stdin.end(stdin);
    });
}

async function ensureDistArtifacts() {
    let missing = false;
    for (const artifact of REQUIRED_DIST_ARTIFACTS) {
        if (!await pathExists(path.join(DIST_DIR, artifact))) {
            missing = true;
            break;
        }
    }

    if (!missing) {
        return;
    }

    const buildResult = await runCommand("npm", ["run", "build:skill"]);
    assert.equal(buildResult.exitCode, 0, `build:skill failed:\n${buildResult.stdout}\n${buildResult.stderr}`);
}

function installRoot(homeDir, agent) {
    switch (agent) {
        case "codex":
            return path.join(homeDir, ".codex", "skills", "blindpass");
        case "claude":
            return path.join(homeDir, ".claude", "skills", "blindpass");
        case "antigravity":
            return path.join(homeDir, ".gemini", "skills", "blindpass");
        case "openclaw":
            return path.join(homeDir, ".openclaw", "skills", "blindpass");
        default:
            throw new Error(`Unknown agent: ${agent}`);
    }
}

async function assertInstallLayout(rootPath) {
    assert.equal(await pathExists(path.join(rootPath, "dist", "mcp-server.mjs")), true);
    assert.equal(await pathExists(path.join(rootPath, "dist", "THIRD_PARTY_NOTICES.md")), true);
    for (const name of ['modelcontextprotocol-server-LICENSE', 'modelcontextprotocol-core-LICENSE', 'zod-LICENSE']) {
        assert.equal(await pathExists(path.join(rootPath, 'dist', 'licenses', name)), true);
    }
    assert.equal(await pathExists(path.join(rootPath, "dist", "blindpass-resolver.mjs")), true);
    assert.equal(await pathExists(path.join(rootPath, "dist", "blindpass.mjs")), true);
    assert.equal(await pathExists(path.join(rootPath, "openclaw.plugin.json")), true);
    assert.equal(await pathExists(path.join(rootPath, "SKILL.md")), true);
    assert.equal(await pathExists(path.join(rootPath, "scripts", "install_skill.sh")), true);
}

async function testGlobalInstallForAgent(agent) {
    const tempHome = await mkdtemp(path.join(os.tmpdir(), `blindpass-install-${agent}-`));
    try {
        const result = await runCommand("bash", [
            INSTALL_SCRIPT_PATH,
            "--mode", "global",
            "--agent", agent,
            "--skip-build",
            "--yes",
        ], {
            env: { HOME: tempHome },
        });
        assert.equal(result.exitCode, 0, `install script failed for ${agent}:\n${result.stdout}\n${result.stderr}`);
        await assertInstallLayout(installRoot(tempHome, agent));
    } finally {
        await rm(tempHome, { recursive: true, force: true });
    }
}

async function testAllModePreservesUnrelatedConfigAndCreatesBackups() {
    const tempHome = await mkdtemp(path.join(os.tmpdir(), "blindpass-install-all-"));
    const existingInstall = installRoot(tempHome, "codex");
    const unrelatedConfig = path.join(tempHome, ".codex", "config.json");

    try {
        await mkdir(existingInstall, { recursive: true });
        await writeFile(path.join(existingInstall, "legacy.txt"), "legacy", "utf8");
        await mkdir(path.dirname(unrelatedConfig), { recursive: true });
        await writeFile(unrelatedConfig, "{\"theme\":\"dark\"}\n", "utf8");

        const result = await runCommand("bash", [
            INSTALL_SCRIPT_PATH,
            "--mode", "global",
            "--agent", "all",
            "--skip-build",
            "--yes",
        ], {
            env: { HOME: tempHome },
        });
        assert.equal(result.exitCode, 0, `install script failed in --agent all mode:\n${result.stdout}\n${result.stderr}`);

        const codexParent = path.dirname(existingInstall);
        const siblingEntries = await readdir(codexParent);
        const backupEntry = siblingEntries.find((entry) => entry.startsWith("blindpass.backup-"));
        assert.ok(backupEntry, "existing install should be backed up before replacement");
        assert.equal(await readFile(unrelatedConfig, "utf8"), "{\"theme\":\"dark\"}\n");

        await assertInstallLayout(installRoot(tempHome, "codex"));
        await assertInstallLayout(installRoot(tempHome, "claude"));
        await assertInstallLayout(installRoot(tempHome, "antigravity"));
        await assertInstallLayout(installRoot(tempHome, "openclaw"));
    } finally {
        await rm(tempHome, { recursive: true, force: true });
    }
}

async function testExistingInstallNeedsConfirmationWithoutYesFlag() {
    const tempHome = await mkdtemp(path.join(os.tmpdir(), "blindpass-install-confirm-"));
    const existingInstall = installRoot(tempHome, "codex");

    try {
        await mkdir(existingInstall, { recursive: true });
        await writeFile(path.join(existingInstall, "legacy.txt"), "legacy", "utf8");

        const result = await runCommand("bash", [
            INSTALL_SCRIPT_PATH,
            "--mode", "global",
            "--agent", "codex",
            "--skip-build",
        ], {
            env: { HOME: tempHome },
            stdin: "n\n",
        });
        assert.equal(result.exitCode, 0);
        assert.match(result.stderr, /already exists\. Backup and replace\? \[y\/N\]:/);
        assert.match(result.stdout, /\[blindpass\] skipped codex/);
        assert.equal(await readFile(path.join(existingInstall, "legacy.txt"), "utf8"), "legacy");
    } finally {
        await rm(tempHome, { recursive: true, force: true });
    }
}

const tests = [
    {
        name: "global install works for codex",
        run: () => testGlobalInstallForAgent("codex"),
    },
    {
        name: "global install works for claude",
        run: () => testGlobalInstallForAgent("claude"),
    },
    {
        name: "global install works for antigravity",
        run: () => testGlobalInstallForAgent("antigravity"),
    },
    {
        name: "global --agent all preserves unrelated config and creates backups when replacing existing installs",
        run: testAllModePreservesUnrelatedConfigAndCreatesBackups,
    },
    {
        name: "existing install requires confirmation when --yes is not provided",
        run: testExistingInstallNeedsConfirmationWithoutYesFlag,
    },
];

let failures = 0;

await ensureDistArtifacts();

for (const test of tests) {
    try {
        await test.run();
        console.log(`ok - ${test.name}`);
    } catch (err) {
        failures += 1;
        console.error(`not ok - ${test.name}`);
        console.error(err);
    }
}

if (failures > 0) {
    process.exitCode = 1;
}
