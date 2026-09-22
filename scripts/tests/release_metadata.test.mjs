import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = path.resolve(TEST_DIR, "..", "..");
const SKILL_PATH = path.join(ROOT_DIR, "packages", "openclaw-plugin", "skills", "blindpass", "SKILL.md");
const PLUGIN_MANIFEST_PATH = path.join(ROOT_DIR, "packages", "openclaw-plugin", "openclaw.plugin.json");
const PUBLISH_DIST_SCRIPT = path.join(ROOT_DIR, "scripts", "publish_dist.sh");
const DIST_DIR = path.join(ROOT_DIR, "packages", "openclaw-plugin", "dist");

function parseSkillFrontmatter(content) {
    const match = content.match(/^---\n([\s\S]*?)\n---\n/);
    if (!match) {
        throw new Error("SKILL.md is missing YAML frontmatter.");
    }

    const frontmatter = match[1];
    const versionMatch = frontmatter.match(/^version:\s*"?([^"\n]+)"?\s*$/m);
    const metadataMatch = frontmatter.match(/^metadata:\s*(\{.+\})\s*$/m);

    if (!versionMatch) {
        throw new Error("SKILL.md frontmatter is missing version.");
    }
    if (!metadataMatch) {
        throw new Error("SKILL.md frontmatter is missing metadata.");
    }

    return {
        version: versionMatch[1].trim(),
        metadata: JSON.parse(metadataMatch[1]),
    };
}

async function runCommand(command, args, options = {}) {
    const { cwd = ROOT_DIR } = options;
    return new Promise((resolve, reject) => {
        const child = spawn(command, args, {
            cwd,
            env: process.env,
            stdio: ["ignore", "pipe", "pipe"],
        });

        let stdout = "";
        let stderr = "";

        child.stdout.on("data", (chunk) => {
            stdout += chunk.toString("utf8");
        });
        child.stderr.on("data", (chunk) => {
            stderr += chunk.toString("utf8");
        });
        child.on("error", (err) => reject(err));
        child.on("close", (exitCode) => resolve({ exitCode, stdout, stderr }));
    });
}

async function ensureDistArtifacts() {
    const required = [
        "blindpass.mjs",
        "index.mjs",
        "mcp-server.mjs",
        "blindpass-resolver.mjs",
        "openclaw.plugin.json",
        "skills/blindpass/SKILL.md",
        "LICENSE",
    ];

    let hasAll = true;
    for (const rel of required) {
        try {
            await readFile(path.join(DIST_DIR, rel), "utf8");
        } catch {
            hasAll = false;
            break;
        }
    }

    if (hasAll) return;

    const build = await runCommand("npm", ["run", "build:skill"]);
    assert.equal(build.exitCode, 0, `build:skill failed:\n${build.stdout}\n${build.stderr}`);
}

async function testReleaseMetadataSyncAndStagedNpmContract() {
    const skillRaw = await readFile(SKILL_PATH, "utf8");
    const skill = parseSkillFrontmatter(skillRaw);
    const pluginManifest = JSON.parse(await readFile(PLUGIN_MANIFEST_PATH, "utf8"));

    assert.equal(skill.version, pluginManifest.version, "SKILL.md and openclaw.plugin.json versions must stay in sync");
    assert.deepEqual(
        skill.metadata?.openclaw?.requires?.bins ?? null,
        [],
        "SKILL.md should not force optional backend binaries in ClawHub metadata",
    );

    const stageDir = await mkdtemp(path.join(os.tmpdir(), "blindpass-stage-metadata-"));
    try {
        const stageResult = await runCommand("bash", [
            PUBLISH_DIST_SCRIPT,
            "--skip-build",
            "--skip-validate",
            "--stage-dir",
            stageDir,
        ]);
        assert.equal(stageResult.exitCode, 0, `publish_dist staging failed:\n${stageResult.stdout}\n${stageResult.stderr}`);

        const stagePackage = JSON.parse(await readFile(path.join(stageDir, "package.json"), "utf8"));
        const stagedManifest = JSON.parse(await readFile(path.join(stageDir, "openclaw.plugin.json"), "utf8"));
        const stagedSkill = parseSkillFrontmatter(await readFile(path.join(stageDir, "SKILL.md"), "utf8"));

        assert.equal(stagePackage.version, skill.version, "dist package.json version must match SKILL.md version");
        assert.equal(stagedManifest.version, skill.version, "staged openclaw.plugin.json version must match SKILL.md version");
        assert.equal(stagedSkill.version, skill.version, "staged SKILL.md version must match source SKILL.md version");

        assert.equal(stagePackage.name, "@blindpass/mcp-server");
        assert.deepEqual(stagePackage.bin, {
            "blindpass-mcp-server": "./dist/mcp-server.mjs",
            "blindpass-resolver": "./dist/blindpass-resolver.mjs",
        });

        const expectedFiles = [
            "dist",
            "SKILL.md",
            "AGENTS.md",
            "agents",
            "openclaw.plugin.json",
            "scripts",
            "LICENSE",
            "README.md",
        ];

        assert.deepEqual(stagePackage.files, expectedFiles, "dist package.json must list only the supported artifacts");
        await assert.rejects(readFile(path.join(stageDir, "CLAUDE.md")), { code: "ENOENT" });
    } finally {
        await rm(stageDir, { recursive: true, force: true });
    }
}

const tests = [
    {
        name: "release metadata stays synchronized and staged npm metadata exposes MCP entries",
        run: testReleaseMetadataSyncAndStagedNpmContract,
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
