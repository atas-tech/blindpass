import assert from "node:assert/strict";
import { chmod, mkdir, rm, symlink, writeFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { IS_LINUX, assertNoLeak, makeCanary, makeTempRoot, snapshotTree } from "./helpers.mjs";
import { UnsafePathError } from "../../src/migrate/safe-fs.mjs";
import { renderPlanJson, renderPlanText, runDryRun } from "../../src/migrate/inventory.mjs";

const opts = { skip: !IS_LINUX && "Linux-only" };
const RELEASE = "2026.8.35";

async function makeConfigDir({ config, env, extra = {}, mode = 0o600 }) {
    const base = await makeTempRoot();
    const dir = path.join(base, "openclaw");
    await mkdir(dir, { mode: 0o700 });
    if (config !== undefined) {
        await writeFile(path.join(dir, "openclaw.json"), typeof config === "string" ? config : JSON.stringify(config, null, 2), { mode });
    }
    if (env !== undefined) {
        await writeFile(path.join(dir, ".env"), env, { mode });
    }
    for (const [name, content] of Object.entries(extra)) {
        await mkdir(path.dirname(path.join(dir, name)), { recursive: true, mode: 0o700 });
        await writeFile(path.join(dir, name), content, { mode });
    }
    return { base, dir };
}

function representative() {
    const c = {
        gateway: makeCanary("gw"),
        model: makeCanary("model"),
        skill: makeCanary("skill"),
        telegram: makeCanary("tg"),
        envOnly: makeCanary("envonly"),
        sa: makeCanary("sa"),
    };
    const config = {
        gateway: { auth: { mode: "token", token: c.gateway } },
        models: { providers: { mockai: { baseUrl: "http://127.0.0.1:18080/v1", apiKey: c.model } } },
        skills: { entries: { demo: { apiKey: c.skill }, other: { apiKey: "" } } },
        channels: {
            telegram: { botToken: c.telegram },
            slack: { botToken: { source: "env", provider: "default", id: "SLACK_BOT_TOKEN" } },
            discord: { token: "${DISCORD_TOKEN}" },
            googlechat: { serviceAccount: { type: "service_account", private_key: c.sa } },
            matrix: { accessToken: "secretref-env:MATRIX_TOKEN" },
        },
    };
    const env = `OPENAI_API_KEY=${c.envOnly}\nTELEGRAM_BOT_TOKEN=${c.telegram}\nLOG_LEVEL=debug\n`;
    return { c, config, env, canaries: Object.values(c) };
}

test("P09-I01 dry run classifies a representative installation", opts, async () => {
    const { c, config, env, canaries } = representative();
    const { base, dir } = await makeConfigDir({
        config,
        env,
        extra: { "openclaw.json.bak": JSON.stringify({ gateway: { auth: { token: c.gateway } } }), "state/openclaw.sqlite": "" },
    });
    try {
        const { plan } = await runDryRun({ configDir: dir, release: RELEASE });
        assert.equal(plan.version, 1);
        assert.equal(plan.mode, "dry-run");
        assert.equal(plan.release, RELEASE);
        const byPath = Object.fromEntries(plan.rows.map((row) => [`${row.file}:${row.keyPath}`, row]));

        for (const [key, id] of [
            ["gateway.auth.token", "openclaw.gateway.auth.token"],
            ["models.providers.mockai.apiKey", "openclaw.models.providers.mockai.apiKey"],
            ["skills.entries.demo.apiKey", "openclaw.skills.entries.demo.apiKey"],
            ["channels.telegram.botToken", "openclaw.channels.telegram.botToken"],
        ]) {
            const row = byPath[`openclaw.json:${key}`];
            assert.equal(row.status, "migratable", key);
            assert.equal(row.value, "[REDACTED]");
            assert.deepEqual(row.proposedRef, { source: "exec", provider: "blindpass", id });
        }
        assert.equal(byPath["openclaw.json:channels.slack.botToken"].status, "already-reference");
        assert.equal(byPath["openclaw.json:channels.discord.token"].status, "env-reference");
        assert.equal(byPath["openclaw.json:skills.entries.other.apiKey"].status, "empty");
        assert.deepEqual(
            [byPath["openclaw.json:channels.googlechat.serviceAccount"].status, byPath["openclaw.json:channels.googlechat.serviceAccount"].reason],
            ["unsupported", "structured-value"],
        );
        assert.deepEqual(
            [byPath["openclaw.json:channels.matrix.accessToken"].status, byPath["openclaw.json:channels.matrix.accessToken"].reason],
            ["unsupported", "legacy-marker"],
        );

        assert.equal(byPath[".env:$env.OPENAI_API_KEY"].status, "unsupported");
        assert.equal(byPath[".env:$env.OPENAI_API_KEY"].reason, "env-credential-has-no-structured-reference");
        assert.equal(byPath[".env:$env.TELEGRAM_BOT_TOKEN"].status, "residual");
        assert.equal(byPath[".env:$env.LOG_LEVEL"], undefined, "non-credential env names are counted, not listed");
        assert.equal(plan.summary.envNonCredential, 1);

        assert.deepEqual(plan.residual, [{ file: "openclaw.json.bak", reason: "holds-copy-of-migratable-value" }]);
        const sqlite = plan.rows.find((row) => row.file === "state/openclaw.sqlite");
        assert.deepEqual([sqlite.status, sqlite.reason], ["unsupported", "auth-profile-store-not-inspected"]);
        assert.deepEqual(
            plan.summary,
            { migratable: 4, alreadyReference: 1, envReference: 1, empty: 1, unsupported: 4, residual: 2, envNonCredential: 1 },
        );
        assert.ok(plan.rows.every((row) => !("length" in row) && !("size" in row) && !("prefix" in row) && !("suffix" in row)));

        const json = renderPlanJson(plan);
        const text = renderPlanText(plan);
        assertNoLeak(assert, json, canaries, "json");
        assertNoLeak(assert, text, canaries, "text");
        assert.equal(JSON.stringify(JSON.parse(json)), JSON.stringify(plan));
        assert.match(text, /\[REDACTED\]/);
    } finally {
        await rm(base, { recursive: true, force: true });
    }
});

test("P09-I01 dry run is deterministic and changes nothing", opts, async () => {
    const { config, env, c } = representative();
    const { base, dir } = await makeConfigDir({ config, env, extra: { "openclaw.json.bak": c.gateway } });
    try {
        const before = await snapshotTree(dir);
        const first = await runDryRun({ configDir: dir, release: RELEASE });
        const second = await runDryRun({ configDir: dir, release: RELEASE });
        assert.equal(renderPlanJson(first.plan), renderPlanJson(second.plan));
        assert.equal(renderPlanText(first.plan), renderPlanText(second.plan));
        assert.deepEqual(await snapshotTree(dir), before, "no file, lock, journal or temp file may be created or touched");
    } finally {
        await rm(base, { recursive: true, force: true });
    }
});

test("P09-I01 unsafe locations are refused, not skipped", opts, async () => {
    const { config } = representative();
    const { base, dir } = await makeConfigDir({ config });
    try {
        const outside = path.join(base, "outside.json");
        await writeFile(outside, JSON.stringify(config), { mode: 0o600 });
        await rm(path.join(dir, "openclaw.json"));
        await symlink(outside, path.join(dir, "openclaw.json"));
        await assert.rejects(runDryRun({ configDir: dir, release: RELEASE }), (e) => e instanceof UnsafePathError && e.reason === "symlink");

        await rm(path.join(dir, "openclaw.json"));
        await writeFile(path.join(dir, "openclaw.json"), JSON.stringify(config), { mode: 0o600 });
        await chmod(path.join(dir, "openclaw.json"), 0o666);
        await assert.rejects(runDryRun({ configDir: dir, release: RELEASE }), (e) => e instanceof UnsafePathError && e.reason === "unsafe-permissions");
        await chmod(path.join(dir, "openclaw.json"), 0o600);

        await symlink(outside, path.join(dir, ".env"));
        await assert.rejects(runDryRun({ configDir: dir, release: RELEASE }), (e) => e instanceof UnsafePathError && e.reason === "symlink");

        const aliasDir = path.join(base, "alias");
        await symlink(dir, aliasDir);
        await assert.rejects(runDryRun({ configDir: aliasDir, release: RELEASE }), (e) => e instanceof UnsafePathError && e.reason === "symlink");
    } finally {
        await rm(base, { recursive: true, force: true });
    }
});

test("P09-I01 unreadable, non-strict, oversize and malformed inputs degrade to unsupported without leaking", opts, async () => {
    const secret = makeCanary("json5");
    const cases = [
        ["not-strict-json", `{ // comment\n "gateway": { "auth": { "token": "${secret}" } } }`],
        ["not-strict-json", `{"gateway": {"auth": {"token": "${secret}",}}}`],
        ["not-an-object", `["${secret}"]`],
        ["too-large", `{"pad":"${"a".repeat(1024 * 1024)}","gateway":{"auth":{"token":"${secret}"}}}`],
    ];
    for (const [reason, content] of cases) {
        const { base, dir } = await makeConfigDir({ config: content });
        try {
            const { plan } = await runDryRun({ configDir: dir, release: RELEASE });
            const file = plan.files.find((f) => f.file === "openclaw.json");
            assert.deepEqual([file.state, file.reason], ["unsupported", reason]);
            assert.deepEqual(plan.rows, []);
            assertNoLeak(assert, renderPlanJson(plan) + renderPlanText(plan), [secret], reason);
        } finally {
            await rm(base, { recursive: true, force: true });
        }
    }
});

test("P09-I01 reports forbidden and ambiguous path segments and malformed references", opts, async () => {
    const config = JSON.parse(
        `{"models":{"providers":{"a.b":{"apiKey":"${makeCanary("dot")}"},"__proto__":{"apiKey":"${makeCanary("proto")}"},"ok":{"apiKey":{"source":"exec","provider":"blindpass"}}}}}`,
    );
    const { base, dir } = await makeConfigDir({ config: JSON.stringify(config) });
    try {
        const { plan } = await runDryRun({ configDir: dir, release: RELEASE });
        const reasons = plan.rows.map((row) => `${row.keyPath}=${row.reason}`).sort();
        assert.deepEqual(reasons, [
            "models.providers.__proto__.apiKey=forbidden-path-segment",
            "models.providers.a.b.apiKey=ambiguous-path-segment",
            "models.providers.ok.apiKey=malformed-secretref",
        ]);
        assert.ok(plan.rows.every((row) => row.status === "unsupported" && row.proposedRef === null));
    } finally {
        await rm(base, { recursive: true, force: true });
    }
});

test("P09-I01 proposed store names are unique, valid resolver ids and stable", opts, async () => {
    const config = {
        models: { providers: { "a/b": { apiKey: makeCanary("p1") }, a_b: { apiKey: makeCanary("p2") }, [`x${"y".repeat(150)}`]: { apiKey: makeCanary("p3") } } },
    };
    const { base, dir } = await makeConfigDir({ config });
    try {
        const { plan } = await runDryRun({ configDir: dir, release: RELEASE });
        const ids = plan.rows.map((row) => row.proposedRef.id);
        assert.equal(new Set(ids).size, 3);
        for (const id of ids) {
            assert.match(id, /^[A-Za-z0-9._-]{1,128}$/);
        }
        const again = await runDryRun({ configDir: dir, release: RELEASE });
        assert.deepEqual(again.plan.rows.map((row) => row.proposedRef.id), ids);
    } finally {
        await rm(base, { recursive: true, force: true });
    }
});

test("P09-I01 warnings: short values, other release, bad dotenv lines, stale journal, absent files", opts, async () => {
    const { base, dir } = await makeConfigDir({
        config: { meta: { lastTouchedVersion: "2026.9.8" }, gateway: { auth: { token: "abc1234" } } },
        env: "OK=1\nBAD LINE\n",
        extra: { ".blindpass-migrate.journal.json": "{}" },
    });
    try {
        const { plan } = await runDryRun({ configDir: dir, release: RELEASE });
        const joined = plan.warnings.join("\n");
        assert.match(joined, /short-value-not-scanned/);
        assert.match(joined, /config-last-touched-by-other-release: 2026\.9\.8/);
        assert.match(joined, /dotenv-line-ignored: line 2 \(unparsed-line\)/);
        assert.match(joined, /unfinished-migration-journal/);
        assert.ok(!joined.includes("abc1234"), "warnings must not echo values");
    } finally {
        await rm(base, { recursive: true, force: true });
    }

    const empty = await makeConfigDir({});
    try {
        const { plan } = await runDryRun({ configDir: empty.dir, release: RELEASE });
        assert.equal(plan.files.find((f) => f.file === "openclaw.json").state, "absent");
        assert.deepEqual(plan.rows, []);
        assert.match(plan.warnings.join("\n"), /openclaw\.json-absent/);
    } finally {
        await rm(empty.base, { recursive: true, force: true });
    }
});

test("P09-I01 refuses an unreviewed release", opts, async () => {
    const { base, dir } = await makeConfigDir({ config: {} });
    try {
        await assert.rejects(runDryRun({ configDir: dir, release: "2026.9.8" }), /Unsupported OpenClaw release/);
    } finally {
        await rm(base, { recursive: true, force: true });
    }
});

test("P09-I01 a residual file too large to search is reported as skipped, never as clean", opts, async () => {
    const secret = makeCanary("big");
    const { base, dir } = await makeConfigDir({
        config: { gateway: { auth: { mode: "token", token: secret } } },
        // Over the 1 MiB bound: the canary sits at the very end where a partial read would miss it.
        extra: { "openclaw.json.bak": `${"x".repeat(1024 * 1024 + 16)}${secret}` },
    });
    try {
        const { plan } = await runDryRun({ configDir: dir, release: RELEASE });
        assert.ok(plan.warnings.includes("residual-scan-skipped: openclaw.json.bak (too-large)"), plan.warnings.join("|"));
        assert.deepEqual(plan.residual, []);
        assertNoLeak(assert, renderPlanJson(plan) + renderPlanText(plan), [secret], "plan");
    } finally {
        await rm(base, { recursive: true, force: true });
    }
});
