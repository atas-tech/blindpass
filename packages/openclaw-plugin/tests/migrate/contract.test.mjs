import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { classifySecretInput } from "../../src/migrate/classify.mjs";
import { parseDotenv } from "../../src/migrate/dotenv.mjs";
import {
    PINNED_RELEASES,
    enumerateConfigTargets,
    loadRegistry,
} from "../../src/migrate/registry.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES = path.join(HERE, "fixtures", "openclaw-2026.8.35");
const fixture = (name) => readFileSync(path.join(FIXTURES, name), "utf8");
const fixtureJson = (name) => JSON.parse(fixture(name));

test("P09.1 registry is pinned to one reviewed OpenClaw release and its vendored matrix", () => {
    assert.deepEqual(PINNED_RELEASES, ["2026.8.35"]);
    const registry = loadRegistry("2026.8.35");
    assert.equal(registry.release, "2026.8.35");
    assert.equal(registry.configTargets.length, 112);
    assert.equal(registry.sqliteAuthProfileSurfaces.length, 2);
    const raw = readFileSync(
        path.join(HERE, "..", "..", "src", "migrate", "registry", "openclaw-2026.8.35.credential-matrix.json"),
    );
    assert.equal(
        createHash("sha256").update(raw).digest("hex"),
        "0c07989dca9dc4dce46e12daecb7af8246da9c41ec64d326facd53109e548921",
    );
});

test("P09.1 registry refuses releases that were not reviewed", () => {
    for (const release of ["2026.9.8", "2026.8.34", "", undefined, "latest"]) {
        assert.throws(() => loadRegistry(release), /unsupported OpenClaw release/i, String(release));
    }
});

test("P09.1 enumerates concrete targets from the real 2026.8.35 config", () => {
    const registry = loadRegistry("2026.8.35");
    const { targets, problems } = enumerateConfigTargets(fixtureJson("real-apply.before.json"), registry);
    assert.deepEqual(problems, []);
    assert.deepEqual(
        targets.map((t) => [t.registryId, t.path]).sort(),
        [
            ["channels.telegram.botToken", "channels.telegram.botToken"],
            ["gateway.auth.token", "gateway.auth.token"],
            ["models.providers.*.apiKey", "models.providers.mockai.apiKey"],
            ["skills.entries.*.apiKey", "skills.entries.demo.apiKey"],
        ],
    );
    const provider = targets.find((t) => t.path === "models.providers.mockai.apiKey");
    assert.deepEqual(provider.segments, ["models", "providers", "mockai", "apiKey"]);
});

test("P09.1 expands every wildcard level and keeps deterministic order", () => {
    const registry = loadRegistry("2026.8.35");
    const config = {
        channels: { telegram: { accounts: { zed: { botToken: "a" }, alpha: { botToken: "b", webhookSecret: "c" } } } },
        models: { providers: { p2: { apiKey: "d", headers: { "x-key": "e" } }, p1: { apiKey: "f" } } },
    };
    const { targets } = enumerateConfigTargets(config, registry);
    assert.deepEqual(
        targets.map((t) => t.path),
        [
            "channels.telegram.accounts.alpha.botToken",
            "channels.telegram.accounts.alpha.webhookSecret",
            "channels.telegram.accounts.zed.botToken",
            "models.providers.p1.apiKey",
            "models.providers.p2.apiKey",
            "models.providers.p2.headers.x-key",
        ],
    );
});

test("P09.1 ignores absent paths and non-object intermediates", () => {
    const registry = loadRegistry("2026.8.35");
    const { targets, problems } = enumerateConfigTargets(
        { gateway: "not-an-object", models: { providers: ["array"] }, skills: null },
        registry,
    );
    assert.deepEqual(targets, []);
    assert.deepEqual(problems, []);
});

test("P09.1 reports ambiguous or forbidden path segments instead of targeting them", () => {
    const registry = loadRegistry("2026.8.35");
    const config = JSON.parse(
        '{"models":{"providers":{"a.b":{"apiKey":"x"},"":{"apiKey":"y"},"__proto__":{"apiKey":"z"},"constructor":{"apiKey":"w"},"ok":{"apiKey":"v"}}}}',
    );
    const { targets, problems } = enumerateConfigTargets(config, registry);
    assert.deepEqual(targets.map((t) => t.path), ["models.providers.ok.apiKey"]);
    assert.deepEqual(
        problems.map((p) => p.reason).sort(),
        ["ambiguous-path-segment", "ambiguous-path-segment", "forbidden-path-segment", "forbidden-path-segment"],
    );
    for (const problem of problems) {
        assert.ok(!JSON.stringify(problem).match(/"(x|y|z|w)"/), "problems must not echo values");
    }
});

test("P09.1 classifies every secret-input form without exposing the value", () => {
    const cases = [
        ["P09-CANARY-plain-0001", "plaintext"],
        ["  P09-CANARY-padded  ", "plaintext"],
        ["-----BEGIN PRIVATE KEY-----\nP09-CANARY\n-----END PRIVATE KEY-----\n", "plaintext"],
        ["", "empty"],
        ["   \n", "empty"],
        ["${OPENAI_API_KEY}", "env-shorthand"],
        ["$OPENAI_API_KEY", "env-shorthand"],
        ["secretref-env:OPENAI_API_KEY", "legacy-marker"],
        ["__OPENCLAW_REDACTED__", "reserved-marker"],
        ["oc-sent-v2.abc.end", "reserved-marker"],
        [{ source: "env", provider: "default", id: "OPENAI_API_KEY" }, "secretref"],
        [{ source: "file", provider: "filemain", id: "/providers/openai/apiKey" }, "secretref"],
        [{ source: "exec", provider: "blindpass", id: "a.b" }, "secretref"],
        [{ source: "store", provider: "default", id: "OPENAI_API_KEY" }, "secretref"],
        [{ source: "exec", provider: "blindpass" }, "unsupported"],
        [{ source: "vault", provider: "x", id: "y" }, "unsupported"],
        [{ type: "service_account", private_key: "P09-CANARY-sa" }, "unsupported"],
        [["P09-CANARY-array"], "unsupported"],
        [12345, "unsupported"],
        [true, "unsupported"],
        [null, "unsupported"],
    ];
    for (const [value, kind] of cases) {
        const result = classifySecretInput(value);
        assert.equal(result.kind, kind, JSON.stringify(value));
        assert.ok(!JSON.stringify(result).includes("P09-CANARY"), "classification must never echo values");
    }
    assert.equal(classifySecretInput({ type: "x" }).reason, "structured-value");
    assert.equal(classifySecretInput(12345).reason, "non-string-value");
    assert.equal(classifySecretInput({ source: "exec", provider: "blindpass" }).reason, "malformed-secretref");
});

test("P09.1 recognises an already-migrated real config as references only", () => {
    const registry = loadRegistry("2026.8.35");
    const config = fixtureJson("real-apply.after.json");
    const { targets } = enumerateConfigTargets(config, registry);
    assert.equal(targets.length, 4);
    assert.ok(targets.every((t) => classifySecretInput(t.value).kind === "secretref"));
    assert.equal(config.secrets.providers.blindpass.source, "exec");
});

// OpenClaw reads .env with dotenv 17.4.2 (installed under the pinned release), so these cases
// pin dotenv's actual semantics: unquoted values end at any "#", only \n and \r are expanded in
// double quotes (a backslash before a quote stays), backticks quote, and nothing is expanded.
test("P09.1 dotenv: supported syntax follows dotenv 17.4.2", () => {
    const parsed = parseDotenv(
        "﻿# leading comment\r\nA=plain\r\n\r\nexport B = spaced value  \nC='single $HOME'\nD=\"double\\nline \\\"q\\\"\"\n" +
            "E=value # trailing\nF=has#hash\nG=\"-----BEGIN KEY-----\nline2\n-----END KEY-----\"\nH=\n",
    );
    assert.deepEqual(parsed.problems, []);
    const byKey = Object.fromEntries(parsed.entries.map((e) => [e.key, e]));
    assert.equal(byKey.A.value, "plain");
    assert.equal(byKey.B.value, "spaced value");
    assert.equal(byKey.C.value, "single $HOME");
    assert.equal(byKey.D.value, 'double\nline \\"q\\"');
    assert.equal(byKey.E.value, "value");
    assert.equal(byKey.F.value, "has");
    assert.equal(byKey.G.value, "-----BEGIN KEY-----\nline2\n-----END KEY-----");
    assert.equal(byKey.G.multiline, true);
    assert.equal(byKey.H.value, "");
    assert.deepEqual(parsed.entries.map((e) => e.line), [2, 4, 5, 6, 7, 8, 9, 12]);
});

test("P09.1 dotenv: never expands or executes, and reports lines dotenv would not read", () => {
    const parsed = parseDotenv(
        "OK=1\nHOME_REF=$HOME\nCMD=$(touch /tmp/p09-should-not-run)\nTICK=`id`\nBAD LINE\nUNTERMINATED=\"abc\n",
    );
    const byKey = Object.fromEntries(parsed.entries.map((e) => [e.key, e]));
    assert.equal(byKey.HOME_REF.value, "$HOME");
    assert.equal(byKey.CMD.value, "$(touch /tmp/p09-should-not-run)");
    assert.equal(byKey.TICK.value, "id");
    assert.equal(byKey.UNTERMINATED.value, '"abc');
    assert.deepEqual(
        parsed.problems.map((p) => [p.line, p.reason]),
        [[5, "unparsed-line"], [6, "unbalanced-quote"]],
    );
    for (const problem of parsed.problems) {
        assert.deepEqual(Object.keys(problem).sort(), ["line", "reason"], "problems carry no content");
    }
});

test("P09.1 dotenv: duplicate keys are flagged and the last assignment wins", () => {
    const parsed = parseDotenv("K=first\nK=second\n");
    assert.equal(parsed.entries.length, 2);
    assert.deepEqual(parsed.duplicates, ["K"]);
    assert.equal(parsed.effective.get("K"), "second");
});

test("P09.1 dotenv: the real 2026.8.35 fixture parses to the documented entries", () => {
    const parsed = parseDotenv(fixture("plaintext.env"));
    assert.deepEqual(parsed.problems, []);
    assert.deepEqual(parsed.entries.map((e) => e.key), ["OPENAI_API_KEY", "TELEGRAM_BOT_TOKEN", "LOG_LEVEL"]);
});
