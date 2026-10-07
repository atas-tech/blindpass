// P07 F-3 (owner decision 2026-10-07): the PUBLISHED bundle has no default SPS endpoint.
//
// esbuild replaces the free identifier __BLINDPASS_REQUIRE_EXPLICIT_SPS__ in the bundle build only. These tests
// set it as a global to exercise the explicit mode in the unbundled source, and leave it unset for the legacy
// mode, which must behave exactly as before (the OpenClaw plugin keeps its default).
import assert from "node:assert/strict";
import { test } from "node:test";
import register from "../index.mjs";
import {
    SpsBaseUrlRequiredError,
    fulfillExchangeFlow,
    requestExchangeFlow,
    requestSecretFlow,
    resolveSpsBaseUrl,
} from "../sps-bridge.mjs";

const FLAG = "__BLINDPASS_REQUIRE_EXPLICIT_SPS__";
const LEGACY_DEFAULT = "https://sps.blindpass.dev";

async function withExplicitMode(fn) {
    globalThis[FLAG] = true;
    try {
        return await fn();
    } finally {
        delete globalThis[FLAG];
    }
}

async function withEnv(overrides, fn) {
    const original = new Map();
    for (const [key, value] of Object.entries(overrides)) {
        original.set(key, process.env[key]);
        if (value == null) delete process.env[key];
        else process.env[key] = String(value);
    }
    try {
        return await fn();
    } finally {
        for (const [key, value] of original) {
            if (value == null) delete process.env[key];
            else process.env[key] = value;
        }
    }
}

// Any outbound request attempt is recorded and refused, so a flow that gets past the endpoint check cannot reach a host.
async function withOutboundGuard(fn) {
    const attempts = [];
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async (url) => {
        attempts.push(String(url));
        throw new Error("outbound request blocked by the test");
    };
    try {
        await fn(attempts);
    } finally {
        globalThis.fetch = originalFetch;
    }
}

function mockApi() {
    const tools = new Map();
    return { tools, registerTool: (tool) => tools.set(tool.name, tool), registerHook() {} };
}

test("legacy mode (flag absent): the helper returns the configured value, else the legacy default", () => {
    assert.equal(resolveSpsBaseUrl({}), LEGACY_DEFAULT);
    assert.equal(resolveSpsBaseUrl({ SPS_BASE_URL: "https://spss.example" }), "https://spss.example");
    // `??` semantics, unchanged: an empty value is a value.
    assert.equal(resolveSpsBaseUrl({ SPS_BASE_URL: "" }), "");
    assert.equal(resolveSpsBaseUrl(), process.env.SPS_BASE_URL ?? LEGACY_DEFAULT);
});

test("explicit mode: an unset, empty or blank value is refused with an error that names SPS_BASE_URL", async () => {
    await withExplicitMode(() => {
        for (const env of [{}, { SPS_BASE_URL: "" }, { SPS_BASE_URL: "   " }, { SPS_BASE_URL: undefined }]) {
            assert.throws(() => resolveSpsBaseUrl(env), (error) => {
                assert.ok(error instanceof SpsBaseUrlRequiredError);
                assert.match(error.message, /SPS_BASE_URL/);
                assert.ok(!error.message.includes(LEGACY_DEFAULT), "the message must not point at a public host");
                return true;
            });
        }
        assert.equal(resolveSpsBaseUrl({ SPS_BASE_URL: "https://spss.example" }), "https://spss.example");
        assert.equal(resolveSpsBaseUrl({ SPS_BASE_URL: "  https://spss.example  " }), "https://spss.example");
    });
});

test("explicit mode: the three SPS flows refuse before any network request or key use", async () => {
    await withExplicitMode(() => withEnv({ SPS_BASE_URL: undefined, BLINDPASS_API_KEY: "ak_dummy_generated_key" }, async () => {
        await withOutboundGuard(async (attempts) => {
            await assert.rejects(requestSecretFlow({ description: "d", onSecretLink: async () => {} }), SpsBaseUrlRequiredError);
            await assert.rejects(fulfillExchangeFlow({ fulfillmentToken: "t", resolveSecret: async () => Buffer.from("x") }), SpsBaseUrlRequiredError);
            await assert.rejects(requestExchangeFlow({ secretName: "n", purpose: "p", fulfillerId: "f", transport: {} }), SpsBaseUrlRequiredError);
            assert.deepEqual(attempts, [], "no request may be made without an explicit endpoint");
        });
    }));
});

test("explicit mode: an explicit endpoint is used as given by the flows", async () => {
    await withExplicitMode(() => withEnv({ SPS_BASE_URL: "http://127.0.0.1:9", BLINDPASS_API_KEY: "ak_dummy_generated_key" }, async () => {
        await withOutboundGuard(async (attempts) => {
            await assert.rejects(requestSecretFlow({ description: "d", onSecretLink: async () => {} }), /outbound request blocked/);
            assert.ok(attempts.length >= 1 && attempts.every((url) => url.startsWith("http://127.0.0.1:9/")), `unexpected targets: ${attempts}`);
        });
    }));
});

test("explicit mode: request_secret, request_secret_exchange and fulfill_secret_exchange answer with a clear refusal and send nothing", async () => {
    await withExplicitMode(() => withEnv({ SPS_BASE_URL: undefined, BLINDPASS_API_KEY: "ak_dummy_generated_key" }, async () => {
        await withOutboundGuard(async (attempts) => {
            const api = mockApi();
            register(api, {});
            const calls = [
                ["request_secret", { description: "AWS deploy token", secret_name: "aws_token" }],
                ["request_secret_exchange", { secret_name: "stripe.key", purpose: "charge", fulfiller_id: "agent:pay" }],
                ["fulfill_secret_exchange", { fulfillment_token: "tok" }],
            ];
            for (const [name, params] of calls) {
                const tool = api.tools.get(name);
                assert.ok(tool, `${name} must be registered`);
                const result = await tool.execute("id", params, { sendText: async () => {} });
                const text = result?.content?.[0]?.text ?? "";
                assert.match(text, /SPS_BASE_URL/, `${name} must name the missing setting`);
                assert.match(text, /^Error:/, `${name} must use the existing 'Error:' convention (the MCP adapter flattens 'Failed' text)`);
                assert.ok(!text.includes(LEGACY_DEFAULT));
                assert.ok(!text.includes("ak_dummy_generated_key"));
            }
            assert.deepEqual(attempts, [], "no request may be made without an explicit endpoint");
        });
    }));
});

test("legacy mode: the tools still default to the legacy host (unchanged behaviour of the unbundled plugin)", async () => {
    await withEnv({ SPS_BASE_URL: undefined, BLINDPASS_API_KEY: "ak_dummy_generated_key" }, async () => {
        await withOutboundGuard(async (attempts) => {
            const api = mockApi();
            register(api, {});
            await api.tools.get("request_secret").execute("id", { description: "d", secret_name: "legacy_default" }, { sendText: async () => {} });
            assert.ok(attempts.length >= 1 && attempts.every((url) => url.startsWith(`${LEGACY_DEFAULT}/`)), `legacy default not used: ${attempts}`);
        });
    });
});
