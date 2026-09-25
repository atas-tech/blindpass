import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { EventEmitter, once } from "node:events";
import { mkdtemp, readFile as readFileFs, rm, writeFile as writeFileFs } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { PassThrough } from "node:stream";
import { fileURLToPath } from "node:url";
import register, {
    buildExchangeDeliveryMessage,
    createOpenClawAgentTransport,
    disposeStoredSecret,
    getStoredSecret,
    resolveOpenClawAgentTarget,
} from "../index.mjs";
import { cleanup as cleanupBridge, requestSecretFlow } from "../sps-bridge.mjs";
import { parseProtocolRequest, resolveSecretEntries, runResolver } from "../blindpass-resolver.mjs";
import { createMcpServer, handleMcpRpcRequest } from "../mcp-server.mjs";
import {
    deriveSopsCommandEnv,
    emitManagedStoreBootstrapReminder,
    persistManagedSecret,
    readManagedSecretStore,
    resolveManagedStoreConfig,
    storeManagedSecret,
    listManagedSecretNames,
} from "../encrypted-store.mjs";

const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(TEST_DIR, "..", "..", "..");
const MCP_SERVER_ENTRY = path.resolve(TEST_DIR, "..", "mcp-server.mjs");
const AGENT_CONFIG_FIXTURES = {
    claude: path.join(REPO_ROOT, "agents", "claude_desktop_config.json"),
    codex: path.join(REPO_ROOT, "agents", "codex_mcp_config.json"),
    antigravity: path.join(REPO_ROOT, "agents", "antigravity_settings.json"),
};

function createMockApi() {
    const state = {
        tools: new Map(),
        hooks: [],
    };

    return {
        state,
        registerTool(tool) {
            state.tools.set(tool.name, tool);
        },
        registerHook(event, handler, meta) {
            state.hooks.push({ event, handler, meta });
        },
    };
}

function getTool(api, name) {
    const tool = api.state.tools.get(name);
    assert.ok(tool, `Tool '${name}' should be registered`);
    return tool;
}

function createMockChild(exitCode = 0, stderrText = "") {
    const child = new EventEmitter();
    child.stdout = new PassThrough();
    child.stderr = new PassThrough();

    setImmediate(() => {
        if (stderrText) {
            child.stderr.write(stderrText);
        }
        child.stdout.end();
        child.stderr.end();
        child.emit("close", exitCode);
    });

    return child;
}

function createExecChild(run) {
    const child = new EventEmitter();
    child.stdout = new PassThrough();
    child.stderr = new PassThrough();
    child.stdin = new PassThrough();
    child.kill = () => {
        child.emit("close", 1);
    };

    setImmediate(async () => {
        try {
            const result = await run();
            if (result?.stdout) {
                child.stdout.write(result.stdout);
            }
            if (result?.stderr) {
                child.stderr.write(result.stderr);
            }
            child.stdout.end();
            child.stderr.end();
            child.emit("close", result?.exitCode ?? 0);
        } catch (err) {
            child.stderr.write(String(err?.message ?? err));
            child.stdout.end();
            child.stderr.end();
            child.emit("close", 1);
        }
    });

    return child;
}

function createSopsPassthroughExecHarness(options = {}) {
    const agePublicKey = options.agePublicKey ?? "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqx4n2w";
    const ageSecretKey = options.ageSecretKey ?? "AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ";
    const encryptDelayMs = options.encryptDelayMs ?? 0;
    const decryptDelayMs = options.decryptDelayMs ?? 0;
    const failEncryptOnCallNumbers = new Set(options.failEncryptOnCallNumbers ?? []);

    const state = {
        calls: [],
        encryptCallCount: 0,
    };

    const maybeDelay = async (ms) => {
        if (ms > 0) {
            await new Promise((resolve) => {
                setTimeout(resolve, ms);
            });
        }
    };

    const execFileFn = (file, args = []) => createExecChild(async () => {
        state.calls.push({ file, args: [...args] });

        if (file === "sops" && args[0] === "--version") {
            return { stdout: "sops 3.9.0\n", exitCode: 0 };
        }

        if (file === "sops" && args[0] === "--encrypt") {
            state.encryptCallCount += 1;
            if (failEncryptOnCallNumbers.has(state.encryptCallCount)) {
                throw new Error(`simulated encrypt failure on call ${state.encryptCallCount}`);
            }
            await maybeDelay(encryptDelayMs);
            const plainPath = args[args.length - 1];
            const payload = await readFileFs(plainPath, "utf8");
            return { stdout: payload, exitCode: 0 };
        }

        if (file === "sops" && args[0] === "--decrypt") {
            await maybeDelay(decryptDelayMs);
            const storePath = args[args.length - 1];
            const payload = await readFileFs(storePath, "utf8");
            return { stdout: payload, exitCode: 0 };
        }

        if (file === "age-keygen" && args[0] === "-y") {
            const identityPath = args[1];
            const raw = await readFileFs(identityPath, "utf8");
            const line = raw.split(/\r?\n/).find((entry) => entry.startsWith("# public key:"));
            if (!line) {
                throw new Error("public key missing");
            }
            const pub = line.slice("# public key:".length).trim();
            return { stdout: `${pub}\n`, exitCode: 0 };
        }

        if (file === "age-keygen") {
            return {
                stdout: `# created: 2026-04-17T00:00:00Z\n# public key: ${agePublicKey}\n${ageSecretKey}\n`,
                exitCode: 0,
            };
        }

        throw new Error(`Unexpected command: ${file} ${args.join(" ")}`);
    });

    return { execFileFn, state, agePublicKey };
}

async function withEnv(overrides, fn) {
    const original = new Map();
    for (const [key, value] of Object.entries(overrides)) {
        original.set(key, process.env[key]);
        if (value == null) {
            delete process.env[key];
        } else {
            process.env[key] = String(value);
        }
    }

    try {
        await fn();
    } finally {
        for (const [key, value] of original.entries()) {
            if (value == null) {
                delete process.env[key];
            } else {
                process.env[key] = value;
            }
        }
    }
}

async function withDateNow(nowMs, fn) {
    const originalNow = Date.now;
    Date.now = () => nowMs;
    try {
        await fn();
    } finally {
        Date.now = originalNow;
    }
}

function encodeMcpFrame(payload) {
    const body = JSON.stringify(payload);
    const length = Buffer.byteLength(body, "utf8");
    return `Content-Length: ${length}\r\n\r\n${body}`;
}

function parseMcpFrame(buffer) {
    const headerEnd = buffer.indexOf("\r\n\r\n");
    if (headerEnd === -1) return null;

    const headerText = buffer.slice(0, headerEnd).toString("utf8");
    const lengthMatch = headerText.match(/content-length:\s*(\d+)/i);
    if (!lengthMatch) {
        throw new Error("MCP response is missing Content-Length header.");
    }

    const contentLength = Number.parseInt(lengthMatch[1], 10);
    const bodyStart = headerEnd + 4;
    const bodyEnd = bodyStart + contentLength;
    if (buffer.length < bodyEnd) return null;

    const body = buffer.slice(bodyStart, bodyEnd).toString("utf8");
    return {
        message: JSON.parse(body),
        remainder: buffer.slice(bodyEnd),
    };
}

async function readOneMcpResponse(stream, timeoutMs = 5000) {
    let buffer = Buffer.alloc(0);
    const onData = (chunk) => {
        buffer = Buffer.concat([buffer, Buffer.from(chunk)]);
        const parsed = parseMcpFrame(buffer);
        if (parsed) {
            cleanup();
            resolve(parsed.message);
        }
    };
    const onError = (err) => {
        cleanup();
        reject(err);
    };
    const onEnd = () => {
        cleanup();
        reject(new Error("MCP process ended before sending a response."));
    };

    let timer = null;
    let resolve;
    let reject;

    const cleanup = () => {
        stream.off("data", onData);
        stream.off("error", onError);
        stream.off("end", onEnd);
        if (timer) {
            clearTimeout(timer);
            timer = null;
        }
    };

    const waitPromise = new Promise((res, rej) => {
        resolve = res;
        reject = rej;
    });

    stream.on("data", onData);
    stream.on("error", onError);
    stream.on("end", onEnd);
    timer = setTimeout(() => {
        cleanup();
        reject(new Error(`Timed out waiting for MCP response after ${timeoutMs}ms.`));
    }, timeoutMs);

    return waitPromise;
}

function remapMcpArgForFixture(arg) {
    if (typeof arg !== "string") {
        return arg;
    }
    if (arg.endsWith("/dist/mcp-server.mjs") || arg.endsWith("\\dist\\mcp-server.mjs")) {
        return MCP_SERVER_ENTRY;
    }
    return arg;
}

async function stopProcess(child) {
    if (child.exitCode != null) {
        return;
    }

    child.kill("SIGTERM");
    const graceful = await Promise.race([
        once(child, "exit").then(() => true),
        new Promise((resolve) => setTimeout(() => resolve(false), 1500)),
    ]);

    if (!graceful && child.exitCode == null) {
        child.kill("SIGKILL");
        await once(child, "exit");
    }
}

async function runMcpLaunchSmokeFromConfig(configPath) {
    const raw = await readFileFs(configPath, "utf8");
    const parsed = JSON.parse(raw);
    const mcp = parsed?.mcpServers?.blindpass;

    assert.ok(mcp, `blindpass MCP config missing in ${configPath}`);
    assert.equal(typeof mcp.command, "string");
    assert.ok(Array.isArray(mcp.args), `blindpass args should be an array in ${configPath}`);

    const command = mcp.command;
    const args = mcp.args.map((entry) => remapMcpArgForFixture(entry));
    const child = spawn(command, args, {
        stdio: ["pipe", "pipe", "pipe"],
        env: {
            ...process.env,
            ...(mcp.env ?? {}),
            BLINDPASS_AUTO_PERSIST: "false",
        },
    });

    let stderrText = "";
    child.stderr.on("data", (chunk) => {
        stderrText += chunk.toString("utf8");
    });

    try {
        child.stdin.write(
            encodeMcpFrame({
                jsonrpc: "2.0",
                id: 1,
                method: "initialize",
                params: {},
            }),
        );
        const response = await readOneMcpResponse(child.stdout);
        assert.equal(response?.result?.serverInfo?.name, "blindpass");
        assert.equal(child.exitCode, null, `MCP process exited early: ${stderrText}`);
    } finally {
        await stopProcess(child);
    }
}

async function testNoPlaintextExposure() {
    const api = createMockApi();
    const outbound = [];

    register(api, {
        requestSecretFlowFn: async ({ onSecretLink }) => {
            await onSecretLink("https://secrets.example/r/abc", "BLUE-FOX-42");
            return Buffer.from("super-secret-value", "utf8");
        },
        cleanupFn: async () => { },
    });

    const result = await getTool(api, "request_secret").execute(
        "id-1",
        { description: "AWS deployment token", secret_name: "aws_token", channel_id: "telegram:111" },
        { sendText: async (message) => outbound.push(message) },
    );

    assert.equal(outbound.length, 1, "Should send one user-facing link message");

    const output = result?.content?.[0]?.text ?? "";
    assert.ok(output.includes("Secret received and stored securely in memory."));
    assert.ok(output.includes("secret_name: aws_token"));
    assert.ok(!output.includes("super-secret-value"), "Tool output must not include plaintext secret");

    const stored = getStoredSecret("aws_token");
    assert.ok(stored, "Stored secret should be available in plugin memory");
    assert.equal(stored.toString("utf8"), "super-secret-value");

    disposeStoredSecret("aws_token");
}

async function testRequestSecretFailsClosedWhenManagedBackendUnsupported() {
    await withEnv(
        {
            BLINDPASS_AUTO_PERSIST: "true",
            BLINDPASS_STORE_BACKEND: "unsupported-backend",
        },
        async () => {
            const api = createMockApi();
            const outbound = [];

            register(api, {
                requestSecretFlowFn: async ({ onSecretLink }) => {
                    await onSecretLink("https://secrets.example/r/managed-fail", "BLUE-FOX-99");
                    return Buffer.from("super-secret-value", "utf8");
                },
                cleanupFn: async () => { },
            });

            const result = await getTool(api, "request_secret").execute(
                "managed-fail",
                { description: "Managed store path", secret_name: "managed_fail", channel_id: "telegram:111" },
                { sendText: async (message) => outbound.push(message) },
            );

            assert.equal(outbound.length, 1, "Secret link should still be delivered before persistence error");
            const output = result?.content?.[0]?.text ?? "";
            assert.match(output, /Unsupported managed-store backend/);
            assert.equal(getStoredSecret("managed_fail"), null, "Secret must not be stored when managed mode fails closed");
        }
    );
}

async function testRequestSecretUsesManagedPersistenceWhenConfigured() {
    const api = createMockApi();
    const outbound = [];
    const managedCalls = [];

    register(api, {
        requestSecretFlowFn: async ({ onSecretLink }) => {
            await onSecretLink("https://secrets.example/r/managed-ok", "GREEN-WOLF-55");
            return Buffer.from("managed-secret", "utf8");
        },
        persistManagedSecretFn: async ({ name, value }) => {
            managedCalls.push({ name, value: Buffer.from(value).toString("utf8") });
            return { persisted: true, storage: "managed" };
        },
        cleanupFn: async () => { },
    });

    const result = await getTool(api, "request_secret").execute(
        "managed-ok",
        { description: "Managed store path", secret_name: "managed_ok", channel_id: "telegram:111", persist: true },
        { sendText: async (message) => outbound.push(message) },
    );

    assert.equal(outbound.length, 1);
    assert.equal(managedCalls.length, 1);
    assert.equal(managedCalls[0].name, "managed_ok");
    assert.equal(managedCalls[0].value, "managed-secret");

    const output = result?.content?.[0]?.text ?? "";
    assert.match(output, /managed encrypted storage/);
    assert.match(output, /storage: managed/);

    const stored = getStoredSecret("managed_ok");
    assert.ok(stored, "Secret should remain available in runtime memory after managed persistence");
    assert.equal(stored.toString("utf8"), "managed-secret");
    disposeStoredSecret("managed_ok");
}

async function testUsesOpenClawCliFallback() {
    const api = createMockApi();
    const calls = [];

    register(api, {
        requestSecretFlowFn: async ({ onSecretLink }) => {
            await onSecretLink("https://secrets.example/r/abc", "BLUE-FOX-42");
            return Buffer.from("cli-secret", "utf8");
        },
        cleanupFn: async () => { },
        execFileFn: (file, args) => {
            calls.push({ file, args });
            return createMockChild(0);
        },
    });

    const result = await getTool(api, "request_secret").execute(
        "id-cli",
        {
            description: "Need token",
            channel_id: "telegram:123456789",
            secret_name: "cli_key",
        },
        {},
    );

    assert.equal(calls.length, 1, "CLI fallback should be attempted exactly once");
    assert.equal(calls[0].file, "openclaw");
    assert.deepEqual(calls[0].args.slice(0, 6), ["message", "send", "--channel", "telegram", "--target", "123456789"]);
    assert.match(result?.content?.[0]?.text ?? "", /Secret received and stored securely in memory/);
    disposeStoredSecret("cli_key");
}

async function testUsesSendMessageWhenSendTextMissing() {
    const api = createMockApi();
    const outbound = [];

    register(api, {
        requestSecretFlowFn: async ({ onSecretLink }) => {
            await onSecretLink("https://secrets.example/r/abc", "BLUE-FOX-42");
            return Buffer.from("s-1", "utf8");
        },
        cleanupFn: async () => { },
    });

    const result = await getTool(api, "request_secret").execute(
        "id-cli",
        {
            description: "Need token",
            channel_id: "telegram:123456789",
            secret_name: "t1",
        },
        { sendMessage: async (message) => outbound.push(message) },
    );

    assert.equal(outbound.length, 1, "Should use context.sendMessage when available");
    assert.match(result?.content?.[0]?.text ?? "", /Secret received and stored securely in memory/);

    disposeStoredSecret("t1");
}

async function testFailsWhenNoTransportAvailable() {
    const api = createMockApi();
    const captured = [];
    const originalError = console.error;
    try {
        console.error = (...args) => {
            captured.push(args.join(" "));
        };

        register(api, {
            requestSecretFlowFn: async ({ onSecretLink }) => {
                await onSecretLink("https://secrets.example/r/abc", "BLUE-FOX-42");
                return Buffer.from("s-2", "utf8");
            },
            cleanupFn: async () => { },
            execFileFn: () => createMockChild(1, "mock cli failure"),
        });

        const result = await getTool(api, "request_secret").execute("id-4", { description: "Need token" }, {});
        const output = result?.content?.[0]?.text ?? "";
        assert.match(output, /Could not deliver secure link to chat channel/);
        assert.equal(captured.length, 1, "Should log transport failure details to console.error when routing params are missing");
    } finally {
        console.error = originalError;
    }
}

async function testUsesRuntimeChannelWhenOtherTransportsMissing() {
    const api = createMockApi();
    const outbound = [];

    api.runtime = {
        channel: {
            sendText: async (message) => outbound.push(message),
        },
    };

    register(api, {
        requestSecretFlowFn: async ({ onSecretLink }) => {
            await onSecretLink("https://secrets.example/r/abc", "BLUE-FOX-42");
            return Buffer.from("s-3", "utf8");
        },
        cleanupFn: async () => { },
    });

    const result = await getTool(api, "request_secret").execute("id-5", { description: "Need token", channel_id: "telegram:555" }, {});

    assert.equal(outbound.length, 1, "Should use api.runtime.channel.sendText when available");
    assert.match(result?.content?.[0]?.text ?? "", /Secret received and stored securely in memory/);

    disposeStoredSecret("default");
}

async function testDoesNotLogSecretUrls() {
    const api = createMockApi();
    const outbound = [];
    const captured = [];
    const originalLog = console.log;

    try {
        console.log = (...args) => {
            captured.push(args.join(" "));
        };

        register(api, {
            requestSecretFlowFn: async ({ onSecretLink }) => {
                await onSecretLink("https://secrets.example/r/abc", "BLUE-FOX-42");
                return Buffer.from("s-4", "utf8");
            },
            cleanupFn: async () => { },
        });

        await getTool(api, "request_secret").execute(
            "id-6",
            {
                description: "Need token",
                channel_id: "telegram:123456789",
                secret_name: "safe_log_check",
            },
            { sendText: async (message) => outbound.push(message) },
        );

        assert.equal(outbound.length, 1, "Should still deliver the secret link to the user");
        assert.ok(captured.some((line) => line.includes("Delivering secure link to configured channel.")));
        assert.ok(captured.every((line) => !line.includes("https://secrets.example/r/abc")), "Logs must not contain secret URLs");
    } finally {
        console.log = originalLog;
    }

    disposeStoredSecret("safe_log_check");
}

async function testShutdownDisposesSecrets() {
    const api = createMockApi();

    register(api, {
        requestSecretFlowFn: async () => Buffer.from("to-be-disposed", "utf8"),
        cleanupFn: async () => { },
    });

    await getTool(api, "request_secret").execute("id-2", { description: "DB password", channel_id: "telegram:222" }, {});
    assert.ok(getStoredSecret("default"));

    for (const hook of api.state.hooks) {
        if (hook.event === "shutdown") {
            await hook.handler();
        }
    }

    assert.equal(getStoredSecret("default"), null);
}

async function testRequestSecretFlowPublishesJwksForJwtAuth() {
    const originalApiKey = process.env.BLINDPASS_API_KEY;
    const originalFallbackApiKey = process.env.SPS_AGENT_API_KEY;
    delete process.env.BLINDPASS_API_KEY;
    delete process.env.SPS_AGENT_API_KEY;

    const calls = {
        loadOrCreateGatewayIdentity: [],
        writeJwksFile: [],
        issueJwt: [],
        destroyKeyPair: 0,
        onSecretLink: [],
    };

    try {
        const plaintext = await requestSecretFlow({
            description: "Bridge JWT fallback secret request",
            agentId: "bridge-jwt-agent",
            identityOptions: {
                keyPath: "/tmp/bridge-jwt-test/gateway-key.json",
            },
            onSecretLink: async (secretUrl, confirmationCode) => {
                calls.onSecretLink.push({ secretUrl, confirmationCode });
            },
            moduleOverrides: {
                identity: {
                    async loadOrCreateGatewayIdentity(opts) {
                        calls.loadOrCreateGatewayIdentity.push(opts);
                        return { kid: "kid-1" };
                    },
                    async writeJwksFile(identity, jwksPath) {
                        calls.writeJwksFile.push({ identity, jwksPath });
                    },
                    async issueJwt(identity, agentId) {
                        calls.issueJwt.push({ identity, agentId });
                        return `jwt-for-${agentId}`;
                    },
                },
                keyManager: {
                    async generateKeyPair() {
                        return { publicKey: "public-key", privateKey: "private-key" };
                    },
                    async decrypt() {
                        return Buffer.from("bridge-secret", "utf8");
                    },
                    destroyKeyPair() {
                        calls.destroyKeyPair += 1;
                    },
                },
                AgentSkillRuntimeModule: {
                    AgentSecretRuntime: class {},
                },
                GatewaySpsClientModule: {
                    GatewaySpsClient: class {
                        async createSecretRequest() {
                            return {
                                requestId: "req-1",
                                secretUrl: "https://secrets.example/r/req-1",
                                confirmationCode: "BLUE-FOX-42",
                            };
                        }
                    },
                },
                SpsClientModule: {
                    SpsClient: class {
                        async pollStatus() {}
                        async retrieveSecret() {
                            return { enc: "enc", ciphertext: "ciphertext" };
                        }
                    },
                },
            },
        });

        assert.equal(plaintext.toString("utf8"), "bridge-secret");
        assert.equal(calls.loadOrCreateGatewayIdentity.length, 1);
        assert.equal(calls.writeJwksFile.length, 1);
        assert.equal(calls.writeJwksFile[0].jwksPath, "/tmp/bridge-jwt-test/jwks.json");
        assert.equal(calls.issueJwt.length, 2);
        assert.deepEqual(calls.issueJwt.map((call) => call.agentId), ["bridge-jwt-agent", "bridge-jwt-agent"]);
        assert.equal(calls.destroyKeyPair, 1);
        assert.equal(calls.onSecretLink.length, 1);
    } finally {
        await cleanupBridge();

        if (originalApiKey === undefined) {
            delete process.env.BLINDPASS_API_KEY;
        } else {
            process.env.BLINDPASS_API_KEY = originalApiKey;
        }

        if (originalFallbackApiKey === undefined) {
            delete process.env.SPS_AGENT_API_KEY;
        } else {
            process.env.SPS_AGENT_API_KEY = originalFallbackApiKey;
        }
    }
}

async function testReRequestFormat() {
    const api = createMockApi();
    const outbound = [];

    register(api, {
        requestSecretFlowFn: async ({ onSecretLink }) => {
            await onSecretLink("https://secrets.example/r/xyz", "RED-BULL-99");
            return Buffer.from("super-secret-value-2", "utf8");
        },
        cleanupFn: async () => { },
    });

    await getTool(api, "request_secret").execute(
        "id-rereq",
        { description: "DB Password", secret_name: "db_pass", channel_id: "telegram:111", re_request: true },
        { sendText: async (message) => outbound.push(message) },
    );

    assert.equal(outbound.length, 1, "Should send one user-facing link message");
    const sentMessage = outbound[0];
    assert.ok(sentMessage.includes("Re-enter your secret to continue"), "Message should contain the re-request prompt");
    assert.ok(!sentMessage.includes("Secure secret requested"), "Message should NOT contain the default prompt");

    disposeStoredSecret("db_pass");
}

async function testRequestSecretFlowSurfacesRateLimitAndDestroysKeyPair() {
    const originalApiKey = process.env.BLINDPASS_API_KEY;
    const originalFallbackApiKey = process.env.SPS_AGENT_API_KEY;
    delete process.env.BLINDPASS_API_KEY;
    delete process.env.SPS_AGENT_API_KEY;

    const calls = { secretRequest: 0, destroyKeyPair: 0, onSecretLink: 0 };
    try {
        await assert.rejects(requestSecretFlow({
            description: "Rate-limited secret request",
            agentId: "bridge-rate-limit-agent",
            onSecretLink: async () => { calls.onSecretLink += 1; },
            moduleOverrides: {
                identity: {
                    async loadOrCreateGatewayIdentity() { return { kid: "rate-limit-kid" }; },
                    async writeJwksFile() {},
                    async issueJwt() { return "rate-limit-jwt"; },
                },
                keyManager: {
                    async generateKeyPair() { return { publicKey: "public-key", privateKey: "private-key" }; },
                    async decrypt() { return Buffer.from("unused"); },
                    destroyKeyPair() { calls.destroyKeyPair += 1; },
                },
                AgentSkillRuntimeModule: { AgentSecretRuntime: class {} },
                GatewaySpsClientModule: {
                    GatewaySpsClient: class {
                        async createSecretRequest() {
                            calls.secretRequest += 1;
                            throw new Error("SPS request failed with status 429");
                        }
                    },
                },
                SpsClientModule: { SpsClient: class {} },
            },
        }), /SPS request failed with status 429/);

        assert.deepEqual(calls, { secretRequest: 1, destroyKeyPair: 1, onSecretLink: 0 });
    } finally {
        await cleanupBridge();
        if (originalApiKey === undefined) delete process.env.BLINDPASS_API_KEY;
        else process.env.BLINDPASS_API_KEY = originalApiKey;
        if (originalFallbackApiKey === undefined) delete process.env.SPS_AGENT_API_KEY;
        else process.env.SPS_AGENT_API_KEY = originalFallbackApiKey;
    }
}

async function testFulfillSecretExchangeUsesStoredSecret() {
    const api = createMockApi();
    const calls = [];

    register(api, {
        requestSecretFlowFn: async () => Buffer.from("super-secret-value", "utf8"),
        cleanupFn: async () => { },
        fulfillExchangeFlowFn: async (params) => {
            calls.push({
                fulfillmentToken: params.fulfillmentToken,
                secret: await params.resolveSecret("stripe.api_key.prod"),
                agentId: params.agentId,
            });
            return {
                exchangeId: "ex-123",
                secretName: "stripe.api_key.prod",
                fulfilledBy: params.agentId,
            };
        },
    });

    const requestTool = getTool(api, "request_secret");
    await requestTool.execute(
        "store-secret",
        { description: "Need token", secret_name: "stripe.api_key.prod", channel_id: "telegram:111" },
        {
            sendText: async () => { },
        },
    );

    const result = await getTool(api, "fulfill_secret_exchange").execute(
        "fulfill-1",
        { fulfillment_token: "token-abc" },
        {},
    );

    assert.equal(calls.length, 1);
    assert.equal(calls[0].fulfillmentToken, "token-abc");
    assert.equal(calls[0].secret.toString("utf8"), "super-secret-value");
    assert.match(result?.content?.[0]?.text ?? "", /Secret exchange fulfilled successfully/);

    disposeStoredSecret("stripe.api_key.prod");
}

async function testRequestSecretExchangeUsesOpenClawTransportAndStoresSecret() {
    const api = createMockApi();
    const sent = [];

    api.runtime = {
        agentToAgent: {
            send: async (payload) => sent.push(payload),
        },
    };

    register(api, {
        cleanupFn: async () => { },
        requestExchangeFlowFn: async ({ secretName, purpose, fulfillerId, transport, agentId }) => {
            await transport.deliverFulfillmentToken({
                kind: "blindpass.exchange-fulfillment.v1",
                exchangeId: "ex-request-1",
                requesterId: agentId,
                fulfillerId,
                secretName,
                purpose,
                fulfillmentToken: "token-request-1",
            });

            return {
                exchangeId: "ex-request-1",
                fulfilledBy: fulfillerId,
                secret: Buffer.from("sk_exchange_123", "utf8"),
            };
        },
    });

    const result = await getTool(api, "request_secret_exchange").execute(
        "request-exchange-1",
        {
            secret_name: "stripe.api_key.prod",
            purpose: "charge-order",
            fulfiller_id: "session:payments",
        },
        {},
    );

    assert.equal(sent.length, 1);
    assert.equal(sent[0].target, "session:payments");
    assert.match(sent[0].message, /fulfill_secret_exchange/);
    assert.match(result?.content?.[0]?.text ?? "", /Secret exchange completed and stored securely in memory/);
    assert.equal(getStoredSecret("stripe.api_key.prod")?.toString("utf8"), "sk_exchange_123");

    disposeStoredSecret("stripe.api_key.prod");
}

async function testRequestSecretExchangeFailsClosedWhenTargetCannotBeResolved() {
    const api = createMockApi();

    register(api, {
        cleanupFn: async () => { },
        createOpenClawAgentTransportFn: (apiArg, options) =>
            createOpenClawAgentTransport(apiArg, { ...options, directTargetFallback: false }),
        requestExchangeFlowFn: async ({ secretName, purpose, fulfillerId, transport, agentId }) => {
            await transport.deliverFulfillmentToken({
                kind: "blindpass.exchange-fulfillment.v1",
                exchangeId: "ex-request-fail",
                requesterId: agentId,
                fulfillerId,
                secretName,
                purpose,
                fulfillmentToken: "token-request-fail",
            });

            return {
                exchangeId: "ex-request-fail",
                fulfilledBy: fulfillerId,
                secret: Buffer.from("should-not-store", "utf8"),
            };
        },
    });

    const result = await getTool(api, "request_secret_exchange").execute(
        "request-exchange-fail",
        {
            secret_name: "stripe.api_key.prod",
            purpose: "charge-order",
            fulfiller_id: "agent:missing-bot",
        },
        {},
    );

    assert.match(
        result?.content?.[0]?.text ?? "",
        /Failed to request secret exchange: OpenClaw transport could not resolve a target session/
    );
    assert.equal(getStoredSecret("stripe.api_key.prod"), null);
}

async function testCreateOpenClawAgentTransportUsesRuntimeAgentChannel() {
    const sent = [];
    const api = {
        runtime: {
            agentToAgent: {
                send: async (payload) => sent.push(payload),
            },
        },
    };

    const transport = createOpenClawAgentTransport(api);
    await transport.deliverFulfillmentToken({
        kind: "blindpass.exchange-fulfillment.v1",
        exchangeId: "ex-transport",
        requesterId: "agent:crm-bot",
        fulfillerId: "session:payments",
        secretName: "stripe.api_key.prod",
        purpose: "charge-order",
        fulfillmentToken: "token-transport",
    });

    assert.equal(sent.length, 1);
    assert.equal(sent[0].target, "session:payments");
    assert.match(sent[0].message, /fulfill_secret_exchange/);
}

async function testResolveOpenClawAgentTargetUsesConfiguredMap() {
    const target = await resolveOpenClawAgentTarget(
        {},
        {
            fulfillerId: "agent:payment-bot",
        },
        {
            targetMap: {
                "agent:payment-bot": "session:payments",
            },
            directTargetFallback: false,
        },
    );

    assert.equal(target, "session:payments");
}

async function testResolveOpenClawAgentTargetUsesRuntimeResolver() {
    const target = await resolveOpenClawAgentTarget(
        {
            runtime: {
                sessions: {
                    resolveTarget: async (agentId) => agentId === "agent:ops-bot" ? "session:ops" : null,
                },
            },
        },
        {
            fulfillerId: "agent:ops-bot",
        },
        {
            directTargetFallback: false,
        },
    );

    assert.equal(target, "session:ops");
}

async function testResolveOpenClawAgentTargetUsesEnvMap() {
    const original = process.env.OPENCLAW_AGENT_TARGETS_JSON;
    process.env.OPENCLAW_AGENT_TARGETS_JSON = JSON.stringify({
        "agent:payment-bot": "session:payments-env",
    });

    try {
        const target = await resolveOpenClawAgentTarget(
            {},
            {
                fulfillerId: "agent:payment-bot",
            },
            {
                directTargetFallback: false,
            },
        );

        assert.equal(target, "session:payments-env");
    } finally {
        process.env.OPENCLAW_AGENT_TARGETS_JSON = original;
    }
}

async function testCreateOpenClawAgentTransportUsesAgentTargetMapBeforeFallback() {
    const sent = [];
    const api = {
        runtime: {
            agentToAgent: {
                send: async (payload) => sent.push(payload),
            },
        },
        agentTargetMap: {
            "agent:payment-bot": "session:payments",
        },
    };

    const transport = createOpenClawAgentTransport(api, { directTargetFallback: false });
    await transport.deliverFulfillmentToken({
        kind: "blindpass.exchange-fulfillment.v1",
        exchangeId: "ex-transport-2",
        requesterId: "agent:crm-bot",
        fulfillerId: "agent:payment-bot",
        secretName: "stripe.api_key.prod",
        purpose: "charge-order",
        fulfillmentToken: "token-transport-2",
    });

    assert.equal(sent.length, 1);
    assert.equal(sent[0].target, "session:payments");
}

async function testBuildExchangeDeliveryMessageIncludesToolCall() {
    const message = buildExchangeDeliveryMessage({
        exchangeId: "ex-42",
        requesterId: "agent:crm-bot",
        fulfillerId: "agent:payment-bot",
        secretName: "stripe.api_key.prod",
        purpose: "charge-order",
        fulfillmentToken: "token-42",
    });

    assert.match(message, /BlindPass secret exchange request/);
    assert.match(message, /fulfill_secret_exchange/);
    assert.match(message, /token-42/);
}

async function testStoreSecretToolIsDisabledByDefault() {
    const api = createMockApi();
    register(api, {
        emitManagedStoreBootstrapReminderFn: async () => ({ emitted: false }),
    });

    assert.equal(api.state.tools.has("store_secret"), false, "store_secret should not be registered by default");
    assert.equal(api.state.tools.has("list_secrets"), true);
    assert.equal(api.state.tools.has("delete_secret"), true);
    assert.equal(api.state.tools.has("confirm_delete_secret"), true);
}

async function testStoreSecretToolCanBeEnabledAndStoresMetadataOnly() {
    await withEnv(
        {
            BLINDPASS_ENABLE_STORE_TOOL: "true",
            BLINDPASS_ALLOW_EXPOSE_PLAINTEXT: "true",
        },
        async () => {
            const api = createMockApi();
            const calls = [];
            register(api, {
                emitManagedStoreBootstrapReminderFn: async () => ({ emitted: false }),
                storeManagedSecretFn: async ({ name, value }) => {
                    calls.push({ name, value: Buffer.from(value).toString("utf8") });
                    return {
                        storage: "managed",
                        backend: "sops",
                    };
                },
            });

            assert.equal(api.state.tools.has("store_secret"), true, "store_secret should be registered when enabled");
            const storeTool = getTool(api, "store_secret");
            const result = await storeTool.execute(
                "store-tool-1",
                {
                    secret_name: "runtime.generated.token",
                    secret_value: "super-sensitive-value",
                },
                {},
            );

            assert.equal(calls.length, 1);
            assert.equal(calls[0].name, "runtime.generated.token");
            assert.equal(calls[0].value, "super-sensitive-value");

            const output = result?.content?.[0]?.text ?? "";
            assert.match(output, /Secret stored in managed encrypted storage/);
            assert.match(output, /secret_name: runtime.generated.token/);
            assert.ok(!output.includes("super-sensitive-value"), "store_secret output must never include plaintext value");
            assert.equal(getStoredSecret("runtime.generated.token")?.toString("utf8"), "super-sensitive-value");

            disposeStoredSecret("runtime.generated.token");
        },
    );
}

async function testStoreSecretFailsClosedWhenManagedStoreUnavailable() {
    await withEnv(
        {
            BLINDPASS_ENABLE_STORE_TOOL: "true",
        },
        async () => {
            const api = createMockApi();
            register(api, {
                emitManagedStoreBootstrapReminderFn: async () => ({ emitted: false }),
                storeManagedSecretFn: async () => {
                    throw new Error("managed store unavailable");
                },
            });

            const result = await getTool(api, "store_secret").execute(
                "store-tool-fail",
                {
                    secret_name: "runtime.generated.token",
                    secret_value: "super-sensitive-value",
                },
                {},
            );

            const output = result?.content?.[0]?.text ?? "";
            assert.match(output, /Failed to store managed secret: managed store unavailable/);
            assert.equal(getStoredSecret("runtime.generated.token"), null, "no runtime store update on managed failure");
        },
    );
}

async function testListSecretsReturnsOnlyNames() {
    const api = createMockApi();
    register(api, {
        emitManagedStoreBootstrapReminderFn: async () => ({ emitted: false }),
        listManagedSecretNamesFn: async () => ({
            names: ["a.secret", "b.secret"],
            backend: "sops",
        }),
    });

    const result = await getTool(api, "list_secrets").execute("list-1", {}, {});
    const output = result?.content?.[0]?.text ?? "";
    assert.match(output, /Managed secrets listed successfully/);
    assert.match(output, /count: 2/);
    assert.match(output, /- a\.secret/);
    assert.match(output, /- b\.secret/);
    assert.ok(!output.includes("secret_value"), "list_secrets should only return names");
}

async function testDeleteSecretRequiresConfirmationAndSingleUseToken() {
    const api = createMockApi();
    const deleteCalls = [];
    register(api, {
        emitManagedStoreBootstrapReminderFn: async () => ({ emitted: false }),
        deleteManagedSecretFn: async ({ name }) => {
            deleteCalls.push(name);
            return {
                deleted: true,
                name,
            };
        },
    });

    const deleteResult = await getTool(api, "delete_secret").execute(
        "delete-1",
        { secret_name: "stripe.api_key.prod" },
        {},
    );
    const deleteOutput = deleteResult?.content?.[0]?.text ?? "";
    const tokenMatch = deleteOutput.match(/confirmation_token: ([a-f0-9]+)/);
    assert.ok(tokenMatch, "delete_secret should return a confirmation token");
    assert.equal(deleteCalls.length, 0, "delete_secret should not perform immediate deletion");

    const token = tokenMatch[1];
    const confirmResult = await getTool(api, "confirm_delete_secret").execute(
        "confirm-1",
        {
            secret_name: "stripe.api_key.prod",
            confirmation_token: token,
        },
        {},
    );
    const confirmOutput = confirmResult?.content?.[0]?.text ?? "";
    assert.match(confirmOutput, /Managed secret deleted successfully/);
    assert.equal(deleteCalls.length, 1);
    assert.equal(deleteCalls[0], "stripe.api_key.prod");

    const reused = await getTool(api, "confirm_delete_secret").execute(
        "confirm-2",
        {
            secret_name: "stripe.api_key.prod",
            confirmation_token: token,
        },
        {},
    );
    const reusedOutput = reused?.content?.[0]?.text ?? "";
    assert.match(reusedOutput, /invalid or expired/);
}

async function testConfirmDeleteSecretRejectsMismatchedAndExpiredTokens() {
    const api = createMockApi();
    const deleteCalls = [];
    register(api, {
        emitManagedStoreBootstrapReminderFn: async () => ({ emitted: false }),
        deleteManagedSecretFn: async ({ name }) => {
            deleteCalls.push(name);
            return {
                deleted: true,
                name,
            };
        },
    });

    const deleteResult = await getTool(api, "delete_secret").execute(
        "delete-mismatch",
        { secret_name: "one.secret" },
        {},
    );
    const token = (deleteResult?.content?.[0]?.text ?? "").match(/confirmation_token: ([a-f0-9]+)/)?.[1];
    assert.ok(token);

    const mismatch = await getTool(api, "confirm_delete_secret").execute(
        "confirm-mismatch",
        {
            secret_name: "two.secret",
            confirmation_token: token,
        },
        {},
    );
    assert.match(mismatch?.content?.[0]?.text ?? "", /does not match the provided secret_name/);
    assert.equal(deleteCalls.length, 0, "mismatch should not delete");

    await withDateNow(Date.now() + 70000, async () => {
        const expired = await getTool(api, "confirm_delete_secret").execute(
            "confirm-expired",
            {
                secret_name: "one.secret",
                confirmation_token: token,
            },
            {},
        );
        assert.match(expired?.content?.[0]?.text ?? "", /invalid or expired/);
    });
    assert.equal(deleteCalls.length, 0, "expired token should not delete");
}

async function testRequestSecretPersistFalseSkipsManagedPersistence() {
    const api = createMockApi();
    const managedCalls = [];

    register(api, {
        requestSecretFlowFn: async ({ onSecretLink }) => {
            await onSecretLink("https://secrets.example/r/persist-false", "CODE-1");
            return Buffer.from("persist-false-secret", "utf8");
        },
        persistManagedSecretFn: async (args) => {
            managedCalls.push(args);
            return { persisted: true, storage: "managed" };
        },
        cleanupFn: async () => { },
    });

    const result = await getTool(api, "request_secret").execute(
        "persist-false-1",
        {
            description: "Interactive-only secret",
            secret_name: "interactive.secret",
            persist: false,
            channel_id: "telegram:123",
        },
        { sendText: async () => { } },
    );

    const output = result?.content?.[0]?.text ?? "";
    assert.equal(managedCalls.length, 0, "persist=false should bypass managed persistence");
    assert.match(output, /stored securely in memory/);
    assert.ok(!output.includes("managed encrypted storage"));
    assert.equal(getStoredSecret("interactive.secret")?.toString("utf8"), "persist-false-secret");
    disposeStoredSecret("interactive.secret");
}

async function testRequestSecretRejectsPersistTrueWithoutSecretName() {
    const api = createMockApi();
    register(api, {
        cleanupFn: async () => { },
    });

    const result = await getTool(api, "request_secret").execute(
        "persist-validate-1",
        {
            description: "Managed request",
            persist: true,
            channel_id: "telegram:123",
        },
        { sendText: async () => { } },
    );
    const output = result?.content?.[0]?.text ?? "";
    assert.match(output, /secret_name is required when persist=true/);
}

async function testRequestSecretExchangeRejectsPersistTrueWithoutSecretName() {
    const api = createMockApi();
    register(api, {
        cleanupFn: async () => { },
    });

    const result = await getTool(api, "request_secret_exchange").execute(
        "persist-validate-2",
        {
            purpose: "charge-order",
            fulfiller_id: "agent:payments",
            persist: true,
        },
        {},
    );
    const output = result?.content?.[0]?.text ?? "";
    assert.match(output, /secret_name is required when persist=true/);
}

async function testRequestSecretManagedModeMetadataOnlyByDefault() {
    const api = createMockApi();
    const managedCalls = [];

    register(api, {
        requestSecretFlowFn: async ({ onSecretLink }) => {
            await onSecretLink("https://secrets.example/r/managed-default", "CODE-2");
            return Buffer.from("managed-default-secret", "utf8");
        },
        persistManagedSecretFn: async ({ name }) => {
            managedCalls.push(name);
            return { persisted: true, storage: "managed", backend: "sops" };
        },
        cleanupFn: async () => { },
    });

    const result = await getTool(api, "request_secret").execute(
        "managed-default-1",
        {
            description: "Managed default flow",
            secret_name: "managed.default.secret",
            persist: true,
            channel_id: "telegram:123",
        },
        { sendText: async () => { } },
    );

    const output = result?.content?.[0]?.text ?? "";
    assert.equal(managedCalls.length, 1);
    assert.match(output, /managed encrypted storage/);
    assert.match(output, /secret_name: managed\.default\.secret/);
    assert.ok(!output.includes("managed-default-secret"), "managed mode should be metadata-only when plaintext exposure is disabled");
    disposeStoredSecret("managed.default.secret");
}

async function testRequestSecretPlaintextExposureControlledByEnvOnly() {
    await withEnv(
        {
            BLINDPASS_ALLOW_EXPOSE_PLAINTEXT: "false",
        },
        async () => {
            const api = createMockApi();
            register(api, {
                requestSecretFlowFn: async ({ onSecretLink }) => {
                    await onSecretLink("https://secrets.example/r/plaintext-off", "CODE-3");
                    return Buffer.from("plaintext-off-secret", "utf8");
                },
                persistManagedSecretFn: async () => ({ persisted: true, storage: "managed" }),
                cleanupFn: async () => { },
            });

            const result = await getTool(api, "request_secret").execute(
                "plaintext-off-1",
                {
                    description: "No plaintext exposure",
                    secret_name: "plaintext.off.secret",
                    persist: true,
                    channel_id: "telegram:123",
                    expose_plaintext: true,
                },
                { sendText: async () => { } },
            );
            const output = result?.content?.[0]?.text ?? "";
            assert.ok(!output.includes("plaintext-off-secret"), "tool params must not override deployment plaintext policy");
            disposeStoredSecret("plaintext.off.secret");
        },
    );

    await withEnv(
        {
            BLINDPASS_ALLOW_EXPOSE_PLAINTEXT: "true",
        },
        async () => {
            const api = createMockApi();
            register(api, {
                requestSecretFlowFn: async ({ onSecretLink }) => {
                    await onSecretLink("https://secrets.example/r/plaintext-on", "CODE-4");
                    return Buffer.from("plaintext-on-secret", "utf8");
                },
                persistManagedSecretFn: async () => ({ persisted: true, storage: "managed" }),
                cleanupFn: async () => { },
            });

            const result = await getTool(api, "request_secret").execute(
                "plaintext-on-1",
                {
                    description: "Allow plaintext exposure",
                    secret_name: "plaintext.on.secret",
                    persist: true,
                    channel_id: "telegram:123",
                },
                { sendText: async () => { } },
            );
            const output = result?.content?.[0]?.text ?? "";
            assert.match(output, /secret_value: plaintext-on-secret/);
            disposeStoredSecret("plaintext.on.secret");
        },
    );
}

async function testManagedStorePathSelectionAndOverrides() {
    const home = "/tmp/home-user";
    const openclawConfig = "/tmp/openclaw-config";

    const openclawConfigResult = resolveManagedStoreConfig(
        {
            HOME: home,
            BLINDPASS_RUNTIME_MODE: "openclaw",
            OPENCLAW_GATEWAY_CONFIG_DIR: openclawConfig,
        },
        "darwin",
    );
    assert.equal(openclawConfigResult.storePath, `${openclawConfig}/blindpass/secrets.enc.json`);
    assert.equal(openclawConfigResult.backend, "sops");

    const mcpConfigResult = resolveManagedStoreConfig(
        {
            HOME: home,
            BLINDPASS_RUNTIME_MODE: "mcp",
        },
        "linux",
    );
    assert.equal(mcpConfigResult.storePath, `${home}/.blindpass/secrets.enc.json`);

    const windowsConfigResult = resolveManagedStoreConfig(
        {
            LOCALAPPDATA: "C:\\Users\\hvo\\AppData\\Local",
        },
        "win32",
    );
    assert.equal(
        windowsConfigResult.storePath.replace(/\\/g, "/"),
        "C:/Users/hvo/AppData/Local/blindpass/secrets.enc.json",
    );

    const overrideResult = resolveManagedStoreConfig(
        {
            BLINDPASS_STORE_PATH: "/custom/path/store.json",
            BLINDPASS_STORE_BACKEND: "custom-vault",
        },
        "linux",
    );
    assert.equal(overrideResult.storePath, "/custom/path/store.json");
    assert.equal(overrideResult.backend, "custom-vault");
}

async function testDeriveSopsCommandEnvFromStoreSiblingFiles() {
    const tempRoot = await mkdtemp(path.join(os.tmpdir(), "blindpass-sops-env-"));
    const storePath = path.join(tempRoot, "secrets.enc.json");
    const sopsConfigPath = path.join(tempRoot, ".sops.yaml");
    const ageKeyPath = path.join(tempRoot, ".age-key.txt");

    try {
        await writeFileFs(sopsConfigPath, "creation_rules:\n", "utf8");
        await writeFileFs(ageKeyPath, "AGE-SECRET-KEY-1TEST\n", "utf8");

        const env = await deriveSopsCommandEnv(storePath, {});
        assert.equal(env.SOPS_CONFIG, sopsConfigPath);
        assert.equal(env.SOPS_AGE_KEY_FILE, ageKeyPath);
    } finally {
        await rm(tempRoot, { recursive: true, force: true });
    }
}

async function testRequestSecretFailsClosedWhenManagedStorePathInvalid() {
    const tempRoot = await mkdtemp(path.join(os.tmpdir(), "blindpass-invalid-store-"));
    const blockerPath = path.join(tempRoot, "blocked");
    const invalidStorePath = path.join(blockerPath, "secrets.enc.json");
    const harness = createSopsPassthroughExecHarness();

    try {
        await writeFileFs(blockerPath, "blocker", "utf8");

        await assert.rejects(
            () => persistManagedSecret({
                name: "invalid.path.secret",
                value: Buffer.from("v", "utf8"),
                env: {
                    ...process.env,
                    BLINDPASS_AUTO_PERSIST: "true",
                    BLINDPASS_STORE_PATH: invalidStorePath,
                },
                execFileFn: harness.execFileFn,
                stderr: { write() { } },
            }),
            /ENOTDIR|EEXIST|ENOENT/,
        );
    } finally {
        await rm(tempRoot, { recursive: true, force: true });
    }
}

async function testRuntimeOnlySecretsAreNotInManagedListOrResolver() {
    const tempRoot = await mkdtemp(path.join(os.tmpdir(), "blindpass-runtime-only-"));
    const storePath = path.join(tempRoot, "blindpass", "secrets.enc.json");
    const harness = createSopsPassthroughExecHarness();

    try {
        const api = createMockApi();
        await withEnv(
            {
                BLINDPASS_AUTO_PERSIST: "false",
                BLINDPASS_STORE_PATH: storePath,
            },
            async () => {
                register(api, {
                    requestSecretFlowFn: async ({ onSecretLink }) => {
                        await onSecretLink("https://secrets.example/r/runtime-only", "CODE-5");
                        return Buffer.from("runtime-only-value", "utf8");
                    },
                    cleanupFn: async () => { },
                });

                await getTool(api, "request_secret").execute(
                    "runtime-only-req",
                    {
                        description: "Runtime only",
                        secret_name: "runtime.only.secret",
                        channel_id: "telegram:123",
                    },
                    { sendText: async () => { } },
                );
            },
        );

        const listed = await listManagedSecretNames({
            env: {
                ...process.env,
                BLINDPASS_STORE_PATH: storePath,
            },
            runtimeMode: "openclaw",
            execFileFn: harness.execFileFn,
        });
        assert.equal(listed.names.length, 0);

        const response = await runResolver({
            argv: ["--store", storePath],
            stdin: createResolverStdin(JSON.stringify({
                protocolVersion: 1,
                provider: "blindpass",
                ids: ["runtime.only.secret"],
            })),
            readManagedSecretStoreFn: async () => ({
                document: {
                    secrets: {},
                },
            }),
        });
        assert.equal(response.response.errors["runtime.only.secret"]?.message, "not found");
    } finally {
        disposeStoredSecret("runtime.only.secret");
        await rm(tempRoot, { recursive: true, force: true });
    }
}

async function testManagedSecretRotationReplacesValueAtomically() {
    const tempRoot = await mkdtemp(path.join(os.tmpdir(), "blindpass-rotation-"));
    const storePath = path.join(tempRoot, "blindpass", "secrets.enc.json");
    const harness = createSopsPassthroughExecHarness();
    const env = {
        ...process.env,
        BLINDPASS_STORE_PATH: storePath,
        BLINDPASS_BACKUP_ACKNOWLEDGED: "true",
    };

    try {
        await storeManagedSecret({
            name: "rotating.secret",
            value: Buffer.from("first-value", "utf8"),
            env,
            runtimeMode: "openclaw",
            execFileFn: harness.execFileFn,
            stderr: { write() { } },
        });
        await storeManagedSecret({
            name: "rotating.secret",
            value: Buffer.from("second-value", "utf8"),
            env,
            runtimeMode: "openclaw",
            execFileFn: harness.execFileFn,
            stderr: { write() { } },
        });

        const store = await readManagedSecretStore({
            env,
            runtimeMode: "openclaw",
            execFileFn: harness.execFileFn,
        });
        assert.equal(store.document.secrets["rotating.secret"].value, "second-value");
    } finally {
        await rm(tempRoot, { recursive: true, force: true });
    }
}

async function testAtomicRenamePreservesStoreOnWriteFailure() {
    const tempRoot = await mkdtemp(path.join(os.tmpdir(), "blindpass-atomic-rename-"));
    const storePath = path.join(tempRoot, "blindpass", "secrets.enc.json");
    const harness = createSopsPassthroughExecHarness({
        failEncryptOnCallNumbers: [3],
    });
    const env = {
        ...process.env,
        BLINDPASS_STORE_PATH: storePath,
        BLINDPASS_BACKUP_ACKNOWLEDGED: "true",
    };

    try {
        await storeManagedSecret({
            name: "stable.secret",
            value: Buffer.from("stable-value", "utf8"),
            env,
            runtimeMode: "openclaw",
            execFileFn: harness.execFileFn,
            stderr: { write() { } },
        });

        await assert.rejects(
            () => storeManagedSecret({
                name: "broken.secret",
                value: Buffer.from("new-value", "utf8"),
                env,
                runtimeMode: "openclaw",
                execFileFn: harness.execFileFn,
                stderr: { write() { } },
            }),
            /simulated encrypt failure/,
        );

        const store = await readManagedSecretStore({
            env,
            runtimeMode: "openclaw",
            execFileFn: harness.execFileFn,
        });
        assert.equal(store.document.secrets["stable.secret"].value, "stable-value");
        assert.equal(store.document.secrets["broken.secret"], undefined);
    } finally {
        await rm(tempRoot, { recursive: true, force: true });
    }
}

async function testAuditLogsAreMetadataOnly() {
    const api = createMockApi();
    const captured = [];
    const originalInfo = console.info;

    try {
        console.info = (...args) => {
            captured.push(args.join(" "));
        };
        register(api, {
            requestSecretFlowFn: async ({ onSecretLink }) => {
                await onSecretLink("https://secrets.example/r/audit", "CODE-6");
                return Buffer.from("audit-secret-value", "utf8");
            },
            persistManagedSecretFn: async () => ({ persisted: true, storage: "managed" }),
            cleanupFn: async () => { },
        });

        await getTool(api, "request_secret").execute(
            "audit-1",
            {
                description: "Audit test",
                secret_name: "audit.secret",
                channel_id: "telegram:123",
            },
            { sendText: async () => { } },
        );

        assert.ok(captured.some((line) => line.includes("[blindpass][audit]")));
        assert.ok(captured.every((line) => !line.includes("audit-secret-value")));
        assert.ok(captured.every((line) => !line.includes("https://secrets.example/r/audit")));
    } finally {
        console.info = originalInfo;
        disposeStoredSecret("audit.secret");
    }
}

async function testMcpServerInitializeAndListTools() {
    const server = createMcpServer({
        runtime: {
            emitManagedStoreBootstrapReminderFn: async () => ({ emitted: false }),
        },
    });

    const initResponse = await handleMcpRpcRequest(server, {
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {},
    });
    assert.equal(initResponse.result.serverInfo.name, "blindpass");
    assert.ok(initResponse.result.capabilities.tools);

    const listResponse = await handleMcpRpcRequest(server, {
        jsonrpc: "2.0",
        id: 2,
        method: "tools/list",
        params: {},
    });
    const toolNames = listResponse.result.tools.map((tool) => tool.name);
    assert.ok(toolNames.includes("request_secret"));
    assert.ok(toolNames.includes("request_secret_exchange"));
    assert.ok(toolNames.includes("fulfill_secret_exchange"));
    assert.ok(toolNames.includes("list_secrets"));
    assert.ok(toolNames.includes("delete_secret"));
    assert.ok(toolNames.includes("confirm_delete_secret"));
    assert.equal(toolNames.includes("store_secret"), false, "store_secret should be hidden unless explicitly enabled");
}

async function testMcpServerStoreSecretToolGating() {
    await withEnv(
        {
            BLINDPASS_ENABLE_STORE_TOOL: "true",
        },
        async () => {
            const server = createMcpServer({
                runtime: {
                    emitManagedStoreBootstrapReminderFn: async () => ({ emitted: false }),
                },
            });

            const listResponse = await handleMcpRpcRequest(server, {
                jsonrpc: "2.0",
                id: 3,
                method: "tools/list",
                params: {},
            });
            const toolNames = listResponse.result.tools.map((tool) => tool.name);
            assert.ok(toolNames.includes("store_secret"));
        },
    );
}

async function testMcpServerToolsCallDelegatesToCoreTools() {
    const server = createMcpServer({
        runtime: {
            emitManagedStoreBootstrapReminderFn: async () => ({ emitted: false }),
            listManagedSecretNamesFn: async () => ({
                names: ["alpha.secret", "beta.secret"],
            }),
        },
    });

    const callResponse = await handleMcpRpcRequest(server, {
        jsonrpc: "2.0",
        id: 4,
        method: "tools/call",
        params: {
            name: "list_secrets",
            arguments: {},
        },
    });

    assert.equal(callResponse.error, undefined);
    const text = callResponse.result?.content?.[0]?.text ?? "";
    assert.match(text, /Managed secrets listed successfully/);
    assert.match(text, /alpha\.secret/);
    assert.match(text, /beta\.secret/);
}

async function testMcpServerUnknownMethodsAndTools() {
    const server = createMcpServer({
        runtime: {
            emitManagedStoreBootstrapReminderFn: async () => ({ emitted: false }),
        },
    });

    const unknownMethod = await handleMcpRpcRequest(server, {
        jsonrpc: "2.0",
        id: 5,
        method: "unknown/method",
        params: {},
    });
    assert.equal(unknownMethod.error.code, -32601);

    const unknownTool = await handleMcpRpcRequest(server, {
        jsonrpc: "2.0",
        id: 6,
        method: "tools/call",
        params: {
            name: "not_a_real_tool",
            arguments: {},
        },
    });
    assert.equal(unknownTool.error, undefined);
    assert.equal(unknownTool.result?.isError, true);
    assert.match(unknownTool.result?.content?.[0]?.text ?? "", /Unknown tool/);
}

async function testMcpManagedModeResponsesRemainMetadataOnly() {
    await withEnv(
        {
            BLINDPASS_ALLOW_EXPOSE_PLAINTEXT: "false",
        },
        async () => {
            const capturedLogs = [];
            const originalInfo = console.info;
            console.info = (...args) => {
                capturedLogs.push(args.join(" "));
            };

            try {
                const server = createMcpServer({
                    runtime: {
                        emitManagedStoreBootstrapReminderFn: async () => ({ emitted: false }),
                        requestSecretFlowFn: async ({ onSecretLink }) => {
                            await onSecretLink("https://secrets.example/r/mcp-managed", "CODE-MCP");
                            return Buffer.from("mcp-managed-secret-value", "utf8");
                        },
                        requestExchangeFlowFn: async ({ secretName, fulfillerId }) => ({
                            exchangeId: "mcp-ex-1",
                            fulfilledBy: fulfillerId,
                            secret: Buffer.from(`exchange-${secretName}-value`, "utf8"),
                        }),
                        persistManagedSecretFn: async () => ({ persisted: true, storage: "managed" }),
                    },
                });

                const requestSecretResponse = await handleMcpRpcRequest(server, {
                    jsonrpc: "2.0",
                    id: 7,
                    method: "tools/call",
                    params: {
                        name: "request_secret",
                        arguments: {
                            description: "MCP managed flow",
                            secret_name: "mcp.secret",
                            persist: true,
                            channel_id: "telegram:123",
                        },
                        context: {
                            sendText: async () => { },
                        },
                    },
                });
                const requestSecretText = requestSecretResponse.result?.content?.[0]?.text ?? "";
                assert.match(requestSecretText, /managed encrypted storage/);
                assert.ok(!requestSecretText.includes("mcp-managed-secret-value"));

                const requestExchangeResponse = await handleMcpRpcRequest(server, {
                    jsonrpc: "2.0",
                    id: 8,
                    method: "tools/call",
                    params: {
                        name: "request_secret_exchange",
                        arguments: {
                            secret_name: "mcp.exchange.secret",
                            purpose: "exchange flow",
                            fulfiller_id: "agent:payments",
                            persist: true,
                        },
                    },
                });
                const requestExchangeText = requestExchangeResponse.result?.content?.[0]?.text ?? "";
                assert.match(requestExchangeText, /managed encrypted storage/);
                assert.ok(!requestExchangeText.includes("exchange-mcp.exchange.secret-value"));

                assert.ok(capturedLogs.some((line) => line.includes("[blindpass][audit]")));
                assert.ok(capturedLogs.every((line) => !line.includes("mcp-managed-secret-value")));
                assert.ok(capturedLogs.every((line) => !line.includes("exchange-mcp.exchange.secret-value")));
            } finally {
                console.info = originalInfo;
            }
        },
    );
}

async function testMcpToolsEnforcePersistValidationInHandlers() {
    const server = createMcpServer({
        runtime: {
            emitManagedStoreBootstrapReminderFn: async () => ({ emitted: false }),
        },
    });

    const requestSecretResponse = await handleMcpRpcRequest(server, {
        jsonrpc: "2.0",
        id: 9,
        method: "tools/call",
        params: {
            name: "request_secret",
            arguments: {
                description: "Missing name",
                persist: true,
            },
            context: {
                sendText: async () => { },
            },
        },
    });
    assert.match(requestSecretResponse.result?.content?.[0]?.text ?? "", /secret_name is required when persist=true/);

    const requestExchangeResponse = await handleMcpRpcRequest(server, {
        jsonrpc: "2.0",
        id: 10,
        method: "tools/call",
        params: {
            name: "request_secret_exchange",
            arguments: {
                purpose: "Missing name",
                fulfiller_id: "agent:payments",
                persist: true,
            },
        },
    });
    assert.match(requestExchangeResponse.result?.content?.[0]?.text ?? "", /secret_name is required when persist=true/);
}

async function testClaudeConfigLaunchesMcpServer() {
    await runMcpLaunchSmokeFromConfig(AGENT_CONFIG_FIXTURES.claude);
}

async function testCodexConfigLaunchesMcpServer() {
    await runMcpLaunchSmokeFromConfig(AGENT_CONFIG_FIXTURES.codex);
}

async function testAntigravityConfigLaunchesMcpServer() {
    await runMcpLaunchSmokeFromConfig(AGENT_CONFIG_FIXTURES.antigravity);
}

function createResolverStdin(payload) {
    const stream = new PassThrough();
    stream.end(payload);
    return stream;
}

async function testResolverParsesProtocolRequest() {
    const parsed = parseProtocolRequest(
        JSON.stringify({
            protocolVersion: 1,
            provider: "blindpass",
            ids: ["stripe.api_key.prod", "aws.token"],
        }),
    );

    assert.equal(parsed.provider, "blindpass");
    assert.deepEqual(parsed.ids, ["stripe.api_key.prod", "aws.token"]);
}

async function testResolverRejectsMalformedProtocolRequest() {
    assert.throws(
        () => parseProtocolRequest("{not-json"),
        /Invalid JSON payload/,
    );

    assert.throws(
        () => parseProtocolRequest(JSON.stringify({ protocolVersion: 1, ids: ["", "ok"] })),
        /Secret IDs cannot be empty/,
    );
}

async function testResolverResolvesBatchValuesAndErrors() {
    const response = resolveSecretEntries(
        ["stripe.api_key.prod", "missing.secret", "expired.secret"],
        {
            secrets: {
                "stripe.api_key.prod": {
                    value: "sk_live_123",
                },
                "expired.secret": {
                    value: "old-value",
                    expires_at: "2000-01-01T00:00:00.000Z",
                },
            },
        },
        new Date("2026-04-17T00:00:00.000Z"),
    );

    assert.equal(response.protocolVersion, 1);
    assert.equal(response.values["stripe.api_key.prod"], "sk_live_123");
    assert.equal(response.errors["missing.secret"]?.message, "not found");
    assert.equal(response.errors["expired.secret"]?.message, "expired");
}

async function testResolverReturnsProtocolSafeErrorForMalformedInput() {
    const { exitCode, response } = await runResolver({
        argv: [],
        stdin: createResolverStdin("{not-json"),
        readManagedSecretStoreFn: async () => {
            throw new Error("should not be called");
        },
    });

    assert.equal(exitCode, 0);
    assert.equal(response.protocolVersion, 1);
    assert.equal(response.values && Object.keys(response.values).length, 0);
    assert.equal(response.errors.__request__.message, "Invalid JSON payload.");
}

async function testResolverSupportsStoreOverrideAndBatchLookup() {
    const calls = [];
    const payload = JSON.stringify({
        protocolVersion: 1,
        provider: "blindpass",
        ids: ["stripe.api_key.prod", "db.password", "missing.secret"],
    });

    const { exitCode, response } = await runResolver({
        argv: ["--store", "/tmp/custom-secrets.enc.json"],
        stdin: createResolverStdin(payload),
        readManagedSecretStoreFn: async (options) => {
            calls.push(options);
            return {
                document: {
                    secrets: {
                        "stripe.api_key.prod": { value: "sk_live_abc" },
                        "db.password": { value: "db-secret-1" },
                    },
                },
            };
        },
    });

    assert.equal(exitCode, 0);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].storePath, "/tmp/custom-secrets.enc.json");
    assert.equal(response.values["stripe.api_key.prod"], "sk_live_abc");
    assert.equal(response.values["db.password"], "db-secret-1");
    assert.equal(response.errors["missing.secret"]?.message, "not found");
}

async function testResolverTimeoutReturnsProtocolSafeError() {
    const payload = JSON.stringify({
        protocolVersion: 1,
        provider: "blindpass",
        ids: ["stripe.api_key.prod"],
    });

    const { exitCode, response } = await runResolver({
        argv: [],
        env: {
            ...process.env,
            BLINDPASS_RESOLVER_TIMEOUT_MS: "5",
        },
        stdin: createResolverStdin(payload),
        readManagedSecretStoreFn: async () => new Promise((resolve) => {
            setTimeout(() => {
                resolve({
                    document: {
                        secrets: {},
                    },
                });
            }, 50);
        }),
    });

    assert.equal(exitCode, 0);
    assert.equal(response.protocolVersion, 1);
    assert.match(response.errors.__request__.message, /timed out/);
}

async function testResolverCorruptStoreFailsClosedWithoutLeakage() {
    const payload = JSON.stringify({
        protocolVersion: 1,
        provider: "blindpass",
        ids: ["stripe.api_key.prod"],
    });

    const { exitCode, response } = await runResolver({
        argv: [],
        stdin: createResolverStdin(payload),
        readManagedSecretStoreFn: async () => {
            throw new Error("Unexpected token s in JSON at position 0 while parsing secret_value=sk_live_should_not_leak");
        },
    });

    assert.equal(exitCode, 0);
    assert.equal(response.protocolVersion, 1);
    assert.equal(response.errors.__request__.message, "Corrupt managed store contents.");
    assert.ok(!response.errors.__request__.message.includes("sk_live_should_not_leak"));
}

async function testResolverStoreReadFailureIsSanitized() {
    const payload = JSON.stringify({
        protocolVersion: 1,
        provider: "blindpass",
        ids: ["stripe.api_key.prod"],
    });

    const { exitCode, response } = await runResolver({
        argv: [],
        stdin: createResolverStdin(payload),
        readManagedSecretStoreFn: async () => {
            throw new Error("exit=1 stderr=sops: failed with AGE-SECRET-KEY-1SENSITIVE");
        },
    });

    assert.equal(exitCode, 0);
    assert.equal(response.protocolVersion, 1);
    assert.equal(response.errors.__request__.message, "Managed store read failed.");
    assert.ok(!response.errors.__request__.message.includes("AGE-SECRET-KEY"));
}

async function testManagedStoreAutoBootstrapCreatesArtifacts() {
    const tempRoot = await mkdtemp(path.join(os.tmpdir(), "blindpass-managed-store-"));
    const storePath = path.join(tempRoot, "blindpass", "secrets.enc.json");
    const harness = createSopsPassthroughExecHarness();
    let stderrOutput = "";

    try {
        const result = await persistManagedSecret({
            name: "stripe.api_key.prod",
            value: Buffer.from("sk_live_123", "utf8"),
            env: {
                ...process.env,
                BLINDPASS_AUTO_PERSIST: "true",
                BLINDPASS_STORE_PATH: storePath,
            },
            execFileFn: harness.execFileFn,
            now: new Date("2026-04-17T02:00:00.000Z"),
            stderr: {
                write(chunk) {
                    stderrOutput += String(chunk);
                },
            },
        });

        assert.equal(result.persisted, true);
        assert.equal(result.bootstrapped, true);
        assert.equal(result.bootstrapBackupPending, true);

        const ageKeyPath = path.join(path.dirname(storePath), ".age-key.txt");
        const sopsConfigPath = path.join(path.dirname(storePath), ".sops.yaml");
        const ageKeyText = await readFileFs(ageKeyPath, "utf8");
        const sopsConfigText = await readFileFs(sopsConfigPath, "utf8");

        assert.match(ageKeyText, /AGE-SECRET-KEY-/);
        assert.match(sopsConfigText, /creation_rules:/);
        assert.match(sopsConfigText, /secrets\\.enc\\.json/);

        const store = await readManagedSecretStore({
            env: {
                ...process.env,
                BLINDPASS_STORE_PATH: storePath,
            },
            execFileFn: harness.execFileFn,
        });

        assert.equal(store.document.metadata.bootstrap_backup_pending, true);
        assert.equal(store.document.metadata.bootstrap_public_key, harness.agePublicKey);
        assert.equal(store.document.secrets["stripe.api_key.prod"].value, "sk_live_123");
        assert.match(stderrOutput, /Managed store bootstrap initialized/);
        assert.match(stderrOutput, new RegExp(storePath.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
    } finally {
        await rm(tempRoot, { recursive: true, force: true });
    }
}

async function testManagedStoreReminderAndBackupAckFlow() {
    const tempRoot = await mkdtemp(path.join(os.tmpdir(), "blindpass-managed-store-reminder-"));
    const storePath = path.join(tempRoot, "blindpass", "secrets.enc.json");
    const harness = createSopsPassthroughExecHarness();

    try {
        await persistManagedSecret({
            name: "aws.token",
            value: Buffer.from("token-1", "utf8"),
            env: {
                ...process.env,
                BLINDPASS_AUTO_PERSIST: "true",
                BLINDPASS_STORE_PATH: storePath,
            },
            execFileFn: harness.execFileFn,
            now: new Date("2026-04-17T03:00:00.000Z"),
            stderr: { write() { } },
        });

        let reminderOutput = "";
        const reminderResult = await emitManagedStoreBootstrapReminder({
            env: {
                ...process.env,
                BLINDPASS_AUTO_PERSIST: "true",
                BLINDPASS_STORE_PATH: storePath,
            },
            execFileFn: harness.execFileFn,
            stderr: {
                write(chunk) {
                    reminderOutput += String(chunk);
                },
            },
        });

        assert.equal(reminderResult.emitted, true);
        assert.match(reminderOutput, /backup is still pending/);

        const ackResult = await emitManagedStoreBootstrapReminder({
            env: {
                ...process.env,
                BLINDPASS_AUTO_PERSIST: "true",
                BLINDPASS_STORE_PATH: storePath,
                BLINDPASS_BACKUP_ACKNOWLEDGED: "true",
            },
            execFileFn: harness.execFileFn,
            stderr: { write() { } },
            now: new Date("2026-04-17T03:01:00.000Z"),
        });

        assert.equal(ackResult.emitted, false);
        assert.equal(ackResult.acknowledged, true);

        const store = await readManagedSecretStore({
            env: {
                ...process.env,
                BLINDPASS_STORE_PATH: storePath,
            },
            execFileFn: harness.execFileFn,
        });
        assert.equal(store.document.metadata.bootstrap_backup_pending, false);
        assert.ok(store.document.metadata.bootstrap_backup_acknowledged_at);
    } finally {
        await rm(tempRoot, { recursive: true, force: true });
    }
}

async function testManagedStoreConcurrentWritesDoNotLoseData() {
    const tempRoot = await mkdtemp(path.join(os.tmpdir(), "blindpass-managed-store-concurrency-"));
    const storePath = path.join(tempRoot, "blindpass", "secrets.enc.json");
    const harness = createSopsPassthroughExecHarness({
        encryptDelayMs: 30,
        decryptDelayMs: 30,
    });
    const env = {
        ...process.env,
        BLINDPASS_AUTO_PERSIST: "true",
        BLINDPASS_STORE_PATH: storePath,
        BLINDPASS_BACKUP_ACKNOWLEDGED: "true",
    };

    try {
        await Promise.all([
            persistManagedSecret({
                name: "stripe.api_key.prod",
                value: Buffer.from("sk_live_aaa", "utf8"),
                env,
                execFileFn: harness.execFileFn,
                stderr: { write() { } },
            }),
            persistManagedSecret({
                name: "db.password",
                value: Buffer.from("db-secret-bbb", "utf8"),
                env,
                execFileFn: harness.execFileFn,
                stderr: { write() { } },
            }),
        ]);

        const store = await readManagedSecretStore({
            env,
            execFileFn: harness.execFileFn,
        });
        assert.equal(store.document.secrets["stripe.api_key.prod"].value, "sk_live_aaa");
        assert.equal(store.document.secrets["db.password"].value, "db-secret-bbb");
    } finally {
        await rm(tempRoot, { recursive: true, force: true });
    }
}

async function testManagedStoreReusesBootstrapArtifactsOnSubsequentWrites() {
    const tempRoot = await mkdtemp(path.join(os.tmpdir(), "blindpass-managed-store-bootstrap-reuse-"));
    const storePath = path.join(tempRoot, "blindpass", "secrets.enc.json");
    const harness = createSopsPassthroughExecHarness();
    const env = {
        ...process.env,
        BLINDPASS_AUTO_PERSIST: "true",
        BLINDPASS_STORE_PATH: storePath,
    };

    try {
        await persistManagedSecret({
            name: "first.secret",
            value: Buffer.from("first", "utf8"),
            env,
            execFileFn: harness.execFileFn,
            stderr: { write() { } },
        });
        await persistManagedSecret({
            name: "second.secret",
            value: Buffer.from("second", "utf8"),
            env,
            execFileFn: harness.execFileFn,
            stderr: { write() { } },
        });

        const ageKeygenCalls = harness.state.calls.filter((call) => call.file === "age-keygen" && call.args.length === 0);
        assert.equal(ageKeygenCalls.length, 1, "age-keygen should only run during first bootstrap");
    } finally {
        await rm(tempRoot, { recursive: true, force: true });
    }
}

async function testManagedStoreWriteFailsWhenLiveLockHeld() {
    const tempRoot = await mkdtemp(path.join(os.tmpdir(), "blindpass-managed-store-lock-live-"));
    const storePath = path.join(tempRoot, "blindpass", "secrets.enc.json");
    const lockPath = `${storePath}.lock`;
    const harness = createSopsPassthroughExecHarness();
    const env = {
        ...process.env,
        BLINDPASS_AUTO_PERSIST: "true",
        BLINDPASS_STORE_PATH: storePath,
        BLINDPASS_BACKUP_ACKNOWLEDGED: "true",
    };

    try {
        await persistManagedSecret({
            name: "seed.secret",
            value: Buffer.from("seed", "utf8"),
            env,
            execFileFn: harness.execFileFn,
            stderr: { write() { } },
        });

        await writeFileFs(lockPath, JSON.stringify({ pid: 424242, created_at: "2026-04-17T03:10:00.000Z" }), "utf8");

        await assert.rejects(
            () => persistManagedSecret({
                name: "new.secret",
                value: Buffer.from("new", "utf8"),
                env,
                execFileFn: harness.execFileFn,
                lockTimeoutMs: 80,
                lockRetryMs: 10,
                pidCheckFn: () => "alive",
                stderr: { write() { } },
            }),
            /Could not acquire within 80ms/,
        );
    } finally {
        await rm(tempRoot, { recursive: true, force: true });
    }
}

async function testManagedStoreBreaksStaleLockAndTreatsUnknownAsLive() {
    const tempRoot = await mkdtemp(path.join(os.tmpdir(), "blindpass-managed-store-lock-stale-"));
    const storePath = path.join(tempRoot, "blindpass", "secrets.enc.json");
    const lockPath = `${storePath}.lock`;
    const harness = createSopsPassthroughExecHarness();
    const env = {
        ...process.env,
        BLINDPASS_AUTO_PERSIST: "true",
        BLINDPASS_STORE_PATH: storePath,
        BLINDPASS_BACKUP_ACKNOWLEDGED: "true",
    };

    try {
        await persistManagedSecret({
            name: "seed.secret",
            value: Buffer.from("seed", "utf8"),
            env,
            execFileFn: harness.execFileFn,
            stderr: { write() { } },
        });

        await writeFileFs(lockPath, JSON.stringify({ pid: 11111, created_at: "2026-04-17T03:20:00.000Z" }), "utf8");
        await persistManagedSecret({
            name: "stale.lock.secret",
            value: Buffer.from("fresh", "utf8"),
            env,
            execFileFn: harness.execFileFn,
            lockTimeoutMs: 120,
            lockRetryMs: 10,
            pidCheckFn: () => "stale",
            stderr: { write() { } },
        });

        const storeAfterStaleBreak = await readManagedSecretStore({
            env,
            execFileFn: harness.execFileFn,
        });
        assert.equal(storeAfterStaleBreak.document.secrets["stale.lock.secret"].value, "fresh");

        await writeFileFs(lockPath, JSON.stringify({ pid: 22222, created_at: "2026-04-17T03:21:00.000Z" }), "utf8");
        await assert.rejects(
            () => persistManagedSecret({
                name: "unknown.lock.secret",
                value: Buffer.from("x", "utf8"),
                env,
                execFileFn: harness.execFileFn,
                lockTimeoutMs: 80,
                lockRetryMs: 10,
                pidCheckFn: () => "unknown",
                stderr: { write() { } },
            }),
            /Could not acquire within 80ms/,
        );
    } finally {
        await rm(tempRoot, { recursive: true, force: true });
    }
}

const tests = [
    {
        name: "request_secret does not return plaintext and stores secret in memory",
        run: testNoPlaintextExposure,
    },
    {
        name: "request_secret fails closed when managed backend is unsupported",
        run: testRequestSecretFailsClosedWhenManagedBackendUnsupported,
    },
    {
        name: "request_secret uses managed encrypted persistence when configured",
        run: testRequestSecretUsesManagedPersistenceWhenConfigured,
    },
    {
        name: "request_secret formats message correctly for re_request: true",
        run: testReRequestFormat,
    },
    {
        name: "request_secret uses OpenClaw CLI fallback",
        run: testUsesOpenClawCliFallback,
    },
    {
        name: "request_secret uses sendMessage when sendText is unavailable",
        run: testUsesSendMessageWhenSendTextMissing,
    },
    {
        name: "request_secret fails when no outbound transport is available",
        run: testFailsWhenNoTransportAvailable,
    },
    {
        name: "request_secret uses api.runtime.channel when other transports are unavailable",
        run: testUsesRuntimeChannelWhenOtherTransportsMissing,
    },
    {
        name: "request_secret does not log live secret URLs",
        run: testDoesNotLogSecretUrls,
    },
    {
        name: "shutdown hook disposes in-memory secrets",
        run: testShutdownDisposesSecrets,
    },
    {
        name: "requestSecretFlow publishes a JWKS when using JWT auth fallback",
        run: testRequestSecretFlowPublishesJwksForJwtAuth,
    },
    {
        name: "requestSecretFlow surfaces 429 without retry and destroys its key pair",
        run: testRequestSecretFlowSurfacesRateLimitAndDestroysKeyPair,
    },
    {
        name: "fulfill_secret_exchange uses the stored runtime secret",
        run: testFulfillSecretExchangeUsesStoredSecret,
    },
    {
        name: "request_secret_exchange uses OpenClaw transport and stores the exchanged secret",
        run: testRequestSecretExchangeUsesOpenClawTransportAndStoresSecret,
    },
    {
        name: "request_secret_exchange fails closed when no target can be resolved",
        run: testRequestSecretExchangeFailsClosedWhenTargetCannotBeResolved,
    },
    {
        name: "createOpenClawAgentTransport uses runtime agent messaging when available",
        run: testCreateOpenClawAgentTransportUsesRuntimeAgentChannel,
    },
    {
        name: "resolveOpenClawAgentTarget uses explicit target maps",
        run: testResolveOpenClawAgentTargetUsesConfiguredMap,
    },
    {
        name: "resolveOpenClawAgentTarget uses runtime session resolvers",
        run: testResolveOpenClawAgentTargetUsesRuntimeResolver,
    },
    {
        name: "resolveOpenClawAgentTarget uses OPENCLAW_AGENT_TARGETS_JSON",
        run: testResolveOpenClawAgentTargetUsesEnvMap,
    },
    {
        name: "createOpenClawAgentTransport uses mapped agent targets before fallback",
        run: testCreateOpenClawAgentTransportUsesAgentTargetMapBeforeFallback,
    },
    {
        name: "buildExchangeDeliveryMessage includes fulfill tool instructions",
        run: testBuildExchangeDeliveryMessageIncludesToolCall,
    },
    {
        name: "store_secret tool is disabled by default while list/delete tools remain available",
        run: testStoreSecretToolIsDisabledByDefault,
    },
    {
        name: "store_secret can be enabled and stores metadata only",
        run: testStoreSecretToolCanBeEnabledAndStoresMetadataOnly,
    },
    {
        name: "store_secret fails closed when managed store is unavailable",
        run: testStoreSecretFailsClosedWhenManagedStoreUnavailable,
    },
    {
        name: "list_secrets returns managed secret names only",
        run: testListSecretsReturnsOnlyNames,
    },
    {
        name: "delete_secret requires confirmation token and tokens are single-use",
        run: testDeleteSecretRequiresConfirmationAndSingleUseToken,
    },
    {
        name: "confirm_delete_secret rejects mismatched and expired tokens",
        run: testConfirmDeleteSecretRejectsMismatchedAndExpiredTokens,
    },
    {
        name: "request_secret supports interactive-only persist=false mode",
        run: testRequestSecretPersistFalseSkipsManagedPersistence,
    },
    {
        name: "request_secret rejects persist=true when secret_name is missing",
        run: testRequestSecretRejectsPersistTrueWithoutSecretName,
    },
    {
        name: "request_secret_exchange rejects persist=true when secret_name is missing",
        run: testRequestSecretExchangeRejectsPersistTrueWithoutSecretName,
    },
    {
        name: "request_secret managed mode returns metadata only by default",
        run: testRequestSecretManagedModeMetadataOnlyByDefault,
    },
    {
        name: "request_secret plaintext exposure is controlled only by deployment env",
        run: testRequestSecretPlaintextExposureControlledByEnvOnly,
    },
    {
        name: "managed store config selects runtime-specific default paths and respects overrides",
        run: testManagedStorePathSelectionAndOverrides,
    },
    {
        name: "deriveSopsCommandEnv resolves sibling bootstrap files",
        run: testDeriveSopsCommandEnvFromStoreSiblingFiles,
    },
    {
        name: "managed persistence fails closed when configured store path is invalid",
        run: testRequestSecretFailsClosedWhenManagedStorePathInvalid,
    },
    {
        name: "runtime-only secrets are isolated from managed listing and resolver reads",
        run: testRuntimeOnlySecretsAreNotInManagedListOrResolver,
    },
    {
        name: "managed secret rotation replaces value atomically",
        run: testManagedSecretRotationReplacesValueAtomically,
    },
    {
        name: "atomic rename preserves store when a write fails",
        run: testAtomicRenamePreservesStoreOnWriteFailure,
    },
    {
        name: "audit logging remains metadata-only without secret leakage",
        run: testAuditLogsAreMetadataOnly,
    },
    {
        name: "mcp-server initialize and tools/list expose the expected default toolset",
        run: testMcpServerInitializeAndListTools,
    },
    {
        name: "mcp-server tools/list includes store_secret only when explicitly enabled",
        run: testMcpServerStoreSecretToolGating,
    },
    {
        name: "mcp-server tools/call delegates to blindpass-core handlers",
        run: testMcpServerToolsCallDelegatesToCoreTools,
    },
    {
        name: "mcp-server returns expected responses for unknown methods and tools",
        run: testMcpServerUnknownMethodsAndTools,
    },
    {
        name: "mcp managed-mode tool responses and logs remain metadata-only",
        run: testMcpManagedModeResponsesRemainMetadataOnly,
    },
    {
        name: "mcp tools enforce handler-side persist validation",
        run: testMcpToolsEnforcePersistValidationInHandlers,
    },
    {
        name: "Claude profile MCP config launches the server",
        run: testClaudeConfigLaunchesMcpServer,
    },
    {
        name: "Codex/OpenAI profile MCP config launches the server",
        run: testCodexConfigLaunchesMcpServer,
    },
    {
        name: "Antigravity/Gemini profile MCP config launches the server",
        run: testAntigravityConfigLaunchesMcpServer,
    },
    {
        name: "blindpass-resolver parses protocol request payloads",
        run: testResolverParsesProtocolRequest,
    },
    {
        name: "blindpass-resolver rejects malformed protocol request payloads",
        run: testResolverRejectsMalformedProtocolRequest,
    },
    {
        name: "blindpass-resolver resolves batch values and returns missing/expired errors",
        run: testResolverResolvesBatchValuesAndErrors,
    },
    {
        name: "blindpass-resolver returns protocol-safe errors for malformed stdin",
        run: testResolverReturnsProtocolSafeErrorForMalformedInput,
    },
    {
        name: "blindpass-resolver honors --store override and batch lookup",
        run: testResolverSupportsStoreOverrideAndBatchLookup,
    },
    {
        name: "blindpass-resolver enforces timeout with protocol-safe error output",
        run: testResolverTimeoutReturnsProtocolSafeError,
    },
    {
        name: "blindpass-resolver fails closed on corrupt managed store without leaking content",
        run: testResolverCorruptStoreFailsClosedWithoutLeakage,
    },
    {
        name: "blindpass-resolver sanitizes managed-store read failures",
        run: testResolverStoreReadFailureIsSanitized,
    },
    {
        name: "managed store auto-bootstrap creates artifacts and pending-backup metadata",
        run: testManagedStoreAutoBootstrapCreatesArtifacts,
    },
    {
        name: "managed store emits backup reminders and supports env acknowledgment",
        run: testManagedStoreReminderAndBackupAckFlow,
    },
    {
        name: "managed store concurrent writes do not lose secret data",
        run: testManagedStoreConcurrentWritesDoNotLoseData,
    },
    {
        name: "managed store reuses bootstrap artifacts after first initialization",
        run: testManagedStoreReusesBootstrapArtifactsOnSubsequentWrites,
    },
    {
        name: "managed store write fails closed when a live lock is held",
        run: testManagedStoreWriteFailsWhenLiveLockHeld,
    },
    {
        name: "managed store breaks stale lock but treats unknown pid status as live",
        run: testManagedStoreBreaksStaleLockAndTreatsUnknownAsLive,
    },
];

let failures = 0;

for (const t of tests) {
    try {
        await t.run();
        console.log(`ok - ${t.name}`);
    } catch (err) {
        failures += 1;
        console.error(`not ok - ${t.name}`);
        console.error(err);
    }
}

if (failures > 0) {
    process.exitCode = 1;
}
