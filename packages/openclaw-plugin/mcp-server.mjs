// SPDX-License-Identifier: MIT
import { realpathSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';
import registerBlindPassTools from './index.mjs';
import { brokerIdentityFromEnvironment, createBrokerClient } from '../mcp-server/src/broker-client.mjs';
import { createMcpServer as createSdkServer, runMcpServerStdio as runSdkStdio } from '../mcp-server/src/index.mjs';

// Trusted embeddings can expose their own protocol callbacks without loading
// the legacy tool registry. These exports contain only the existing MIT SDK API.
export { createSdkServer as createProtocolServer, runSdkStdio as runProtocolStdio,
    brokerIdentityFromEnvironment, createBrokerClient };
export { createDeliveryRouter, createUrlElicitationProvider } from '../mcp-server/src/deliver.mjs';

// Fleet mode (a broker client/identity is present) must not keep the legacy
// exposure switches (P05-D8, M07). The legacy request tool can route a secure
// link to an arbitrary chat (channel_id/channel/target/chat_id) and print it raw
// (raw_link); two environment switches have the same effect for every call.
// In fleet mode startup refuses either switch and the adapter drops these
// parameters from every legacy schema and rejects calls that still carry them.
const FLEET_FORBIDDEN_PARAMETERS = Object.freeze(['raw_link', 'channel_id', 'channel', 'target', 'chat_id']);
const FLEET_FORBIDDEN_ENVIRONMENT = Object.freeze(['OPENCLAW_SECRETS_RAW_LINK', 'BLINDPASS_ALLOW_EXPOSE_PLAINTEXT']);
const FALSY = /^(?:0|false|no|off)?$/i;
const FLEET_FAILURE = Object.freeze({ isError: true, content: [{ type: 'text', text: 'Operation failed' }] });
// A switch counts as set unless it is absent, empty or an explicit false value.
// Unrecognised text is refused too: fail closed, and never echo the value.
function assertNoExposureSwitches(env) {
    for (const name of FLEET_FORBIDDEN_ENVIRONMENT) {
        const value = env?.[name];
        if (value !== undefined && !(typeof value === 'string' && FALSY.test(value.trim()))) throw new Error('invalid_startup');
    }
}
function fleetSchema(parameters) {
    const properties = { ...parameters?.properties };
    for (const name of FLEET_FORBIDDEN_PARAMETERS) delete properties[name];
    const required = Array.isArray(parameters?.required) ? parameters.required.filter((name) => !FLEET_FORBIDDEN_PARAMETERS.includes(name)) : undefined;
    return { type: 'object', ...parameters, properties, ...(required ? { required } : {}), additionalProperties: false };
}

// This wrapper owns the MIT legacy plugin adapter. The SDK package receives
// trusted callbacks and never imports the plugin, helper or AGPL server code.
export function createMcpOptions(options = {}) {
    const fleet = options.brokerClient !== undefined;
    if (fleet) assertNoExposureSwitches(options.env ?? process.env);
    const tools = []; const names = new Set();
    registerBlindPassTools({
        registerTool(tool) {
            if (!tool?.name || typeof tool.execute !== 'function' || names.has(tool.name)) throw new Error('invalid_tool_configuration');
            names.add(tool.name);
            tools.push({ name: tool.name, description: tool.description ?? '',
                inputSchema: fleet ? fleetSchema(tool.parameters) : { type: 'object', properties: {}, ...tool.parameters, additionalProperties: false },
                async execute(args, context) {
                    if (fleet && args && typeof args === 'object'
                        && FLEET_FORBIDDEN_PARAMETERS.some((name) => Object.hasOwn(args, name))) {
                        return { isError: FLEET_FAILURE.isError, content: FLEET_FAILURE.content.map((item) => ({ ...item })) };
                    }
                    const result = await tool.execute(`${tool.name}-${randomUUID()}`, args, { ...context, ...options.toolContext });
                    // Existing legacy catch blocks return "Failed ..." text
                    // without isError. Mark these before the SDK boundary so
                    // upstream links/codes cannot become normal tool content.
                    if (result?.content?.some((item) => item.type === 'text' && typeof item.text === 'string' && /^Failed(?:\s|:)/.test(item.text))) {
                        return { isError: true, content: [{ type: 'text', text: 'Operation failed' }] };
                    }
                    return result;
                },
            });
        },
        registerHook() { /* OpenClaw hooks are registered by its native plugin entrypoint. */ },
    }, { managedStoreRuntimeMode: 'mcp', ...options.runtime });
    return { tools, brokerClient: options.brokerClient, toolTimeoutMs: options.toolTimeoutMs, diagnostics: options.diagnostics };
}

export function createMcpServer(options = {}) { return createSdkServer(createMcpOptions(options)); }
export function runMcpServerStdio(options = {}, streams = {}) { return runSdkStdio(createMcpOptions(options), streams); }

export function main() {
    if (process.argv.length !== 2) throw new Error('invalid_startup');
    // Legacy handlers use console for notices and upstream errors. MCP stdout
    // belongs solely to the SDK; no private diagnostic is copied to stderr.
    for (const method of ['log', 'info', 'warn', 'error', 'debug', 'trace']) console[method] = () => {};
    const identity = brokerIdentityFromEnvironment();
    return runMcpServerStdio({ brokerClient: identity && createBrokerClient(identity) });
}
function normalizedEntryHref(entryPath) {
    if (!entryPath) return '';
    try { return pathToFileURL(realpathSync(entryPath)).href; }
    catch { return pathToFileURL(entryPath).href; }
}
if (normalizedEntryHref(fileURLToPath(import.meta.url)) === normalizedEntryHref(process.argv[1])) {
    try { main(); } catch { process.exitCode = 64; }
}
