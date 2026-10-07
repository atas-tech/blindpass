/**
 * SPS Bridge — thin wrapper combining:
 * - Gateway JWT issuance (for authenticating to SPS)
 * - SPS client calls (create request, poll, retrieve)
 * - HPKE key management (generate, decrypt, destroy)
 *
 * This module works both inside an OpenClaw plugin and standalone (for E2E tests).
 */

import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

// F-3 (owner decision 2026-10-07): the PUBLISHED bundle has no default SPS endpoint. scripts/build_bundle.sh
// passes --define:__BLINDPASS_REQUIRE_EXPLICIT_SPS__=true for the bundle only, so esbuild folds the conditional
// below to its first branch and the legacy default (inlined in the other branch, not a constant) leaves the
// artifact. In this unbundled source the identifier is undeclared, `typeof` yields "undefined", and the
// OpenClaw plugin keeps its legacy default unchanged.
export class SpsBaseUrlRequiredError extends Error {
    constructor() {
        super("SPS_BASE_URL is not set. This BlindPass build has no default endpoint, so nothing was sent. "
            + "Set SPS_BASE_URL to your controller's https URL and restart the client.");
        this.name = "SpsBaseUrlRequiredError";
    }
}

function requireExplicitSpsBaseUrl(env) {
    const configured = typeof env.SPS_BASE_URL === "string" ? env.SPS_BASE_URL.trim() : "";
    if (configured === "") throw new SpsBaseUrlRequiredError();
    return configured;
}

export function resolveSpsBaseUrl(env = process.env) {
    return typeof __BLINDPASS_REQUIRE_EXPLICIT_SPS__ !== "undefined" && __BLINDPASS_REQUIRE_EXPLICIT_SPS__ === true
        ? requireExplicitSpsBaseUrl(env)
        : env.SPS_BASE_URL ?? "https://sps.blindpass.dev";
}

// Dynamic imports so tests can override modules while production builds bundle
// these compiled workspace package outputs.
let _gatewayIdentity = null;
let _jwksPath = null;
let _tempDir = null;

/**
 * Lazy-load compiled workspace packages.
 * Callers can override individual modules via `opts` for testing.
 */
async function loadModules(opts = {}) {
    const identity = opts.identity ?? await import("../gateway/dist/identity.js");
    const keyManager = opts.keyManager ?? await import("../agent-skill/dist/key-manager.js");
    const AgentSkillRuntimeMod = opts.AgentSkillRuntimeModule ?? await import("../agent-skill/dist/index.js");
    const SpsClientMod = opts.SpsClientModule ?? await import("../agent-skill/dist/sps-client.js");
    const GatewaySpsClientMod = opts.GatewaySpsClientModule ?? await import("../gateway/dist/sps-client.js");

    return {
        identity,
        keyManager,
        AgentSecretRuntime: AgentSkillRuntimeMod.AgentSecretRuntime,
        SpsClient: SpsClientMod.SpsClient,
        GatewaySpsClient: GatewaySpsClientMod.GatewaySpsClient,
    };
}

function resolveAgentId(agentId) {
    return agentId ?? process.env.BLINDPASS_AGENT_ID ?? process.env.OPENCLAW_AGENT_ID ?? "blindpass-agent";
}

/**
 * Initialize gateway identity (generates ephemeral keys in a temp dir if no keyPath provided).
 */
async function ensureIdentity(identity, opts = {}) {
    if (_gatewayIdentity) return _gatewayIdentity;

    if (!opts.keyPath) {
        const envKeyPath = process.env.SPS_GATEWAY_KEY_FILE || process.env.GATEWAY_KEY_PATH;
        if (envKeyPath) {
            opts.keyPath = envKeyPath;
        } else {
            _tempDir = await mkdtemp(path.join(os.tmpdir(), "sps-plugin-"));
            opts.keyPath = path.join(_tempDir, "gateway-key.json");
        }
    }

    _gatewayIdentity = await identity.loadOrCreateGatewayIdentity(opts);

    if (typeof identity.writeJwksFile === "function") {
        try {
            _jwksPath = path.join(path.dirname(opts.keyPath), "jwks.json");
            await identity.writeJwksFile(_gatewayIdentity, _jwksPath);
        } catch (err) {
            console.warn(`[sps-bridge] Could not write JWKS file alongside key: ${err.message}`);
        }
    }

    return _gatewayIdentity;
}

let _cachedApiToken = null;
let _cachedApiTokenExpiresAt = 0;

/**
 * Gets an SPS authentication token either by exchanging an API Key or signing a Gateway JWT.
 */
async function getAgentAuthToken(modules, agentId, spsBaseUrl, identityOptions) {
    const apiKey = process.env.BLINDPASS_API_KEY?.trim() || process.env.SPS_AGENT_API_KEY?.trim();
    if (apiKey) {
        const nowMs = Date.now();
        if (_cachedApiToken && nowMs < _cachedApiTokenExpiresAt - (60 * 1000)) {
            return _cachedApiToken;
        }

        const url = `${spsBaseUrl.replace(/\/+$/, '')}/api/v2/agents/token`;
        const res = await fetch(url, {
            method: "POST",
            headers: { "x-agent-api-key": apiKey }
        });

        if (!res.ok) {
            const err = await res.text().catch(() => "");
            throw new Error(`Failed to exchange API key for token: ${res.status} ${err}`);
        }

        const data = await res.json();
        _cachedApiToken = data.access_token;
        _cachedApiTokenExpiresAt = typeof data.access_token_expires_at === "number" 
            ? data.access_token_expires_at * 1000 
            : nowMs + (55 * 60 * 1000);
            
        return _cachedApiToken;
    }

    const gwIdentity = await ensureIdentity(modules.identity, identityOptions);
    return await modules.identity.issueJwt(gwIdentity, agentId);
}

/**
 * Full request_secret flow:
 *   1. Generate HPKE keypair
 *   2. POST /request to SPS
 *   3. Return link info (caller sends it to the user via their channel)
 *   4. Poll until submitted
 *   5. Retrieve + decrypt
 *   6. Destroy keypair
 *
 * @param {object} params
 * @param {string} params.description - Human-readable description of what the secret is for
 * @param {string} params.spsBaseUrl - SPS server base URL
 * @param {Function} params.onSecretLink - Callback with (secretUrl, confirmationCode) for sending to user
 * @param {object} [params.moduleOverrides] - Override loaded modules for testing
 * @param {object} [params.identityOptions] - Options for gateway identity
 * @returns {Promise<Buffer>} The decrypted secret plaintext bytes
 */
export async function requestSecretFlow(params) {
    const {
        description,
        spsBaseUrl = resolveSpsBaseUrl(),
        onSecretLink,
        agentId,
        moduleOverrides = {},
        identityOptions = {},
    } = params;

    const modules = await loadModules(moduleOverrides);
    const resolvedAgentId = resolveAgentId(agentId);

    // 1. Generate HPKE keypair
    const keyPair = await modules.keyManager.generateKeyPair();

    try {
        const apiKey = process.env.BLINDPASS_API_KEY?.trim() || process.env.SPS_AGENT_API_KEY?.trim();

        // 2. Create secret request via Gateway SPS client
        const gatewayToken = await getAgentAuthToken(modules, resolvedAgentId, spsBaseUrl, identityOptions);
        const gatewayClient = new modules.GatewaySpsClient({
            baseUrl: spsBaseUrl,
            gatewayBearerToken: gatewayToken,
            bootstrapApiKey: apiKey || undefined,
        });

        const request = await gatewayClient.createSecretRequest({
            description,
            publicKey: keyPair.publicKey ?? keyPair.public_key,
        });

        // 3. Let the caller deliver the link to the user (Telegram, etc.)
        await onSecretLink(request.secretUrl, request.confirmationCode);

        // 4. Poll until submitted
        const agentToken = await getAgentAuthToken(modules, resolvedAgentId, spsBaseUrl, identityOptions);
        const agentClient = new modules.SpsClient({
            baseUrl: spsBaseUrl,
            gatewayBearerToken: agentToken,
            bootstrapApiKey: apiKey || undefined,
        });

        await agentClient.pollStatus(request.requestId, 1000, 180_000, 60_000);

        // 5. Retrieve + decrypt
        const payload = await agentClient.retrieveSecret(request.requestId);
        const plaintext = await modules.keyManager.decrypt(keyPair.privateKey, payload.enc, payload.ciphertext);
        return Buffer.from(plaintext);
    } finally {
        // 6. Always destroy keypair
        modules.keyManager.destroyKeyPair(keyPair);
    }
}

export async function fulfillExchangeFlow(params) {
    const {
        fulfillmentToken,
        resolveSecret,
        spsBaseUrl = resolveSpsBaseUrl(),
        agentId,
        moduleOverrides = {},
        identityOptions = {},
    } = params;

    const modules = await loadModules(moduleOverrides);
    const resolvedAgentId = resolveAgentId(agentId);
    const agentToken = await getAgentAuthToken(modules, resolvedAgentId, spsBaseUrl, identityOptions);
    const agentClient = new modules.SpsClient({
        baseUrl: spsBaseUrl,
        gatewayBearerToken: agentToken,
    });

    const reservation = await agentClient.fulfillExchange(fulfillmentToken);
    const secret = await resolveSecret(reservation.secretName);
    if (!secret) {
        throw new Error(`Secret '${reservation.secretName}' is missing from runtime memory.`);
    }

    const secretBuffer = Buffer.isBuffer(secret) ? Buffer.from(secret) : Buffer.from(secret);

    try {
        const sealed = await modules.keyManager.encrypt(reservation.requesterPublicKey, secretBuffer);
        await agentClient.submitExchange(reservation.exchangeId, sealed);
        return {
            exchangeId: reservation.exchangeId,
            secretName: reservation.secretName,
            fulfilledBy: reservation.fulfilledBy,
        };
    } finally {
        secretBuffer.fill(0);
    }
}

export async function requestExchangeFlow(params) {
    const {
        secretName,
        purpose,
        fulfillerId,
        priorExchangeId,
        transport,
        reservedTimeoutMs,
        spsBaseUrl = resolveSpsBaseUrl(),
        agentId,
        moduleOverrides = {},
        identityOptions = {},
    } = params;

    const modules = await loadModules(moduleOverrides);
    const resolvedAgentId = resolveAgentId(agentId);
    const agentToken = await getAgentAuthToken(modules, resolvedAgentId, spsBaseUrl, identityOptions);
    const runtime = new modules.AgentSecretRuntime({
        spsBaseUrl,
        gatewayBearerToken: agentToken,
        agentId: resolvedAgentId,
    });

    try {
        const result = await runtime.requestAndStoreExchangeSecret({
            secretName,
            purpose,
            fulfillerHint: fulfillerId,
            priorExchangeId,
            transport,
            reservedTimeoutMs,
        });
        const secret = Buffer.from(runtime.checkSecretOrThrow(secretName));

        return {
            exchangeId: result.exchangeId,
            fulfilledBy: result.fulfilledBy,
            secret,
        };
    } finally {
        runtime.store.disposeAll();
    }
}

/**
 * Cleanup any temp files created during identity initialization.
 */
export async function cleanup() {
    _gatewayIdentity = null;
    _jwksPath = null;
    if (_tempDir) {
        await rm(_tempDir, { recursive: true, force: true }).catch(() => { });
        _tempDir = null;
    }
}
