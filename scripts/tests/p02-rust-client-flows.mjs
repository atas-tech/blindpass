#!/usr/bin/env node

import assert from "node:assert/strict";
import { SpsClient } from "../../packages/agent-skill/src/sps-client.ts";
import * as agentKeyManager from "../../packages/agent-skill/src/key-manager.ts";
import * as AgentSkillRuntimeModule from "../../packages/agent-skill/src/index.ts";
import { GatewaySpsClient } from "../../packages/gateway/src/sps-client.ts";
import { startAdapter } from "../../packages/contract-tests/src/adapter.ts";
import { addCanaries, AGENT_IDS, SECRET_NAMES } from "../../packages/contract-tests/src/fixtures.ts";
import { containsCanary } from "../../packages/contract-tests/src/normalization.ts";
import { httpRequest, jsonRequestBody, withBearer } from "../../packages/contract-tests/src/http.ts";

if (process.env.SUT !== "rust") {
  throw new Error("CC02 requires SUT=rust");
}

const adapter = await startAdapter();
if (!adapter) throw new Error("Rust server adapter did not start");

const inheritedApiKey = process.env.BLINDPASS_API_KEY;
const inheritedSpsApiKey = process.env.SPS_AGENT_API_KEY;
delete process.env.BLINDPASS_API_KEY;
delete process.env.SPS_AGENT_API_KEY;

try {
  const fixture = adapter.fixture;
  const bridge = await import("../../packages/openclaw-plugin/sps-bridge.mjs");
  const identity = {
    loadOrCreateGatewayIdentity: async () => ({ kid: "contract-openclaw" }),
    issueJwt: async (_identity, agentId) => adapter.externalJwt({
      sub: agentId,
      workspace_id: fixture.workspaceId,
      workload_mode: "external"
    }),
    writeJwksFile: async () => undefined
  };
  const moduleOverrides = {
    identity,
    keyManager: agentKeyManager,
    AgentSkillRuntimeModule,
    SpsClientModule: { SpsClient },
    GatewaySpsClientModule: { GatewaySpsClient }
  };

  const requestedPlaintext = Buffer.from("dummy-cc02-openclaw-request");
  const opened = await bridge.requestSecretFlow({
    description: "CC02 OpenClaw request flow",
    spsBaseUrl: adapter.baseUrl,
    agentId: AGENT_IDS.requester,
    moduleOverrides,
    onSecretLink: async (secretUrl) => {
      const url = new URL(secretUrl);
      const requestId = url.searchParams.get("id") ?? "";
      const metadataSig = url.searchParams.get("metadata_sig") ?? "";
      const submitSig = url.searchParams.get("submit_sig") ?? "";
      assert.match(requestId, /^[a-f0-9]{64}$/);
      const metadata = await httpRequest(
        adapter.baseUrl,
        `/api/v2/secret/metadata/${requestId}?sig=${encodeURIComponent(metadataSig)}`
      );
      assert.equal(metadata.status, 200);
      assert.ok(metadata.body && typeof metadata.body.public_key === "string");
      const sealed = await agentKeyManager.encrypt(metadata.body.public_key, requestedPlaintext);
      const submitted = await httpRequest(
        adapter.baseUrl,
        `/api/v2/secret/submit/${requestId}?sig=${encodeURIComponent(submitSig)}`,
        jsonRequestBody(sealed)
      );
      assert.equal(submitted.status, 201);
      addCanaries(fixture, secretUrl, metadataSig, submitSig, requestedPlaintext.toString("utf8"));
    }
  });
  assert.ok(opened.equals(requestedPlaintext));

  const requesterKeyPair = await agentKeyManager.generateKeyPair();
  try {
    const requesterClient = new SpsClient({
      baseUrl: adapter.baseUrl,
      gatewayBearerToken: fixture.agents.requester.accessToken
    });
    const exchange = await requesterClient.createExchangeRequest({
      publicKey: requesterKeyPair.publicKey,
      secretName: SECRET_NAMES.allowed,
      purpose: "CC02 OpenClaw fulfillment flow",
      fulfillerHint: AGENT_IDS.fulfiller
    });
    assert.equal(exchange.status, "pending");

    const exchangePlaintext = Buffer.from("dummy-cc02-openclaw-exchange");
    const fulfilled = await bridge.fulfillExchangeFlow({
      fulfillmentToken: exchange.fulfillmentToken,
      resolveSecret: async (secretName) => secretName === SECRET_NAMES.allowed ? exchangePlaintext : null,
      spsBaseUrl: adapter.baseUrl,
      agentId: AGENT_IDS.fulfiller,
      moduleOverrides
    });
    assert.equal(fulfilled.exchangeId, exchange.exchangeId);
    const retrieved = await requesterClient.retrieveExchange(exchange.exchangeId);
    const exchangeOpened = await agentKeyManager.decrypt(
      requesterKeyPair.privateKey,
      retrieved.enc,
      retrieved.ciphertext
    );
    assert.ok(exchangeOpened.equals(exchangePlaintext));
    addCanaries(fixture, exchangePlaintext.toString("utf8"));

    const audit = await httpRequest(
      adapter.baseUrl,
      "/api/v2/audit/?limit=200",
      withBearer(fixture.adminAccessToken)
    );
    assert.equal(audit.status, 200);
    assert.deepEqual(containsCanary(audit.body?.records ?? [], fixture.canaries), []);
  } finally {
    agentKeyManager.destroyKeyPair(requesterKeyPair);
  }

  process.stdout.write("CC02 passed: gateway request, OpenClaw poll/decrypt, agent exchange and OpenClaw fulfillment against Rust.\n");
} finally {
  if (inheritedApiKey === undefined) delete process.env.BLINDPASS_API_KEY;
  else process.env.BLINDPASS_API_KEY = inheritedApiKey;
  if (inheritedSpsApiKey === undefined) delete process.env.SPS_AGENT_API_KEY;
  else process.env.SPS_AGENT_API_KEY = inheritedSpsApiKey;
  await adapter.close();
}
