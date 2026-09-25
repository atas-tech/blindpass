import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { startAdapter, type ServerAdapter } from "../src/adapter.js";
import { httpRequest, jsonRequestBody, withBearer, withOrigin } from "../src/http.js";
import { addCanaries, AGENT_IDS, CANARIES, SECRET_NAMES, type AgentId, type ContractFixture } from "../src/fixtures.js";
import { containsCanary } from "../src/normalization.js";
import { SnapshotRecorder } from "../src/snapshots.js";
import { expiredBrowserPayload, signBrowserPayload } from "../src/signing.js";
import { verifyFulfillmentToken } from "../../sps-server/src/services/crypto.js";
import { buildApp } from "../../sps-server/src/index.js";
import { InMemoryRequestStore } from "../../sps-server/src/services/redis.js";
import { SpsClient } from "../../agent-skill/src/sps-client.js";
import { GatewaySpsClient } from "../../gateway/src/sps-client.js";
import { evaluatePolicyVectors } from "../src/vectors.js";

const runContractSuite = Boolean(process.env.SUT);
const describeContract = runContractSuite ? describe : describe.skip;

vi.setConfig({ hookTimeout: 90_000, testTimeout: 90_000 });

type Result = Awaited<ReturnType<typeof httpRequest>>;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function expectExpiresIn(expiresAt: number, ttlSeconds: number): void {
  const remainingSeconds = expiresAt - Math.floor(Date.now() / 1000);
  expect(remainingSeconds).toBeGreaterThanOrEqual(ttlSeconds - 1);
  expect(remainingSeconds).toBeLessThanOrEqual(ttlSeconds);
}

function agent(fixture: ContractFixture, id: AgentId): { token: string; apiKey: string; agentId: string } {
  const value = fixture.agents[id];
  return {
    token: value.accessToken,
    apiKey: value.apiKey,
    agentId: value.agentId
  };
}

function secretUrlParts(secretUrl: string): { requestId: string; metadataSig: string; submitSig: string } {
  const url = new URL(secretUrl);
  return {
    requestId: url.searchParams.get("id") ?? "",
    metadataSig: url.searchParams.get("metadata_sig") ?? "",
    submitSig: url.searchParams.get("submit_sig") ?? ""
  };
}

function requireBody<T>(result: Awaited<ReturnType<typeof httpRequest<T>>>): T {
  if (!result.body) {
    throw new Error(`Expected JSON body for status ${result.status}: ${result.text.slice(0, 300)}`);
  }
  return result.body;
}

describeContract("P00 CT/CC black-box baseline", { timeout: 90_000 }, () => {
  let adapter: ServerAdapter;
  let fixture: ContractFixture;
  const snapshots = new SnapshotRecorder();
  const namedResults = new Map<string, Result>();

  beforeAll(async () => {
    const started = await startAdapter();
    if (!started) {
      throw new Error("Contract suite was enabled without a server adapter");
    }
    adapter = started;
    fixture = adapter.fixture;
  });

  afterAll(async () => {
    try {
      await snapshots.finish();
    } finally {
      await adapter?.close();
    }
  });

  async function call<T = unknown>(name: string, path: string, init: RequestInit = {}): Promise<Awaited<ReturnType<typeof httpRequest<T>>>> {
    const response = await httpRequest<T>(fixture.baseUrl, path, init);
    const mismatchTarget = process.env.P02_INJECT_RESPONSE_MISMATCH;
    if (mismatchTarget && process.env.SUT !== "rust") {
      throw new Error("P02 response mismatch injection is available only with SUT=rust");
    }
    const result = name === mismatchTarget
      ? { ...response, status: response.status === 200 ? 503 : 502 }
      : response;
    if (!name.startsWith("helper.")) {
      snapshots.record(name, result);
      namedResults.set(name, result);
    }
    return result;
  }

  async function createSecretRequest(id: AgentId = "requester", description = "P00 contract request"): Promise<{
    requestId: string;
    metadataSig: string;
    submitSig: string;
    response: Result;
  }> {
    const response = await call<{ request_id: string; confirmation_code: string; secret_url: string }>(
      `helper.secret.${id}.${description}`,
      "/api/v2/secret/request",
      withBearer(agent(fixture, id).token, {
        ...jsonRequestBody({
          public_key: "Y29udHJhY3QtcHViLWtleQ==",
          description
        })
      })
    );
    expect(response.status).toBe(201);
    const body = requireBody(response);
    const parts = secretUrlParts(body.secret_url);
    addCanaries(fixture, body.secret_url, parts.metadataSig, parts.submitSig);
    expect(parts.requestId).toMatch(/^[a-f0-9]{64}$/);
    return { ...parts, response };
  }

  async function submitSecret(requestId: string, submitSig: string, ciphertext = "Q0FOQVJZX0NJUEhFUl9QMDA") {
    return call<{ status: string }>(`helper.submit.${requestId}`, `/api/v2/secret/submit/${requestId}?sig=${encodeURIComponent(submitSig)}`, {
      ...jsonRequestBody({ enc: "ZW5jLXBvbGljeQ==", ciphertext })
    });
  }

  async function createExchange(
    purpose = "contract-deploy",
    secretName = SECRET_NAMES.allowed,
    snapshotName = "helper.exchange.request"
  ) {
    const response = await call<{
      exchange_id: string;
      status: string;
      expires_at: number;
      fulfillment_token: string;
      policy: Record<string, unknown>;
    }>(snapshotName, "/api/v2/secret/exchange/request", withBearer(agent(fixture, "requester").token, {
      ...jsonRequestBody({
        public_key: "Y29udHJhY3QtcHViLWtleQ==",
        secret_name: secretName,
        purpose,
        fulfiller_hint: AGENT_IDS.fulfiller
      })
    }));
    if (response.body?.fulfillment_token) {
      addCanaries(fixture, response.body.fulfillment_token);
    }
    return response;
  }

  it("CT01 records health and readiness over HTTP", async () => {
    const health = await call("CT01.healthz", "/healthz");
    expect(health.status).toBe(200);
    expect(requireBody<{ ok: boolean }>(health).ok).toBe(true);

    const ready = await call(process.env.SUT === "rust" ? "helper.CT01.readyz.up" : "CT01.readyz.up", "/readyz");
    expect(ready.status).toBe(200);
    const expectedChecks = process.env.SUT === "rust"
      ? { database: "up" }
      : { database: "up", redis: "up" };
    const readyBody = requireBody<{ ok: boolean; checks: Record<string, string> }>(ready);
    expect(readyBody).toMatchObject({
      ok: true,
      checks: expectedChecks
    });
    if (process.env.SUT === "rust") {
      snapshots.recordValue("CT01.readyz.up", {
        status: ready.status,
        ok: readyBody.ok,
        database: readyBody.checks.database
      });
    }
  });

  it("CT02 preserves bootstrap-key auth, rotation, revocation, and throttling", async () => {
    const rotatable = agent(fixture, "rotatable");
    const bearer = await call<{ access_token: string }>("CT02.token.bearer", "/api/v2/agents/token", {
      method: "POST",
      headers: {
        authorization: `Bearer ${rotatable.apiKey}`,
        "x-forwarded-for": "198.51.100.40"
      }
    });
    expect(bearer.status).toBe(200);
    addCanaries(fixture, requireBody(bearer).access_token);

    const header = await call<{ access_token: string }>("CT02.token.header", "/api/v2/agents/token", {
      method: "POST",
      headers: {
        "x-agent-api-key": agent(fixture, "revocable").apiKey,
        "x-forwarded-for": "198.51.100.41"
      }
    });
    expect(header.status).toBe(200);
    addCanaries(fixture, requireBody(header).access_token);

    const missing = await call("CT02.token.missing", "/api/v2/agents/token", { method: "POST" });
    expect(missing.status).toBe(401);

    const malformed = await call("CT02.token.malformed", "/api/v2/agents/token", {
      method: "POST",
      headers: { authorization: "Basic not-a-bearer" }
    });
    expect(malformed.status).toBe(401);

    const unknown = await call("CT02.token.unknown", "/api/v2/agents/token", {
      method: "POST",
      headers: { authorization: "Bearer ak_00000000-0000-4000-8000-000000000000_unknown" }
    });
    expect(unknown.status).toBe(401);

    const rotate = await call<{ bootstrap_api_key: string }>("CT02.key.rotate", `/api/v2/agents/${AGENT_IDS.rotatable}/rotate-key`, withBearer(fixture.adminAccessToken, {
      method: "POST"
    }));
    expect(rotate.status).toBe(200);
    const rotatedKey = requireBody(rotate).bootstrap_api_key;
    addCanaries(fixture, rotatedKey);

    const oldKey = await call("CT02.key.rotated-old", "/api/v2/agents/token", {
      method: "POST",
      headers: { authorization: `Bearer ${rotatable.apiKey}`, "x-forwarded-for": "198.51.100.42" }
    });
    expect(oldKey.status).toBe(401);

    const newKey = await call<{ access_token: string }>("CT02.key.rotated-new", "/api/v2/agents/token", {
      method: "POST",
      headers: { authorization: `Bearer ${rotatedKey}`, "x-forwarded-for": "198.51.100.43" }
    });
    expect(newKey.status).toBe(200);
    addCanaries(fixture, requireBody(newKey).access_token);
    fixture.agents.rotatable.apiKey = rotatedKey;

    const revoke = await call("CT02.key.revoke", `/api/v2/agents/${AGENT_IDS.revocable}`, withBearer(fixture.adminAccessToken, {
      method: "DELETE"
    }));
    expect(revoke.status).toBe(200);

    const revokedKey = await call("CT02.key.revoked", "/api/v2/agents/token", {
      method: "POST",
      headers: { authorization: `Bearer ${agent(fixture, "revocable").apiKey}`, "x-forwarded-for": "198.51.100.44" }
    });
    expect(revokedKey.status).toBe(401);

    const limit = 5;
    for (let index = 0; index < limit; index += 1) {
      await call(`CT02.rate.allowed.${index + 1}`, "/api/v2/agents/token", {
        method: "POST",
        headers: {
          authorization: "Bearer ak_00000000-0000-4000-8000-000000000000_unknown",
          "x-forwarded-for": "203.0.113.220"
        }
      });
    }
    const limited = await call("CT02.rate.limited", "/api/v2/agents/token", {
      method: "POST",
      headers: {
        authorization: "Bearer ak_00000000-0000-4000-8000-000000000000_unknown",
        "x-forwarded-for": "203.0.113.220"
      }
    });
    expect(limited.status).toBe(429);
    expect(requireBody<{ retry_after_seconds: number }>(limited).retry_after_seconds).toBeGreaterThan(0);
    expect(Number(limited.headers.get("retry-after"))).toBeGreaterThan(0);
  });

  it("CT03 creates signed requests for hosted and external workload tokens", async () => {
    const created = await createSecretRequest("requester", "CT03 hosted request");
    expect(created.response.status).toBe(201);

    const external = await call("CT03.request.external-jwks", "/api/v2/secret/request", withBearer(adapter.externalJwt(), {
      ...jsonRequestBody({
        public_key: "Y29udHJhY3QtZXh0ZXJuYWw=",
        description: "CT03 external request"
      })
    }));
    expect(external.status).toBe(201);

    const expiredExternal = await call("CT03.request.expired-external", "/api/v2/secret/request", withBearer(adapter.externalJwt({}, Math.floor(Date.now() / 1000) - 600), {
      ...jsonRequestBody({ public_key: "Y29udHJhY3Q=", description: "expired external token" })
    }));
    expect(expiredExternal.status).toBe(401);

    // SPS verifies workload JWTs with zero clock tolerance: five seconds past
    // `exp` is expired, not inside a leeway window.
    const justExpiredExternal = await call("CT03.request.just-expired-external", "/api/v2/secret/request", withBearer(adapter.externalJwt({}, Math.floor(Date.now() / 1000) - 305), {
      ...jsonRequestBody({ public_key: "Y29udHJhY3Q=", description: "external token expired five seconds ago" })
    }));
    expect(justExpiredExternal.status).toBe(401);

    const missing = await call("CT03.request.missing-auth", "/api/v2/secret/request", jsonRequestBody({
      public_key: "Y29udHJhY3Q=",
      description: "missing auth"
    }));
    expect(missing.status).toBe(401);

    const wrongIssuer = await call("CT03.request.wrong-issuer", "/api/v2/secret/request", withBearer(adapter.externalJwt({ iss: "wrong-issuer" }), {
      ...jsonRequestBody({ public_key: "Y29udHJhY3Q=", description: "wrong issuer" })
    }));
    expect(wrongIssuer.status).toBe(401);

    const wrongAudience = await call("CT03.request.wrong-audience", "/api/v2/secret/request", withBearer(adapter.externalJwt({ aud: "wrong-audience" }), {
      ...jsonRequestBody({ public_key: "Y29udHJhY3Q=", description: "wrong audience" })
    }));
    expect(wrongAudience.status).toBe(401);

    // A configured issuer and audience are required claims, not checks that
    // apply only when the token happens to carry them.
    const missingIssuer = await call("CT03.request.missing-issuer", "/api/v2/secret/request", withBearer(adapter.externalJwt({}, undefined, ["iss"]), {
      ...jsonRequestBody({ public_key: "Y29udHJhY3Q=", description: "missing issuer" })
    }));
    expect(missingIssuer.status).toBe(401);

    const missingAudience = await call("CT03.request.missing-audience", "/api/v2/secret/request", withBearer(adapter.externalJwt({}, undefined, ["aud"]), {
      ...jsonRequestBody({ public_key: "Y29udHJhY3Q=", description: "missing audience" })
    }));
    expect(missingAudience.status).toBe(401);

    const invalidPublicKey = await call("CT03.request.invalid-public-key", "/api/v2/secret/request", withBearer(agent(fixture, "requester").token, {
      ...jsonRequestBody({ public_key: "not base64!", description: "invalid public key" })
    }));
    expect(invalidPublicKey.status).toBe(400);

    const body = requireBody<{ request_id: string; confirmation_code: string; secret_url: string }>(created.response);
    expect(body.request_id).toMatch(/^[a-f0-9]{64}$/);
    expect(body.confirmation_code).toMatch(/^[A-Z]+-[A-Z]+-\d{2}$/);
    expect(new URL(body.secret_url).searchParams.get("api_url")).toBe(fixture.baseUrl);
  });

  it("CT04 enforces signed metadata scope, expiry, tamper, and unknown-id behavior", async () => {
    const created = await createSecretRequest("requester", "CT04 metadata request");
    const correct = await call("CT04.metadata.correct", `/api/v2/secret/metadata/${created.requestId}?sig=${encodeURIComponent(created.metadataSig)}`);
    expect(correct.status).toBe(200);
    expect(requireBody<Record<string, unknown>>(correct)).not.toHaveProperty("ciphertext");

    const wrongScope = await call("CT04.metadata.submit-scope", `/api/v2/secret/metadata/${created.requestId}?sig=${encodeURIComponent(created.submitSig)}`);
    expect(wrongScope.status).toBe(403);

    const tampered = `${created.metadataSig.slice(0, -1)}${created.metadataSig.endsWith("A") ? "B" : "A"}`;
    const tamperedResult = await call("CT04.metadata.tampered", `/api/v2/secret/metadata/${created.requestId}?sig=${encodeURIComponent(tampered)}`);
    expect(tamperedResult.status).toBe(403);

    const expired = expiredBrowserPayload(created.requestId, "metadata", fixture.hmacSecret);
    const expiredResult = await call("CT04.metadata.expired", `/api/v2/secret/metadata/${created.requestId}?sig=${encodeURIComponent(expired)}`);
    expect(expiredResult.status).toBe(410);

    const unknownId = "b".repeat(64);
    const unknownSig = signBrowserPayload(unknownId, Math.floor(Date.now() / 1000) + 30, "metadata", fixture.hmacSecret);
    const unknown = await call("CT04.metadata.unknown", `/api/v2/secret/metadata/${unknownId}?sig=${encodeURIComponent(unknownSig)}`);
    expect(unknown.status).toBe(410);
  });

  it("CT05 preserves one-use browser submission and payload validation", async () => {
    const created = await createSecretRequest("requester", "CT05 submit request");
    const submitted = await submitSecret(created.requestId, created.submitSig);
    expect(submitted.status).toBe(201);
    expect(JSON.stringify(submitted.body)).not.toContain(CANARIES.ciphertext);

    const repeated = await call("CT05.submit.repeat", `/api/v2/secret/submit/${created.requestId}?sig=${encodeURIComponent(created.submitSig)}`, {
      ...jsonRequestBody({ enc: "ZW5jLXBvbGljeQ==", ciphertext: "Q0FOQVJZX0NJUEhFUl9QMDA" })
    });
    expect(repeated.status).toBe(409);

    // The signed link keeps its metadata authority after submission until the
    // request's submitted deadline, so a reloaded page is not told it expired.
    const afterSubmit = await call("CT05.metadata.after-submit", `/api/v2/secret/metadata/${created.requestId}?sig=${encodeURIComponent(created.metadataSig)}`);
    expect(afterSubmit.status).toBe(200);

    const wrongScopeRequest = await createSecretRequest("requester", "CT05 wrong scope request");
    const wrongScope = await submitSecret(wrongScopeRequest.requestId, wrongScopeRequest.metadataSig);
    expect(wrongScope.status).toBe(403);

    const oversizedRequest = await createSecretRequest("requester", "CT05 oversized request");
    const oversized = await call("CT05.submit.oversized", `/api/v2/secret/submit/${oversizedRequest.requestId}?sig=${encodeURIComponent(oversizedRequest.submitSig)}`, {
      ...jsonRequestBody({ enc: "ZW5j", ciphertext: "A".repeat(524_289) })
    });
    expect(oversized.status).toBe(400);
  });

  it("CT06 exposes only pending/submitted status and expires foreign/consumed records", async () => {
    const pending = await createSecretRequest("requester", "CT06 pending");
    const pendingStatus = await call("CT06.pending", `/api/v2/secret/status/${pending.requestId}`, withBearer(agent(fixture, "requester").token));
    expect(pendingStatus.status).toBe(200);
    expect(requireBody(pendingStatus)).toEqual({ status: "pending" });

    const submitted = await createSecretRequest("requester", "CT06 submitted");
    await submitSecret(submitted.requestId, submitted.submitSig);
    const submittedStatus = await call("CT06.submitted", `/api/v2/secret/status/${submitted.requestId}`, withBearer(agent(fixture, "requester").token));
    expect(submittedStatus.status).toBe(200);
    expect(requireBody(submittedStatus)).toEqual({ status: "submitted" });

    const unknown = await call("CT06.unknown", `/api/v2/secret/status/${"c".repeat(64)}`, withBearer(agent(fixture, "requester").token));
    expect(unknown.status).toBe(410);
    expect(requireBody(unknown)).toEqual({ status: "expired" });

    const foreign = await call("CT06.foreign", `/api/v2/secret/status/${pending.requestId}`, withBearer(agent(fixture, "observer").token));
    expect(foreign.status).toBe(410);

    const consumed = await createSecretRequest("requester", "CT06 consumed");
    await submitSecret(consumed.requestId, consumed.submitSig);
    const consumedRetrieve = await call("helper.retrieve.consumed", `/api/v2/secret/retrieve/${consumed.requestId}`, withBearer(agent(fixture, "requester").token));
    expect(consumedRetrieve.status).toBe(200);
    const consumedStatus = await call("CT06.consumed", `/api/v2/secret/status/${consumed.requestId}`, withBearer(agent(fixture, "requester").token));
    expect(consumedStatus.status).toBe(410);

    const expiring = await createSecretRequest("requester", "CT06 expired");
    await sleep(Number(process.env.CONTRACT_REQUEST_TTL_SECONDS ?? 8) * 1000 + 250);
    const expired = await call("CT06.expired", `/api/v2/secret/status/${expiring.requestId}`, withBearer(agent(fixture, "requester").token));
    expect(expired.status).toBe(410);
  });

  it("CT07 enforces owner-only, atomic one-use retrieval over HTTP", async () => {
    const beforeSubmit = await createSecretRequest("requester", "CT07 before submit");
    const before = await call("CT07.retrieve.before-submit", `/api/v2/secret/retrieve/${beforeSubmit.requestId}`, withBearer(agent(fixture, "requester").token));
    expect(before.status).toBe(409);

    await submitSecret(beforeSubmit.requestId, beforeSubmit.submitSig);
    const owner = await call("CT07.retrieve.owner", `/api/v2/secret/retrieve/${beforeSubmit.requestId}`, withBearer(agent(fixture, "requester").token));
    expect(owner.status).toBe(200);
    const replay = await call("CT07.retrieve.replay", `/api/v2/secret/retrieve/${beforeSubmit.requestId}`, withBearer(agent(fixture, "requester").token));
    expect(replay.status).toBe(410);

    const foreignRequest = await createSecretRequest("requester", "CT07 foreign");
    await submitSecret(foreignRequest.requestId, foreignRequest.submitSig);
    const foreign = await call("CT07.retrieve.foreign", `/api/v2/secret/retrieve/${foreignRequest.requestId}`, withBearer(agent(fixture, "observer").token));
    expect(foreign.status).toBe(410);
    const ownerAfterForeign = await call("CT07.retrieve.owner-after-foreign", `/api/v2/secret/retrieve/${foreignRequest.requestId}`, withBearer(agent(fixture, "requester").token));
    expect(ownerAfterForeign.status).toBe(200);

    const raced = await createSecretRequest("requester", "CT07 race");
    await submitSecret(raced.requestId, raced.submitSig);
    const results = await Promise.all(Array.from({ length: 8 }, () => httpRequest(fixture.baseUrl, `/api/v2/secret/retrieve/${raced.requestId}`, withBearer(agent(fixture, "requester").token))));
    const statuses = results.map((result) => result.status).sort((left, right) => left - right);
    snapshots.recordValue("CT07.retrieve.race", statuses);
    expect(statuses).toEqual([200, 410, 410, 410, 410, 410, 410, 410]);
  });

  it("CT08 preserves expiry semantics for pending, submitted, and revoked records", async () => {
    const pending = await createSecretRequest("requester", "CT08 pending expiry");
    await sleep(Number(process.env.CONTRACT_REQUEST_TTL_SECONDS ?? 8) * 1000 + 250);
    const pendingStatus = await call("CT08.pending.expired", `/api/v2/secret/status/${pending.requestId}`, withBearer(agent(fixture, "requester").token));
    expect(pendingStatus.status).toBe(410);

    const submitted = await createSecretRequest("requester", "CT08 submitted expiry");
    await submitSecret(submitted.requestId, submitted.submitSig);
    await sleep(Number(process.env.CONTRACT_SUBMITTED_TTL_SECONDS ?? 3) * 1000 + 250);
    const submittedStatus = await call("CT08.submitted.expired", `/api/v2/secret/status/${submitted.requestId}`, withBearer(agent(fixture, "requester").token));
    expect(submittedStatus.status).toBe(410);
    const submittedRetrieve = await call("CT08.submitted.retrieve-expired", `/api/v2/secret/retrieve/${submitted.requestId}`, withBearer(agent(fixture, "requester").token));
    expect(submittedRetrieve.status).toBe(410);

    const exchange = await createExchange("CT08 revoked expiry");
    expect(exchange.status).toBe(201);
    const exchangeId = requireBody(exchange).exchange_id;
    const revoke = await call("CT08.revoked", `/api/v2/secret/exchange/revoke/${exchangeId}`, withBearer(agent(fixture, "requester").token, { method: "DELETE" }));
    expect(revoke.status).toBe(200);
    await sleep(Number(process.env.CONTRACT_REVOKED_TTL_SECONDS ?? 4) * 1000 + 250);
    const revokedExpired = await call("CT08.revoked.expired", `/api/v2/secret/exchange/status/${exchangeId}`, withBearer(agent(fixture, "requester").token));
    expect(revokedExpired.status).toBe(410);
  });

  it("CT09 records allow, approval, deny, and unknown policy decisions", async () => {
    const allowed = await createExchange("CT09 allow", SECRET_NAMES.allowed, "CT09.exchange.allow");
    expect(allowed.status).toBe(201);
    const allowedBody = requireBody(allowed);
    expect(allowedBody.policy).toMatchObject({ mode: "allow", rule_id: "contract-allow" });
    const allowedClaims = await verifyFulfillmentToken(allowedBody.fulfillment_token, fixture.hmacSecret);
    const policyVectors = await evaluatePolicyVectors(fixture.workspaceId);
    expect(allowedClaims.policy_hash).toBe(policyVectors[4]?.policy_hash);

    const approval = await createExchange("CT09 approval", SECRET_NAMES.approval, "CT09.exchange.approval");
    expect(approval.status).toBe(403);
    expect(requireBody(approval)).toMatchObject({ policy: { mode: "pending_approval", approval_required: true } });

    const denied = await createExchange("CT09 deny", SECRET_NAMES.denied, "CT09.exchange.deny");
    expect(denied.status).toBe(403);
    expect(requireBody(denied)).toMatchObject({ policy: { mode: "deny", approval_required: false } });

    const unknown = await createExchange("CT09 unknown", "unknown.secret", "CT09.exchange.unknown");
    expect(unknown.status).toBe(403);
  });

  it("CT10 restricts exchange status to the requester and records lifecycle states", async () => {
    const exchange = await createExchange("CT10 lifecycle");
    expect(exchange.status).toBe(201);
    const exchangeId = requireBody(exchange).exchange_id;
    const fulfillmentToken = requireBody(exchange).fulfillment_token;
    expectExpiresIn(requireBody(exchange).expires_at, Number(process.env.CONTRACT_REQUEST_TTL_SECONDS ?? 8));

    const pending = await call("CT10.status.pending", `/api/v2/secret/exchange/status/${exchangeId}`, withBearer(agent(fixture, "requester").token));
    expect(pending.status).toBe(200);
    const foreign = await call("CT10.status.foreign", `/api/v2/secret/exchange/status/${exchangeId}`, withBearer(agent(fixture, "fulfiller").token));
    expect(foreign.status).toBe(410);
    const thirdParty = await call("CT10.status.third-party", `/api/v2/secret/exchange/status/${exchangeId}`, withBearer(agent(fixture, "observer").token));
    expect(thirdParty.status).toBe(410);

    const reserved = await call("helper.exchange.fulfill", "/api/v2/secret/exchange/fulfill", withBearer(agent(fixture, "fulfiller").token, {
      ...jsonRequestBody({ fulfillment_token: fulfillmentToken })
    }));
    expect(reserved.status).toBe(200);
    const reservedStatus = await call("CT10.status.reserved", `/api/v2/secret/exchange/status/${exchangeId}`, withBearer(agent(fixture, "requester").token));
    expect(reservedStatus.status).toBe(200);

    const submitted = await call("helper.exchange.submit", `/api/v2/secret/exchange/submit/${exchangeId}`, withBearer(agent(fixture, "fulfiller").token, {
      ...jsonRequestBody({ enc: "ZW5jLXBvbGljeQ==", ciphertext: CANARIES.ciphertext })
    }));
    expect(submitted.status).toBe(201);
    const submittedStatus = await call("CT10.status.submitted", `/api/v2/secret/exchange/status/${exchangeId}`, withBearer(agent(fixture, "requester").token));
    expect(submittedStatus.status).toBe(200);

    const retrieved = await call("helper.exchange.retrieve", `/api/v2/secret/exchange/retrieve/${exchangeId}`, withBearer(agent(fixture, "requester").token));
    expect(retrieved.status).toBe(200);
    const afterRetrieve = await call("CT10.status.after-retrieve", `/api/v2/secret/exchange/status/${exchangeId}`, withBearer(agent(fixture, "requester").token));
    expect(afterRetrieve.status).toBe(410);

    const expiredExchange = await createExchange("CT10 expiry", SECRET_NAMES.allowed, "CT10.exchange.expiring");
    const expiredExchangeId = requireBody(expiredExchange).exchange_id;
    await sleep(Number(process.env.CONTRACT_REQUEST_TTL_SECONDS ?? 8) * 1000 + 250);
    const expiredStatus = await call("CT10.status.expired", `/api/v2/secret/exchange/status/${expiredExchangeId}`, withBearer(agent(fixture, "requester").token));
    expect(expiredStatus.status).toBe(410);
  });

  it("CT11 binds fulfillment and submission to the authorized fulfiller", async () => {
    const exchange = await createExchange("CT11 ownership");
    expect(exchange.status).toBe(201);
    const created = requireBody(exchange);
    const claims = await verifyFulfillmentToken(created.fulfillment_token, fixture.hmacSecret);
    expect(claims).toMatchObject({
      exchange_id: created.exchange_id,
      requester_id: agent(fixture, "requester").agentId,
      workspace_id: fixture.workspaceId,
      secret_name: SECRET_NAMES.allowed,
      purpose: "CT11 ownership",
      tokenKind: "agent"
    });
    const rawClaims = JSON.parse(Buffer.from(created.fulfillment_token.split(".")[1]!, "base64url").toString()) as Record<string, unknown>;
    expect(rawClaims).toMatchObject({ iss: "sps", aud: "agent-fulfill" });
    expectExpiresIn(Number(rawClaims.exp), Number(process.env.CONTRACT_REQUEST_TTL_SECONDS ?? 8));

    const wrongFulfiller = await call("CT11.fulfill.wrong-agent", "/api/v2/secret/exchange/fulfill", withBearer(agent(fixture, "observer").token, {
      ...jsonRequestBody({ fulfillment_token: created.fulfillment_token })
    }));
    expect(wrongFulfiller.status).toBe(409);

    const reserved = await call("CT11.fulfill.owner", "/api/v2/secret/exchange/fulfill", withBearer(agent(fixture, "fulfiller").token, {
      ...jsonRequestBody({ fulfillment_token: created.fulfillment_token })
    }));
    expect(reserved.status).toBe(200);
    const beforeSubmit = await call("CT11.retrieve.before-submit", `/api/v2/secret/exchange/retrieve/${created.exchange_id}`, withBearer(agent(fixture, "requester").token));
    expect(beforeSubmit.status).toBe(409);

    const wrongSubmit = await call("CT11.submit.wrong-agent", `/api/v2/secret/exchange/submit/${created.exchange_id}`, withBearer(agent(fixture, "observer").token, {
      ...jsonRequestBody({ enc: "ZW5j", ciphertext: CANARIES.ciphertext })
    }));
    expect(wrongSubmit.status).toBe(409);

    const submitted = await call("CT11.submit.owner", `/api/v2/secret/exchange/submit/${created.exchange_id}`, withBearer(agent(fixture, "fulfiller").token, {
      ...jsonRequestBody({ enc: "ZW5j", ciphertext: CANARIES.ciphertext })
    }));
    expect(submitted.status).toBe(201);

    const wrongRetrieve = await call("CT11.retrieve.wrong-agent", `/api/v2/secret/exchange/retrieve/${created.exchange_id}`, withBearer(agent(fixture, "observer").token));
    expect(wrongRetrieve.status).toBe(410);

    // A configured issuer's claim for another workspace never acts as the
    // requester, even when its subject collides with the requester's. The
    // denied calls add no audit events, so the P00 audit snapshot is unchanged.
    const requesterSub = (JSON.parse(Buffer.from(agent(fixture, "requester").token.split(".")[1]!, "base64url").toString()) as { sub: string }).sub;
    const collidingToken = adapter.externalJwt({ sub: requesterSub, workspace_id: "foreign-workspace" });
    for (const [method, route] of [
      ["GET", "status"],
      ["GET", "retrieve"],
      ["DELETE", "revoke"]
    ] as const) {
      const denied = await httpRequest(fixture.baseUrl, `/api/v2/secret/exchange/${route}/${created.exchange_id}`, withBearer(collidingToken, { method }));
      expect(denied.status, `${method} ${route} with a colliding foreign-workspace subject`).toBe(410);
      expect(containsCanary(denied.body, fixture.canaries)).toEqual([]);
    }

    const before = await call("CT11.retrieve.requester", `/api/v2/secret/exchange/retrieve/${created.exchange_id}`, withBearer(agent(fixture, "requester").token));
    expect(before.status).toBe(200);
    const replay = await call("CT11.retrieve.replay", `/api/v2/secret/exchange/retrieve/${created.exchange_id}`, withBearer(agent(fixture, "requester").token));
    expect(replay.status).toBe(410);

    const racedExchange = await createExchange("CT11 parallel retrieve", SECRET_NAMES.allowed, "CT11.exchange.parallel");
    const raced = requireBody(racedExchange);
    const racedReserve = await call("helper.CT11.parallel.fulfill", "/api/v2/secret/exchange/fulfill", withBearer(agent(fixture, "fulfiller").token, {
      ...jsonRequestBody({ fulfillment_token: raced.fulfillment_token })
    }));
    expect(racedReserve.status).toBe(200);
    const racedSubmit = await call("helper.CT11.parallel.submit", `/api/v2/secret/exchange/submit/${raced.exchange_id}`, withBearer(agent(fixture, "fulfiller").token, {
      ...jsonRequestBody({ enc: "ZW5j", ciphertext: CANARIES.ciphertext })
    }));
    expect(racedSubmit.status).toBe(201);
    const raceResults = await Promise.all(Array.from({ length: 8 }, () => httpRequest(
      fixture.baseUrl,
      `/api/v2/secret/exchange/retrieve/${raced.exchange_id}`,
      withBearer(agent(fixture, "requester").token)
    )));
    const raceStatuses = raceResults.map((result) => result.status).sort((left, right) => left - right);
    snapshots.recordValue("CT11.retrieve.race", raceStatuses);
    expect(raceStatuses).toEqual([200, 410, 410, 410, 410, 410, 410, 410]);
  });

  it("CT12 records requester and configured-issuer admin-claim revocation", async () => {
    const requesterExchange = await createExchange("CT12 requester revoke");
    const requesterId = requireBody(requesterExchange).exchange_id;
    const revoke = await call("CT12.revoke.requester", `/api/v2/secret/exchange/revoke/${requesterId}`, withBearer(agent(fixture, "requester").token, { method: "DELETE" }));
    expect(revoke.status).toBe(200);
    expect(requireBody(revoke)).toEqual({ status: "revoked" });
    const revokedStatus = await call("CT12.status.revoked", `/api/v2/secret/exchange/status/${requesterId}`, withBearer(agent(fixture, "requester").token));
    expect(requireBody(revokedStatus)).toEqual({ status: "revoked" });
    const repeat = await call("CT12.revoke.repeat", `/api/v2/secret/exchange/revoke/${requesterId}`, withBearer(agent(fixture, "requester").token, { method: "DELETE" }));
    expect(repeat.status).toBe(200);
    const foreign = await call("CT12.revoke.foreign", `/api/v2/secret/exchange/revoke/${requesterId}`, withBearer(agent(fixture, "fulfiller").token, { method: "DELETE" }));
    expect(foreign.status).toBe(410);
    const revokedRetrieve = await call("CT12.retrieve.revoked", `/api/v2/secret/exchange/retrieve/${requesterId}`, withBearer(agent(fixture, "requester").token));
    expect(revokedRetrieve.status).toBe(409);

    const reservedExchange = await createExchange("CT12 reserved revoke", SECRET_NAMES.allowed, "CT12.exchange.reserved");
    const reservedBody = requireBody(reservedExchange);
    const reserve = await call("CT12.fulfill.reserved", "/api/v2/secret/exchange/fulfill", withBearer(agent(fixture, "fulfiller").token, {
      ...jsonRequestBody({ fulfillment_token: reservedBody.fulfillment_token })
    }));
    expect(reserve.status).toBe(200);
    const reservedRevoke = await call("CT12.revoke.reserved", `/api/v2/secret/exchange/revoke/${reservedBody.exchange_id}`, withBearer(agent(fixture, "requester").token, { method: "DELETE" }));
    expect(requireBody(reservedRevoke)).toEqual({ status: "revoked" });
    const reservedStatus = await call("CT12.status.reserved-revoked", `/api/v2/secret/exchange/status/${reservedBody.exchange_id}`, withBearer(agent(fixture, "requester").token));
    expect(requireBody(reservedStatus)).toEqual({ status: "revoked" });
    const reservedRetrieve = await call("CT12.retrieve.reserved-revoked", `/api/v2/secret/exchange/retrieve/${reservedBody.exchange_id}`, withBearer(agent(fixture, "requester").token));
    expect(reservedRetrieve.status).toBe(409);

    const adminExchange = await createExchange("CT12 admin revoke");
    const adminId = requireBody(adminExchange).exchange_id;
    const nonAdminToken = adapter.externalJwt({ admin: false });
    const nonAdminRevoke = await httpRequest(fixture.baseUrl, `/api/v2/secret/exchange/revoke/${adminId}`, withBearer(nonAdminToken, { method: "DELETE" }));
    expect(nonAdminRevoke.status).toBe(410);
    const foreignAdminToken = adapter.externalJwt({ admin: true, workspace_id: "foreign-workspace" });
    const foreignAdminRevoke = await httpRequest(fixture.baseUrl, `/api/v2/secret/exchange/revoke/${adminId}`, withBearer(foreignAdminToken, { method: "DELETE" }));
    expect(foreignAdminRevoke.status).toBe(410);
    const adminToken = adapter.externalJwt({ admin: true });
    const adminRevoke = await call("CT12.revoke.issuer-admin-claim", `/api/v2/secret/exchange/revoke/${adminId}`, withBearer(adminToken, { method: "DELETE" }));
    expect(adminRevoke.status).toBe(200);
    const adminRevokedStatus = await call("CT12.status.admin-revoked", `/api/v2/secret/exchange/status/${adminId}`, withBearer(agent(fixture, "requester").token));
    expect(requireBody(adminRevokedStatus)).toEqual({ status: "revoked" });

    await sleep(Number(process.env.CONTRACT_REVOKED_TTL_SECONDS ?? 4) * 1000 + 250);
    const afterExpiry = await call("CT12.retrieve.revoked-expired", `/api/v2/secret/exchange/retrieve/${requesterId}`, withBearer(agent(fixture, "requester").token));
    expect(afterExpiry.status).toBe(410);
    const statusAfterExpiry = await call("CT12.status.revoked-expired", `/api/v2/secret/exchange/status/${requesterId}`, withBearer(agent(fixture, "requester").token));
    expect(statusAfterExpiry.status).toBe(410);
  });

  it("CT13 keeps pending approval machine-visible and continues only after an admin decision", async () => {
    const approval = await createExchange("CT13 approve", SECRET_NAMES.approval, "CT13.exchange.approve.pending");
    expect(approval.status).toBe(403);
    const approvalBody = requireBody<{ policy: { approval_reference: string } }>(approval);
    const approvalReference = approvalBody.policy.approval_reference;

    const approve = await call("CT13.approval.approve", `/api/v2/secret/exchange/admin/approval/${approvalReference}/approve`, withBearer(fixture.adminAccessToken, { method: "POST" }));
    expect(approve.status).toBe(200);

    const continued = await createExchange("CT13 approve", SECRET_NAMES.approval, "CT13.exchange.approve.continued");
    expect(continued.status).toBe(201);
    expect(requireBody(continued).policy).toMatchObject({ mode: "allow", approval_required: false });

    const rejection = await createExchange("CT13 reject", SECRET_NAMES.approval, "CT13.exchange.reject.pending");
    expect(rejection.status).toBe(403);
    const rejectionReference = requireBody<{ policy: { approval_reference: string } }>(rejection).policy.approval_reference;
    const reject = await call("CT13.approval.reject", `/api/v2/secret/exchange/admin/approval/${rejectionReference}/reject`, withBearer(fixture.adminAccessToken, { method: "POST" }));
    expect(reject.status).toBe(200);
    const rejectedAgain = await createExchange("CT13 reject", SECRET_NAMES.approval, "CT13.exchange.reject.rejected");
    expect(rejectedAgain.status).toBe(403);
    expect(requireBody(rejectedAgain)).toMatchObject({ error: "Exchange approval was rejected" });
  });

  if (process.env.SUT !== "rust") {
    it("CT14 records hosted user refresh rotation, replay rejection, expiry, and absence", async () => {
      const seeded = await httpRequest<{
        refresh_token: string;
        access_token: string;
      }>(fixture.baseUrl, "/api/v2/auth/test/seed-workspace", {
        ...jsonRequestBody({ prefix: "refresh", role: "workspace_admin" }),
        headers: {
          "content-type": "application/json",
          "x-blindpass-e2e-seed-token": fixture.seedToken
        }
      });
      expect(seeded.status).toBe(201);
      const oldRefresh = requireBody(seeded).refresh_token;
      const refreshWorkspaceAccess = requireBody(seeded).access_token;
      addCanaries(fixture, oldRefresh, refreshWorkspaceAccess);
      const rotated = await call<{ refresh_token: string; access_token: string }>("CT14.refresh.valid", "/api/v2/auth/refresh", jsonRequestBody({ refresh_token: oldRefresh }));
      expect(rotated.status).toBe(200);
      const cookie = rotated.headers.get("set-cookie");
      expect(cookie).toMatch(/^sps_refresh_token=[^;]+;/);
      const cookieAttributes = new Map(cookie!.split(";").slice(1).map((part) => {
        const [name, ...value] = part.trim().split("=");
        return [name!.toLowerCase(), value.join("=")];
      }));
      snapshots.recordValue("CT14.refresh.cookie", {
        path: cookieAttributes.get("path"),
        expires: cookieAttributes.has("expires") ? "<timestamp>" : null,
        max_age: cookieAttributes.has("max-age") ? "<seconds>" : null,
        http_only: cookieAttributes.has("httponly"),
        same_site: cookieAttributes.get("samesite"),
        secure: cookieAttributes.has("secure")
      });
      const rotatedBody = requireBody(rotated);
      addCanaries(fixture, rotatedBody.refresh_token, rotatedBody.access_token);

      const replay = await call("CT14.refresh.replay", "/api/v2/auth/refresh", jsonRequestBody({ refresh_token: oldRefresh }));
      expect(replay.status).toBe(401);

      const absent = await call("CT14.refresh.absent", "/api/v2/auth/refresh", jsonRequestBody({}));
      expect(absent.status).toBe(401);

      await sleep(Number(process.env.CONTRACT_REFRESH_TOKEN_TTL_SECONDS ?? 10) * 1000 + 250);
      const expired = await call("CT14.refresh.expired", "/api/v2/auth/refresh", jsonRequestBody({ refresh_token: rotatedBody.refresh_token }));
      expect(expired.status).toBe(401);
    });
  }

  if (process.env.SUT === "rust") {
    it("keeps hosted user refresh outside the controller", async () => {
      const response = await httpRequest(fixture.baseUrl, "/api/v2/auth/refresh", jsonRequestBody({}));
      expect(response.status).toBe(404);
    });

    it("P02-I01 keeps a submit/revoke HTTP race revoked without retrievable ciphertext", async () => {
      const created = requireBody(await createExchange("P02-I01 HTTP race", SECRET_NAMES.allowed, "helper.P02-I01.exchange"));
      const exchangeId = created.exchange_id;
      const reserved = await httpRequest(fixture.baseUrl, "/api/v2/secret/exchange/fulfill", withBearer(agent(fixture, "fulfiller").token, {
        ...jsonRequestBody({ fulfillment_token: created.fulfillment_token })
      }));
      expect(reserved.status).toBe(200);

      const [submitted, revoked] = await Promise.all([
        httpRequest(fixture.baseUrl, `/api/v2/secret/exchange/submit/${exchangeId}`, withBearer(agent(fixture, "fulfiller").token, {
          ...jsonRequestBody({ enc: "ZW5j", ciphertext: CANARIES.ciphertext })
        })),
        httpRequest(fixture.baseUrl, `/api/v2/secret/exchange/revoke/${exchangeId}`, withBearer(agent(fixture, "requester").token, { method: "DELETE" }))
      ]);
      expect([201, 409, 410]).toContain(submitted.status);
      expect(revoked.status).toBe(200);
      expect(revoked.body).toEqual({ status: "revoked" });

      const status = await httpRequest(fixture.baseUrl, `/api/v2/secret/exchange/status/${exchangeId}`, withBearer(agent(fixture, "requester").token));
      expect(status.status).toBe(200);
      expect(status.body).toEqual({ status: "revoked" });
      const retrieved = await httpRequest(fixture.baseUrl, `/api/v2/secret/exchange/retrieve/${exchangeId}`, withBearer(agent(fixture, "requester").token));
      expect(retrieved.status).toBe(409);
      expect(retrieved.text).not.toContain(CANARIES.ciphertext);
    });
  }

  it("CT15 records rate-limit rejection and window reset without changing production defaults", async () => {
    await sleep(Number(process.env.CONTRACT_AGENT_TOKEN_RATE_WINDOW_MS ?? 1000) + 250);
    const reset = await call<{ access_token: string }>("CT15.rate.reset", "/api/v2/agents/token", {
      method: "POST",
      headers: {
        authorization: `Bearer ${fixture.agents.rotatable.apiKey}`,
        "x-forwarded-for": "203.0.113.220"
      }
    });
    expect(reset.status).toBe(200);
    addCanaries(fixture, requireBody(reset).access_token);
    expect(namedResults.get("CT02.rate.limited")?.status).toBe(429);
  });

  it("CT16 grants CORS only to configured origins", async () => {
    const allowed = await call(process.env.SUT === "rust" ? "helper.CT16.cors.allowed" : "CT16.cors.allowed", "/healthz", withOrigin("http://allowed.contract.test", {
      method: "OPTIONS",
      headers: {
        "access-control-request-method": "GET"
      }
    }));
    expect(allowed.status).toBe(204);
    expect(allowed.headers.get("access-control-allow-origin")).toBe("http://allowed.contract.test");
    if (process.env.SUT === "rust") {
      snapshots.recordValue("CT16.cors.allowed", {
        status: allowed.status,
        allow_origin: allowed.headers.get("access-control-allow-origin"),
        allow_credentials: allowed.headers.get("access-control-allow-credentials")
      });
    }

    const disallowed = await call(process.env.SUT === "rust" ? "helper.CT16.cors.disallowed" : "CT16.cors.disallowed", "/healthz", withOrigin("http://denied.contract.test", {
      method: "OPTIONS",
      headers: {
        "access-control-request-method": "GET"
      }
    }));
    expect(disallowed.headers.get("access-control-allow-origin")).toBeNull();
    if (process.env.SUT === "rust") {
      snapshots.recordValue("CT16.cors.disallowed", {
        allow_origin: disallowed.headers.get("access-control-allow-origin")
      });
    }

    const allowedSimple = await call(process.env.SUT === "rust" ? "helper.CT16.cors.allowed-simple" : "CT16.cors.allowed-simple", "/healthz", withOrigin("http://allowed.contract.test"));
    expect(allowedSimple.status).toBe(200);
    expect(allowedSimple.headers.get("access-control-allow-origin")).toBe("http://allowed.contract.test");
    if (process.env.SUT === "rust") {
      snapshots.recordValue("CT16.cors.allowed-simple", {
        status: allowedSimple.status,
        allow_origin: allowedSimple.headers.get("access-control-allow-origin"),
        allow_credentials: allowedSimple.headers.get("access-control-allow-credentials")
      });
    }

    const disallowedSimple = await call(process.env.SUT === "rust" ? "helper.CT16.cors.disallowed-simple" : "CT16.cors.disallowed-simple", "/healthz", withOrigin("http://denied.contract.test"));
    expect(disallowedSimple.status).toBe(200);
    expect(disallowedSimple.headers.get("access-control-allow-origin")).toBeNull();
    if (process.env.SUT === "rust") {
      snapshots.recordValue("CT16.cors.disallowed-simple", {
        status: disallowedSimple.status,
        allow_origin: disallowedSimple.headers.get("access-control-allow-origin")
      });
    }
  });

  it("CT17 records metadata-only audit output and rejects canary leakage", async () => {
    const audit = await call<{ records: unknown[] }>(process.env.SUT === "rust" ? "helper.CT17.audit" : "CT17.audit", "/api/v2/audit/?limit=200", withBearer(fixture.adminAccessToken));
    expect(audit.status).toBe(200);
    const records = requireBody(audit).records;
    expect(records.length).toBeGreaterThan(0);
    const eventTypes = new Set(records.flatMap((record) => {
      if (!record || typeof record !== "object" || !("event_type" in record)) return [];
      return [String(record.event_type)];
    }));
    expect([...eventTypes]).toEqual(expect.arrayContaining([
      "agent_token_minted",
      "exchange_pending_approval",
      "exchange_rejected"
    ]));
    expect(containsCanary(records, fixture.canaries)).toEqual([]);
    const recordShape = ["actor_id", "actor_type", "created_at", "event_type", "id", "ip_address", "metadata", "resource_id", "workspace_id"];
    expect(records.every((record) => record && typeof record === "object"
      && JSON.stringify(Object.keys(record).sort()) === JSON.stringify(recordShape))).toBe(true);
    if (process.env.SUT === "rust") {
      snapshots.recordValue("CT17.audit", {
        status: audit.status,
        content_type: audit.contentType?.split(";", 1)[0] ?? null,
        record_shape: recordShape,
        required_events: ["agent_token_minted", "exchange_pending_approval", "exchange_rejected"]
      });
    }
  });

  it("CT18 preserves route-specific error bodies across representative status classes", async () => {
    const malformed = await call("CT18.error.400", "/api/v2/secret/request", withBearer(agent(fixture, "requester").token, {
      ...jsonRequestBody({ public_key: "bad!", description: "bad" })
    }));
    expect(malformed.status).toBe(400);
    expect(requireBody(malformed)).toHaveProperty("statusCode");

    const unauthorized = await call("CT18.error.401", "/api/v2/secret/request", jsonRequestBody({ public_key: "YQ==", description: "bad" }));
    expect(unauthorized.status).toBe(401);

    const forbidden = namedResults.get("CT04.metadata.submit-scope");
    expect(forbidden?.status).toBe(403);
    snapshots.recordValue("CT18.error.403", { status: forbidden?.status, body: forbidden?.body });

    const notFound = await call("CT18.error.404", "/route-that-does-not-exist");
    expect(notFound.status).toBe(404);

    const conflict = namedResults.get("CT05.submit.repeat");
    expect(conflict?.status).toBe(409);
    snapshots.recordValue("CT18.error.409", { status: conflict?.status, body: conflict?.body });

    const gone = namedResults.get("CT06.unknown");
    expect(gone?.status).toBe(410);
    snapshots.recordValue("CT18.error.410", { status: gone?.status, body: gone?.body });

    const limited = namedResults.get("CT02.rate.limited");
    expect(limited?.status).toBe(429);
    snapshots.recordValue("CT18.error.429", { status: limited?.status, body: limited?.body });

    const tooLarge = await call("CT18.error.413", "/api/v2/secret/request", withBearer(agent(fixture, "requester").token, {
      ...jsonRequestBody({ public_key: "YQ==", description: "x".repeat(1024 * 1024) })
    }));
    expect(tooLarge.status).toBe(413);

    const oversized = namedResults.get("CT05.submit.oversized");
    expect(oversized?.status).toBe(400);
    snapshots.recordValue("CT18.error.validation", { status: oversized?.status, body: oversized?.body });

    if (process.env.SUT === "rust") {
      if (!adapter.withReadinessFailure) {
        throw new Error("CT18 requires the Rust adapter to force a readiness failure");
      }
      const readiness = await adapter.withReadinessFailure(() => httpRequest(adapter.baseUrl, "/readyz"));
      expect(readiness.status).toBe(503);
      expect(readiness.body).toEqual({ ok: false, checks: { database: "down" } });
      snapshots.recordValue("CT18.error.503", {
        status: readiness.status,
        ok: (readiness.body as { ok: boolean }).ok,
        database: (readiness.body as { checks: { database: string } }).checks.database
      });
      const recovered = await httpRequest(adapter.baseUrl, "/readyz");
      expect(recovered.status).toBe(200);
      return;
    }

    const unavailableApp = await buildApp({
      store: new InMemoryRequestStore(),
      useInMemoryStore: true,
      hmacSecret: "ct18-readiness-dummy-secret",
      readinessChecks: {
        db: async () => { throw new Error("CT18 database dependency unavailable"); },
        redis: async () => { throw new Error("CT18 Redis dependency unavailable"); }
      }
    });
    try {
      const baseUrl = await unavailableApp.listen({ host: "127.0.0.1", port: 0 });
      const readiness = await httpRequest(baseUrl, "/readyz");
      expect(readiness.status).toBe(503);
      expect(readiness.body).toEqual({
        ok: false,
        code: "service_unavailable",
        checks: { database: "down", redis: "down" }
      });
      snapshots.record("CT18.error.503", readiness);
    } finally {
      await unavailableApp.close();
    }
  });

  it("CC01 keeps the agent-skill and gateway clients compatible with live responses", async () => {
    const created = await createSecretRequest("requester", "CC01 client shape");
    const body = requireBody<{ request_id: string; confirmation_code: string; secret_url: string }>(created.response);
    expect(body).toEqual(expect.objectContaining({
      request_id: expect.any(String),
      confirmation_code: expect.any(String),
      secret_url: expect.any(String)
    }));

    const status = await call("CC01.secret-status", `/api/v2/secret/status/${created.requestId}`, withBearer(agent(fixture, "requester").token));
    expect(requireBody(status)).toEqual(expect.objectContaining({ status: "pending" }));

    const gatewayClient = new GatewaySpsClient({
      baseUrl: fixture.baseUrl,
      gatewayBearerToken: agent(fixture, "requester").token
    });
    const gatewayRequest = await gatewayClient.createSecretRequest({
      publicKey: "Y29udHJhY3QtZ2F0ZXdheQ==",
      description: "CC01 gateway client"
    });
    expect(gatewayRequest).toEqual(expect.objectContaining({
      requestId: expect.any(String),
      confirmationCode: expect.any(String),
      secretUrl: expect.any(String)
    }));

    const agentClient = new SpsClient({
      baseUrl: fixture.baseUrl,
      gatewayBearerToken: agent(fixture, "requester").token
    });
    const agentRequest = await agentClient.requestSecret({
      publicKey: "Y29udHJhY3QtYWdlbnQ=",
      description: "CC01 agent-skill client"
    });
    expect(agentRequest).toEqual(expect.objectContaining({
      requestId: expect.any(String),
      confirmationCode: expect.any(String),
      secretUrl: expect.any(String)
    }));

    const exchange = await agentClient.createExchangeRequest({
      publicKey: "Y29udHJhY3QtYWdlbnQ=",
      secretName: SECRET_NAMES.allowed,
      purpose: "CC01 exchange shape",
      fulfillerHint: AGENT_IDS.fulfiller
    });
    expect(exchange).toEqual(expect.objectContaining({
      exchangeId: expect.any(String),
      status: "pending",
      expiresAt: expect.any(Number),
      fulfillmentToken: expect.any(String)
    }));
  });

  if (process.env.SUT === "rust") {
    it("CT19 grants idempotent status-only browser authority bounded by the metadata signature", async () => {
      const created = await createSecretRequest("requester", "CT19 browser recovery status");
      const capabilityPath = `/api/v2/secret/browser-status/${created.requestId}/capability?sig=${encodeURIComponent(created.metadataSig)}`;
      const first = await httpRequest<{ status_sig: string }>(fixture.baseUrl, capabilityPath, { method: "POST" });
      expect(first.status).toBe(200);
      expect(first.body?.status_sig).toMatch(/^\d+\.[A-Za-z0-9_-]+$/);
      addCanaries(fixture, first.body?.status_sig);
      const metadataExpiry = Number(created.metadataSig.split(".", 1)[0]);
      const statusExpiry = Number(first.body?.status_sig.split(".", 1)[0]);
      expect(statusExpiry).toBeLessThanOrEqual(metadataExpiry);

      const retried = await httpRequest<{ status_sig: string }>(fixture.baseUrl, capabilityPath, { method: "POST" });
      expect(retried.status).toBe(200);
      expect(retried.body?.status_sig).toBe(first.body?.status_sig);

      const missingSource = await httpRequest(fixture.baseUrl,
        `/api/v2/secret/browser-status/${created.requestId}/capability`, { method: "POST" });
      expect(missingSource.status).toBe(410);
      expect(missingSource.body).toEqual({ status: "expired" });
      const wrongScopeSource = await httpRequest(fixture.baseUrl,
        `/api/v2/secret/browser-status/${created.requestId}/capability?sig=${encodeURIComponent(created.submitSig)}`,
        { method: "POST" });
      expect(wrongScopeSource.status).toBe(410);
      expect(wrongScopeSource.body).toEqual({ status: "expired" });
      const tamperedSource = created.metadataSig.replace(/.$/, created.metadataSig.endsWith("A") ? "B" : "A");
      const invalidSource = await httpRequest(fixture.baseUrl,
        `/api/v2/secret/browser-status/${created.requestId}/capability?sig=${encodeURIComponent(tamperedSource)}`,
        { method: "POST" });
      expect(invalidSource.status).toBe(410);
      expect(invalidSource.body).toEqual({ status: "expired" });

      const statusPath = `/api/v2/secret/browser-status/${created.requestId}?sig=${encodeURIComponent(first.body?.status_sig ?? "")}`;
      const pending = await httpRequest<{ status: string }>(fixture.baseUrl, statusPath);
      expect(pending.status).toBe(200);
      expect(pending.body).toEqual({ status: "pending" });
      if (!adapter.restartController) {
        throw new Error("CT19 requires a harness-spawned Rust controller to verify status across restart");
      }
      await adapter.restartController();
      const pendingAfterRestart = await httpRequest<{ status: string }>(fixture.baseUrl, statusPath);
      expect(pendingAfterRestart.status).toBe(200);
      expect(pendingAfterRestart.body).toEqual({ status: "pending" });

      const wrongScope = await httpRequest(fixture.baseUrl,
        `/api/v2/secret/browser-status/${created.requestId}?sig=${encodeURIComponent(created.metadataSig)}`);
      expect(wrongScope.status).toBe(410);
      expect(wrongScope.body).toEqual({ status: "expired" });
      const tampered = first.body?.status_sig.replace(/.$/, first.body.status_sig.endsWith("A") ? "B" : "A") ?? "bad";
      const invalid = await httpRequest(fixture.baseUrl,
        `/api/v2/secret/browser-status/${created.requestId}?sig=${encodeURIComponent(tampered)}`);
      expect(invalid.status).toBe(410);
      expect(invalid.body).toEqual({ status: "expired" });
      const missing = await httpRequest(fixture.baseUrl, `/api/v2/secret/browser-status/${created.requestId}`);
      expect(missing.status).toBe(410);
      expect(missing.body).toEqual({ status: "expired" });

      const foreign = await createSecretRequest("requester", "CT19 foreign request");
      const foreignStatus = await httpRequest(fixture.baseUrl,
        `/api/v2/secret/browser-status/${foreign.requestId}?sig=${encodeURIComponent(first.body?.status_sig ?? "")}`);
      expect(foreignStatus.status).toBe(410);
      expect(foreignStatus.body).toEqual({ status: "expired" });

      const statusAsSubmit = await httpRequest(fixture.baseUrl,
        `/api/v2/secret/submit/${created.requestId}?sig=${encodeURIComponent(first.body?.status_sig ?? "")}`,
        jsonRequestBody({ enc: "ZW5jLWN0MTk=", ciphertext: "Y2lwaGVydGV4dC1jdDE5" }));
      expect([403, 410]).toContain(statusAsSubmit.status);
      const statusAsAgentStatus = await httpRequest(fixture.baseUrl, `/api/v2/secret/status/${created.requestId}?sig=${encodeURIComponent(first.body?.status_sig ?? "")}`);
      expect(statusAsAgentStatus.status).toBe(401);
      const statusAsRetrieve = await httpRequest(fixture.baseUrl, `/api/v2/secret/retrieve/${created.requestId}?sig=${encodeURIComponent(first.body?.status_sig ?? "")}`);
      expect(statusAsRetrieve.status).toBe(401);

      // A submit whose response is discarded models the browser's uncertain
      // outcome; the separate capability remains safe to query afterward.
      const submitted = await submitSecret(created.requestId, created.submitSig, "Y2lwaGVydGV4dC1jdDE5");
      expect(submitted.status).toBe(201);
      const submittedStatus = await httpRequest<{ status: string }>(fixture.baseUrl, statusPath);
      expect(submittedStatus.status).toBe(200);
      expect(submittedStatus.body).toEqual({ status: "submitted" });

      const retrieved = await httpRequest(fixture.baseUrl,
        `/api/v2/secret/retrieve/${created.requestId}`,
        withBearer(agent(fixture, "requester").token));
      expect(retrieved.status).toBe(200);
      const consumed = await httpRequest(fixture.baseUrl, statusPath);
      expect(consumed.status).toBe(410);
      expect(consumed.body).toEqual({ status: "expired" });

      // A reloaded page retries issuance after its submit response was lost.
      // Submitting shortens the request deadline below the metadata
      // credential's expiry; the retry must still succeed, clamped to that
      // shorter deadline rather than extending authority.
      const reloaded = await createSecretRequest("requester", "CT19 capability after submit");
      const reloadedSubmit = await submitSecret(reloaded.requestId, reloaded.submitSig, "Y2lwaGVydGV4dC1jdDE5LXJlbG9hZA==");
      expect(reloadedSubmit.status).toBe(201);
      const submittedDeadline = Math.floor(
        (Date.now() + Number(process.env.CONTRACT_SUBMITTED_TTL_SECONDS ?? 3) * 1_000) / 1_000
      );
      const reissued = await httpRequest<{ status_sig: string }>(fixture.baseUrl,
        `/api/v2/secret/browser-status/${reloaded.requestId}/capability?sig=${encodeURIComponent(reloaded.metadataSig)}`,
        { method: "POST" });
      expect(reissued.status).toBe(200);
      addCanaries(fixture, reissued.body?.status_sig);
      const reissuedExpiry = Number(reissued.body?.status_sig.split(".", 1)[0]);
      expect(reissuedExpiry).toBeLessThanOrEqual(Number(reloaded.metadataSig.split(".", 1)[0]));
      expect(reissuedExpiry).toBeLessThanOrEqual(submittedDeadline);
      expect(reissuedExpiry * 1_000).toBeGreaterThan(Date.now());
      const reloadedStatus = await httpRequest<{ status: string }>(fixture.baseUrl,
        `/api/v2/secret/browser-status/${reloaded.requestId}?sig=${encodeURIComponent(reissued.body?.status_sig ?? "")}`);
      expect(reloadedStatus.status).toBe(200);
      expect(reloadedStatus.body).toEqual({ status: "submitted" });

      const expiring = await createSecretRequest("requester", "CT19 expired capability");
      const expiringCapability = await httpRequest<{ status_sig: string }>(fixture.baseUrl,
        `/api/v2/secret/browser-status/${expiring.requestId}/capability?sig=${encodeURIComponent(expiring.metadataSig)}`,
        { method: "POST" });
      expect(expiringCapability.status).toBe(200);
      const expiresAt = Number(expiringCapability.body?.status_sig.split(".", 1)[0]) * 1_000;
      await sleep(Math.max(0, expiresAt - Date.now() + 1_100));
      const expired = await httpRequest(fixture.baseUrl,
        `/api/v2/secret/browser-status/${expiring.requestId}?sig=${encodeURIComponent(expiringCapability.body?.status_sig ?? "")}`);
      expect(expired.status).toBe(410);
      expect(expired.body).toEqual({ status: "expired" });
      const expiredSource = await httpRequest(fixture.baseUrl,
        `/api/v2/secret/browser-status/${expiring.requestId}/capability?sig=${encodeURIComponent(expiring.metadataSig)}`,
        { method: "POST" });
      expect(expiredSource.status).toBe(410);
      expect(expiredSource.body).toEqual({ status: "expired" });
    }, 90_000);
  }
});
