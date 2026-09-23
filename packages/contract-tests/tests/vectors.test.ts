import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { SignJWT } from "jose";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  CONFIRMATION_CODE_ADJECTIVES,
  CONFIRMATION_CODE_NOUNS,
  verifyFulfillmentToken,
  verifyPayload
} from "../../sps-server/src/services/crypto.js";
import { deriveAgentFulfillmentTokenSecret, deriveBrowserSigSecret } from "../../sps-server/src/utils/signing-secrets.js";
import { buildVectorResults, evaluatePolicyVectors, openHpkeInteropFixture, openRfc9180Vector, runHpkeRoundTrip } from "../src/vectors.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));

afterEach(() => {
  vi.useRealTimers();
});

describe("P00 golden vectors", () => {
  it("CV01 signs browser links with scope separation", async () => {
    const vectors = await buildVectorResults();
    const fixture = JSON.parse(await readFile(path.join(HERE, "../fixtures/cv01-signed-link.json"), "utf8")) as {
      root_secret: string;
      request_id: string;
      expiry: number;
    };
    expect(vectors.cv01.metadata).toMatch(/^\d+\.[A-Za-z0-9_-]{43}$/);
    expect(vectors.cv01.submit).toMatch(/^\d+\.[A-Za-z0-9_-]{43}$/);
    expect(vectors.cv01.metadata).not.toBe(vectors.cv01.submit);
    expect(vectors.cv01).toEqual({
      metadata: "1893456000.QiWsb6-OdGimp89Li--_FXx0vecvkjPFlEXG7XIMebU",
      submit: "1893456000.sPZHTFHnECuhdZtEVdHcw_CZVQwEk7c2viseMrYK4F0"
    });
    const browserSecret = deriveBrowserSigSecret(fixture.root_secret);
    expect(verifyPayload(fixture.request_id, "metadata", vectors.cv01.metadata, browserSecret, fixture.expiry - 1)).toEqual({
      ok: true,
      exp: fixture.expiry
    });
    expect(verifyPayload(fixture.request_id, "submit", vectors.cv01.metadata, browserSecret, fixture.expiry - 1)).toEqual({
      ok: false,
      reason: "invalid"
    });
    expect(verifyPayload(fixture.request_id, "metadata", `${vectors.cv01.metadata.slice(0, -1)}A`, browserSecret, fixture.expiry - 1)).toEqual({
      ok: false,
      reason: "invalid"
    });
    expect(verifyPayload(fixture.request_id, "metadata", vectors.cv01.metadata, browserSecret, fixture.expiry + 1)).toEqual({
      ok: false,
      reason: "expired"
    });
  });

  it("CV02 derives domain-separated signing secrets", async () => {
    const vectors = await buildVectorResults();
    expect(Object.keys(vectors.cv02)).toEqual(["browser-sig", "agent-fulfillment"]);
    expect(vectors.cv02["browser-sig"]).toHaveLength(43);
    expect(vectors.cv02["agent-fulfillment"]).toHaveLength(43);
    expect(vectors.cv02["browser-sig"]).not.toBe(vectors.cv02["agent-fulfillment"]);
    expect(vectors.cv02).toEqual({
      "browser-sig": "wH9iVWHWBxdNCoa5EoYZQ-PP9Axey8C0Jwrwpz7Exuc",
      "agent-fulfillment": "77uVRAIUqv-1ek5FF03jVB6z9dGZZbSK_TvCJTuM-cc"
    });
  });

  it("CV03 emits a stable HS256 fulfillment-token shape", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(1_700_000_000_000));
    const vectors = await buildVectorResults();
    const fixture = JSON.parse(await readFile(path.join(HERE, "../fixtures/cv01-signed-link.json"), "utf8")) as {
      root_secret: string;
    };
    expect(vectors.cv03.token.split(".")).toHaveLength(3);
    expect(vectors.cv03).toMatchObject({ issuer: "sps", audience: "agent-fulfill" });
    const [header, payload, signature] = vectors.cv03.token.split(".");
    expect(JSON.parse(Buffer.from(header!, "base64url").toString())).toEqual({ alg: "HS256", typ: "JWT" });
    expect(JSON.parse(Buffer.from(payload!, "base64url").toString())).toMatchObject({
      exchange_id: "b".repeat(64), requester_id: "agent-a", workspace_id: "workspace-p00",
      secret_name: "finance.api_key", policy_hash: "c".repeat(64),
      iss: "sps", aud: "agent-fulfill", iat: 1_700_000_000, exp: 1_700_000_300
    });
    expect(signature).toBe("Ia6yMQOsaw7DSkiUtveQWvB-Zts5gbcvJD4bUFhy4Lk");
    await expect(verifyFulfillmentToken(vectors.cv03.token, fixture.root_secret)).resolves.toMatchObject({
      exchange_id: "b".repeat(64),
      requester_id: "agent-a",
      workspace_id: "workspace-p00",
      secret_name: "finance.api_key",
      purpose: "deploy",
      policy_hash: "c".repeat(64),
      tokenKind: "agent"
    });

    const tokenSecret = new TextEncoder().encode(deriveAgentFulfillmentTokenSecret(fixture.root_secret));
    const claims = {
      exchange_id: "b".repeat(64),
      requester_id: "agent-a",
      workspace_id: "workspace-p00",
      secret_name: "finance.api_key",
      purpose: "deploy",
      policy_hash: "c".repeat(64),
      approval_reference: null
    };
    const wrongAudience = await new SignJWT(claims)
      .setProtectedHeader({ alg: "HS256", typ: "JWT" })
      .setSubject("workspace-p00")
      .setIssuer("sps")
      .setAudience("wrong-audience")
      .setIssuedAt(1_700_000_000)
      .setExpirationTime(1_700_000_300)
      .sign(tokenSecret);
    const expired = await new SignJWT(claims)
      .setProtectedHeader({ alg: "HS256", typ: "JWT" })
      .setSubject("workspace-p00")
      .setIssuer("sps")
      .setAudience("agent-fulfill")
      .setIssuedAt(1_699_999_000)
      .setExpirationTime(1_699_999_999)
      .sign(tokenSecret);
    await expect(verifyFulfillmentToken(wrongAudience, fixture.root_secret)).rejects.toThrow("Invalid fulfillment token");
    await expect(verifyFulfillmentToken(expired, fixture.root_secret)).rejects.toThrow("Invalid fulfillment token");
  });

  it("CV04 preserves the confirmation-code dictionary and shape", async () => {
    const fixture = JSON.parse(await readFile(path.join(HERE, "../fixtures/cv04-confirmation-code.json"), "utf8")) as {
      adjectives: string[];
      nouns: string[];
      number_min: number;
      number_max: number;
      format: string;
    };
    expect(fixture.adjectives).toEqual(CONFIRMATION_CODE_ADJECTIVES);
    expect(fixture.nouns).toEqual(CONFIRMATION_CODE_NOUNS);
    expect(fixture.number_min).toBe(0);
    expect(fixture.number_max).toBe(99);
    expect(fixture.format).toBe("ADJECTIVE-NOUN-00");
  });

  it("CV05 evaluates policy decisions and hashes identically", async () => {
    const results = await evaluatePolicyVectors();
    const fixture = JSON.parse(await readFile(path.join(HERE, "../fixtures/cv05-policy.json"), "utf8")) as {
      cases: Array<{ expectedMode: string; expectedRuleId: string | null }>;
    };
    expect(results).toHaveLength(fixture.cases.length);
    expect(results.map((result) => result.mode)).toEqual(fixture.cases.map((testCase) => testCase.expectedMode));
    expect(results.map((result) => result.ruleId)).toEqual(fixture.cases.map((testCase) => testCase.expectedRuleId));
    expect(results.map((result) => result.mode)).toEqual(["allow", "pending_approval", "none", "none", "allow"]);
    expect(results.map((result) => result.policy_hash)).toEqual([
      "6b81aae31baf41a8d34abdc5cf033d111ff6ae2abd25510fb9304f6622407eb4",
      "2725cbdd7c1da2ad27e7fc73b27745d7fef175f962d4c4210dbebbe6845551b3",
      null, null,
      "9788fc2bef8cff976f886422e95e24f9024fb244ecef4a07162acb7252389fd4"
    ]);
  });

  it("CV06 runs the TypeScript HPKE round trip with the accepted suite", async () => {
    const result = await runHpkeRoundTrip();
    expect(result.enc).toMatch(/^[A-Za-z0-9+/]+=*$/);
    expect(result.ciphertext).toMatch(/^[A-Za-z0-9+/]+=*$/);
    expect(result.plaintext).toBe("CV06-P00-round-trip");
    expect(await openHpkeInteropFixture()).toBe("P01-CROSS-RUNTIME-CANARY");
    expect(await openRfc9180Vector()).toBe("4265617574792069732074727574682c20747275746820626561757479");
  });
});
