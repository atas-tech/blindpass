import { createHash, createHmac } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { AeadId, CipherSuite, KdfId, KemId } from "hpke-js";
import { ExchangePolicyEngine, hashPolicyDecision } from "../../sps-server/src/services/policy.js";
import { policyHash, signBrowserPayload, deriveSigningSecret } from "./signing.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));

export interface VectorResults {
  cv01: { metadata: string; submit: string };
  cv02: Record<string, string>;
  cv03: { token: string; issuer: string; audience: string };
}

function readJson<T>(name: string): Promise<T> {
  return readFile(path.join(HERE, "../fixtures", name), "utf8").then((value) => JSON.parse(value) as T);
}

function makeJwt(secret: string): string {
  const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify({
    exchange_id: "b".repeat(64),
    requester_id: "agent-a",
    workspace_id: "workspace-p00",
    secret_name: "finance.api_key",
    purpose: "deploy",
    policy_hash: "c".repeat(64),
    approval_reference: null,
    iss: "sps",
    aud: "agent-fulfill",
    sub: "workspace-p00",
    iat: 1_700_000_000,
    exp: 1_700_000_300
  })).toString("base64url");
  const input = `${header}.${payload}`;
  const signature = createHmac("sha256", deriveSigningSecret(secret, "agent-fulfillment"))
    .update(input)
    .digest("base64url");
  return `${input}.${signature}`;
}

export async function buildVectorResults(): Promise<VectorResults> {
  const cv01 = await readJson<{
    root_secret: string;
    request_id: string;
    expiry: number;
  }>("cv01-signed-link.json");
  const cv02 = await readJson<{ root_secret: string; domains: string[] }>("cv02-derived-secrets.json");
  const rootSecret = cv01.root_secret;

  return {
    cv01: {
      metadata: signBrowserPayload(cv01.request_id, cv01.expiry, "metadata", rootSecret),
      submit: signBrowserPayload(cv01.request_id, cv01.expiry, "submit", rootSecret)
    },
    cv02: Object.fromEntries(cv02.domains.map((domain) => [domain, deriveSigningSecret(cv02.root_secret, domain)])),
    cv03: {
      token: makeJwt(rootSecret),
      issuer: "sps",
      audience: "agent-fulfill"
    }
  };
}

export async function runHpkeRoundTrip(): Promise<{ enc: string; ciphertext: string; plaintext: string }> {
  const suite = new CipherSuite({
    kem: KemId.DhkemX25519HkdfSha256,
    kdf: KdfId.HkdfSha256,
    aead: AeadId.Chacha20Poly1305
  });
  const keyPair = await suite.kem.generateKeyPair();
  const publicKey = await suite.kem.serializePublicKey(keyPair.publicKey);
  const recipientPublicKey = await suite.kem.deserializePublicKey(publicKey);
  const sealed = await suite.seal({ recipientPublicKey }, new TextEncoder().encode("CV06-P00-round-trip").buffer);
  const privateKeyBytes = await suite.kem.serializePrivateKey(keyPair.privateKey);
  const recipientKey = await suite.kem.deserializePrivateKey(privateKeyBytes);
  const opened = await suite.open({ recipientKey, enc: sealed.enc }, sealed.ct);

  return {
    enc: Buffer.from(new Uint8Array(sealed.enc)).toString("base64"),
    ciphertext: Buffer.from(new Uint8Array(sealed.ct)).toString("base64"),
    plaintext: Buffer.from(new Uint8Array(opened)).toString("utf8")
  };
}

export async function evaluatePolicyVectors(): Promise<Array<Record<string, unknown>>> {
  const fixture = await readJson<{
    registry: Array<{ secretName: string; classification: string }>;
    rules: Array<Record<string, unknown>>;
    cases: Array<Record<string, string | null>>;
  }>("cv05-policy.json");
  const engine = new ExchangePolicyEngine(fixture.registry, fixture.rules as never);

  return fixture.cases.map((input) => {
    const result = engine.evaluate({
      requesterId: input.requesterId!,
      secretName: input.secretName!,
      purpose: input.purpose!,
      fulfillerHint: input.fulfillerHint!
    });
    if (!result) {
      return {
        mode: "none",
        ruleId: null,
        policy_hash: null,
        source_hash: null
      };
    }

    return {
      mode: result.decision.mode,
      ruleId: result.decision.ruleId,
      policy_hash: policyHash({
        mode: result.decision.mode,
        approvalRequired: result.decision.approvalRequired,
        ruleId: result.decision.ruleId,
        reason: result.decision.reason,
        approvalReference: result.decision.approvalReference,
        requesterRing: result.decision.requesterRing,
        fulfillerRing: result.decision.fulfillerRing,
        secretName: result.decision.secretName,
        allowedFulfillerId: result.allowedFulfillerId,
        workspaceId: "workspace-p00"
      }),
      source_hash: hashPolicyDecision(result.decision, result.allowedFulfillerId, "workspace-p00")
    };
  });
}

export { createHash };
