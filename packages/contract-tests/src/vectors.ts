import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { AeadId, CipherSuite, KdfId, KemId } from "hpke-js";
import { ExchangePolicyEngine, hashPolicyDecision } from "../../sps-server/src/services/policy.js";
import { generateScopedSigs, signFulfillmentToken } from "../../sps-server/src/services/crypto.js";
import { deriveAgentFulfillmentTokenSecret, deriveBrowserSigSecret } from "../../sps-server/src/utils/signing-secrets.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));

export interface VectorResults {
  cv01: { metadata: string; submit: string };
  cv02: Record<string, string>;
  cv03: { token: string; issuer: string; audience: string };
}

function readJson<T>(name: string): Promise<T> {
  return readFile(path.join(HERE, "../fixtures", name), "utf8").then((value) => JSON.parse(value) as T);
}

export async function buildVectorResults(): Promise<VectorResults> {
  const cv01 = await readJson<{
    root_secret: string;
    request_id: string;
    expiry: number;
  }>("cv01-signed-link.json");
  const cv02 = await readJson<{ root_secret: string; domains: string[] }>("cv02-derived-secrets.json");
  const rootSecret = cv01.root_secret;
  const cv01Sigs = generateScopedSigs(cv01.request_id, cv01.expiry, deriveBrowserSigSecret(rootSecret));
  const cv03Token = await signFulfillmentToken({
    exchange_id: "b".repeat(64),
    requester_id: "agent-a",
    workspace_id: "workspace-p00",
    secret_name: "finance.api_key",
    purpose: "deploy",
    policy_hash: "c".repeat(64),
    approval_reference: null
  }, rootSecret, 1_700_000_300);

  return {
    cv01: {
      metadata: cv01Sigs.metadataSig,
      submit: cv01Sigs.submitSig
    },
    cv02: Object.fromEntries(cv02.domains.map((domain) => [
      domain,
      domain === "browser-sig"
        ? deriveBrowserSigSecret(cv02.root_secret)
        : deriveAgentFulfillmentTokenSecret(cv02.root_secret)
    ])),
    cv03: {
      token: cv03Token,
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

export async function openHpkeInteropFixture(): Promise<string> {
  const fixture = await readJson<{
    interop_fixture: { recipient_private_key: string; enc: string; ciphertext: string; aad: string };
  }>("cv06-hpke.json");
  const suite = new CipherSuite({
    kem: KemId.DhkemX25519HkdfSha256,
    kdf: KdfId.HkdfSha256,
    aead: AeadId.Chacha20Poly1305
  });
  const bytes = (value: string) => Uint8Array.from(Buffer.from(value, "base64")).buffer;
  const recipientKey = await suite.kem.deserializePrivateKey(bytes(fixture.interop_fixture.recipient_private_key));
  const opened = await suite.open(
    { recipientKey, enc: bytes(fixture.interop_fixture.enc) },
    bytes(fixture.interop_fixture.ciphertext),
    bytes(fixture.interop_fixture.aad)
  );
  return new TextDecoder().decode(opened);
}

export async function openRfc9180Vector(): Promise<string> {
  const fixture = await readJson<{
    rfc_a2_1_base_sequence_0: {
      recipient_private_key_hex: string; enc_hex: string; info_hex: string;
      aad_hex: string; ciphertext_hex: string;
    };
  }>("cv06-hpke.json");
  const vector = fixture.rfc_a2_1_base_sequence_0;
  const suite = new CipherSuite({
    kem: KemId.DhkemX25519HkdfSha256,
    kdf: KdfId.HkdfSha256,
    aead: AeadId.Chacha20Poly1305
  });
  const bytes = (value: string) => Uint8Array.from(Buffer.from(value, "hex")).buffer;
  const recipientKey = await suite.kem.deserializePrivateKey(bytes(vector.recipient_private_key_hex));
  const opened = await suite.open(
    { recipientKey, enc: bytes(vector.enc_hex), info: bytes(vector.info_hex) },
    bytes(vector.ciphertext_hex),
    bytes(vector.aad_hex)
  );
  return Buffer.from(opened).toString("hex");
}

export async function evaluatePolicyVectors(workspaceId = "workspace-p00"): Promise<Array<Record<string, unknown>>> {
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
        policy_hash: null
      };
    }

    return {
      mode: result.decision.mode,
      ruleId: result.decision.ruleId,
      policy_hash: hashPolicyDecision(result.decision, result.allowedFulfillerId, workspaceId)
    };
  });
}
