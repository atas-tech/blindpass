import { generateKeyPairSync, sign as signBytes } from "node:crypto";
import { generateScopedSigs } from "../../sps-server/src/services/crypto.js";
import {
  deriveAgentFulfillmentTokenSecret,
  deriveBrowserSigSecret,
  deriveGuestAccessTokenSecret,
  deriveGuestFulfillmentTokenSecret
} from "../../sps-server/src/utils/signing-secrets.js";

export function base64Url(value: Uint8Array | string): string {
  return Buffer.from(value).toString("base64url");
}

export function deriveSigningSecret(rootSecret: string, domain: string): string {
  switch (domain) {
    case "browser-sig": return deriveBrowserSigSecret(rootSecret);
    case "agent-fulfillment": return deriveAgentFulfillmentTokenSecret(rootSecret);
    case "guest-fulfillment": return deriveGuestFulfillmentTokenSecret(rootSecret);
    case "guest-access": return deriveGuestAccessTokenSecret(rootSecret);
    default: throw new Error(`Unsupported signing domain: ${domain}`);
  }
}

export function signBrowserPayload(requestId: string, exp: number, scope: "metadata" | "submit", rootSecret: string): string {
  const signatures = generateScopedSigs(requestId, exp, deriveBrowserSigSecret(rootSecret));
  return scope === "metadata" ? signatures.metadataSig : signatures.submitSig;
}

export function expiredBrowserPayload(requestId: string, scope: "metadata" | "submit", rootSecret: string): string {
  return signBrowserPayload(requestId, Math.floor(Date.now() / 1000) - 10, scope, rootSecret);
}

export interface ExternalJwtIdentity {
  privateKey: ReturnType<typeof generateKeyPairSync>["privateKey"];
  publicJwk: Record<string, unknown>;
}

export function createExternalJwtIdentity(): ExternalJwtIdentity {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const publicJwk = publicKey.export({ format: "jwk" }) as Record<string, unknown>;
  publicJwk.kid = "contract-ed25519";
  return { privateKey, publicJwk };
}

export function signExternalJwt(
  identity: ExternalJwtIdentity,
  claims: Record<string, unknown>,
  nowSeconds = Math.floor(Date.now() / 1000)
): string {
  const header = base64Url(JSON.stringify({ alg: "EdDSA", kid: "contract-ed25519", typ: "JWT" }));
  const payload = base64Url(JSON.stringify({
    ...claims,
    iat: nowSeconds,
    exp: nowSeconds + 300,
    iss: claims.iss ?? "contract-gateway",
    aud: claims.aud ?? "contract-sps"
  }));
  const signingInput = `${header}.${payload}`;
  const signature = signBytes(null, Buffer.from(signingInput), identity.privateKey);
  return `${signingInput}.${base64Url(signature)}`;
}
