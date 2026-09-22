import { createHash, createHmac, generateKeyPairSync, sign as signBytes } from "node:crypto";

export function base64Url(value: Uint8Array | string): string {
  return Buffer.from(value).toString("base64url");
}

export function deriveSigningSecret(rootSecret: string, domain: string): string {
  return createHmac("sha256", rootSecret).update(`blindpass:${domain}`).digest("base64url");
}

export function signBrowserPayload(requestId: string, exp: number, scope: "metadata" | "submit", rootSecret: string): string {
  const derived = deriveSigningSecret(rootSecret, "browser-sig");
  const signature = createHmac("sha256", derived)
    .update(`${requestId}.${exp}.${scope}`)
    .digest("base64url");
  return `${exp}.${signature}`;
}

export function expiredBrowserPayload(requestId: string, scope: "metadata" | "submit", rootSecret: string): string {
  return signBrowserPayload(requestId, Math.floor(Date.now() / 1000) - 10, scope, rootSecret);
}

export function policyHash(input: {
  mode: "allow" | "pending_approval" | "deny";
  approvalRequired: boolean;
  ruleId: string;
  reason: string;
  approvalReference?: string | null;
  requesterRing?: string | null;
  fulfillerRing?: string | null;
  secretName: string;
  allowedFulfillerId: string | null;
  workspaceId?: string | null;
}): string {
  return createHash("sha256")
    .update(JSON.stringify({
      mode: input.mode,
      approvalRequired: input.approvalRequired,
      ruleId: input.ruleId,
      reason: input.reason,
      approvalReference: input.approvalReference ?? null,
      requesterRing: input.requesterRing ?? null,
      fulfillerRing: input.fulfillerRing ?? null,
      secretName: input.secretName,
      allowedFulfillerId: input.allowedFulfillerId ?? null,
      workspaceId: input.workspaceId ?? null
    }))
    .digest("hex");
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
