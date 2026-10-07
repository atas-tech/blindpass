import { createHmac, timingSafeEqual } from "node:crypto";
import { deriveAgentFulfillmentTokenSecret, deriveGuestFulfillmentTokenSecret } from "./signing.js";

// Clean-room oracle for the fulfillment-token contract (CV03). The token is a compact HS256 JWT built by hand on
// node:crypto, so it depends on neither SPS nor a JWT library. Its exact bytes are frozen in
// fixtures/cv03-fulfillment-token.json, which the Rust controller also reads.
//
// Contract:
//   header   {"alg":"HS256","typ":"JWT"} (this key order)
//   payload  exchange_id, requester_id, workspace_id (null when absent), secret_name, purpose, policy_hash,
//            approval_reference (null when absent), sub (workspace_id, else requester_id), iss "sps",
//            aud "agent-fulfill" | "guest-fulfill", iat, exp, in that order
//   key      UTF-8 bytes of the kind's derived signing secret
//
// Verification is stricter than the legacy jose call in two ways that cannot matter for a server's own tokens:
// it requires `exp`, and it accepts only alg HS256 (jose, given no allow-list, also takes HS384/HS512 for an
// HMAC key).
export interface FulfillmentTokenClaims {
  exchange_id: string;
  requester_id: string;
  workspace_id?: string;
  secret_name: string;
  purpose: string;
  policy_hash: string;
  approval_reference?: string | null;
}

export type FulfillmentTokenKind = "agent" | "guest";

const encode = (value: unknown): string => Buffer.from(JSON.stringify(value)).toString("base64url");

function audience(kind: FulfillmentTokenKind): "agent-fulfill" | "guest-fulfill" {
  return kind === "guest" ? "guest-fulfill" : "agent-fulfill";
}

function signingSecret(rootSecret: string, kind: FulfillmentTokenKind): string {
  return kind === "guest" ? deriveGuestFulfillmentTokenSecret(rootSecret) : deriveAgentFulfillmentTokenSecret(rootSecret);
}

function sign(input: string, secret: string): string {
  return createHmac("sha256", secret).update(input).digest("base64url");
}

async function mint(claims: FulfillmentTokenClaims, rootSecret: string, expiresAt: number, kind: FulfillmentTokenKind): Promise<string> {
  const signingInput = `${encode({ alg: "HS256", typ: "JWT" })}.${encode({
    exchange_id: claims.exchange_id,
    requester_id: claims.requester_id,
    workspace_id: claims.workspace_id ?? null,
    secret_name: claims.secret_name,
    purpose: claims.purpose,
    policy_hash: claims.policy_hash,
    approval_reference: claims.approval_reference ?? null,
    sub: claims.workspace_id ?? claims.requester_id,
    iss: "sps",
    aud: audience(kind),
    iat: Math.floor(Date.now() / 1000),
    exp: expiresAt
  })}`;
  return `${signingInput}.${sign(signingInput, signingSecret(rootSecret, kind))}`;
}

export function signFulfillmentToken(claims: FulfillmentTokenClaims, rootSecret: string, expiresAt: number): Promise<string> {
  return mint(claims, rootSecret, expiresAt, "agent");
}

export function signGuestFulfillmentToken(claims: FulfillmentTokenClaims, rootSecret: string, expiresAt: number): Promise<string> {
  return mint(claims, rootSecret, expiresAt, "guest");
}

function parseObject(segment: string): Record<string, unknown> | null {
  try {
    const value: unknown = JSON.parse(Buffer.from(segment, "base64url").toString("utf8"));
    return value !== null && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

function verifyAs(token: string, rootSecret: string, kind: FulfillmentTokenKind, nowSeconds: number): FulfillmentTokenClaims | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [headerSegment, payloadSegment, signature] = parts as [string, string, string];
  const header = parseObject(headerSegment);
  const payload = parseObject(payloadSegment);
  if (!header || !payload || header.alg !== "HS256") return null;

  const expected = Buffer.from(sign(`${headerSegment}.${payloadSegment}`, signingSecret(rootSecret, kind)));
  const actual = Buffer.from(signature);
  if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) return null;

  const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (payload.iss !== "sps" || !audiences.includes(audience(kind))) return null;
  if (typeof payload.exp !== "number" || payload.exp <= nowSeconds) return null;
  if (payload.nbf !== undefined && (typeof payload.nbf !== "number" || payload.nbf > nowSeconds)) return null;

  const text = (value: unknown): string | null => (typeof value === "string" && value !== "" ? value : null);
  const exchangeId = text(payload.exchange_id);
  const requesterId = text(payload.requester_id);
  const secretName = text(payload.secret_name);
  const purpose = text(payload.purpose);
  const policyHash = text(payload.policy_hash);
  if (!exchangeId || !requesterId || !secretName || !purpose || !policyHash) return null;

  return {
    exchange_id: exchangeId,
    requester_id: requesterId,
    workspace_id: typeof payload.workspace_id === "string" ? payload.workspace_id : undefined,
    secret_name: secretName,
    purpose,
    policy_hash: policyHash,
    approval_reference: typeof payload.approval_reference === "string" ? payload.approval_reference : payload.approval_reference === null ? null : undefined
  };
}

export async function verifyFulfillmentToken(
  token: string,
  rootSecret: string
): Promise<FulfillmentTokenClaims & { tokenKind: FulfillmentTokenKind }> {
  const nowSeconds = Math.floor(Date.now() / 1000);
  for (const tokenKind of ["agent", "guest"] as const) {
    const claims = verifyAs(token, rootSecret, tokenKind, nowSeconds);
    if (claims) return { ...claims, tokenKind };
  }
  throw new Error("Invalid fulfillment token");
}
