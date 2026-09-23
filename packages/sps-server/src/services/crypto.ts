import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { jwtVerify, SignJWT } from "jose";
import type { PolicyDecision, RequestScope } from "../types.js";
import {
  deriveAgentFulfillmentTokenSecret,
  deriveGuestFulfillmentTokenSecret
} from "../utils/signing-secrets.js";

export const CONFIRMATION_CODE_ADJECTIVES = [
  "BLUE",
  "GREEN",
  "SILVER",
  "BRIGHT",
  "BOLD",
  "SWIFT",
  "CALM",
  "NOBLE"
];

export const CONFIRMATION_CODE_NOUNS = [
  "FOX",
  "RIVER",
  "MOUNTAIN",
  "FALCON",
  "HARBOR",
  "PINE",
  "MEADOW",
  "FIELD"
];

interface CanonicalPayload {
  requestId: string;
  exp: number;
  scope: RequestScope;
}

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

function canonicalize(payload: CanonicalPayload): string {
  return `${payload.requestId}.${payload.exp}.${payload.scope}`;
}

function hmac(payload: string, secret: string): string {
  return createHmac("sha256", secret).update(payload).digest("base64url");
}

function signaturesMatch(expected: string, actual: string): boolean {
  if (expected.length !== actual.length) {
    return false;
  }

  return timingSafeEqual(Buffer.from(expected), Buffer.from(actual));
}

export function generateRequestId(): string {
  return randomBytes(32).toString("hex");
}

export function generateConfirmationCode(): string {
  const adjective = CONFIRMATION_CODE_ADJECTIVES[randomBytes(1)[0] % CONFIRMATION_CODE_ADJECTIVES.length];
  const noun = CONFIRMATION_CODE_NOUNS[randomBytes(1)[0] % CONFIRMATION_CODE_NOUNS.length];
  const number = randomBytes(1)[0] % 100;
  return `${adjective}-${noun}-${number.toString().padStart(2, "0")}`;
}

export function signPayload(payload: CanonicalPayload, secret: string): string {
  const signature = hmac(canonicalize(payload), secret);
  return `${payload.exp}.${signature}`;
}

export function verifyPayload(
  requestId: string,
  scope: RequestScope,
  token: string,
  secret: string,
  nowSeconds = Math.floor(Date.now() / 1000)
): { ok: true; exp: number } | { ok: false; reason: "invalid" | "expired" } {
  const parts = token.split(".");
  if (parts.length !== 2) {
    return { ok: false, reason: "invalid" };
  }

  const [expRaw, signature] = parts;
  const exp = Number.parseInt(expRaw, 10);
  if (!Number.isFinite(exp) || exp <= 0 || !signature) {
    return { ok: false, reason: "invalid" };
  }

  if (exp < nowSeconds) {
    return { ok: false, reason: "expired" };
  }

  const expected = hmac(canonicalize({ requestId, exp, scope }), secret);
  if (!signaturesMatch(expected, signature)) {
    return { ok: false, reason: "invalid" };
  }

  return { ok: true, exp };
}

export function generateScopedSigs(requestId: string, exp: number, secret: string): { metadataSig: string; submitSig: string } {
  return {
    metadataSig: signPayload({ requestId, exp, scope: "metadata" }, secret),
    submitSig: signPayload({ requestId, exp, scope: "submit" }, secret)
  };
}

function fulfillmentSecret(secret: string): Uint8Array {
  return new TextEncoder().encode(secret);
}

function fulfillmentAudience(tokenKind: FulfillmentTokenKind): "agent-fulfill" | "guest-fulfill" {
  return tokenKind === "guest" ? "guest-fulfill" : "agent-fulfill";
}

function fulfillmentSigningSecret(rootSecret: string, tokenKind: FulfillmentTokenKind): string {
  return tokenKind === "guest"
    ? deriveGuestFulfillmentTokenSecret(rootSecret)
    : deriveAgentFulfillmentTokenSecret(rootSecret);
}

export async function signFulfillmentToken(
  claims: FulfillmentTokenClaims,
  rootSecret: string,
  expiresAt: number
): Promise<string> {
  return signNamedFulfillmentToken(claims, rootSecret, expiresAt, "agent");
}

export async function signGuestFulfillmentToken(
  claims: FulfillmentTokenClaims,
  rootSecret: string,
  expiresAt: number
): Promise<string> {
  return signNamedFulfillmentToken(claims, rootSecret, expiresAt, "guest");
}

async function signNamedFulfillmentToken(
  claims: FulfillmentTokenClaims,
  rootSecret: string,
  expiresAt: number,
  tokenKind: FulfillmentTokenKind
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({
    exchange_id: claims.exchange_id,
    requester_id: claims.requester_id,
    workspace_id: claims.workspace_id ?? null,
    secret_name: claims.secret_name,
    purpose: claims.purpose,
    policy_hash: claims.policy_hash,
    approval_reference: claims.approval_reference ?? null
  })
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setSubject(claims.workspace_id ?? claims.requester_id)
    .setIssuer("sps")
    .setAudience(fulfillmentAudience(tokenKind))
    .setIssuedAt(now)
    .setExpirationTime(expiresAt)
    .sign(fulfillmentSecret(fulfillmentSigningSecret(rootSecret, tokenKind)));
}

export async function verifyFulfillmentToken(
  token: string,
  rootSecret: string
): Promise<FulfillmentTokenClaims & { tokenKind: FulfillmentTokenKind }> {
  for (const tokenKind of ["agent", "guest"] as const) {
    try {
      const { payload } = await jwtVerify(token, fulfillmentSecret(fulfillmentSigningSecret(rootSecret, tokenKind)), {
        issuer: "sps",
        audience: fulfillmentAudience(tokenKind)
      });

      const exchangeId = typeof payload.exchange_id === "string" ? payload.exchange_id : null;
      const requesterId = typeof payload.requester_id === "string" ? payload.requester_id : null;
      const workspaceId = typeof payload.workspace_id === "string" ? payload.workspace_id : undefined;
      const secretName = typeof payload.secret_name === "string" ? payload.secret_name : null;
      const purpose = typeof payload.purpose === "string" ? payload.purpose : null;
      const policyHash = typeof payload.policy_hash === "string" ? payload.policy_hash : null;
      const approvalReference =
        typeof payload.approval_reference === "string" ? payload.approval_reference : payload.approval_reference === null ? null : undefined;

      if (!exchangeId || !requesterId || !secretName || !purpose || !policyHash) {
        throw new Error("Invalid fulfillment token payload");
      }

      return {
        exchange_id: exchangeId,
        requester_id: requesterId,
        workspace_id: workspaceId,
        secret_name: secretName,
        purpose,
        policy_hash: policyHash,
        approval_reference: approvalReference,
        tokenKind
      };
    } catch {
      // Try the next fulfillment-token domain.
    }
  }

  throw new Error("Invalid fulfillment token");
}
