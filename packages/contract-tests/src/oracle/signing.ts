import { createHmac, timingSafeEqual } from "node:crypto";

// Clean-room oracle for the signed-link contract (CV01, CV02). It is written from the contract, not copied from a
// server, and is pinned by the frozen vectors in fixtures/cv01-signed-link.json and cv02-derived-secrets.json plus
// the expected values in tests/vectors.test.ts. Until SPS source is removed, tests/ts-oracle-parity.test.ts also
// proves it agrees with the legacy implementation.
//
// Contract:
//   signing secret  = base64url(HMAC-SHA256(key = root secret, data = "blindpass:" + domain))
//   link signature  = base64url(HMAC-SHA256(key = browser secret, data = requestId + "." + exp + "." + scope))
//   link token      = exp + "." + link signature
export type SigningDomain = "browser-sig" | "agent-fulfillment" | "guest-fulfillment" | "guest-access";
export type LinkScope = "metadata" | "submit";

export function deriveSigningSecret(rootSecret: string, domain: SigningDomain): string {
  return createHmac("sha256", rootSecret).update(`blindpass:${domain}`).digest("base64url");
}

export const deriveBrowserSigSecret = (rootSecret: string): string => deriveSigningSecret(rootSecret, "browser-sig");
export const deriveAgentFulfillmentTokenSecret = (rootSecret: string): string => deriveSigningSecret(rootSecret, "agent-fulfillment");
export const deriveGuestFulfillmentTokenSecret = (rootSecret: string): string => deriveSigningSecret(rootSecret, "guest-fulfillment");
export const deriveGuestAccessTokenSecret = (rootSecret: string): string => deriveSigningSecret(rootSecret, "guest-access");

function linkSignature(requestId: string, exp: number, scope: LinkScope, secret: string): string {
  return createHmac("sha256", secret).update(`${requestId}.${exp}.${scope}`).digest("base64url");
}

export function generateScopedSigs(requestId: string, exp: number, secret: string): { metadataSig: string; submitSig: string } {
  return {
    metadataSig: `${exp}.${linkSignature(requestId, exp, "metadata", secret)}`,
    submitSig: `${exp}.${linkSignature(requestId, exp, "submit", secret)}`
  };
}

export type LinkVerification = { ok: true; exp: number } | { ok: false; reason: "invalid" | "expired" };

// Same observable rules as the legacy verifier: two dot-separated parts, an integer prefix that parses as a
// positive expiry (trailing text after the digits is ignored by parseInt), expiry checked before the signature,
// and a link that expires exactly at `nowSeconds` still valid. One deliberate difference: a signature whose byte
// length differs from the expected one is "invalid" here, where the legacy code throws a RangeError.
export function verifyPayload(
  requestId: string,
  scope: LinkScope,
  token: string,
  secret: string,
  nowSeconds = Math.floor(Date.now() / 1000)
): LinkVerification {
  const parts = token.split(".");
  if (parts.length !== 2) return { ok: false, reason: "invalid" };
  const [expRaw, signature] = parts as [string, string];
  const exp = Number.parseInt(expRaw, 10);
  if (!Number.isFinite(exp) || exp <= 0 || !signature) return { ok: false, reason: "invalid" };
  if (exp < nowSeconds) return { ok: false, reason: "expired" };
  const expected = Buffer.from(linkSignature(requestId, exp, scope, secret));
  const actual = Buffer.from(signature);
  if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) return { ok: false, reason: "invalid" };
  return { ok: true, exp };
}
