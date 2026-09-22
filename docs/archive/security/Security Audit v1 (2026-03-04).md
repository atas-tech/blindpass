# 🔒 Security Audit Report — blindpass

> Historical record, archived during the 2026-09-22 documentation alignment. Dates, checkboxes, commands, and proposed decisions below describe their original review period; they do not establish current support or authorize new work. See the [current documentation](../../README.md) and [roadmap](../../product/Roadmap.md).

**Date**: 2026-03-04\
**Scope**: Full codebase review of `blindpass` v0.1.0\
**Packages reviewed**: `sps-server`, `gateway`, `agent-skill`, `browser-ui`, scripts

---

## Executive Summary

The blindpass project implements a **Secure Secret Provisioning Service (SPS)** that enables humans to securely deliver secrets to AI agents via HPKE end-to-end encryption. The architecture demonstrates strong security fundamentals — proper use of HPKE (X25519 + ChaCha20-Poly1305), Ed25519 JWT authentication, scoped HMAC signatures, atomic single-use retrieval, and private key zeroing.

However, several findings across **Critical**, **High**, **Medium**, and **Low** severity levels should be addressed before production deployment.

**Findings Summary**:

| Severity | Count |
|----------|-------|
| 🔴 Critical | 2 |
| 🟠 High | 4 |
| 🟡 Medium | 5 |
| 🔵 Low / Informational | 5 |

---

## 🔴 Critical Findings

### C-1: HMAC Signature Comparison Uses Non-Constant-Time Equality

**File**: [crypto.ts](../../../packages/sps-server/src/services/crypto.ts)

```typescript
if (expected !== signature) {
  return { ok: false, reason: "invalid" };
}
```

The HMAC verification uses JavaScript's `!==` string equality, which is **not constant-time**. This makes the system vulnerable to **timing side-channel attacks**, where an attacker can determine the correct HMAC byte-by-byte by measuring response times.

**Recommendation**: Use `crypto.timingSafeEqual()` for HMAC comparison:

```typescript
import { timingSafeEqual } from "node:crypto";

const expectedBuf = Buffer.from(expected, "base64url");
const signatureBuf = Buffer.from(signature, "base64url");
if (expectedBuf.length !== signatureBuf.length || !timingSafeEqual(expectedBuf, signatureBuf)) {
  return { ok: false, reason: "invalid" };
}
```

---

### C-2: Default HMAC Secret Is a Hardcoded String

**File**: [index.ts](../../../packages/sps-server/src/index.ts)

```typescript
const hmacSecret = options.hmacSecret ?? process.env.SPS_HMAC_SECRET ?? "local-dev-hmac-secret";
```

If `SPS_HMAC_SECRET` is not set in the environment, the fallback `"local-dev-hmac-secret"` is used. In a deployment where the env var is accidentally omitted, **all browser-facing signatures become trivially forgeable** by anyone who reads the source code.

**Recommendation**:
- Throw an error if `SPS_HMAC_SECRET` is missing in production mode, similar to what's done for in-memory stores.
- Enforce a minimum entropy/length requirement.

```typescript
if (process.env.NODE_ENV === "production" && !process.env.SPS_HMAC_SECRET) {
  throw new Error("SPS_HMAC_SECRET is required in production");
}
```

---

## 🟠 High Findings

### H-1: Redis `updateRequest` Has a TOCTOU Race Condition

**File**: [redis.ts](../../../packages/sps-server/src/services/redis.ts)

`updateRequest` performs GET → modify → SET as separate Redis commands without any transaction or Lua script atomicity. Two concurrent calls could read the same state and overwrite each other's changes.

While `atomicRetrieveAndDelete` correctly uses a Lua script, `updateRequest` (used in the submit flow) does not. A race between two concurrent `/submit` calls could result in inconsistent state.

**Recommendation**: Wrap the GET + SET in a Lua script or use Redis `WATCH`/`MULTI`/`EXEC` for optimistic locking.

---

### H-2: No Rate Limiting on Any Endpoint

No rate limiting is configured on any of the API endpoints. This exposes the service to:
- **Brute-force attacks** on request IDs (though 256-bit IDs make this impractical for ID guessing)
- **Resource exhaustion** via rapid creation of secret requests (`POST /request`)
- **DoS against Redis** by filling the store with pending requests

**Recommendation**: Add rate limiting at minimum on `POST /api/v2/secret/request` and `POST /api/v2/secret/submit/:id`. Consider using `@fastify/rate-limit`.

---

### H-3: Confirmation Code Has Insufficient Entropy

**File**: [crypto.ts](../../../packages/sps-server/src/services/crypto.ts)

```typescript
const adjective = ADJECTIVES[randomBytes(1)[0] % ADJECTIVES.length];  // 8 options
const noun = NOUNS[randomBytes(1)[0] % NOUNS.length];                  // 8 options
const number = randomBytes(1)[0] % 100;                                 // 100 options
```

The confirmation code has only **8 × 8 × 100 = 6,400 possible values** (~12.6 bits of entropy). Additionally, using `randomBytes(1)[0] % 8` introduces **modular bias** since 256 is divisible by 8 (no bias in this case), but `% 100` on a byte (0–255) is biased: values 0–55 are ~1.17× more likely than 56–99.

More importantly, 6,400 combinations is very low — it's a human-readable confirmation code, not a security token, but it should still be hard enough that an attacker can't present a plausible-looking code to social engineer the user.

**Recommendation**: Increase the word lists or add a third word to raise the entropy to at least 20+ bits.

---

### H-4: CORS Is Configured with `origin: true` (Reflects Any Origin)

**File**: [index.ts](../../../packages/sps-server/src/index.ts)

```typescript
await app.register(cors, {
  origin: true,
  credentials: false
});
```

`origin: true` reflects any requesting origin in the `Access-Control-Allow-Origin` header. While `credentials: false` means cookies won't be sent, this still allows **any website** to make API requests to the SPS server from a browser, which could be exploited for:
- Information disclosure (reading metadata about pending requests)
- Submitting secrets to arbitrary request IDs if signatures are somehow leaked

**Recommendation**: Restrict to the actual deployment origin(s), or at minimum restrict to the same origin.

---

## 🟡 Medium Findings

### M-1: Gateway Code Generator Uses `Math.random()` Instead of CSPRNG

**File**: [code-generator.ts](../../../packages/gateway/src/code-generator.ts)

```typescript
const adjective = ADJECTIVES[Math.floor(Math.random() * ADJECTIVES.length)];
const noun = NOUNS[Math.floor(Math.random() * NOUNS.length)];
const num = Math.floor(Math.random() * 100)
```

This uses `Math.random()` which is **not cryptographically secure**. While the server-side `generateConfirmationCode` correctly uses `randomBytes`, this gateway-side duplicate uses a predictable PRNG. If this code is used in any security-relevant context, the output is predictable.

**Recommendation**: Use `crypto.randomBytes()` or `crypto.getRandomValues()` consistently.

---

### M-2: No CSP (Content-Security-Policy) Header

The Vite-built HTML page has no `Content-Security-Policy` header. While the deployment architecture separates the SPA from the API, CSP is still critical for preventing XSS attacks on the secret input page. If an XSS vulnerability existed in the SPA frontend, an attacker could extract the secret before encryption.

**Recommendation**: Add a strict CSP header via standard `<meta>` tag in `index.html` or at the CDN/Hosting Edge.
```html
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self' http://localhost:3100 https://api.yourdomain.com; frame-ancestors 'none'">
```

---

### M-3: Static Asset Serving Could Expose Unintended Files (RESOLVED)

*(Note: Resolved as of the frontend decoupling. The `sps-server` no longer serves static assets.)*

Previously, the `/ui/*` route served arbitrary files from the `browser-ui` directory. While there was a path traversal check, the content-type detection was based on file extension only.

**Resolution**: The `browser-ui` is now a standalone Vite single-page application. The `sps-server` API no longer has any static file serving routes (`get("/ui/*")` removed). This vulnerability has been entirely mitigated by architectural decoupling.

---

### M-4: JWKS Cache Has No TTL / No Revocation Mechanism

**File**: [auth.ts](../../../packages/sps-server/src/middleware/auth.ts)

The JWKS is loaded from a file and cached indefinitely. If a gateway key is compromised and rotated:
- The old key remains cached until server restart
- There's no mechanism to force cache invalidation
- File-based JWKS distribution requires manual file updates on every SPS instance

**Recommendation**: Add a TTL to the JWKS cache and consider supporting JWKS URIs for automated rotation.

---

### M-5: Browser UI Does Not Verify Confirmation Code Binding

The browser UI at `/r/:id` displays the confirmation code from the metadata endpoint to the human, but there's no mechanism for the human to verify this code against the agent's out-of-band display beyond manual visual comparison. If an attacker could intercept the chat channel and replace the URL with their own request, the human might submit the secret to the attacker's public key.

This is acknowledged as a design limitation of the confirmation code approach, but it's worth noting that the confirmation code doesn't cryptographically bind the human's browser session to the agent's request — it's purely a human-readability aid.

---

## 🔵 Low / Informational Findings

### L-1: Private Key File Permissions on Gateway Identity

**File**: [identity.ts](../../../packages/gateway/src/identity.ts)

The gateway key file is correctly written with `mode: 0o600`, ✅ but is the JWKS file:

```typescript
// identity.ts line 126
await writeFile(jwksPath, JSON.stringify(getJWKS(identity), null, 2));
// No mode specified — defaults to 0o666 (umask-dependent)
```

The JWKS file only contains public keys so this is informational, but explicitly setting permissions is good practice.

---

### L-2: Audit Log Goes Only to `console.info`

**File**: [audit.ts](../../../packages/sps-server/src/services/audit.ts)

Audit events go only to stdout via `console.info`. In production, this requires external log collection (which may or may not be in place). If the process crashes, buffered log entries may be lost.

**Recommendation**: For production, ship audit events to a durable, append-only store (e.g., dedicated audit log stream).

---

### L-3: No `X-Content-Type-Options` or Other Security Headers

Only `Referrer-Policy` is set. Missing headers include:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Strict-Transport-Security` (for HTTPS deployments)
- `X-XSS-Protection: 0` (to disable legacy browser XSS filters that can cause issues)

**Recommendation**: Add comprehensive security headers via `@fastify/helmet` or manually.

---

### L-4: `SecretStore.get()` Should Return Defensive Copies

**File**: [secret-store.ts](../../../packages/agent-skill/src/secret-store.ts)

```typescript
get(name: string): Buffer | null {
  const value = this.store.get(name);
  return value ? Buffer.from(value) : null;
}
```

✅ Good — `Buffer.from(value)` creates a copy, preventing mutation of the internal buffer. This is done correctly.

---

### L-5: `.gitignore` Covers `.env` but Not `gateway-key.json`

**File**: [.gitignore](../../../.gitignore)

The `.gitignore` excludes `.env` but does not exclude `gateway-key.json` (the private key file for gateway identity). If a developer runs the E2E test or server from the project root, `gateway-key.json` would be created in the project directory and could be accidentally committed.

**Recommendation**: Add `gateway-key.json` and `jwks.json` to `.gitignore`.

---

## ✅ Positive Security Findings

The following aspects of the codebase reflect **good security practices**:

| Area | Assessment |
|------|------------|
| **HPKE Cipher Suite** | X25519 + HKDF-SHA256 + ChaCha20-Poly1305 — excellent modern choice |
| **Private Key Zeroing** | `destroyKeyPair()` correctly `fill(0)` on the Buffer ✅ |
| **SecretStore.toJSON()** | Returns `"[REDACTED]"` to prevent serialization leaks ✅ |
| **Atomic Retrieve-and-Delete** | Lua script ensures single-use retrieval ✅ |
| **JWT Auth** | Ed25519 (EdDSA) with proper issuer/audience/subject/role validation ✅ |
| **Scoped Signatures** | Separate `metadata` and `submit` HMAC scopes prevent scope confusion ✅ |
| **Input Validation** | Strict AJV schemas with `additionalProperties: false` ✅ |
| **Egress Filter** | URL redaction from outbound LLM responses ✅ |
| **Referrer-Policy** | `no-referrer` prevents secret URL leakage via referrer headers ✅ |
| **Path Traversal Protection** | `/ui/*` route validates path stays within `browserUiDir` ✅ |
| **In-Memory Store Blocked in Prod** | `buildApp` throws if in-memory store is used in production ✅ |
| **TTL on Requests** | Both pending (180s) and submitted (60s) states auto-expire ✅ |
| **Key File Permissions** | Gateway key written with `0o600` permissions ✅ |
| **Body Size Limit** | Fastify configured with 1MB body limit ✅ |
| **Test Coverage** | Adversarial tests cover races, oversized payloads, tampered sigs ✅ |

---

## Recommended Prioritization

| Priority | Finding | Effort |
|----------|---------|--------|
| **P0** | C-1: Constant-time HMAC comparison | Low (1-line fix) |
| **P0** | C-2: Reject missing HMAC secret in prod | Low (3-line fix) |
| **P1** | H-2: Add rate limiting | Medium |
| **P1** | H-4: Restrict CORS origins | Low |
| **P1** | M-2: Add CSP header to browser UI | Low |
| **P1** | L-5: Update `.gitignore` | Low |
| **P2** | H-1: Atomic `updateRequest` in Redis | Medium |
| **P2** | H-3: Increase confirmation code entropy | Low |
| **P2** | M-1: Fix `Math.random()` usage in gateway | Low |
| **P2** | L-3: Add security headers | Low |
| **P3** | M-3: Allowlist static file extensions | Low |
| **P3** | M-4: JWKS cache TTL | Medium |
| **P3** | L-2: Durable audit log | Medium |
