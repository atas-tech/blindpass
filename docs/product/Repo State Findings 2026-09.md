# BlindPass Repo State Findings — September 2026

> **Date:** 2026-09-10  
> **Updated:** 2026-09-12 — MCP framing probe and credential-consumption finding; original live-service observations were not repeated  
> **Reviewed commit:** `5b233c3` (2026-04-18)  
> **Method:** static read of the monorepo, live probes of the hosted endpoints, npm registry lookups  
> **Companion:** [Product Review 2026-09](Product%20Review%202026-09.md) · [Roadmap Reset 2026-09](Roadmap%20Reset%202026-09.md)

This document records only what was **directly observed**. Market and competitor claims live in the product review. Pre-existing security findings are tracked in [Security Audit v2](../security/Security%20Audit%20v2.md) and are cross-referenced rather than restated.

## Table of Contents

- [1. Summary](#1-summary)
- [2. Blocking Findings](#2-blocking-findings)
- [3. Distribution Findings](#3-distribution-findings)
- [4. Scope And Balance](#4-scope-and-balance)
- [5. Documentation Inconsistencies](#5-documentation-inconsistencies)
- [6. Live Deployment Observations](#6-live-deployment-observations)
- [7. Carried-Over Security Items](#7-carried-over-security-items)
- [8. What Is In Good Shape](#8-what-is-in-good-shape)

---

## 1. Summary

| ID | Finding | Severity | Area |
|---|---|---|---|
| [F-1](#f-1-request_secret-cannot-complete-in-plain-mcp-mode) | `request_secret` cannot complete in plain MCP mode | **Blocker** | Plugin |
| [F-2](#f-2-mcp-server-pins-an-obsolete-protocol-version-and-implements-no-elicitation) | MCP server pins protocol `2024-11-05`, no elicitation | **Blocker** | Plugin |
| [F-3](#f-3-default-sps-hostname-does-not-resolve) | Default SPS hostname does not resolve | **Blocker** | Distribution |
| [F-4](#f-4-nothing-is-published-to-npm) | Nothing published to npm under `@blindpass` | High | Distribution |
| [F-5](#f-5-scope-skew-toward-payments-and-guest-intake) | Payments/guest/billing outweighs core flows ~1.7 : 1 | High | Product |
| [F-6](#f-6-project-dormant-since-april) | Dormant since 2026-04-18 | High | Project |
| [F-7](#f-7-aead-cipher-documented-incorrectly) | AEAD cipher documented incorrectly | Medium | Docs |
| [F-8](#f-8-refresh-token-storage-status-contradicts-across-documents) | Refresh-token storage status contradicts across docs | Medium | Docs/Security |
| [F-9](#f-9-permissive-connect-src-in-production-csp) | Permissive `connect-src` in production CSP | Medium | Deployment |
| [F-10](#f-10-no-hsts-on-any-hosted-origin) | No HSTS on any hosted origin | Medium | Deployment |
| [F-11](#f-11-localhost-origins-in-the-production-browser-ui-csp) | Localhost origins in production browser-ui CSP | Low | Deployment |
| [F-12](#f-12-mcp-stdio-framing-is-incompatible-with-standard-clients) | Standard newline-delimited initialization receives no response | **Blocker** | Plugin |
| [F-13](#f-13-secret-storage-does-not-complete-an-authenticated-task) | Plugin storage has no general credential-consumption bridge for a stock MCP client's tools | **Blocker** | Product |

---

## 2. Blocking Findings

### F-1: `request_secret` cannot complete in plain MCP mode

**Severity:** Blocker — this breaks the product's headline flow for every non-OpenClaw client.

The MCP entry point builds an `api` object containing **only** `registerTool` and `registerHook`:

- `packages/openclaw-plugin/mcp-server.mjs:33` — `const api = { registerTool, registerHook }`

The `request_secret` handler delivers the secure link through `onSecretLink`, which tries four transports in order and throws if all fail:

1. `sendMessageToChannel(api, context, ...)` — needs an OpenClaw plugin chat API
2. `sendViaRuntimeChannel(api, ...)` — needs `api.runtime.channel`
3. `sendViaOpenClawCli(...)` — needs the `openclaw` binary plus a channel and target
4. `sendTelegramFallback(...)` — needs `TELEGRAM_BOT_TOKEN` and a chat ID

- `packages/openclaw-plugin/blindpass-core.mjs:837` — throws *"Could not deliver secure link to chat channel."*

**Consequence:** a developer who installs the MCP server into Claude Code, Cursor, VS Code, or Codex and calls `request_secret` gets an error, not a link. The flow only works inside OpenClaw or with a Telegram bot configured. There is no local browser fallback and no elicitation path.

**Note on design intent:** withholding the URL from the tool result is *correct* — it is the LLM-blindness property (defense layer 6 in the design doc). The defect is that no non-chat delivery channel was ever implemented, so the correct design has no viable transport outside OpenClaw.

### F-2: MCP server pins an obsolete protocol version and implements no elicitation

**Severity:** Blocker — it forecloses the officially sanctioned fix for F-1.

- `packages/openclaw-plugin/mcp-server.mjs:7` — `MCP_PROTOCOL_VERSION = "2024-11-05"`
- `packages/openclaw-plugin/mcp-server.mjs:145` — declares `capabilities: { tools: {} }` only
- No occurrence of `elicit` anywhere in `packages/openclaw-plugin/` or `packages/agent-skill/src/`

URL-mode elicitation — the MCP-sanctioned mechanism for exactly this interaction — arrived in spec version `2025-11-25`. Pinning `2024-11-05` means the server cannot negotiate it even against clients that support it.

**September 12 correction:** URL-mode elicitation can address delivery for clients that advertise that mode, but does not alone resolve framing or credential consumption. It is a client capability, so adding it beside server `tools` capabilities is not the fix. Implement and test each supported protocol version and actual client. See F-12 and F-13 below.

### F-12: MCP stdio framing is incompatible with standard clients

**Severity:** Blocker — initialization fails before a client can call the tool.

The [MCP server](../../packages/openclaw-plugin/mcp-server.mjs) encodes and parses messages using `Content-Length` headers. The [MCP stdio specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports) requires newline-delimited JSON-RPC and reserves stdout for protocol messages.

A September 12 in-memory stream probe passed the same initialization request into `runMcpServerStdio` with two framings:

| Framing | Initialization response | Response bytes |
|---|---|---|
| Standard newline-delimited JSON | None | 0 |
| Current `Content-Length` framing | Returned | 169 |

This probe exercised framing with a minimal server object; it was not a complete stock-client E2E test. Update framing and logging, then verify actual supported clients rather than relying only on a harness that reproduces the same custom protocol.

### F-13: Secret storage does not complete an authenticated task

**Severity:** Blocker for the proposed complete-workflow claim.

Static inspection of [plugin storage](../../packages/openclaw-plugin/blindpass-core.mjs) shows `persistSecret` falls back to a plugin-local map when no managed backend or runtime storage hook is available. The [MCP registration API](../../packages/openclaw-plugin/mcp-server.mjs) supplies registration hooks, not a general bridge from that map to a stock client's shell or unrelated tools. Successful input therefore does not automatically enable the next authenticated task.

This does not negate existing OpenClaw persistence or plugin-local exchange functions. It identifies the missing integration for a stock AI client's subsequent operation. The [Linux fleet pilot](Native%20Linux%20Fleet%20Research%202026-09.md) must prove either a brokered operation that retains the credential or an explicit delivery adapter with the consumer's plaintext access documented.

### F-3: Default SPS hostname does not resolve

**Severity:** Blocker for onboarding.

The default and documented base URL is `https://sps.blindpass.dev`, which returns no response:

| Location | Value |
|---|---|
| `packages/openclaw-plugin/openclaw.plugin.json:16` | `"default": "https://sps.blindpass.dev"` |
| `packages/openclaw-plugin/blindpass-core.mjs:628` | fallback |
| `packages/openclaw-plugin/blindpass-core.mjs:764` | fallback |
| `packages/openclaw-plugin/blindpass-core.mjs:928` | fallback |
| `CLAUDE.md:35` | example MCP config |

Probe results (2026-09-10):

| Host | Result |
|---|---|
| `https://sps.blindpass.dev/healthz` | no response |
| `https://blindpass.dev/` | no response |
| `https://sps.atas.tech/healthz` | `200` |
| `https://sps.atas.tech/readyz` | `200` |
| `https://app.atas.tech/` | `200` |
| `https://secret.atas.tech/` | `200` |
| `https://blindpass.atas.tech/` | `200` |

The live stack runs entirely on `atas.tech`. Every default points somewhere that does not exist. **Any user who installs with defaults fails immediately.**

**Decision required:** either register and point `blindpass.dev`, or change all defaults to the `atas.tech` hosts. The former is better for the product identity; the latter is free and immediate.

---

## 3. Distribution Findings

### F-4: Nothing is published to npm

Registry lookups on 2026-09-10 returned `404` for:

- `@blindpass/openclaw-plugin`
- `@blindpass/agent-skill`
- `@blindpass/sdk`
- `blindpass`

Every package in `packages/` is marked `"private": true`. The publishing machinery exists — `scripts/publish_dist.sh`, `scripts/publish_clawhub.sh`, `scripts/build_bundle.sh`, plus release-metadata and audience-packaging tests — but has never been run against a public registry.

The documented dist repo (`atas-tech/blindpass-dist`) does not exist. ClawHub listing status was **not verified** in this review.

The public GitHub repository has 1 star and 1 fork.

**Consequence:** there is currently no way for anyone to install BlindPass except by cloning the monorepo and building from source.

### F-6: Project dormant since April

| Metric | Value |
|---|---|
| First commit | 2026-03-05 |
| Last commit | 2026-04-18 |
| Total commits | 126 |
| Distinct authors | 1 (two identities, same email) |
| Commits by month | 112 in March, 14 in April |
| Gap to review date | ~5 months |

The velocity profile shows an intense six-week build followed by a full stop. Nothing about the code suggests abandonment for technical reasons; the more likely cause is that the scope outgrew a single maintainer.

---

## 4. Scope And Balance

### F-5: Scope skew toward payments and guest intake

Line counts in `packages/sps-server/src`:

| Category | Lines |
|---|---|
| Payments, billing, guest intake, x402, ledgers, allowances | 3,915 |
| Core secret request, exchange, HPKE, retrieval | 2,284 |
| **Ratio** | **~1.7 : 1** |

Largest individual modules:

| File | Lines |
|---|---|
| `routes/exchange.ts` | 1,655 |
| `routes/public-intents.ts` | 1,451 |
| `services/user.ts` | 1,452 |
| `services/guest-intent.ts` | 1,166 |
| `services/x402.ts` | 1,149 |
| `routes/auth.ts` | 835 |
| `services/workspace-policy.ts` | 722 |

Of 17 database migrations, 6 exist purely for billing, x402, offers, guest intents, guest payments, and guest delivery state.

Per-package totals:

| Package | Lines |
|---|---|
| `sps-server` | 30,002 |
| `dashboard` | 11,407 |
| `openclaw-plugin` | 5,969 |
| `agent-skill` | 1,926 |
| `browser-ui` | 989 |
| `gateway` | 674 |
| `i18n` | 417 |

**Observation:** `browser-ui` — the component where the actual zero-knowledge encryption happens and the only surface a first-time human user touches — is the second-smallest package at 989 lines. The guest payment subsystem alone is larger.

This is the clearest quantitative statement of the ordering problem: the monetization and multi-tenancy layers were built out before the primitive had users.

---

## 5. Documentation Inconsistencies

### F-7: AEAD cipher documented incorrectly

| Source | Claimed AEAD |
|---|---|
| `docs/architecture/Brainstorm Secure Secret System.md:77` | AES-256-GCM |
| `packages/agent-skill/src/key-manager.ts:6` | `AeadId.Chacha20Poly1305` |
| `packages/browser-ui/src/crypto.js:6` | `AeadId.Chacha20Poly1305` |
| `packages/openclaw-plugin/skills/blindpass/SKILL.md` | ChaCha20-Poly1305 |

The code and the skill file agree on ChaCha20-Poly1305. The "locked design decisions" table in the primary architecture document says AES-256-GCM. Since that table is the document a security reviewer or prospective customer reads first, the error matters more than its size. **Fix the document, not the code** — ChaCha20-Poly1305 is a sound choice for a browser-side implementation.

### F-8: Refresh-token storage status contradicts across documents

| Source | Claim |
|---|---|
| `docs/architecture/Phase 3E - Hosted Hardening, Ecosystem & Launch.md` | Milestone 1 implemented: "hosted refresh cookies, access-token-in-memory dashboard auth" |
| `docs/security/Security Audit v2.md` (H-2, 2026-03-24) | Partial: "Moved from `localStorage` to `sessionStorage`; still JS-readable" |
| `docs/security/blindpass-threat-model.md` (TM-003) | "tokens remain JS-readable" |

Three documents in the same repo disagree about whether the hosted dashboard still exposes refresh tokens to JavaScript. **This needs to be resolved by reading the code, not the docs**, and then stated once in a single authoritative place. It was not resolved during this review.

### Other documentation drift

- `docs/architecture/Implementation Plan.md` carries per-phase status snapshots dated 2026-03-12, 2026-03-24, and 2026-03-27 that have not been revisited since.
- `docs/architecture/Brainstorm Secure Secret System.md:691` describes Phase 4 and Phase 5 scope that no longer reflects any current intent.
- The README lists hosted service URLs on `atas.tech` while the plugin defaults point at `blindpass.dev` (see F-3).

---

## 6. Live Deployment Observations

All four hosted origins responded on 2026-09-10. Header observations:

| Header | `sps.atas.tech` | `secret.atas.tech` | `app.atas.tech` | `blindpass.atas.tech` |
|---|---|---|---|---|
| `strict-transport-security` | absent | absent | absent | absent |
| `content-security-policy` | n/a (API) | present | present | absent |
| `x-frame-options` | absent | `DENY` | `DENY` | absent |
| `x-content-type-options` | absent | `nosniff` | `nosniff` | absent |
| `referrer-policy` | `no-referrer` | `no-referrer` | `strict-origin-when-cross-origin` | absent |
| `permissions-policy` | absent | present | present | absent |

### F-9: Permissive `connect-src` in production CSP

`app.atas.tech` serves:

```
connect-src 'self' http: https: ws: wss: https://challenges.cloudflare.com
```

`http:`, `https:`, `ws:`, and `wss:` as bare schemes permit connections to **any** host. For a dashboard that handles session tokens, agent enrollment keys, and audit data, this removes CSP's value as an exfiltration control — which is precisely the control that matters if the frontend is ever compromised.

This directly updates the open question in `docs/security/blindpass-threat-model.md`, which asks whether production edge headers are enforced. **They are enforced, but the `connect-src` policy is too permissive to be meaningful.**

**Recommended:** restrict to `'self'` plus the explicit SPS API origin and the Cloudflare challenge endpoint.

### F-10: No HSTS on any hosted origin

No `strict-transport-security` header on any of the four hosts, including the API origin that receives bearer tokens and the browser UI that receives plaintext secrets before encryption. This is tracked as partially open in the audit (M-6) and remains unaddressed in production.

**Recommended:** `max-age=31536000; includeSubDomains` at the edge, after confirming every subdomain is HTTPS-ready.

### F-11: Localhost origins in the production browser-ui CSP

`secret.atas.tech` serves a CSP containing:

```
connect-src 'self' http://127.0.0.1:3100 http://localhost:3100 https:
```

Two development origins are baked into the production policy, and the trailing `https:` again permits any HTTPS host. The localhost entries are harmless in isolation but indicate the production CSP is built from the development template.

The landing page at `blindpass.atas.tech` ships no security headers at all. Lower risk since it is static marketing, but it is the origin a first-time visitor sees.

---

## 7. Carried-Over Security Items

These were identified in [Security Audit v2](../security/Security%20Audit%20v2.md) and remained open at that document's last update. They were **not re-verified against code** in this review; the audit's own status is reproduced for planning purposes.

| ID | Item | Audit status |
|---|---|---|
| H-3 / L-4 | Confirmation code entropy — 6,400 combinations | Open |
| M-7 / M-1 | Gateway confirmation codes use `Math.random()` | Open |
| M-2 | Verification tokens stored in plaintext in the database | Open |
| M-3 | Verification tokens have no expiry | Open |
| M-4 | x402 facilitator responses trusted by TLS alone | Open |
| M-5 | Password validation is length-only | Open |
| M-8 | Guest subject hash anchored on IP address | Open |
| L-1 | `.gitignore` missing sensitive generated files including `gateway-key.json` | Open |
| L-2 | Stale log files committed to the repo | Open |
| L-5 | No account-level lockout, IP rate limiting only | Open |
| L-6 | No client-side request timeouts in the dashboard | Open |

Several of these are inexpensive. `Math.random()` to `crypto.randomInt`, wider confirmation-code entropy, hashing and expiring verification tokens, and the `.gitignore` cleanup are each small changes that materially improve how the project reads to a security-minded evaluator — which is the entire target audience.

---

## 8. What Is In Good Shape

The findings above are about ordering and packaging, not craft. Worth recording explicitly:

- **Cryptographic design is sound.** HPKE per RFC 9180, X25519 with HKDF-SHA256 and ChaCha20-Poly1305, ephemeral per-request keypairs, single-use retrieval enforced atomically through Redis Lua scripts.
- **Test coverage is real.** 56 test files, PostgreSQL-backed E2E suites, Redis integration tests, adversarial route tests, Playwright dashboard tests, plus installer-integrity and release-metadata smoke tests.
- **Security work is unusually thorough for a solo project.** Two audit rounds and a threat model, with a documented remediation ledger and honest open-item tracking. Several critical findings were genuinely fixed, including constant-time HMAC comparison, fail-closed startup on missing signing secrets, removal of the query-controlled `api_url` injection path, CORS origin allowlisting, and atomic Redis state transitions.
- **The A2A protocol has explicit lifecycle contracts.** Exchange records include owner binding, fulfillment-token claims, trust-ring policy, cross-ring approval, revocation tombstones, and rotation lineage. This is reusable implementation work; competitive differentiation is a separate product hypothesis.
- **Operational surface is complete.** Workspace RBAC, audit persistence with retention, quota enforcement, rate limiting, analytics, Docker Compose, Unraid templates, an OpenAPI snapshot, and a maintained `.env.example`.

The problem is not that the wrong things were built well. It is that too many things were built before the first one reached a user.
