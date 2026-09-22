# BlindPass threat model

**Aligned to source:** 2026-09-22. This replaces the March threat-model snapshot in the Obsidian vault as the current interpretation. Existing TM-001–TM-007 identifiers are retained. The update inspects selected code paths; it does not rerun the original audits, public deployment probes or proposed fleet tests.

## Scope and trusted endpoints

Existing SPS, browser input, dashboard, gateway, agent runtime and OpenClaw paths are in scope. Hosted-style and local deployments have different exposure/configuration. Billing and guest code remains a maintenance surface despite frozen expansion. The new controller, host broker and browser operation are proposed boundaries, not implemented controls.

Protect source credentials, access/refresh tokens, bootstrap API keys, signing keys, secure-input links, recipient-key integrity, workspace policy and authorization/audit state. The browser handling input and the recipient decrypting it are plaintext endpoints. HPKE protects the relay path only when endpoint code and recipient-key binding are trustworthy.

An authorized process receiving a credential can read/copy it. The proposed browser mode intentionally hands session authority to the agent. A short SPS retrieval TTL or broker grant does not shorten a static provider key's lifetime or revoke a website session. See [mode/revocation contracts](../product/Specification.md#consumption-modes).

## Authentication storage

Source: [SPS auth routes](../../packages/sps-server/src/routes/auth.ts), [dashboard AuthContext](../../packages/dashboard/src/auth/AuthContext.tsx), [browser auth storage](../../packages/browser-ui/src/auth-storage.js), [browser requests](../../packages/browser-ui/src/app.js).

| Mode/path | Actual behavior |
|---|---|
| Hosted mode, non-test | Auth responses set `sps_refresh_token` in an `HttpOnly`, `SameSite=Lax` cookie at `/api/v2/auth` and omit the raw refresh token from JSON |
| Cookie flags | `Secure` is set for production or detected HTTPS; a configured domain override is optional. Deployments still need correctly configured TLS/proxy trust |
| Hosted `NODE_ENV=test` | Also returns `refresh_token` in JSON for test fixtures; must remain isolated from public use |
| Non-hosted mode | Returns the refresh token in JSON |
| Refresh request parsing | A supplied body token takes precedence over the cookie, including in hosted mode; this is not cookie-only enforcement |
| Dashboard | Access token in React memory/ref. A returned body refresh token is written to `localStorage`; refresh prefers that stored token with credentials omitted, otherwise uses cookies |
| Browser input | The storage helper uses `localStorage`, and its refresh path supports a body token plus cookie credentials |
| Cleanup gap | Dashboard `clearAuth()` clears memory but does not remove the stored refresh token; changing to hosted cookie responses does not itself clear existing browser storage |

The earlier claim that refresh tokens were uniformly in `sessionStorage` is incorrect for this checkout. Hosted cookies reduce direct JavaScript token readability on their intended path, but legacy/test body-token storage remains readable. XSS can also exercise an authenticated user's authority even without reading an HttpOnly cookie. Browser-session/CSRF-origin behavior and storage migration/cleanup need explicit testing; do not claim frontend compromise is contained by cookies alone.

## Selected controls checked in source

| Area | Source observation | Evidence/limit |
|---|---|---|
| HPKE | X25519, HKDF-SHA256, ChaCha20-Poly1305 in browser and agent | [Key manager](../../packages/agent-skill/src/key-manager.ts), [browser crypto](../../packages/browser-ui/src/crypto.js); corrects the old AES-256-GCM design row |
| Email verification/reset tokens | SHA-256 token hashes in `user_tokens`; expiry and atomic consumed-at checks; verification TTL one day, reset TTL one hour | [User service](../../packages/sps-server/src/services/user.ts); supersedes v2 M-2/M-3's March status, without claiming a new test pass |
| Frontend headers | Both production nginx configs include CSP/frame and related headers; dashboard permits broad connection schemes, input page includes loopback and broad HTTPS connections; neither config adds HSTS | [Dashboard nginx](../../packages/dashboard/nginx.conf), [input nginx](../../packages/browser-ui/nginx.conf); actual deployed edge remains unverified in this pass |
| Input origin | Request context ignores query-controlled `api_url`; frontend uses its configured API origin | [Parser](../../packages/browser-ui/src/request-context.js), [regression cases](../../packages/browser-ui/tests/request-context.test.mjs) |
| Confirmation codes | SPS has 8×8×100 = 6,400 combinations using random bytes with modulo mapping; gateway has 4×4×100 = 1,600 combinations using `Math.random()` | [SPS generator](../../packages/sps-server/src/services/crypto.ts), [gateway generator](../../packages/gateway/src/code-generator.ts); entropy/generation remediation remains open |
| Runtime custody | `SecretStore.get()` returns a plaintext copy and has no built-in expiry/use count; resolver intentionally returns plaintext | [Store](../../packages/agent-skill/src/secret-store.ts), [resolver](../../packages/openclaw-plugin/blindpass-resolver.mjs); handoff TTL is not local plaintext expiry |
| Packaging | Current SPS Dockerfile has no explicit non-root `USER`; development Redis configuration disables persistence | [Dockerfile](../../packages/sps-server/Dockerfile), [Compose](../../docker-compose.test.yml); these files do not meet the proposed W2 contract by themselves |

Other controls reported in historical audits—fail-closed signing configuration, scoped signing domains, constant-time comparisons, CORS allowlists, hashed sessions/API keys, and atomic exchange transitions—remain supported by their referenced code/tests. This limited alignment pass does not newly certify every path or mark every historical finding resolved.

## Threat register

| ID | Abuse path and impact | Current control/boundary | Remaining work or evidence |
|---|---|---|---|
| TM-001 | Signing-key compromise or configuration regression permits forged user/agent/fulfillment authority | Required-secret checks and token scope/workspace validation in SPS | Protect/recover/rotate deployed keys; retain fail-closed regressions. A compromised controller remains an authorization risk |
| TM-002 | An official input link redirects credential submission through attacker-controlled API/key metadata | Query-controlled API origin removed | Keep origin/key-substitution regressions; trusted input code and recipient-key binding remain necessary |
| TM-003 | Frontend compromise steals a body/legacy refresh token or exercises authenticated authority | Hosted non-test cookie delivery exists; access token is in memory | `localStorage` compatibility, body-token precedence and cleanup gaps remain; test migration, logout and origin/session behavior |
| TM-004 | Logs/artifacts disclose secure links, codes, tokens or credential values | Runtime logging redaction/opt-in controls were reported in March | Demos intentionally print dummy values and cannot prove runtime secrecy; inspect actual client/log/artifact paths and restrict sensitive evidence |
| TM-005 | Public guest requests or repeated approvals exhaust quotas, queues or operator attention | Existing rate limits and policy/approval checks | Maintain public-surface protections while expansion is frozen; pilot must measure approval fatigue and preserve bounded grant scope |
| TM-006 | Same-origin script compromise abuses input/dashboard sessions, worsened by permissive CSP | Repo-visible nginx CSP and frame protections | Tighten production connection policies, validate actual deployed headers, and retain session authority/XSS limits; cookies do not stop all authenticated actions |
| TM-007 | Compromised facilitator/payment trust causes fraudulent acceptance | Historical atomic settlement ownership reduces local duplicate-settlement races | Facilitator trust/reconciliation remains on the frozen payment-surface backlog; no new payment audit in this pass |
| TM-008 | A local process spoofs a systemd routing name or reuses a PID/invocation to obtain another workload's credential | Proposed root-only loader socket plus pidfd-based unit/invocation authentication | W0 real-systemd tests, including known forged-name regression; user-manager/shared-UID delivery excluded |
| TM-009 | Controller/key substitution or copied grants redirect provisioning across nodes/workloads | Proposed verified recipient binding, enrollment lifecycle, local ceiling and scoped grants | Fleet E/I/C scenarios; ciphertext-only storage is not proof against controller compromise |
| TM-010 | Agent accesses private login state or receives more cookies/storage than approved | Proposed account/process separation and fresh-context cookie allowlist | Browser B-I14/B-I15; no general confinement claim for unrestricted browser tools |
| TM-011 | Handed-off session creates lasting account authority or survives cancellation | Proposed restricted application role, non-extendable lifetime and server revocation | B-E12/B-E15/B-E16/B-E17; reject applications that cannot enforce these prerequisites |
| TM-012 | Broker/socket failure starts a service with missing/partial credentials; copied provider key survives grant expiry | Proposed explicit consumer validation and separate provider-revocation status | C04/C12/C13; service delivery trusts the consumer and cannot recall copies |
| TM-013 | Controller partition, stale restore or competing restored instance revives revoked/consumed authority | Proposed expiry/reconciliation, protected key backups and single-controller fencing | E07, O-series and D-series in both deployment profiles |
| TM-014 | Browser login page or deployed application itself captures the source password | The credential receiver is a trusted endpoint | B-E14 boundary demonstration; do not let agent-controlled code modify the approved login endpoint |

## Evidence and follow-up

The [pilot test catalog](../testing/Linux%20Fleet%20Pilot.md) owns scenario detail. S-series covers W5 regressions; B-series covers mode-1 browser handoff; fleet E/I/C/O/D covers identity, service delivery and deployment. Existing repository test locations and flags are in [testing setup](../testing/README.md).

Resolve audit items by identifier and evidence date. This update corrects F-7/F-8 documentation and v2 M-2/M-3's current interpretation; code/test/deployment follow-up remains explicit. Confirmation codes, storage cleanup, client timeouts, origin restrictions, deployment hygiene and active-path exposure risks stay in W5. Frozen guest/payment risks remain tracked rather than disappearing with the old roadmap.

Actual host isolation, MCP-client handling, server-side website revocation and deployment parity have not been executed here. Local scans and documentation review cannot establish those guarantees. See [security references](README.md) for the dated reports.
