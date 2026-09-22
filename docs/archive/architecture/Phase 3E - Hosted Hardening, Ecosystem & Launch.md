# Phase 3E: Hosted Hardening, Ecosystem & Launch

> Historical record, archived during the 2026-09-22 documentation alignment. Dates, checkboxes, commands, and proposed decisions below describe their original review period; they do not establish current support or authorize new work. See the [current documentation](../../README.md) and [roadmap](../../product/Roadmap.md).

Phase 3E picks up after the core operator dashboard and admin workflows are in place. This phase hardens the hosted product for broader use, adds the ecosystem and documentation work needed for adoption, and closes with the actual hosted go-live path.

The workspace-scoped PostgreSQL policy engine that was once bundled into Phase 3E is now tracked separately in [Hosted Workspace Policy Foundation](Hosted%20Workspace%20Policy%20Foundation.md). Phase 3E assumes that foundation already exists and focuses on session hardening, abuse controls, analytics, ecosystem work, and launch readiness.

This phase is intentionally separate from:

- **Phase 3B**: core operator dashboard and admin UX
- **Phase 3C**: paid guest requester flows
- **Phase 3D**: autonomous payments and crypto billing

**Prerequisites**:

- Phase 3A hosted platform is complete
- Phase 3B operator dashboard and recurring billing admin UX are complete
- [Hosted Workspace Policy Foundation](Hosted%20Workspace%20Policy%20Foundation.md) is complete
- Hosted APIs are stable enough to publish SDKs and onboarding docs

**Development strategy**: land hosted session hardening and abuse controls first, then analytics and ecosystem packaging/documentation, with production deployment and domain cutover left for the final milestone.

## Current Repo State

As of `2026-03-27`, the repository already contains a substantial portion of this phase:

- Milestone 1 is implemented in code and tests: hosted refresh cookies, access-token-in-memory dashboard auth, Turnstile support, and workspace burst throttling are present in `packages/sps-server` and `packages/dashboard`
- Milestone 2 analytics is implemented: analytics routes, aggregation services, dashboard analytics UI, and regression coverage are present
- Milestone 2 docs/community artifacts are present in-repo: `docs/guides/quickstart.md`, `docs/guides/self-hosting.md`, `docs/api/openapi.yaml`, `.env.example`, `docker-compose.test.yml`, and `Makefile`
- Milestone 4 launch-readiness foundation has started: `GET /readyz`, dashboard containerization, image-publishing workflow updates, and Unraid deployment artifacts are in place

The biggest remaining gaps in this phase are:

- Python and Go SDK implementation and hosted-flow validation
- transactional email delivery for verification and recovery flows
- live production image publishing and domain cutover verification
- final production HTTPS, DNS, and reverse-proxy rollout checks

> [!IMPORTANT]
> This plan is divided into **4 incremental milestones**. The order is: Session Hardening & Abuse Controls → Analytics, SDKs, Docs & Community → Transactional Email With Resend → Hosted Deployment & Domain Cutover.

## Milestone 1: Dashboard Session Hardening & Advanced Abuse Controls

Harden hosted dashboard authentication before wider rollout, then strengthen signup/auth abuse protections.

### Dashboard Session Hardening

The current dashboard stores the refresh token in `localStorage`. That is acceptable only as an MVP shortcut. Before wider hosted rollout, the dashboard should migrate to a cookie-based refresh model:

- refresh token stored in a `Secure` + `httpOnly` cookie in hosted mode
- access token remains memory-only in the dashboard runtime
- hosted dashboard API calls use `credentials: include` for refresh/logout flows
- logout clears both the cookie and the server-side session
- no refresh token remains readable through `localStorage`, `sessionStorage`, or other JS-visible browser storage in hosted mode

This migration is a prerequisite for production hosted go-live, not a late checklist item.

#### [MODIFY] `packages/sps-server/src/routes/auth.ts`

- hosted login/register/refresh responses set or rotate the refresh cookie instead of returning a JS-managed refresh token
- logout clears the refresh cookie and revokes the backing session
- cookie behavior is configured for hosted HTTPS deployment and fails closed in production if secure cookie requirements are not met

#### [MODIFY] `packages/dashboard/src/auth/AuthContext.tsx`

- remove refresh-token persistence from `localStorage`
- switch refresh/logout flows to cookie-backed requests
- keep the access token memory-only
- update E2E and component tests so the dashboard asserts the refresh token is not readable from JS-visible storage

### Advanced Abuse Controls

Strengthen protections beyond Phase 3A's per-IP rate limiting.

#### [MODIFY] Frontend: Cloudflare Turnstile Integration

- Add Turnstile challenge widget to `Register.tsx` and `Login.tsx`
- Dashboard sends the Turnstile response token with auth requests
- Backend validates the token server-side via Turnstile `/siteverify` before processing registration/login

#### [MODIFY] `packages/sps-server/src/routes/auth.ts`

- Add optional `cf_turnstile_response` field to register/login request bodies
- When `SPS_TURNSTILE_SECRET` is set, validate the token before auth processing
- When it is not set, skip challenge verification for local/dev

#### [MODIFY] `packages/sps-server/src/middleware/rate-limit.ts`

- Add anomaly burst detection: if a single workspace exceeds 5x its tier quota within a sliding hour window, emit an `abuse_alert` audit event and temporarily throttle to 1 req/min for that workspace
- Workspace-level throttle is self-clearing after the hour window passes

**Acceptance**: Hosted dashboard refresh handling no longer relies on JS-visible refresh-token storage. Login, refresh, and logout work through secure cookie-backed session flows in hosted mode. Turnstile blocks automated signup in hosted mode. Burst anomaly detection throttles and logs abuse attempts.

---

## Milestone 2: Analytics, SDKs, Documentation & Community

Add hosted operational analytics, then make the platform accessible to developers who are not reading source code directly.

### Analytics Page (`/analytics`)

Metadata-minimized, zero-knowledge-preserving workspace metrics:

- **Request volume**: daily secret request count over last 30 days
- **Exchange metrics**: successful vs. failed/expired/denied exchanges over last 30 days
- **Active agents**: count of agents that minted a JWT in the last 24 hours

### [NEW] `packages/sps-server/src/services/analytics.ts`

Backend aggregate queries over the `audit_log` table, scoped by `workspace_id`:

- `getRequestVolume(workspaceId, days)` → daily counts of `request_created` events
- `getExchangeMetrics(workspaceId, days)` → daily counts grouped into successful, failed/expired, and denied terminal buckets
- `getActiveAgentCount(workspaceId, hours)` → distinct `actor_id` where `actor_type = 'agent'` and `event_type = 'agent_token_minted'`

All queries return counts and timestamps only. They never expose secret names, ciphertext, token values, or per-agent identifiers beyond aggregate counts.

### [NEW] `packages/sps-server/src/routes/analytics.ts`

| Endpoint | Auth | Behavior |
|----------|------|----------|
| `GET /api/v2/analytics/requests` | User JWT (admin/operator) | Daily request volume for last N days |
| `GET /api/v2/analytics/exchanges` | User JWT (admin/operator) | Daily exchange outcome metrics |
| `GET /api/v2/analytics/agents` | User JWT (admin/operator) | Active agent count |

RBAC: `workspace_viewer` cannot access analytics in the MVP.

### Language SDKs

Publish officially supported SDK packages that wrap the SPS API. **Node.js first**, then Python and Go.

| SDK | Package Name | Key Capabilities |
|-----|-------------|-----------------|
| **Node.js** | `@blindpass/sdk` | Published from existing `packages/agent-skill` with documentation, types, and npm release |
| **Python** | `blindpass` (PyPI) | HPKE keygen, secret request/retrieve, exchange request/fulfill/retrieve, bootstrap auth |
| **Go** | `github.com/atas-tech/blindpass-go` | Same capabilities as Python SDK |

All SDKs must support:

- Bootstrap API key → JWT minting flow
- HPKE key generation and secret decryption
- Human→Agent: `requestSecret()`, `retrieveSecret()`
- Agent→Agent: `requestExchange()`, `fulfillExchange()`, `submitExchange()`, `retrieveExchange()`
- In-memory-only secret storage with explicit zeroing

### Documentation

| Document | Location | Content |
|----------|----------|---------|
| API Reference | `docs/api/` | Maintained OpenAPI 3.1 snapshot for the stable hosted/dev SPS routes, plus usage notes |
| Quick Start | `docs/guides/quickstart.md` | 5-minute guide: register workspace → enroll agent → deliver first secret |
| Identity Bootstrap | Planned follow-on guide | How to get an `ak_` key, mint JWTs, and configure `agent-skill` |
| Policy Configuration | `docs/guides/policy.md` | Hosted workspace policy editor model, trust rings, secret registry, exchange policies, approval workflows, and self-hosted env bootstrap/default behavior |
| Self-Hosting | `docs/guides/self-hosting.md` | Docker Compose guide with env var reference, local harness, and reverse proxy setup |

### Docker Compose Community Guide

Sanitize and publish the production Docker Compose setup:

- Remove operator-specific details
- Add `.env.example` with all required variables and sensible defaults
- Add `docker-compose.test.yml` as the standard local PostgreSQL/Redis harness
- Add `Makefile` with `make up`, `make down`, `make logs`, `make migrate` targets
- Include clear README with prerequisites (Docker, domain, DNS)

**Current status**: analytics, Node.js SDK-hosted flow coverage, API/docs/community artifacts, and the standard local compose harness are now present in-repo. The main Milestone 2 work still open is Python and Go SDK completion plus their hosted-flow verification.

---

## Milestone 3: Transactional Email With Resend

Finish the hosted account email flows by introducing a real transactional email provider instead of the current manual/operator-assisted verification path.

### Goals

- deliver verification emails in hosted mode through Resend
- support password-reset email flows end-to-end
- keep development and self-hosted setups usable without requiring a live mail provider
- avoid sending passwords, bootstrap API keys, verification tokens, or reset tokens to logs

### [NEW] `packages/sps-server/src/services/mailer.ts`

Add a small mailer abstraction with a Resend-backed implementation and a safe local/dev fallback:

- `sendVerificationEmail(input)` sends the hosted verification link
- `sendPasswordResetEmail(input)` sends the hosted password-reset link
- local/dev may continue to log delivery guidance when explicitly opted in, but hosted/prod must fail closed if Resend is required and misconfigured
- provider responses are normalized into retryable vs non-retryable failures so routes can return coherent errors and emit audit events

### [MODIFY] `packages/sps-server/src/services/user.ts`

- replace direct verification-link logging as the primary hosted behavior with mailer calls
- keep verification token issuance separate from email transport so retries do not mint unbounded extra state
- move verification and password-reset tokens onto a shared database model such as `user_tokens`
- store only token hashes at rest using a fast token hash such as SHA-256 or HMAC-SHA-256, with `type`, `expires_at`, and `consumed_at` fields
- enforce single active token semantics per user and token type so re-triggering verification or reset invalidates older links cleanly
- store password-reset tokens with TTL/expiry and single-use semantics

### [MODIFY] `packages/sps-server/src/routes/auth.ts`

- registration triggers a verification email send in hosted mode
- `POST /api/v2/auth/retrigger-verification` reflects actual delivery success/failure instead of implying email delivery unconditionally
- add forgot-password request and reset endpoints with generic responses that do not reveal whether an email address exists
- apply endpoint-specific abuse controls for `POST /api/v2/auth/forgot-password` and `POST /api/v2/auth/retrigger-verification`
- require optional Cloudflare Turnstile checks for these email-triggering routes in hosted mode, just as login and registration already do
- add dedicated per-IP rate limits for these routes rather than relying only on workspace burst throttling
- equalize observable behavior for existing vs missing emails by returning the same body and enforcing a minimum response duration on both paths

### [MODIFY] `packages/dashboard`

- replace the current forgot-password placeholder with a real request/reset flow
- update the verification banner copy so it accurately reflects queued/sent vs failed delivery states
- surface retryable delivery errors without leaking provider internals

### Delivery Rules

- use Resend for the hosted production path
- do not email temporary passwords or bootstrap API keys
- member onboarding emails may include a sign-in link or operator instructions, but any secret/bootstrap credential remains out-of-band
- all emailed links must use the configured hosted base URLs and expire
- local/dev without `RESEND_API_KEY` may log the constructed verification or reset URL to server stdout for developer convenience, but this fallback must stay disabled in production

**Acceptance**: Hosted registration sends a verification email through Resend. Resending verification invalidates prior links and reports delivery failures correctly. Forgot-password works end-to-end with generic request responses, minimum-duration enumeration resistance, hashed expiring single-use tokens stored outside the `users` table, and endpoint-specific Turnstile plus per-IP rate limiting. Local/dev still works without a live Resend account.

---

## Milestone 4: Hosted Deployment & Domain Cutover

Stand up the production deployment with proper domains and TLS. This is the final hosted-launch milestone.

### Deployment Architecture

| Subdomain | Service | Container |
|-----------|---------|-----------|
| `sps.atas.tech` | SPS API | `ghcr.io/atas-tech/blindpass-sps-server` |
| `secret.atas.tech` | Browser UI (zero-knowledge sandbox) | `ghcr.io/atas-tech/blindpass-browser-ui` |
| `app.atas.tech` | Operator Dashboard | `ghcr.io/atas-tech/blindpass-dashboard` |

Reverse proxy and TLS are handled by the operator's existing Unraid reverse proxy (for example Nginx Proxy Manager or Traefik). No bundled reverse proxy is included.

### [NEW] `packages/sps-server/src/routes/health.ts`

| Endpoint | Auth | Behavior |
|----------|------|----------|
| `GET /healthz` | None | Returns `200` if server is up |
| `GET /readyz` | None | Returns `200` if PostgreSQL + Redis are reachable; `503` otherwise |

Health checks are used by Docker `HEALTHCHECK` and by the reverse proxy for upstream readiness.

### [MODIFY] `.github/workflows/build-and-push-images.yml`

- Add `dashboard` image build target (`ghcr.io/atas-tech/blindpass-dashboard`)
- Pin `VITE_SPS_API_URL=https://sps.atas.tech` for production browser-ui and dashboard builds

### [MODIFY] `docs/deployment/Unraid.md`

- Add dashboard container template reference
- Update domain examples to `sps.atas.tech`, `secret.atas.tech`, `app.atas.tech`
- Document reverse proxy configuration for the three domains
- Add `SPS_HOSTED_MODE`, `SPS_TURNSTILE_SECRET`, and other Phase 3E env vars
- Clarify that `SPS_SECRET_REGISTRY_JSON` and `SPS_EXCHANGE_POLICY_JSON` are self-hosted bootstrap/default inputs, not the hosted per-workspace configuration path

### [NEW] `deploy/unraid/blindpass-dashboard.xml`

Unraid Docker template for the dashboard SPA container.

### DNS Setup

Create A or CNAME records for `sps.atas.tech`, `secret.atas.tech`, and `app.atas.tech` pointing to the Unraid host. TLS is managed by the operator's reverse proxy.

### Gateway Allowlist Update

Update the SPS egress URL filter allowlist to match the production domains:

- Secret input sandbox: `https://secret.atas.tech/*`
- Dashboard: `https://app.atas.tech/*` if links are ever sent in chat

**Acceptance**: All three subdomains serve over HTTPS with valid TLS. Health checks pass. Existing SPS operations work at the new URLs. Dashboard login/registration completes successfully against the production API. Gateway egress URL allowlist is verified.

---

## Milestone 5: Internationalization (i18n)

Multi-language support now ships across the main user-facing BlindPass surfaces in English (en) and Vietnamese (vi). The rollout landed in the planned order: server-backed locale contract first, then dashboard copy migration, then browser-ui and email rendering. The remaining follow-up work is verification depth, not foundational plumbing.

### Goals

- Replace all hardcoded UI strings with translatable keys across the dashboard, browser-ui, and email templates
- Clean up internal placeholder text (Stitch references, milestone labels, developer jargon) with professional English copy
- Support automatic language detection from `navigator.language` with English fallback
- Store explicit user locale preference in the database for server-side email localization
- Establish a scalable translation architecture for adding future languages

### Implemented Rollout

1. Locale contract: `preferred_locale` in auth responses, registration seed, and a dedicated locale update endpoint
2. Dashboard synchronization: server-backed locale reapplied after login/refresh, manual switch persisted to both `localStorage` and the database
3. Dashboard page migration: remove hardcoded strings and internal placeholder copy
4. Browser UI migration: lightweight translation loader using the shared locale package
5. Email rendering: locale-aware template selection in the mailer

### `packages/i18n/`

A shared workspace package containing all locale resources:

- `locales/en/*.json` and `locales/vi/*.json` — namespace-organized translation files (auth, dashboard, agents, billing, audit, policy, settings, browser-ui, email, common, etc.)
- `index.ts` — locale resolver utility and TypeScript key types
- `supported.ts` — list of supported locale codes
- `scripts/validate-keys.ts` + `scripts/validation-lib.ts` — validation for both key parity and suspicious untranslated-copy drift
- `tests/validate-keys.test.ts` — regression coverage for the validator heuristics

No runtime dependencies. Pure JSON exports consumed by downstream packages.

### `packages/dashboard`

Integrated `react-i18next` with `i18next-browser-languagedetector`:

- `src/i18n/config.ts` — i18next initialization with namespace-based lazy loading
- `src/components/LocaleSwitcher.tsx` — language toggle in sidebar footer and auth shell
- Locale is re-applied from the authenticated user record after login and refresh
- Manual language switches persist through a dedicated auth endpoint instead of `localStorage` only
- All 15 pages and 12 components migrated from hardcoded strings to `t('namespace:key')` calls
- Simultaneous cleanup of Stitch references, milestone labels, and internal jargon across all pages

### `packages/browser-ui`

Lightweight custom i18n without a framework dependency:

- `src/i18n.js` — minimal translation loader with `t(key)` function and `data-i18n` attribute scanner
- `index.html` updated with `data-i18n` attributes; English text remains as fallback content
- `app.js` status messages and UI text replaced with `t()` calls
- Locale resolves from `localStorage("blindpass_locale")` first, then browser language, then English fallback
- `document.documentElement.lang` is updated during initialization

### `packages/sps-server/src/services/mailer.ts`

- Add `locale` parameter (default `"en"`) to `sendVerificationEmail()` and `sendPasswordResetEmail()`
- Load locale-appropriate email strings from `@blindpass/i18n`
- Set `<html lang="...">` on rendered email templates

### `packages/sps-server/src/routes/auth.ts`

- Seed registration locale from the dashboard-selected locale
- Add `PATCH /api/v2/auth/locale` for explicit preference updates
- Return `preferred_locale` from auth/register, auth/login, auth/refresh, and auth/me user payloads
- Extract locale from `Accept-Language` only as a fallback for email-triggering flows where no stored preference exists
- Pass resolved locale to mailer functions

### Migration: `017_user_preferred_locale.sql`

Add `preferred_locale` column to the `users` table:

```sql
ALTER TABLE users ADD COLUMN IF NOT EXISTS preferred_locale TEXT DEFAULT 'en';
```

### `packages/sps-server/src/services/user.ts`

- Include `preferred_locale` in `UserRecord` and `UserRow` types
- Read and write locale on registration and explicit locale updates
- Expose locale in auth/token responses so the dashboard can initialize with the correct language

### Language Detection Priority

1. `preferred_locale` from user profile (database-backed)
2. `localStorage("blindpass_locale")` — manual override before login
3. `navigator.language` / `navigator.languages` — browser auto-detect
4. Fallback to `"en"`

Registration uses the current browser-selected locale as the initial default. Existing users keep their stored preference until they explicitly change it.

### Placeholder Text Cleanup

The production UI no longer exposes internal references such as:

- **Stitch references**: `"Stitch layout reference"`, `"Stitch-designed operations grid"`, `"Stitch table treatment"`, etc.
- **Milestone labels**: `"Milestone 3"`, `"Milestone 4"`, `"Desktop Agents Management"`, etc.
- **Developer jargon**: `"operator shell"`, `"header chrome"`, `"x402 overages settle before release"`, etc.

These have been replaced with professional, user-facing English copy before translation to Vietnamese.

**Current shipped state**: Dashboard, browser-ui, and emails render correctly in both English and Vietnamese. Locale detection works from browser settings with English fallback. Manual toggle persists through both `localStorage` and the authenticated user record. User locale is stored in the database and returned by auth/register, auth/login, auth/refresh, and auth/me flows. No Stitch references, milestone labels, or developer jargon remain in production UI text. Adding a new language is mostly a locale-resource change, but the current implementation also requires registering the locale in `packages/i18n/src/supported.ts`, `packages/dashboard/src/i18n/config.ts`, and `packages/browser-ui/src/i18n.js`.

**Remaining follow-up**: add browser-level locale E2E coverage for the dashboard toggle, browser-ui locale resolution, and hosted end-to-end email locale behavior.

---

## Infrastructure Changes

### Container Images

| Image | Source | Notes |
|-------|--------|-------|
| `ghcr.io/atas-tech/blindpass-sps-server` | Existing | Add health check endpoints + analytics routes |
| `ghcr.io/atas-tech/blindpass-browser-ui` | Existing | Rebuild with production `VITE_SPS_API_URL` |
| `ghcr.io/atas-tech/blindpass-dashboard` | New | Vite build, served via lightweight static server |
| `postgres:16-alpine` | Upstream | Production credentials via env |
| `redis:7-alpine` | Upstream | Unchanged |

### New Environment Variables

| Variable | Used By | Purpose |
|----------|---------|---------|
| `SPS_TURNSTILE_SECRET` | sps-server | Cloudflare Turnstile server-side validation key |
| `SPS_AUTH_COOKIE_DOMAIN` | sps-server | Cookie domain for hosted refresh-session cookies |
| `RESEND_API_KEY` | sps-server | API key for hosted transactional email delivery |
| `SPS_EMAIL_FROM` | sps-server | Verified sender used for verification and password-reset emails |
| `SPS_EMAIL_REPLY_TO` | sps-server | Optional reply-to address for support and operator contact |
| `VITE_TURNSTILE_SITE_KEY` | dashboard | Turnstile widget site key baked into the build |
| `BILLING_PORTAL_RETURN_URL` | sps-server | URL to redirect after billing portal session (default: `https://app.atas.tech/billing`) |
| `VITE_SPS_API_URL` | dashboard, browser-ui | SPS API base URL baked at build time |

---

## Verification Plan

Detailed E2E and integration scenarios for this phase live in `docs/testing/Phase 3E.md`.

### Automated Tests

All tests use **Vitest**. Run from project root:

```bash
npm test
npm test --workspace=packages/sps-server
npm test --workspace=packages/dashboard
```

#### Milestone 1: hosted auth hardening and abuse-control coverage

- hosted login/register/refresh set or rotate the refresh cookie with the expected hosted security attributes
- dashboard refresh/logout flows work with cookie-backed auth and no refresh token in JS-visible storage
- logout clears the hosted refresh cookie and revokes the backing session
- Turnstile validation rejects invalid tokens when configured
- Burst anomaly detection triggers workspace throttle after 5x quota

#### Milestone 2: analytics, SDK integration, and documentation validation

- `getRequestVolume` returns correct daily counts from `audit_log`
- `getExchangeMetrics` groups by terminal status correctly
- `getActiveAgentCount` counts distinct `agent_token_minted` actors within the time window
- Analytics endpoints return only caller-workspace data

- Node.js SDK bootstrap → request secret → retrieve flow succeeds
- Quick Start, self-hosting, env-template, Makefile, and OpenAPI reference artifacts exist and match the current hosted/local setup
- Python SDK succeeds with the same hosted bootstrap and delivery flow
- Go SDK succeeds with the same hosted bootstrap and delivery flow
- OpenAPI spec validates against running server responses

#### Milestone 3: `health.test.ts` and deployment checks

- `GET /healthz` returns `200`
- `GET /readyz` returns `200` when PostgreSQL and Redis are reachable
- `GET /readyz` returns `503` when PostgreSQL or Redis is unavailable
- Production image builds pass CI
- All three subdomains resolve and serve with valid TLS
- Hosted login / refresh / logout work correctly with secure cookie-backed session auth at production URLs

### Manual Verification

1. **Session hardening**: log in to the hosted dashboard, verify no refresh token is readable from browser storage, refresh the page, and verify the session persists through the hosted cookie flow.
2. **Abuse controls**: attempt rapid-fire signups and verify Turnstile appears; trigger a burst and verify throttle + `abuse_alert`.
3. **Analytics**: generate traffic over several days and verify charts render on the analytics page.
4. **SDK quickstart**: follow the quickstart guide from a clean machine and verify first secret delivery succeeds.
5. **Production**: deploy all containers to Unraid and complete a full register → enroll agent → deliver secret flow at production URLs.

---

## Resolved Decisions

- **Dashboard refresh-token handling** → hosted mode must migrate refresh handling to `Secure` + `httpOnly` cookies before wider go-live; `localStorage` persistence is not the long-term hosted model
- **Turnstile** → Cloudflare Turnstile for signup/login challenge, gated by env var so local/dev can skip it
- **Analytics scope** → business-event counts and timestamps only; no secret names, ciphertext, token values, specific agent identifiers, or HTTP response-class telemetry
- **Hosted policy foundation** → workspace-scoped PostgreSQL policy lives in the separate Hosted Workspace Policy Foundation milestone and is a prerequisite for later hosted phases
- **SDK priority** → Node.js first, then Python, then Go
- **API documentation** → maintained OpenAPI 3.1 snapshot; hand-written initially, auto-generation deferred
- **Reverse proxy** → operator-managed; no bundled reverse proxy
- **Domain strategy** → `app.atas.tech` for dashboard, `secret.atas.tech` for sandbox, `sps.atas.tech` for API
- **Launch ordering** → local hardening and ecosystem work land before production cutover

### Suggested Work Breakdown

1. Hosted cookie/session migration + dashboard auth updates + Turnstile + burst detection
2. Analytics backend + analytics UI + Node.js SDK publish + Python SDK + Go SDK + docs + community guide
3. Hosted deployment + domain cutover + health checks
