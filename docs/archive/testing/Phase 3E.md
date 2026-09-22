# Phase 3E Test Plan: Hosted Hardening, Ecosystem & Launch

> Historical record, archived during the 2026-09-22 documentation alignment. Dates, checkboxes, commands, and proposed decisions below describe their original review period; they do not establish current support or authorize new work. See the [current documentation](../../README.md) and [roadmap](../../product/Roadmap.md).

This document defines the End-to-End (E2E), integration, and operational verification scenarios for the hosted hardening and launch work split out of Phase 3B.

## How To Run

Phase 3E spans `packages/sps-server`, `packages/dashboard`, SDK packaging work, and deployment artifacts.

1. Start local dependencies:
   `make up`
2. Export the PostgreSQL connection string and enable hosted integration coverage:
   `export DATABASE_URL=postgresql://blindpass:localdev@127.0.0.1:5433/blindpass`
   `export SPS_PG_INTEGRATION=1`
3. Run the server test suites:
   `npm test --workspace=packages/sps-server`
4. Run the dashboard test suites:
   `npm test --workspace=packages/dashboard`

Useful companion commands:

- `make migrate`
- `npm run dev --workspace=packages/sps-server`
- `npm run dev --workspace=packages/dashboard`
- `npm run test:e2e --workspace=packages/sps-server`

## Milestone 1: Dashboard Session Hardening & Advanced Abuse Controls

- [x] **Hosted refresh-session cookie migration**
  - [x] Hosted login and refresh responses set or rotate the refresh token using `Secure` + `httpOnly` cookies
  - [x] Dashboard auth no longer persists the refresh token in `localStorage` or `sessionStorage`
  - [x] Page reload and token refresh still work through the cookie-backed hosted session flow
  - [x] Logout clears the refresh cookie and revokes the backing server-side session
  - [x] Missing or invalid hosted refresh cookies fail closed without silently restoring the session

- [x] **Turnstile**
  - [x] Register/login accepts a valid Turnstile token when configured
  - [x] Register/login rejects an invalid Turnstile token when configured
  - [x] Local/dev mode skips Turnstile validation when the secret is unset

- [x] **Burst throttling**
  - [x] A workspace exceeding the burst threshold emits an `abuse_alert` audit event
  - [x] Throttled workspaces are reduced to 1 request/minute
  - [x] The throttle clears automatically after the window expires
- [x] **Burst Simulator**
  - [x] Trigger a 5x quota burst
  - [x] Verify `abuse_alert` is emitted
  - [x] Verify the throttle applies only to the affected workspace

## Milestone 2: Analytics, SDKs, Documentation & Community

- [x] **Business-event analytics**
  - [x] Analytics API request-volume series reflects `request_created` audit events
  - [x] Analytics API exchange-outcome series groups successful vs failed/expired vs denied terminal business events
  - [x] Analytics API active-agent count reflects distinct recent agent token-mint actors over the configured window
  - [x] Analytics API enforces workspace scoping and blocks `workspace_viewer` access
  - [x] Request volume chart reflects `request_created` audit events
  - [x] Exchange outcome chart reflects requested/submitted/retrieved/denied/rejected business events
  - [x] Active agent count reflects distinct agent actors over the configured window
  - [x] Analytics never exposes secret names, ciphertext, token values, or per-agent identities

- [x] **Node.js SDK**
  - [x] Bootstrap API key to JWT minting works against a local hosted SPS
  - [x] Secret request and retrieval flow succeeds end-to-end
  - [x] Exchange request, fulfill, submit, and retrieve flow succeeds end-to-end

- [x] **Analytics E2E**
  - [x] Dashboard metrics reflect workspace activity (Request volume, Active agents)
  - [x] Charts and insight panels render correctly
  - [x] Timeframe selectors trigger data reloads

- [ ] **Python and Go SDKs**
  - [ ] Both SDKs complete the same hosted bootstrap and secret delivery flow
  - [ ] Both SDKs document in-memory-only secret handling expectations

- [x] **Docs and community artifacts**
  - [x] Quickstart guide works from a clean machine
  - [x] OpenAPI references match real route contracts
  - [x] Policy guide explains the hosted workspace policy model and the self-hosted env bootstrap/default path
  - [x] Provide a standard SDK integration harness such as `docker-compose.test.yml` or an equivalent mock container setup

## Milestone 3: Transactional Email With Resend

- [x] **Verification email delivery**
  - [x] Hosted registration sends a verification email through Resend with the correct workspace/app URL
  - [x] Retrying verification invalidates prior verification links so only the newest link succeeds
  - [x] Delivery failures are surfaced as retryable errors without logging raw tokens or provider secrets
  - [x] Local/dev mode still supports a no-provider fallback without blocking local signup flows
  - [x] Verification tokens are stored only as hashes and not in plaintext on the `users` table

- [x] **Forgot-password**
  - [x] Forgot-password request returns the same generic response for existing and unknown email addresses
  - [x] Existing and unknown email paths have comparable observable latency through a minimum-response-duration guard
  - [x] Existing accounts receive a password-reset email through Resend
  - [x] Reset tokens are hashed at rest, expire, are single-use, and live in a shared token table rather than ad hoc user columns
  - [x] Reset completion rotates credentials without reviving revoked or expired reset tokens

- [x] **Abuse controls**
  - [x] `POST /api/v2/auth/forgot-password` enforces dedicated per-IP rate limits
  - [x] `POST /api/v2/auth/retrigger-verification` enforces dedicated per-user or per-IP rate limits
  - [x] Hosted mode can require Turnstile for both email-triggering endpoints
  - [x] These protections work independently of workspace-level burst throttling

- [x] **Dashboard UX**
  - [x] The forgot-password page is no longer a placeholder and completes the request flow
  - [x] Verification resend UI distinguishes successful delivery from backend/provider failure
  - [x] UI messages do not leak account-existence or provider-specific internals

- [x] **Operational coverage**
  - [x] Provider outages or rate limits produce actionable server logs and audit events without exposing recipient-specific secret material
  - [x] Mailer integration tests cover provider success, transient failure, and permanent failure branches
  - [x] Fully automated un-mocked E2E test (`scripts/e2e-real-email.mjs`) verifies end-to-end integration and delivery via Mail.tm


## Milestone 4: Hosted Deployment & Domain Cutover

- [x] `GET /healthz` returns `200`
- [x] `GET /readyz` returns `200` only when PostgreSQL and Redis are reachable
- [x] `GET /readyz` returns `503` if Redis is down but PostgreSQL is up, and vice versa
- [ ] Production dashboard, browser UI, and API images build successfully
- [ ] `app.atas.tech`, `secret.atas.tech`, and `sps.atas.tech` serve over valid HTTPS
- [ ] Hosted register → enroll agent → deliver secret flow succeeds at production URLs
- [ ] Hosted login / refresh / logout work correctly with secure cookie-backed session auth at production URLs
- [ ] No refresh token is readable from JS-accessible browser storage after hosted login
- [ ] A throttled workspace does not impact the performance or rate limits of other active workspaces on the same instance

## Milestone 5: Internationalization (i18n)

- [x] **Locale resource validation**
  - [x] `npm run validate --workspace=packages/i18n` confirms all English and Vietnamese locale files have identical key structures
  - [x] Validator heuristics flag suspicious untranslated English-copy drift in non-English namespaces
  - [x] Intentional technical/product identifiers are handled through a small explicit allowlist so validator output stays actionable
  - [x] Current validator output is clean with no remaining EN/VI warnings

- [x] **Auth and database locale contract**
  - [x] `preferred_locale` column exists on `users` table after migration
  - [x] User registration accepts and stores the current browser-selected locale as the initial default
  - [x] Auth/register, auth/login, auth/refresh, and auth/me responses include `preferred_locale`
  - [x] `PATCH /api/v2/auth/locale` updates the current user record without affecting other users or workspaces
  - [x] Server-side email locale selection prefers stored `preferred_locale` and uses `Accept-Language` only as fallback
  - [x] Covered by `packages/sps-server/tests/auth-routes.test.ts`

- [x] **Dashboard implementation**
  - [x] Dashboard locale detection and persistence are wired through `react-i18next`, browser detection, `localStorage`, and the authenticated user record
  - [x] Registration seeds `preferred_locale` from the current dashboard locale
  - [x] Auth shell and workspace pages render from shared EN/VI namespace resources
  - [x] No Stitch references, milestone labels, or internal jargon remain in production dashboard copy
  - [x] Covered by dashboard smoke and page tests including `dashboard.test.tsx`, `dashboard.turnstile.test.tsx`, `dashboard.email.test.tsx`, and page-level Vitest suites

- [x] **Browser UI implementation**
  - [x] Browser UI resolves locale from `blindpass_locale` or browser settings, then sets `<html lang>`
  - [x] Static HTML text and JS status messages render from shared locale resources
  - [x] English fallback remains in place for missing translation keys through the bundled browser-ui locale loader
  - [x] Build and browser-ui test suite pass with the localized runtime

- [x] **Email template implementation**
  - [x] Verification email renders in Vietnamese when locale is `vi`
  - [x] Password reset email renders in Vietnamese when locale is `vi`
  - [x] Emails default to English when no locale is specified
  - [x] Covered by `packages/sps-server/tests/mailer.test.ts`

- [x] **Targeted regression**
  - [x] `npm test --workspace=packages/i18n`
  - [x] `npm run validate --workspace=packages/i18n`
  - [x] `npm run build --workspace=packages/dashboard`
  - [x] Targeted dashboard and SPS regression suites pass for the i18n slices landed so far

- [ ] **Remaining E2E coverage**
  - [ ] Add Playwright coverage for dashboard locale toggle persistence across login, refresh, and logout
  - [ ] Add browser-level locale-resolution coverage for browser-ui using stored locale and browser-language fallbacks
  - [ ] Add hosted end-to-end email-locale smoke coverage that proves stored `preferred_locale` wins over `Accept-Language`
