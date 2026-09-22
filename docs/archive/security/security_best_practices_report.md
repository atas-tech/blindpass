# BlindPass Security Review Supplement

> Historical record, archived during the 2026-09-22 documentation alignment. Dates, checkboxes, commands, and proposed decisions below describe their original review period; they do not establish current support or authorize new work. See the [current documentation](../../README.md) and [roadmap](../../product/Roadmap.md).

Date: 2026-03-24

### Related Documents

- [Security Audit v2](Security%20Audit%20v2.md) — canonical audit report (SBP-DELTA-001 elevated there as C-4)
- [Threat Model](../../security/blindpass-threat-model.md) — formal threat model (SBP-DELTA-001 maps to TM-002/TM-003; SBP-DELTA-002 maps to TM-004)

## Executive summary

This note is intentionally aligned with `docs/security/Security Audit v2.md` and now serves as a historical delta plus remediation note. The two additions from this review were a critical browser-ui origin-trust flaw and a medium-severity log leak involving live secret URLs. Both have since been addressed in code; `Security Audit v2.md` is the canonical source for the live issue list and status.

## Delta findings

### SBP-DELTA-001 → Elevated to [C-4 in Security Audit v2](Security%20Audit%20v2.md)

- Current status: ✅ Fixed on 2026-03-24
- Rule ID: JS-XSS-001 / REACT-XSS-002
- Severity: Critical
- Location:
  - Historical vulnerable path:
    - `packages/browser-ui/src/request-context.js`
    - `packages/browser-ui/src/app.js`
  - Current fixed path:
    - `packages/browser-ui/src/request-context.js`
    - `packages/browser-ui/src/app.js`
    - `packages/browser-ui/tests/request-context.test.mjs`
- Evidence:
  - The browser UI formerly accepted `api_url` directly from the query string.
  - Metadata fetches and secret submission formerly used that attacker-supplied origin.
  - The implementation now ignores `api_url` in request parsing and preview-link generation and pins to the configured API origin.
- Impact:
  - Historical impact was official-origin phishing and refresh-token exfiltration.
  - That direct exploit path is now closed for the reviewed code paths.
- Fix:
  - `api_url` was removed from user-controlled query parsing.
  - Browser-ui requests now use the configured API origin only.
  - Regression tests now enforce that query-supplied API overrides are ignored.
- Mitigation:
  - Consider revoking any browser refresh tokens if this feature was exposed before the fix.
  - Keep an end-to-end security test for rejected query-supplied API origins on the roadmap.
- False positive notes:
  - This was a direct code-path issue and did not depend on XSS.
  - The reviewed exploit path is closed unless the behavior is reintroduced.

### SBP-DELTA-002

- Current status: ✅ Fixed on 2026-03-24
- Rule ID: General logging hygiene
- Severity: Medium
- Location:
  - Historical vulnerable path:
    - `packages/openclaw-plugin/index.mjs`
    - `packages/sps-server/src/services/audit.ts`
    - `packages/sps-server/src/services/user.ts`
  - Current fixed path:
    - `packages/openclaw-plugin/index.mjs`
    - `packages/openclaw-plugin/tests/index.test.mjs`
    - `packages/sps-server/src/services/audit.ts`
    - `packages/sps-server/src/services/user.ts`
    - `packages/sps-server/tests/logging.test.ts`
- Evidence:
  - The OpenClaw plugin formerly logged full `secretUrl` values to stdout before delivery.
  - `logAudit()` formerly emitted full audit records, including request IDs, exchange IDs, secret names, payment IDs, approval references, and IPs, to stdout.
  - Non-production user flows formerly logged raw email verification URLs.
  - Debug workspace-owner verification logs were present in the service layer.
- Impact:
  - Historical impact was recovery of one-time secret URLs and sensitive operational metadata through live logs.
  - Default stdout leakage for those fields has now been removed.
- Fix:
  - Live magic-link logging was removed from the plugin.
  - Audit stdout is now redacted and opt-in behind `SPS_LOG_AUDIT_EVENTS=1`.
  - Verification URL logging is now opt-in behind `SPS_LOG_VERIFICATION_URLS=1`.
  - Leftover debug logging was removed from user services.
- Mitigation:
  - Treat existing log sinks as sensitive and restrict access/retention immediately.
  - Add regression tests that assert redaction for secret URLs and magic-link-like fields.
- False positive notes:
  - The operational impact depends on who can read logs and how quickly.
  - The OpenClaw link leak is time-bound by TTL, but still exploitable during active sessions.

## Alignment notes with Security Audit v2

- `docs/security/Security Audit v2.md` should remain the canonical audit document for:
  - the current done / partial / open issue list
  - overlapping findings on secret fallbacks, refresh-token handling, CSP/header coverage, and CORS
  - remaining remediation priorities

## Commands run

- `npm run test --workspace=packages/browser-ui`
- `npm run test --workspace=packages/openclaw-plugin`
- `npm run test --workspace=packages/sps-server -- tests/logging.test.ts tests/secret-config.test.ts tests/routes.test.ts`
- `npm run build --workspace=packages/browser-ui`
- `npm run build --workspace=packages/sps-server`
