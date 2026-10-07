# P07 slice 2 evidence: operator auth limits, headers and bundle check

**Date:** 2026-10-06
**Scope:** P07.2 — P07-D4 (abuse limits), P07-D6 (header scope, bundle check),
P07-I02, P07-I03, pilot S01–S05, client timeouts, production rejection of test
flags, review findings N-01..N-06. Design and operating limits:
[operator-auth-and-headers](../../security/operator-auth-and-headers.md).
**Status:** local test evidence only. Owner confirmation of the D4 shape, the
Compose/Chromium run and hosted CI are open (see "Not run").

Status words below are literal. **Done** means the command ran in this
working tree and the result is quoted. **Not run** means no result exists.

## What changed, per finding

| Finding | Before | Applied (D4 shape confirmed by the owner 2026-10-06; N-03 and N-05 remainders deferred) | Tests |
|---|---|---|---|
| N-01 bootstrap hashed before the token check, inline, unthrottled | Argon2 on the async worker for every request | Token usability is read first (one SHA-256 row lookup, no hash). Argon2 runs on the blocking pool behind the shared 4-permit semaphore (`429 bootstrap_busy` when full). An unusable token spends a per-peer-shard (10 / 900 s, 256 shards) and a global (100 / 900 s) failure budget, then `429 bootstrap_rate_limited`. At most 257 rows. A valid token is never refused. Reissue deletes earlier unused tokens | `bootstrap_limits.rs` BL01–BL07 |
| N-02 account bucket spent by every attempt, keyed by username only, not cleared by reset | One attacker address could lock a named operator indefinitely | Failures only; success clears. Per (account, source-address-hash) lock at 10 failures / 900 s; account-wide lock at 50 failures from any sources; per-address ceiling of 30 failures then `429`. Reset (admin socket, `blindpass admin reset-password`, admin route) clears all four row families | `login_limits.rs` LL01–LL15 |
| N-03 test mode refused only for `NODE_ENV=production` | No shipped profile sets `NODE_ENV` | Refused when `BLINDPASS_PROXY_REQUIRED=1` (every shipped native, image and Compose profile) or `NODE_ENV=production`; `check-config` warns on stderr when test mode is on. **Not done:** the stricter "production unless an explicit non-production marker" | `production_flags.rs` PF01–PF07 |
| N-04 login timing revealed usernames | Unknown username returned in ~4.5 ms; real operator ~402 ms (debug build) | A dummy Argon2 hash (warmed at startup) is verified for unknown and disabled accounts; they also lock identically (no 423-vs-401 oracle) | LL07, LL15 |
| N-05 refresh reset the TTL; temporary passwords never expire | Rotation restarted a 30-day TTL each time | **Done:** absolute lifetime from first sign-in, default 7 days (`BLINDPASS_SESSION_ABSOLUTE_SECONDS`, 3,600–2,592,000), published in `capabilities.limits.session`; a refresh past it revokes the family. **Not done:** temporary-password expiry (needs a column, schema 20) | `session_lifetime.rs` SL01–SL04 |
| N-06 browser-ui nginx CSP admitted `http: https: ws: wss:` | Static `connect-src` with bare schemes | `nginx.conf.template` rendered at image build with the exact reviewed HTTPS API origin; loopback, plain-http, wildcard, userinfo or path origins fail the build unless `BLINDPASS_UI_DEV_IMAGE=1` | `packages/browser-ui/tests/nginx-csp.test.mjs` (7) |

### P07-D4 limits, final shape

| Limit | Default | Config | Published |
|---|---|---|---|
| Failures per (account, source) before that pair locks | 10 per 900 s, lock 900 s | `BLINDPASS_LOGIN_ACCOUNT_FAILURES` | `limits.login.account_failures` |
| Failures per account from all sources before everyone is locked | 50 per 900 s | `BLINDPASS_LOGIN_ACCOUNT_TOTAL_FAILURES` | `account_total_failures` |
| Failures per source address, any username | 30 per 900 s, then `429 login_rate_limited` | `BLINDPASS_LOGIN_IP_FAILURES` | `ip_failures` |
| Window / lock length | 900 s / 900 s | `BLINDPASS_LOGIN_WINDOW_SECONDS`, `BLINDPASS_LOGIN_LOCKOUT_SECONDS` | `window_seconds`, `lockout_seconds` |
| Live pair rows for unknown usernames | 10,000 | `BLINDPASS_LOGIN_TRACKED_ACCOUNTS` | no |
| Bootstrap failures per peer shard / global | 10 / 100 per 900 s | `BLINDPASS_BOOTSTRAP_FAILURES_PER_PEER`, `..._GLOBAL` | no |

The plan's default was one account bucket of 10 failures / 15 min. That shape
is exactly what N-02 shows is abusable, so two counters are applied and are
**confirmed by the owner on 2026-10-06**. Residual risks (stated in the security doc): an
attacker with `ceil(50 / 10)` = 5 addresses still locks an account for all
sources for 900 s (recovery = password reset); operators behind one NAT share a
pair counter with anything behind it; concurrent attempts can overshoot by at
most 3 (4 hashing slots − 1); a flood can answer other clients
`429 login_busy`.

## P07-D6 header findings

- Embedded console and input HTML: `default-src 'none'; script-src 'self';
  style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self';
  frame-ancestors 'none'; base-uri 'none'; form-action 'self'`, plus
  `X-Frame-Options: DENY`, `Cross-Origin-Opener-Policy: same-origin`,
  `Permissions-Policy`, `Referrer-Policy: no-referrer`,
  `X-Content-Type-Options: nosniff`, `Cache-Control: no-store`. No development
  origin and no scheme wildcard. Verified by parsing the served header
  (`headers.rs` HD01–HD02), not by grepping for strings.
- **No CORS grant by default**, not even for the UI origin;
  `BLINDPASS_CORS_ALLOWED_ORIGINS` names exact origins (HD03).
- **HSTS scope (correction to an early assumption):** the controller itself
  emits `Strict-Transport-Security: max-age=31536000` (no `includeSubDomains`,
  no `preload`) only when `BLINDPASS_PROXY_REQUIRED=1` with valid trusted-edge
  headers, or with built-in TLS. A plain-HTTP profile never emits it, and a
  client-supplied `X-Forwarded-Proto: https` cannot make it (HD04). The shipped
  nginx and Caddy examples add the same value per server block and strip an
  upstream copy (HD05, HD06). The one-year `max-age` is an owner choice: the
  recommendation is a staged short value first; no `includeSubDomains`.
- Legacy `packages/dashboard/nginx.conf` still admits `http: https: ws: wss:` in
  `connect-src`. Not in this slice and **not changed**.
- Bundle check: `scripts/release/check-bundles-for-localhost.sh` fails on
  loopback origins (`localhost`, `127.0.0.1`, `[::1]`, `0.0.0.0`), bare-scheme or
  `*` CSP sources and `unsafe-eval`/script `unsafe-inline`; it fails closed (exit 2)
  on a missing, unreadable or empty scan. Reviewed false-positive classes, counted
  and not findings: the bare `http(s)://localhost` placeholder libraries hand to
  the URL parser, and `www.w3.org` XML/SVG namespaces.

## Client timeouts (10 s connect / 30 s total)

| Client | Finding | Bound now | Test |
|---|---|---|---|
| Console | 15 s default total; a per-call override was unbounded | clamped to 30 s (`MAX_TIMEOUT_MS`); a 423 is a distinct `locked` error | `client.test.ts` (+3), `login.test.tsx` (+2) |
| Desktop approval app | curl `connect-timeout = 5`, `max-time = 15` | unchanged, now pinned | `tst_lib.qml::test_curl_config_bounds_connect_and_total_time` |
| MCP server | no HTTP client; broker calls use a Unix socket with a delivery budget refused above 25 s | no change; documented | not touched |

A timeout is an unknown outcome in every client and is never an approval. **No
`packages/mcp-server` source or test was changed by this slice.** My own
wall-clock-sensitive tests are ratio checks, not absolute deadlines: LL15
(unknown username at least half the time of a known one) and BL05 (invalid
token at least 3x faster than a hashed bootstrap). Under heavy machine load they
could flake; neither ran under the load average of about 74 reported for the
`mcp-server` run.

## Red first versus written after

**Red first (failed on the old code, then went green):** login limits:
12 of the 13 LL cases written first were red against the old single limiter
(LL14 and LL15 were added later; LL15 is in the next list);
BL02–BL05; SL01–SL04; `nginx-csp.test.mjs`; console 423/`locked` and timeout
clamp; login-page 423 state. BL04 took 211 s before the fix and about 2.5 s after.

**Written after the code (not red first), mutation-checked where stated:**
LL15 timing (mutation: 4.5 ms unknown vs 402 ms known with the dummy hash
removed); PF02 and PF04 (mutation removing the proxy-required rule fails both);
HD01 (mutation widening the CSP fails it); PF01, PF03, PF05–PF07.

**Characterization (passed on first run, so they prove nothing about a defect):**
BL01, BL06, BL07; HD02–HD06; the QML timeout test; `bundle-localhost-check`
(its self-test plants about 27 cases, including every finding class and every
fail-closed exit); `confirmation-code-role.test.mjs`; `auth_secrets_at_rest.rs`.

## Pilot rows S01–S05

| Row | Result | Evidence |
|---|---|---|
| S01 confirmation code | Code role made explicit: human correlation text only. The generator is 8 adjectives x 8 nouns x 100 numbers = 6,400 codes (about 12.6 bits; `random[2] % 100` has a small modulo bias). It appears only in response schemas (`SecretRequestCreated`, `SecretMetadata`) and is never read from a request. About 3% chance of a collision among 20 simultaneous pending requests. Raising entropy is a shared-dictionary contract change (CV04): **owner decision, not built** | `scripts/tests/confirmation-code-role.test.mjs` (3, pass) |
| S02 verification tokens | Bootstrap token, passwords, browser session and refresh cookies, desktop access and refresh tokens are stored only as SHA-256 or Argon2 verifiers; refusals (replay, unknown token) echo no credential or verifier; the bootstrap token is single use and expires at 15 min. **Exception, not a verifier:** the double-submit `csrf_secret` is stored as issued because the session read serves it back; the test pins that it is never a bearer secret. Replay of a rotated refresh token revokes the family (browser and desktop) | `auth_secrets_at_rest.rs` AT01–AT02 (pass, SQLite and PostgreSQL); written after the code, characterization; existing `admin_session.rs` and `desktop_session.rs` cover replay |
| S03 login/refresh/logout in the real console | Cookie attributes (`HttpOnly`, `SameSite=Strict`, refresh cookie scoped to the refresh path) and replay are covered by `admin_session.rs` and `desktop_session.rs`. The existing Chromium flow `test:p02-browser` (CC02 `e2e-human`, CC03) drove the real console against the Rust controller and passed after this slice. That run is a plain-HTTP test-mode controller, **not** a Compose release profile, and I did not add cookie or storage inspection to it. F-8 is not resolved by this run | partial |
| S04 production CSP / headers / forbidden destinations | CSP and baseline headers parsed from served responses (HD01–HD06); nginx and Caddy examples parsed for HSTS scope and header overwrite; bundle checker clean on console and browser-ui dist. **No Chromium network inspection of a deployed profile**, so allowed-call and blocked-exfiltration behavior in a browser is unproven | partial |
| S05 distributed-IP guessing, lockout, recovery, slow API | In-process: distributed-source lock, per-address ceiling, unknown-vs-known identical answers, every reset path including the real admin socket, bootstrap abuse, console and QML timeouts. **No run through a real edge with distinct source addresses, and no slow-API run in a browser** | partial |

## Gates

All commands ran from the repository root in this working tree, which also
holds uncommitted changes from other workstreams.

| Gate | Result |
|---|---|
| `cargo fmt --all -- --check` | exit 0 |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | exit 0, no warnings |
| `cargo test --workspace --locked --no-fail-fast` | exit 0: **816 passed, 0 failed, 151 ignored** across 88 test binaries. The 151 ignored are PostgreSQL-authority, pinned-toolkit-image and Quickshell tests that need their own drivers; none was run by this command |
| New or changed controller tests in that run | `login_limits` 15, `bootstrap_limits` 7, `session_lifetime` 4, `production_flags` 7, `headers` 6, `auth_secrets_at_rest` 2, `security_perf_regressions` 6, `deployment_proxy` 7: all pass on SQLite |
| PostgreSQL variants (`P02_TEST_BACKEND=postgres`, local fixture on 5433): `login_limits`, `bootstrap_limits`, `session_lifetime`, `auth_secrets_at_rest`, `security_perf_regressions`, `admin_socket`, `desktop_session`, `rate_limits`, `embedded_ui`, `browser_cors`, `desktop_app_e2e` | All pass (15, 7, 4, 2, 6, 6, 8, 1, 5, 2; `desktop_app_e2e` 3 ignored, needs Quickshell). `headers`, `production_flags` and `deployment_proxy` were not run on PostgreSQL (header and configuration level). `admin_session` failed 3 of 4 with `408` in the batch run while the machine was loaded and passed 4 of 4 in 6.1 s alone: load-induced, not a defect shown in the code |
| `recovery-authority-postgres.py --test-target production_ownership --controller-backend postgres` | 33 passed, 0 failed, driver exit 0 (a first run also passed 33 but exited 1 with 6 cleanup errors; I dropped that run's leftover disposable database and roles by hand) |
| `recovery-authority-postgres.py --test-target deployment_startup --controller-backend sqlite` | 5 passed, driver exit 0 in 2.3 s. A first run failed `p06_s03` (serve not refused within 3 s) and `p06_s04` (not ready in time) while the leftover fixture objects above existed and the host was loaded; two filtered reruns failed at fixture setup with an empty log; a rerun after cleanup passed. The environmental cause is **inferred, not proven**; I did not build a pre-change baseline |
| `npm run build` | exit 0 |
| `npm test` | exit 0. 349 Node-runner tests passed, 0 failed (includes `mcp-server` 108/108, `browser-ui` 64/64 with the 7 CSP tests, and my `confirmation-code-role` and `bundle-localhost-check` tests, now wired into `scripts/tests/run-workspace-tests.mjs`); vitest: console 113/113, dashboard 42/42, agent-skill 23/23, gateway 9/9; **`sps-server` 80 passed, 101 skipped (17 of 32 files skipped; needs services, not run)** |
| `SUT=rust` contract suite, SQLite and PostgreSQL | 40/40 and 40/40 pass |
| `npm run test:p02-browser --workspace=@blindpass/console` (Chromium, Rust controller, SQLite) | 3/3 pass |
| `check-bundles-for-localhost.sh --self-test` | pass (about 27 planted cases) |
| `check-bundles-for-localhost.sh` on `packages/console/dist` | files=32, findings=0, bare `http://localhost` placeholder=2, XML namespaces=19 |
| `check-bundles-for-localhost.sh` on `packages/browser-ui/dist` and `dist-embedded` | files=4 each, findings=0 |
| `node scripts/tests/controller-openapi.test.mjs` | 13/13 pass |
| Console `tsc --noEmit`; QML `qmltestrunner` | clean; 51 passed, 0 failed |
| Pilot S01–S05 on a Compose release profile with Chromium | **NOT RUN** (below) |
| `tests/deployment/compose-backup.py` with the changed fixture | **NOT RUN**; it compiles (`py_compile`) and now matches its sibling `compose-backup-postgres.py`, which already sets `BLINDPASS_PROXY_REQUIRED=0` |

The machine ran other work (load average 6–40 during these gates; about 74 when
the `mcp-server` flake below occurred). Three timing-sensitive checks deserve
the caveat: my LL15 and BL05 are ratio checks (passed in every run recorded
here); `deployment_startup` s03/s04 use 3 s and polling deadlines and failed
once under load as described above.

## Not run

- **Compose release-profile run with a real nginx edge and Chromium network
  inspection (S03, S04, S05).** Not run: it needs a rebuilt controller image
  and a Compose harness that does not exist for these checks (the existing
  `compose-up.py` P06 scenarios do not drive a browser), and the turn budget
  was spent on the finding fixes and gates. Still needed: cookie and storage
  inspection after real sign-in, refresh and sign-out; CSP violation and
  outbound-request capture for the console and input origins; lockout and
  reset-password recovery and distributed-source guessing through the edge from
  distinct source addresses; a paused-controller sign-in to show the console's
  bounded timeout; `docker run nginx -t` on the rendered browser-ui config.
- Hosted CI.
- Temporary-password expiry (needs schema 20): not built.
- Confirmation-code entropy change: not built (contract change).
- `packages/dashboard` legacy CSP: not in this slice.

## Defects and decisions outside this slice

- `packages/dashboard/nginx.conf` legacy CSP still admits bare schemes in
  `connect-src`.
- `crates/blindpass-controller/tests/deployment_proxy.rs` served its ingress
  component fixture with test mode and `BLINDPASS_PROXY_REQUIRED=1`, which the
  new rule refuses; it now uses the in-process `Config::with_test_fixture_mode`
  seam (PF07 pins that no non-test source calls it).
- `tests/deployment/compose-backup.py` fixture changed (`"1"` -> `"0"`), not
  re-run (above). `scripts/tests/run-workspace-tests.mjs` gained two test files.
- i18n `login.errors.locked` strings were added in `packages/i18n` (outside the
  assigned ownership list).
- The PostgreSQL authority driver can leave disposable databases and roles
  behind when its cleanup fails (`owned_authority_cleanup_errors>0`) and then
  fail later runs at fixture setup with an empty log and no explanation.
- `packages/mcp-server` (not changed by this slice): a first `npm test` run
  under machine load failed 7 of 108 and then passed 108/108 on four reruns;
  in this slice's run it passed 108/108. If any of its timeout tests depend on
  wall-clock deadlines they are load-sensitive; I did not inspect them.

## Owner decisions

Answered 2026-10-06: item 1 (two-counter D4 shape) confirmed; items 2 and 3 (stricter test-mode rule, temporary-password expiry) deferred and documented as known limitations. Items 4 and 5 are still open.

1. Confirm the two-counter D4 shape (per-source 10 and account-wide 50) or
   restore the plan's single bucket and accept the lock-out-by-anyone risk.
2. N-03 stricter rule ("production unless an explicit non-production marker"):
   about 35–40 harness edits; today a hand-edited profile with
   `BLINDPASS_PROXY_REQUIRED=0` plus test mode still starts.
3. Temporary-password expiry (schema 20).
4. HSTS: ship one-year `max-age` in the examples or stage a short value first;
   `includeSubDomains` stays off.
5. Confirmation-code entropy (contract change).

## Update 2026-10-06 (workstream G2): rows S03–S05 on the shipped Compose profiles

The "Not run" item above (Compose release profile with a real nginx edge and Chromium network inspection) has now been
run for S03, S04 and S05 on both shipped profiles, SQLite and PostgreSQL: 73 of 73 checks each, against image
`blindpass-p07-controller:s06`, the shipped `nginx.conf.example` edge with TLS, and Chromium 152. Full record:
[p07-profile-browser-2026-10-06](p07-profile-browser-2026-10-06.md).

| Row | Now established | Still partial |
|---|---|---|
| S03 | Cookie attributes of `bp_session`, `bp_refresh` and `bp_csrf` after a real console sign-in; no credential in localStorage, sessionStorage or IndexedDB; CSRF refusal; cross-origin forgery fails; refresh rotation, replay (`401`) and whole-family revocation; sign-out invalidates server-side | Chromium only; the legacy dashboard `localStorage` token (F-8 on the legacy path) is a different path and was not run; idle (12 h) and absolute (7 day) lifetimes not waited out |
| S04 | Served CSP equals the documented policy on the console and the input page; HSTS exactly where documented (edge adds it, client-supplied forwarding headers do not change it, trusted-HTTP peer and untrusted peer get none); allowed API call works; fetch, XHR, WebSocket, image, script and form to a non-allowed origin blocked with recorded `securitypolicyviolation`; framing refused; no `Referer`; outbound requests all to the edge origins | nginx example only (Caddy not run); Firefox and Safari not run; legacy `ui` image rendered and `nginx -t` checked but not browsed |
| S05 | Distinct source addresses through the edge: per-(account, source) lock at 10 failures (`423`, `Retry-After: 900`), legitimate address unaffected, identical answers for unknown usernames, account-wide lock after spread guessing, per-address ceiling `429` after 30, packaged admin-socket `reset-password` clears the account's rows and forces the console change flow, bootstrap flood bounded with the valid token still accepted, paused-API sign-in ends in the console's 15 s timeout with no cookie, approval or session change | Docker bridge addresses, not internet distribution; timing oracle measured in-process only; 30 s ceiling, desktop app and MCP not driven against a paused controller; N-04 through the edge is status-sequence equality only |

No product defect was found; every failure during development was a harness defect (listed in the record). Hosted CI is
not run. Owner decisions listed above are unchanged.
