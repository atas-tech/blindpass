# P07 slice 2 execution: S03–S05 on the shipped Compose profiles with Chromium

**Date:** 2026-10-06. **Workstream:** G2. **Scope:** pilot S03, S04, S05, P07-I02 and P07-I03 on an actual
release profile: the shipped Compose files (SQLite and PostgreSQL profiles), the shipped nginx edge example
(`deploy/proxy/nginx.conf.example`) with real TLS, and real Chromium; plus `nginx -t` on the rendered configs and the
two Compose backup harnesses. Design and limits under test:
[operator auth and headers](../../security/operator-auth-and-headers.md); slice-2 gates:
[p07-auth-headers-2026-10-06](p07-auth-headers-2026-10-06.md).
**Status:** local execution evidence only. Not release evidence; P06 and P07 are not accepted; hosted CI not run.

Candidate under test: image `blindpass-p07-controller:s06` (id `dc891c85b8ff`, created 2026-10-06 19:48 +07). No file
under `crates/`, `packages/console/src`, `packages/browser-ui/src`, `packages/i18n`, `deploy/`, `Cargo.toml` or `Cargo.lock`
is newer than that build, so it contains the slice-2 changes. Edge: the shipped nginx example, unmodified except for the
upstream name and certificate paths, in the disposable helper image `blindpass-p06-edge:local`. The certificate is a
one-day self-signed fixture; Chromium trusts it only through an SPKI pin
(`--ignore-certificate-errors-spki-list`), and `--host-resolver-rules` maps `blindpass.example:443` and
`input.example:443` to the published edge port, so the page origin is exactly `https://blindpass.example`.

## Result

| Run | Profile | Checks | Result | Offline canary scan |
|---|---|---|---|---|
| `tests/deployment/p07-profile-browser.py --profile sqlite` | SQLite, remote-style PG authority, nginx edge | 73 | **73 passed, 0 failed** | PASS: 51 files, 4.9 MB (controller database, WAL and SHM included), 0 exposed, 0 incomplete |
| `tests/deployment/p07-profile-browser.py --profile postgres` | PostgreSQL, same edge | 73 | **73 passed, 0 failed** | PASS: 49 files, 267 KB (schema dump), 0 exposed, 0 incomplete |
| `tests/deployment/p07-nginx-config-check.py` | nginx syntax | 15 | 15 passed (includes a negative control that must fail) | n/a |
| `tests/deployment/compose-backup.py --faults` | SQLite backup | CB02–CB05 | all PASS | scans switched to the fail-closed helper |
| `tests/deployment/compose-backup-postgres.py` | PostgreSQL backup | PGC01–PGC05 | all PASS | scans switched to the fail-closed helper |

Per run: 47 browser checks (S03 21, S04 20, locked 2, forced-change 2, paused API 2) and 26 host-side checks
(bootstrap 5, HSTS and edge 6, lock shapes 10, paused-API state 2, canaries 3). The raw run directories are
`~/.cache/canary-scan-p07/runs/g2` and `g2-postgres` (outside the repository: they hold request lists and a database
copy). Sanitized per-run summaries (`results.json`, one summary per step, probe status lines, the offline scan text)
are committed under [`p07-profile-browser-2026-10-06/`](p07-profile-browser-2026-10-06/); they hold status codes,
header values, cookie attributes and SHA-256 prefixes, never a cookie or credential value. The committed files were
scanned with both runs' canary lists: 70 files, 0 exposed.

## What each pilot row now establishes

**S03 (sign-in, refresh, sign-out in the real console):**
- After a real console sign-in, `bp_session` is HttpOnly, Secure, SameSite=Strict, Path `/`, host-only on
  `blindpass.example` (about 12 h); `bp_refresh` is HttpOnly, Secure, SameSite=Strict, Path
  `/api/v3/admin/session/refresh`; `bp_csrf` is Secure, SameSite=Strict, Path `/` and script-readable (the double-submit
  value). Before sign-in no `bp_` cookie exists.
- `localStorage`, `sessionStorage` and IndexedDB hold nothing (no keys, no databases) and contain none of the
  operator password, session or refresh values; the rendered DOM holds none of them; the only script-readable cookie is
  `bp_csrf`. This is the browser-storage half of F-8/TM-003 on the selected path; the legacy dashboard is a different path.
- A state-changing call without the CSRF header, or with a wrong value, is refused (`403 csrf_denied`). A page on a
  third origin (`https://evil.example`, served through a Playwright route) cannot reach a response when it sends
  credentials and a CSRF value cross-origin (CORS and SameSite).
- Refresh rotates the credential (200, new value). Replaying the rotated-out refresh credential from a clean profile is
  `401`, and it revokes the whole family: the current session cookie then answers `401`.
- Sign-out in the console clears the three cookies in the browser, and the signed-out session and refresh values are
  refused by the server (`401`), so sign-out invalidates server-side, not only in the browser.
- No CSP violation during the journey; every request is same-origin.

**S04 (production CSP, headers, allowed and forbidden destinations):**
- The console and the input page are served by the shipped edge with exactly the documented CSP (`default-src 'none';
  script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';
  base-uri 'none'; form-action 'self'`), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy: same-origin`, `Cache-Control: no-store`, and
  `Strict-Transport-Security: max-age=31536000` with no `includeSubDomains` or `preload`. The served CSP has no
  localhost, wildcard, bare scheme or unsafe source.
- HSTS scope: sent by the edge on HTTPS responses; client-supplied `X-Forwarded-Proto: http` and `Forwarded` headers do
  not change it; an unknown `Host` is refused at the edge (`421`). Straight to the controller's internal port: a trusted
  peer that reports plain HTTP gets no HSTS, a trusted peer reporting HTTPS gets `max-age=31536000` (the edge hides and
  re-adds it), and an untrusted peer is refused `403` with no HSTS.
- Allowed same-origin API calls work (`/readyz` 200). A script in the page that tries `fetch`, XHR, WebSocket, an image
  beacon, a script element and a form post to a non-allowed origin fails on every channel, and a
  `securitypolicyviolation` is recorded for each (`connect-src`, `img-src`, `script-src-elem`, `form-action`); no request
  to that origin completed. Same result on the console and on the input page.
- No `Referer` header on a same-origin request (read from the wire view `request.allHeaders()`, not the stale
  `headers()` view).
- A page on another origin that embeds the console and the input page renders neither (`chrome-error://chromewebdata/`).
- The full outbound request list is `blindpass.example`, `input.example` and the blocked exfiltration target only.

**S05 (account controls, distributed guessing, recovery, bootstrap, slow API), through the edge:**
- Distinct sources are real: probe containers with distinct static addresses on the edge network (`172.29.86.0/24`, `.10` to `.71` used) reach the
  shipped nginx, which writes `X-Forwarded-For $remote_addr`; the controller then held 7 separate per-address failure
  rows and 6 separate per-(account, source) rows. One address failing 12 times produced one address row and one
  pair-lock row and nothing for the legitimate address.
- One address: `401` x10, then `423` with `Retry-After: 900` (the lock starts at the 11th attempt). A legitimate
  sign-in from another address succeeds while that pair is locked (`200`). An unknown username returns the identical
  status sequence (`401` x10, `423` x2): no `423`-versus-`401` oracle in status codes.
- Guessing spread over six addresses (10 failures each) locks the account for every source: the sixth address and the
  legitimate address both get `423`. The real console shows the lock notice ("This account is locked after too many
  failed sign-ins. Try again in about 15 min") and stays on the login page.
- Recovery through the packaged admin socket (`docker compose exec controller blindpass admin reset-password`) issues a
  temporary password and removes every limiter row of that account (rows of an unrelated, unknown account remain, as
  designed); the previously locked attacker address then gets `401` again. The temporary password then forces the real
  change flow in the console (a temporary-password session is blocked from admin routes with `403
  password_change_required`; the change completes and the console is usable).
- Per-address ceiling: one address guessing 33 different usernames gets `401` x30 then `429`; another address is
  unaffected.
- Bootstrap flood (fresh controller, no administrator): eleven addresses sending wrong tokens each get `409` x10 then
  `429`; once the global budget (100 failures per 15 min) is spent the tenth address is `429` from its second attempt and
  the eleventh from its first, and a fresh address is `429` on its first wrong token; limiter rows stay at 13 (bound 257), and the **valid** token from yet another address still creates the operator (`201`). The used token's
  row is marked used and a second bootstrap is never `200`.
- Paused API: with the controller container paused (`docker pause`), a console sign-in ends in the console's
  bounded timeout after 15.1 s (SQLite) and 15.3 s (PostgreSQL) with the message "Sign-in didn't complete. Try again.",
  no session or refresh cookie (only the pre-session CSRF value), the page still on the login form, no approval row
  changed (0 and 0 before and after) and no session row created in the 6 s after unpause (7 and 7). The console's own 15 s default
  total timeout ended it, inside the 30 s bound.

**P07-I03 (production CSP and verified HTTPS scope):** the CSP, HSTS scope, framing, referrer and forbidden-destination
checks above were taken from the shipped edge over TLS, not from a dev server.

## Red first versus written after

None of this harness was red first against a product defect: the controller changes under test were already built
and the harness characterizes them. Every failure during development was a defect in the harness itself, found by
running it:

1. An unknown-`Host` probe used the wrong SNI, so TLS verification failed before the edge answered (fixed: SNI stays
   `blindpass.example`, only the `Host` header changes).
2. The temporary directory could not be removed because Docker had chowned the config directory to uid 10001
   (fixed: chown back before cleanup; the leftover `/tmp/blindpass-p07-*` directory was recovered and removed).
3. The `Referer` check read `request.headers()`, which is not the wire view (fixed: `request.allHeaders()`).
4. The reset-password row check counted limiter rows of an unrelated unknown account that an earlier probe created
   (fixed: the account key is derived and only that account's rows count).
5. The paused-API check treated the pre-session `bp_csrf` cookie as a session credential (fixed: only `bp_session` and
   `bp_refresh` count).
6. The per-(account, source) count looked at failure rows only, but a pair's counter becomes a lock row at the limit
   (fixed: both families).
7. The offline scanner rejected an empty `edge.log` (it fails closed on empty logs on purpose); the empty log is by
   design (`access_log off; error_log /dev/null crit`), so the harness now asserts that configuration and records the
   reason as a note instead of an empty file.
8. The first database export copied only the main SQLite file; the newest rows live in the WAL (fixed: copy the
   database, `-wal` and `-shm` together; the PostgreSQL profile scans a text dump of the `controller` schema).

The checks can fail: items 1, 3, 4 and 5 were real failures of the harness before they were corrected. No mutation of
the product was run against this harness. The offline scanner was shown to see real artifacts of this run: a 27-byte
value taken from `compose.log` was reported (`FAIL_EXPOSED`, offset 30), and the real canaries gave `PASS`.

The backup harness edits (below) were not red first either; the helper they call is covered by
`canary_log_scan_test.py` (26 tests, unchanged and passing).

## nginx syntax (P07-D6)

`tests/deployment/p07-nginx-config-check.py` runs `nginx -t` in a disposable container on: the legacy `ui` image config
rendered by `render-nginx-conf.mjs` for a reviewed HTTPS origin and for same-origin (both pass and carry exactly the
expected `connect-src`), the shipped edge example with the profile paths (passes), and a deliberately broken config
(must fail, and does). The renderer also refuses a loopback, plain-http, wildcard, userinfo and path origin without echoing
it. Limit: the nginx is the helper image's Debian build, not the runtime image's `nginx:1.29-alpine` (not present on this
host), so this is a syntax result only. The rendered legacy image was **not** run in a browser.

## Compose backup harnesses

`compose-backup.py` and `compose-backup-postgres.py` were the last P06 harnesses on the fail-open scan shape
(`secret in text`). Their five log scans now call `tests/deployment/canary_log_scan.py` (fail on an empty or short
capture, require expected content, positive control, canaries only by hash prefix in a failure). Edits: one import and
five scan lines, nothing else. Both ran after the edit against `blindpass-p07-controller:s06`: SQLite with `--faults`
passed CB02, CB03, CB04 and the three CB05 ENOSPC phases (this is also the first run of B's fixture change
`BLINDPASS_PROXY_REQUIRED` `"1"` to `"0"`), and PostgreSQL passed PGC01–PGC05.

## Not run, and what stays partial

- **Hosted CI:** not run. The harnesses need Docker and Chromium and are manual (`python3 tests/deployment/p07-profile-browser.py --profile sqlite|postgres`, one at a time).
- **Real deployment:** no public DNS, no publicly trusted certificate, no real client networks. Source addresses are
  Docker bridge addresses behind a trusted edge; the `X-Forwarded-For` trust chain is the shipped one, but internet-scale
  distribution is not exercised (five attacker addresses reach the account-wide lock, as the limits document says).
- **Browsers:** Chromium 152 only. Firefox and Safari behaviour (cookies, CSP reporting, framing) is not run.
- **Edge:** the nginx example only. The shipped Caddy example was not run in a browser for this slice.
- **Timeouts:** the console's 15 s default was measured; the 30 s clamp was not exercised at its ceiling through the
  edge, and the desktop approval app and MCP server were not driven against a paused controller (the QML timeout has a
  unit test only).
- **Timing oracle (N-04):** the status sequences are identical for known and unknown usernames; the Argon2 timing
  equalisation was measured in-process by workstream B, not through the edge.
- **Lifetimes:** the 12 h idle limit and the 7-day absolute session lifetime were not waited out; they have unit tests.
- **Legacy paths:** the legacy dashboard, SPS and the legacy `ui` image were not browsed.
- **Observation, not a defect:** once the global bootstrap budget (100 failures per 15 min) is spent, a mistyped token is
  also `429` until the window ends; the exact valid token still works. That matches the documented design and keeps the
  valid token from being burned, but an operator who mistypes during an attack waits out the window.
- **Product defects found:** none. (Open owner choices are unchanged: the HSTS `max-age` staging, temporary-password
  expiry, the stricter test-mode rule.)

## Reproduce

```sh
python3 tests/deployment/p07-profile-browser.py --profile sqlite      # image blindpass-p07-controller:s06 by default
python3 tests/deployment/p07-profile-browser.py --profile postgres
python3 tests/deployment/p07-nginx-config-check.py
python3 tests/deployment/compose-backup.py --image blindpass-p07-controller:s06 --faults
python3 tests/deployment/compose-backup-postgres.py --image blindpass-p07-controller:s06
```

Files: `tests/deployment/p07-profile-browser.py` (orchestrator), `p07-profile-browser.mjs` (Chromium steps),
`p07-probe.py` (distinct-address probe), `p07-nginx-config-check.py`; edited `compose-backup.py` and
`compose-backup-postgres.py` (scan lines).
