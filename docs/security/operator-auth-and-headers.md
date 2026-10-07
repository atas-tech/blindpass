# Operator sign-in limits, session lifetime, bootstrap and browser headers

P07 slice 2 (P07-D4, P07-D6). This page states what the Rust controller does
today and where the limits are. The two-counter sign-in design below was
**confirmed by the owner on 2026-10-06**; the plan's default was one account
bucket, and this page records why the applied shape differs. Temporary-password
expiry and the stricter test-mode rule were **deferred by the owner** on the
same date and stay listed as known limitations. Test evidence and its limits:
[p07-auth-headers-2026-10-06](../testing/evidence/p07-auth-headers-2026-10-06.md).

## Sign-in limits (S05)

Every limit counts **failures only**; a successful sign-in never spends budget
and clears the account's counters. Values are configuration and are published
in `GET /api/v3/capabilities` under `limits.login`.

| Setting | Default (range) | Meaning |
|---|---|---|
| `BLINDPASS_LOGIN_ACCOUNT_FAILURES` | 10 (1–100,000) | Failures for one account **from one source address** inside the window before that account/source pair locks |
| `BLINDPASS_LOGIN_ACCOUNT_TOTAL_FAILURES` | 50 (1–1,000,000, at least the previous) | Failures for one account from **all** addresses inside the window before the account locks for everyone |
| `BLINDPASS_LOGIN_IP_FAILURES` | 30 (1–100,000) | Failures from one client address, across all usernames, before sign-in answers 429 |
| `BLINDPASS_LOGIN_WINDOW_SECONDS` | 900 (1–86,400) | Failure counting window |
| `BLINDPASS_LOGIN_LOCKOUT_SECONDS` | 900 (1–86,400) | How long a lock lasts |
| `BLINDPASS_LOGIN_TRACKED_ACCOUNTS` | 10,000 (16–1,000,000) | Cap on live pair rows for usernames that do not exist (state bound, not published) |

Answers: a locked account or pair is `423 {"error":"locked","message":…,"retry_after":N}`
with `Retry-After`, even for the right password. A spent address budget is
`429 login_rate_limited`. The address budget answers first, so a blocked
address learns nothing about which accounts are locked. Browser and desktop
sign-in share the same counters.

Why two account counters: one bucket per account lets anyone who can reach the
login route lock a named operator out from a single address without guessing a
password (finding N-02). With the pair counter that guesser locks only its own
address; the operator signs in from elsewhere. The account-wide total still
stops guessing spread over many addresses; reaching it locks the account for
everyone until the lock lapses or an administrator resets the password.

Residual risks, stated plainly:

- An attacker with at least `ceil(total / per-pair)` addresses can still lock an
  account for everyone for the lockout period. Recovery is the reset below.
- Operators behind one shared address (a NAT) share a pair counter with an
  attacker behind it.
- Concurrent attempts can overshoot a limit by at most the number of password
  hashing slots (4) minus one, because the lock is written after verification.
- The controller hashes at most four passwords at once; a flood of
  attempts can make sign-in answer `429 login_busy` to other clients until it
  ends. A source already over its failure budget is refused before it takes a
  slot.
- Unknown usernames lock exactly like real ones (no 423-versus-401 oracle) and
  cost the same Argon2 work (no timing oracle; measured before the fix:
  unknown 4.5 ms against 402 ms for a real operator on a debug build).
  Above the `TRACKED_ACCOUNTS` cap unknown names stop being tracked while real
  operators always are, so a flood of invented names cannot unlock a real one;
  that degrade can reveal that a name is unknown. Usernames are low-secrecy in
  a single-tenant controller.

### Recovering a locked account

There is no unlock without changing the password, by design: an unlock that
does not rotate the credential would let a guesser continue.

```sh
sudo -u blindpass blindpass admin reset-password <username-or-id>   # local admin socket
sudo -u blindpass blindpass admin operators list                    # ids, usernames, roles, lock state
```

The argument is the username as the console shows it (any letter case, surrounding whitespace ignored) or the
operator id. A one-administrator install has no other operator to ask, so this command is its recovery path.

An administrator can use the console's reset for another operator. Either
way the reset clears every counter and lock for that account, revokes its
sessions and sets a temporary password that must be changed at next sign-in.
The failure windows are also cleared when the controller fences after a host
restart with a changed boot identity or runs `reconcile-clock`, so those paths
clear locks too; do not treat a restart as an unlock. A restored backup carries
whatever window rows were in it.

## Session lifetime

Idle limit 12 hours. A session's **absolute lifetime** is
`BLINDPASS_SESSION_ABSOLUTE_SECONDS` (default 604,800 = 7 days; 3,600–2,592,000)
from sign-in, however often it refreshes: sign-in and every rotation cap the new
row's expiry at the family's first sign-in plus that lifetime, and a refresh
past it revokes the family. Published as `limits.session`. The desktop approval
app uses the same family rule (its access token still lives 20 minutes).
Before this change a refresh restarted a 30-day TTL each time (finding N-05).

**Not done:** temporary-password expiry. A temporary password (bootstrap through
the admin socket, reset) stays valid until used. It needs a timestamp column
(schema 20), which touches upgrade, backup and the authority layouts; it needs
an owner decision before it is built.

## Stored verifiers (S02)

Bootstrap tokens, browser session and refresh cookies and desktop access and
refresh tokens are stored as SHA-256 digests, operator passwords as Argon2
hashes; a refused or replayed credential is answered without echoing it.
One exception: the double-submit CSRF value (`csrf_secret`) is stored as issued
because the session read returns it, so a database reader learns CSRF values
but not a usable session (the session identifier is a digest). It never equals a
bearer secret. Hashing it would need the session read to stop returning it.

## Bootstrap

`blindpass admin bootstrap-token` (admin socket) issues a 256-bit token valid
15 minutes and single use; issuing another **invalidates every earlier unused
token**, which is the recovery from an exposed token. The token is the whole
capability and is stored as SHA-256; there is no public identifier, so a wrong
guess reads one row and changes nothing and cannot burn or block a valid token.
`POST /api/v3/admin/bootstrap` checks the token **before** any password work,
then hashes on the same four bounded slots (`429 bootstrap_busy` when full). An
unusable token spends a failure budget: `BLINDPASS_BOOTSTRAP_FAILURES_PER_PEER`
(10 per 15 min, per one of 256 peer shards) and
`BLINDPASS_BOOTSTRAP_FAILURES_GLOBAL` (100 per 15 min), then
`429 bootstrap_rate_limited` with `Retry-After`. Rows are bounded at 257. A
request holding the valid token is never refused for what others did. Once an
administrator exists no token can be issued and every bootstrap answers 409.

## Test mode is refused on a production profile

`BLINDPASS_TEST_MODE=1` removes the ownership requirement, mounts the seed route
and trusts loopback `X-Forwarded-For`. Every shipped native, image and Compose
profile sets `BLINDPASS_PROXY_REQUIRED=1` and none sets `NODE_ENV`, so the
controller now refuses test mode when `BLINDPASS_PROXY_REQUIRED=1` or
`NODE_ENV=production`, and every `BLINDPASS_TEST_*` override without test mode.
`blindpass-controller check-config` prints a warning when test mode is on. The
list of test flags is read from the source by `tests/production_flags.rs`, so a
new flag cannot ship untested. Open: a hand-edited profile with
`BLINDPASS_PROXY_REQUIRED=0` and test mode still starts (the plan's
stricter "production unless an explicit non-production marker" would need
every fixture harness to set one; recorded as an owner decision).

## Browser headers and HSTS scope (S04)

| Response | Headers |
|---|---|
| Console and input HTML, embedded | `Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`, `X-Frame-Options: DENY`, `Cross-Origin-Opener-Policy: same-origin`, `Permissions-Policy`, `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`, `Cache-Control: no-store` |
| Every other controller response | `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store` unless a route sets its own |
| Cross-origin access | none by default, not even for the UI origin; `BLINDPASS_CORS_ALLOWED_ORIGINS` names exact origins (a separately hosted compatibility input) |

HSTS (`max-age=31536000`, no `includeSubDomains`, no `preload`) is sent only
where the connection is known to be HTTPS: by the TLS terminator (the nginx and
Caddy examples add it on every response and strip an upstream copy), by the
controller behind a trusted edge that passes the reviewed forwarding headers, or
by the controller's built-in TLS. A plain-HTTP profile never emits it, and a
client's `X-Forwarded-Proto` does not make it. Do not add `includeSubDomains`
until every subdomain of the host serves HTTPS and you control them; a one-year
`max-age` on first deployment is hard to take back, so stage it (a short value
first) if HTTPS readiness for the hostname is not yet proven. The staged value is
an operator choice the shipped examples do not make for you.

The legacy separately hosted input image (`packages/browser-ui/Dockerfile`) renders its `connect-src` from the
`VITE_SPS_API_URL` it was built for (`packages/browser-ui/scripts/render-nginx-conf.mjs`);
a loopback, plain-http, wildcard or path-bearing origin fails the build unless
`BLINDPASS_UI_DEV_IMAGE=1`. The workflow that published it, `build-and-push-images.yml`, was removed on
2026-10-07, and the hosted dashboard image went with the SPS stack; the only workflow that builds this image now is
`ci-full.yml`, for a browser CSP check. `scripts/release/check-bundles-for-localhost.sh`
fails a release whose built bundles or rendered config name a loopback
origin, a bare-scheme or `*` CSP source or `unsafe-eval`, and fails closed on a
missing directory or an empty scan.

## Client timeouts

Bound: 10 s connect, 30 s total. Console: one 15 s total by default, clamped to
30 s however a caller asks (browsers expose no separate connect timeout).
Desktop approval app: curl `connect-timeout = 5`, `max-time = 15`. MCP server:
no HTTP client; broker calls run on a Unix socket under a call budget that the
package refuses above 25 s. A timeout is reported as an unknown outcome and is
never an approval.
