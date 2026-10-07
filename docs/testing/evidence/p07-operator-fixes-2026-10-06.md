# P07 slice 7 evidence: operator-path fixes from the cold-operator dry run (workstream H1)

**Date:** 2026-10-06
**Scope:** defects found by the unfamiliar-operator dry run
(`docs/testing/evidence/p07-dryrun-env-2026-10-06.md`, notes in the maintainer's
`~/.cache/p07-dryrun/cold-operator-notes.md`, steps 19, 28, 30, 31, 36, 37), plus the
P07-E03 rollback rehearsal.
**Status:** H1 STOPPED EARLY at the coordinator's usage-limit instruction (its text is kept below). **H3 continued the
same day** and finished items 1 to 3; corrections to H1's text are marked **[H3]**, and item 4 has its own record,
[p07-rollback-2026-10-06](p07-rollback-2026-10-06.md) (P07-E03 **not passed**). Status words are literal: **Done** = the
command ran in this working tree and the result is quoted; **Not run** = no result exists. Nothing is committed or pushed.

## Findings addressed

| # | Dry-run finding | State |
|---|---|---|
| 1 | `blindpass admin reset-password` needs a UUID the console never shows; a username gives `operator_not_found`; no way to list operators; a locked sole administrator cannot recover | **Done and green on SQLite and PostgreSQL** ([H3 gates](#h3-continuation)). |
| 2 | `backup verify` fails with "invalid backup options" / "unsafe backup input" naming no option, rule or path | **Done and green.** **[H3]** The native VM harness then found a regression in H1's early credential check (it refused systemd service credentials); fixed and re-run on both guests and on Compose ([details](#h3-continuation)). |
| 3 | `install.sh --start` prints `ok: true`, exit 0, for a service that exits a second later (`startup_failed`, `reason: fenced`); docs claim a "diagnostic process" the operator never saw | **Built by H3.** H1's reading of the behaviour was incomplete (see the correction under item 3); `--start` now waits a bounded time and refuses an exited or never-ready service. |
| 4 | P07-E03 rollback rehearsal | **Rehearsed by H3 on Ubuntu 24.04 and Debian 12 guests: NOT PASSED** (the previous program version cannot be put back with the shipped installer). See [the record](p07-rollback-2026-10-06.md). |

### 1. Operator reference and listing (done)

- `crates/blindpass-controller/src/admin_socket.rs`: `reset-password` takes `id` (or `operator`) and resolves it after
  trimming: operator id first, then the exact username, then a case-insensitive username that matches exactly one
  operator. Distinct errors: `operator_not_found`, `operator_ambiguous` (two operators differ only by case; usernames are
  unique case-sensitively, so this can happen), `operator_disabled` (was reported as not-found), `invalid_operator_id`
  (characters no id or username can contain; checked before any lookup). New `operators-list` command returns id,
  username, display name, role, disabled, must_change_password, `account_locked_seconds` and `source_locks`; it never
  returns a hash, session or token.
- `crates/blindpass-controller/src/store/login_limits.rs` + `store/mod.rs`: read-only `Store::operator_lock_state`
  (SQLite and PostgreSQL branches, same pattern as the neighbouring queries).
- `crates/blindpass-cli/src/main.rs`: `reset-password <OPERATOR>` (help says username or id), new
  `blindpass admin operators list [--json] [--socket]` (table with ID, USERNAME, ROLE, STATE, or raw JSON), and
  `explain_admin_error`: the four operator-reference codes print guidance that says a username is accepted and points at
  `operators list`; it never echoes what the operator typed; every other error code is unchanged. The socket field name
  stays `id` for wire compatibility.
- Tests: `crates/blindpass-controller/tests/admin_operators_socket.rs` AO01-AO05, over the real admin socket in the exact
  request shape the CLI sends. AO05 is the dry-run case: the only administrator is locked account-wide by 50 failures
  from distinct addresses, the right password is refused with `423` and `Retry-After`, `reset-password` by upper-cased
  username clears it, the temporary password signs in, every other admin route answers `403 password_change_required`,
  and the forced change-password call succeeds. CLI tests in `crates/blindpass-cli/tests/migrate.rs`: two new, one
  changed (help now asserts `<OPERATOR>` and the word username), fixture server made to time out instead of hanging.

### 2. Named backup refusals (done)

- `crates/blindpass-controller/src/backup.rs::run_command` now refuses with text that names the option and the rule,
  built from per-option static strings (a macro), never from a path or value:
  an odd argument list ("every option needs a value"), a relative path ("--archive must be an absolute path"), a repeated
  option, an unknown option (not echoed), a wrong option set (each command lists what it needs), a malformed
  `--expected-archive-sha256` (now distinct from a digest mismatch) and a bad `--role`. For `verify` and `create` it then
  runs the same checks `private_input` applies later but names the option: directory not owned by the current user with
  mode 0700, missing file, not a regular file, more than one link or a different owner than its directory, group or world
  access (mode 0600 or 0400), empty, too large; `--work-directory` must be an existing 0700 directory (verify and
  cleanup). The checks only run earlier; they accept nothing the later checks would refuse.
- Credential options keep the long-standing prefix `unsafe backup recovery credential:` because
  `tests/deployment/compose-backup.py` (CB03) asserts that text; `--archive` and `--work-directory` use
  `unsafe backup input:`.
- **[H3 correction]** The sentence above, "the checks only run earlier; they accept nothing the later checks would refuse", was true
  in one direction only. For **credential** options the early check also **refused** what the real reader (`read_private_file`)
  accepts: it demanded a 0700, owner-private directory, but a systemd service credential (root-owned 0440 with an exact named-user
  ACL, as the packaged backup unit delivers it) lives in the unit's credential directory. The native VM stage B08 failed on it:
  `unsafe backup recovery credential: --signing-credential-file is in a directory that is not owned by the current user with mode
  0700`. Fix (`backup.rs::check_credential_option`): credential, certificate and key options ask `read_private_file` first and are
  accepted whenever it accepts them (an empty file is still refused by name); only a refusal is classified, by option and rule, never
  by path. The archive keeps the private-directory rule. BO05 now covers the archive only; BO05b asserts that a 0600 and a 0400
  credential in a 0755 directory are not refused for their directory and that a 0640 one still is. BO05b was written **after** the
  fix and was not observed red (the service-credential case needs root-owned files); the red evidence is the VM B08 failure above.
- Not changed: `OpenArgs`/`SealArgs` (restore and handoff) still answer the generic "invalid backup options", and
  internal staged-file checks (`private_input`) keep their generic text.
- Tests: `crates/blindpass-controller/tests/backup_option_errors.rs` BO01-BO08, run through the real
  `blindpass-controller backup ...` binary.

### 3. `install.sh --start` (investigated by H1, built by H3)

What the code does, read from `deploy/native/controller-install.py`, `deploy/native/blindpass-controller.service`,
`crates/blindpass-controller/src/main.rs::serve` and `ownership_session.rs::claim_ownership`, and matching the dry-run
observations (steps 19, 28, 36):

- `--start` runs `systemctl enable --now blindpass-controller.service` and then prints the summary. The unit is
  `Type=exec`, so `systemctl` returns as soon as the process has been exec'd. The summary says `ok: true` regardless of
  what the process does next.
- With an authority, `serve` calls `claim_ownership` before it binds a listener or the admin socket. Without a live
  activation (never granted, or the previous revision already consumed by an earlier start) the claim fails and the
  process exits non-zero with `{"event":"startup_failed","reason":"fenced"}`. There is **no diagnostic HTTP process**
  in this case: no listener at all. The "diagnostic readiness 503 / health 200" behaviour belongs to a controller that is
  running and has `recovery_required` (restored or clock-fenced state), not to an unactivated start.
- The unit has `Restart=no`, so a plain `systemctl restart`, a reinstall of retained state followed by `--start`, and a
  container restart all end in the same `fenced` exit until a fresh `authority-activate.sql` is run.

**[H3 correction]** The second bullet is wrong for one of the two real cases. A record that was **never activated** (fenced) is
not refused at startup: `claim_process` accepts the phases `fenced` and `recovering`, so the controller **does** run, as a diagnostic
process (`/healthz` 200, `/readyz` 503 `recovery_required`) and keeps running. Only an already-**consumed** activation (or another
holder) exits with `startup_failed` `{"reason":"fenced"}` before any listener. The first native VM run failed at N02 ("command
unexpectedly accepted") because the harness, like H1, assumed the exit. Both cases are now handled and documented (native
quickstart step 5, `docs/deploy/README.md`).

Built by H3 in `deploy/native/controller-install.py`: `--start` runs `systemctl enable --now`, then polls `systemctl show`
(`ActiveState`, `Result`, `InvocationID`) and the loopback `/healthz` and `/readyz` (the port from `BLINDPASS_LISTEN`, forced to
loopback; HTTPS when the TLS drop-in is installed) for `--start-timeout` seconds (default 20, 1 to 300). It succeeds only when the
unit is active **and** `/readyz` answers 200 and prints `{"ok": true, "started": true, "ready": true, ...}`. On `failed` or
`inactive` it refuses, exit 1, with the reason read from **that invocation's** journal (`_SYSTEMD_INVOCATION_ID`; only a
`[a-z_]{1,48}` reason is accepted, anything else is not echoed) and, for `fenced`, the next step (`authority-activate.sql`). On a
running controller that never becomes ready it refuses with `running but not ready` and the sanitized readiness reason. The install
itself is reported completed (`"installed": true`) either way. Tests: `tests/deployment/native-start-test.py` (11 tests with a fake
`systemctl`/`journalctl`/prober/clock) and, on real guests, N02 (never-activated: unready refusal), N05b (NS1 to NS4: plain restart
exits fenced one second after `systemctl` returned, `--start` refuses it, an activated `--start` reports started and ready, a second
`--start` is idempotent) and the post-activation restart. Red evidence: the first guest run of the old harness, N02, as above; the unit
tests were written alongside the function and their first failing run was not separately recorded.

Original H1 design note, superseded: after `systemctl enable --now`, poll
`systemctl show -p ActiveState,SubState,Result` and the loopback `/healthz` (the installer always writes
`BLINDPASS_LISTEN=127.0.0.1:3200`; HTTPS when the built-in TLS drop-in is installed) for a bounded time; on `failed` or
`inactive`, refuse with exit 1 and the fixed vocabulary reason from the last `startup_failed` journal event (only a
`[a-z_]{1,48}` reason is extracted), plus the hint that every start needs an activation when the reason is `fenced`;
report `ok: true` only when the unit is active and `/healthz` answers, and add a separate `ready` field from `/readyz`.
A test needs either an injectable `systemctl` runner in the Python installer or the native VM harness
(`tests/deployment/native-install.sh`); neither was written.

### 4. P07-E03 rollback rehearsal

**[H3]** Run; see [p07-rollback-2026-10-06](p07-rollback-2026-10-06.md). Result: **not passed**; nine of ten required observations
were made on both guests, and the native installer cannot restore the previous program version.

## Red first versus written after

- **Red first, then green:** AO01-AO05 (5 of 5 failed on the old code: usernames gave `operator_not_found`, there was no
  `operators-list`); the two new CLI tests and the changed help assertion (failed or hung on the old CLI); BO01-BO07
  (7 of 7 failed on the old messages).
- **Characterization (passed on the old code, so they prove nothing about a defect):** BO08 (refusals never echo
  paths or credential text), which now also guards the new messages.

## Gates

Run in this working tree, which also holds other workstreams' uncommitted changes:

| Command | Result |
|---|---|
| `cargo test -p blindpass-controller --test admin_operators_socket --locked` | 5 passed, 0 failed (SQLite) |
| `cargo test -p blindpass-cli --test migrate --locked` | 8 passed, 0 failed |
| `cargo test -p blindpass-controller --test backup_option_errors --locked` | 8 passed, 0 failed |
| `cargo test -p blindpass-controller --lib --locked admin_socket` | 3 passed, 0 failed (36 filtered out) |
| `cargo test -p blindpass-controller --test login_limits --locked` | 15 passed, 0 failed (unchanged suite, SQLite) |
| `cargo fmt --all -- --check` | exit 0 |
| `cargo clippy -p blindpass-controller -p blindpass-cli --all-targets --locked -- -D warnings` | exit 0 (after fixing one `collapsible_if` in `backup.rs`) |

## Not run (H1's list at the time it stopped; superseded by the H3 continuation below)

- **PostgreSQL variants** of `admin_operators_socket` (`P02_TEST_BACKEND=postgres`) and `login_limits`. The new store method
  has a PostgreSQL branch that has never executed.
- **Full workspace** `cargo test --workspace --locked --no-fail-fast`, workspace-wide clippy (only the two edited crates
  were checked), `npm run build`, `npm test`.
- **Native VM runs** (Debian 12, Ubuntu 24.04), including `tests/deployment/native-install.sh`, which runs `backup
  verify` in a guest, and `tests/deployment/compose-backup.py` (CB03 asserts the credential wording this change kept).
  The new refusals were never exercised by those harnesses.
- Item 3's fix, item 4's rehearsal, and any real operator walk-through of the new messages.

## Doc changes for H2 (H1's list; **synced by H3**, see the continuation for what changed from it)

All of these describe behaviour that exists in the tree now, except where marked **(not built)**.

1. **Lockout recovery (native quickstart, Compose quickstart, `docs/security/operator-auth-and-headers.md` around line 65,
   the finding-disposition text if it repeats it).** Replace `blindpass admin reset-password <operator-id>` with
   `blindpass admin reset-password <username-or-id>`: the argument is the username as the console shows it (any letter
   case, surrounding whitespace ignored) or the operator id. It clears every sign-in lock for the account, revokes its
   sessions, prints a temporary password and forces a password change at next sign-in. Errors are
   `operator_not_found` (also for an operator that does not exist), `operator_ambiguous` (two operators differ only by
   case: use the id), `operator_disabled` (reset applies to enabled operators only) and `invalid_operator_id`.
   Add `blindpass admin operators list [--json]` (id, username, role, state including `locked <N>s` and
   `<N> source(s) locked`), run as the service user or root against the admin socket like the other admin commands. In a
   one-administrator install say the CLI is the recovery; "ask an administrator" is impossible there.
2. **Backup verification (both quickstarts and the offline-verification step).** `blindpass backup verify` needs absolute
   paths; the directory holding `--archive`, `--recipient-key-file` and `--signing-certificate-file` must be owned by the
   user running the command with mode 0700; each of those files must be a regular file with one link, owned by that user,
   mode 0600 or 0400, non-empty; `--work-directory` must already exist with mode 0700; `--expected-archive-sha256` is
   64 lowercase hex characters (a malformed value is now a distinct refusal from a mismatch). The refusals name the option
   and the rule and never print a path.
3. **Start and restart semantics (native quickstart, Compose quickstart, `docs/deploy/controller-ingress.md`).**
   Correct "A start without an activation runs as a diagnostic process and never becomes ready": it exits with
   `{"event":"startup_failed","reason":"fenced"}` and opens no listener. The diagnostic readiness behaviour applies only
   to a running controller in `recovery_required`. Every start of the authority-backed controller consumes one activation
   revision, the unit has `Restart=no`, and so `systemctl restart`, a container restart and a reinstall of retained
   state each need a fresh `authority-activate.sql` first. State that `install.sh --start` currently returns once
   systemd has exec'd the process and prints `ok: true` even if the service then exits, so the operator must check
   `systemctl status blindpass-controller` and `/readyz` afterwards **(a bounded wait with a non-zero exit is designed but
   not built)**.
4. **Uninstall/reinstall snippet.** Add the activation step before `install.sh --start`, and say the backup timer stays
   disabled after a reinstall of retained state and must be re-enabled by the operator.

## Owner decisions (H1's list; answered in the continuation)

- Build the `--start` readiness wait as designed above, or accept the documentation-only mitigation for the pilot.
- Whether restore and handoff (`OpenArgs`/`SealArgs`) should get the same named refusals; they were left generic.
- Re-run the Compose backup harness and the native VM matrix on this change before relying on it.

## H3 continuation

**Date:** 2026-10-06, same working tree (uncommitted, unpushed). Archive under test sha256
`1e94f20d27764b82fbda3c74c11fd400f24939078e7edd1e3bb68c8790c9c123` (built from the working tree after the fixes below, bookworm
baseline). Logs are kept outside the repository in `~/.cache/p07-h3/`.

### Changes made

- `crates/blindpass-controller/src/backup.rs`: `check_credential_option` (the regression fix above). `tests/backup_option_errors.rs`: BO05
  narrowed to the archive, BO05b added, fixture helper replaces an existing read-only file.
- `deploy/native/controller-install.py`: the bounded `--start` wait and `--start-timeout` (item 3).
- Tests: `tests/deployment/native-start-test.py` (new, 11), `tests/deployment/native-guest.py` (N02 asserts the unready refusal, new N05b,
  stage `after-reboot-rollback`), `tests/deployment/native-node-guest.py` (the same N02 change), `tests/deployment/native_rollback.py` (new)
  and `tests/deployment/native-install.sh --rollback`; `native-start-test.py` is now run by `.github/workflows/ci.yml` with the other
  deployment unit tests.
- Docs: `docs/deploy/native-quickstart.md` (step 5; backup-verify input rules), `docs/deploy/compose-quickstart.md` (backup-verify input
  rules), `docs/deploy/README.md` (`--start` comment), `docs/deploy/upgrade.md`, `docs/security/operator-auth-and-headers.md` (reset-password
  by username or id, `operators list`), `docs/release/rollback.md`, `docs/release/known-limitations.md`, `docs/testing/README.md`.
  From H1's "Doc changes for H2": item 1 (lockout recovery) done everywhere it appeared; item 2 (backup verify) done with the
  corrected rules (**credential files need not sit in a private directory; only the archive and the work directory do**); item 3 (start
  semantics) done with the two-case truth, and the "designed but not built" remark no longer applies; item 4 (reinstall snippet) was
  already in the native quickstart.

### Gates run (all in this working tree)

| Command | Result |
|---|---|
| `cargo fmt --all -- --check` | exit 0 |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | exit 0 |
| `cargo test --workspace --locked --no-fail-fast` (run alone, SQLite backend) | 94 result lines: **832 passed, 0 failed, 151 ignored**. The 151 ignored are the PostgreSQL authority, toolkit and disposable-database suites (reasons printed by each test); they were **not** executed here |
| `P02_TEST_BACKEND=postgres P02_TEST_POSTGRES_URL=... cargo test -p blindpass-controller --locked --test admin_operators_socket --test login_limits` | `admin_operators_socket` 5 passed, `login_limits` 15 passed, 0 failed (PostgreSQL 16 fixture container, `blindpass-postgres`, 127.0.0.1:5433) |
| `cargo test -p blindpass-controller --test backup_option_errors` | 9 passed (BO01 to BO08, BO05b) |
| `python3 tests/deployment/native-start-test.py` | 11 passed |
| `python3 tests/deployment/native-package-test.py`, `release-artifacts-test.py` | 7 and 11 passed (the controller-archive documentation closure, including `rollback.md`, is in the latter) |
| `node --test scripts/tests/release-docs.test.mjs` | 4 passed |
| `npm run test:exposure` | OK: scanner 6 tests, core-limit audit 20 units and 10 Compose files, canary-log-scan 26 tests |
| `git diff --check` | exit 0 |
| Relative links and anchors in every doc touched | all resolve, except two links in `docs/testing/README.md` (`Controller%20Contract%20Suite.md`, `Manual%20Demos.md`) that are in `HEAD` too and not from this work |

### Real-host and container harness reruns (the backup credential fix and the `--start` change)

| Command | Result |
|---|---|
| `tests/deployment/native-install.sh --os ubuntu-24.04 --archive ARCHIVE` | exit 0: N01, N02, N03, N04 (restart, reboot), N05, **N05b**, N06, N07, **B08**, N08, N10, N09 all PASS; kernel 6.8.0-139-generic, systemd 255.4-1ubuntu8.17 |
| `tests/deployment/native-install.sh --os debian-12 --archive ARCHIVE` | exit 0: the same cases PASS; kernel 6.1.0-53-cloud-amd64, systemd 252.39-1~deb12u2 |
| `... --recovery` on both | exit 0: the cases above plus **NR01 to NR05** PASS on both guests |
| `python3 tests/deployment/compose-backup.py --image blindpass-p07-controller:h3 --faults` | exit 0: CB02 (70 concurrent requests, 0 failures, 1.334 s), **CB03** (wrong-offline, host-credential, missing and exposed custody refused; the `unsafe backup recovery credential` wording still asserted), CB04, CB05 (capture, encryption and verification ENOSPC), resources removed |

`blindpass-p07-controller:h3` was built from the working tree with `docker build -f deploy/controller/Dockerfile`. The first native Ubuntu
run with H1's code failed at **B08** (the regression above) and, before the harness was corrected, at **N02**; both are fixed. The default
runs used earlier revisions of `native-guest.py` (sha256 prefixes `87cd29e2` and `6bc6f85f`) than the final `5c6cdde5`; the only
differences are the rollback stage and its exit status, which the non-rollback modes never reach.

### Red first versus written after (H3)

- **Red first:** N02 on the real guest (old assumption, "command unexpectedly accepted"); B08 on the real guest (credential refusal).
- **Written alongside or after, not observed red:** `native-start-test.py` (written with `wait_for_start`; first failing run not recorded),
  BO05b (written after the fix), `native_rollback.py` (a rehearsal, not a regression test).

### Answers to H1's open items

- Build the `--start` wait: **built** (item 3).
- Named refusals for restore and handoff (`OpenArgs`/`SealArgs`): **unchanged**; they still answer the generic "invalid backup options".
- Re-run the Compose backup harness and the native VM matrix: **done** (above), except that the Compose backup run was SQLite only and the
  PostgreSQL Compose backup harness (`compose-backup-postgres.py`) was **not** run.

### Still not run

`compose-backup-postgres.py`; the PostgreSQL authority suites behind the 151 ignored tests; the full `npm test`; hosted CI; `--power-loss`,
`--tool-faults`, `--credential-faults` and `--faults` modes of the native harness (only the default and `--recovery` and `--rollback`).
