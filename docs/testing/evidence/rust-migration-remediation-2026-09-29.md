# Rust migration review fixes: local execution record

**Date:** 2026-09-29. **Tree:** uncommitted changes on `1a37bbe`.

This record covers six findings from the Rust migration review against the current vault roadmap and fleet plan. It is implementation evidence, not a pilot acceptance or production cutover record. Tests use generated dummy credentials and disposable SQLite/PostgreSQL state.

| Finding | Change and regression check |
|---|---|
| Old grants accepted after registration changes | Signed grants carry `registration_version`, checked against the broker's current registration. `registration_change_cannot_reauthorize_a_replayed_grant_after_restart` checks replay after restart. Previously issued signed grants without the new field receive a terminal, audited rejection so they cannot block the relay inbox. |
| Operator password work can saturate the async runtime | Login attempts are limited per account and trusted client IP before password verification. At most four Argon2 checks run concurrently in blocking workers. `login_attempts_are_bounded_before_password_verification` checks the account limit. |
| Database read can replay operator sessions | Browser and desktop access tokens use random 32-byte values; the database stores their SHA-256 digests. The version 14 migration removes old sessions. Browser and desktop tests try stored IDs as credentials, and a migration test checks removal. |
| Revocation outcome lost when audit queue is full | The broker records the first outcome and observation time in the revocation tombstone. Startup rebuilds unacknowledged outcomes without relying on signed-document redelivery; a separate private acknowledgement journal keeps completed outcomes from being re-emitted after restart. `revocation_outcome_recovers_after_full_queue_and_restart` checks a full queue, restart without redelivery, the original event body, acknowledgement write failure, and the one-record tombstone contract. |
| Expired grants accumulate in memory | Signed time updates retire unconsumed expired grants; the accepted map has a 10,000-grant bound and reports a durable rejection at capacity. `expired_unconsumed_grants_leave_the_accepted_map` checks expiry and the preserved `grant_expired` denial; `accepted_grants_have_a_fixed_capacity` checks the bound. |
| Idle node polls write session rows each second | An idle poll checks inbox and session existence with a read query, entering the delivery transaction only for an acknowledgement or pending document. Tests count session writes during an empty poll and check prompt failure after session removal. |

The controller consumes the operator password in its request and Argon2 worker memory for the login attempt. The worker's copied secret buffer is cleared when dropped; the original request string remains in runtime memory until the request is dropped. Raw access tokens live in browser cookies or the desktop process until expiry, logout or revocation. The desktop session helper keeps its refresh token in a mode-0600 local file until rotation or logout; the controller database stores only refresh-token hashes. CSRF secrets remain in controller storage for request validation and do not authenticate by themselves. Broker grant authority exists in memory until consumption, revocation or expiry; its consumption and revocation journals retain bounded replay evidence.

## Verification

| Gate | Result |
|---|---|
| `npm run build`; `npm test` | Passed with host access. SPS reported 101 default service-gated skips across 17 files; those skipped cases are unexecuted here. |
| `cargo fmt --all -- --check`; `cargo clippy --workspace --all-targets --locked -- -D warnings`; `cargo test --workspace --locked --quiet` | Passed with host socket access for the integration tests. The default Rust run leaves three opt-in desktop-app tests and one PostgreSQL outage test ignored. |
| Rust HTTP contract suite on SQLite and PostgreSQL | 40/40 on each backend. |
| `P02_TEST_BACKEND=<sqlite\|postgres> cargo test -p blindpass-controller --test security_perf_regressions --locked` | 6/6 on each backend. |
| PostgreSQL `admin_session`, `desktop_session`, `store_transitions` | 4/4, 8/8 and 35/35 respectively. |
| `npm run test:e2e --workspace=@blindpass/console` | 64 passed; one optional previous-binary rollback case skipped. |
| Broker full-queue revocation restart test | Passed after the journal was reduced to one durable tombstone record. |
| `./tests/fleet/p03-vm.sh --backend both` | Passed on the pinned P03 image with two systemd guests: all SQLite and PostgreSQL scenarios completed, including revocation transport replay, broker restart recovery, old-grant denial, parallel identities and no-key-at-controller checks. The VM release binary preceded the final BTree range-lookup optimization; the current source version is covered by the workspace tests below. |

The schema 14 migration requires operators to sign in again. An older controller cannot serve schema 14; rollback requires restoring a pre-migration database backup and reauthenticating operators. The optional previous-binary Playwright case assumes sessions survive rollback on the same database and must be revised before it can prove rollback for this schema. Older broker binaries cannot read the new tombstone outcome fields; a broker rollback also needs a pre-upgrade state backup. Tombstones written by an earlier broker without outcome metadata cannot reconstruct an outcome already lost before this change.
