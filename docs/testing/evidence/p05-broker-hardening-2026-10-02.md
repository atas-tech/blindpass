# P05 broker hardening — 2026-10-02

**Status: host unit-test evidence only; P05 is not accepted.** This record covers
review fixes to the Rust broker coordinator, session journal, request parsing and
owner retention. No real systemd VM, real helper/browser, stock client, controller
or node run is part of it, and nothing here establishes any VM or real-client
behaviour. All original acceptance, inherited, two-host and pilot gates remain
required.

## Scope

| Finding | Change | Where |
|---|---|---|
| H1 | The website revoke is always attempted at actor cleanup: by handle for a known session, account-wide otherwise. Helper termination is a separate input to journal reconciliation, so an unverified helper keeps the record blocked for recovery without suppressing the revoke. A missing or dead runtime-manager connection is replaced once at cleanup. A supervisor that was connected but never produced a verified browser (failed prepare or proof) is unverified unless its stop was acknowledged. | `browser_coordinator.rs` |
| H2 | No pending record stalls dispatch any more. `SessionJournal::reserve` already refuses the same account or workload; the dispatcher now skips such candidates without preparing them. Class-wide recovery plus per-record account revoke runs only with no actor running. With actors running a light pass revokes the account for pending records that belong to no running actor and closes a record only where its processes are known terminated. A shared running-operation set is registered before the actor spawns and cleared when its slot drops. | `browser_coordinator.rs` |
| H2c, H2d | `SessionJournal::release_expired` closes, without a confirmed revoke, any unfinished record once trusted controller time reaches its reservation plus 120 s operation deadline, 30 min application session ceiling and 60 s margin (1 980 000 ms). A unit-file test ties the margin to the helper (60 s) and browser (30 min) `RuntimeMaxSec` values. It runs on the 60 s maintenance tick, logs one fixed line per release and publishes a closure for records that had a durable login. This is the only way a record whose recipe was edited after restart frees its account. | `session_journal.rs`, `browser_coordinator.rs` |
| H3 | Provably terminal operation owners (and their closures) are evicted oldest first when admission finds the table full, and opportunistically from the maintenance tick. See [Owner retention](#owner-retention). | `owner_retention.rs`, `lib.rs` |
| M1 | A trusted-time step back of at most 2 500 ms is applied as the high-water mark itself in every journal transition; larger regressions, zero, overflow and a fenced journal still fail closed. | `session_journal.rs` |
| M2 | An idle prune no longer rewrites the journal: it persists on removal or when the durable mark is 10 minutes stale. `try_unfence` writes a durable snapshot and clears the fence; permits and ready contexts invalidated by the fence stay invalid because the shared availability flag is replaced, never revived. The dispatcher retries every 5 s while fenced and recovery resumes when it succeeds. | `session_journal.rs`, `browser_coordinator.rs` |
| M4 | The original-lease (pidfd/manager, up to 5 s) and administrator revalidation runs before the journal mutex is taken. `prepare_helper_exchange` is split into `take_checked_source` (no journal parameter) and `journal_helper_exchange` (journal work only). | `ops/browser_session.rs`, `browser_coordinator.rs` |
| Purpose | `purpose` rejects every Unicode control character (CR, LF, NUL and TAB included) and U+00AD, U+061C, U+200B–U+200F, U+2028–U+2029, U+202A–U+202E, U+2060–U+2064, U+2066–U+2069, U+FEFF. The 512-byte limit is unchanged. | `operation_request.rs` |
| L4 | A browser session whose grant carries a controller revocation tombstone (or on a revoked node) records the local closure as `cancelled`, not `completed`. A signed closure already recorded is never replaced. The result event sent to the controller is unchanged. | `lib.rs`, `owner_retention.rs` |
| Startup | If the startup class-wide recovery fails (manager unreachable or its reply times out) the broker still starts. Browser dispatch and all recovery stay disabled and the dispatcher retries every 5 s; the first success captures the records pending at that time as already terminated. No actor starts before a class-wide recovery succeeded. | `browser_coordinator.rs` |

### Owner retention

An owner is terminal only when all of these hold: it is not a pre-admission
withdrawal; a closure is recorded for its key; a requested cancellation was
acknowledged; no original-process lease and no ready context remain; no unfinished
session-journal record correlates to the key; and no queued node event names the
key. Native-mode and untyped owners carry no grant correlation, so the signed
closure is their only evidence and they are never evicted without one. Eviction is
fail safe: status reports `unknown`, cancellation reports an unknown operation and
a late grant for the key is refused. A failed durable write restores both tables
and leaves the outbox fence set.

Measured finding: the durable outbox header is canonical JSON capped at 1 MiB.
Realistic browser owners with closures reach that cap at about 1 760 records and
minimal untyped owners at about 3 330, long before the 10 000 count bound. Before
this change the broker would have failed every request write after roughly that
many lifetime requests, because owners were never removed. Admission and the tick
therefore also reclaim by projected size (an allocation-free upper bound checked
against the real encoding in a test), keeping room for one more owner and for the
closure every unclosed owner will receive. No snapshot format change was needed;
the version stays 5.

## Tests

New or changed host unit tests, by module (all pass):

- `session_journal` (9 new, 3 changed): tolerance and fail-closed regression in
  every transition; zero, overflow and fence; release at the bound, restart and
  idempotence; released record with a login; unit-file lifetime assumptions;
  unrecoverable record and account reuse; idle prune write count; unfence with
  invalidated permits; blocked-account admission and unresolved-key view. Changed
  for the deliberate policy changes: `expired_known_or_unknown_session_is_still_blocked_without_reconciliation`
  (blocked before the bound, released at it), `detached_helper_permission_is_single_use_bound_and_withdrawn_before_reconciliation`
  and `activation_is_bound_and_reconciliation_requires_both_real_effects` (regressions of 1–2 ms are now
  tolerated, so they use a step beyond 2 500 ms).
- `operation_request` (4 new): control characters, invisible format and bidi
  characters, a bidi override example, ordinary international text and the limit.
- `browser_coordinator` (17 new, 1 changed): no stall for another account, refusal
  without consuming the grant, release bound with a stale recipe, light recovery
  (running actor untouched, pre-startup record closed, runtime record revoked but
  not closed and throttled, closed after the next full pass), full recovery with
  closure publication, release publication, startup-failure gating, registration
  before launch and release on drop and on failed launch, fenced journal retry,
  cleanup ordering (revoke despite helper failure, helper never started, supervisor
  without a verified browser), manager reconnect, and the journal-lock seam.
  `actor_slot_drop_*` gained the running-set fields.
- `owner_retention` (11 new): size-bound reclamation oldest first with durable
  round trip, refusal with only live owners, withdrawal-path reclamation, every
  protected owner kind, status/cancel/late grant after eviction, failed snapshot
  restore, 10 001+ lifetime requests, periodic reclamation, estimate tightness and
  the coordinator view.
- `lib` (1 new): revoked grant closes as `cancelled`.

Red/green: the journal, purpose, owner-retention and L4 tests were run against
stubs or the old code and failed before implementation (journal 8 tests, purpose
4, owner retention 7 of its first 9, L4 1; the unit-file lifetime test and the
beyond-tolerance cases pass on both). The
coordinator was restructured before its tests were written, so those tests were
instead checked by mutation: each of seven re-introduced defects (revoke gated on
helper stop, the global stall, running records not skipped, light pass closing
unterminated records, failed prepare treated as stopped, journal locked before
revalidation, startup failure not gating dispatch) fails at least one test. These
are host unit-test results, not behavioural evidence of the real services.

## Commands and results

Run from the repository root with a private target directory, unsandboxed because
the Unix-socket tests fail with `EPERM` in the default sandbox.

| Command | Result |
|---|---|
| `cargo test -p blindpass-broker --locked -- --test-threads=1` | 291 passed, 0 failed, 0 ignored (library 280, broker binary 3, loader 2, workload client 6) |
| `cargo clippy -p blindpass-broker --all-targets --locked -- -D warnings` | Passed, no warnings |

The library count includes tests another change added to the provisioning and
control modules in the same working tree; the baseline before this work was 228
library tests.

## Files changed

`crates/blindpass-broker/src/`: `browser_coordinator.rs`, `session_journal.rs`,
`operation_request.rs`, `ops/browser_session.rs`, `owner_retention.rs` (new) and
`lib.rs` (module declaration, one state field and its initialiser, the two
admission capacity checks, the shared outbox header builder, and the closure
status helper calls). This record is the only file outside the crate.

## Limits and not established

- No VM, systemd, real helper/browser, real administrator revocation service,
  controller, node or stock-client run. The cleanup, reconnect, light recovery and
  startup-gating decisions are exercised only through fakes at the seams named
  above; the production implementations of those seams are unchanged code paths
  not run here.
- The trusted-time estimate can step back by more than 2.5 s when relay delay
  differs between replies (up to the 35 s reply bound). Such a step still fails
  closed and heals itself; it is not covered by the tolerance.
- The administrator revocation connection held by an actor is not reconnected at
  cleanup (its credential was consumed at preflight); a dead one leaves the record
  to recovery.
- A light pass cannot close a record created while running until a class-wide
  recovery with no actor running, or the 1 980 000 ms release bound, so under
  continuous load such an account can stay blocked for up to about 33 minutes.
  After any successful class-wide recovery with no actor running, the records
  pending then count as terminated for later light passes.
- A retry that reuses the request key of an evicted terminal operation is admitted
  as a new request. The window is the most recent few thousand operations.
- A released record's closure is published as completed/`browser_session_closed`
  although no revoke was confirmed; the application's own 30-minute session
  maximum is the assumption, as for the release bound itself.
- The durable journal high-water mark may lag memory by up to 10 minutes after a
  restart; controller-time monotonicity is still enforced by the grant verifier.
- The VM harness diagnostic filters forward only `actor_failed` and
  `recovery_waiting` lines. The new fixed lines (`startup_recovery_waiting`,
  `startup_recovery_complete`, `record_released`, `journal_unfenced`) are not
  forwarded by them.
