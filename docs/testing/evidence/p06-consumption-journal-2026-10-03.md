# P06 bound consumption journal — 2026-10-03

CJ01–CJ05 pass for durable grant/operation/epoch correlation and journal custody.
The production consume path now appends the correlation in the same fsynced
one-use intent before authorizing an effect. Existing legacy consumption denies
remain intact and unmapped. This is a durable report input, not complete history,
report export, live reconciliation, external ownership or restored activation.
CJ06 passes on the actual Root-installed broker after a durable-intent abort/restart; the full normal two-guest SQLite harness terminates exit 0.

## Actual source checks

The paired [P06 plan](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/testing/phases/06-deployment-and-recovery.md)
records CJ01–CJ06 before implementation. The scoped
[first red](p06-consumption-journal-2026-10-03/first-red.txt) executes six cases,
all fail (exit 101). The [final target](p06-consumption-journal-2026-10-03/final-green.txt)
passes seven cases (exit 0), including the added torn bound-record control.

| Case | Executed result |
|---|---|
| CJ01 | Production GrantVerifier consume with fixture acceptance/time writes the exact grant/operation/epoch/expiry; reopen denies replay and preserves bytes |
| CJ02 | Original two-field intent stays consumed with absent correlation; a new bound record persists beside it; no owner/epoch is guessed |
| CJ03 | Existing authenticated-time compaction preserves retained bound record bytes and removes expired legacy rows; no historical completeness claim |
| CJ04 | Unknown/duplicate/missing fields, invalid op/epoch, conflicting op/epoch/expiry and same-ID legacy↔bound conflicts in both orders refuse complete file unchanged; exact repeated bound row is idempotent |
| CJ04b | Complete bound intent survives a torn next operation field; only that incomplete tail is truncated, with no invented next consumption |
| CJ05a | Internal malformed accepted-grant fixture is refused before journal/effect authorization; this bypasses the typed signed parser and is defensive validation, not proof it previously admitted malformed signed input |
| CJ05b | A hardlink introduced after valid consumption prevents subsequent append and reopen; target/alias bytes remain unchanged |

The tests call the production verifier's grant acceptance, trusted time and
consumption routines with fixture authority. They do not establish actual
network signature admission or Linux peer identity; those require the VM/control
path. Every new line uses fixed field ordering and positive safe issuer epoch,
with validated opaque IDs. The exact legacy two-field encoding remains readable.
Complete malformed/conflicting records refuse; torn-tail recovery remains the
existing documented behavior. A mixed legacy/bound duplicate cannot enrich an
old record by guessing its operation. Successful intent flush precedes effect.

Private opens now also require one link, alongside regular file, effective UID,
exact 0600 and O_NOFOLLOW checks. This shared helper covers the associated
revocation/time/ACK paths too; all Rust gates below exercise surrounding behavior.
It is not a proof against a hostile Root changing files concurrently. Scoped
CJ, inspector and control-copy fixtures are actually absent after execution;
RAII removes new private fixtures on failure. Five original pre-RAII red fixtures
were previously identified from that exact run and removed, without wildcard
removal of other test/user state.

## Guest assertion regression controls

The old guest grep counted the event key in both schema-5 ownership header and
its queued event. The new assertion parses unique JSON fields and counts only
exact top-level event keys in the broker's stored three-field records. Missing,
malformed/duplicate/partial records, header/nested mentions, unsafe mode and
hardlinks refuse without repair. Four current cases pass in the
[final inspector run](p06-consumption-journal-2026-10-03/inspector-green.txt).

An unchanged-HEAD private copy of the original assertion makes all four current
fixture cases [fail](p06-consumption-journal-2026-10-03/inspector-legacy-control.txt),
exit 1; the owned control tree is removed. The earliest
[fixture red](p06-consumption-journal-2026-10-03/inspector-first-red.txt) also fails
four, but its event initially uses the node's four-field signed shape. That
mistake is caught after the second VM failure: replacing it with the actual
broker three-field shape produces an honest
[schema red](p06-consumption-journal-2026-10-03/inspector-schema-red.txt) (one fails),
then correcting the parser yields four green. Neither initial fixture green
nor a later source inspection substitutes for actual VM execution.

## Required gates and earlier failed attempts

The initial [Rust workspace attempt](p06-consumption-journal-2026-10-03/rust-first.txt)
fails the existing fleet intent trigger fixture with `trigger ... already exists`.
The unchanged [isolated case](p06-consumption-journal-2026-10-03/rust-fixture-isolated.txt)
passes. The [workspace retry](p06-consumption-journal-2026-10-03/rust-retry.txt)
passes 688 tests/zero failures/eight ignores over 70 targets, exit 0. The final
current [authority workspace gate](p06-recovery-authority-ledger-2026-10-03/membership-rust-workspace.txt)
passes 689/zero/14 over 71 targets with the membership guard. No application
fix is made for the fixture retry; its intermittent cause remains unestablished.

The [Node26 build](p06-consumption-journal-2026-10-03/node26-build.txt) passes.
The [first workspace test run](p06-consumption-journal-2026-10-03/node26-first.txt)
fails five console UI assertions during concurrent jobs. The unchanged-input
[retry](p06-consumption-journal-2026-10-03/node26-retry.txt) passes: console 108,
MCP 108, helper/channel 147 and SPS 80 with 101 service-gated skips in 17 files.
Concurrency is observed, not an established diagnosis. Node24 and full client
GUI/profile acceptance are not inferred. Workspace
[Clippy](p06-consumption-journal-2026-10-03/clippy.txt) and the later
[final all-target gate](p06-recovery-authority-ledger-2026-10-03/membership-clippy.txt) pass with
warnings denied; format, shell/Python syntax and diff checks pass. Four snapshot
and six authority ordinary ignores have separate actual execution; three
Quickshell and one opt-in outage remain unexecuted by the current full Rust run.

Run from the repository root:

```sh
cargo test -p blindpass-broker --lib --locked p06_cj -- --test-threads=1
python3 tests/fleet/p03-broker-event-test.py
```

## Real VM progress and artifact scope

All three earlier runs use the full normal SQLite harness with two pinned
Ubuntu systemd guests, not debug/extended-only filtering. They terminate exit 1
and never reach CJ06. The [first](p06-consumption-journal-2026-10-03/vm-first.txt)
fails the text event count; the [second](p06-consumption-journal-2026-10-03/vm-second.txt)
fails the initially wrong signed event shape. The
[third](p06-consumption-journal-2026-10-03/vm-third.txt) passes those checks and
actual reboot, suspend/clock rollback and node-revocation transport replay, then
expects `node_revoked` from an original waiter already denied `grant_revoked`.

The fourth normal run preserves every main/extended scenario. Only that original
waiter admits the two valid terminal codes, with no marker/completion and exact
signed node-revocation application still required. The separate subsequent
fresh invocation after channel restart must report node revocation and accept
no request. The paired plan records this observed ordering correction before
source changes. The [fourth full normal run](p06-consumption-journal-2026-10-03/vm-current.txt)
terminates exit 0 with 23 passed scenario lines and no debug-stage skips.
[Terminal metadata](p06-consumption-journal-2026-10-03/vm-terminal.txt) records
complete teardown. CJ06 actually observes the exact operation/epoch binding in
the mode-0600 Root-owned single-link journal after abort and restart. The installed
broker SHA256 equals the inspected host artifact. Intent count is one, no marker
is created, replay is denied grant_consumed and the controller records uncertain.
The same run passes the actual positive-control private-node-key scan (three
identities/24 patterns, control found, zero exposures in controller state/log).
This completes the selected SQLite/Ubuntu crash scenario, not full P03/P06 acceptance.

The approved host checks establish /dev/kvm read/write and QEMU 11.1.1; the driver
verifies the pinned Ubuntu image SHA256
`612b2c0cc1bc413a6cb8c38fd611794caf0f2b436c50013d8b3794db12ad7354` and creates its
own overlays/SSH key. All three failed fixture directories are removed.
[Live guest artifact inspection](p06-consumption-journal-2026-10-03/vm-artifacts.txt)
actually matches both Root-installed broker/helper hashes to their host inputs.
Both guests run kernel 6.8.0-139, systemd 255.4-1ubuntu8.17 and Python 3.12.3.
The actual host-built broker SHA256 is
`977a0637a4f3357182d49e089174c79e6c8310cf7f2df189bd1f60833b963542`.
Its ELF requires libsystemd.so.0, libcrypto.so.3, libgcc_s.so.1, libc.so.6 and
ld-linux-x86-64.so.2; highest referenced GLIBC version is 2.34. These observations
are not a rebuilt bookworm release archive, Debian journal gate or new OCI image.

The working tree remains uncommitted at base
`8a595ad18783634da59e046595942e729b56147b`. Exact current source pins:

| Source | SHA256 |
|---|---|
| `crates/blindpass-broker/src/grants.rs` | `32ddfe1bc712392acd50086d0598dcbdc3916e9a5b3d92aaba04f3feba4f8717` |
| `tests/fleet/p03-guest.sh` | `ad13fe6e225205b44c48793519d40e615e7b191dacf7b2d511a7a87e40af1051` |
| `tests/fleet/p03-vm-extended.sh` | `62636ca878c637600fb95c0e4e86099177b33705aecd7aab0c31d107d2f3913a` |
| `tests/fleet/p03-vm.sh` | `68b777a12d731e36696e5a76326d5d5127932779d92e63adfda45b5193de48f0` |
| `tests/fleet/p03-broker-event-test.py` | `16ead581cdb4a8678f0264586645082d97037f4d663c149779502cdc2f46c832` |

## Lifetime, compatibility and unfinished acceptance

The journal contains only opaque IDs, issuer epoch and expiry in persistent
private broker storage; no secret payload, bearer, private key or provider
cleanup handle. Runtime parsers hold metadata temporarily. Dummy test keys stay
in fixture memory; disposable VM keys remain in private guest/runner fixtures.
Retained logs have no private-key, credential-bearing PostgreSQL URL or bearer
header markers under a scoped scan; this does not prove arbitrary secret absence.

Compaction still prunes at the existing expiry-plus-24-hour bound. Legacy and
pruned history lacks authenticated coverage/correlation and cannot become a
complete report by guessing. Add durable coverage/pagination, revocation/session
mapping, fresh challenges/current enrolled keys and a transactional reconciliation
consumer; keep generic consumed_report admission closed until then. Earlier
broker parsers may reject extended lines. Downgrade needs matching protected
pre-upgrade state plus external recovery/reconciliation before activation;
never silently erase consumed intent to run an old binary.

No new dependency/manifest/lockfile or package/license boundary changes. Protected
P03 evidence stays unstaged at 66 additions/zero removals. No slice-6 commit
precedes incomplete slice 5. Preserve all nine slices: matching PostgreSQL full
dump/isolated restore and artifact faults, external process ownership/HWM and
all-route fencing, stale transient-authority invalidation and provider cleanup,
offline quarantine, locked upgrades, interrupted native↔Compose migration and
all three shipped/remote/browser/native/inherited gates. P06 remains active and
unaccepted; TLS/scanner approvals and the separate PostgreSQL authority choice
do not approve ADR 0011's pending backup-toolkit proposal.
