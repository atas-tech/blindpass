# P06 authenticated fenced restore stage — 2026-10-04

> **Superseded in part.** This record covers schema 16/17 at the time of the stage. Later records ([application](p06-recovery-application-2026-10-04.md)) migrate schemas 16–18 to 19 and the operating guide and capabilities response now state schema 19.

**Status:** Implemented destination-stage candidate with actual CLI, production
HTTP, authority/socket and interruption evidence. Full nine-slice P06 goal remains
active; slices 5/6 and phase acceptance are not complete. No commit is made.
The [product plan](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/phases/06-deployment-and-recovery.md)
and [paired test plan](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/testing/phases/06-deployment-and-recovery.md)
received ST01–ST08 test-first scenarios before implementation and verified execution
checkpoints after these gates. See the [operating guide](../../deploy/recovery-stage.md).

## Behavior and custody

The controller/co-located CLI `restore` command accepts exact absolute archive,
recovery-key, new-destination and protected-authority-file options plus opaque
existing tenant/owner/recovery IDs. It authenticates and extracts once, checks
fixed archive members/digests, SQLite integrity/foreign keys, supported schema
and exact snapshot metadata, and derives issuer identity from the restored key.
The restricted separate PostgreSQL authority must already be `recovering` at an
epoch above the snapshot. No caller epoch, provisioning/reservation/activation,
overwrite, source-stop shortcut or authority credential in the bundle is added.

The exact detached recovering holder guards isolated migration and durable
invalidation. A private typed Store purpose suppresses clock initialization,
requires protected tenant/key/epoch and admits only this recovery path. Schema 16
is migrated to 17 only inside authenticated private staging with the unchanged
source archive retained as the pre-upgrade backup. Current 17 is supported; future,
missing-clock and unequal metadata refuse. The target retains the snapshot clock.

Recovery deletes transient capabilities/sessions and records revoked/disabled
legacy credentials, uncertain operations, indefinite grant tombstones and
quarantined nodes/review subjects. SQLite checkpoint/pool close and file/directory
flushes precede fresh ownership checks and one private-root publication using
Linux `renameat2(RENAME_NOREPLACE)`. Unsupported publication semantics refuse;
[Linux rename documentation](https://man7.org/linux/man-pages/man2/rename.2.html)
supports the no-replace contract. A post-rename failure preserves the fenced
destination for review. No method clears recovery intent or external quarantine.

Plaintext restored keys and decrypted archive/database material exist in private
0700/0600 staging; restored keys then persist in the private destination. OpenSSL
consumes the recovery credential during crypto execution, and SQLx retains
external authority credentials in process memory for its connection/pool lifetime.
Caller-owned secret buffers are wiped on drop; library/allocator/OS copies and
filesystem erasure are not guaranteed. Normal exit removes transient stages.
Dedicated abrupt exits may leave identifiable private `.backup-*` residue;
explicit cleanup requires the parent custody lock and preserves published state
and encrypted input. No credential contents are command arguments or error output.

## Actual scenarios

The [final ordinary gate](p06-restore-stage-2026-10-04/stage-final-normal.txt) passes
seven cases; [dedicated fault gate](p06-restore-stage-2026-10-04/stage-final-fault.txt)
passes nine, including the same seven. These are overlapping runs, not 16 distinct
scenarios. All disposable driver cleanup summaries are zero.

| IDs | Actual evidence |
|---|---|
| ST01 | Real encrypted archive/controller CLI preserves keys/identity/clock, installs protected epoch 8, deletes seeded transient tables, revokes/disables credentials, persists uncertain completed-operation history, indefinite tombstone and node/six-subject quarantine. Actual production `serve` returns health 200, ready 503 with recovery reason and ordinary 503; shutdown is bounded. |
| ST02 | Corrupt CMS, wrong recipient, authenticated unsafe USTAR name, wrong tenant/owner/issuer, missing/admin/unreachable authority file, nonrecovering and stale target records refuse with fixed output and no destination. Invalid records use fresh independently provisioned test contexts, never anti-rollback-trigger bypass. |
| ST03 | Existing empty directory/file/dangling link, busy parent lock, permissive/linked parent and hard-linked/permissive authority credential preserve existing state/refuse. Core tests independently verify no-replace directory publication. |
| ST04 | Live competing recovering holder refuses; genuine holder release permits fenced restore. Dedicated stopped process loses its independently observed own runtime-role socket immediately before publication and refuses without a destination or plaintext diagnostic output. |
| ST05 | Dedicated abrupt exit after extraction, invalidation and before publication leaves only private residue, no published destination, unchanged encrypted source; post-invalidation residue carries durable invalidated epoch 8. Busy cleanup refuses; explicit cleanup and retry publish only fenced state. |
| ST06 | Authentic schema16 migrates to 17 only in isolated staging, preserves source schema/archive/clock and invalidates at epoch 8. Separately authenticated/digested future 18, lost-clock and unequal tenant/epoch fixtures refuse. |
| ST07 | Real restore under a 512 MiB **per-process address-space limit**, two Tokio workers and 10,000 preserved audit rows runs below 60 seconds. This is not whole-container/profile memory proof, maximum-size archive evidence or QF06 worst-case crypto proof. |
| ST08 | Built co-located CLI forwards the actual command and JSON fenced receipt; second restore refuses without altering the published receipt. |

Build actual CLI first, then run the owned driver as documented in
[deployment testing](../../../tests/deployment/README.md). Dedicated faults use
`--test-features p02-test-failpoints`; stop/exit hooks are absent from ordinary
builds. Socket observation/termination uses current database and current runtime
user, never another host process or a shared authority. The final default binary
[reset and CLI hook-absence gate](p06-restore-stage-2026-10-04/reset-normal-summary.txt)
passes after fault testing, leaving co-located debug binaries without test hooks. No dependencies,
manifest/lockfile or licensing boundaries change.

## Test-first evidence, corrections and controls

[Behavioral ST01 red](p06-restore-stage-2026-10-04/st01-actual-red2.txt) reaches the
missing real controller restore command after fixture-only corrections (private
TestDirectory field and valid agent ID). The
[second matrix](p06-restore-stage-2026-10-04/stage-second-matrix.txt) records six
passes and a real co-located CLI assertion failure before forwarding was added.
The [core API red](p06-restore-stage-2026-10-04/publication-api-red.txt) is compile
failure for the absent publication method, not runtime behavior proof.

Intermediate runs retain a fixture attempt to mutate protected authority records
without valid revisions and a `/readyz` JSON-oracle compile error. These were
corrected by fresh protected contexts and JSON inspection. Initial lost-socket
observation used the separate administrator role, which cannot view the runtime
role's PostgreSQL activity. Final observation uses the same restricted runtime
role and exact own database/user before terminating one observed holder.
No authority ACL was weakened to make the test pass. The first complete ordinary
Rust run passed 698; Clippy then found constant-chunk iteration and a redundant
byte-slice conversion. Both were corrected, controls/source hashes refreshed and
the final Rust/Clippy gates rerun; intermediate logs remain separate artifacts.
One control hash snapshot preceded formatting and failed its metadata check;
final hashes were captured after formatting and both behavioral controls rerun.

[Two private controls](p06-restore-stage-2026-10-04/controls-summary.txt) replace
no-replace publication with ordinary rename or skip bulk invalidation while
allowing its prepared phase to publish. Both exit 101 at actual assertions:
[existing destination replaced](p06-restore-stage-2026-10-04/overwrite-control-red.txt)
and [epoch 1 instead of 8](p06-restore-stage-2026-10-04/invalidation-control-red.txt).
Four production source hashes remain unchanged, copied control trees are removed
and generated authority resources are cleaned.

## Required regressions and limits

[Node 26 build](p06-restore-stage-2026-10-04/node26-build.txt),
[npm tests](p06-restore-stage-2026-10-04/node26-test.txt),
[Clippy](p06-restore-stage-2026-10-04/clippy.txt),
[formatting](p06-restore-stage-2026-10-04/format.txt) and
[OpenAPI](p06-restore-stage-2026-10-04/openapi.txt) all exit zero.
SPS retains 80 passes and 101 skips in 17 files. The
[ordinary Rust workspace](p06-restore-stage-2026-10-04/rust-workspace.txt) passes
698 with zero failures and 72 ignores across 77 result targets.
The [authority regression matrix](p06-restore-stage-2026-10-04/regressions-summary.txt)
passes 127 existing cases, and the
[PostgreSQL snapshot gates](p06-restore-stage-2026-10-04/postgres-snapshot-summary.txt)
pass four. The final restore matrix adds nine distinct cases (seven also run in
ordinary feature mode). Focused/snapshot total is 140, overlapping ordinary Source
checks are not added to the ordinary workspace count. Three Quickshell and one
optional PostgreSQL outage case remain unexecuted; skips establish no behavior.

[Source pins](p06-restore-stage-2026-10-04/source-pins.json) cover 66 runtime/
fixture/package boundaries. [Final catalog](p06-restore-stage-2026-10-04/authority-final-cleanup.txt)
has zero generated authority/snapshot databases or roles.
[Final QA](p06-restore-stage-2026-10-04/final-qa.txt) verifies current hashes, results,
relative links, credential markers, cleanup and both vault checkpoints.
User P03 evidence remains 66 additions/zero deletions, unstaged/untouched;
index empty; no commit. Historical execution records keep original source pins.

Full QF06 worst-case synchronous crypto, durable/authenticated QF07/QF08 source/
server stop, complete current-key broker report challenge/history/pagination,
provider cleanup, persistent reconciled review/offline quarantine and protected
activation/unfence remain required. PostgreSQL dump/full restore retains its
separate toolkit review. Packaged migrate→serve active-attempt sequencing,
automatic verified pre-upgrade backups/retention, both native↔Compose directions,
current profile/VM/stock-client/browser parity, full nine slices and inherited
P02.6/P03/P05 acceptance remain open. This stage does not establish them.
