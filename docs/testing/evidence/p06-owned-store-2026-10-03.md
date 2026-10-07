# P06 owned Store and admitted operation lifetimes — 2026-10-03

This is execution evidence for the ownership candidate, not acceptance of P06 or
any deployment profile. All nine implementation slices remain in scope. The
paired authoritative [product](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/phases/06-deployment-and-recovery.md)
and [testing](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/testing/phases/06-deployment-and-recovery.md)
plans recorded OP12–OP13 before their tests. The existing approved SQLx stack is
used; no dependency, manifest, lockfile or package boundary changed.

## Implemented boundary

A holder admits operations under the same mutex that permanently fences it.
Fencing refuses new work and retains its dedicated PostgreSQL transaction while
operation permits exist. Dropping the final permit releases a fenced guard;
explicit three-second quiescence waits for drainage and refuses a timeout without
resetting the latch. A permit retains the holder itself. HTTP permits cover
handler futures, not streamed response bodies.

An immutable binding is shared by Store clones created before binding and by
attached signer clones. [The method inventory](p06-owned-store-2026-10-03/wrapped-methods.json)
lists 121 protected async Result methods, including maintenance. They check live
authority and exact local epoch, hold a permit and cancel on fencing. Readiness
and direct signing also use this boundary. Raw issuer-epoch metadata and
crate-private database readiness diagnostics remain available for diagnosis.
The two direct node TimeReply/ApplicationAck paths use the same guarded signer
as transactional inbox documents. Signing checks the issuer key, epoch and latch
before signing and rechecks fencing before returning a document. A different
binding fences both holders instead of resetting the existing Store.

Authority credentials remain in SQLx process memory, outside controller backups
and public evidence; no zeroization guarantee is added. Signer private keys remain
in existing controller memory. These changes add no plaintext-secret consumer;
the retrieval fixture uses dummy ciphertext and the direct replies carry protocol
metadata. Cancellation discards results but does not prove rollback of arbitrary
server-side work, worker termination or plaintext-memory erasure.

## Actual tests and controls

| Scenario | Executed result |
|---|---|
| OP12 | Two admitted permits survive independent administrative fencing; reservation refuses while either remains. Quiescence times out and remains fenced, then succeeds only after both end; explicit reservation advances 101 to 102 |
| OP13a | Existing Store/signer clones sign a valid TimeReply before binding loss; wrong signing epoch refuses; reads, creation, maintenance, monitoring and signing refuse after fencing; replacing a binding cannot reset it |
| OP13b | A real SQLite BEGIN IMMEDIATE write lock holds an admitted one-use retrieval pending. Fencing cancels its future. After lock release and Store-pool drainage, an independent database read still finds the submitted record |
| OP13c | Without HTTP or a monitor, direct signing refuses exact PostgreSQL backend loss, local epoch mismatch and wrong issuer binding; local and external metadata remain unchanged |

The [final current-source driver run](p06-owned-store-2026-10-03/postgres-current.txt)
passed **25 tests**, with zero failures, in 23.34 seconds. It includes the previous
six ledger cases and all process/router cases, including 144 protected HTTP
requests and CORS preflight. [Its summary](p06-owned-store-2026-10-03/postgres-current-summary.txt)
reports exit 0 and zero cleanup errors. The final independent
[catalog check](p06-owned-store-2026-10-03/authority-final-cleanup.txt) found zero
generated databases and zero generated roles. Faults touched only owned rows,
connections, loopback proxies and temporary test databases.

Initial [permit API](p06-owned-store-2026-10-03/first-red.txt) and
[Store API](p06-owned-store-2026-10-03/store-first-red.txt) compilations failed
before implementation. These are compile-first checks, not runtime failure proof.
The first full execution passed 23 and failed one because its empty TimeReply
body was invalid; replacing it with a valid typed body produced 24 passes.
The additional direct-signing test produced 25 passes.

Two private temporary source copies independently removed the protection. The
[early-release control](p06-owned-store-2026-10-03/early-release-control-red.txt)
failed OP12 at the live-permit reservation assertion (0 passed, 1 failed, exit
101). The [Store-bypass control](p06-owned-store-2026-10-03/store-bypass-control-red.txt)
failed OP13b because its blocked future did not cancel (0 passed, 1 failed, exit
101). [Control cleanup](p06-owned-store-2026-10-03/controls-summary.txt) confirms
production source was unchanged and temporary trees were removed. These are real
assertion failures, not intentionally broken test expectations or compiler errors.

## Workspace gates and source pins

- [Full Rust workspace](p06-owned-store-2026-10-03/rust-workspace.txt): exit 0,
  689 passed, zero failed, 33 ignored across 71 result targets. This ran after the
  semantic implementation and before final wrapper indentation and strengthening
  OP13b's post-pool-drain read. Final 25-case integration and Clippy ran afterward.
- [Final Clippy](p06-owned-store-2026-10-03/final-clippy-retry.txt): workspace/all
  targets, locked/offline, warnings denied, exit 0. Earlier logs retain three
  style findings and a transient indentation-helper syntax error; both were fixed.
- [Node 26.10.0 build](p06-owned-store-2026-10-03/node26-build.txt) and
  [workspace tests](p06-owned-store-2026-10-03/node26-test.txt): exit 0 on first
  execution. SPS reports 80 passes and 101 skips in 17 skipped files; those skips
  are not execution evidence. No JavaScript behavior changed.

The 25 authority ignores were actually executed separately above. Four exported
PostgreSQL-snapshot ignores have prior scoped [snapshot evidence](p06-postgres-snapshot-2026-10-03.md)
and were not rerun here. Three Quickshell checks and one optional PostgreSQL
outage check were not run this turn. Node 24, real systemd VM/profile parity,
release artifact/image rebuilding and separate-host issuer recovery were not run.

[Current source pins](p06-owned-store-2026-10-03/source-pins.json) cover 18 files:
authority, router, direct node signing, twelve Store modules, tests, schema and
driver. Historical [process/router evidence](p06-process-ownership-2026-10-03.md)
retains its own pins. Check current logs and limitations before claiming behavior
for a packaged artifact.

## Remaining gates

Production serve still uses the original unbound builder. Bound maintenance is
protected when a binding is installed; mandatory production startup, local
administration and configuration are not wired. Complete mutation/response-body
quiescence, ambiguous commit reconciliation and source-stop proof remain open.
No method here activates restored state or authenticates complete broker recovery
coverage. Transactional legacy/fleet invalidation, live signed reports, cleanup,
offline quarantine, migration locks/backups, transfer and the full three-profile
parity matrix remain unfinished. PostgreSQL custom-dump/full isolated restore
still awaits the distinct [toolkit review](../../product/decisions/0011-p06-postgresql-backup-toolkit-review.md);
the user's SQLx authority choice does not approve that toolkit. No slice 5 or 6
commit was made. The unrelated user P03 evidence edit remains 66 additions,
unstaged and unchanged.
