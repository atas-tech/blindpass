# P06 paginated broker recovery export — 2026-10-04

**Status:** Broker producer and strict shared contract implemented and host-tested.
Full nine-slice P06 remains active and unaccepted. Slices 5/6 are incomplete;
no commit is made. The [product plan](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/phases/06-deployment-and-recovery.md)
and [paired acceptance plan](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/testing/phases/06-deployment-and-recovery.md)
retain BR01–BR10 and complete protected deployment/recovery acceptance.

The V2 manifest fixes recovery identity, current node-key version, original
observed issuer epoch, history identity/pruning/unmapped bounds, total count and
full ordered-history digest. Strict pages contain at most 128 original uncertain
consume intents; metadata-only signed frames stay within 64 KiB and history stays
within existing journal limits and the explicit million-record contract cap.
Unknown, legacy, unmapped and pruned histories never gain coverage from receiving
all pages. Page gaps, replay, changed manifests, order, counts or digest refuse;
an accumulator error permanently poisons that collector. It is an in-memory
integrity primitive, not the required durable recovering-controller consumer.

The broker's actual private control socket exposes a fresh suspend-aware 30-second
local nonce and accepts only a pinned-controller-signed, strict bounded request
bound to node/scope/key version/recovery/generation/controller nonce. The initial
challenge carries unsigned public metadata; only the broker-signed pages are
receipts. The controller signature and fresh local nonce gate journal access and
pin advancement. Callers cannot supply rows, paths or arbitrary signing bodies.
Existing peer checks remain in force. This nonce gate does not establish durable
one-use controller receipt storage or protected recovery ownership.

Recovery pinning retains the original observed epoch before its own advancement;
observations above a proposed generation remain visible and require a new
protected reservation. Current-key/version and current-pin checks are locked
through page signing. Actual node-key rotation invalidates cached old-version
requests. A new regression first reproduces consumption by a stale verifier after
another writer durably advances the issuer pin; journal append now requires the
bound epoch to equal the history high-watermark. Normal PIN_ISSUER also holds the
BrokerState lock before publication. This proves the tested runtime/durable race,
not hostile Root mutation or protection from rolling back broker state.

The real journal is frozen under its private lock into one unlinked 0600 file.
Directory synchronization precedes metadata writes. Page offsets and incremental
digest avoid cloning the entire history for each page. New consumes and actual
pruning do not change the cached manifest or records. No credential payload is
exported. Plaintext consists of existing journal metadata, runtime maps, bounded
page buffers and the anonymous snapshot descriptor. The descriptor can remain
open while idle after expiry; a later request/new challenge or shutdown closes it.
Validity is checked before/after signing, not a hard 30-second memory-erasure
claim. Restart loses the ephemeral nonce/snapshot; a new request may need a higher
protected reservation because the earlier epoch fence remains durable.

## Actual checks and controls

[Epoch race red](p06-paginated-recovery-2026-10-04/epoch-race-red.log) fails the new
authorized-effect assertion; [green](p06-paginated-recovery-2026-10-04/epoch-race-green.log)
passes after the durable history fence. The [initial V2 API check](p06-paginated-recovery-2026-10-04/pages-api-absent.log)
fails compilation because the module did not exist; it is not runtime red evidence.
The [V1 nonce regression](p06-paginated-recovery-2026-10-04/nonce-initial-green.log)
already passed and required no production change.

Seven [core cases](p06-paginated-recovery-2026-10-04/core-expanded.log) cover
0/1/128/129/384 records, actual Ed25519 signatures, canonical parsing, strict
scope/count/sort/current-key checks, poisoned completion, digest tampering,
unknown/pruned/unmapped coverage, higher observed epochs and bounded signed-request
schema/signature/nonce/domain checks. Eight real host control-socket cases execute
in the [normal final broker run](p06-paginated-recovery-2026-10-04/normal-broker-reset.log).
They cover 129 actually delivered/consumed signed grants and marker effects,
original correlation, old-grant fencing, forged/wrong scope/key/version/nonce
requests and caller rows, exact retry, frozen later consumption and authenticated
time pruning, restart refusal, key rotation, changed recovery context, actual
30.1-second expiry, unknown missing history and an observed epoch above the target.

The first [expanded control attempt](p06-paginated-recovery-2026-10-04/control-final.log)
passes seven cases but fails fixture setup because the test guessed the journal
filename. [Corrected missing-history check](p06-paginated-recovery-2026-10-04/missing-history-corrected.log)
uses NodeIdentity's actual journal path and passes; the complete final ordinary
broker run also passes. This setup failure does not establish behavior.

Two private-copy mutation controls actually fail the intended assertions:
[digest comparison removed](p06-paginated-recovery-2026-10-04/digest-control.log)
and [higher observation clipped](p06-paginated-recovery-2026-10-04/epoch-clipping-control.log).
Both exit 101; copies are removed, production source hashes match, and normal
core/broker tests and broker binaries are reset before final Clippy. No production
fault hook or package/dependency change is introduced.

Node26 build/tests, workspace Rust, workspace/final Clippy, format, OpenAPI and
diff checks exit 0. Workspace results: 726 passed, 0 failed, 72
ignored across 78 result targets. Final broker has 325 library cases;
counts overlap. Raw [gate results](p06-paginated-recovery-2026-10-04/gates.json),
[counts](p06-paginated-recovery-2026-10-04/counts.json),
[controls](p06-paginated-recovery-2026-10-04/controls.json) and
[75 current source pins](p06-paginated-recovery-2026-10-04/source-pins.json)
retain the execution boundary. The protected user P03 record remains unstaged at
66 additions/0 deletions; the index is empty and no slice commit is made.

## Required remaining work

No actual node HTTPS recovery relay, independently current enrolled-key authority,
durable SQLite/PostgreSQL page/challenge consumer, provider/session cleanup,
authenticated previous-host/database stop, persistent authority review or protected
explicit activation is implemented or executed here. Generic report-event
admission stays closed. Disk-full/partial-write/power-loss snapshot faults, full
million-record producer resource limits, offline/rotated/pruned recovery variants,
actual two-broker stale restore, all three profiles, both transfer directions,
locked automatic-backup upgrades/retention3 and stock-client/VM/inherited gates
remain mandatory. Ordinary ignored suites and default SPS skips retain earlier
execution scope; this run does not execute those external/backend/GUI scenarios.
The separate PostgreSQL toolkit review remains pending; approval of external
PostgreSQL authority/SQLx does not approve that custom-dump toolkit. The full
nine-slice goal remains active.
