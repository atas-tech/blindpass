# 0014: P06 protected recovery activation (source-stop proof, node gate, operator review)

**Status:** Accepted by the project owner on 2026-10-05 (P06-D30, D31, D32), implemented and gated as recorded in the [execution record](../../testing/evidence/p06-recovery-activation-2026-10-05.md). This extends the authority of [0012](0012-p06-external-recovery-authority.md) (layout 5). It does **not** establish P06 acceptance: the record lists what still blocks it.

## Context

After a restore the authority record is `recovering` and the restored controller answers `503 recovery_required`. Nothing could move it to a serving state: `authority-activate.sql` refuses `recovering`, and the controller's local recovery latch (any `controller_recoveries` row) was permanent. Three questions were open: what proves the old host is stopped, when are the nodes reconciled enough, and who decides what to do with the uncertain operations, grants and accounts the restore quarantined.

A fact shaped every answer: the source and the recovering controller share one tenant guard row (same tenant, same owner id). An attestation can therefore only be recorded while *both* are stopped, and the controller that gathers the review evidence cannot be the one that activates.

## Decision

1. **Source-stop proof (D30).** The authority verifies mechanically that the tenant guard is free and the record is `recovering`, and the authority administrator records an attestation row (who, host id, note, when). Activation requires that row. The administrator-only function `attest_source_stop` refuses while any process holds the guard. It works when the source host is lost because the attestation is the administrator's statement and the lock is the independent half.
2. **Activation gate (D31).** Every trusted broker has a covered relay receipt for the recovery epoch, **or** an operator-recorded named waiver (the node stays revoked: the waiver revokes its broker trust in the authority in the same transaction, and completing the review revokes it locally). Every enumerated review item has a decision. The attestation exists. Then **one** explicit command, `authority-recover-activate.sql`, moves `recovering` to `active` (`activate_recovery`, administrator only) and writes the activation proof row.
3. **Provider review (D32).** An operator review lists the quarantined operations, accounts, agents, workloads, policies, source bindings, pending node key rotations and the grants a node reported but the controller could not reconcile (`grant_intent`), from the existing controller recovery tables. Each gets `accept`, `reject` or `revoke` with operator id and note; decisions are stored in the authority, replaceable until a final completion step. No provider API is called; "revoke" is metadata.
4. **Where the evidence lives.** In the authority at layout 5 (`recovery_source_stop`, `recovery_node_waivers`, `recovery_review_decisions`, `recovery_review_complete`, `recovery_activations`), insert-only, outside controller backups, written by the live recovering holder (decisions, waivers, completion) or the administrator (attestation, activation). The controller schema did not change.
5. **Leaving recovery requires the proof.** The controller's recovery latch is released at start only when the authority holds a `recovery_activations` row for exactly the recovery's target epoch **and** this process holds the active record at that epoch. Fencing a recovering record and activating it with `authority-activate.sql` yields an active record without that row, so the controller stays `recovery_required` (tested).

## Alternatives considered

- **Attestation only (no mechanical guard check).** Rejected: a typo or a stale belief would activate over a live source. The ledger lock costs nothing and catches live holders.
- **Mechanical proof only.** Impossible: the lock cannot see a source on a partitioned network or a lost host; some human statement is unavoidable, so it is recorded with a name.
- **All nodes must report (no waiver).** Rejected: one dead node would block the whole fleet forever. A waiver is explicit, named, revokes the node and is final.
- **Decisions in the controller database.** Rejected: the restored database is the thing being distrusted, and a bumped controller schema touches backup/restore/upgrade for every deployment. The authority already has the proof discipline.
- **A controller-side `activate` command.** Rejected: the activating party must be the authority administrator with the guard free, not the recovering process.
- **Making accept revive items.** Rejected: acceptance of a revoked grant or agent would re-create authority the restore deliberately destroyed. Accounts are the one exception because operators must be able to log in to finish the work.

## Trade-offs and limits

- The authority can only count decisions; item enumeration is controller-side. A controller that omitted items could complete early. The controller computes the set from its own recovery tables and refuses completion while any item is undecided.
- Completion is final. A missed item after completion means restoring again under a higher reservation (rollback is restore-only anyway).
- The administrator's attestation is trusted; the ledger cannot prove a partitioned source dead. The runbook says to fence the source from the authority database before attesting.
- `grant_intent` items only cover non-`matched` grants; matched grants are covered by their operation's decision.
- Waiver means re-enrolment later. There is no un-waive.
- A start after activation consumes the activated revision like any start (D12); a restart needs `authority-activate.sql`.
- The upgrade for an existing authority is a separate layout 4→5 migration (administrator, all tenants fenced, no guard held).

## Consequences

- New runtime-role grants: SELECT on the five tables and EXECUTE on four functions; the runtime role is audited at start and refuses the two administrator functions.
- Packaging ships the three `authority-recover-*.sql` scripts and the migration.
- P06 acceptance still needs the items listed in the record (multi-node recovery against real nodes, Compose/native recovery, PostgreSQL controller recovery in a VM, provider-side review semantics).
