# Protected recovery activation

How a restored controller (authority record `recovering`) becomes a serving controller. This is the
last stage of the [P06 recovery plan](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/phases/06-deployment-and-recovery.md);
decisions P06-D30–D32 and their trade-offs are in
[ADR 0014](../product/decisions/0014-p06-recovery-activation.md). The evidence and what it does **not**
establish are in the [activation record](../testing/evidence/p06-recovery-activation-2026-10-05.md).

Nothing in this procedure calls a provider or reads a secret value. It decides what happens to
*metadata* the restore quarantined, and it proves the old host stopped before the new one serves.

## Before you start

You have run the [restore stage](recovery-stage.md): the record is `recovering`, the restored
controller runs and answers `503 recovery_required`, and `blindpass admin recovery status` works against its local
administration socket. The old (source) controller must be unreachable by the time you attest in step 6.
Everything below runs on the host that holds the authority administrator credential, except steps 2–5
which use the recovering controller's local socket.

```text
fenced ──reserve_recovery──▶ recovering ──(this procedure)──▶ active
                                              relay · review · waive · complete │ stop · attest · activate
```

## The gates

Activation of a `recovering` record needs every gate. The ledger enforces them; the controller precheck
(`blindpass admin recovery status`) and the administrator precheck (`authority-recover-status.sql`) list the open
ones by fixed name.

| Gate | Met when | Who/what enforces |
|---|---|---|
| `source_stop_missing` | The authority administrator recorded an attestation row (who, host id, note, time) for this recovery epoch. | `attest_source_stop` (administrator only, never granted to the runtime role). It refuses unless the record is `recovering` **and** no process holds the tenant guard, so the attestation is made only while both controllers are stopped. |
| `source_process_live` | No process holds the tenant guard. | The ledger's lock, at activation time. The source and the recovering controller share one guard row (same tenant and owner), so a live holder on any host blocks activation. |
| `node_uncovered` | Every trusted (active) broker has a covered relay receipt for this epoch **or** an operator-recorded named waiver. | `recovery_activation_gaps`, from the authority's own broker trust, not the controller's snapshot. |
| `review_incomplete` | The operator review was completed. | `complete_recovery_review`; completion is refused while any enumerated item is undecided or any node is unaccounted for. |
| `review_undecided` | (controller precheck only) every enumerated item has a decision. | The controller; the authority checks that the number of decisions equals the count completed. |
| `not_recovering` | The record is `recovering`. | `activate_recovery`. |

Then **one** explicit command activates: `authority-recover-activate.sql`. No relay result, review
decision or attestation activates anything by itself.

## Procedure

1. **Reconcile each node.** On every node run `blindpass-node recovery-relay --controller https://…` against the
   recovering controller (verified HTTPS). Expect `state=covered … activation_permitted=false`. A page lost in flight
   leaves the receipt `rebase_required`; the only way forward is a higher protected reservation and a new restore.
2. **Review.** `blindpass admin recovery review list [--offset N]` shows every quarantined item with its
   category, subject and decision so far: operations (all `uncertain`), accounts, agents, workloads, policies,
   source bindings, pending node key rotations, and `grant_intent` items for grants a node reported that the controller could not
   reconcile (`unknown`, `conflicting` or `unmapped`; a `matched` grant is covered by its operation).
   Record a decision per item:
   `blindpass admin recovery review decide --category C [--subject S [--related R]] --decision accept|reject|revoke --operator ID [--note …]`.
   Without `--subject` the decision applies to every *undecided* item of the category. Decisions can change until step 4.
   - What a decision does. It is recorded in the authority with the operator id and note. `accept` means "reviewed, the
     controller may serve with this state". It never revives a revoked grant, agent, workload or operation: those stay
     revoked/uncertain and are re-issued through the ordinary flows. The one local effect is on **accounts**: completing the
     review re-enables operator accounts decided `accept` that the invalidation disabled (an account an administrator had
     disabled before the snapshot stays disabled).
3. **Waive a node that cannot report** (offline, lost, decommissioned):
   `blindpass admin recovery waive-node NODE --operator ID --note WHY`. The authority records who and why and revokes the node's broker
   trust in the same transaction; completing the review revokes the node in the controller too. The node must be re-enrolled
   after activation. A node that already reported cannot be waived.
4. **Complete the review.** `blindpass admin recovery review complete --operator ID`. Refused (nothing fenced, nothing changed)
   while an item is undecided or a trusted node is neither covered nor waived. **Completion is final:** decisions and waivers close.
   If something was missed after completing, restore again under a higher reservation.
5. **Check.** `blindpass admin recovery status` should list only `source_stop_missing`.
6. **Stop and attest.** Stop the recovering controller. Confirm the *source* host is stopped (power off, or cut it off
   the network and the database), then, as the authority administrator:
   ```bash
   psql -v ON_ERROR_STOP=1 -v tenant=TENANT -v owner=OWNER -v issuer=ISSUER_KEY_ID \
        -v host=SOURCE_HOST_ID -v by=ADMIN_ID -v note='how you know it is stopped' \
        -f authority-recover-attest.sql
   ```
   Refused while any process holds the guard. The row is insert-only: nobody, including the administrator, can edit or delete it.
   This works when the source host is gone — the attestation is your statement, and the ledger's guard check is the
   independent half. It is not proof that a source on a partitioned network is dead: the guard lock only sees processes that
   can still reach the authority database. Fence the source from the authority database before attesting.
7. **Precheck, then activate.**
   ```bash
   psql … -f authority-recover-status.sql     # prints the record and any open gate
   psql … -f authority-recover-activate.sql   # refuses naming the open gates, changes nothing
   ```
   `authority-activate.sql` still refuses a `recovering` record. Fencing a recovering record and then activating it with
   the ordinary script does not bypass anything: the controller leaves recovery only when the authority holds the activation
   proof written by `activate_recovery`, so such a controller stays `recovery_required`.
8. **Start the controller normally** (`serve`, or the packaged unit / Compose service). Like any start it consumes the
   activated revision, so a restart needs a fresh [`authority-activate.sql`](handoff.md). Check
   `blindpass status --nodes --require-online`. Nodes that reported reconnect without re-enrolment; waived nodes stay revoked.

## What stays true afterwards

- Recovered grants, agents, workloads, operations and approvals are not revived. Operations are `uncertain`; consumed grants
  stay consumed. Re-issue what you still need.
- The old source can never serve again: the record moved to a higher epoch and the source's database is at the old one. A
  source start is refused ([evidence](../testing/evidence/p06-recovery-activation-2026-10-05.md)). Retire its host and keys.
- **Rollback is restore-only.** Fence the activated controller, reserve a higher epoch, restore the archive again and repeat this
  procedure. Grants the node consumed since the archive appear as `grant_intent` items to decide. Each recovery epoch has its
  own attestation, decisions and activation row.
- The evidence tables (`recovery_source_stop`, `recovery_node_waivers`, `recovery_review_decisions`, `recovery_review_complete`,
  `recovery_activations`) are in the authority database, outside controller backups, and are insert-only (decisions can change
  only until completion).

## Failure behaviour

| Situation | Result |
|---|---|
| A decision, waiver or completion the authority refuses (completed review, lost holder, wrong node) | An answer to the operator (`refused`); the controller stays recovering and is **not** fenced. |
| The authority is unreachable during a review command | The recovering controller fences itself (`authority_fenced`); re-reserve and restore again. |
| Attest while any process holds the guard | Lock error; nothing written. |
| Activate with any gate open | Error naming the gates; nothing changed. |
| The activated controller's start fails after activation | The revision is spent; run `authority-activate.sql` before the next start. |

## Layout 5 upgrade of an existing authority

Layout 5 is a separate migration. As the authority administrator, with every tenant fenced and no process holding a guard:

```bash
psql -v ON_ERROR_STOP=1 -v runtime_role=RUNTIME_ROLE -f deploy/controller/recovery-authority-v4-to-v5.sql
```

It refuses an active tenant, a held guard and a non-v4 layout, and it keeps all existing trust, receipts and tenants. The
controller refuses a layout-4 authority at start; startup never migrates. New installations get layout 5 from
`recovery-authority.sql`.

## Packaged profiles

The same procedure runs on the packaged profiles; only the restore step differs.

| Profile | Restore step | Harness |
|---|---|---|
| Compose SQLite / PostgreSQL | `controller-restore` and `controller-restore-install` jobs of `compose.restore-<profile>.yml` ([guide](compose-quickstart.md#restore-and-recovery-activation-on-this-profile)) | `compose-up.py --profile sqlite\|postgres --scenario recovery` |
| Native package (SQLite) | packaged `blindpass-controller-restore.service` (offline custody and a private environment file written for the restore only), then copy the restored `data` and `keys` ([guide](native-quickstart.md#restore-and-recovery-activation-on-the-native-package)) | `native-install.sh --os debian-12\|ubuntu-24.04 --recovery` |

Both harnesses run the refusals (ordinary activation of a `recovering` record, recovery activation before the gates are met,
attestation while a controller holds the guard, completion with an undecided review or an uncovered node), a named
waiver, completion, attestation, activation, a refused second activation, a restore into a second Compose project with fresh volumes (Compose; the original stack stays refused
and the restored one keeps serving) and a restore-based rollback that needs its own review, attestation and activation. The native
harness additionally runs `--faults` (SIGKILL, SIGSTOP, database loss) against an activated controller. See the [packaged recovery record](../testing/evidence/p06-packaged-recovery-2026-10-05.md).

## Not covered

No provider API is called and no secret is read; "revoke" is metadata. Nothing here proves a provider-side effect did or did not
happen. Two real nodes (two QEMU guests, covered and waived variants and the refusal) and a PostgreSQL controller (backup, restore and
activation through the pinned toolkit image) are exercised by the host-controller QEMU harnesses, see the
[recovery matrix record](../testing/evidence/p06-recovery-matrix-2026-10-05.md); those runs use a controller process on the host
and the toolkit image only for backup and restore, so they are not a packaged PostgreSQL recovery. The `compose-up.py` and `native-install.sh` recovery runs have **no real node**: one seeded broker trust row is covered only by a named
waiver. A real node against the **Compose** profiles (SQLite and PostgreSQL: relay covered and waived, activation, the unchanged node
returning, an ordinary grant) is proven by the [Compose node record](../testing/evidence/p06-compose-node-2026-10-05.md), and a real node
against the **native package** (Ubuntu 24.04 and Debian 12 controller guests: packaged backup and restore units, relay covered and waived,
activation, the unchanged node returning in 3.1-4.3 s, an ordinary grant) by the [native node record](../testing/evidence/p06-native-node-2026-10-05.md).
Those native runs use one host, the guest's own PostgreSQL as the authority and the P03 node units; the native package has no PostgreSQL
backend. A stale source is proven for a stopped source on the same machine: on Compose the same archive is restored into a second
project, activated, and the original stack never serves (P06-RC8); on the native package the original state is refused both as a second
instance of the packaged unit while the restored controller serves (the authority guard and `startup_failed`) and swapped into the
service paths after an ordinary activation (`recovery_required`, its database byte-unchanged).
A source that is still running on another machine is covered only by the authority's guard and the operator's attestation.
