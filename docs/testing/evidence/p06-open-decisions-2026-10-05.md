# P06 open decisions and what each unblocks — 2026-10-05

Four items are blocked on a project-owner decision, not on more testing. Each has a recommendation; none has been implemented. Everything else still open for P06 needs hardware or a longer rehearsal and is listed in the [relay VM record](p06-relay-vm-2026-10-05.md), the [Compose fault subset](p06-parity-faults-2026-10-05.md) and the [aarch64 record](p06-aarch64-emulated-2026-10-05.md).

## 1. Slice 8 route: planned handoff or wait for recovery activation

**Fact:** `blindpass restore` always produces a fenced destination under a `recovering` authority record, and `deploy/controller/authority-activate.sql` refuses that state. Activation after recovery needs node reconciliation (the relay now works, RR03/RR04 subset), provider review, a source-stop proof and an explicit activation step, none of which exists. So a restore-based migration or rollback never reaches a serving controller, and P06-E02 and the restore rollback rehearsal cannot finish.

| Option | What it is | Cost / risk |
| --- | --- | --- |
| A (recommended) | Planned same-owner handoff for E02: fence the source (`authority-fence.sql`), stop cleanly, copy the quiesced database and keys, activate the destination with the same owner id (a `fenced` record already activates). Keep restore for disaster recovery. | Preserves identity, epoch and node trust with no reconciliation. Two-writer rejection rests on the authority's tenant guard alone; SQLite WAL/checkpoint and `reconcile_clock` boot-ID behavior across hosts are unmeasured; native↔Compose also needs one authority both sides can reach. Differs from P06-D4 text, which would need amending. |
| B | Hold slice 8 until recovery activation exists | No new mechanism; E02 and rollback rehearsal stay blocked through the pilot |

Unblocks: slice 8 (both directions with interrupts), the restore-based rollback rehearsal (under B only after activation exists), `status --nodes` use as the reconnect gate (the command already exists).

## 2. D12: fence only on a definite epoch mismatch?

**Fact:** the owner fences on any unanswerable epoch check, so a PostgreSQL outage forces a fresh activation after the database returns (O07 asserts this; the Compose gate shows it).

Recommendation: keep the current fail-closed behavior for the pilot and document the operational cost in the runbook. Narrowing it to a definite mismatch trades safety (a partitioned owner could keep serving) for availability, and no measurement supports the trade yet. If changed, O07 and the P06-D12 text change with it.

## 3. `node_key_version` pinning on the recovering lane

**Fact:** `/api/recovery/request` takes the node key version from the caller and the first open wins in `blindpass_authority.open_recovery_challenge`. While a rotation is pending, an outsider who can reach the recovering lane can pin the wrong key, so the real node's page then fails verification. It cannot forge pages (signatures are checked against the bound key); the effect is denial of service of that node's report.

| Option | Cost |
| --- | --- |
| A (recommended for the pilot) | Accept as a DoS-only risk on a lane that is private to the recovery operator, state it in the runbook and the threat notes, fix before wider exposure. No schema change. |
| B | Let an unstaged `collecting` challenge be superseded by a new open (still bounded by the fresh broker nonce). Needs a change to `open_recovery_challenge` in `recovery-authority.sql` and the v3-to-v4 script, a layout bump to v5 with migration and tests; an interleaving outsider could still race the real node. |

## 4. ADR 0010 key custody split

**Fact:** one recovery credential both signs and decrypts backups, and plaintext key material is staged under the output directory. A compromise of that one credential forges and reads archives.

Recommendation: before acceptance, split signing (operator-held, not on the controller host) from the decryption recipient key (sealed or HSM-backed) and stage restored keys on tmpfs. Status quo is acceptable only for a pilot with the credential held offline and rotated. This needs an ADR (proposed text not written) and changes to backup create/verify/restore formats, so it should be decided before more archive tooling is added.

## Not decisions, just work

Native aarch64 hardware, the full slice 9 parity matrix (native, remote controller, stock client, loaded bounds), RR05 (activation, source-stop proof, provider review, two-broker recovery) and multi-release upgrade chains.
