# P03 fleet authorization execution record

**Run date:** 2026-09-25
**Status:** Partial runtime evidence; P03 acceptance remains open.
**Runner owner:** `local-kvm-p03-final-rotation-20260925`

## Environment

The committed P03 runner built the controller, broker, and node relay and booted
two disposable Ubuntu 24.04 guests under QEMU/KVM. QEMU was 11.1.1, `/dev/kvm`
was readable and writable, and the pinned image SHA-256 was
`612b2c0cc1bc413a6cb8c38fd611794caf0f2b436c50013d8b3794db12ad7354`. The test
created temporary SSH and controller TLS keys, fixture credentials, database
state, and guest overlays. The successful run removed its temporary artifacts.

Command:

```bash
BLINDPASS_FLEET_RUNNER_OWNER=local-kvm-p03-final-rotation-20260925 \
  ./tests/fleet/p03-vm.sh --backend both
```

The run used isolated SQLite state for the first pass and a disposable
PostgreSQL schema for the second. The harness ended with
`P03-VM-COMPLETE ... backends=both guests=2 revocation=reconciled
recovery=passed` and exit status 0. No generated fixture values or private
keys were retained in the repository.

## Results

| Phase scenario | SQLite | PostgreSQL | Evidence |
|---|---|---|---|
| P03-I01 enrollment and key-rotation subset | Pass | Pass | HTTP integration covers one-use enrollment, key/fingerprint binding, replay and expiry rejection, staged rotation, candidate-key reconnect, old-key rejection, and revocation of the old session. The VM prepared a candidate pair in the broker, delivered the signed rotation, and observed broker application acknowledgement and controller key version 2 on each backend. |
| P03-I03/I04 approval queue subset | Pass | Pass | Two operations share an explicitly scoped group; a decision naming an operation from another group returns 409. The unified queue paginates two pending groups with `limit=1`, and the count converges from two to one after rejection. The test also updates policy before a stale decision. It does not race distinct operators or paginate beyond the legacy audit window. |
| P03-I06 partition/restart/replay subset | Pass | Pass | Broker event survives broker restart; node outbox survives a dropped application response and relay restart; both event queues drain after signed application acknowledgement. |
| P03-E01 two-host authorization and connected revocation | Pass; revocation applied in 1,499 ms | Pass; revocation applied in 955 ms | Two separately enrolled nodes completed approved dummy marker operations with node/workload/invocation/grant/audit linkage. An undelivered grant was revoked; the connected node applied and acknowledged its tombstone within the 30-second bound, and the old workload was denied after restart. |
| P03-E02 revoked-node recovery | Pass | Pass | The revoked identity remained denied after broker restart. Recovery archived the old identity, enrolled a distinct node identity, registered its workload, and completed a fresh approved operation. |

Portable Rust boundary tests cover the broker's 10,000-event audit buffer and
the relay's 1,000-event durable outbox. They verify fail-closed behavior at
capacity, recording overflow and recovery after space returns, and queue
restoration after reopening its state file. These checks do not simulate a
disk-full filesystem or exercise delayed duplicate events and purpose
sanitization.

## Remaining acceptance work

This execution does not establish complete P03 acceptance. It leaves the
remaining P03-I01 and P03-I02/I03/I04/I05 cases open; clock rollback,
suspend/resume, delayed-grant, version-mismatch and reconnect-storm cases in
P03-I06; full P03-I07 coverage; and the broader pilot catalog, including
E05–E07 and E10–E13. The broader P01/P02 inherited gates and P02.6 controller
cutover gate also remain prerequisites. The VM drives the authenticated
controller API directly; it does not exercise the administrator CLI or an
operator fleet UI. The CLI has separate authenticated HTTP integration tests.
Do not infer that an unlisted scenario passed from the two-backend VM run.
