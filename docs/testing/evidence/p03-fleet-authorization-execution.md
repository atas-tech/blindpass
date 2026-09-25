# P03 fleet authorization execution record

**Run date:** 2026-09-25
**Status:** Partial runtime evidence; P03 acceptance remains open.
**Runner owner:** `local-kvm-p03-acceptance-20260925`

## Environment

The committed P03 runner built the controller, broker, and node relay and booted
two disposable Ubuntu 24.04 guests under QEMU/KVM. QEMU was 11.1.1, `/dev/kvm`
was readable and writable, and the pinned image SHA-256 was
`612b2c0cc1bc413a6cb8c38fd611794caf0f2b436c50013d8b3794db12ad7354`. The test
created temporary SSH and controller TLS keys, fixture credentials, database
state, and guest overlays. The successful run removed its temporary artifacts.

Command:

```bash
BLINDPASS_FLEET_RUNNER_OWNER=local-kvm-p03-acceptance-20260925 \
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
| P03-I01 enrollment, key rotation and revocation | Pass | Pass | HTTP integration covers one-use enrollment, signing- and recipient-key substitution rejection, key/fingerprint binding, replay and expiry rejection, staged rotation, candidate-key reconnect, old-key rejection, node revocation and old-identity reconnect rejection. The VM prepared a candidate pair in the broker, delivered the signed rotation, and observed broker application acknowledgement and controller key version 2 on each backend. |
| P03-I02 workload identity and API authorization subset | Pass | Pass | Core identity tests reject changed node, workload, unit, invocation, and peer-account bindings; protocol parsing rejects an extra caller-supplied account. HTTP integration rejects signed broker evidence with mismatched node, workload, unit, account, or invocation, and unauthenticated mapping and policy edits return 401. Purpose text asking to bypass approval remains approval-gated; control characters are sanitized and markup remains text data. |
| P03-I03 approval decision subset | Pass | Pass | Two distinct authenticated administrators race approve and reject on one approval; exactly one receives 200 and the other receives 409. Operation scoping and stale-policy rejection also pass. |
| P03-I04 unified approval queue subset | Pass | Pass | Seeds 101 pending approval groups, reads 100 and follows the cursor, makes a decision while paging, expires the last item, and verifies queue/count convergence from 101 to 100 to 99. SQLite and PostgreSQL runs pass. |
| P03-I05 grant and signed-envelope binding subset | Pass | Pass | Consume rejects changed node, workload, unit, invocation, operation, and policy version; receipt rejects changed registration node/workload/unit/account/mode/invocation, revoked registration, and wrong audience. Envelope tampering of body, kind, key ID, or epoch is rejected; the controller rejects a forged broker-event signature. Two concurrent consumers produce exactly one successful consume and marker. |
| P03-I06 partition/restart/replay and protocol-mismatch subset | Pass | Pass | Broker event survives broker restart; node outbox survives a dropped application response and relay restart; both event queues drain after signed application acknowledgement. A two-guest VM run injects HTTP 426 into the relay, confirms systemd records exit 78 with zero restarts, then restores the proxy and verifies node reconnection. |
| P03-E01 two-host authorization and connected revocation | Pass; revocation applied in 1,484 ms | Pass; revocation applied in 1,548 ms | Two separately enrolled nodes completed approved dummy marker operations with node/workload/invocation/grant/audit linkage. An undelivered grant was revoked; the connected node applied and acknowledged its tombstone within the 30-second bound, and the old workload was denied after restart. |
| P03-E02 revoked-node recovery | Pass | Pass | The revoked identity remained denied after broker restart. Recovery archived the old identity, enrolled a distinct node identity, registered its workload, and completed a fresh approved operation. |

Portable Rust boundary tests cover the broker's 10,000-event audit buffer and
the relay's 1,000-event durable outbox. They verify fail-closed behavior at
capacity, recording overflow and recovery after space returns, queue restoration
after reopening its state file, and a simulated broker restart after fsynced
consume intent but before the operation marker effect. The grant remains
unreceivable and no marker is created after restart. Purpose tests confirm
bypass wording cannot skip approval and control characters are sanitized. These
checks do not simulate a disk-full filesystem or exercise all delayed duplicate
events and full audit-queue recovery paths.

## Supplemental P03-I05 verification — 2026-09-26

The focused grant-binding and simulated crash-boundary tests passed. The fleet
enrollment HTTP integration passed against SQLite and PostgreSQL, including
rejection of a forged broker-event signature. `cargo test --workspace --locked`
passed with the existing PostgreSQL-outage test ignored; workspace Clippy,
formatting, and `git diff --check` passed. The initial sandboxed workspace run
was interrupted after socket-dependent tests failed and stalled; the successful
workspace run used host socket permissions.

Focused timing tests also passed. A grant received 20 seconds after the signed
time sample gets only its remaining 40-second lifetime; advancing the supplied
BOOTTIME value to its deadline denies use. Expired and over-age grants, plus a
time reply beyond the 35-second challenge bound, are rejected. The BOOTTIME
advance is deterministic simulation, not evidence from suspending a guest VM.

## Supplemental P03-I07 verification — 2026-09-26

The full broker audit buffer now writes its 10,000 queued events and overflow
state to the private mode-0600 outbox, restores them after broker restart, and
records the overflow event after an authenticated acknowledgement frees space.
A forced atomic outbox-commit failure denies an operation request, leaves the
queue unchanged, and removes the temporary file. This exercises persistence
failure handling but does not simulate a disk-full filesystem.

## Supplemental P03-I01 verification — 2026-09-26

The enrollment HTTP integration now changes only `recipient_pub` while keeping
the original proof and requires HTTP 400. The legitimate key submission then
succeeds, and replaying that one-use submission returns HTTP 410. The focused
`fleet_enrollment` integration passed against SQLite and the disposable local
PostgreSQL service; both runs include the one-use, expiry, fingerprint,
rotation, revocation and reconnect checks listed above. The PostgreSQL run
used an isolated schema, which the test dropped on completion.

The final repository gates for this slice passed: `cargo test --workspace
--locked` (the existing PostgreSQL-outage test remained ignored), workspace
Clippy, Rust formatting, `npm run build`, and `npm test`. The JavaScript suite
reported 101 skipped tests across 17 skipped SPS test files. Its first
restricted run had three MCP child-process launch failures; the host-access
rerun passed those launch checks.

## Supplemental P03-I06 protocol-mismatch VM verification — 2026-09-26

The two-guest harness ran on QEMU 11.1.1 with the pinned Ubuntu image and
writable `/dev/kvm`, against SQLite and PostgreSQL. In each backend, the TLS
proxy injected HTTP 426 into the live node relay. The systemd service reached
`failed` with `ExecMainStatus=78` and `NRestarts=0`, and its journal reported
the incompatible controller protocol. After the proxy returned to normal
forwarding, the same node reconnected and reported a fresh `last_seen_at`.
Both backend runs completed the existing two-host operation, connected
revocation and distinct-identity recovery scenarios; revocation applied in
1,489 ms on SQLite and 896 ms on PostgreSQL. The harness ended with
`P03-VM-COMPLETE ... backends=both guests=2 revocation=reconciled
recovery=passed` and exit status 0.

The relay now maps HTTP 426 to exit status 78, and its systemd unit prevents
that status from entering an automatic restart loop. Unit coverage checks the
exit mapping, unit setting, exponential backoff cap and 80–120% jitter bounds.
Final gates passed: `cargo test --workspace --locked -- --test-threads=1`
(the existing PostgreSQL-outage test remained ignored), workspace Clippy,
Rust formatting, `npm run build`, and `npm test`. The JavaScript suite reported
101 skipped tests across 17 skipped SPS test files. The initial parallel Rust
workspace run hit a transient `Text file busy` in a CLI migration test; the
serial rerun passed.

## Remaining acceptance work

This execution does not establish complete P03 acceptance. It leaves broader
P03-I05 cases open; real VM clock changes,
suspend/resume, delayed-grant relay and reconnect-storm cases in P03-I06; full
P03-I07 coverage; and the broader pilot catalog, including E05–E07 and
E10–E13. The broader P01/P02 inherited gates and P02.6 controller
cutover gate also remain prerequisites. The VM drives the authenticated
controller API directly; it does not exercise the administrator CLI or an
operator fleet UI. The CLI has separate authenticated HTTP integration tests.
Do not infer that an unlisted scenario passed from the two-backend VM run.
