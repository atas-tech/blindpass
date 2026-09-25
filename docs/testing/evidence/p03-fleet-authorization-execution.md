# P03 fleet authorization execution record

**Run date:** 2026-09-26
**Status:** Partial runtime evidence; P03 acceptance remains open.
**Runner owner:** `local-kvm-p03-i06-time-replay-20260926`

## Environment

The P03 runner built the controller, broker, and node relay and booted
two disposable Ubuntu 24.04 guests under QEMU/KVM. QEMU was 11.1.1, `/dev/kvm`
was readable and writable, and the pinned image SHA-256 was
`612b2c0cc1bc413a6cb8c38fd611794caf0f2b436c50013d8b3794db12ad7354`. The test
created temporary SSH and controller TLS keys, fixture credentials, database
state, and guest overlays. The successful run removed its temporary artifacts.

Command:

```bash
BLINDPASS_P03_KEEP_FAILED_ARTIFACTS=1 \
BLINDPASS_FLEET_RUNNER_OWNER=local-kvm-p03-i06-time-replay-20260926 \
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
| P03-I06 reconnect storm | Pass | Pass | The proxy returned 503 for three consecutive node polls. The relay recovered using bounded exponential backoff; measured intervals were 1,051/2,010 ms on SQLite and 1,106/2,094 ms on PostgreSQL. The node service remained active with zero systemd restarts on both backends. |
| P03-I06 signed time-reply replay after broker restart | Pass | Pass | The TLS proxy captured a genuine signed controller `TimeReply`, then replayed it once after broker and node restart against a fresh broker challenge. Each broker rejected exactly one stale reply; the node recovered with a fresh signed reply, advanced `last_poll_at`, and had zero systemd restarts. |
| P03-I06 suspend and guest wall-clock rollback | Pass | Pass | The controller grant was acknowledged by the broker with 18,882 ms remaining on SQLite and 18,875 ms on PostgreSQL. The guest then suspended and woke from an RTC alarm after 25,320/25,360 ms of BOOTTIME. After the guest wall clock was moved back two hours, workload consumption was denied and no marker was created. The disposable guest clock was restored. |
| P03-I06 delayed expired grant | Pass | Pass | The node's signed grant poll response was held for 10 seconds against an 8-second grant TTL. The broker discarded the expired grant, the controller stored exactly one typed `expired_before_receipt` audit event, and the durable event queues drained. The same grant was then denied by the revoked broker. |
| P03-E01 two-host authorization and connected revocation | Pass; revocation applied in 13,694 ms | Pass; revocation applied in 13,936 ms | Two separately enrolled nodes completed approved dummy marker operations with node/workload/invocation/grant/audit linkage. An undelivered grant was revoked; the connected node applied and acknowledged its tombstone within the 30-second bound, and the old workload was denied after restart. |
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

## Earlier supplemental P03-I06 protocol-mismatch VM run — 2026-09-26

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

## Supplemental P03-I06 delayed-grant VM verification — 2026-09-26

The final two-backend QEMU/KVM run held the first signed grant poll response for
10 seconds while the grant TTL was 8 seconds. The controller operation request
and grant used the same signed TTL. On both SQLite and PostgreSQL, the broker
discarded the expired grant at receipt, persisted one stable rejection event,
and drained the event queues after the controller accepted exactly one
`grant_rejected` audit row with reason `expired_before_receipt` and the signed
expiry time. The revoked grant and the old workload remained denied. Connected
revocation completed in 11,828 ms on SQLite and 12,370 ms on PostgreSQL. The
runner then archived the revoked identity, enrolled a distinct node, and
completed a fresh approved operation on both backends. The run ended with
`P03-VM-COMPLETE ... backends=both guests=2 revocation=reconciled
recovery=passed` and exit status 0; disposable artifacts were removed.

## Supplemental P03-I06 reconnect-storm VM verification — 2026-09-26

The clean two-backend QEMU/KVM run used a controlled proxy that returned HTTP
503 to three consecutive `POST /api/v3/node/poll` requests. The node was stopped
before proxy replacement so the measured intervals exclude proxy teardown. The
relay recovered on both backends using its bounded exponential retry schedule:
1,186 ms and 2,026 ms between failures on SQLite, and 1,209 ms and 2,493 ms on
PostgreSQL. In each guest, the node channel became active, `last_poll_at`
advanced, and systemd reported zero service restarts. The same run passed
partition/restart/replay, protocol-mismatch fail-stop/recovery, key rotation,
delayed expired-grant audit, E01 connected revocation and E02 identity recovery.
It ended with `P03-VM-COMPLETE ... backends=both guests=2
revocation=reconciled recovery=passed` and exit status 0; disposable artifacts
were removed.

## Supplemental P03-I06 suspend and wall-clock rollback VM verification — 2026-09-26

The two-backend QEMU/KVM run enabled ACPI S3 and used `rtcwake --mode mem` in
each guest. The 20-second grant was confirmed in an acknowledged `node_inbox`
row before suspension, with 19,003 ms remaining on SQLite and 18,691 ms on
PostgreSQL. Each guest suspended and woke from its RTC alarm; `/proc/uptime`
advanced by 25,730 ms and 25,670 ms, respectively. After wake, the guest wall
clock was set back two hours and the held grant ID was provided to the waiting
workload. The broker denied both consumes and neither guest created an operation
marker. The guest wall clocks were restored before the remaining revocation and
recovery scenarios. The run also passed the reconnect storm at 1,008/1,690 ms
on SQLite and 948/1,823 ms on PostgreSQL, with zero node-service restarts. E01
connected revocation completed in 11,916 ms and 12,048 ms, and E02 recovery
passed on both backends. The run ended with `P03-VM-COMPLETE ...
backends=both guests=2 revocation=reconciled recovery=passed` and exit status 0;
disposable artifacts were removed.

## Supplemental P03-I06 signed time-reply replay VM verification — 2026-09-26

The two-backend QEMU/KVM run captured the controller's genuine signed time
reply in the TLS test proxy's memory, restarted the broker and node to create a
new pending time challenge, then replayed the captured reply exactly once. On
SQLite and PostgreSQL the broker logged one rejection for a reply that did not
match its pending challenge. The relay remained active without systemd
restarts, then accepted a fresh signed reply and advanced `last_poll_at` beyond
the replay time. The same run passed reconnect recovery at 1,051/2,010 ms on
SQLite and 1,106/2,094 ms on PostgreSQL, guest suspension and wall-clock
rollback (25,320/25,360 ms BOOTTIME; 18,882/18,875 ms remaining at grant
acknowledgement), E01 connected revocation (13,694/13,936 ms), and E02 recovery
on both backends. The runner ended with
`P03-VM-COMPLETE runner_owner=local-kvm-p03-i06-time-replay-20260926
backends=both guests=2 revocation=reconciled recovery=passed` and exit status
0; disposable artifacts were removed.

## Final verification for the delayed-grant slice — 2026-09-26

`cargo test --workspace --locked -- --test-threads=1`, workspace Clippy with
warnings denied, Rust formatting, `npm run build`, and the host-access rerun of
`npm test` passed. The npm suite reported 80 passing tests and 101 skipped
tests across 17 gated SPS files. The PostgreSQL-only outage/recovery test was
also run explicitly and passed. `npm run test:controller-openapi` passed all
11 checks, and `npm run test:openapi-types --workspace=@blindpass/contract-tests`
passed its type and test checks. The first sandboxed `npm test` run could not
launch three MCP subprocesses; the same command passed with host process access.

The requested unsandboxed Socket deep scan resolved `pkg:cargo/reqwest` to
`reqwest` 0.12.22. Its aggregate supply-chain score was 12, with middle alerts
for native code, install scripts, network access and shell access, and a
transitive shell/unsafe capability. The dependency guard classifies this as
blocked. The node continues using its existing system `curl` transport; no
Cargo manifest or lockfile changed.

## Remaining acceptance work

This execution does not establish complete P03 acceptance. It leaves broader
P03-I05 cases open; controller clock rollback, guest/node reboot cases beyond
the broker-restart time-reply replay, delayed/replayed policy and revocation
cases in P03-I06; full P03-I07 coverage;
and the broader pilot catalog, including E05–E07 and
E10–E13. The broader P01/P02 inherited gates and P02.6 controller
cutover gate also remain prerequisites. The VM drives the authenticated
controller API directly; it does not exercise the administrator CLI or an
operator fleet UI. The CLI has separate authenticated HTTP integration tests.
Do not infer that an unlisted scenario passed from the two-backend VM run.
