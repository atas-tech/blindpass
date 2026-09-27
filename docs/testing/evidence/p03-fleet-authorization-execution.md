# P03 fleet authorization execution record

**Run date:** 2026-09-26; latest full run 2026-09-27
**Status:** Local runtime evidence for the implemented P03 scope; acceptance review, hosted runs and inherited gates remain open.
**Runner owner:** `local-kvm-p03-i06-reboot-final-20260926`; latest `local-kvm-p03-finish-20260927`

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
BLINDPASS_P03_SSH_PORT_A=22322 \
BLINDPASS_P03_SSH_PORT_B=22323 \
BLINDPASS_FLEET_RUNNER_OWNER=local-kvm-p03-i06-reboot-final-20260926 \
  ./tests/fleet/p03-vm.sh --backend both
```

The run used isolated SQLite state for the first pass and a disposable
PostgreSQL schema for the second. The harness ended with
`P03-VM-COMPLETE runner_owner=local-kvm-p03-i06-reboot-final-20260926
backends=both guests=2 revocation=reconciled recovery=passed` and exit status
0. No generated fixture values or private keys were retained in the repository.

## Results

| Phase scenario | SQLite | PostgreSQL | Evidence |
|---|---|---|---|
| P03-I01 enrollment, key rotation and revocation | Pass | Pass | HTTP integration covers one-use enrollment, signing- and recipient-key substitution rejection, key/fingerprint binding, replay and expiry rejection, staged rotation, candidate-key reconnect, old-key rejection, node revocation and old-identity reconnect rejection. The VM prepared a candidate pair in the broker, delivered the signed rotation, and observed broker application acknowledgement and controller key version 2 on each backend. |
| P03-I02 workload identity and API authorization subset | Pass | Pass | Core identity tests reject changed node, workload, unit, invocation, and peer-account bindings; protocol parsing rejects an extra caller-supplied account. HTTP integration rejects signed broker evidence with mismatched node, workload, unit, account, or invocation, and unauthenticated mapping and policy edits return 401. Purpose text asking to bypass approval remains approval-gated; control characters are sanitized and markup remains text data. |
| P03-I03 approval decision subset | Pass | Pass | Two distinct authenticated administrators race approve and reject on one approval; exactly one receives 200 and the other receives 409. Operation scoping and stale-policy rejection also pass. |
| P03-I04 unified approval queue subset | Pass | Pass | Seeds 101 pending approval groups, reads 100 and follows the cursor, makes a decision while paging, expires the last item, and verifies queue/count convergence from 101 to 100 to 99. SQLite and PostgreSQL runs pass. |
| P03-I05 grant and signed-envelope binding subset | Pass | Pass | Consume rejects changed node, workload, unit, invocation, operation, and policy version; receipt rejects changed registration node/workload/unit/account/mode/invocation, revoked registration, and wrong audience. Envelope tampering of body, kind, key ID, or epoch is rejected; the controller rejects a forged broker-event signature. Two concurrent consumers produce exactly one successful consume and marker. |
| P03-I06 partition/restart/replay and protocol-mismatch subset | Pass | Pass | Broker event survives broker restart; node outbox survives a dropped application response and relay restart; both event queues drain after signed application acknowledgement. A two-guest VM run injects HTTP 426 into the relay, confirms systemd records exit 78 with zero restarts, then restores the proxy and verifies node reconnection. |
| P03-I06 reconnect storm | Pass | Pass | The proxy returned 503 for three consecutive node polls. The relay recovered using bounded exponential backoff; measured intervals were 1,037/2,380 ms on SQLite and 1,162/2,216 ms on PostgreSQL. The node service remained active with zero systemd restarts on both backends. |
| P03-I06 signed time-reply replay after broker restart | Pass | Pass | The TLS proxy captured a genuine signed controller `TimeReply`, then replayed it once after broker and node restart against a fresh broker challenge. Each broker rejected exactly one stale reply; the node recovered with a fresh signed reply, advanced `last_poll_at`, and had zero systemd restarts. |
| P03-I06 suspend and guest wall-clock rollback | Pass | Pass | The controller grant was acknowledged by the broker with 18,643 ms remaining on SQLite and 18,850 ms on PostgreSQL. The guest then suspended and woke from an RTC alarm after 25,150/25,850 ms of BOOTTIME. After the guest wall clock was moved back two hours, workload consumption was denied and no marker was created. The disposable guest clock was restored. |
| P03-I06 delayed expired grant | Pass | Pass | The node's signed grant poll response was held for 10 seconds against an 8-second grant TTL. The broker discarded the expired grant, the controller stored exactly one typed `expired_before_receipt` audit event, and the durable event queues drained. The same grant was then denied by the revoked broker. |
| P03-I06 guest reboot with unconsumed grant | Pass | Pass | A full guest reboot changed the kernel boot ID. The broker/node channel recovered with zero node-service restarts; each pre-reboot grant still had more than 107 seconds remaining, was denied when presented after reboot, and created no marker. A new grant then completed with one audited result. |
| P03-I06 delayed signed policy replay and cursor recovery | Pass | Pass | The TLS proxy replayed signed policy version 2 after deny version 3 with a synthetic outer sequence. The broker retained version 3 and denied a fresh workload. The relay then reconciled the conflicting sequence and delivered signed deny version 4 without a node-service restart; fresh workloads were denied before and after a later channel restart, with no new marker. |
| P03-I06 signed grant revocation replay | Pass | Pass | The TLS proxy captured a genuine signed grant revocation for the recovered node. The broker denied the held grant, persisted one private tombstone, retained it across broker restart, then applied and acknowledged the replayed signed revocation without a duplicate journal record or node-service restart. |
| P03-E01 two-host authorization and connected revocation | Pass; revocation applied in 14,435 ms | Pass; revocation applied in 13,920 ms | Two separately enrolled nodes completed approved dummy marker operations with node/workload/invocation/grant/audit linkage. An undelivered grant was revoked; the connected node applied and acknowledged its tombstone within the 30-second bound, and the old workload was denied after restart. |
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

## Supplemental P03-I06 broker policy and revocation replay tests — 2026-09-26

Focused broker control-socket tests passed for delayed policy version 4 after
version 5, both before and after broker restart; the newer policy stayed
active and persisted. Replaying a grant revocation after restart remained
idempotent, and presenting the revoked signed grant again was denied after a
fresh signed time challenge. Replaying an acknowledged node revocation after
restart left the node revoked and did not create a duplicate acknowledgement
event. These broker-local checks use the same code for both controller
database backends; they do not exercise the controller database or
delays/replays through the node HTTPS transport. The focused command passed
all 7 matching tests:

```bash
cargo test -p blindpass-broker --locked control::tests:: -- --test-threads=1
```

## Supplemental P03-I06 guest-reboot VM verification — 2026-09-26

The final two-backend QEMU/KVM run added a full systemd guest reboot after the
broker had acknowledged a 120-second grant but before the workload received it.
Both guests returned with a different kernel boot ID. The node channel resumed
polling with zero service restarts, and the old grant still had 107,227 ms
remaining on SQLite and 107,540 ms on PostgreSQL. Presenting either old grant
after boot failed closed without a marker or completion event. A fresh
post-reboot grant completed and produced exactly one audited result on each
backend. The run also repeated the partition/restart/replay, protocol-mismatch,
reconnect storm (1,037/2,380 ms on SQLite and 1,162/2,216 ms on PostgreSQL),
signed time-reply replay, suspend and wall-clock rollback (25,150/25,850 ms
BOOTTIME), delayed expired-grant audit, key rotation, two-host authorization,
connected revocation (14,435/13,920 ms), and revoked-node recovery scenarios.
It ended with `P03-VM-COMPLETE
runner_owner=local-kvm-p03-i06-reboot-final-20260926 backends=both guests=2
revocation=reconciled recovery=passed` and exit status 0. The pinned Ubuntu
24.04 guests used QEMU 11.1.1 and the reviewed image hash recorded above;
temporary overlays and keys were removed.

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

## Supplemental P03-I06 delayed policy replay VM verification — 2026-09-26

A two-backend QEMU/KVM run captured the controller's signed policy snapshot
version 2 in the TLS test proxy. After the administrator installed signed deny
policy version 3, the proxy delivered the newer policy, then injected the older
signed snapshot with a synthetic outer poll sequence. On both SQLite and
PostgreSQL, the relay acknowledged the injected document while the broker kept
policy version 3 with no allowed actions. A new workload invocation was denied
by the broker's local policy, with no operation request, completion, or new
marker. After the node channel restarted and completed two fresh authenticated
polls, another new invocation was denied the same way. This exercises an
on-path relay replaying a genuine older signature; it does not establish
revocation replay coverage or liveness after every forged transport sequence.

The full runner repeated the other P03-I06, P03-E01 and P03-E02 cases on both
backends and ended with exit status 0:

```text
P03-VM-COMPLETE runner_owner=local-kvm-p03-policy-replay-diagnostic-20260926 backends=both guests=2 revocation=reconciled recovery=passed
```

The host used QEMU 11.1.1, writable `/dev/kvm`, and the pinned Ubuntu 24.04
image hash recorded above. Connected revocation took 13,898 ms on SQLite and
14,056 ms on PostgreSQL, within the 30-second phase bound. The command was:

```bash
BLINDPASS_P03_KEEP_FAILED_ARTIFACTS=1 \
BLINDPASS_P03_SSH_PORT_A=22322 \
BLINDPASS_P03_SSH_PORT_B=22323 \
BLINDPASS_FLEET_RUNNER_OWNER=local-kvm-p03-policy-replay-diagnostic-20260926 \
  ./tests/fleet/p03-vm.sh --backend both
```

The workload client now stops retrying explicit local-policy and revoked-node
denials. The VM helper requires a newly recorded systemd invocation and compares
the marker count before and after each denial. Earlier diagnostic runs exposed
an invocation observation race and an absent marker directory after broker
restart; these were harness failures, not acceptance passes. The final run
passed after those assertions were corrected. `npm run build`, `npm test`,
`cargo test --workspace --locked`, workspace Clippy with warnings denied,
Rust formatting, shell syntax, proxy Python compilation and `git diff --check`
passed. The default npm suite still skipped 101 service-gated SPS tests across
17 files, and the Rust workspace gate ignored its PostgreSQL-only outage test.

## Supplemental P03-I06 transport cursor recovery VM verification — 2026-09-26

The relay now clears its in-memory poll acknowledgement cursor when the
controller returns a sequence that is no greater than the cursor. It retries
the authenticated session and applies only broker-verified signed documents.
This addresses the liveness gap exposed by the synthetic outer sequence in the
older policy replay. A focused Rust regression test first failed because the
cursor reconciliation was absent, then passed with the fix.

The full QEMU/KVM rerun passed on SQLite and PostgreSQL. After the proxy
replayed signed policy version 2 behind version 3, the controller issued signed
deny policy version 4. Each guest applied version 4 without a node-service
restart, and a new workload invocation was denied by local policy with no new
marker. Both guests stayed denied after a later channel restart. Connected
revocation completed in 13,784 ms on SQLite and 14,017 ms on PostgreSQL. The
run ended with exit status 0:

```text
P03-VM-COMPLETE runner_owner=local-kvm-p03-policy-cursor-recovery-20260926 backends=both guests=2 revocation=reconciled recovery=passed
```

The rerun used the pinned Ubuntu image, QEMU 11.1.1 and writable `/dev/kvm`.
Its command was:

```bash
BLINDPASS_P03_KEEP_FAILED_ARTIFACTS=1 \
BLINDPASS_P03_SSH_PORT_A=22322 \
BLINDPASS_P03_SSH_PORT_B=22323 \
BLINDPASS_FLEET_RUNNER_OWNER=local-kvm-p03-policy-cursor-recovery-20260926 \
  ./tests/fleet/p03-vm.sh --backend both
```

This checks delivery of one later signed policy after a forged sequence and
denial across a channel restart. It does not cover repeated adversarial
sequence injection, node-revocation replay through transport, or the remaining
P03 acceptance matrix.

The final `cargo test --workspace --locked`, `cargo clippy --workspace
--all-targets --locked -- -D warnings`, `cargo fmt --all -- --check`,
`npm run build`, `npm test`, shell syntax and `git diff --check` gates passed.
The default Rust test command ignored the PostgreSQL-only outage test, and the
default npm run skipped 101 service-gated SPS tests across 17 files.

## Supplemental P03-I06 signed grant revocation replay VM verification — 2026-09-26

The two-guest QEMU/KVM runner captured a genuine controller-signed grant
revocation in the TLS proxy after the recovered node received a live,
unconsumed grant. On each backend, the broker wrote one private mode-0600
revocation journal record and denied the waiting workload when it presented
that grant; no operation marker was created. After broker and node restart, the
journal still held exactly one tombstone. The proxy then injected the same
signed revocation with a synthetic outer poll sequence. The broker applied it,
the relay acknowledged it, and the journal still held one record. The node
service had zero automatic restarts, and the controller grant remained revoked.

SQLite and PostgreSQL both passed this new case alongside the existing P03 VM
scenarios. Connected node revocation took 13,667 ms and 14,538 ms,
respectively. The run ended with status 0:

```text
P03-VM-COMPLETE runner_owner=local-kvm-p03-grant-replay-rerun-20260926 backends=both guests=2 revocation=reconciled recovery=passed
```

The host used QEMU 11.1.1, writable `/dev/kvm`, and the pinned Ubuntu 24.04
image hash recorded above. The command was:

```bash
BLINDPASS_P03_KEEP_FAILED_ARTIFACTS=1 \
BLINDPASS_P03_SSH_PORT_A=22322 \
BLINDPASS_P03_SSH_PORT_B=22323 \
BLINDPASS_FLEET_RUNNER_OWNER=local-kvm-p03-grant-replay-rerun-20260926 \
  ./tests/fleet/p03-vm.sh --backend both
```

An earlier diagnostic run stopped at the E01 workload start because journald
left the fast failed process message without `_SYSTEMD_INVOCATION_ID`. The
repaired helper correlates the systemd manager invocation with the following
unit messages. It was checked directly on the retained disposable guest before
the successful full rerun. The failed run is not acceptance evidence; its
temporary VM and generated keys were removed after diagnosis.

This covers one grant revocation replay through the node HTTPS transport.
Node-revocation replay through that transport, repeated adversarial replays,
and the broader P03-I06 matrix remain open.

Final gates passed: `cargo test --workspace --locked`, workspace Clippy with
warnings denied, Rust formatting, `npm run build`, `npm test`, shell syntax,
proxy Python compilation and `git diff --check`. The default Rust workspace
run ignored its PostgreSQL-only outage test; the default npm run skipped 101
service-gated SPS tests across 17 files.

## Review, fixes and extended VM verification — 2026-09-27

A review of the implemented P03 code against the acceptance plan found gaps in
the broker, controller and harness. They were fixed in 32 local commits from
`61d2d99` to `2100222`. The commits are not pushed, and no hosted workflow has
run on them.

Decisions recorded for this pass:

- Operation approvals must name approvers: `pending_approval` rules carry
  `approver_ids`, and the decider must be named and must not be the requester.
- Each (node, unit) pair has at most one active workload registration, and the
  broker resolves the registration from the pidfd unit.
- E10, O08, C13 and the credential-handle parts of C09/C10 are reassigned to
  later phases (see below).

Material fixes:

- **Broker time estimate.** The signed `TimeReply` now carries
  `challenge_received_at_ms`. The broker counts relay-held round-trip time as
  elapsed controller time, so a held reply cannot extend an expired grant.
- **Consume path.**
  - Deadlines are clamped by every local ceiling.
  - Consume denials return stable reason codes.
  - Registrations are resolved from the pidfd unit.
  - A journal failure denies consumption; it is not ignored.
  - Revocations are applied in memory before they are persisted, with a fence.
  - Old-epoch grants are retired.
  - Torn journal appends are recovered.
  - Each grant revocation emits a signed outcome.
- **Operation closures.** A signed `OperationClosed` document tells a waiting
  workload that its request was rejected, expired, cancelled or denied.
- **Controller.**
  - Node session challenges are stateless.
  - Node events are bound to their session, with partial acknowledgement.
  - Revocations are redelivered on each session.
  - Grants expire through a sweep, followed by retention pruning.
  - Retiring a workload revokes its grants.
  - A fenced controller clock withdraws fleet authority.
  - Fleet operator audit rows are written in the action's transaction.
  - The fleet role matrix is tested.
  - Schema version is 13.
- **Execution outcomes found by the VM.**
  - An operation still `executing` when its grant deadline passes becomes
    `uncertain` with `completion_unconfirmed` (`af343b8`).
  - Broker evidence older than the one-minute window returns 409
    `broker_evidence_stale`; it is not reported as a binding mismatch
    (`cdbd153`).
- **Harness.**
  - Each workload runs in its own system unit.
  - A second operator is the named approver.
  - Denial checks require the broker's exact reason code, replacing checks that
    an unrelated socket failure could pass.
  - Node-revocation transport replay was added to the main stage.
  - A new extended stage, `tests/fleet/p03-vm-extended.sh`, was added.

The two-guest QEMU/KVM runner passed all 24 scenarios on each backend. Host,
QEMU version and image hash are as recorded above. The command was:

```bash
BLINDPASS_P03_KEEP_FAILED_ARTIFACTS=1 \
BLINDPASS_P03_SSH_PORT_A=22322 \
BLINDPASS_P03_SSH_PORT_B=22323 \
BLINDPASS_FLEET_RUNNER_OWNER=local-kvm-p03-finish-20260927 \
  ./tests/fleet/p03-vm.sh --backend both
```

```text
P03-VM-COMPLETE runner_owner=local-kvm-p03-finish-20260927 backends=both guests=2 revocation=reconciled recovery=passed
```

| Scenario | SQLite | PostgreSQL | Observation |
|---|---|---|---|
| P03-I06 partition, protocol mismatch, time replay, key rotation (I01) | Pass | Pass | Exit 78 without a restart loop; stale time reply rejected; key version 2 |
| P03-I06 reconnect storm | Pass; 947/2,369 ms | Pass; 1,286/2,447 ms | Three failures, bounded backoff, zero node-service restarts |
| P03-I06 guest reboot | Pass; 108,423 ms left | Pass; 108,249 ms left | Old grant denied with `grant_unknown`; fresh operation completed |
| P03-I06 suspend plus wall-clock rollback | Pass; 18,914 ms left | Pass; 19,044 ms left | Denied with `grant_expired` after 25 s suspend; no marker |
| P03-I06 delayed expired grant | Observed | Observed | 10 s hold against 8 s TTL; one `expired_before_receipt` event |
| P03-I06 node-revocation transport replay | Pass | Pass | Genuine signed node revocation duplicated under a synthetic outer sequence; exactly one `node_revocation_applied` event |
| P03-E01 two-host authorization and connected node revocation | Pass; 10,714 ms | Pass; 10,866 ms | Within the 30 s bound; pending grant denied with `node_revoked` |
| P03-E02 revoked-node recovery | Pass | Pass | Distinct identity enrolled; fresh operation completed |
| E06 connected grant revocation | Pass; 1,323 ms | Pass; 1,342 ms | Broker-signed outcome `revoked_before_consumption` |
| P03-I06 signed grant revocation replay | Pass | Pass | One tombstone across broker restart; held grant denied with `grant_revoked` |
| P03-I06 delayed signed policy replay | Pass | Pass | Version 2 after 3 rejected; version 4 applied without restart |
| I10 unprivileged approval | Pass | Pass | Requester self-approval 403; workload account on the approval API 401 |
| E05 reject, cancel, expire | Pass | Pass | Worker ends with signed `operation_rejected`, `operation_cancelled`, `operation_expired`; no grant issued |
| E12 and I02 forged callers | Pass | Pass | Unregistered unit, copied live grant, sibling claim and out-of-unit process all denied with specific codes; legitimate workload then completed |
| E11 parallel workloads | Pass | Pass | Four workloads on two nodes completed once each; cross-identity reuse denied |
| P03-I05 crash after consume intent (I08) | Pass | Pass | Broker aborted after the fsynced intent; one intent record, no marker, retry denied, operation `uncertain` |
| E07 controller hang | Pass; 35,149 ms outage | Pass; 35,262 ms outage | Grant live for 28.9 s at outage start, denied after expiry; outage-era request refused `broker_evidence_stale` after recovery; fresh request completed; zero relay restarts |
| O01 controller restart | Pass | Pass | Channel recovered; fresh operation completed |
| E01 private-key exposure | Pass | Pass | 12 key encodings from both guests searched in a full database dump and controller log; positive-control canary found; 0 exposed |

The runner removed its disposable guests and keys. Debug runs that used the
`BLINDPASS_P03_EXTENDED_ONLY` filter are not evidence. Failed runs that kept
their artifacts were diagnosed and then deleted.

Scope reassigned in the vault plans on 2026-09-27:

- E10 (Omarchy shell) moves to P04.
- O08 (real-operator prompt load) moves to P08.
- C13 and the credential-handle parts of C09/C10 move to P05.

P03 retains only headless analogs:

- a copied or expired grant presented by another unit is denied;
- a substituted recipient key is rejected at enrollment and rotation.

These analogs do not satisfy the reassigned IDs.

Known limits of this pass:

- A poison event can block the relay outbox until an operator intervenes.
- Migration 0013 fails when duplicate active (node, unit) workloads already
  exist; the operator must retire the duplicates first.
- Operator routes return 401 while the controller clock is fenced.
- The controller parses request bodies before authentication, so a malformed
  unauthenticated body returns 422 rather than 401.
- Controller clock rollback has Rust-level coverage only.

Final gates on `2100222`: Rust formatting; workspace Clippy with warnings denied;
`cargo test --workspace --locked` (264 passed, 0 failed, 1 ignored
PostgreSQL-only outage test); controller tests against PostgreSQL (109 passed,
1 ignored); `npm run build`; `npm test` (80 passed, 101 service-gated SPS tests
skipped across 17 files); `test:controller-openapi`, `test:openapi-types` and
`test:contract-progress`; shell syntax, proxy Python compilation, Node syntax
and `git diff --check`.

## Remaining acceptance work

This record does not establish P03 acceptance. Open items:

- A dated acceptance review of the evidence above by the phase owner.
- Hosted `ci-full.yml` and `fleet-vm.yml` runs on the pushed commits.
- The inherited P01/P02 gates and the P02.6 controller cutover gate.
- In P03-I06: controller clock rollback on real VMs, reboot cases beyond the
  tested unconsumed-grant reboot, and repeated adversarial replays.
- In P03-I07: an actual disk-full filesystem and the full delayed
  duplicate-event matrix.
- Pilot catalog cases with only partial evidence under other scenario names.
  None has been reviewed as a complete pass.
  - E13 and O07: old-identity denial and recovery (E01/E02, I01 key rotation).
    The E13 provider-credential risk display belongs to P05.
  - O03: delayed grant, node and policy replay. Duplicate approval delivery has
    integration coverage only.
  - O06: protocol mismatch. The unsupported-host profile is P01 evidence.
  - C19: prior grant after reboot, and a copied grant. The restart race during
    unit-to-invocation resolution is untested.
  - O02 and O05: Rust and HTTP tests only; disk-full and UI rendering are
    untested.
  - C20: P01 host evidence only.

The VM drives the authenticated controller API directly. It does not exercise
the administrator CLI or an operator fleet UI; the CLI has separate
authenticated HTTP integration tests. Do not infer that an unlisted scenario
passed from the two-backend VM run.
