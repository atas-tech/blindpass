# P01 disposable systemd VM runner

This directory is the executable harness for the P01 acceptance plan. It
requires a maintainer-managed disposable x86_64 Linux runner with QEMU/KVM,
not a hosted CI VM and not a mocked peer-identity fixture.

The runner expects a pinned cloud image with systemd as PID 1, SSH, cloud-init,
and passwordless sudo for the configured test account. It creates a temporary
qcow2 overlay, boots it with user-mode networking, copies only the release
probe binaries and unit files, runs the guest checks, and destroys the overlay
and QEMU process on success, failure, or cancellation.

Required host configuration:

```bash
export BLINDPASS_FLEET_GUEST_IMAGE=/srv/blindpass-images/noble-server-cloudimg-amd64.img
export BLINDPASS_FLEET_GUEST_IMAGE_SHA256=replace-with-the-reviewed-sha256
export BLINDPASS_FLEET_SSH_KEY=/srv/blindpass-runner/ed25519
export BLINDPASS_FLEET_GUEST_USER=blindpass
export BLINDPASS_FLEET_RUNNER_OWNER=platform-team
./tests/fleet/p01-vm.sh
```

For a user-owned persistent local image store, set the image path from XDG
data storage:

```bash
export PATH="$HOME/.local/bin:$PATH"
export BLINDPASS_FLEET_GUEST_IMAGE="${XDG_DATA_HOME:-$HOME/.local/share}/blindpass/vm-images/noble-server-cloudimg-amd64.img"
export BLINDPASS_FLEET_GUEST_IMAGE_SHA256=612b2c0cc1bc413a6cb8c38fd611794caf0f2b436c50013d8b3794db12ad7354
```

The local copy is reusable across runs and is accompanied by `.sha256` and
`.source.txt` sidecars. `cloud-localds` and the `genisoimage` wrapper are
retained in `~/.local/bin`; the wrapper uses the installed `xorriso`. The image
remains outside the repository.

`BLINDPASS_FLEET_GUEST_IMAGE_SHA256` is mandatory. The guest image, SSH key,
and QEMU artifacts are never committed. The guest uses synthetic
`P01-*-CANARY` values only.
`cloud-localds` also needs a `genisoimage`-compatible ISO writer; the current
local run used `xorriso` in mkisofs compatibility mode. The host account must
have read/write access to `/dev/kvm` and the configured SSH key.

The default profile has no TPM device. To exercise the optional emulated TPM
profile, provide a runner-local `swtpm` binary and a directory containing the
pinned Ubuntu noble `tpm2-tss` runtime `.deb` files plus `tpm-udev`, then add:

```bash
export BLINDPASS_FLEET_TPM_MODE=emulated
export BLINDPASS_FLEET_SWTPM=/srv/blindpass-runner/swtpm
export BLINDPASS_FLEET_SWTPM_LD_LIBRARY_PATH=/srv/blindpass-runner/swtpm-libs
export BLINDPASS_FLEET_TPM_DEB_DIR=/srv/blindpass-runner/ubuntu-noble-tpm2-debs
./tests/fleet/p01-vm.sh
```

The host harness prints SHA-256 values for every supplied package, installs
the bundle only in the disposable guest overlay, attaches `tpm-tis` to QEMU,
and requires an explicit `systemd-creds --with-key=tpm2` encrypt/decrypt
round-trip. The package directory is not a repository dependency and is not
copied into committed artifacts.

The script exits `78` with an `UNSUPPORTED` record when QEMU, KVM, the pinned
image, cloud-localds, or the named runner owner is missing. That is an
infrastructure block, not a passing or skipped P01 gate.

The guest exercises direct helper delivery and stock system-scope
`LoadCredential=` delivery through the broker. For native delivery it verifies
the peer's root UID and pidfd-derived target unit/invocation against the
abstract route before applying the protected mapping. It also exercises
root-only socket boundaries, real user-manager denial, registered fixed-account and
`DynamicUser` workloads, stale and repeated loader/workload
pidfd-to-invocation restart races, empty/partial/malformed/oversized/corrupt
delivery, a bounded stalled frame, unauthorized unit routing, API-removal
fail-closed behavior, ephemeral custody restart/expiry/one-use behavior, and
controlled credential rotation. It also runs a disposable credential-consuming
backup/restore probe before and after rotation; the probe persists only a
checksum and is not a production backup implementation. The mandatory native
`LoadCredentialEncrypted=` comparison runs with an explicit systemd host-key
profile and records initial delivery and controlled rotation; it does not
claim TPM protection.

Use `./tests/fleet/p01-teardown.sh failure` and
`./tests/fleet/p01-teardown.sh cancel` with the same environment to verify
bounded failure and cancellation cleanup. The pinned Ubuntu profile does not
close the physical-TPM/firmware-measured, crash-artifact, kernel API, or
guest-version matrix; those remain explicitly recorded as open or unclaimed
rather than being converted into passes.

The local KVM runner used on 2026-09-23 reported QEMU 11.1.1, `qemu-img`
11.1.1, readable/writable `/dev/kvm`, and `cloud-localds`. It booted the
pinned Ubuntu 24.04 image, recorded guest kernel 6.8.0-139-generic and
systemd 255, and removed the QEMU process, guest broker sockets, and guest
disk artifacts after the run. The positive run owner was explicitly supplied
as `local-kvm-p01-full-final-20260923`. The final profile passed the complete
guest gate, including native `LoadCredential=` peer binding, live HPKE
provisioning failures and expiry, API-removal fail-closed behavior, account
isolation, rotation, canary scans and cleanup. Separate `failure` and `cancel`
teardown runs also passed with owner `local-kvm-p01-teardown-final-20260923`.
This is disposable runtime evidence, not a claim that the manual VM job is
already configured as a shared GitHub self-hosted runner.

To run the P02-I09 real-clock probe after the P01 guest checks, set
`BLINDPASS_FLEET_P02_CLOCK_TEST=1` when invoking `p01-vm.sh`. The guest check
installs PostgreSQL inside the disposable overlay and runs the controller with
SQLite and PostgreSQL. For each backend it steps the guest wall clock backward
while running and while the controller is stopped, steps it forward, verifies
readiness fencing and persistence across controller restart, and runs
`reconcile-clock`. It then reboots the guest with a PostgreSQL fixture containing
transient authority and an operator session. A boot-resume check requires the
transient rows to be purged, the session to remain active, and exactly one
count-only `clock_restart_fence` audit event. The guest probe restores the clock
from the original wall-time/boottime pair during cleanup. It does not change the
host clock, and the P01 runner destroys the guest overlay on exit. Use a fresh
disposable SSH key for each run; the test creates no repository credentials or
database artifacts.

A Debian 12 candidate-minimum attempt (kernel 6.1.0-53, systemd 252) was
recorded for an earlier broker build that dynamically imported
`sd_pidfd_get_unit` and failed to load `LIBSYSTEMD_253`. The current build no
longer imports that symbol: it uses `GetUnitByPIDFD` and reports missing
`SO_PEERPIDFD` or D-Bus method support as an explicit `unsupported_host`
denial. The current runtime behavior has not been exercised on systemd 252;
that host matrix remains open.

The successful guest run measured a stalled-frame denial at 2.023 seconds,
tested empty/partial/malformed/oversized/corrupt delivery, stale invocation
rejection, two loader restart races, three workload restart races, registered
`DynamicUser`, live wrong-key/tamper/AAD/replay and shortened-TTL expiry
probes, host-key encrypted `LoadCredentialEncrypted=` rotation, and
system-bus/`getsockopt` removal. Generated canaries were absent from selected
process arguments, journals, and scanned runtime/log/crash paths. The default
no-TPM profile rejected explicit `tpm2` mode. Forced reuse of the same numeric
PID, the systemd 252 host matrix, and physical TPM/measured boot remain open.
The earlier opt-in `local-kvm-p01-tpm-pass` run tested the emulated TPM
comparison only; it did not close those exclusions. See
`docs/testing/p01-host-broker-evidence.md` for the dated evidence record.

## P03 fleet authorization runner

The `blindpass` CLI can manage enrollment and node keys against the same
operator API used by the console. Fleet commands require an administrator
login, the exact controller-approved origin, and the password on stdin:

```bash
printf '%s\n' "$OPERATOR_PASSWORD" | blindpass admin \
  --controller-url https://controller.example \
  --username admin --password-stdin enrollment list
```

Use `enrollment create NAME --token-file PATH` to write the one-use enrollment
token to a new mode-0600 file. `enrollment approve ID --expected-fingerprint
SHA256` and `enrollment reject ID --expected-fingerprint SHA256` require the
operator to compare the displayed fingerprint. `node revoke ID --confirm ID`
requires the exact node ID. For rotation, prepare a candidate on the node with
`blindpass-node rotate-prepare`, save its public JSON metadata, then run
`node rotate ID --metadata-file PATH --expected-fingerprint SHA256`. The CLI
checks the key pair fingerprint and consecutive key version before requesting
the staged rotation.

The CLI process reads the operator password into memory and sends it to curl
over stdin for the controller login. It attempts logout at command completion,
then deletes its mode-0600 runtime cookie file. The enrollment token is
plaintext in the requested mode-0600 file until the node consumes it or it
expires; remove that file after enrollment.

`p03-vm.sh` boots two disposable guests and runs the controller on the host.
Each backend pass enrolls separate nodes, registers fixed system-unit
workloads, authorizes dummy `noop.marker` operations, checks broker result and
audit linkage, propagates a signed node revocation, retries the revoked
workload, and recovers through a new node identity. It also drops one TLS
application response and restarts the broker and relay to verify durable event
replay and application acknowledgement. A fault-injection proxy also returns
HTTP 426 to the live relay; the guest verifies the relay exits with status 78,
systemd does not restart it, and the node reconnects after normal forwarding is
restored.

The runner defaults to both backends; choose an individual pass with
`--backend sqlite` or `--backend postgres`:

```bash
export BLINDPASS_FLEET_GUEST_IMAGE="${XDG_DATA_HOME:-$HOME/.local/share}/blindpass/vm-images/noble-server-cloudimg-amd64.img"
export BLINDPASS_FLEET_GUEST_IMAGE_SHA256=612b2c0cc1bc413a6cb8c38fd611794caf0f2b436c50013d8b3794db12ad7354
export BLINDPASS_FLEET_RUNNER_OWNER=platform-team
./tests/fleet/p03-vm.sh --backend both
```

The image defaults to the path above and its reviewed SHA-256 is pinned by the
runner. `p03-vm.sh` creates a disposable SSH key itself. PostgreSQL defaults
to the disposable local development endpoint
`postgres://blindpass:localdev@127.0.0.1:5433/blindpass`; override it with
`P03_TEST_POSTGRES_URL`. The runner requires QEMU/KVM, readable and writable
`/dev/kvm`, the listed host tools, and a named runner owner. It removes guest
overlays, generated keys, fixture state, and temporary database schemas after
success or failure. With `BLINDPASS_P03_KEEP_FAILED_ARTIFACTS=1`, a failed run
retains the protected temporary directory for diagnosis and prints its path.

This runner's key-rotation, protocol-mismatch, reconnect-storm, time-reply replay,
guest-reboot, delayed policy replay, grant revocation replay, and E01/E02 output
is phase-local evidence; it is not the complete P03
acceptance matrix. It holds a signed 8-second grant response for 10 seconds and verifies
one durable `expired_before_receipt` audit event on both SQLite and PostgreSQL.
A controlled three-failure poll storm recovered with bounded backoff and zero
systemd restarts on both backends. It also suspends each guest until after a
broker-acknowledged 20-second grant expires, rolls the guest wall clock back by
two hours, and verifies no operation marker appears. After broker and node
restart, the TLS test proxy replays one captured signed time reply against the
new broker challenge; the broker rejects it and then recovers with fresh signed
time on both backends. The runner also reboots each guest after broker
acknowledgement of an unconsumed grant; the old still-live grant is denied after
boot, the node channel recovers without service restarts, and a fresh operation
succeeds. The proxy also replays an older signed policy after a newer deny
policy. The broker denies fresh workload invocations; the relay reconciles the
conflicting outer sequence and applies another signed deny policy without a
node-service restart. Denial persists after channel restart, with no new marker.
The proxy also captures and replays a signed grant revocation after broker
restart. The held grant is denied, its private tombstone stays at one record,
and the replay is acknowledged without a node-service restart. Controller time
rollback (covered only by Rust tests), reboot cases beyond this tested guest
scenario and further transport-level policy replay remain open; node-revocation
transport replay is covered by the main stage below. Portable Rust tests cover bounded queues,
durable audit backpressure and purpose sanitization; actual disk-full and all
delayed duplicate-event cases remain open. The extended stage below covers the
crash-after-intent I05 case and pilot scenarios E05, E07, E11 and E12;
inherited P01/P02 gates and hosted runs still require execution evidence. See
`docs/testing/evidence/p03-fleet-authorization-execution.md` for the last
two-backend result and its exact limits.

### Extended P03 stage and harness conventions

Each registered workload runs in its own system unit (`blindpass-p03-<label>.service`)
with its own root-owned grant file, because a node allows one active registration
per unit. The runner seeds a second operator and names it in the
`pending_approval` rule's `approver_ids`; the administrator requests operations
and the named approver decides them, since the controller refuses self-approval.
Denial checks require the broker's exact reason code (for example
`grant_revoked`, `grant_unknown` after reboot, `grant_expired` after suspend),
so an unrelated socket or permission failure cannot pass them.

After the E02 recovery, `tests/fleet/p03-vm-extended.sh` runs on each backend:

- E05 and I10: reject, cancel and expire approvals (the runner sets
  `BLINDPASS_TEST_APPROVAL_TTL_SECONDS=20`). The waiting worker ends with the
  controller-signed `operation_<status>` closure. The requester's own approval
  returns 403, and the workload account cannot reach the approval API.
- E12 and I02: an unregistered unit claiming a registered workload, the same
  unit presenting a copied live grant, a registered sibling claiming another
  workload, and a process outside any unit claiming the unit, invocation and
  grant are all denied with specific codes; the legitimate workload then
  consumes its grant.
- E11: four workloads on two nodes run concurrently; each grant completes once
  with its own audit linkage, and a consumed grant presented by another
  workload is denied.
- P03-I05 and I08: with a test-mode drop-in and a one-shot root-owned flag, the
  broker aborts after the durable consume intent and before the marker. The
  retry is denied, no marker appears and the controller records `uncertain`.
- E07 and O01: the controller is stopped with `SIGSTOP` while a grant is held
  and another request is queued; the held grant is denied after expiry and the
  relay does not restart. After `SIGCONT` the queued request's broker evidence
  is older than the one-minute window, so the controller refuses it with
  `broker_evidence_stale`; a fresh request on the same unit then completes.
  The controller process is then restarted and a fresh operation completes.
- E01 exposure: every private node key encoding from both guests is searched
  for in a full controller database dump and log. A random canary placed in an
  operation purpose must be found first, so an empty dump cannot pass.

The main stage also duplicates the genuine signed node revocation under a
synthetic outer sequence and requires exactly one controller
`node_revocation_applied` event, and it measures connected grant revocation
(E06) against the 30-second bound with the broker-signed
`revoked_before_consumption` outcome.

Focused broker control-socket tests also reject an older signed policy after a
newer snapshot has been applied, keep that policy across broker restart, and
preserve grant and node revocations when their signed documents are replayed.
They verify the revoked grant remains denied after a fresh signed time reply.
The VM scenarios above exercise policy, grant revocation and node revocation
replay through the node HTTPS transport.

## P06 journal checks

The P06 [journal checkpoint](../../docs/testing/evidence/p06-consumption-journal-2026-10-03.md)
adds operation/epoch inspection to the existing crash-after-intent scenario.
The full normal SQLite driver must reach the actual abort/restart/no-marker and
replay assertions before CJ06 is claimed; earlier main-stage failures do not
establish that scenario. `python3 tests/fleet/p03-broker-event-test.py` executes
four isolated cases for the exact guest queue assertion, including schema-5
header references and the broker's stored three-field events. It cannot replace
the VM. An original waiter may settle first on grant or node revocation; the
subsequent fresh invocation after restart still requires node-revoked denial.

## P06 recovery relay rehearsal

`p06-relay-vm.py` is the RC09-RR03 actual / RR04 subset harness (the
[evidence record](../../docs/testing/evidence/p06-relay-vm-2026-10-05.md) lists what
it proves and what it does not). A production-mode, authority-backed controller
with built-in TLS runs on the host; a real broker and node in the pinned P01 guest
enroll over verified HTTPS, one grant is consumed, an authenticated backup is
restored under a `recovering` authority record, and the guest runs
`blindpass-node recovery-relay` against the real broker socket. It also covers TLS
name/trust failures, a stalled and a restarted controller, an expired nonce,
malformed frames, a broker restart and the lost-page `rebase_required` case.

```
cargo build --release -p blindpass-controller -p blindpass-cli -p blindpass-broker -p blindpass-node
PATH=$HOME/.local/bin:$PATH python3 tests/fleet/p06-relay-vm.py [--until source|enroll|grant|restore|faults|rebase|relay]
```

It needs `/dev/kvm`, QEMU, `cloud-localds`, the pinned image and the
`blindpass-postgres` container on 5433 (a random authority database and roles are
created and dropped). Exit 78 with `P06-RR-UNSUPPORTED` means a prerequisite is
missing and is not a pass. `BLINDPASS_P06_DEBUG=1` prints guest stderr and
`BLINDPASS_P06_KEEP_ARTIFACTS=1` keeps the run directory and authority database.
This is not RR05: nothing is activated and no SourceStopProof exists.

## P06 recovery activation, PostgreSQL store and two-node matrix

`p06-recovery-activation-vm.py` takes the relay rehearsal through review, source-stop attestation, activation, an ordinary grant,
the refused old source and a restore-based rollback (`--scenario main`) or a named node waiver (`--scenario waiver`).
`p06-recovery-matrix-vm.py` runs the same recovery with **two** real broker+node pairs in two guests (SSH ports 22231 and
22232, override with `BLINDPASS_P06_SSH_PORT` and `BLINDPASS_P06_SSH_PORT_B`):

| Scenario | What it proves |
|----------|----------------|
| `refusal` | A covered, B neither covered nor waived: review completion and activation are refused, the controller is not fenced, the record is unchanged |
| `waiver` | B waived by name: activation succeeds, A online and consuming a grant, B stays revoked and a workload registration for B is refused (`node_unavailable`) |
| `both` | activation refused while only A is covered; B relays after A; both nodes online and each consumes an ordinary grant |

`--backend postgres` (or `BLINDPASS_P06_BACKEND=postgres`) on the relay, activation and matrix harnesses keeps the controller
store in a PostgreSQL schema of the `blindpass-postgres` fixture. The host has no PGDG toolkit, so `backup create`,
`backup verify` and `restore` run in the controller image (`BLINDPASS_P06_TOOLKIT_IMAGE`, default
`blindpass-p06-controller:pkgrec`, a locally built image of `deploy/controller/Dockerfile` from the same tree): the run directory is handed to UID 10001 for the
duration of the call and returned afterwards, and the image defaults `BLINDPASS_PROXY_REQUIRED` and `BLINDPASS_DATA_DIR` are
overridden. The controller process itself still runs on the host. The PostgreSQL relay harness runs the `source`, `enroll`,
`grant`, `restore` and `relay` stages only (the fault and rebase stages stay SQLite-only).

```
PATH=$HOME/.local/bin:$PATH python3 tests/fleet/p06-recovery-activation-vm.py [--backend postgres] --scenario main|waiver
PATH=$HOME/.local/bin:$PATH python3 tests/fleet/p06-recovery-matrix-vm.py [--backend postgres] --scenario refusal|waiver|both
```

The prerequisites and exit-78 convention are those of the relay rehearsal. Records:
[recovery activation](../../docs/testing/evidence/p06-recovery-activation-2026-10-05.md),
[recovery matrix](../../docs/testing/evidence/p06-recovery-matrix-2026-10-05.md). Run the harnesses one at a time: they share the
fixed ports 8443 and 22231 and the PostgreSQL fixture.

## P06 real broker and node on the shipped Compose profiles

`p06-compose-node-vm.py` ([evidence record](../../docs/testing/evidence/p06-compose-node-2026-10-05.md)) runs the recovery
path against the **packaged Compose stack** instead of a host controller process. The controller is the shipped
`deploy/controller/compose.<profile>.yml` project (pinned image, authority in its own `verify-full` TLS container, shipped
backup and restore jobs) behind an nginx edge generated from `deploy/proxy/nginx.conf.example` (the harness rewrites only the
names, the `:8443` suffix of the `Host` headers and the upstream address). A real broker and node in a QEMU guest enroll over
verified HTTPS through that edge, consume a grant, and the guest then recovers into a **second** Compose project restored by the
shipped restore jobs; the edge container keeps its name, port and certificate and is only pointed at the new project.

| Scenario | What it proves |
|----------|----------------|
| `main` | node enrollment and a grant through the edge; shipped backup job while serving; fence and stop; restore into a second project (host custody refused, PostgreSQL init-hook schema refused with its fixed reason until dropped); gate refusals; original stack refused while recovering; completion refused for an uncovered node, then the real relay covers it; review, attestation, activation; the unchanged node returns (`status --nodes --require-online`, reconnect time recorded); an ordinary grant; original stack refused and its SQLite database byte-unchanged; no credential in any log |
| `waiver` | the node never reports: waived by name, stays revoked, the controller still activates and serves, the online gate fails for it |

```
PATH=$HOME/.local/bin:$PATH python3 tests/fleet/p06-compose-node-vm.py --profile sqlite|postgres [--scenario main|waiver]
```

Prerequisites: those of the relay rehearsal (`/dev/kvm`, QEMU, the pinned guest image, release `blindpass`, `blindpass-broker`,
`blindpass-node` and `blindpass-workload-client` built from the same tree), plus Docker, the controller image
(`BLINDPASS_P06_CONTROLLER_IMAGE`, default `blindpass-p06-controller:node`, built from `deploy/controller/Dockerfile`) and the edge image
(`BLINDPASS_P06_EDGE_IMAGE`, default `blindpass-p06-edge:local`, from `tests/deployment/edge.Dockerfile`). It does **not** need the
`blindpass-postgres` fixture. It uses the fixed ports 127.0.0.1:8443 and SSH 22231 and the Docker subnets 172.29.81-84.0/24, so run it
alone, not beside another harness. Exit 78 means a prerequisite is missing. `BLINDPASS_P06_DEBUG=1` prints tool diagnostics from
disposable containers and `BLINDPASS_P06_KEEP_ARTIFACTS=1` keeps the run directory.

## P06 real broker and node on the packaged native controller

`p06-native-node-vm.py` ([evidence record](../../docs/testing/evidence/p06-native-node-2026-10-05.md)) uses **two** QEMU/KVM
guests. Guest C runs the packaged native controller (the bookworm-baseline archive installed by `controller-install.py`, built-in
TLS from a throwaway test CA, the documented `BLINDPASS_LISTEN` step for a remote direct-TLS controller, the guest's own PostgreSQL
as the authority). Guest N runs a real `blindpass-broker` and `blindpass-node` enrolled over verified HTTPS: C forwards host
`127.0.0.1:8443` to its listener and N resolves `p03-controller` to the QEMU gateway `10.0.2.2`. The flow is the Compose one:
enrollment and a grant, the packaged backup unit, fence, restore through `blindpass-controller-restore.service` into a second
private path on C (then installed into the service paths), relay, review, attestation, activation, reconnect, an ordinary grant
and the stale-source drills (the original state refused as a second instance of the packaged unit while the restored controller
serves, and when swapped into the service paths). `tests/deployment/native-node-guest.py` is the controller-guest driver.

| Scenario | What it proves |
|----------|----------------|
| `main` | enrollment and a grant; packaged backup while serving; fence; restore (host custody refused, no operator input skipped); gate refusals; completion refused while the real node is uncovered, then the real relay covers it; review, attestation, activation; the unchanged node returns (`status --nodes --require-online`, reconnect time); an ordinary grant; original controller refused (authority guard and recovered-epoch state check; its SQLite file byte-unchanged); no credential in any log |
| `waiver` | the node never reports: waived by name, stays revoked, the controller still activates and serves, the online gate fails for it |

```
BUNDLE=$(mktemp -d)
docker build --file scripts/release/Dockerfile --target export --output type=local,dest=$BUNDLE/bin .
scripts/release/build-tarballs.sh --profile controller --arch x86_64 --bin-dir $BUNDLE/bin --output-dir $BUNDLE/out --allow-dirty
PATH=$HOME/.local/bin:$PATH python3 tests/fleet/p06-native-node-vm.py \
  --archive $BUNDLE/out/blindpass-controller-0.1.0-linux-x86_64.tar.zst --bin-dir $BUNDLE/bin \
  [--os ubuntu-24.04|debian-12 --controller-image IMAGE --controller-image-sha256 HEX] [--scenario main|waiver]
```

Prerequisites: `/dev/kvm`, QEMU, `cloud-localds`, OpenSSL, the pinned Ubuntu image for guest N (and for guest C unless
`--controller-image` names the pinned Debian 12 image), and the `blindpass`, `blindpass-broker`, `blindpass-node` and
`blindpass-workload-client` binaries (`--bin-dir`, default `target/release`; use the export the archive was built from). It needs
no Docker at run time and no PostgreSQL fixture, but uses the fixed ports 127.0.0.1:8443, SSH 22262 (guest C) and 22231 (guest N), so
run it alone. Exit 78 means a prerequisite is missing. `BLINDPASS_P06_KEEP_ARTIFACTS=1` keeps the run directory.

`--scenario serving-faults` ([record](../../docs/testing/evidence/p06-serving-faults-2026-10-06.md)) runs the `main` recovery
sequence and then, on the activated controller: `browser` (a stock Chromium, `p06-console-browser.mjs`, signs in to the embedded
console over verified HTTPS with the served leaf's public key pinned, reads the nodes and approvals pages, checks CSP and origin
use, signs out through the UI and replays the old cookie; needs `node`, the locked Playwright package and a Chromium, taken from
`BLINDPASS_PLAYWRIGHT_EXECUTABLE_PATH` or `/usr/bin/chromium`), `ui_logout` (logout without CSRF or from a foreign origin, replay,
second logout, another session and the node unaffected) and `disk_full` (every free block of the data filesystem is taken, then
released; D12 fencing, session and node recovery and an ordinary grant afterwards). Wrap the command in
`tests/deployment/loaded-bounds.py --factor 2 --` for the loaded runs. The harness polls the node list through one operator
session because each login counts against the controller's 10-a-minute account limit.

`--scenario ai-task` ([record](../../docs/testing/evidence/p06-stock-ai-client-2026-10-06.md)) runs the P05 managed Grafana workflow in a
fresh node guest against the packaged controller (`p06-ai-guest.sh`, `fleet-browser-guest.mjs` with
`BLINDPASS_P06_REMOTE_CONTROLLER=1`). Needs `P05_GRAFANA_HOME` (a verified Grafana 13.2.3 distribution), the Node 26.10 and Playwright 1.58.2
prerequisites of the P05 helper harness, `BLINDPASS_P06_NODE_MEMORY_MB=2048` and `BLINDPASS_P06_NODE_DISK_GB=8`. Set
`BLINDPASS_P05_AI_CLIENT=claude` or `codex` to run the stock client on this host's own sign-in (it spends that account's usage); without it
only the managed workflow runs.

## P05 native restic backup runner (blocked, never run)

`p05-backup.sh` and `p05-backup-guest.sh` are the P05-I05 / P05-E02 harness for
an ordinary systemd `restic` job whose repository password comes from the broker
(`deploy/examples/example-backup.service`, no MCP) with a disposable
`rest-server` on a second guest. They have **never been run**: the real restic and
rest-server binaries are blocked pending human review
([ADR 0007](../../docs/product/decisions/0007-p05-native-backup-dependency-review.md)).
Only `bash -n`, the artifact-gate exit paths and an offline scanner self-test
have been executed. They are not P05-I05 or P05-E02 evidence.

The runner exits `77` with `blocked: reviewed restic/rest-server artifacts not
provided (ADR 0007)` unless `RESTIC_BIN`, `REST_SERVER_BIN`, `RESTIC_SHA256` and
`REST_SERVER_SHA256` name executable files whose SHA-256 values match the reviewed
ones. The gate hashes the files and never executes them; `--check-artifacts`
stops after the gate. When allowed it provisions the password through the real
HPKE path, runs the unit, restores and byte-compares the artifact, exercises the
`password-file` profile rejections, shows that a JSON-looking value is never
decoded, rotates the repository password with `restic key passwd`, proves
missing (broker restart) and stale (old password) denial, keeps a running job
alive across operator logout, repeats the cycle with a native
`LoadCredentialEncrypted=` unit derived from the same example, and scans files,
process arguments and the journal for generated canaries with positive controls.
See `docs/product/p05-native-service.md` for the scope and what stays open.

## P06 planned handoff rehearsal

`p06-handoff-vm.py` ([evidence record](../../docs/testing/evidence/p06-handoff-2026-10-05.md),
[runbook](../../docs/deploy/handoff.md)) reuses the relay harness: a production-mode controller on the host
enrolls a real broker and node in the pinned guest and consumes one grant, is fenced and handed off
(`blindpass handoff export|import`, `authority-activate.sql`) to a second host controller with new
directories on the same TLS endpoint, while the guest node stays enrolled. It covers abort before
activation (and the source serving again), a second export, interrupted export and import, refusals,
the destination coming up, the node being seen by the destination (`status --nodes --require-online`
run inside the guest, bound 120 s, measured time printed), a grant issued and consumed after the
handoff, the stale source refusing with the record active and the destination down, abort refusing
after activation, a destination restart and a credential scan of every log.

```
cargo build --release -p blindpass-controller -p blindpass-cli -p blindpass-broker -p blindpass-node
cargo build --release --locked -p blindpass-controller --features p02-test-failpoints --target-dir /tmp/bp-failpoint-target
BLINDPASS_P06_FAILPOINT_CONTROLLER=/tmp/bp-failpoint-target/release/blindpass-controller \
  PATH=$HOME/.local/bin:$PATH python3 tests/fleet/p06-handoff-vm.py [--until source|export|abort|import|activate|grant|restart]
```

Same prerequisites and exit codes as the relay rehearsal (exit 78 is not a pass). Without
`BLINDPASS_P06_FAILPOINT_CONTROLLER` the two interrupted-step cases (`H1a`, `H7a`) print `SKIPPED`.
The failpoint binary is used only for those two commands; everything else runs the release build.
The scenario uses the host SSH port 22231 like the relay harness, so the two cannot run together.
