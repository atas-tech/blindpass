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

This runner's key-rotation, protocol-mismatch, E01/E02 output is phase-local
evidence; it is not the complete P03 acceptance matrix. P03-I06 clock changes,
suspend/resume, delayed-grant relay and reconnect-storm scenarios remain open.
Portable Rust tests cover bounded queues, durable audit backpressure and
purpose sanitization; actual disk-full and all delayed duplicate-event cases
remain open. Broader I05 cases, pilot scenarios and inherited gates still
require implementation or execution evidence. See
`docs/testing/evidence/p03-fleet-authorization-execution.md` for the last
two-backend result and its exact limits.
