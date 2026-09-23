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
