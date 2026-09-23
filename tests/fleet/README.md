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
sudo -E ./tests/fleet/p01-vm.sh
```

`BLINDPASS_FLEET_GUEST_IMAGE_SHA256` is mandatory. The guest image, SSH key,
and QEMU artifacts are never committed. The guest uses synthetic
`P01-*-CANARY` values only.

The default profile has no TPM device. To exercise the optional emulated TPM
profile, provide a runner-local `swtpm` binary and a directory containing the
pinned Ubuntu noble `tpm2-tss` runtime `.deb` files plus `tpm-udev`, then add:

```bash
export BLINDPASS_FLEET_TPM_MODE=emulated
export BLINDPASS_FLEET_SWTPM=/srv/blindpass-runner/swtpm
export BLINDPASS_FLEET_SWTPM_LD_LIBRARY_PATH=/srv/blindpass-runner/swtpm-libs
export BLINDPASS_FLEET_TPM_DEB_DIR=/srv/blindpass-runner/ubuntu-noble-tpm2-debs
sudo -E ./tests/fleet/p01-vm.sh
```

The host harness prints SHA-256 values for every supplied package, installs
the bundle only in the disposable guest overlay, attaches `tpm-tis` to QEMU,
and requires an explicit `systemd-creds --with-key=tpm2` encrypt/decrypt
round-trip. The package directory is not a repository dependency and is not
copied into committed artifacts.

The script exits `78` with an `UNSUPPORTED` record when QEMU, KVM, the pinned
image, cloud-localds, or the named runner owner is missing. That is an
infrastructure block, not a passing or skipped P01 gate.

The guest exercises the portable loader/workload path, root-only socket
boundaries, real user-manager denial, registered fixed-account and
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
as `local-kvm-p01-final`; separate `failure` and `cancel` teardown runs also
passed with named local owners. This is disposable runtime evidence, not a
claim that the manual VM job is already configured as a shared GitHub
self-hosted runner.

A Debian 12 candidate-minimum attempt (kernel 6.1.0-53, systemd 252) was
recorded as `P01-UNSUPPORTED` because the broker binary requires the
`LIBSYSTEMD_253` pidfd API; it failed before delivery and did not become a
pass or silent skip.

The run passed the exercised loader/workload boundaries, recorded real
UID/GID/pidfd/unit/invocation traces, user-manager denial,
stale-invocation rejection and re-registration, repeated loader and
workload pidfd/invocation restart races, `DynamicUser` registration,
bounded stalled-frame denial, broker delivery fault matrix,
consumer validation, ephemeral custody restart/expiry/one-use checks, canary
exposure and apport crash-report checks, backup write/restore and controlled
rotation, uninstall cleanup, system-bus and `getsockopt` API-removal fail-closed
behavior, and native host-key `LoadCredentialEncrypted=` comparison including
missing-key denial. The default no-TPM profile rejects explicit `tpm2` mode.
The opt-in `local-kvm-p01-tpm-pass` run attached a real QEMU/swtpm TPM device,
installed the pinned tpm2-tss runtime bundle, and passed the explicit TPM2
credential round-trip; `systemd-creds has-tpm2` correctly reported `partial`
because the emulated profile has no firmware-measured TPM state. This is an
emulated TPM-present result, not a physical TPM or measured-boot claim. The
alternate kernel/systemd, guest-version and persistent broker-custody matrices
remain explicitly outside this narrow profile. See
`docs/testing/p01-host-broker-evidence.md` for the dated evidence record.
