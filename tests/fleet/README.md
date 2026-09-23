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
export BLINDPASS_FLEET_GUEST_IMAGE=/srv/blindpass-images/debian-12-amd64.qcow2
export BLINDPASS_FLEET_GUEST_IMAGE_SHA256=replace-with-the-reviewed-sha256
export BLINDPASS_FLEET_SSH_KEY=/srv/blindpass-runner/ed25519
export BLINDPASS_FLEET_GUEST_USER=blindpass
export BLINDPASS_FLEET_RUNNER_OWNER=platform-team
sudo -E ./tests/fleet/p01-vm.sh
```

`BLINDPASS_FLEET_GUEST_IMAGE_SHA256` is mandatory. The guest image, SSH key,
and QEMU artifacts are never committed. The guest uses synthetic
`P01-*-CANARY` values only.

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
close the full TPM, crash-artifact, kernel API, or guest-version matrix; those
remain explicitly recorded as open or unclaimed rather than being converted
into passes.

The local KVM runner used on 2026-09-23 reported QEMU 11.1.1, `qemu-img`
11.1.1, readable/writable `/dev/kvm`, and `cloud-localds`. It booted the
pinned Ubuntu 24.04 image, recorded guest kernel 6.8.0-139-generic and
systemd 255, and removed the QEMU process, guest broker sockets, and guest
disk artifacts after the run. The positive run owner was explicitly supplied
as `local-kvm-p01-loader-final2`; separate `failure` and `cancel` teardown runs also
passed with named local owners. This is disposable runtime evidence, not a
claim that the manual VM job is already configured as a shared GitHub
self-hosted runner.

The run passed the exercised loader/workload boundaries, user-manager denial,
stale-invocation rejection and re-registration, repeated loader and
workload pidfd/invocation restart races, `DynamicUser` registration,
bounded stalled-frame denial, broker delivery fault matrix,
consumer validation, ephemeral custody restart/expiry/one-use checks, canary
exposure checks, backup write/restore and controlled rotation, uninstall
cleanup, system-bus API-removal fail-closed behavior, and native host-key
`LoadCredentialEncrypted=` comparison. The TPM capability command is not
available in this systemd 255 profile, so the TPM-required path is explicitly
not claimed. The kernel API matrix, guest-version matrix, and deeper
crash/custody profiles remain explicit additional profiles for the W0
go/narrow/stop review. See
`docs/testing/p01-host-broker-evidence.md` for the dated evidence record.
