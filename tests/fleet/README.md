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

The guest exercises the portable loader/workload path, consumer rejection for
empty/partial/malformed/oversized files, unauthorized unit routing, a
registered non-root workload, and controlled credential rotation. The
mandatory native `LoadCredentialEncrypted=` comparison runs with an explicit
systemd host-key profile and records initial delivery and controlled rotation;
it does not claim TPM protection. The
pidfd-to-unit restart race, API-removal profile, TPM modes, cancellation
teardown, and deeper custody recovery remain separately recorded VM scenarios
where they require additional fault injection; this harness must not turn
their absence into a pass.

The local KVM runner used on 2026-09-23 reported QEMU 11.1.1, `qemu-img`
11.1.1, readable/writable `/dev/kvm`, and `cloud-localds`. It booted the
pinned Ubuntu 24.04 image, recorded guest kernel 6.8.0-139-generic and
systemd 255, and removed the QEMU process and guest broker sockets after the
run. The run owner was explicitly supplied as `local-kvm`; this is disposable
runtime evidence, not a claim that the manual VM job is already configured as
a shared GitHub self-hosted runner.

The run passed the exercised loader/workload boundaries, consumer validation,
controlled rotation, and native host-key `LoadCredentialEncrypted=` comparison.
P01-I01, P01-I03, the VM half of P01-I05, and P01-I06 remain explicit
additional profiles for the W0 go/narrow/stop review. See
`docs/testing/p01-host-broker-evidence.md` for the dated evidence record.
