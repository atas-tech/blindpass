# P09 disposable OpenClaw guest

Real-runtime harness for the OpenClaw credential migration ([contract](../../docs/product/openclaw-migration.md)).
It boots a throwaway QEMU/KVM guest that holds the pinned toolchain, so the migration is exercised against the real
OpenClaw gateway, real `sops` and real `age` and never against mocks.

OpenClaw, `sops` and `age` fail Socket review. They are installed **only inside the guest**, never on the host, and
no manifest or lockfile lists them. The sops/age release binaries are hash-checked on the host against
`tools.lock` and copied in; OpenClaw is installed from npm inside the guest at the pinned version.

```bash
export BLINDPASS_FLEET_RUNNER_OWNER=<name>      # same convention as tests/fleet
tests/openclaw/vm.sh prepare                   # once: build the cached base image (about 5 minutes)
tests/openclaw/vm.sh up                        # boot a fresh overlay (about 16 seconds)
tests/openclaw/vm.sh ssh 'openclaw --version'
tests/openclaw/vm.sh down                      # stop and delete every run artifact
```

Requirements match [fleet setup](../fleet/README.md): readable/writable `/dev/kvm`, QEMU, `cloud-localds`, and the
pinned Ubuntu image (`BLINDPASS_FLEET_GUEST_IMAGE`, default under `~/.local/share/blindpass/vm-images`). Exit status 78
with a `P09-UNSUPPORTED` record means an infrastructure prerequisite is missing; it is not a pass.

The guest user is `blindpass` with passwordless sudo, an ed25519 key is generated per run in the run directory, and the
guest only ever holds generated `P09-CANARY-*` dummy credentials. The cached base image and tool downloads live outside
the repository (`~/.local/share/blindpass/vm-images`, `~/.cache/blindpass/openclaw-tools`).
