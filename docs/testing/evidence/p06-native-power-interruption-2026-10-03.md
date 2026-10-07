# P06 abrupt native guest power interruption — 2026-10-03

NB05/B06 passes on real Debian 12 and Ubuntu 24.04 systemd guests. During an
observed partial encryption write, the harness freezes the exact backup cgroup,
confirms a live OpenSSL encryption child, SIGKILLs the scoped QEMU process, and
restarts the same disposable disk. Both guests retain source identity/payload/keys
and the prior fully verified archive, classify and clean private crash residue,
and remain unready until explicit clock reconciliation.

This tests abrupt loss of guest kernel/runtime memory and filesystem recovery
with QEMU's default disk/cache profile on the host tmpfs-backed disposable overlay.
It does not test physical host/storage power loss, hostile storage rollback,
protected external recovery ownership or restored-state activation.

## Exact tested artifact and fixtures

The native archive from the earlier
[native backup checkpoint](p06-native-backup-2026-10-03.md) is unchanged:
`blindpass-controller-0.1.0-linux-x86_64.tar.zst`, SHA256
`86796930032b8231476c58659e5bb3458f1e8e80b093879cfd6ad9686abc2ea8`.
No replacement native binary is inferred for the later SQLx-only PostgreSQL
preparation. The final guest fixture SHA256 is
`1bddab55e7e69a918a7a87d7590e3c1953badcef16bdfb08b0025ba315a387f5`.
The paired vault plan defines NB05 before this harness extension.

KVM read/write and QEMU 11.1.1 were verified through approved host execution.
The harness creates its own SSH key and overlay, grows only that overlay to 8 GiB
when needed, and runs all Root installation/fault actions inside the guest.
After enlarging the dummy blob to 192 MiB, it flushes known-good source/reference
state before starting the fault job. It performs no sync, stop, thaw or graceful
shutdown after freezing encryption.

The exact `/system.slice/blindpass-controller-backup.service` kernel cgroup is
frozen directly because systemd refuses its FreezeUnit API during a pending
oneshot start job. The harness observes `cgroup.events` and the actual encryption
child before interrupting QEMU. This uses the
[documented kernel freezer interface](https://docs.kernel.org/admin-guide/cgroup-v2.html#core-interface-files).
A bounded read-only overlay-lock wait follows process death before disk reopening.

| Actual gate | Debian 12 | Ubuntu 24.04 |
|---|---|---|
| Pinned base image SHA256 |`7b3faf645268d65f91676b11cda5ab18294b1f0ac0062238f00d279551bdecad` |`612b2c0cc1bc413a6cb8c38fd611794caf0f2b436c50013d8b3794db12ad7354` |
| Kernel/systemd |6.1.0-53-cloud-amd64 /252.39-1~deb12u2 |6.8.0-139-generic /255.4-1ubuntu8.17 |
| OpenSSL/libssl package |3.0.22-1~deb12u1 |3.0.13-0ubuntu3.16 vendor backport |
| Earlier 8-MiB backup creation/full verification |0.433s |0.486s |
| Partial encrypted output /plaintext archive |202,031,104 /202,033,664 bytes |202,031,104 /202,033,664 bytes |
| New boot; no new successful publication |Pass |Pass |
| Retained tenant/epoch/config/key hashes, 192-MiB payload and SQLite integrity |Pass |Pass |
| Previous archive hash and full authentication/decryption/extraction/SQLite verification |Pass |Pass |
| Persisted private staging trees, classified then explicitly removed |1 |1 |
| 0700 directories/0600 files, service UID; no transient recovery credential |Pass |Pass |
| Readiness 503 before explicit clock reconciliation; ready afterward |Pass |Pass |
| N01–N09 retained-state lifecycle and exact purge |Pass |Pass |
| Scoped VM/key/overlay teardown |Pass |Pass |

Generated controller keys, offline recovery source and transient systemd credential
copies never enter output. Source/partial plaintext remains in private guest
staging/runtime during the job and across the crash until explicit cleanup;
recovery source persists under guest Root custody until disposal. Deletion is not
secure erasure. Shared host services, databases, mounts and pinned base images
remain untouched.

## Execution and corrections

Final sanitized [Debian](p06-native-power-interruption-2026-10-03/debian-final.txt)
and [Ubuntu](p06-native-power-interruption-2026-10-03/ubuntu-final.txt) outputs
record actual passes and teardown. Earlier outputs are retained in the same
directory: the first observer missed nested crypto staging; Ubuntu then lacked
disk space, systemd refused the pending-job freezer, a D-Bus query missed the
short output-write window, and immediate disk reopening raced lock release.
Those failed attempts do not establish completed recovery. The final fixture
resolves the cgroup during capture, freezes immediately on output growth, and
asserts a live encryption child and a genuinely partial file before power loss.

Run the existing pinned-image native command with `--power-loss`:

```bash
tests/deployment/native-install.sh --os debian-12 --archive FILE --power-loss
tests/deployment/native-install.sh --os ubuntu-24.04 --archive FILE --power-loss
```

Guest Python/shell syntax, seven existing native artifact preflight cases and diff
whitespace pass. Required current source gates remain those in the
[SQLx snapshot record](p06-postgres-snapshot-2026-10-03.md); this subsequent change
modifies only the Python/shell harness and execution documentation.

Slice 5 remains uncommitted pending PostgreSQL custom dump/full isolated restore
and its separate toolkit approval. Protected external authority/ownership,
stale-state fencing, locked upgrades, interrupted transfers and complete
three-profile/browser/native/inherited acceptance remain required across all
nine slices. This tested clock fence does not substitute for restore authority.
