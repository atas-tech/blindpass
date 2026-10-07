# P06 native missing/stalled tool faults — 2026-10-03

NB06/B10 passes in the actual native backup service on both pinned Debian 12 and
Ubuntu 24.04 systemd guests. Missing OpenSSL fails with a fixed diagnostic. An
exec-only sleep fixture reaches the production 60-second tool deadline; its actual
child is killed/reaped, private staging and transient recovery copies disappear,
and source identity/payload/keys and the earlier archive remain intact. Restored
OpenSSL then fully verifies that earlier archive.

The unchanged tested archive is `blindpass-controller-0.1.0-linux-x86_64.tar.zst`,
SHA256 `86796930032b8231476c58659e5bb3458f1e8e80b093879cfd6ad9686abc2ea8`,
from the [native backup checkpoint](p06-native-backup-2026-10-03.md). This does not
infer a replacement binary for the later SQLx-only PostgreSQL preparation.
The guest fixture SHA256 is
`c001f0a478242fec36c2cf74167fc369fcdf6b219014e292754eeb581a0810b1`;
host driver SHA256 is
`aee00f7a8889e21662273ad05886958444dd3bff692e2f27693fc6955f9e6ab6`.
The paired vault plan defines NB06 before implementation.

| Actual result | Debian 12 | Ubuntu 24.04 |
|---|---:|---:|
| Missing-tool failure |0.144s |0.104s |
| Stalled-tool failure |60.187s |60.364s |
| Successful actual readiness probes during stall |291 |292 |
| Child has no new privileges and zero core limit |Pass |Pass |
| Original child absent after job exit; no zombie accepted |Pass |Pass |
| No new publication, residue or transient recovery copy |Pass |Pass |
| Original executable hash/mode restored; earlier archive fully verifies |Pass |Pass |
| Source tenant/epoch/config/keys, 8-MiB payload and SQLite integrity retained |Pass |Pass |
| N01–N09 retained-state lifecycle/exact purge and fixture teardown |Pass |Pass |

The missing-tool gate uses the exact journal invocation's static
`backup tool unavailable` diagnostic. The stalled gate observes `/bin/sleep 300`
in the exact backup service cgroup, verifies inherited restrictions, and requires
failure between 60 and 70 seconds with `backup tool timed out`. The executable is
restored in a finally path. No host executable or package manifest changes.
Only disposable guests receive Root fault actions; KVM read/write and
QEMU 11.1.1 were verified through approved host execution.

The [Debian](p06-native-tool-faults-2026-10-03/debian-final.txt) and
[Ubuntu](p06-native-tool-faults-2026-10-03/ubuntu-final.txt) logs record actual
passes. OS/image/kernel/systemd/OpenSSL pins match the earlier native checkpoint:
Debian kernel 6.1.0-53/systemd 252.39/OpenSSL 3.0.22-1~deb12u1;
Ubuntu kernel 6.8.0-139/systemd 255.4/OpenSSL 3.0.13-0ubuntu3.16.

The mock child inherits a private input descriptor but reads and prints nothing.
Controller/SQLite/private staging retain backup plaintext during the job; systemd
credential copies and raw staging disappear after failure. The protected recovery
source and original archive persist until guest disposal. Deletion is not secure
erasure. No key contents, URLs, tokens or database credentials enter outputs.

With the existing pinned image/SSH setup, run:

```bash
tests/deployment/native-install.sh --os debian-12 --archive FILE --tool-faults
tests/deployment/native-install.sh --os ubuntu-24.04 --archive FILE --tool-faults
```

Python/shell syntax and diff whitespace pass. Production Rust/JS is unchanged;
required current source gates remain those in the
[SQLx snapshot record](p06-postgres-snapshot-2026-10-03.md). No further broad
workspace rerun is needed for this tested harness-only extension.

This checks normal bounded child timeout, not termination under uninterruptible
kernel I/O. PostgreSQL custom dump/full isolated restore still awaits its separate
toolkit approval. Slice 5 remains uncommitted; all protected external recovery,
ownership/stale-state fencing, upgrades, transfer and complete profile/native/
browser/inherited acceptance remain required across all nine slices.
