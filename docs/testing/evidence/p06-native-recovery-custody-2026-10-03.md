# P06 native original recovery custody — 2026-10-03

NB07/B03/B08 passes on real Debian 12 and Ubuntu 24.04 systemd guests with the
updated native controller archive. Eight unsafe original-custody fixtures fail
before backup execution, preserving controller readiness, identity and the
previous archive. Restoring safe custody permits full verification again.
This is a selected slice 5 gate; complete P06 acceptance remains open.

## Problem, implementation and executed scope

The [first-red Debian run](p06-native-recovery-custody-2026-10-03/debian-first-red.txt)
used the earlier archive SHA256
`86796930032b8231476c58659e5bb3458f1e8e80b093879cfd6ad9686abc2ea8`.
Changing the original recovery file to mode 0644 still allowed the backup job to
succeed. Checking systemd's private runtime credential protected the delivered
copy but did not establish custody of its original source.

The new fixed-path Root preflight checks metadata only: parent directories from
`/` through `/etc/blindpass`, Root ownership and no group/other writes, then
single-link regular recovery and enable-marker files with exact 0600 modes.
The recovery file must contain 1–16384 bytes; the marker allows 0–128 bytes.
Descriptor-relative `O_PATH`/`O_NOFOLLOW` checks reject links and FIFOs without
reading recovery plaintext. The preflight accepts no arguments or configurable
paths and repairs nothing. Its unit has empty capabilities, no new privileges,
zero core limit, restricted syscalls/filesystem and a 10-second start budget.

The non-root backup unit requires and follows this preflight. The check does not
remain active after exit, so every configured backup checks custody anew.
Unconfigured backup still skips without generating keys or output. The
[native guide](../../deploy/native-quickstart.md) describes custody, both journals
and opt-in; the installer and archive inventory include the checker and unit.

| Exact updated-archive result | Debian 12 | Ubuntu 24.04 |
|---|---:|---:|
| Protected live backup creation/full verification |0.532s |0.545s |
| Recovery mode 0644 / wrong UID / hard link |Pass |Pass |
| Recovery symlink / FIFO / oversized dummy file |Pass |Pass |
| Marker mode 0644 / group-writable parent |Pass |Pass |
| Each custody refusal bounded below 10 seconds |Pass |Pass |
| Preflight fails; backup start timestamp unchanged |Pass |Pass |
| No new archive/staging; earlier archive hash unchanged |Pass |Pass |
| Continued readiness and unchanged source identity |Pass |Pass |
| Safe custody restored; earlier archive fully verifies |Pass |Pass |
| N01–N09 install/reboot/retention/exact purge and teardown |Pass |Pass |

The final [Debian](p06-native-recovery-custody-2026-10-03/debian-custody-final.txt)
and [Ubuntu](p06-native-recovery-custody-2026-10-03/ubuntu-custody-final.txt) runs are
terminal passes. Only disposable guests receive Root installation/fault actions;
no host executable, service, mount or shared database is changed.

Both first post-fix runs reached the static custody refusal, then failed the
harness's `systemctl` handling: [Debian](p06-native-recovery-custody-2026-10-03/debian-first-postfix.txt),
[Ubuntu](p06-native-recovery-custody-2026-10-03/ubuntu-first-postfix.txt).
Resetting only the failed preflight, rather than also the dependency-refused
backup unit, fixed both reruns. The backup unit never ran and may be unloaded.
The failed attempts remain recorded and do not establish acceptance.

## Artifact and host pins

The updated `blindpass-controller-0.1.0-linux-x86_64.tar.zst` has SHA256
`fad2c7b884ff2575cefb25b1e2f0a15b0a22e93e194271b31a94bf7f6dd84b10`.
Its manifest records dirty source at base
`8a595ad18783634da59e046595942e729b56147b` and the bookworm/glibc 2.36 build baseline.
It includes the SQLx-only PostgreSQL snapshot preparation and the native custody
preflight; PostgreSQL custom dump/full isolated restore is still unavailable.

| Packaged member | SHA256 |
|---|---|
| CLI |`03bc1bd66960dc2767d5ef008f1bba8084d0e9ac188293398fe418bc6c9713bf` |
| Controller |`00e3e1ba9839227899915a1ce75319863a89a55fb772777223bfa80de2b5281b` |
| Metadata checker |`9c9182f2885ed5ee43e5486ebbc8f76fef0f9bc42642ca8f09bb00eff23ba5f9` |
| Metadata preflight unit |`a494d6f4858a6527a048d835417a1e57717cc4dd5753bb7bc0a1552c3dbfb11a` |
| Backup unit |`46ae03c1b2da4a4a1b6280d0f96e81eaa211ad05b2343a3061d2814853f281a2` |

Custody-final guest fixture SHA256:
`d585bf31719b624fd4eb461cd083ff6053f7981899dd57f36bc5494abd9b0aad`.
Host driver SHA256:
`2cb1c80b8ac56b242e392823ab77a1924ff51755918223a4873dcc54b7be07a8`.
The paired vault acceptance plan defines NB07 before implementation.

The pinned guest images match the
[earlier native checkpoint](p06-native-backup-2026-10-03.md): Debian kernel
6.1.0-53/systemd 252.39/OpenSSL 3.0.22-1~deb12u1; Ubuntu kernel
6.8.0-139/systemd 255.4/OpenSSL 3.0.13-0ubuntu3.16. Approved KVM/QEMU 11.1.1 host
access is used with temporary overlays and disposable SSH keys.

With that pinned image/SSH setup:

```bash
tests/deployment/native-install.sh --os debian-12 --archive FILE --credential-faults
tests/deployment/native-install.sh --os ubuntu-24.04 --archive FILE --credential-faults
```

## Current source and archive gates

Fresh [bookworm build](p06-native-recovery-custody-2026-10-03/bookworm-build.txt)
and [extracted archive](p06-native-recovery-custody-2026-10-03/release-archive.txt)
pass. The latter checks hashes, safe inventory, dummy-secret exclusion,
no-overwrite behavior, extracted CLI/controller and embedded UI startup.
[Native preflight](p06-native-recovery-custody-2026-10-03/native-preflight.txt)
passes seven cases; [release tests](p06-native-recovery-custody-2026-10-03/release-tests.txt)
pass eight.

Fresh [locked Rust workspace](p06-native-recovery-custody-2026-10-03/rust-workspace.txt)
passes 673 cases with zero failures across 68 targets, with eight ordinary ignores.
Four SQLx PostgreSQL snapshot ignores were separately executed in the
[snapshot record](p06-postgres-snapshot-2026-10-03.md); three Quickshell and one
opt-in PostgreSQL outage case remain unexecuted by this workspace run.
[All-target Clippy](p06-native-recovery-custody-2026-10-03/clippy.txt) and formatting
pass. Node 26.10.0 [build](p06-native-recovery-custody-2026-10-03/node26-build.txt)
and [workspace tests](p06-native-recovery-custody-2026-10-03/node26-test.txt) pass,
including MCP 108 and helper/channel 147; SPS has 80 passes and 101 service-gated
skips across 17 files. Node 24 and inherited workflow acceptance are not inferred.

The checker consumes metadata, not recovery plaintext. Systemd's manager still
reads the protected recovery source to deliver a private copy to the non-root
backup job; that copy lasts for the job. Controller/SQLite, backup process,
OpenSSL children and private staging consume plaintext during capture and full
verification. Normal exit removes staging and transient copies; deletion is not
secure erasure. Original protected custody persists until explicit purge or VM
disposal. No recovery contents, bearer tokens or database credentials enter logs.

## Updated-archive missing/stalled-tool regression gate

NB06/B10 also passes on this updated archive, separately from the older
[tool-fault checkpoint](p06-native-tool-faults-2026-10-03.md).
Both final [Debian](p06-native-recovery-custody-2026-10-03/debian-tool-final.txt)
and [Ubuntu](p06-native-recovery-custody-2026-10-03/ubuntu-tool-final.txt) runs are
terminal passes, including full verification after restoring the executable,
retained-state lifecycle/exact purge and teardown.

| Actual result | Debian 12 | Ubuntu 24.04 |
|---|---:|---:|
| Missing-tool refusal |0.133s |0.117s |
| Stalled-tool refusal |60.263s |60.169s |
| Successful readiness probes during stall |294 |294 |
| Observed child's no-new-privileges/zero-core restriction and reaping |Pass |Pass |
| No publication/residue/transient recovery copy; source and earlier archive intact |Pass |Pass |

The first [Debian](p06-native-recovery-custody-2026-10-03/debian-tool-first.txt)
and [Ubuntu](p06-native-recovery-custody-2026-10-03/ubuntu-tool-first.txt) reruns
passed missing-tool refusal but failed the harness's immediate cgroup assertion.
The new ordered preflight means `start --no-block` can return before the backup
cgroup exists. The harness now observes that same queued start with a bounded
read-only wait, without retrying the start mutation. The two final runs then
observe the real sleep child and the production 60-second timeout. These failed
observations remain evidence of the harness correction, not accepted timeout runs.
Final tool-fixture SHA256:
`7fb63a368fbf396752824a24bd94713bb8138083b4433b4da509de6ee3976b38`.
The archive and host driver are unchanged.

## Updated-archive abrupt guest-power regression gate

NB05/B06 passes again on this updated archive in both real pinned profiles:
[Debian](p06-native-recovery-custody-2026-10-03/debian-power-final.txt) and
[Ubuntu](p06-native-recovery-custody-2026-10-03/ubuntu-power-final.txt).
Both observe 202,031,104 encrypted bytes against 202,033,664 plaintext tar bytes
and a live encryption child in the frozen backup cgroup. Only that scoped QEMU
receives SIGKILL; no sync, thaw, stop or guest shutdown follows freezing. Restart
reopens the same disposable disk after a bounded read-only lock wait.

Each new boot retains source identity, the 192-MiB payload, key/config custody
and the earlier archive hash/full verification. One private staging tree is
classified and explicitly removed; no transient recovery copy remains and no
new archive was published. Clock-fenced readiness is observed before explicit
clock reconciliation; it succeeds afterward. N01–N09 retention/exact purge and
teardown pass. The observer allows the ordered preflight to finish before
resolving the cgroup, while retaining the 30-second overall progress deadline.
Final power-fixture SHA256:
`14b235592969a36ae7a6e8204d9e8bddb03ceb1c81fcfb72b224177bc600f792`.
The archive and host driver are unchanged.

This is guest kernel/runtime interruption on the default QEMU disk/cache profile
with tmpfs-backed host overlays. It is separate from physical host/storage power
loss, hostile storage rollback or protected restored ownership. The
[earlier power record](p06-native-power-interruption-2026-10-03.md) documents the
same fault method and its initial observer/freezer/disk-space corrections.

Approved read-only host inspection after the final gates finds zero scoped
temporary VM directories and zero runner-visible overlay holders; KVM read/write
and QEMU 11.1.1 are available. Python/shell syntax, 190 relative links across
changed repository documents and both paired vault plans, and diff whitespace
pass. A scan of the 19 retained terminal logs finds no private-PEM markers or
credential-bearing PostgreSQL URLs. P03 user edits remain 66 additions/zero
removals and unstaged; no dependency manifests or lockfiles changed.

This check assumes trusted Root administration; it does not defend against a
host administrator replacing custody concurrently. It does not authorize restore
or establish protected external ownership/recovery authority. Slice 5 remains
uncommitted pending approved PostgreSQL dump/full isolated restore and artifact
fault gates. All nine slices, stale restore/fencing, locked upgrades, interrupted
transfer and full three-profile/browser/native/inherited acceptance remain required.
