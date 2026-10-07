# P06 native SQLite backup artifact — 2026-10-03

**Status:** Selected P06-B08/B10 and NB01–NB04 artifact checks pass on real
Debian 12/Ubuntu 24.04 systemd guests. The full slice 5 is uncommitted and open;
PostgreSQL backup, remaining size/fault checks and slices
6–9 remain required. This is not full P06 or browser/native-workflow acceptance.

The candidate is on top of repository commit `8a595ad`, with version 0.1.0,
schema 16 and both embedded web surfaces. The pinned bookworm release builder
compiled the current controller/CLI. The final controller archive SHA-256 is
`86796930032b8231476c58659e5bb3458f1e8e80b093879cfd6ad9686abc2ea8`.
No new npm/Cargo dependency, lockfile or PostgreSQL runtime package change was
made. The separate PostgreSQL toolkit proposal remains pending human review.

## Executed profiles

| Profile | Pinned image SHA-256 | Runtime | Final 8-MiB backup creation |
|---|---|---|---|
| Debian 12 genericcloud 20260923-2610 | `7b3faf645268d65f91676b11cda5ab18294b1f0ac0062238f00d279551bdecad` | kernel 6.1.0-53-cloud-amd64; systemd 252.39-1~deb12u2; OpenSSL/libssl3 3.0.22-1~deb12u1 | 0.408 s |
| Ubuntu 24.04 noble | `612b2c0cc1bc413a6cb8c38fd611794caf0f2b436c50013d8b3794db12ad7354` | kernel 6.8.0-139-generic; systemd 255.4-1ubuntu8.17; OpenSSL/libssl3t64 3.0.13-0ubuntu3.16 | 0.466 s |

The public OpenSSL command/library versions match. Actual key initialization,
encryption and verification pass the prerequisite guard: Debian uses the fixed
upstream 3.0.22 branch; Ubuntu executes the explicit vendor-backport package
check with 3.0.13-0ubuntu3.16 (minimum 3.0.13-0ubuntu3.7). The Debian 3.0.18 vendor
branch remains covered by source version-matrix checks, not this VM run.

Both runs use the exact final archive and record the guest-driver hash. The
driver runs N01–N09 plus the new backup cases before and after a real reboot.
It creates disposable SSH/TLS/recovery keys and thin overlays, never invokes
the installer on the host, and destroys those private VM resources on exit.
KVM read/write access and QEMU 11.1.1 were confirmed on the approved host before
the runs. No sandbox-only observation is counted as VM evidence.

## Native backup and recovery custody

| Scenario | Executed behavior |
|---|---|
| NB01 / N07 | Unconfigured backup skips with no executable invocation, key generation or backup directory; timer remains disabled/inactive. Explicit dedicated key initialization writes private recovery material; the documented no-clobber root copy succeeds once and refuses a repeat. |
| NB02 / B08 | While the controller serves, the shipped non-root hardened unit captures an 8-MiB database fixture, creates a verified encrypted archive, and leaves only UID-owned 0700/0600 backup output. A protected transient verifier accepts it; a different recovery key reaches the actual fixed authentication failure. Source data and controller identity remain intact; no private PEM appears in the backup journal. The systemd credential copy disappears after unit exit. |
| NB03 / N08 | Explicitly configured timer enables/starts. Default uninstall retains recovery source, enable marker, archive and controller identity. Same-artifact reinstall keeps the timer disabled until a separate opt-in and verifies the retained archive. |
| NB04 / N09 | Incorrect purge confirmation, a linked recovery source, world-readable recovery source and linked data refuse before stopping the active controller. Exact confirmed purge removes managed backup credentials/marker and controller state, preserves unrelated canaries and the separate recovery fixture, and requires explicit initialization for a fresh tenant. |

The unit has no capabilities, no-new-privileges, strict filesystem protection,
private temp/devices, no core dumps and control-group termination. Its complete
job budget is 15 minutes with a 10-second stop budget; individual backup tools
remain bounded to 60 seconds. These are configured limits. The measured small
fixture does not establish maximum-size performance or an observed 15-minute
timeout under a stalled filesystem.

Purge validation now opens recovery/marker paths without following links and
checks only file-descriptor metadata: root ownership, single regular file,
mode 0600 and bounded size. It does not read recovery-key plaintext merely to
delete the managed path. Ordinary uninstall preserves that custody.

The explicit setup CLI/OpenSSL generation process and root copy process consume
recovery plaintext while they run. Protected source/copy files persist under
operator custody. Backup/verification processes, OpenSSL children and private
staging consume plaintext during the job; systemd credential delivery lasts
for the unit. Ordinary staging cleanup is not secure media erasure. This
rehearsal keeps the separate key in a private guest fixture; it does not prove
off-host recovery storage or the external non-restored authority anchor.

## First failures and fixes

The first native run created the archive but failed in the new transient
verification helper. Unit-file `%d` syntax was passed as a transient argument;
the corrected helper reads `CREDENTIALS_DIRECTORY` inside the unit. Unique
transient names and the exact cryptographic-failure assertion ensure the wrong
key case cannot pass because a unit failed to launch.

One diagnostic rerun ended during SSH setup with a connection reset before
artifact testing. Its handle was terminal and the overlay was removed before
a new run. The host driver now retries only the read-only cloud-init observation
on transport/timeout errors, with a checked 180-second deadline; installer and
purge mutations are never retried this way.

After fixing the verifier, B08/N08 passed and the intended N09 test failed:
linked recovery custody was accepted by purge. The installer now preflights
these managed paths before stopping/deleting anything and removes them on exact
purge. Both OS profiles then passed, including the final metadata-only check
and actual documented no-clobber setup command.

## Gates and recorded output

| Gate | Evidence |
|---|---|
| Bookworm build | [build](p06-native-backup-2026-10-03/bookworm-build.txt) |
| Exact final package | [package](p06-native-backup-2026-10-03/package-final.txt) |
| Real final VM runs | [Debian](p06-native-backup-2026-10-03/debian-final.txt), [Ubuntu](p06-native-backup-2026-10-03/ubuntu-final.txt) |
| Intended first-red purge check | [output](p06-native-backup-2026-10-03/debian-purge-red.txt) |
| Initial verifier / SSH failures | [verifier](p06-native-backup-2026-10-03/debian-verifier-red.txt), [SSH](p06-native-backup-2026-10-03/debian-ssh-reset.txt) |
| Actual extracted archive R01–R04 | [runtime](p06-native-backup-2026-10-03/archive-runtime.txt) |
| Bookworm binary ENOSPC | [result](p06-native-backup-2026-10-03/bookworm-disk-full.txt) |
| Native manifest preflight / release components | 7/8 pass; [preflight](p06-native-backup-2026-10-03/preflight.txt), [release](p06-native-backup-2026-10-03/release-tests.txt) |

The extracted archive/disk-full gates use the same bookworm binaries; the final
native lifecycle runs additionally bind the final installer/unit/guide archive.
Python/shell syntax, local links and diff whitespace pass. The prior full source
gates remain in the [component evidence](p06-backup-components-2026-10-03.md):
672 Rust passes/four inherited ignores, final 10 backup checks, Clippy/format
and Node 26 build/tests with 101 SPS skips. Rust/JS source did not change during
this native follow-up. The user's existing P03 evidence edit remains untouched.

No restore is activated. Snapshot issuer metadata does not authorize stale
authority resurrection. PostgreSQL exported snapshot/full isolated restore,
PostgreSQL Compose backup, power loss, full size limits,
external ownership/recovery/fencing, upgrades,
transfers, complete three-profile/remote workflows and inherited gates remain
open. See the [paired vault plan](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/testing/phases/06-deployment-and-recovery.md).

The later [SQLite Compose and tool-fault follow-up](p06-compose-backup-2026-10-03.md)
records selected actual Compose B08, 100-MB timing/concurrent console requests,
encryption/decryption SIGKILL and all three ENOSPC phases. Those host tool gates
do not establish power-loss, container-fault or maximum-size behavior.
