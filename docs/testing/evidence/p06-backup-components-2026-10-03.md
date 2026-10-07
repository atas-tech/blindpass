# P06 authenticated backup components — 2026-10-03

**Status:** Slice 5 in progress. SQLite source components are verified; this is
an uncommitted implementation candidate on top of `8a595ad`. Selected native
and SQLite Compose artifact follow-ups are linked below. PostgreSQL backup
and remaining phase gates stay open. Full P06 acceptance remains open.
[Format/tool record](../../product/decisions/0010-p06-authenticated-backup-format.md)
· [paired acceptance plan](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/testing/phases/06-deployment-and-recovery.md)
· [sanitized execution outputs](p06-backup-components-2026-10-03/).

## Behavior checked

The source candidate adds `blindpass backup key-init|create|verify`, delegated
to the co-located controller. It creates a dedicated private recovery
key/certificate explicitly, captures SQLite with completed `VACUUM INTO`, binds
all three matching controller keys and snapshot metadata in a strict complete
archive, encrypts/signs with standard CMS, and verifies the decrypted archive
and database before encrypted publication. Verification requires the supplied
recovery credential independently of current controller keys. It does not
activate, migrate, initialize or reconcile a restored issuer.

The paired P06-B01–B10 scenarios were written before implementation. First-red
checks found missing envelope/snapshot/archive APIs and the absent CLI recovery
command; the OpenSSL prerequisite matrix failed before its implementation.
The first SQLite capture run failed because an in-memory connect option was
still active after setting a filename. Explicit file-backed read-only immutable
options fixed both live snapshot and damage checks.

| Scenario | Actual source result | Remaining scope |
|---|---|---|
| B01 | Concurrent WAL writes commit pairs during capture; captured transactions are complete, metadata matches and output mode is 0600 | Artifact repetition and crash boundaries |
| B02 | Not executed; current candidate explicitly refuses PostgreSQL backup | Matching custom dump, exported snapshot and isolated restore |
| B03 | Private recovery key, no overwrite, wrong/unsafe/linked key refusal; actual co-located CLI creation/repeat smoke passes | Native credential delivery and artifact runs |
| B04 | Changed/truncated ciphertext, unsigned input, embedded wrong signer, signed CBC and valid-signature/corrupt-GCM-tag inputs reject; no plaintext is published | Artifact interoperability and interruption matrix |
| B05 | Fixed members/modes, traversal/link headers with valid checksums, invalid checksum, altered member, truncation, trailing data, duplicate/unknown members, nonzero padding, oversized declarations, unknown/duplicate JSON fields and unsupported format/schema checks pass; failed extraction leaves an empty target | Artifact and full-size boundary repetition |
| B06 | Missing database never initializes; lost issuer key and conflicting key-directory lock refuse; ordinary errors leave no extra backup/staging; hanging child is killed/reaped; actual capture SIGKILL publishes nothing and explicit locked cleanup removes private residue; actual 1-MiB tmpfs capture ENOSPC cleans staging and preserves the 8-MiB source | Encryption/verification interruption and ENOSPC, power loss and PG failures |
| B07 | Captured keys match loaded config; shared directory lock prevents conflicting managed capture/key change; manifest binds complete snapshot/keys/digests | External continuity record and artifact/key-change rehearsal |
| B08 | Host source CLI only | Native unit and both Compose backup artifacts |
| B09 | Corrupt SQLite and missing provisioning table refuse; damaged database with fresh digests and a legitimate recovery signature still fails verification | PostgreSQL damaged dump and isolated restore |
| B10 | Host OpenSSL 3.6.4 passes prerequisite; fixed/vulnerable/unknown version matrix, real child timeout, missing-tool diagnostics, oversized declarations and newer-schema refusal pass | Actual vendor-backport checks and complete size-limit artifact tests |

## Gates and limits

Commands run from the repository root:

```sh
cargo test -p blindpass-controller --lib backup::tests --locked
cargo test -p blindpass-controller --test backup_envelope --test backup_archive --test backup_snapshot --test backup_command --locked
cargo test --workspace --locked -- --test-threads=1
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo fmt --all -- --check
npm run build
npm test
```

The full host Rust workspace passed **670 tests with four inherited ignores**:
three offscreen Quickshell cases and the opt-in PostgreSQL outage case. This
run preceded the final narrow Linux FFI declaration cleanup, GCM-tag regression
extension and archive-size reservation adjustment. Final affected backup
checks passed **eight tests, zero ignores**; the additional GCM-tag case and
affected archive/command cases passed again after those adjustments. Final
all-target Clippy and format checks pass. This is source evidence, not an exact
released artifact attestation.

Node **26.10.0** build and workspace tests pass on approved host execution.
The SPS default suite has **80 passes and 101 skips in 17 gated files**. The
workspace also reports 108 MCP and 147 helper/channel passes. Node 24 was not
rerun. Service-gated SPS, PostgreSQL backup, native VM backup, Compose backup,
Unraid, remote release and browser/operator backup acceptance are not established
by this checkpoint. No Cargo/npm package or lockfile changes accompany it.

The co-located CLI smoke created a mode-0600 recovery credential, refused a
repeat and removed its private fixture. No key bytes or plaintext archive were
printed. Shell syntax, local links and tracked/untracked whitespace checks pass.
The pre-existing P03 evidence edit remains unstaged and was not edited here.

Plaintext consumers/lifetimes, patched OpenSSL prerequisites and private crash
residue are specified in the [format record](../../product/decisions/0010-p06-authenticated-backup-format.md).
Integrity verification is not recovery authorization. The snapshot issuer epoch
does not replace a protected non-restored high-watermark. Stale-authority
invalidation, external ownership, reconciliation and fencing remain slice 6.

## Interruption and adversarial-archive follow-up — 2026-10-03

The additional B05/B10 cases use well-formed checksums and reconstructed
manifest headers, so malformed fixtures reach the intended member/manifest
checks. Duplicate members and bad member padding occur after a key has been
extracted; refusal removes that partial plaintext. Duplicate JSON fields,
unknown fields, unsupported format/schema and oversized declarations also
refuse. The actual canonical archive still verifies successfully.

The B06 cleanup test first failed because the command was missing
([red log](p06-backup-components-2026-10-03/cleanup-red.txt)).
`backup cleanup --work-directory <private-directory>` now takes exclusive
parent/candidate locks, preflights private no-follow directory custody and
removes only reserved staging names. Active parent/nested verifier locks,
linked stage directories and unsafe modes refuse. Published backups, recovery
files, unrelated names and an outside symlink target remain intact.

A separate actual process test kills capture after observing more than 1 MiB
of a 64-MiB dummy database in staging. No archive is published; retained files
are private and explicit cleanup removes them. The original payload remains
complete ([interruption log](p06-backup-components-2026-10-03/interruption.txt)).
This observes capture interruption, not encryption/verification interruption
or abrupt VM power loss.

Run the explicit disk-full gate from the root:

```sh
python3 tests/deployment/backup-disk-full.py --controller target/debug/blindpass-controller
```

The approved host has working non-root user/mount namespaces. Inside one,
the gate mounts a private 1-MiB tmpfs and attempts an 8-MiB SQLite snapshot.
The expected capture failure leaves no staging or published backup, and the
source length/integrity remain valid. The private mount is removed; no global
host mount or installed package changes. See the
[disk-full result](p06-backup-components-2026-10-03/disk-full.txt).
This script may target a future artifact, but this run used the source binary.

The scoped TLS and SBOM scanner approvals remain recorded in decisions
0008/0009. The separate [PostgreSQL toolkit proposal](../../product/decisions/0011-p06-postgresql-backup-toolkit-review.md)
is awaiting required human review. No runtime manifest change was applied
from that proposal. Full slice 5 and P06 acceptance remain open.

The follow-up full Rust workspace passes **672 tests, four inherited ignores**.
That run began before the final candidate-directory lock refinement. All final
affected backup checks then pass separately: **two unit checks and eight
integration cases, zero ignores**. Final all-target Clippy and format checks
pass. Node26 build/workspace gates pass again; SPS retains 80 passes/101 skips
in 17 gated files. No new Cargo/npm dependencies or lockfile changes were made.
Logs: [full Rust](p06-backup-components-2026-10-03/workspace-follow-up.txt),
[final units](p06-backup-components-2026-10-03/units-final.txt),
[final integrations](p06-backup-components-2026-10-03/integrations-final.txt),
[Clippy](p06-backup-components-2026-10-03/clippy-final.txt),
[Node build](p06-backup-components-2026-10-03/cleanup-npm-build.txt),
[Node tests](p06-backup-components-2026-10-03/cleanup-npm-test.txt).


## Native artifact follow-up — 2026-10-03

The [native execution record](p06-native-backup-2026-10-03.md) supersedes this
checkpoint's unrun native B08 status: the final bookworm controller archive
passes N01–N09 and NB01–NB04 on real Debian 12 and Ubuntu 24.04 systemd guests.
Actual shipped-unit capture and protected verification of an 8-MiB fixture
take 0.408 s and 0.466 s respectively for creation. Purge refuses unsafe recovery
custody before stopping the controller and removes only managed credentials
under exact confirmation. Retained-state reinstall verifies the old archive.

B10 executes the fixed upstream OpenSSL 3.0.22 branch on Debian and the explicit
Ubuntu 3.0.13 vendor-backport guard (package 3.0.13-0ubuntu3.16). Full size limits,
PostgreSQL, Compose backup, remaining interruption/fault cases and complete
slices 6–9 remain open. These artifact checks do not authorize restore activation
or establish full P06 acceptance.


## Compose and tool-fault follow-up — 2026-10-03

The [Compose backup/fault record](p06-compose-backup-2026-10-03.md) supersedes
this checkpoint's unrun SQLite Compose B08 and encryption/verification B06
status. Actual optional offline UID10001 backup service create/verify, custody
failures and retained-state recreation pass. Final 100-MB creation takes
2.104/5.735 s, with 109/280 continuous console-page HTTP requests and zero failures.
Actual shipped HTTPS profiles also pass on SQLite and PostgreSQL; ordinary
PostgreSQL serving does not imply PostgreSQL backup.

Observed capture/encryption/decryption ENOSPC cleans all staging, publishes
nothing and preserves the source. Actual crypto SIGKILL kills/reaps the child,
leaves only private residue and explicit cleanup preserves source/keys/original
archive. A complete 192-MiB bookworm-binary fixture verifies in 2.524 s. These
are selected B06/B10 checks, not power loss, container fault or maximum-size proof.
PostgreSQL backup, updated current-image SBOM and all remaining full-phase gates
stay open; full slice 5 remains uncommitted.


## Exact attested image and container fault follow-up — 2026-10-03

The [attested backup image/fault record](p06-backup-sbom-container-faults-2026-10-03.md)
binds config `3e84437a30e9e0f9419c2a77d40e8b18987597808000c7893c8ef718f45307a3`
to the actual OCI descriptor/subject/layer graph, three named SPDX inventories,
complete source lock entries and all 91 exact runtime Debian package/version
pairs. Eight verifier regressions pass after tests-first inventory and layer
binding failures. Exact-image create/verify/custody, 100-MB timing/concurrent
console requests, ordinary SQLite/PostgreSQL HTTPS profiles and actual container
capture/encryption/decryption ENOSPC pass. Empty staging is checked before
tmpfs unmount, and source/archives/readiness remain intact.

This closes selected SQLite artifact/SBOM and ordinary container ENOSPC gaps,
not PostgreSQL backup, sudden power loss, maximum-size or full P06. Toolkit human
review and all external recovery/ownership/fencing, upgrade/transfer and complete
workflow/remote/inherited gates remain required. The complete slice is uncommitted.
