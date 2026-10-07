# P06 deployment verification

The [vault acceptance plan](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/testing/phases/06-deployment-and-recovery.md)
owns the scenario IDs and complete matrix. Selected artifact/profile checks
below do not establish complete deployment parity, real broker workflows or
recovery/migration behavior. See [release layout](../../docs/deploy/release-layout.md).

From the repository root:

```sh
cargo test -p blindpass-cli --test keys --locked
cargo test -p blindpass-core --test consumed_report --locked
cargo test -p blindpass-controller --test deployment_layout --test shell_config --locked
cargo test -p blindpass-controller --test deployment_startup --test deployment_proxy --locked
python3 tests/deployment/controller-tls.py
python3 tests/deployment/release-artifacts-test.py
# After the pinned bookworm build from the release-layout guide:
python3 tests/deployment/release-archive.py --arch x86_64 \
  --bin-dir /tmp/blindpass-bookworm-binaries
```

The key tests cover P06-K01–K08 with disposable synthetic key material, exact
permissions, no silent trust replacement, symlink/hardlink denial, bounded
FIFO refusal and safe output. Layout/version cases cover P06-L01–L07; existing
shell tests preserve the legacy configuration/readiness envelope. Loopback
and Unix sockets require permitted host execution.

Startup/readiness cases preserve P06-S01–S06, including production process
refusal of absent/empty/older/damaged state, stable identity across restart and
adapter-specific missing metadata and clock-fence checks. Proxy cases preserve
P06-X01–X06 with actual TCP peers, reviewed IPv4/IPv6 CIDRs, forwarded-header
refusal, HSTS and rate-limit identity. The TLS script preserves P06-T01–T04;
build the current controller with embedded UI first. It needs OpenSSL for a
generated disposable certificate, validates it with Python's SSL trust store,
checks distinct input/console HTML, rate limiting and plaintext rejection,
saturates 64 handshakes and measures recovery and graceful shutdown. It consumes
no protected Source and is not a VM or full deployment-profile result.

The eight archive unit cases cover real ELF inspection, wrong architecture,
incompatible glibc requirements, unsafe/missing inputs, manifest hashes,
no-replace archive publication and failed compression. The actual archive gate
packages only explicit build inputs, adds a dummy exclusion canary, verifies
every extracted member's hash/mode/size, rejects duplicate publication and
starts the extracted controller/CLI with disposable private key/data roots.
It checks both embedded HTML surfaces, CSP and readiness and bounds shutdown.
This uses production config rules over loopback; it is not a systemd installer,
TLS proxy, Compose or two-host browser/native-backup E2E. The separate
`release-node-archive.py` gate (arguments in the release-layout guide) validates
the complete node archive, references from every shipped native unit to included
executables, full notices, helper/MCP resolution and a real packaged sandboxed
headless Chromium launch. It does not approve a browser task or consume a Source.

Still required: complete native/Compose workflow parity; consistent
authenticated encrypted backups on both stores; stale
restore against live/offline brokers; external ownership and interrupted source
fencing; protected upgrades/restore-only rollback; migration in both directions
with fault injection; the three-profile and remote-controller common-workflow
matrix; measured numerical bounds and inherited phase acceptance. P06-E05
SQLite/PostgreSQL conversion is explicitly unsupported and never counted passed.

## OCI and HTTPS edge candidates

```sh
cargo test -p blindpass-controller --test deployment_health --locked
python3 tests/deployment/container-config-test.py
docker build -f deploy/controller/Dockerfile -t blindpass-p06-controller:local .
docker build -f tests/deployment/edge.Dockerfile -t blindpass-p06-edge:local tests/deployment
tests/deployment/compose-up.sh --profile sqlite
tests/deployment/compose-up.sh --profile postgres
python3 tests/deployment/controller-sbom-test.py
python3 tests/deployment/controller-sbom.py --archive /path/to/named-attested-image.tar \
  --config-digest sha256:TESTED_IMAGE_ID --runtime-packages /path/to/runtime-packages.tsv
```

The first two gates cover H01/H02 and Compose/Unraid O09 configuration. The
actual TLS script also covers H03's verified CA/name and refusal cases. The
profile driver uses uniquely named disposable projects, private dummy keys,
password/URL files and certificates, actual volume initialization, real
process/mount checks, both shipped nginx/Caddy examples, untrusted network
peer and forged-header denials, controller recreation, PostgreSQL outage and
bounded Docker readiness. It captures bootstrap credentials only in memory;
logs assert they never appear. It removes only its own containers, networks,
volumes and private fixture files. Docker host access is required. It never
installs a controller on the host or runs a broker container.

O01 scans every exported image layer for the generated exposure canary and
encoded private PEMs. The sole exception is a public self-test key inside the
identical GnuTLS binary from the pinned official Debian base. It is digest-bound
rather than a blanket skip for libraries or lower layers. The image also
preserves available upstream npm/Cargo notices with path/hash inventories.

O10 needs an attestation-capable Buildx driver and a named OCI export; the
classic Docker driver cannot export attestations. Use the exact user-approved
scanner and additive cataloger expression in the
[controller image workflow](../../.github/workflows/build-and-push-images.yml).
The verifier checks all OCI descriptor hashes, image/subject binding, ordered
uncompressed-layer hashes from the image config, the three named SPDX documents,
every Cargo registry lock entry in the Rust inventory and every non-optional npm
lock entry in the UI inventory. `--config-digest` binds the artifact to the tested
local image ID; `--runtime-packages` requires exact runtime Debian package/version
equality with the private-output-free TSV queried from that same image:

```sh
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --entrypoint dpkg-query IMAGE \
  -W '-f=${Package}\t${Version}\n' > runtime-packages.tsv
```

The eight synthetic regression cases reject missing/duplicate/mislabeled stages,
cross-stage package substitution, descriptor corruption, wrong config and wrong
filesystem hashes. They do not execute the scanner. Build-stage inventories include source/fixture
and declared dependencies; they do not imply all packages execute at runtime.
Local OCI attachment is separate from unexecuted GHCR publication/aarch64 CI.

The [Compose guide](../../docs/deploy/compose-quickstart.md) documents credential
consumers/lifetimes, explicit initialization, ingress and retained-state removal.
Real Unraid GUI/pool/lifecycle checks, complete browser/native backup workflows,
recovery/fencing/upgrade/migration and the full three-profile/remote matrix remain
required. Selected Compose lifecycle checks do not establish P06 acceptance.


## Packaged authority sequence

```sh
cargo build -p blindpass-controller -p blindpass-cli --locked
python3 tests/deployment/authority-operator-flow.py --log "$(mktemp -u)"
python3 tests/deployment/native-authority-test.py
```

AO00–AO09 run the shipped `authority-*.sql` files and the real controller against
a disposable PostgreSQL authority: issuer id, pristine registration, migrate,
one-use activation, restart without activation (not ready), re-activation after
stop, fencing a live holder, maintenance only while fenced and refusal to
activate a `recovering` record. The native VM harness uses an in-guest PostgreSQL
as the authority, which proves the installer sequence but is **not** an
independent authority host. Compose gates (`compose-up.py`) supply the authority
URL/CA through the read-only `/authority` bind mount.

## Authenticated backup candidates

The separate [authority/process/router checks](../../docs/testing/evidence/p06-process-ownership-2026-10-03.md)
and [operation/store checks](../../docs/testing/evidence/p06-owned-store-2026-10-03.md)
use the existing reviewed PostgreSQL test fixture. They provision only a new
generated authority database and restricted roles, never controller state:

```sh
cargo test -p blindpass-controller --test recovery_authority --locked
python3 tests/deployment/recovery-authority-postgres.py --log /tmp/p06-authority-test.txt
python3 tests/deployment/recovery-authority-postgres.py --filter p06_pt --controller-backend postgres --log /tmp/p06-trust-postgres.txt
python3 tests/deployment/recovery-authority-postgres.py --test-target recovery_authority_migration --log /tmp/p06-authority-migration.txt
python3 tests/deployment/recovery-authority-postgres.py --test-target recovery_receipts --log /tmp/p06-receipts.txt
```

The driver requires host Docker access and the existing `blindpass-postgres`
fixture on 5433 (explicit options override container/admin identity/port).
It bounds administration, creates the public log exclusively with mode 0600,
keeps generated credentials out of argv/output and drops only its generated
database/roles. Run after other Cargo builds release the shared build lock.

PT01–PT06 add actual held-connection proof, separately protected current/pending
broker keys, revocation and actual owned enrollment/rotation/revocation HTTP
publication. Run the `p06_pt` filter on both controller backends. A failed local
controller commit preserves external revocation and fences uncertain work.
The migration target gets its own database and constructs a version-2 input
from the schema-3 fixture by removing only the new additions; it is not an
installed-deployment migration result. It executes the administrator SQL,
refuses active tenants, runtime administration, held guards and replay, and
verifies preserved high-watermarks/attempts, absent historical proof and the
explicit v3→v4 step, retained keys/revocation and subsequent current claim/publication.
The receipt target tests durable exact-context nonce/page storage, current or
approved pending signatures, restarted collection, digest/coverage/refusal and
observed-epoch bounds outside controller backups. Reopening cannot reset a
consumed nonce; unknown/pruned/unmapped reports stay blocked, and observation at
or above the reservation requires rebase. Read the
[execution boundary](../../docs/testing/evidence/p06-durable-receipts-2026-10-04.md)
for all six expanded runtime cases and the separate workspace/profile limits.
RC08a/b run with `--test-target restore_stage --filter p06_rc08`. They restore
actual encrypted schema16/17 input, verify persisted snapshot time/digest after
fenced production restart, and refuse missing/tampered/unbound signed context.
See [snapshot execution limits](../../docs/testing/evidence/p06-authenticated-recovery-snapshot-2026-10-04.md).
The PostgreSQL local migration/read implementation is not full PostgreSQL archive
restore evidence; that toolkit and isolated restore remain separate.
Four scoped Store cases run with `--test-target restore_stage --filter p06_rc08c`:
protected current keys despite stale restored key rows, foreign snapshot time/
digest refusal before mutation, replay/context/gap refusals and actual blocked
stage/socket loss with retained uncertainty. See [scope execution limits](../../docs/testing/evidence/p06-scoped-recovery-collection-2026-10-04.md).
Six local application cases run with `--test-target restore_stage --filter p06_rc08d`. The driver now always provisions a separate disposable PostgreSQL controller database for this target, alongside its restricted external authority. A manually populated local PostgreSQL fixture tests application and rollback, not PostgreSQL archive restore. See [execution evidence](../../docs/testing/evidence/p06-recovery-application-2026-10-04.md).
None of these checks establish authenticated source
shutdown, complete recovering report consumption, node relay or activation.
The 33 authority integration cases are ignored by ordinary cargo tests and actually
executed by this driver. `--filter p06_op11` selects a narrower named check;
inspect executed counts and use the default full run for this component gate.
Faults affect only generated database connections and owned loopback proxies.
Operation/store cases exercise retained guard lifetimes, irreversible Store/signing
bindings and cancellation of a one-use retrieval behind a real SQLite write lock.
They do not establish mandatory production startup integration, separate-host
issuer exclusion, ambiguous server-side mutation/body quiescence or restore/activation.

```sh
cargo test -p blindpass-controller --test postgres_config_diagnostics --locked
cargo test -p blindpass-controller --test backup_envelope --test backup_archive --test backup_snapshot --test backup_command --test backup_cleanup --locked
python3 tests/deployment/backup-disk-full.py
python3 tests/deployment/backup-interruption.py
python3 tests/deployment/backup-size-limit.py
# Guest-only installation from the exact packaged native archive:
tests/deployment/native-install.sh --os debian-12 --archive FILE
tests/deployment/native-install.sh --os ubuntu-24.04 --archive FILE
# Abrupt guest power interruption and recovery during encryption:
tests/deployment/native-install.sh --os debian-12 --archive FILE --power-loss
tests/deployment/native-install.sh --os ubuntu-24.04 --archive FILE --power-loss
# N10 (forward upgrade with an automatic verified pre-upgrade backup) is part of every
# run above, including --power-loss since 2026-10-05; the guest repacks the same binaries as 0.1.1.
# The run directory (guest overlay, several GiB) defaults to /tmp; on a quota- or size-limited
# tmpfs set BLINDPASS_NATIVE_RUN_ROOT=/path/with/room (see the P06-D29 record).
# Missing/stalled crypto tool in the disposable guest, then restoration:
tests/deployment/native-install.sh --os debian-12 --archive FILE --tool-faults
tests/deployment/native-install.sh --os ubuntu-24.04 --archive FILE --tool-faults
# Unsafe original backup custody (signing credential, recipient certificate), refused before backup execution:
tests/deployment/native-install.sh --os debian-12 --archive FILE --credential-faults
tests/deployment/native-install.sh --os ubuntu-24.04 --archive FILE --credential-faults
tests/deployment/native-install.sh --os debian-12 --archive FILE --recovery   # restore, review, attestation, activation (NR01-NR05)
tests/deployment/native-install.sh --os ubuntu-24.04 --archive FILE --recovery
```

PGQ01–PGQ03 reject unsupported PostgreSQL URL option names before SQLx can log
their values. The actual JSON/text startup checks use a private dummy listener,
require no database connection/state creation and expose no generated canaries.
Supported plain/encoded names and production-file/test-mode transport are checked
without a PostgreSQL server or the proposed dump/restore toolkit.

The source backup cases cover selected B01/B03–B07/B09/B10, including live WAL
capture, protected key binding, authenticated envelope/member validation, actual
SQLite integrity checks and explicit locked cleanup after capture SIGKILL. The
disk-full script requires approved non-root user/mount namespace access and uses
private tiny tmpfs mounts. It observes actual capture/encryption/decryption output
growth, then asserts ENOSPC refusal, complete cleanup and intact source.
It mounts no host filesystem globally. See [source evidence](../../docs/testing/evidence/p06-backup-components-2026-10-03.md).
The interruption script uses a private child subreaper to kill during observed
encryption/decryption progress and actually reap adopted OpenSSL children; it
checks private residue, explicit cleanup and preserved source/key/archive state.
Its complete 192-MiB fixture is a selected large-backup gate, not the 512-MiB limit.
The size-limit script constructs the largest admitted page-aligned SQLite member,
fully creates/verifies its authenticated backup, then adds one overflow page and
requires limit refusal with the old archive and source identity/payload/keys intact.
Allow about 8 GiB temporary free space. See
[actual boundary evidence](../../docs/testing/evidence/p06-backup-size-boundary-2026-10-03.md).

The existing SQLx-only PostgreSQL snapshot guards are separately tested with a
private disposable `P02_TEST_POSTGRES_URL`:

```sh
cargo test -p blindpass-controller --test backup_postgres_snapshot --locked -- --ignored --test-threads=1
cargo test -p blindpass-controller --lib postgres_snapshot --locked -- --ignored --test-threads=1
```

These tests establish snapshot import, metadata/count coherence, read-only mode,
lifetime and schema refusal. They create no PostgreSQL dump and perform no isolated
restore. See [snapshot evidence](../../docs/testing/evidence/p06-postgres-snapshot-2026-10-03.md).
The [abrupt guest-power record](../../docs/testing/evidence/p06-native-power-interruption-2026-10-03.md)
adds observed frozen encryption, scoped QEMU SIGKILL, rebooted-disk custody,
private residue cleanup, earlier-archive verification and clock-fenced readiness
on both pinned native profiles. This is separate from physical host/storage power
loss and restored-state authority.
The [native tool-fault record](../../docs/testing/evidence/p06-native-tool-faults-2026-10-03.md)
adds missing-tool refusal, the actual 60-second tool deadline, child reaping,
continued readiness, private cleanup and earlier-archive verification after
restoring OpenSSL. `--power-loss`, `--tool-faults`, `--credential-faults` and `--recovery` are
separate opt-in runs.

NB07/B03/B08 checks the original recovery file's ownership, mode, link count,
type and size, plus the enable marker and parent directory protections. The
metadata-only preflight must refuse each unsafe fixture before the backup
executable starts, preserving readiness and the earlier fully verified archive.
Systemd's private runtime credential does not establish original source custody.
The [custody record](../../docs/testing/evidence/p06-native-recovery-custody-2026-10-03.md)
records the first-red gap, corrected harness and actual updated-archive passes
on both pinned native profiles.

The actual native harness extends N01–N09 with NB01–NB04/B08: disabled-by-default
backup, explicit protected recovery-key delivery, live shipped-unit create/verify,
wrong-key refusal, timer opt-in, retained-state reinstall and exact purge custody.
It requires the pinned guest image and its digest from the fleet setup, disposable
SSH/TLS keys and approved KVM/QEMU access. Installers run only in the guest.
[Native evidence](../../docs/testing/evidence/p06-native-backup-2026-10-03.md) records
the exact final archive, both real profiles, durations and tool versions;
[the guide](../../docs/deploy/native-quickstart.md) states plaintext consumers
and lifetimes. PostgreSQL backup and remaining phase gates stay open.

```sh
# Build the current candidate image first; the earlier image has no backup CLI.
docker build -f deploy/controller/Dockerfile -t blindpass-p06-controller:backup-sqlite .
python3 tests/deployment/compose-backup.py --image IMAGE --payload-bytes 100000000 --faults
```

CB01 is in `container-config-test.py`. CB02–CB04/B08 use the actual shipped
SQLite backup overlay and private UID10001 recovery bind, with no recovery
mount on the ordinary controller and no backup network/host socket. The 100-MB
variant measures selected I02's 30-second creation bound and continuously
requests the embedded console through the configured trusted edge peer;
HTTPS edge behavior runs separately in `compose-up.py`. All resources belong
to a uniquely named disposable project. See [Compose backup/fault evidence](../../docs/testing/evidence/p06-compose-backup-2026-10-03.md)
and [operator commands](../../docs/deploy/compose-quickstart.md#explicit-sqlite-backup).
CB05 exhausts space in private per-container backup tmpfs mounts, observes actual
capture/encryption/decryption output growth and inspects empty staging before
unmount. Original source/archives/readiness survive, with no global host mount
changes. The [attested image/fault record](../../docs/testing/evidence/p06-backup-sbom-container-faults-2026-10-03.md)
binds final image/SBOM/layer/package metadata to actual backup and both baseline
HTTPS profiles. Current candidate is `blindpass-p06-controller:backup-sqlite-sbom`;
use its recorded config ID rather than inferring identity from a mutable tag.

### PostgreSQL toolkit backup (ADR 0011)

```sh
docker build -f deploy/controller/Dockerfile -t blindpass-p06-controller:pg .
tests/deployment/pg-toolkit-test.sh                     # PGT01-PGT05 in the image's pgtest stage, UID 10001
python3 tests/deployment/compose-backup-postgres.py --image blindpass-p06-controller:pg
```

`pg-toolkit-test.sh` builds the Dockerfile's `pgtest` stage and runs the ignored
`backup_postgres_toolkit` tests inside it, because the pinned binaries exist only
in the image. They cover the full backup/verify path, concurrent writes, flipped,
truncated and forged dumps, wrong password/stopped database, and SIGKILL cleanup.
`compose-backup-postgres.py` (PGC01-PGC05) runs the shipped overlay against a
disposable PostgreSQL project, including output exhaustion at capture and at
verification. Docker host access is required. Set `BLINDPASS_HARNESS_DIAGNOSTICS=1`
to print container logs on failure. The runtime `Dockerfile` stage must stay last.

PostgreSQL restore and upgrade run through the authority driver inside the same
`pgtest` image (host networking reaches the disposable authority; environment values
travel by name only):

```sh
python3 tests/deployment/recovery-authority-postgres.py --test-target restore_postgres --log /new/log
python3 tests/deployment/recovery-authority-postgres.py --test-target production_ownership \
  --controller-backend postgres --in-image --filter p06_up --log /new/log
python3 tests/deployment/compose-up.py --profile postgres --image IMAGE   # includes the PostgreSQL upgrade gate
```

RP01-RP05 and UP13/UP14 are described in the
[restore and upgrade record](../../docs/testing/evidence/p06-postgres-restore-2026-10-05.md).
The `pgtest` stage prebuilds its test targets, so a source change rebuilds them with
the image. Docker needs several GB of free disk for this stage.

## Durable recovery invalidation candidate

Run RI01–RI06 on both stores using the existing approved PostgreSQL fixture:

```sh
python3 tests/deployment/recovery-authority-postgres.py --test-target recovery_invalidation --controller-backend sqlite --log /tmp/p06-ri-sqlite.txt
python3 tests/deployment/recovery-authority-postgres.py --test-target recovery_invalidation --controller-backend postgres --log /tmp/p06-ri-postgres.txt
python3 tests/deployment/recovery-authority-postgres.py --test-target recovery_activation --controller-backend sqlite --log /tmp/p06-ra-sqlite.txt
python3 tests/deployment/recovery-authority-postgres.py --test-target recovery_activation --controller-backend postgres --log /tmp/p06-ra-postgres.txt
```

Use fresh log paths: the driver refuses overwrite and linked files. It owns a
separate authority database with restricted runtime access and, for PostgreSQL,
a distinct controller database/role with no authority privileges. Credentials
exist only in private process memory/stdin/environment; logs contain fixed
summaries. All generated databases/roles are removed in `finally`. The normal
schema16 archive-verification case runs in the regular Rust suite. These are
metadata/HTTP/database tests, not signed broker report, actual restore activation
or packaged-profile guarantees. See [execution evidence](../../docs/testing/evidence/p06-recovery-invalidation-2026-10-03.md).

## Legacy JWT/HMAC authority versioning

```sh
python3 tests/deployment/recovery-authority-postgres.py --test-target legacy_authority --controller-backend sqlite --log /tmp/p06-la-sqlite.txt
python3 tests/deployment/recovery-authority-postgres.py --test-target legacy_authority --controller-backend postgres --log /tmp/p06-la-postgres.txt
python3 tests/deployment/recovery-authority-postgres.py --test-target fleet_provisioning_submit --controller-backend postgres --filter p06_la05 --log /tmp/p06-la-source-postgres.txt
```

Use fresh log paths. The legacy target runs four explicitly ignored HTTP cases;
`fleet_provisioning_submit` runs normal cases and does not pass `--ignored`.
Omitting its filter executes the complete Source suite. Its SQLite cases and
three LA06 crypto vectors also run in the ordinary Rust workspace. Fixture epoch
writes isolate cryptographic versioning while retaining credentials/rows; they
are not an external reservation, restore/unfence or packaged-profile proof.
See [execution evidence](../../docs/testing/evidence/p06-legacy-authority-2026-10-04.md).


### Mandatory production ownership candidate

```sh
python3 tests/deployment/recovery-authority-postgres.py --test-target production_ownership --controller-backend sqlite --log /tmp/p06-production-sqlite.txt
python3 tests/deployment/recovery-authority-postgres.py --test-target production_ownership --controller-backend postgres --log /tmp/p06-production-postgres.txt
python3 tests/deployment/recovery-authority-postgres.py --test-target deployment_startup --log /tmp/p06-production-startup.txt
```

The first target now runs ten ignored integration cases with actual production
processes, complete quiescent private fixture copies, held guards, ordinary HTTP
and local admin, diagnostic startup and fenced maintenance. The last runs five
original S01–S05 SQLite production cases with real separate authority; its backend
is SQLite only. Normal source startup cases continue to test both adapters.
Record fields remain private files/environment, never argv or public logs.
The controller role has no authority-table/DDL permission. These fixtures do not
perform protected restore/unfence, source-stop proof or packaged-profile transfer.
See [execution evidence](../../docs/testing/evidence/p06-production-ownership-2026-10-04.md).


### Transport lifetime and shutdown candidate

```sh
python3 tests/deployment/recovery-authority-postgres.py --test-target production_ownership --controller-backend sqlite --filter p06_qf --log /tmp/p06-qf-process-sqlite.txt
python3 tests/deployment/recovery-authority-postgres.py --test-target production_ownership --controller-backend postgres --filter p06_qf --log /tmp/p06-qf-process-postgres.txt
python3 tests/deployment/recovery-authority-postgres.py --filter p06_qf --log /tmp/p06-qf-socket.txt
cargo test -p blindpass-controller --test admin_socket --locked --offline -- --test-threads=1
```

The process filter executes three real HTTP/TLS/admin shutdown cases per backend.
The authority filter executes three actual socket cases, including measured
60-second idle expiry, an unread large response and exact local FD closure before
ownership release. Linux proc observations inspect only this test process or its
owned controller child; they are not old-host authentication or server SQL proof.
Already accepted transports may close during fencing. Fresh diagnostic readiness
must still reach 503 and all ordinary paths refuse without additional mutation.
Use fresh log paths; the full target also preserves all seven ownership cases.
[Execution record](../../docs/testing/evidence/p06-transport-ownership-2026-10-04.md)
distinguishes local transport/task drainage from QF07/QF08, which remain required.

For actual PostgreSQL server cancellation/COMMIT faults, run:

```bash
python3 tests/deployment/recovery-authority-postgres.py \
  --test-target store_quiescence --controller-backend postgres \
  --log /tmp/p06-store-quiescence.txt
```

The four QF07-A–D cases use a separate disposable controller database and
restricted authority. Observers wait for actual server completion before reading
late committed rows. The first three must retain uncertainty and refuse local
quiescence/reservation while their owner lives; the healthy case drains. Database
pool closure and future cancellation are not server rollback receipts. Production
shutdown checks separately classify successful local drain and the exact refusal,
preserving their five-second stop and no-issued-row assertions. See the
[execution record](../../docs/testing/evidence/p06-database-uncertainty-2026-10-04.md).


## P06 authenticated fenced restore stage

Build the real co-located CLI first (`cargo build -p blindpass-cli --locked
--offline`). Run `python3 tests/deployment/recovery-authority-postgres.py
--test-target restore_stage --log /tmp/p06-restore-stage.txt` with approved
access to the existing PostgreSQL fixture. Seven ignored ST01/ST02/ST03/ST04/
ST06/ST07/ST08 cases exercise real encrypted archives, restricted authority,
private no-overwrite publication, competing holders, isolated schema-16 migration,
actual fenced production HTTP diagnostics and CLI forwarding. ST07 applies a
512 MiB **process address-space** limit with two Tokio workers and 10,000 audit
rows; it does not establish whole-container/profile memory bounds.

For the dedicated fault build, add `--test-features p02-test-failpoints`. Two
additional ignored ST04/ST05 cases stop the owned restore process immediately
before publication and terminate its independently observed disposable authority
socket, or exit at extract/invalidation/pre-publication boundaries. They require
Linux `/proc` and `/bin/kill`, preserve encrypted input, inspect private residue,
exercise explicit custody-locked cleanup and retry to fenced state. The stop hook
is absent from ordinary builds. The driver owns and cleans its authority database
and roles; never supply a shared production authority.

The ordinary core `directory_publication` tests cover existing-empty-directory
preservation and complete private directory publication with linked/unsafe source
refusals. See the [restore stage guide](../../docs/deploy/recovery-stage.md).
Full source-stop, broker/provider reconciliation, protected activation and all
nine P06 slices remain required.

## Planned same-owner handoff (P06-D28)

[Runbook](../../docs/deploy/handoff.md) and [evidence record](../../docs/testing/evidence/p06-handoff-2026-10-05.md).

| ID | Where | What it proves |
|----|-------|----------------|
| `p06_ho01`–`p06_ho05`, `p06_ho07` | `crates/blindpass-controller/tests/production_ownership.rs` (authority driver, SQLite and PostgreSQL controller backend) | export/import/abort state machine, every import mismatch, the destination exact-revision rule, retirement of the source, repeatable export, PostgreSQL controllers refuse |
| `p06_ho06` | same file, `--test-features p02-test-failpoints` | export killed after the archive and import killed before publication repeat safely |
| `p06_ho_cli_*`, `p06_ho_unit_*` | `blindpass-cli/tests/handoff.rs`, `handoff.rs` unit tests | CLI forwarding and option refusal; marker parsing |
| `P06-H1`–`P06-H5` | `compose-up.py --profile sqlite --scenario handoff` | two Compose projects sharing one authority: export, repeat, abort, re-export, import, install, activation, stale-source refusal, abort refusal after activation |
| container config `p06_ho_config_*` | `container-config-test.py` | the overlay is opt-in, private, offline where it can be, and keeps recovery custody off the ordinary service |

```sh
python3 tests/deployment/recovery-authority-postgres.py --test-target production_ownership --controller-backend sqlite --log NEW_LOG
python3 tests/deployment/recovery-authority-postgres.py --test-target production_ownership --controller-backend postgres --log NEW_LOG
python3 tests/deployment/recovery-authority-postgres.py --test-target production_ownership --controller-backend sqlite \
  --test-features p02-test-failpoints --filter p06_ho --log NEW_LOG
docker build -f deploy/controller/Dockerfile -t blindpass-p06-controller:handoff .
python3 tests/deployment/compose-up.py --profile sqlite --scenario handoff --image blindpass-p06-controller:handoff
```

`--scenario handoff` runs only the handoff gate (no image scan, no edge, no fault scenarios) and
the handoff overlay is included only for it, because the overlay requires its variables at render
time. The real-node scenario is `tests/fleet/p06-handoff-vm.py` ([fleet README](../fleet/README.md)).

## Packaged recovery (P06-D30..D32 on the shipped profiles)

[Evidence record](../../docs/testing/evidence/p06-native-recovery-faults-2026-10-05.md) (earlier flow:
[packaged recovery](../../docs/testing/evidence/p06-packaged-recovery-2026-10-05.md)) and
[runbook](../../docs/deploy/recovery-activation.md).

| Scenario | Command | What it proves |
|---|---|---|
| `P06-RC1`–`RC8` | `python3 tests/deployment/compose-up.py --profile sqlite --scenario recovery --image IMAGE` and `--profile postgres` | backup through the shipped backup job, fence, reserve, total loss of keys and state, offline-custody restore through `controller-restore`/`controller-restore-install`, fenced restored controller, refusals, review, named waiver, completion, attestation, activation, served identity and key bytes preserved, a restore of the same archive into a second Compose project with fresh volumes (original stack never serves, restored stack keeps serving; the PostgreSQL profile needs the init hook's empty `controller` schema dropped first), restore-based rollback, no secret in logs |
| `P06-NR01`–`NR05` | `tests/deployment/native-install.sh --os debian-12\|ubuntu-24.04 --archive FILE --recovery` | the same on the native package in a real systemd guest, with the restore run through the packaged `blindpass-controller-restore.service` (offline custody and a private environment file present only for the restore; skipped when they are absent; hardening properties asserted); the pre-restore state is refused after activation |
| `P06-NF1`–`NF3` | `tests/deployment/native-install.sh --os debian-12\|ubuntu-24.04 --archive FILE --faults` | the Compose F1-F3 subset on the native package: SIGKILL (never ready without a fresh activation, then ready under 15 s), 20 s SIGSTOP, and loss of the database (refused with reason `state_missing`, never recreated, restored state serves again) |
| `container-config-test.py` `rc_config` | `python3 tests/deployment/container-config-test.py` | both restore overlays are opt-in, private, offline-custody only, tmpfs staging, no network for the install job |

`--scenario recovery` includes the backup and restore overlays only for itself because they require their variables at render time.
The harnesses have no real node: they seed one authority broker-trust row and cover it with a named waiver. The real-node scenarios
are the QEMU harnesses in the [fleet README](../fleet/README.md); `tests/fleet/p06-compose-node-vm.py` runs a real broker and node
against these same shipped Compose profiles ([record](../../docs/testing/evidence/p06-compose-node-2026-10-05.md)).
`tests/fleet/p06-native-node-vm.py` (with the controller-guest driver `native-node-guest.py` in this directory) does the same against the packaged native
controller in a second guest, including the native stale-source refusal ([record](../../docs/testing/evidence/p06-native-node-2026-10-05.md)); `native-guest.py` has a `main()`
guard so that driver can import its helpers.
