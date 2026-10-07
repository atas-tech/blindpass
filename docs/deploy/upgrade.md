# Controller upgrade

Status: SQLite (native installer and Compose overlay) and PostgreSQL (Compose
overlay, controller image only) engines. A PostgreSQL store needs the pinned
toolkit that only the controller image carries, so a host without it refuses an
older PostgreSQL schema unchanged. Downgrade is restore-only.

## What `migrate` does for an older schema

`blindpass migrate --pre-upgrade-backup-dir DIR --signing-credential-file SIGNING
--recipient-certificate-file RECIPIENT_CERT` (or the earlier single `--recovery-key-file`), under the
fenced authority record (the same maintenance rule as initialization):

1. Reads the stored schema. Current: verifies and exits, no backup. Newer than
   this build, older than schema 16 or damaged: refuses unchanged and takes no
   backup. An older PostgreSQL store with no pinned toolkit also refuses unchanged. Older, supported (16 or later) with the two
   options: continues. Older without them: refuses unchanged.
2. Publishes an encrypted backup of the still-unmigrated database to
   `DIR/pre-upgrade-<13-digit-ms>-v<schema>/`, after a complete verification
   (decrypt, integrity, schema and tenant). With split custody the upgrade host has no
   key that decrypts the archive, so the verification runs inside the backup through a
   throwaway co-recipient that is destroyed with the staging directory; with the
   single credential the published archive is also reopened independently. A backup
   that cannot be created or verified aborts the upgrade and leaves nothing published.
3. Applies the idempotent migrations, advances the schema marker once, verifies
   metadata against the protected record and reopens the store.
4. Keeps the three newest `pre-upgrade-*` directories; unrecognized names and
   links are never touched. Retention is best effort after the migration.

An interrupted upgrade is repeatable: the marker moves only at the end, so a rerun
takes a new backup and completes. The only supported rollback is to restore the
pre-upgrade backup with `restore`; there is no schema downgrade. A PostgreSQL
pre-upgrade archive restores into an **empty** target database and is brought
forward there ([recovery stage](recovery-stage.md#postgresql-archives)). A restored
controller serves again only through the [protected recovery activation](recovery-activation.md)
procedure; the restore-based rollback rehearsal for it is recorded in the
[activation record](../testing/evidence/p06-recovery-activation-2026-10-05.md).

Custody follows [ADR 0013](../product/decisions/0013-p06-backup-key-custody-split.md):
the upgrade host holds a signing credential and the recipient's *certificate*; the
recipient private key stays offline. The create-time verification does not prove that
the offline recipient entry decrypts. After every upgrade run `blindpass backup verify`
with the recipient key (and keep a restore drill on a schedule) before relying on the
rollback archive. The single `--recovery-key-file` form is still accepted; it signs
and decrypts, so anyone holding it reads every archive.

## Native sequence

Before the first step, take and verify a backup if the new build keeps the same schema: `migrate` publishes its
automatic pre-upgrade backup only for an **older** schema, and a native installation has **no way back to the previous
program** (the installer refuses an older archive; only a restore returns the earlier state). See
[rollback](../release/rollback.md), which also records what a rehearsed rollback does and does not restore.

```sh
sudo systemctl stop blindpass-controller.service
# Administrator: new artifact installs only, never migrates or starts.
sudo ./deploy/native/install.sh --upgrade        # from the new, verified archive
psql -v tenant=TENANT -v owner=OWNER -v issuer=ISSUER -f authority-fence.sql
sudo systemctl start blindpass-controller-upgrade.service
journalctl -u blindpass-controller-upgrade.service -o cat   # from/to schema, backup_taken
psql -v tenant=TENANT -v owner=OWNER -v issuer=ISSUER -f authority-activate.sql
sudo systemctl start blindpass-controller.service
```

`--upgrade` refuses: a running controller, a missing or unsafe backup custody
(`/etc/blindpass/controller-backup-signing-credential` and
`/etc/blindpass/controller-backup-recipient-certificate`, both root-only 0600), a version not
newer than the installed one, an installation without an authority, and any
`--initialize`/`--start`. It installs the new tree beside the old one, publishes the
new units, then switches `current` atomically and records the version. The old
tree stays until uninstall. The upgrade unit runs with the same hardening as
initialization and writes backups to `/var/lib/blindpass/controller/pre-upgrade-backups`.

Run the unit only when the controller is stopped and the record is fenced: starting
it with an active record refuses. A start of the upgraded controller still needs a
fresh activation.

## Compose PostgreSQL

[`compose.upgrade-postgres.yml`](../../deploy/controller/compose.upgrade-postgres.yml)
adds the opt-in `upgrade` profile job to the PostgreSQL profile. Same sequence as the
SQLite overlay: stop the controller, fence the authority record, run the job with the
protected recovery directory, then activate and start. The job reads the database
URL from the private `/config/database.url` file, joins only the edge and internal
database networks and writes backups to `/data/pre-upgrade-backups`:

```sh
docker compose -p blindpass -f deploy/controller/compose.postgres.yml \
  -f deploy/controller/compose.upgrade-postgres.yml --profile upgrade \
  run --rm controller-upgrade
```

## Confirming that nodes reconnected

After activation, check the fleet through the operator API before retiring the
previous controller or declaring a rollback unnecessary:

```sh
printf '%s\n' "$OPERATOR_PASSWORD" | blindpass status --nodes --require-online \
  --controller-url https://controller.example --username admin --password-stdin
```

The report counts nodes as `online` (seen within 45 s), `stale` (within 120 s),
`offline` or `revoked`, and lists id, status, key version and last-seen time only.
`--require-online` exits non-zero unless at least one node is active and every
active node is online. It reads what the controller has observed; it does not
prove that a broker will accept work or that the node holds the right keys. The
120 s reconnect bound in the P06 plan is a measurement to take with a real node,
not something this command enforces. After a Compose recovery activation a real
node passed this gate 1.6–5.7 s after the controller started (four runs, one
host; [record](../testing/evidence/p06-compose-node-2026-10-05.md)).

## Moving to a new host or project

Upgrading in place keeps the same host and volumes. To move a SQLite controller to a new
host or Compose project under the same owner without a recovery, use the
[planned handoff](handoff.md); it needs the same stopped, fenced source and a destination
at the **same schema**, so upgrade first. The handoff is not a rollback path once the
destination activated.

## Not covered

A restore-based rollback of a PostgreSQL controller (the restore of a PostgreSQL
pre-upgrade archive is tested in the toolkit image, not as a full rollback; the SQLite native rollback was rehearsed on real guests,
[record](../testing/evidence/p07-rollback-2026-10-06.md)), returning a native installation to the previous program version (not possible with the shipped installer), upgrade across more than one installed version, native aarch64 (the Compose upgrade gates pass on an emulated arm64 image, see the [aarch64 record](../testing/evidence/p06-aarch64-emulated-2026-10-05.md)), and a packaged
previous-release artifact (the VM test repacks the current binaries as a newer
version and rewinds the schema to 18; one host-process SQLite test does start from a database a real
earlier binary created, see the [previous-release record](../testing/evidence/p06-previous-release-upgrade-2026-10-05.md)). See the
[P06 upgrade record](../testing/evidence/p06-upgrade-2026-10-04.md).
