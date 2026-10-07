# Planned same-owner handoff (SQLite controllers)

Status: implemented for SQLite controllers (P06-D28). Tested at component level on SQLite
and PostgreSQL controller backends, end to end with a real node in a QEMU guest (host
controllers, same TLS endpoint) and between two Compose SQLite projects that share one
authority. See the [evidence record](../testing/evidence/p06-handoff-2026-10-05.md) for what
ran and what did not. Not tested: a native systemd package, native to Compose, a PostgreSQL
controller, a second broker or a real DNS/load-balancer cutover. This is not P06 acceptance.
Restoring after a loss is a different procedure: [protected recovery activation](recovery-activation.md).

## What it is, and what it is not

A handoff moves one controller (same tenant, issuer key and owner, same epoch) to a new host
or Compose project **under your control, with the source cleanly stopped**. The guest nodes
stay enrolled: they keep their keys and reconnect to the same HTTPS endpoint, which now
reaches the destination. It reuses the existing authenticated, encrypted backup archive and
the existing `authority-fence.sql` / `authority-activate.sql`.

It is **not** disaster recovery. A handoff needs a stopped, fenced source whose database is
intact. If the source is lost, use [restore](recovery-stage.md): that path reserves a higher
epoch, quarantines nodes and cannot activate yet. Rolling back **after** the destination
activated is also restore-only (below).

PostgreSQL-backed controllers do not need it: both controllers point at the same database and
only the authority record moves. `handoff export` refuses a non-SQLite store.

## Order of steps

| # | Where | Step | Authority record |
|---|-------|------|------------------|
| 1 | source | stop the controller; `authority-fence.sql` | `active` → `fenced`, revision R |
| 2 | source | `blindpass handoff export` | unchanged (`fenced`, R) |
| 3 | transfer | copy the archive and its receipt to the destination | |
| 4 | destination | `blindpass handoff import` into a **new** root | unchanged (`fenced`, R) |
| 5 | destination | install the staged keys and database into the destination layout | unchanged |
| 6 | operator | `authority-activate.sql`, start the destination, move the endpoint | `active`, revision R+1 |
| 7 | operator | `blindpass status --nodes --require-online`, delete the transfer package and staging root | |

### 1–2. Fence, stop and export (source)

```sh
# controller stopped; record fenced with authority-fence.sql
blindpass handoff export --output TRANSFER_DIR --handoff-id ID \
  --signing-credential-file SIGNING_CREDENTIAL --recipient-certificate-file RECIPIENT_CERTIFICATE
```

`ID` is an operator-chosen identifier (letters, digits, `_`, `-`, up to 128). The command needs the
same environment as `serve` (data and key directories, `BLINDPASS_AUTHORITY_URL_FILE`,
`BLINDPASS_CONTROLLER_TENANT_ID`, `BLINDPASS_CONTROLLER_OWNER_ID`), claims a **fenced** record as a
maintenance holder, seals a verified backup archive into `TRANSFER_DIR`, writes a retirement marker
`handoff-marker.json` (0600) next to the database and a receipt `handoff-ID.json` next to the
archive, and prints one JSON line with the handoff id, archive name, receipt name, archive SHA-256,
epoch and revision. The authority record is not changed.

From this moment the source **refuses to serve, migrate or reconcile its clock**
(`startup_failed` reason `handoff_retired`), even if someone activates the record again.

Under [ADR 0013](../product/decisions/0013-p06-backup-key-custody-split.md) the export host holds only a
signing credential and the recipient's *certificate*; it cannot open the archive it writes. Only the
offline recipient key reads the database and the keys, so protect that key and the transfer package
accordingly. The single `--recovery-key-file` form is still accepted (it both signs and decrypts).

### 4. Import (destination)

```sh
blindpass handoff import --archive TRANSFER/ARCHIVE --receipt TRANSFER/handoff-ID.json \
  --recipient-key-file RECIPIENT_KEY --signing-certificate-file SIGNING_CERTIFICATE \
  --destination NEW_ROOT --authority-url-file AUTHORITY_URL_FILE --tenant-id TENANT --owner-id OWNER
```

The import decrypts into a private **tmpfs** staging directory (`--staging-directory`, else
`BLINDPASS_RESTORE_STAGING_DIR`, else the runtime directory, else `/dev/shm`) and refuses persistent disk
or a directory with less than twice the archive size plus 8 MiB free; see the
[recovery stage](recovery-stage.md#split-custody-and-tmpfs-staging-adr-0013). The keys are copied to
`NEW_ROOT` last, just before publication. The receipt already pins the archive digest, so
`--expected-archive-sha256` is optional here.

Import verifies, in this order: the receipt and archive name/digest; the archive signature and its
manifest (SQLite backend, **schema equal to this build**, tenant, issuer key, `recovery_generation`
equal to the receipt's epoch); then the authority: the record must be `fenced` with the receipt's
epoch and revision. It writes `NEW_ROOT/keys` and `NEW_ROOT/data/controller.db` (private, 0700/0600)
plus a destination marker `data/handoff-marker.json`, and leaves the record **fenced and unchanged**.
It reserves nothing and invalidates nothing. `NEW_ROOT` must not exist.

Import refuses: a different tenant, issuer key or owner; an epoch or revision that is not the
receipt's (the authority moved since the export); a record that is not `fenced`; an existing
destination; a tampered or substituted archive; a different schema; a PostgreSQL archive.

### 5–6. Install, activate, start

Place `NEW_ROOT/keys` and `NEW_ROOT/data` at the destination's key and data directories with the
same private modes and ownership (Compose: the `controller-handoff-install` job below). Then run
`authority-activate.sql` and start the controller. The destination's **first** start needs exactly
revision R+1, which one activation produces. Any other revision (an extra activation, or an
activation after the source or another holder ran) makes the first start refuse with reason
`handoff_stale`. Once a start was attempted, any later activation is accepted (a crashed first
start must be repeatable) and the marker is deleted when the store has opened. A later restart is
an ordinary restart: activate again, start.

### 7. Verify and clean up

`blindpass status --nodes --require-online --controller-url URL --username OPERATOR --password-stdin`
passes when every active node was seen within 45 s. The enrolled nodes need no action: same keys,
same endpoint. Then delete the transfer package and the staging root (they hold the archive, the
keys and the database in a form readable with the offline recipient key or in plaintext) and destroy the
source's keys and data when you no longer need them as rollback.

## Interrupted steps

| Interrupted | State | Repeat |
|-------------|-------|--------|
| export before the archive is sealed | nothing published, no marker | run export again |
| export after the archive, before the marker | one **unreferenced** sealed archive in `TRANSFER_DIR`, no marker, record unchanged | run export again (a new archive is sealed); delete the orphan from `TRANSFER_DIR` yourself, `abort` cannot know it |
| export after the marker, before the receipt | marker exists | run export again with the **same** id: reuses the archive after re-checking its digest and recreates the receipt |
| a different id while a marker exists | refused | `abort` the open handoff first |
| import before publication | no destination root, record unchanged | run import again |
| import after publication | destination exists | do not rerun; install it. To start over delete the root and run import again |
| activation recorded, destination never started | marker not attempted, revision R+1 | start it |
| destination start attempted and crashed | marker `attempted` | activate again, start |

## Abort and rollback

`blindpass handoff abort --handoff-id ID [--output TRANSFER_DIR]` un-retires the source. It is
accepted only while the authority record is still the exported one (`fenced`, same epoch and
revision), which proves no destination (and no accidental source activation) happened after the
export. It deletes the marker and, with `--output`, this handoff's receipt and archive. Then
activate the source and start it as usual. A destination root staged before the abort can no
longer start (its first start would need revision R+1, which is now the source's).

**After the destination activated, or after any later activation of the record, abort refuses
(`authority moved after the export; rollback is restore-only`).** The only way back is the
[restore stage](recovery-stage.md) from the exported archive (keep the transfer package until the
destination is verified) or a regular backup, which is a recovery with its own limits and loses
everything the destination wrote after the export. This is deliberately strict: an activation of the source by mistake after the export also
makes abort impossible.

## Guarantees and limits

- One holder at a time comes from the authority ledger: each start consumes one revision and a
  second process cannot register for a live revision. The retirement marker and the destination
  marker are **local** guards that make the sequential misuse (starting the retired source, an
  out-of-order destination) fail with a clear reason. Deleting a marker by hand is an operator
  override with no proof; the record's revision is then the only fence.
- Clocks: a destination host whose clock is behind the source's last write can trip the clock
  regression guard and fence; `blindpass admin reconcile-clock` applies.
- No node reconciliation is needed because nothing was lost; there is no recovering lane, no
  source-stop attestation and no previous-host shutdown evidence beyond the operator having stopped
  and fenced it. A restore after a disaster takes the
  [protected recovery activation](recovery-activation.md) path instead. Export requires the record to be `fenced` and takes the maintenance claim, so it
  refuses while the record is active; a source process still running after the fence is
  fenced out by the record, but the handoff does not prove it exited.
- The reconnect time depends on node polling and your endpoint cutover. In the QEMU rehearsal the
  node was seen by the destination about 2 s after its start (same host, same port); this is not
  a DNS or load-balancer measurement.
- Compose and native are separate profiles; the archive layout is the same but a native to
  Compose (or the reverse) handoff was **not** run. The native profile has no packaged handoff
  units: run the commands by hand as the service account with the service's environment.

## Compose SQLite

`deploy/controller/compose.handoff-sqlite.yml` adds opt-in jobs (profile `handoff`, never part of
`up`). Set `BLINDPASS_HANDOFF_TRANSFER_DIR` and `BLINDPASS_HANDOFF_STAGING_DIR` to private
directories owned by UID 10001, `BLINDPASS_BACKUP_RECOVERY_DIR` to the directory the job needs (for
export: `signing.pem` and `recipient-certificate.pem`; for import: the **offline** `recipient.pem` and
`signing-certificate.pem`, mounted from the operator's own custody, never the backup host's
directory), `BLINDPASS_RESTORE_TMPFS_SIZE` (default `1g`, must cover twice the archive plus 8 MiB) for the
import job's in-memory staging mount, and
`BLINDPASS_HANDOFF_ID` (plus `BLINDPASS_HANDOFF_ARCHIVE`, the archive name the export printed, for
import).

```sh
# source project, controller stopped and record fenced
docker compose -f compose.sqlite.yml -f compose.handoff-sqlite.yml --profile handoff run --rm controller-handoff-export
# destination host/project (the same authority must be reachable from it)
docker compose -f compose.sqlite.yml -f compose.handoff-sqlite.yml --profile handoff run --rm controller-handoff-import
docker compose -f compose.sqlite.yml -f compose.handoff-sqlite.yml --profile handoff run --rm controller-handoff-install
# authority-activate.sql, then
docker compose -f compose.sqlite.yml up --detach controller
```

`controller-handoff-install` has no network, mounts staging read-only and refuses unless both
destination volumes are empty. `controller-handoff-abort` is the abort job. Delete the staging
directory afterwards.
