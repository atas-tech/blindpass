# Authenticated fenced restore candidate (SQLite and PostgreSQL)

The P06 controller and co-located CLI can restore a complete authenticated SQLite
archive into a **new** private destination, and a PostgreSQL archive into an
**empty** target database ([below](#postgresql-archives)). The destination stays
`recovery_required`: diagnostics can run, readiness returns 503 and ordinary
requests are refused. This is one stage of the
[P06 recovery plan](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/phases/06-deployment-and-recovery.md).
It does not authorize activation or establish previous-host shutdown, broker
consumption coverage or provider cleanup. PostgreSQL restore uses the pinned
[ADR 0011 toolkit](../product/decisions/0011-p06-postgresql-backup-toolkit-review.md)
and is only as complete as the [PostgreSQL restore record](../testing/evidence/p06-postgres-restore-2026-10-05.md) says.

Before this command, an independently administered
[external authority](../product/decisions/0012-p06-external-recovery-authority.md)
must already hold the exact tenant, issuer-key ID and installation owner in
`recovering` phase at an epoch above the backup's epoch. This command does not
provision that authority, reserve an epoch from caller input or transfer ownership.
Reservation is operator-run SQL; relay, review, source-stop attestation and activation
follow the [protected recovery activation runbook](recovery-activation.md). Keep the authority
database and credentials outside controller backups.

Use the installed co-located binaries. Supply absolute paths; the destination's
existing parent must be owned by the invoking account, mode 0700 and free of
symlink components. The destination name must not already exist, including an
empty directory or dangling symlink. Credential/archive files must meet the
existing private-file custody checks. The authority runtime role must have only
the reviewed restricted grants; administrator credentials are refused.

```bash
blindpass restore \
  --archive /srv/private-backups/controller.bpbackup \
  --recipient-key-file /srv/offline/recipient.pem \
  --signing-certificate-file /srv/offline/signing-certificate.pem \
  --expected-archive-sha256 DIGEST_RECORDED_OFF_HOST \
  --destination /srv/private-recovery/restored-controller \
  --authority-url-file /srv/private-authority/runtime-url \
  --tenant-id EXISTING_TENANT_ID \
  --owner-id EXISTING_OWNER_ID \
  --recovery-id UNIQUE_RECOVERY_ID
```

### Split custody and tmpfs staging ([ADR 0013](../product/decisions/0013-p06-backup-key-custody-split.md))

Archives made with the shipped split credentials open only with the **offline
recipient key** (`--recipient-key-file`) and the **signer's certificate**
(`--signing-certificate-file`, certificate-only is enough). The backup host holds the
signing credential and the recipient's certificate, never the recipient key. The
earlier single credential still works: replace both options with
`--recovery-key-file`. Mixing the two forms, giving only one half of the split pair
or repeating an option refuses.

- `--expected-archive-sha256` (optional, also on `backup verify`) refuses an archive
  whose SHA-256 differs from the digest `backup create` printed. Record that digest
  somewhere the backup host cannot write: it is the control against a forged archive
  signed with a stolen signing credential.
- Decrypted material is staged **only on a private tmpfs or ramfs directory**. The
  directory is `--staging-directory`, else `BLINDPASS_RESTORE_STAGING_DIR`, else
  `$XDG_RUNTIME_DIR/blindpass-restore`, else `/dev/shm/blindpass-restore-<uid>`. It
  is created mode 0700 if absent and must be owned by the invoking user, mode 0700, on
  tmpfs/ramfs, with free space of at least twice the archive size plus 8 MiB.
  A named directory (option or environment) never falls back to another location;
  persistent disk, a wrong owner, mode, a link or too little room refuses before
  anything is decrypted.
- The tmpfs stage holds the decrypted tar, the extracted members and the three
  controller keys, and is removed on every exit. Only the database is copied to the
  destination stage (the store must open it); the keys reach persistent disk last,
  immediately before publication, after the invalidation has succeeded. A killed
  process leaves nothing on disk beyond what the destination stage always held.
- This is not swap protection or forensic erasure: unlinking tmpfs files is not
  secure erasure and a swapped page is outside this record. Containers need a tmpfs
  mount for the staging directory (the shipped handoff import has one).

`blindpass-controller restore` accepts the same options. Paths and opaque IDs are
arguments; credential contents are read from protected files. Controller restore failures are static
and never print connection strings, key bytes or decrypted contents. Successful
JSON reports `phase: recovery_required`, `activation_permitted: false`, snapshot
and target epochs, schema/backend and recovery ID. A dummy receipt looks like:

```json
{"phase":"recovery_required","activation_permitted":false,"target_epoch":8,"snapshot_epoch":1,"schema_version":19,"backend":"sqlite","recovery_id":"P06_DUMMY_RESTORE"}
```

Treat a failed result after publication as uncertain; preserve any published
destination for review.

## PostgreSQL archives

A PostgreSQL archive restores into an explicit, **empty** target database through
the controller image (it carries the pinned toolkit; the native host profile does
not). Add `--database-url-file` and keep every other option:


The refusal for an occupied target is the generic `authenticated fenced restore refused`, with one exception: when the only occupant is a single empty schema (the Compose init hook creates `controller`), the command prints the fixed reason `PostgreSQL restore target holds an empty schema: drop it first (docs/deploy/recovery-stage.md)`. Drop it with `DROP SCHEMA controller CASCADE` and run the restore again. The restore never drops or merges into it itself, and a schema holding any object, or any other schema or `public` object, stays the generic refusal.
```bash
blindpass restore \
  --archive /srv/private-backups/controller.bpbackup \
  --recipient-key-file /srv/offline/recipient.pem \
  --signing-certificate-file /srv/offline/signing-certificate.pem \
  --destination /srv/private-recovery/restored-controller \
  --database-url-file /srv/private-recovery/target-database.url \
  --authority-url-file /srv/private-authority/runtime-url \
  --tenant-id EXISTING_TENANT_ID --owner-id EXISTING_OWNER_ID \
  --recovery-id UNIQUE_RECOVERY_ID
```

- The argument form must match the archive: a PostgreSQL archive requires
  `--database-url-file`, a SQLite archive refuses it.
- The URL file is a private, mode-`0600` file in the same custody as the other
  credentials; the password never appears in arguments, environment or output.
- The target must hold no schema other than `public` and no object in `public`.
  Anything else is refused and left untouched. The restore never merges or
  replaces. The role needs permission to create the archive's `controller`
  schema and its `search_path` must select it (the shipped Compose profile
  provisions this on first initialization).
- The pinned `pg_restore` runs as one transaction. The restored schema is then
  measured again against the authenticated manifest, bound to the recovering
  authority record, invalidated by the same store code as a SQLite restore (the PostgreSQL tests
  check the invalidated recovery record and the cleared bootstrap tokens, requests
  and sessions; the full SQLite assertion set was not duplicated), and only then are
  the three controller keys published under `--destination` (`keys/` and
  `restore.json`; there is no `data/` directory).
- Publishing the keys directory is the decisive step. Any failure before it
  drops the schema this command restored (and only that schema) and publishes
  nothing; a failure after it keeps everything for review.
- The receipt reports `"backend":"postgres"`. Only the current schema version is
  supported for PostgreSQL archives (none older exist).

The restored controller starts fenced (`/readyz` 503 `recovery_required`) and
needs the same [source-stop, reconciliation and activation workflow](recovery-activation.md)
as a SQLite restore (that workflow was exercised end to end with a SQLite controller; a
PostgreSQL controller was covered at component level only).

The whole destination contains `keys/` and `data/` (0700), three restored keys
(0600), `data/controller.db` and a metadata-only `restore.json` receipt. CMS
verification, exact archive-member checks, SQLite integrity/foreign-key/schema
validation and snapshot metadata equality precede external process ownership.
The same inspected files are then restored. Schemas 16/17/18 migrate to local schema
19 only inside isolated staging, retaining the unchanged encrypted source archive
as the pre-upgrade backup. Current schema 19 is supported; unsupported or damaged
state refuses. No new tenant, clock anchor or guessed epoch is initialized.

Before invalidation and publication, the verified archive also supplies a durable
snapshot epoch/time and manifest digest. A separate Ed25519 signature binds these
metadata to the exact tenant, issuer, owner, recovery ID and external epoch/revision.
The local reader checks this signature under the live bound recovering holder;
missing/tampered/unbound metadata refuses. Historical recoveries receive no guessed
archive context during migration. The signature and public digest are metadata,
not source-stop proof, a coverage receipt or admission permission. Signing uses
the existing protected runtime issuer key; its lifetime remains that of the
existing signer. The later local application candidate retains quarantine metadata; the actual
node relay and full reconciliation remain required. See the
[authenticated snapshot evidence](../testing/evidence/p06-authenticated-recovery-snapshot-2026-10-04.md).

The recovering holder guards migration and durable invalidation. Recovery deletes
transient capabilities/sessions, revokes or disables legacy credentials and
records quarantined nodes, operations and review subjects. It preserves the
snapshot clock for explicit subsequent recovery review. SQLite is checkpointed,
files/directories are flushed and ownership is checked again before an atomic
publication which cannot replace an existing name. Publication never clears the
durable recovery fence or marks the external authority active.

Plaintext restored keys live in private tmpfs staging, are copied to the destination
stage only just before publication and then persist in the private published key
directory. OpenSSL consumes the recipient (or single recovery) credential during the
bounded crypto subprocess; SQLx holds the authority credential in process memory
for its pool/connection lifetime. Caller-owned credential buffers are wiped when
dropped, but library/allocator/OS copies have no erasure guarantee. Decrypted
archive/database material exists in the private tmpfs `.backup-*` stage until normal
cleanup or reboot; `backup verify` (an operator check, not a restore) still stages
under its `--work-directory`. Abrupt interruption of verify may leave that residue;
it is not activated state.

After all owners of the private parent have stopped, use explicit locked cleanup:

```bash
blindpass backup cleanup --work-directory /srv/private-recovery
```

Cleanup refuses a busy custody lock and never removes the published destination
or encrypted source archive. Filesystem deletion is not secure erasure. Retry into
an absent destination under a valid protected reservation; never overwrite a
published result. Restore-stage process/resource tests are scoped evidence, not
whole-container memory limits, current packaged profile parity or full P06 acceptance.

New broker identities now create a private consumption-history genesis before
enrollment. The first controller pin binds that history to its tenant, node and
issuer key; node key rotation preserves the binding. Authenticated-time journal
compaction retains the greatest removed expiry and the highest trusted issuer
epoch even when no consume records remain. These are coverage bounds, not proof
that a workload effect completed or that a provider session was removed.

The separate [authority database](../product/decisions/0012-p06-external-recovery-authority.md)
now requires schema 4. Current and approved pending broker public keys,
immutable prior keys and revocation stay outside controller backups. The owned
controller lifecycle publishes approved keys/revocation before committing its
local transaction; a failed local commit leaves conservative authority metadata
and fences the controller. Older controller rows are not automatic recovery
trust, and existing nodes without independent records remain unresolved.
Administrator-only v2→v3 and v3→v4 migrations preserve the ledger and historical
attempts after authenticated source shutdown, fenced tenants and released
process guards. Database exclusion alone does not prove that shutdown. The
actual recovering controller workflow and node relay remain required.

Schema 4 stages controller nonces and signed pages in that separate authority,
bound to exact recovery ownership and independently current/approved-pending
broker keys. Reopening or reacquiring a recovering holder preserves the nonce,
page progress and consumed state. The collector re-verifies all signatures and
the ordered history digest before atomically consuming a fully covered nonce.
Missing/pruned/unmapped history remains blocked; authenticated observations at
or above the proposed epoch require a higher protected reservation. Observation
bounds survive partial collection and stale caller input. A covered history is
metadata only: revoked nodes, pending rotations and uncertain provider effects
still require review, and no ordinary route or issuer is activated.
The [current receipt evidence](../testing/evidence/p06-durable-receipts-2026-10-04.md)
records all six expanded cases, both-store regressions and the current acceptance limits.

Recovering Store collection now reads signed local scope for every open/stage/
finish operation. It refuses a protected challenge with a different snapshot
before mutation, even when the node signature and other recovery bindings match.
Late scope validation cannot undo a page write, so the pre-write comparison is
mandatory. [Scoped collection evidence](../testing/evidence/p06-scoped-recovery-collection-2026-10-04.md)
retains actual current-key/refusal/socket-loss checks. Collection is metadata only;
This collection layer does not itself apply records or expose a node HTTPS route
or activation. The later local application candidate is described below.

Existing broker identities and legacy journals do not gain a guessed genesis.
Missing, pruned or uncorrelated history must remain unresolved during recovery.
Preserve broker state; deleting a journal or copying an older broker backup does
not establish complete history. A new genesis format is unreadable by earlier
brokers, so broker rollback requires a matching pre-upgrade state backup and
recovery review. The private journal lock must remain in place while the broker
runs. The broker now exports immutable version-2 history pages through its
private control socket. A fresh suspend-aware 30-second broker nonce and a
pinned-controller-signed request bind tenant, node, current node key version,
recovery ID, proposed generation and controller nonce. Callers cannot supply
history rows or an arbitrary signing body. The broker durably fences the issuer
epoch before exporting; the original observed epoch remains in the signed
manifest, including when it exceeds the proposed generation.

Each page contains at most 128 original intent records and a signature from the
locked current node key. The manifest fixes the history ID, pruning boundary,
unmapped count, total count and full ordered-history digest. Records attest only
to an uncertain effect. Complete page delivery never establishes missing or
pruned history, effect completion or provider cleanup.

The broker retains one metadata snapshot in an unlinked private file descriptor.
It synchronizes the unlink before writing metadata, and accepts page requests
only until the nonce's 30-second expiry. The descriptor can remain open while
idle after expiry; a subsequent request, new challenge or broker shutdown closes
it. Broker runtime maps and persistent journals keep their existing lifetimes.
No credential payload is exported. Restart loses the cached snapshot and nonce;
retry needs a fresh challenge and may require a higher protected reservation
because the earlier fence remains durable. Key rotation invalidates old-version
page requests.

The HTTPS relay (`blindpass-node recovery-relay`), the operator review and the source-stop and
activation procedure are in the [activation runbook](recovery-activation.md). The external authority
now retains the one-use nonce and immutable pages independently of controller backups. The generic report event route stays
closed.


The local schema19 application candidate re-reads covered, consumed reports from
the external authority under signed archive scope and the live recovering holder.
Every page uses independently current/approved-pending keys again. It verifies
the complete ordered digest and unchanged protected context before one local
transaction commits. Exact tenant/node/grant/operation/epoch/expiry bindings become
`matched` metadata. Other bindings remain `unknown` or `conflicting`; missing or
unmapped history and higher observations cannot become covered application proof.
No grant or operation is created, and existing grants stay revoked, operations
uncertain and nodes quarantined. Provider outcome is never inferred from intent.

Application and external nonce consumption are separate commits. A restart/retry
re-verifies the already consumed receipt and exact local marker; it never consumes
twice. This is a Store API candidate with no production administration/HTTP relay
yet. Actual encrypted SQLite fixtures and a manually populated PostgreSQL local
fixture exercise selected behavior; the latter is not PostgreSQL archive restore.
Full resource/cancellation/unknown-node enumeration and old-host/source/provider
review remain open. Schemas16/17/18 migrate additively in isolated SQLite staging;
older binaries need a pre-migration backup for rollback.

[Local application evidence](../testing/evidence/p06-recovery-application-2026-10-04.md) retains actual test/control/gate results and remaining acceptance.

Evidence: [restore stage execution record](../testing/evidence/p06-restore-stage-2026-10-04.md).

## Recovering lane exposure (accepted pilot limit)

`/api/recovery/request` and `/api/recovery/page` are unauthenticated metadata routes
that run only under the recovering owner. The request carries a caller-chosen
`node_key_version`, and the first open of a challenge wins in the authority ledger.
While a node key rotation is pending, anyone who can reach this lane can bind the wrong
key version for a node, so that node's page then fails verification and its report
must be reopened under a fresh reservation. Pages cannot be forged: signatures are
checked against the bound key. This is a denial-of-service limit only, accepted by the
project owner for the pilot. Mitigation: keep the recovering controller reachable only
by the recovery operator and the nodes being reconciled, and do not rotate node keys
during recovery. A fix needs an authority-schema change (supersede an unstaged
challenge) and a layout bump; it is required before wider exposure of this lane.
