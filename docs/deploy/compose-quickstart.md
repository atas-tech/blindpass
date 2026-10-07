# Compose controller quickstart

Start with [Start here](README.md): prerequisites, how to verify the download and a worked single-host
evaluation of this path. This page is the reference for the Compose profiles.

The [SQLite profile](../../deploy/controller/compose.sqlite.yml) and
[PostgreSQL profile](../../deploy/controller/compose.postgres.yml) run the Rust
controller with both embedded browser surfaces. They require Docker Compose,
a separately administered HTTPS edge, and explicit initialization. Brokers run
on native hosts.

**Requirements.** Docker with the Compose plugin on an x86_64 host, the controller image (next section), a
PostgreSQL 16 recovery authority reachable from the controller over verified TLS (it is never part of this
Compose project), and an HTTPS reverse proxy with a certificate for each of the two public names
([HTTPS ingress](controller-ingress.md)). The release archive carries the Compose files, `.env.example`,
`postgres-init/` and the proxy examples under `deploy/`; run every command from the unpacked archive root.

## Image and private state

Get the image from the release, verified, before anything else. Two ways, the first needs no registry:

```sh
# 1. From the verified release assets (works on a stock Docker store):
docker load --input blindpass-controller-image-X.Y.Z-linux-amd64.docker.tar
export BLINDPASS_CONTROLLER_IMAGE=ghcr.io/atas-tech/blindpass-controller:X.Y.Z
# 2. After the release is published to the registry, by the digest in controller-image.digest:
docker pull ghcr.io/atas-tech/blindpass-controller@sha256:DIGEST
export BLINDPASS_CONTROLLER_IMAGE=ghcr.io/atas-tech/blindpass-controller@sha256:DIGEST
```

A stock Docker (overlay2 image store) cannot `docker load` the `.oci.tar` asset; that archive is the source for
registry publication and carries the SBOM and provenance attestations. The `.docker.tar` is derived from it
with the same config and layer bytes and is covered by the same signed `SHA256SUMS`
([release layout](release-layout.md)). `docker image inspect --format '{{.Id}}' "$BLINDPASS_CONTROLLER_IMAGE"`
prints the image's config digest. Until a release is published there is no registry image: the registry
path does not exist and a source template tag is not proof that one does.

To build from a repository checkout instead (contributors, not release operators), from the repository root:

```sh
docker build -f deploy/controller/Dockerfile -t blindpass-controller:local .
```

The pinned bookworm builder produces the controller and co-located CLI. The
bookworm-slim runtime contains OpenSSL 3, CA certificates and notices, runs as
`10001:10001`, and embeds the console/input page. It contains no Node, browser,
Redis or broker runtime. The current base pins target x86_64; an arm64 build must pass
the reviewed arm64 `NODE_IMAGE` and `RUST_IMAGE` digests (see the
[emulated aarch64 record](../testing/evidence/p06-aarch64-emulated-2026-10-05.md):
without them the build now stops at the architecture check instead of shipping an x86-64 binary). Registry publishing
and native aarch64 execution are separate gates.

Named `/data` and `/keys` volumes receive private `0700`, UID/GID 10001 roots
from the image. `/keys` is read-only while serving; `/data` is writable. The
root filesystem is read-only, all capabilities are dropped, no-new-privileges
is set, core dumps are disabled, and a private `/run` tmpfs holds the `0600`
administration socket. Container recreation retains keys and database; `/run`
is volatile. No host ports, Docker socket, systemd mount or host PID namespace
are configured. Do not use a network/FUSE filesystem for SQLite.

## Recovery authority

Both profiles need the separately administered recovery authority (PostgreSQL 16,
never on this Compose project or its backups). Create a database of its own for it, apply
`deploy/controller/recovery-authority.sql` to it as a PostgreSQL superuser, create a runtime role
(`CREATE ROLE ROLE LOGIN PASSWORD '…'`) and apply `deploy/controller/authority-runtime-role.sql`
(`-v runtime_role=ROLE`). Feed each file to `psql` on standard input (`psql -d DB -f - < file`) so the database
account needs no access to your files. [Start here](README.md#docker-compose-evaluation-on-one-host) shows a
complete, tested recipe for a single-host evaluation, including the private certificate authority and a
PostgreSQL container with TLS. Prepare a private directory owned by `10001:10001`
(a root helper container can `chown` it where there is no `sudo`),
mode `0700`, containing `authority-url` (mode `0600`):
`postgresql://ROLE:<password>@HOST:5432/DB?sslmode=verify-full&sslrootcert=/authority/authority-ca.pem`
and the CA file it names. A remote (non-loopback) authority must use
`verify-full` or `verify-ca`; the controller refuses anything else, and with `verify-full` the certificate's
name (`subjectAltName`) must match `HOST`. The directory
is mounted read-only at `/authority`. The tenant and owner names are yours
(`[A-Za-z0-9_-]{1,128}`).

## SQLite initialization

Copy the [public configuration example](../../deploy/controller/.env.example)
to a protected local configuration file. Set the two exact HTTPS origins,
the exact edge peer IP on the configured subnet and the authority settings.
Commands below use explicit process environment; Compose loads `.env` according
to its working/project configuration, not the repository workspace scripts.

```sh
export BLINDPASS_CONTROLLER_IMAGE=ghcr.io/atas-tech/blindpass-controller:X.Y.Z   # from the previous section
export BLINDPASS_PUBLIC_URL=https://blindpass.example
export BLINDPASS_UI_BASE_URL=https://input.example
export BLINDPASS_EDGE_SUBNET=172.29.6.0/24
export BLINDPASS_CONTROLLER_IP=172.29.6.2
export BLINDPASS_TRUST_PROXY=172.29.6.3
export BLINDPASS_CONTROLLER_TENANT_ID=TENANT BLINDPASS_CONTROLLER_OWNER_ID=OWNER
export BLINDPASS_AUTHORITY_CONFIG_DIR=/srv/blindpass/authority
# Use the same project, the same files and the same exported variables for every command (also for `down`).
C="docker compose -p blindpass -f deploy/controller/compose.sqlite.yml"
$C -f deploy/controller/compose.initialize.yml --profile initialize run --rm -T keys-init
$C run --rm -T --no-deps controller keys issuer-id --directory /keys   # prints ed25519-...
# Administrator: register once, then (after migrate) grant each start. Run these against the authority
# database, with the issuer ID printed above:
#   psql -d DB -v tenant=TENANT -v owner=OWNER -v issuer=ISSUER_KEY_ID -f - < deploy/controller/authority-register.sql
$C run --rm -T controller migrate
#   psql -d DB -v tenant=TENANT -v owner=OWNER -v issuer=ISSUER_KEY_ID -f - < deploy/controller/authority-activate.sql
$C up -d controller
```

The two public URLs must carry the port when it is not 443, and the proxy must then send the same
`Host:PORT` and `X-Forwarded-Host:PORT` ([HTTPS ingress](controller-ingress.md)). The tenant and owner values
and the issuer ID in the SQL commands are the ones exported and printed above.

`keys init` refuses existing/partial keys; it never overwrites trust. `migrate`
refuses until the issuer is registered, and creates the database exactly once
against the fenced record. A start without a fresh activation never becomes ready.
The service uses `restart: "no"`: every later start or recreate — including after a
crash or host reboot — needs a new `authority-activate.sql` after the previous
container is gone. `authority-fence.sql` cuts off a running controller or prepares
fenced maintenance such as `reconcile-clock`; a `recovering` record is never
activated by these scripts. A controller-store outage also fences the owner: when the database returns the
controller stays not ready until the next activation. This fail-closed behavior (P06-D12)
is the confirmed pilot decision: any unanswerable epoch check fences, and availability
during store outages is deliberately traded for never serving from a partitioned owner.
Plan for one re-activation after every database outage.
Ordinary startup validates configuration and existing
initialized state. Missing, exposed or linked keys and absent/unsupported database
state refuse serving. Startup applies no migrations; locked verified upgrade
migrations are later P06 work.

Initialize the first administrator with the local socket:

```sh
docker compose -p blindpass -f deploy/controller/compose.sqlite.yml \
  exec -T controller blindpass admin bootstrap
```

Unlike the native package, which mints a one-use setup token for a `/setup` page, Compose prints a one-time
temporary password for the account `admin` to the operator's terminal. Keep it outside shared terminals, logs and evidence; log
in through the configured HTTPS console and complete the password change.
Repeated bootstrap refuses after administrator creation. If an operator is
locked out by repeated wrong passwords (ten from one address, fifty across
addresses; 15 minutes), reset it through the same socket with
`blindpass admin reset-password <username-or-id>` in place of `bootstrap`
(`blindpass admin operators list` shows every operator's id, username, role and lock state); a reset
clears the lock, revokes the operator's sessions and prints a new temporary
password. See [operator sign-in limits](../security/operator-auth-and-headers.md).

## PostgreSQL initialization

Use the PostgreSQL profile instead of the SQLite file in every command above.
Set `BLINDPASS_POSTGRES_PASSWORD_FILE` to a private host file containing a strong
password, and `BLINDPASS_DATABASE_CONFIG_DIR` to a prepared private directory
owned by `10001:10001`, mode `0700`. Its `database.url` file must be mode `0600`,
owned by 10001, containing the matching URL
`postgresql://blindpass:<percent-encoded-password>@postgres:5432/blindpass`.
Prepare those files through a private editor or secret-management tool; no
password belongs in an environment assignment, command argument, template or
committed `.env`.

The profile mounts [`postgres-init/`](../../deploy/controller/postgres-init/10-controller-schema.sql)
into the official image's first-initialization hook, which creates the dedicated
`controller` schema and sets it as the `blindpass` role's `search_path`. The
controller store therefore never lives in `public`, and the
[PostgreSQL backup](#explicit-postgresql-backup) can dump exactly that schema.
The hook runs only when the data volume is first initialized. A deployment whose
volume already holds the store in `public` is refused by the backup; with the
controller stopped and the fenced authority record in place, move it once with
`ALTER SCHEMA public RENAME TO controller; CREATE SCHEMA public;
ALTER ROLE blindpass SET search_path = controller;` and restart the controller.
That move was not run against a real pre-existing deployment in this evidence.

The official pinned PostgreSQL 16 image reads its password from a Compose
secret file. The controller reads the URL from the read-only `/config` mount;
Docker's configured environment contains file paths. PostgreSQL's entrypoint
reads the password and exports it inside the container process environment;
it remains available to the database process for its lifetime. Container/host
administrators and authorized database processes therefore consume plaintext.
The controller consumes the protected URL while opening database connections
and keeps its connection configuration in process memory while running. The protected
URL and password files remain on host storage until the operator removes them.
The internal database network publishes no database port. This profile uses
plaintext PostgreSQL transport inside that private bridge; it does not assert
end-to-end database wire encryption. Configure verified database TLS separately
for a remote database.

The controller waits for PostgreSQL's health dependency, and the database
volume survives recreation. The first migrate command creates schema/tenant;
normal serving refuses an uninitialized database. SQLite↔PostgreSQL conversion
is unsupported: use a fresh deployment and explicit reenrollment.

## Explicit SQLite backup

The optional [SQLite backup overlay](../../deploy/controller/compose.backup-sqlite.yml)
creates and fully verifies an authenticated encrypted archive with the current
candidate image. It has no network access or scheduler. The
[PostgreSQL overlay](#explicit-postgresql-backup) below covers backup creation
and verification only (restoring a PostgreSQL archive is in the
[restore guide](recovery-stage.md#postgresql-archives); activating a restored controller is in the
[activation runbook](recovery-activation.md) and [below](#restore-and-recovery-activation-on-this-profile)). Backups use **split
custody** ([ADR 0013](../product/decisions/0013-p06-backup-key-custody-split.md)): a
signing credential and the recipient's certificate live on the backup host, and the
recipient private key stays offline. Losing the recipient key makes its archives
unrecoverable. The ordinary controller receives no recovery mount. The [format and OpenSSL prerequisites](../product/decisions/0010-p06-authenticated-backup-format.md)
apply; an unsupported or unpatched installation refuses backup.

Prepare two private host directories owned by the image's UID/GID: the backup host's
custody and the operator's offline material (keep the latter on separate storage and
mount it only for verification, restore and import). Generate both role credentials
once with the same image; these commands generate no replacement controller trust:

```sh
export BLINDPASS_BACKUP_RECOVERY_DIR=/var/lib/blindpass-backup-custody
export BLINDPASS_OFFLINE_DIR=/srv/offline/blindpass-backup
sudo install -d -m 0700 -o 10001 -g 10001 "$BLINDPASS_BACKUP_RECOVERY_DIR" "$BLINDPASS_OFFLINE_DIR"
keyinit() { docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --ulimit core=0 \
  --mount "type=bind,src=$BLINDPASS_BACKUP_RECOVERY_DIR,dst=/recovery" \
  --mount "type=bind,src=$BLINDPASS_OFFLINE_DIR,dst=/offline" \
  "$BLINDPASS_CONTROLLER_IMAGE" backup key-init "$@"; }
keyinit --role signing --output /recovery/signing.pem --certificate-output /recovery/signing-certificate.pem
keyinit --role recipient --output /offline/recipient.pem --certificate-output /offline/recipient-certificate.pem
# Public material only crosses between the two sides:
sudo cp "$BLINDPASS_OFFLINE_DIR/recipient-certificate.pem" "$BLINDPASS_BACKUP_RECOVERY_DIR/"
sudo cp "$BLINDPASS_BACKUP_RECOVERY_DIR/signing-certificate.pem" "$BLINDPASS_OFFLINE_DIR/"
docker compose -p blindpass -f deploy/controller/compose.sqlite.yml \
  exec -T controller /bin/sh -ec 'umask 077; mkdir -p /data/backups'
```

Key initialization refuses an existing output and requires both outputs of a role in
one private directory. After this the backup host's directory holds
`signing.pem` (the only private key), `signing-certificate.pem` and
`recipient-certificate.pem`; it never holds `recipient.pem`, and the create job refuses
a recipient file that contains a private key. Keep **two** protected offline copies of
`recipient.pem`: it is the only way to read an archive. Docker bind mounts preserve host
permissions; they do not repair unsafe credentials. Host processes with UID 10001 and
host/container administrators can read the signing credential; a stolen signing
credential allows forged archives (not decryption), which is why `backup create`
prints `archive_sha256` for you to record where the backup host cannot write. Only
paths belong in configuration and arguments, never key contents. Move the offline
directory away from the host after generation; `BLINDPASS_OFFLINE_DIR` is not read
by the backup job.

Run the opt-in job while the SQLite controller serves:

```sh
docker compose -p blindpass -f deploy/controller/compose.sqlite.yml \
  -f deploy/controller/compose.backup-sqlite.yml --profile backup \
  run --rm --no-deps controller-backup
```

Success prints the encrypted archive's basename and `verified: true`. The
private `/data/backups` directory contains mode-`0600` `.bpbackup` files owned
by UID 10001. Copy encrypted archives to separately administered backup storage;
keeping only the data volume does not survive loss of that volume. Do not copy
live SQLite database/WAL files as a backup.

Verify a retained archive by substituting its basename below. Use absolute paths (the container paths below
are), make the work directory exist as a private directory (`0700`), and keep the directory holding the archive
private (`0700`). The key and certificate files must be regular files with one link, owned by the user the command runs as,
mode `0600` or `0400`; their directory need not be private. The command refuses a relative path, a missing or
non-private work directory, a non-private archive directory and any input that group or world can access, naming the
option and the rule but never the path:

```sh
docker compose -p blindpass -f deploy/controller/compose.sqlite.yml \
  -f deploy/controller/compose.backup-sqlite.yml --profile backup \
  run --rm --no-deps --volume "$BLINDPASS_OFFLINE_DIR:/offline:ro" controller-backup backup verify \
  --archive /data/backups/ARCHIVE.bpbackup \
  --recipient-key-file /offline/recipient.pem \
  --signing-certificate-file /offline/signing-certificate.pem \
  --expected-archive-sha256 DIGEST_RECORDED_AT_CREATE_TIME --work-directory /data/backups
```

Create-time `verified: true` means the exact sealed bytes were decrypted and restored in
isolation with a throwaway co-recipient; it does **not** prove that the offline recipient
entry decrypts. Run the verify command above (and a restore drill) on a schedule.

The job runs as UID 10001 with a read-only root filesystem/recovery mount,
read-only controller keys, no capabilities, no core dumps and no host socket.
It has writable data/private staging for capture and verification. Its explicit
`timeout` wrapper allows 15 minutes, then sends TERM and KILL after another
10 seconds; individual tools have 60-second bounds. These configured limits
do not establish maximum-size timing or bound uninterruptible filesystem I/O.
The archive limit is 512 MiB, with additional staging space required; it is not
a memory limit. The job and OpenSSL consume database/controller-key/signing
plaintext while running, and plaintext staging lasts until cleanup. The custody
bind remains on host storage after the container exits. Ordinary cleanup is
not secure erasure.

After interruption, stop any active backup/verification job before explicitly
running the same service with `backup cleanup --work-directory /data/backups`.
Custody locks refuse active jobs and unsafe residue. Verification checks the
complete SQLite snapshot and manifest; it does not activate state or authorize
restored issuance. External ownership, stale-authority invalidation, recovery,
upgrade and transfer guarantees remain required P06 work.

## Explicit PostgreSQL backup

[`compose.backup-postgres.yml`](../../deploy/controller/compose.backup-postgres.yml)
adds the same opt-in `controller-backup` job to the PostgreSQL profile. It joins
only the internal `database` network (no edge, no published port), reads the
database URL from the private `/config/database.url` file, and uses the same
the same split custody as the SQLite job. Run it with the PostgreSQL profile:

```sh
docker compose -p blindpass -f deploy/controller/compose.postgres.yml \
  -f deploy/controller/compose.backup-postgres.yml --profile backup \
  run --rm --no-deps controller-backup
```

The job exports one snapshot, dumps the `controller` schema with the pinned
PostgreSQL 16.15 `pg_dump` (invoked only by absolute path under
`/usr/lib/postgresql/16/bin`, password only through a private password file),
and proves the dump by restoring it completely into a private, socket-only,
unprivileged cluster inside the job's staging space before re-measuring and
comparing the restored snapshot with the authenticated manifest. The
verification cluster needs more than 40 MiB of staging beyond the dump and
archive (a 40 MiB quota failed closed in testing; no upper bound was measured),
and exhaustion fails closed and publishes nothing. The `.bpbackup` archive, `backup verify` and
`backup cleanup` behave as for SQLite. The image carries the pinned PGDG
packages ([ADR 0011](../product/decisions/0011-p06-postgresql-backup-toolkit-review.md));
the native SQLite profile does not. Restoring a PostgreSQL archive into a target
database and PostgreSQL upgrade are not implemented and refuse.

## HTTPS edge and checks

Attach the separately administered edge to the project `blindpass_edge`
network with exactly the configured trusted IP (the example uses 172.29.6.3).
Use the [nginx](../../deploy/proxy/nginx.conf.example) or
[Caddy](../../deploy/proxy/Caddyfile.example) example, changing both backend
addresses from `127.0.0.1:3200` to `controller:3200`, replacing the certificate
paths and configuring the exact two public authorities. Publish only the
edge's HTTPS port and protect its private key. Both examples overwrite Host,
X-Forwarded-Host/Proto/For, remove Forwarded, add HSTS and discard request/error
logs that could carry signed links. The controller rejects untrusted direct
peers, malformed forwarded headers and mismatched authorities.

```sh
docker compose -p blindpass -f deploy/controller/compose.sqlite.yml ps
docker compose -p blindpass -f deploy/controller/compose.sqlite.yml \
  exec -T controller blindpass-controller healthcheck
```

The built-in probe contacts only loopback `/readyz`, reads no controller keys
or database configuration, uses a two-second total transport bound and writes
only a fixed failure diagnostic. When using built-in controller TLS instead of
an edge, configure `BLINDPASS_HEALTH_TLS_NAME` and, for a private CA,
`BLINDPASS_HEALTH_CA_FILE`; verification is mandatory. Its loopback connection
requires a wildcard or loopback listener. The supplied Compose profiles use
plain private backend transport and required HTTPS proxy mode.

Stop with `docker compose ... down`. It retains named state volumes. Do not use
`down --volumes` on real state unless deliberately destroying it. Do not copy a
live SQLite database/WAL or clone these volumes as a migration: authenticated
complete backups, external ownership fencing, stale restore reconciliation and
interrupted transfer runbooks are still required P06 work.

A planned move of a SQLite controller to a second Compose project under the same
owner (not a disaster recovery) is in the [handoff runbook](handoff.md); it uses
the opt-in `compose.handoff-sqlite.yml` jobs and stays out of ordinary `up`.

### Restore and recovery activation on this profile

The opt-in `restore` profile of [`compose.restore-sqlite.yml`](../../deploy/controller/compose.restore-sqlite.yml) and
[`compose.restore-postgres.yml`](../../deploy/controller/compose.restore-postgres.yml) ships the two restore jobs. Include the
overlay only for a recovery; ordinary `up` never sees it.

1. Stop the controller. Fence the authority and reserve recovery (`authority-fence.sql`, then `reserve_recovery`, see
   [recovery stage](recovery-stage.md)). The authority must then be `recovering` at a higher epoch than the archive.
2. Put the archive in a private UID 10001 directory (`BLINDPASS_RESTORE_ARCHIVE_DIR`, file name in `BLINDPASS_RESTORE_ARCHIVE`),
   create a private UID 10001 staging directory (`BLINDPASS_RESTORE_STAGING_DIR`; the job creates `root` below it, and `root`
   must not exist yet) and mount the **offline** custody (`recipient.pem`, `signing-certificate.pem`) as
   `BLINDPASS_BACKUP_RECOVERY_DIR`. Set a unique `BLINDPASS_RESTORE_ID`.
3. `docker compose --profile restore run --rm controller-restore` verifies the archive, decrypts into a 1 GiB (override with
   `BLINDPASS_RESTORE_TMPFS_SIZE`) memory-backed staging mount and writes the fenced restore to `<staging>/root`. The receipt
   says `phase: recovery_required`, `activation_permitted: false`.
4. Install it into **empty** volumes: `docker compose --profile restore run --rm controller-restore-install` (no network, copies
   `keys` and, for SQLite, `data`; it refuses non-empty destination volumes). On the PostgreSQL profile the restore needs an
   **empty** `controller` schema in the database, so drop the schema the init hook created
   (`DROP SCHEMA controller CASCADE`) before step 3, and keep only the keys in the install step (the data comes back through
   the restore job itself). If the empty schema is still there, the restore refuses with the fixed reason
   `PostgreSQL restore target holds an empty schema: drop it first`; any other occupied target gets the generic
   `authenticated fenced restore refused`. Neither changes the database.
5. `docker compose up -d controller` starts the restored controller fenced (`/readyz` 503, `recovery_required`). Continue with
   the [activation runbook](recovery-activation.md): `docker compose exec controller blindpass admin recovery status`, review
   and waive nodes, `docker compose stop controller`, `authority-recover-attest.sql`, `authority-recover-activate.sql`, then
   `docker compose up -d controller`. Every recovery epoch needs its own review, attestation and activation, including a
   repeated restore of the same archive (rollback).

**Restoring into a new project (another stack or host).** Use a new Compose project name so every volume starts empty, keep
the same authority and tenant/owner identifiers, and make the authority reachable from the new project's network under the
same verified host name. On the PostgreSQL profile start `postgres` first and drop the init hook's empty schema
(`DROP SCHEMA controller CASCADE`); the restore refuses a database that already holds a user schema. Then run steps 1-5 above
in the new project. The original stack must be stopped before the attestation; once the new stack is activated, the original
one can only start as `startup_failed` with reason `fenced` (while the new owner holds the guard) or `recovery_required`
(after any later ordinary activation), because its database is at the older epoch. Retire the original stack's volumes and
keys anyway; this refusal is not a substitute for stopping it.

`tests/deployment/compose-up.py --profile sqlite|postgres --scenario recovery` runs this whole flow on both profiles, including
the second-project restore (P06-RC8)
([record](../testing/evidence/p06-native-recovery-faults-2026-10-05.md); earlier flow:
[packaged recovery](../testing/evidence/p06-packaged-recovery-2026-10-05.md)). **Limits:** that harness has no real node. It seeds
one active broker trust row into the authority and covers it only by an explicit named waiver. A real broker and node in a QEMU guest
against these Compose profiles (enrollment, the shipped backup and restore jobs into a second project, the relay, review,
attestation, activation and the node's return) is `tests/fleet/p06-compose-node-vm.py`, see the
[Compose node record](../testing/evidence/p06-compose-node-2026-10-05.md). The second project runs on the same Docker host with the
authority container attached to both networks; a source running on a different machine is not simulated. The node relay
(`blindpass-node recovery-relay`) runs on the node, not in the Compose profile.

## Status and limits

The paragraphs below are the maintainers' status notes for these profiles. They name internal evidence records and
are not installation instructions.

Current transport candidate: active HTTP/TLS/admin connections retain ownership
until local IO closes. Fencing can close an in-flight connection; reconnect for
diagnostic readiness 503/health 200. HTTP connections reconnect within 60 seconds;
node polls keep their existing 35-second handler bound. Local admin connections
last at most 10 seconds. Shutdown fences and stops transports before graceful
waiting. [Transport evidence](../testing/evidence/p06-transport-ownership-2026-10-04.md)
is source/process evidence, not authenticated old-host stop or ambiguous SQL
rollback. Complete restore/transfer profiles still require integration and actual
verification.

The current source [production ownership candidate](../testing/evidence/p06-production-ownership-2026-10-04.md)
requires `BLINDPASS_AUTHORITY_URL_FILE`, `BLINDPASS_CONTROLLER_TENANT_ID` and
`BLINDPASS_CONTROLLER_OWNER_ID` before production configuration/serve/maintenance.
Keep the authority credential outside backed-up state/keys, in a private file
owned by the service UID; never use an inline URL. Its separately provisioned
PostgreSQL database uses the reviewed [authority layout](../../deploy/controller/recovery-authority.sql).
Startup never creates or activates that record. Initialization/clock maintenance
require a fenced record; serving requires an explicit current process revision,
which one start consumes and which is never replayed after process death. `authority-activate.sql` refuses a restored (`recovering`) record; a restored snapshot is
activated only through the protected [recovery activation](recovery-activation.md) (restore
jobs and an end-to-end Compose run are [above](#restore-and-recovery-activation-on-this-profile)). Compose has no verified upgrade flow yet (the SQLite engine and
native path are in the [upgrade runbook](upgrade.md)). The
sequence above is exercised by the actual Compose gate recorded in the
[P06 authority provisioning record](../testing/evidence/p06-authority-provisioning-2026-10-04.md);
earlier lifecycle logs predate it and retain their historical limits.

Complete P06 recovery, upgrades, migration and workflow parity remain unfinished; these profiles are deployment
candidates. A single-host Compose evaluation from the release assets (SQLite profile, curl checks only, no
browser sign-in) is recorded in the [operator documentation evidence](../testing/evidence/p07-operator-docs-2026-10-06.md).

The source candidate also conservatively refuses local quiescence after admitted
database work is cancelled or loses its acknowledgement. Production stop can
return `controller shutdown did not drain within bound` even when its process
exits within the five-second transport bound. Do not use that refusal as transfer
or activation proof. The uncertainty latch retains the live authority guard but
is lost with the process; durable external source-stop/database evidence remains
required. See [actual PostgreSQL cancellation/COMMIT evidence](../testing/evidence/p06-database-uncertainty-2026-10-04.md).
