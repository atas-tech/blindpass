# Native controller quickstart

Start with [Start here](README.md): prerequisites, how to verify the download and a worked single-host
evaluation. This page is the reference for the native package.

**Requirements.** An x86_64 Debian 12 or Ubuntu 24.04 host with real systemd, Python 3, OpenSSL 3, CA
certificates, `zstd` to unpack the archive, and a reverse proxy with a certificate for each of two public names
([HTTPS ingress](controller-ingress.md)). The installed controller needs no Docker, Redis or Node runtime.
The recovery authority needs PostgreSQL 16; Debian 12 ships PostgreSQL 15, so add the PostgreSQL project's apt
repository ([Start here](README.md#native-evaluation-on-one-host)).

**Recovery authority.** The controller serves only while a separate PostgreSQL 16 database (the authority)
records it as the current owner. Production configuration needs `BLINDPASS_AUTHORITY_URL_FILE`,
`BLINDPASS_CONTROLLER_TENANT_ID` and `BLINDPASS_CONTROLLER_OWNER_ID`; the installer sets them from its options.
Keep the authority credential in a private file owned by the service user, outside backed-up state and keys, and
never as an inline URL. The layout is [`recovery-authority.sql`](../../deploy/controller/recovery-authority.sql).
Startup never creates or activates that record: serving needs an explicit activation, and one start consumes it.
`authority-activate.sql` refuses a restored (`recovering`) record; a restored snapshot is activated only through
the protected [recovery activation](recovery-activation.md) runbook
([native restore sequence](#restore-and-recovery-activation-on-the-native-package)). A locked SQLite upgrade with
an automatic verified pre-upgrade backup is in the [upgrade runbook](upgrade.md).

**Verify what you downloaded** before extracting it: [Verify a download](../release/README.md#verify-a-download)
checks the signature and the checksums. Checksums and the archive's member manifest detect corruption; only the
signature, checked against a key fingerprint you obtained through another channel, authenticates the publisher.

## Provisioning sequence

The recovery authority is a separate PostgreSQL 16 database that you administer
independently of this host (never on the controller's backup path). Remote
authority hosts require `sslmode=verify-full` (or `verify-ca`) in the URL; the
installer refuses anything else, and local loopback is exempt. The archive ships
the administrator SQL under `deploy/controller/`.

1. **Authority (administrator).** In a PostgreSQL 16 database of its own (create it first), apply
   `deploy/controller/recovery-authority.sql` as a PostgreSQL superuser, create a runtime role
   (`CREATE ROLE ROLE LOGIN PASSWORD '…'`) and apply `deploy/controller/authority-runtime-role.sql` with
   `-v runtime_role=ROLE`. Feed each file to `psql` on standard input (`psql -d DB -f - < file`) so the
   PostgreSQL account needs no access to your home directory. Put the runtime URL, in the form
   `postgresql://ROLE:PASSWORD@HOST:5432/DATABASE` (add `?sslmode=verify-full&sslrootcert=PATH` for a remote
   host), in a private file (`0600`, no symlinks), for example `/root/private/authority-url`. The installer checks
   only `sslmode`; the file named by `sslrootcert` must be readable by the `blindpass` account, and a remote
   authority with a private CA was not exercised on the native path in the dry run.
2. **Install and create keys.** The installer validates the URL, copies it to a
   root-only directory delivered by `LoadCredential`, creates the keys and prints
   the public issuer key ID:

   ```bash
   tar --zstd -xf blindpass-controller-0.1.0-linux-x86_64.tar.zst
   cd blindpass-controller-0.1.0-linux-x86_64
   ./deploy/native/install.sh --verify-only
   sudo ./deploy/native/install.sh --public-url https://blindpass.example \
     --ui-url https://input.example --authority-url-file /root/private/authority-url \
     --tenant-id TENANT --owner-id OWNER --initialize-keys
   ```

3. **Register (administrator).** `psql -d DB -v tenant=TENANT -v owner=OWNER -v issuer=ISSUER_KEY_ID -f - < deploy/controller/authority-register.sql`
   with the printed `issuer_key_id` (it can be read again with `sudo -u blindpass blindpass keys issuer-id`; the
   command only works as the service account). The record starts fenced at epoch 1; a repeat or conflict refuses.
4. **Create the database.** `sudo ./deploy/native/install.sh --initialize` creates
   the SQLite database once, against the fenced record.
5. **Grant a start (administrator), then start.**
   `psql -d DB -v tenant=... -v owner=... -v issuer=... -f - < deploy/controller/authority-activate.sql`, then
   `sudo ./deploy/native/install.sh --start`. `--start` waits (20 seconds by default; `--start-timeout SECONDS`,
   1 to 300) for the unit to be active **and** `/readyz` to answer 200 on the loopback listener, then prints
   `{"ok": true, "started": true, "ready": true, …}`. Otherwise it exits with status 1, prints
   `{"ok": false, "started": false, …}` on standard output and says why on standard error. Two different failures
   look alike but are not the same:
   * **The activation was already consumed** (a restart, a reboot, a second start of one activation) or another
     holder exists: the process exits before it opens any listener; `--start` reports
     `startup_failed reason=fenced` read from that start's journal.
   * **The authority record is fenced and was never activated** (or the state was restored and awaits its recovery
     activation): the controller keeps running as a diagnostic process, `/healthz` answers 200 and `/readyz`
     answers 503 `recovery_required` indefinitely; `--start` reports `running but not ready` and the same next
     step. Stop the service before activating (the ledger refuses an activation while a holder exists).

   Both messages name the next step: run `authority-activate.sql` for this start. `journalctl -u blindpass-controller`
   has the full record. Confirm a start independently with `curl --fail http://127.0.0.1:3200/readyz`
   (`{"ok":true,…}` once the activation is consumed).

Every later start or restart — including after a reboot or crash — needs a new
activation, because a started process consumes its one-use revision. The unit has
`Restart=no` for that reason. The ledger refuses an activation while any holder
still exists; stop the service first. To run `reconcile-clock` or other fenced
maintenance, stop the service, run `authority-fence.sql`, run the maintenance
command, then activate again. `authority-fence.sql` also cuts off a running
controller. A store outage that blocks the epoch check also fences the owner; the
service stays not ready after the store returns until the next activation. This
fail-closed behavior (P06-D12) is the confirmed pilot decision, so plan for one
re-activation after every store outage. Never
activate a `recovering` (restored) record: the script refuses.

The two-step key/database initialization replaces the earlier single
`--initialize`. The installer never evaluates shell config and never infers
missing trust from a service restart.

For built-in TLS, supply a matching private PEM pair instead of the proxy:

```bash
sudo ./deploy/native/install.sh --public-url https://blindpass.example:3200 \
  --tls-cert /root/private/fullchain.pem --tls-key /root/private/key.pem \
  --authority-url-file /root/private/authority-url --tenant-id TENANT --owner-id OWNER \
  --initialize-keys   # then steps 3-5 above
```

Both inputs must be regular single-link files with no group/other access or
symlink path components. The installer copies them to a root-only directory;
systemd passes them to the service with `LoadCredential`. TLS paths use unit
`Environment=` specifiers, since `EnvironmentFile` does not expand `%d`.
The initial listen address is still loopback; a remote direct-TLS deployment
requires the operator to set `BLINDPASS_LISTEN` in the protected config and
restart, with matching endpoint routing and firewall rules.
The backup job and the handoff commands load the same file without the TLS credential and with the bind pinned to loopback, so
a wildcard bind does not stop them (`Config::from_env_offline`; the [native node run](../testing/evidence/p06-native-node-2026-10-05.md)
took a packaged backup on such a controller).

The dedicated locked `blindpass` system account has no login shell, home or
extra groups. Existing unmanaged accounts, units, state and program paths are
refused. Installed executables live under `/opt/blindpass/controller/0.1.0`,
selected by `current`; `/usr/local/bin` contains the two managed links.
`/etc/blindpass/controller.env` is root:blindpass 0640. Keys and data directories
are blindpass-owned 0700; keys are 0600. The service uses a private runtime
directory and a read-only root filesystem with only its data/runtime writable,
no capabilities, no new privileges, private devices/temp and restricted system
calls/namespaces. Core dumps are disabled.

```bash
sudo systemctl status blindpass-controller.service
curl --fail http://127.0.0.1:3200/readyz  # proxy mode, local probe only
sudo blindpass admin bootstrap-token
```

In TLS mode the probe uses `https://127.0.0.1:3200/readyz` and a matching trusted
certificate, rather than plaintext. Deliver the one-use bootstrap token
directly to its intended administrator; do not capture it in shared logs. The
token lives 15 minutes; issuing another invalidates every earlier unused one, so
re-run `blindpass admin bootstrap-token` if one may have been exposed. After ten
wrong passwords from one address an operator account locks that address for 15
minutes (fifty across addresses locks it for everyone); recover a locked
operator with `sudo blindpass admin reset-password <username-or-id>`; `sudo blindpass admin operators list`
shows every operator's id, username, role and lock state without opening the database. See
[operator sign-in limits](../security/operator-auth-and-headers.md).
The controller consumes raw key plaintext in runtime memory for its lifetime;
systemd credential copies last for the unit lifetime. SQLite contains protected
application state, not a substitute for encrypted recovery backups.
During an explicit TLS install, the installer and its short-lived OpenSSL
validation subprocess consume the supplied PEM plaintext in memory until
their processes exit. They publish only the protected files and fixed status
messages, never PEM content or parser diagnostics.

The backup service/timer are installed **disabled and inactive**. No backup
credential or enable marker is created. The SQLite candidate takes a completed snapshot,
includes all three controller keys and a bound manifest, encrypts/signs it with
standard CMS and verifies the decrypted archive and database before publication.
Its names are `blindpass-controller-backup.*`; existing broker backup probe units
are separate. Complete P06 recovery and workflow acceptance remain open.

Backups use split custody ([ADR 0013](../product/decisions/0013-p06-backup-key-custody-split.md)).
Create both role credentials once in a private root directory, install **only** the
signing credential and the recipient's certificate on the host, and move the recipient
key to separate offline storage:

```bash
sudo install -d -m 0700 /root/blindpass-backup-custody
sudo blindpass backup key-init --role signing --output /root/blindpass-backup-custody/signing.pem \
  --certificate-output /root/blindpass-backup-custody/signing-certificate.pem
sudo blindpass backup key-init --role recipient --output /root/blindpass-backup-custody/recipient.pem \
  --certificate-output /root/blindpass-backup-custody/recipient-certificate.pem
sudo sh -c 'umask 077; set -C
  cat /root/blindpass-backup-custody/signing.pem > /etc/blindpass/controller-backup-signing-credential
  cat /root/blindpass-backup-custody/recipient-certificate.pem > /etc/blindpass/controller-backup-recipient-certificate'
# Now move recipient.pem (and signing-certificate.pem) to offline storage and delete the local copy.
```

Key creation and the no-clobber copies refuse an existing output. Keep **two**
protected offline copies of `recipient.pem` before enabling the timer: it is the only
way to read an archive, and losing it makes existing encrypted archives
unrecoverable. The create job refuses a recipient file that contains a private key.
Both installed files must remain root-owned single-link mode-0600 files. The command
checks patched system OpenSSL; see the
[format and prerequisites](../product/decisions/0010-p06-authenticated-backup-format.md).

Every configured backup first runs the Root metadata-only
`blindpass-controller-backup-credential-check.service`. It checks both custody files
and the enable marker, including safe parent directories, Root ownership,
single regular files, exact 0600 modes and size bounds. It refuses symlinks, hard
links, FIFOs and unsafe custody before the backup process starts. It reads no
credential plaintext and repairs no permissions. Correct custody privately before
retrying a failed check; systemd's private credential copy does not establish
protection of its original source.

Verify retained archives on the offline machine (or by mounting the offline files only
for the check) with `blindpass backup verify --archive A --recipient-key-file
recipient.pem --signing-certificate-file signing-certificate.pem --work-directory W
--expected-archive-sha256 DIGEST`. Give absolute paths, create the work directory first as a private directory (`0700`, yours) and keep the
directory that holds the archive private too. The key and certificate files must be regular files with one link,
owned by you, mode `0600` or `0400`; their directory need not be private. The command refuses a relative path, a
missing or non-private work directory, a non-private archive directory and any input that group or world can
access, and each refusal names the option and the rule (never the path). `backup create` prints the digest; record it where the
backup host cannot write. Create-time `verified: true` does not prove the offline
recipient entry decrypts, so verify on a schedule.

After protecting the offline copies, opt in and run the first backup:

```bash
sudo install -m 0600 /dev/null /etc/blindpass/controller-backup-enabled
sudo systemctl start blindpass-controller-backup.service
sudo journalctl -u blindpass-controller-backup-credential-check.service -u blindpass-controller-backup.service -n 10 --no-pager
# Enable the daily timer after the journal reports a verified backup.
sudo systemctl enable --now blindpass-controller-backup.timer
```

Successful jobs publish only mode-0600 encrypted `.bpbackup` files under
`/var/lib/blindpass/controller/backups` (mode 0700, owned by blindpass). Copy
encrypted archives to separately managed backup storage before removing local
state. The timer runs at 03:00 local time with up to 15 minutes of random delay.
The complete service has a start budget of 15 minutes and a stop budget of
10 seconds; each backup tool has its own limit of 60 seconds. Failure never
publishes an unverified archive. The archive limit is 512 MiB; total RAM usage
can exceed that size.

The backup process, OpenSSL children and private staging consume database/key
plaintext during the job. Systemd delivers the protected signing credential and recipient certificate for
the unit lifetime and removes its credential copy after exit. Ordinary return
removes staging; interrupted jobs can leave sensitive private residue. After
stopping the backup service, remove that residue explicitly as the service UID:

```bash
sudo systemctl stop blindpass-controller-backup.service
sudo runuser -u blindpass -- blindpass backup cleanup --work-directory /var/lib/blindpass/controller/backups
```

Cleanup takes custody locks and preserves published archives. Unlinking is not
secure media erasure. Verification checks archive authenticity, safe members and
database integrity; restored-state activation is the
[protected activation procedure](recovery-activation.md) (external authority, source-stop
attestation, node coverage and operator review).

A same-manifest reinstall preserves keys, config and database. A different
version or changed artifact is refused without `--upgrade`; `--upgrade` accepts
only a newer version and is followed by the separate fenced migration in the
[upgrade runbook](upgrade.md). Downgrade is restore-only.
Default startup validates config and requires existing initialized state;
it does not migrate, repair or replace missing state. Systemd may recreate an
empty `StateDirectory`, but serving still refuses a missing database. The
root-only initialization record prevents a later installer from treating lost
state as a new tenant. This local record is clonable metadata, **not** the P06
external recovery/ownership anchor.

After a full host reboot the existing controller clock guard can require
explicit reconciliation. This invalidates transient authority and operator
sessions; read the [test setup](https://github.com/atas-tech/blindpass/blob/main/docs/testing/README.md)
before running it:

```bash
sudo systemctl stop blindpass-controller.service
sudo systemctl start blindpass-controller-reconcile-clock.service
sudo systemctl start blindpass-controller.service
```

Default uninstall removes only managed controller programs and units, retaining
keys, data, TLS material, config, installation records and the system account:

```bash
sudo ./deploy/native/uninstall.sh
# The same extracted artifact can reinstall retained state without --initialize.
# Every start needs a fresh activation, so grant one before starting (the authority is untouched by uninstall):
psql -d DB -v tenant=TENANT -v owner=OWNER -v issuer=ISSUER_KEY_ID -f - < deploy/controller/authority-activate.sql
sudo ./deploy/native/install.sh --start
# The backup timer is disabled again after a reinstall; re-enable it if you used it:
sudo systemctl enable --now blindpass-controller-backup.timer
```

Explicit irreversible purge requires both flags:

```bash
sudo ./deploy/native/uninstall.sh --purge --confirm-purge blindpass-controller
```

Purge validates custody and refuses linked/unsafe state, removes controller keys,
data/config/TLS and the managed backup signing credential, recipient certificate and enable marker, and retains
the locked account and a root-only **purged** custody
record. It leaves broker/node/probe units and unrelated files alone. An operator
may explicitly initialize a new tenant after this confirmed purge; that action
does not restore old authority. Interrupted setup that already created any key
material needs manual review and recovery; rerunning initialization never
overwrites it. Migration between profiles and complete
three-profile workflow parity remain required by P06.


The source candidate also conservatively refuses local quiescence after admitted
database work is cancelled or loses its acknowledgement. Production stop can
return `controller shutdown did not drain within bound` even when its process
exits within the five-second transport bound. Do not use that refusal as transfer
or activation proof. The uncertainty latch retains the live authority guard but
is lost with the process; durable external source-stop/database evidence remains
required. See [actual PostgreSQL cancellation/COMMIT evidence](../testing/evidence/p06-database-uncertainty-2026-10-04.md).


A planned move of the controller to another host under the same owner (not a
disaster recovery) is in the [handoff runbook](handoff.md). The native package has no
handoff units yet: the commands run by hand as the service account, and the
packaged native profile was not exercised for it.

## Restore and recovery activation on the native package

The package ships `blindpass-controller-restore.service`, an operator-started `Type=oneshot` unit that runs as the
`blindpass` account with the offline custody loaded as credentials, tmpfs staging and one writable state directory. It is
never enabled and never started by the installer; it `Conflicts=` with the serving unit and does not start without its
operator-written inputs. `tests/deployment/native-install.sh --recovery` runs exactly this sequence in a real systemd guest.
The authority is the separately administered PostgreSQL; the harness uses the guest's own PostgreSQL, which is **not**
independent.

1. **Reserve.** `systemctl stop blindpass-controller`, `authority-fence.sql`, then `reserve_recovery(tenant, issuer, owner,
   revision, 1)` (see [recovery stage](recovery-stage.md)). The record is now `recovering` at a higher epoch.
2. **Stage the archive.** Copy the archive to a directory the service account owns (mode 0700), for example
   `/var/lib/blindpass/controller-restore/archives/` (the unit's state directory). Keep the offline recipient key and the
   signer certificate outside the host's backup custody (ADR 0013); the backup host's own credential cannot open the archive.
3. **Restore.** Put the offline custody on the host only for the restore: `/etc/blindpass/controller-restore/recipient-key` and
   `/etc/blindpass/controller-restore/signing-certificate` (root-owned, mode 0600; systemd loads them as credentials and the
   service account never sees the files), and write `/etc/blindpass/controller-restore.env` (root, 0600):

   ```bash
   BLINDPASS_RESTORE_ARCHIVE=/var/lib/blindpass/controller-restore/archives/ARCHIVE.bpbackup
   BLINDPASS_RESTORE_DESTINATION=/var/lib/blindpass/controller-restore/root
   BLINDPASS_RESTORE_TENANT_ID=TENANT
   BLINDPASS_RESTORE_OWNER_ID=OWNER
   BLINDPASS_RESTORE_RECOVERY_ID=UNIQUE_ID
   ```

   then `systemctl start blindpass-controller-restore.service` and read the receipt from
   `<BLINDPASS_RESTORE_DESTINATION>/restore.json` (the harness reads that file; the receipt was not found in the unit's journal in
   the guest runs, so do not rely on the journal for it). Afterwards delete the custody directory and the environment
   file. The unit is skipped (condition failed) while any of the inputs is missing, so a stray start does nothing; the staging
   area under `/run` and the credential copies are removed when the unit ends.

   The receipt says `phase: recovery_required`, `activation_permitted: false`; the destination must not exist.
4. **Install the restored state.** Move the damaged `/var/lib/blindpass/controller` and `/etc/blindpass/keys` aside, copy
   `root/data` and `root/keys` into place with `cp -a`, and restore owner `blindpass:blindpass` and mode 0700 on both
   directories (key files stay 0600). Keep your archive directory under the new data directory if you used it. Remove
   the staged `root` afterwards.
5. **Start it fenced and finish the protected procedure.** `systemctl start blindpass-controller` (no activation: the
   process serves only `recovery_required`), then as the service account
   `blindpass admin recovery status|review list|review decide|waive-node|review complete`, `systemctl stop`,
   `authority-recover-attest.sql`, `authority-recover-activate.sql` and `systemctl start`, exactly as in the
   [activation runbook](recovery-activation.md). Every recovery epoch, including a repeated restore of the same archive
   (rollback), needs its own review, attestation and activation. `authority-activate.sql` refuses a `recovering` record.

The guest run covers both operating systems (see the [record](../testing/evidence/p06-packaged-recovery-2026-10-05.md)).
**Limits:** `native-install.sh --recovery` has no real node in its guest, so one seeded broker trust row is covered only by a named
waiver. A real node in a second guest is covered by the [native node record](../testing/evidence/p06-native-node-2026-10-05.md)
(`tests/fleet/p06-native-node-vm.py`), which also exercises the remote direct-TLS configuration of this guide (a wildcard
`BLINDPASS_LISTEN` with built-in TLS) and the stale-source refusals. The authority is in-guest PostgreSQL in both. The
restore unit and the fault scenarios were run on x86-64 only ([record](../testing/evidence/p06-native-recovery-faults-2026-10-05.md)).

## Status and limits

The paragraphs below are the maintainers' status notes for this package. They name internal evidence records and
are not installation instructions.

Current transport candidate: active HTTP/TLS/admin connections retain ownership
until local IO closes. Fencing can close an in-flight connection; reconnect for
diagnostic readiness 503/health 200. HTTP connections reconnect within 60 seconds;
node polls keep their existing 35-second handler bound. Local admin connections
last at most 10 seconds. Shutdown fences and stops transports before graceful
waiting. [Transport evidence](../testing/evidence/p06-transport-ownership-2026-10-04.md)
is source/process evidence, not authenticated old-host stop or ambiguous SQL
rollback. Complete restore/transfer profiles still require integration and
actual verification.


The current source [production ownership candidate](../testing/evidence/p06-production-ownership-2026-10-04.md)
requires `BLINDPASS_AUTHORITY_URL_FILE`, `BLINDPASS_CONTROLLER_TENANT_ID` and
`BLINDPASS_CONTROLLER_OWNER_ID` before production configuration/serve/maintenance.
Keep the authority credential outside backed-up state/keys, in a private file
owned by the service UID; never use an inline URL. Its separately provisioned
PostgreSQL database uses the reviewed [authority layout](../../deploy/controller/recovery-authority.sql).
Startup never creates or activates that record. Initialization/clock maintenance
require a fenced record; serving requires an explicit current process revision,
which one start consumes and which is never replayed after process death. `authority-activate.sql` refuses a
restored (`recovering`) record; a restored snapshot is activated only through the protected
[recovery activation](recovery-activation.md) ([native restore sequence](#restore-and-recovery-activation-on-the-native-package)). A locked SQLite upgrade with an automatic verified pre-upgrade
backup is described in the [upgrade runbook](upgrade.md). The
[operator sequence](#provisioning-sequence) above is exercised by real Debian 12
and Ubuntu 24.04 guest runs recorded in the
[P06 authority provisioning record](../testing/evidence/p06-authority-provisioning-2026-10-04.md);
earlier lifecycle logs predate it and retain their historical limits.

The P06 controller archive contains both embedded web surfaces, the local CLI
and the native lifecycle scripts. Use a reviewed x86_64 artifact on Debian 12
or Ubuntu 24.04 with real systemd, Python 3, OpenSSL 3 and CA certificates.
No Docker, Redis or Node runtime is needed by the installed controller.
Other architectures and full deployment/recovery acceptance remain open.
See [release layout](release-layout.md) and [HTTPS ingress](controller-ingress.md).

Verify `SHA256SUMS` obtained through your trusted release channel before
extracting the archive. Checksums and its member manifest detect corruption;
they do not authenticate an untrusted publisher.
