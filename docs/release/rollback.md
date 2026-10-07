# Rollback of a bad release

**Rehearsed 2026-10-06 on the packaged native controller (SQLite store, Ubuntu 24.04 and Debian 12 guests); P07-E03 is
not passed.** Everything the procedure promises about **state** held: the identity came back byte-identical, every operator
session was gone, nodes that could not report lost their trust, the defective release's state was refused and one issuer
existed throughout. The one required result that failed is that **the previous program version cannot be put back with the
shipped native installer** ([record](../testing/evidence/p07-rollback-2026-10-06.md)). The rehearsal used stand-ins: no
earlier packaged release exists, so "previous" is the 0.1.0 archive and "candidate" is the same binaries repacked as 0.1.1
with an unchanged schema. It proves the procedure and the installer's behaviour, not that two different builds
interoperate.

## Principles

- Stop further distribution first; restore the last tested release second.
- **Software rollback does not revoke credentials.** Rehearsed: after the installed artifact was removed and put back over
  its retained state, a session issued before the upgrade and one issued by the candidate both still answered `200`. A bad
  release can leave sessions, grants and node trust that were created while it ran; revoke them (step 5) when the defect
  implicates them.
- A controller schema has no downgrade, and the native installer has no downgrade either: it refuses an older archive both
  with and without `--upgrade` (`downgrade is restore-only`). A native installation moves forward only. The way back to an
  earlier **state** is a restore; a restored controller serves only after the protected recovery activation.
- Two controllers must never issue at once: every route below goes through the authority record
  ([recovery activation](../deploy/recovery-activation.md)).

## Before you upgrade

`migrate` takes an automatic verified backup only when the stored schema is **older** than the new build's. A release that
leaves the schema unchanged takes none. Before every `install.sh --upgrade`, start the backup unit and verify the archive
with the offline recipient key ([native quickstart](../deploy/native-quickstart.md)), then keep a copy off the host. That
archive is the rollback point. Record the version you are leaving, and note that **the upgrade removes nothing but also
keeps no way back**: the old program tree stays on disk until an uninstall, but no installer path selects it again.

## Order

1. **Stop distribution.** Leave the GitHub release a draft or mark it a pre-release and say why; remove the
   `X.Y` and `X.Y.Z` image tags from documentation; deprecate the npm version
   (`npm deprecate @blindpass/mcp-server@X.Y.Z "<reason>"`, maintainer credentials; not rehearsed).
   Published artifacts are signed: do not re-sign or replace them, publish a new version.
2. **Decide what has to change.**
   - *Only the binaries are wrong and the state is fine.* On native there is no way to reinstall the previous archive over
     the candidate (rehearsed: refused with `downgrade is restore-only`, state and installed version unchanged). Publish a
     fixed version and `--upgrade` to it. Replacing damaged binaries of the **same** version is supported: stop the
     controller, `uninstall.sh`, `install.sh`, grant an activation and `install.sh --start`; the backup timer is disabled
     again by that and must be re-enabled. This changes no credential. Compose pins an image tag, so the previous tag can
     be run again **against the previous state**; a Compose rollback was not rehearsed.
   - *The candidate wrote state that must not survive.* Go to step 3.
3. **Restore the state from the rollback point** (rehearsed end to end on both guests). Follow
   [Restore and recovery activation on the native package](../deploy/native-quickstart.md#restore-and-recovery-activation-on-the-native-package):
   stop the controller, fence the authority record and reserve a recovery epoch; stage the archive; run
   `blindpass-controller-restore.service` with the offline custody; move the defective state aside and put the restored
   `keys` and `data` in place; start the controller (it serves only `recovery_required`); review, waive nodes that cannot
   report, attest that the source is stopped and activate. Observed results:
   - the issuer key, root secret and agent secret are byte-identical to before the upgrade; the authority ledger moved one
     epoch (`active:1:11` to `active:2:15`) with one issuer and one holder;
   - **every operator session was already gone when the restored files were placed** (the restore deletes sessions) and the
     review listed only the operator account;
   - a node trust row that could not report had to be waived and is `revoked` afterwards (the node must be enrolled again);
   - starting the defective release's state again was refused by the controller after the new epoch;
   - everything written after the backup is lost, and **the controller that comes back runs the installed (candidate)
     program, not the previous one.** Today the only way to run the previous binaries is to purge the installation and
     install the previous archive fresh; that path was probed and is blocked (see *Open*).
   Context: [upgrade runbook](../deploy/upgrade.md), [restore stage](../deploy/recovery-stage.md).
4. **Planned handoff was the change.** `blindpass handoff abort` works only while the authority record is still
   the exported one; after the destination activated, rollback is restore-only
   ([handoff](../deploy/handoff.md#abort-and-rollback)).
5. **Revoke and reconcile.** A software-only rollback keeps sessions; a restore deletes them. In both cases:
   - Operator sessions that must not survive: `blindpass admin reset-password <username>` per operator (username in any
     letter case, or the id; `blindpass admin operators list` shows them). Rehearsed after a software-only reinstall: the
     session issued before the upgrade and the candidate's both answered `401` afterwards. The reset also clears sign-in
     locks, sets a temporary password and forces a change at the next sign-in.
   - An operator locked out by the incident (or by a guesser) is recovered by the same command; rehearsed after the
     rollback: locked account `423`, reset by upper-cased username, old password `401`, temporary password signs in, forced
     change accepted, new password signs in.
   - Nodes, grants and agents: run `blindpass status --nodes --require-online` and the recovery review steps
     (`blindpass admin recovery status|review list|decide|complete|waive-node`, [recovery activation](../deploy/recovery-activation.md))
     for what changed while the bad release served. A node waiver revokes that node's trust row
     ([packaged recovery record](../testing/evidence/p06-packaged-recovery-2026-10-05.md)); `blindpass admin node revoke` revokes one
     node through the controller API (not rehearsed).
   - `blindpass admin reconcile-clock` also revokes operator sessions but is the clock-regression recovery and removes
     expiring state; do not use it as a general revoke.
6. **Freeze recruitment** (P08) and record the corrective evidence before resuming
   ([recruitment](recruitment.md)).

## Open (owner decision)

The native installer is a ratchet. After an upgrade there is no supported route to the previous program version:
`install.sh` and `install.sh --upgrade` refuse the older archive; `uninstall.sh` keeps the installed version's record. The
only route left, purge and a fresh install of the previous archive, was probed in the rehearsal and stops at the
restore: `blindpass-controller-restore.service` and `blindpass-controller.service` both require
`/etc/blindpass/controller-initialized`, which only `install.sh --initialize` writes, and `--initialize` creates a new
database with new keys instead of adopting the restored one. Options: accept roll-forward plus restore-based state rollback
for the pilot and say so wherever a "previous release restored" guarantee could be read; or add an installer path that
adopts a restored installation. Until one is chosen, do not claim that a native upgrade can be rolled back to the previous
program.

## Not rehearsed

A genuine previous release (two different builds); a schema-changing candidate and its automatic `pre-upgrade-*` backup used
as the rollback point; PostgreSQL controller store; Compose and node-package rollbacks; a real node reporting during
recovery; the distribution steps in 1 (GitHub, npm, image tags); `blindpass admin node revoke`; hosted CI.
