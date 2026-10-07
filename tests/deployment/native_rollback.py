# SPDX-License-Identifier: AGPL-3.0-only
"""P07-E03: rollback rehearsal of a candidate native release, inside a disposable real-systemd guest only.

Run through `native-install.sh --rollback` (stage `after-reboot-rollback` of native-guest.py, which passes its own
module in as `ng`). No secret output: passwords, tokens and session identifiers stay in memory and are scanned for in
the controller journal at the end.

Stand-ins, stated plainly: no earlier packaged release exists, so "previous" is the 0.1.0 archive under test and
"candidate" is the same verified binaries repacked as 0.1.1 with the schema unchanged. The rehearsal therefore proves
the procedure, the installer's refusals and the state, identity, session and authority behaviour; it cannot prove that
two genuinely different builds interoperate.
"""
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shutil
import ssl
import subprocess
import time
import urllib.error
import urllib.request

import canary_log_scan

ORIGIN = 'https://localhost:3200'
ADMIN_SOCKET = '/run/blindpass-controller/admin.sock'
UPGRADE_UNIT = 'blindpass-controller-upgrade.service'
MARKER = Path('/etc/blindpass/controller-install.json')
PREFIX = Path('/opt/blindpass/controller')
RESTORE_STATE = Path('/var/lib/blindpass/controller-restore')
RESTORE_ROOT = RESTORE_STATE / 'root'
WRONG_PASSWORD = 'p07-rb-dummy-wrong-password'
OBSERVATIONS = {}


def observe(name, value, detail=''):
    OBSERVATIONS[name] = bool(value)
    print('P07-E03 observation ' + name + '=' + ('yes' if value else 'no') + ((' ' + detail) if detail else ''), flush=True)


def note(label, **fields):
    print('P07-' + label + ' ' + ' '.join(key + '=' + str(value) for key, value in fields.items()), flush=True)


def parse(body):
    try:
        return json.loads(body)
    except ValueError:
        return None


def rehearse(ng):
    state = ng.authority_state()
    user = pwd.getpwnam('blindpass')
    secrets_seen = []          # every credential this rehearsal creates, scanned for in the journal at the end

    # ------------------------------------------------------------------ helpers
    def http(method, path, body=None, headers=None):
        context = ssl.create_default_context(cafile=str(ng.CERT))
        sent = {'content-type': 'application/json'} if body is not None else {}
        sent.update(headers or {})
        request = urllib.request.Request(ORIGIN + path, data=None if body is None else json.dumps(body).encode(),
                                         method=method, headers=sent)
        try:
            with urllib.request.urlopen(request, context=context, timeout=20) as response:
                return response.status, response.read(), response.headers
        except urllib.error.HTTPError as error:
            return error.code, error.read(), error.headers

    def login(username, password, address):
        status, body, headers = http('POST', '/api/v3/admin/session/login', {'username': username, 'password': password},
                                     {'origin': ORIGIN, 'cookie': 'bp_csrf=p07-rb-pre-session',
                                      'x-csrf-token': 'p07-rb-pre-session', 'x-forwarded-for': address})
        session = None
        for cookie in headers.get_all('Set-Cookie') or []:
            if cookie.startswith('bp_session='):
                session = cookie.split(';', 1)[0].split('=', 1)[1]
        if session:
            secrets_seen.append(session)
        return status, parse(body), session, headers

    def session_status(session):
        return http('GET', '/api/v3/admin/session', headers={'cookie': 'bp_session=' + session})[0]

    def admin(*args, success=True):
        result = subprocess.run(['runuser', '-u', 'blindpass', '--', ng.BLINDPASS, 'admin', *args, '--socket', ADMIN_SOCKET],
                                stdin=subprocess.DEVNULL, capture_output=True, timeout=120)
        if (result.returncode == 0) != success:
            first = result.stderr.decode(errors='replace').splitlines()
            print('P07-' + ng.case + ' admin ' + ' '.join(a for a in args if a.startswith('-') or a.isalpha() and len(a) < 16)
                  + ' expected_success=' + str(success) + ' rc=' + str(result.returncode) + ' stderr=' + (first[0][:80] if first else ''), flush=True)
        assert (result.returncode == 0) == success, 'admin ' + args[0] + (' failed' if success else ' was accepted')
        return result

    def admin_json(*args):
        return json.loads(admin(*args).stdout.decode())

    def scalar(sql):
        return ng.psql(sql=sql).strip()

    def ledger():
        return scalar("SELECT phase||':'||epoch||':'||revision FROM blindpass_authority.recovery_authority WHERE tenant_id='" + state['tenant'] + "'")

    def facts():
        pid = ng.show('MainPID')
        exe = os.readlink('/proc/' + pid + '/exe') if pid not in ('', '0') else None
        epoch, revision = ledger().split(':')[1:]
        issuer_disk = ng.run(['runuser', '-u', 'blindpass', '--', ng.BLINDPASS, 'keys', 'issuer-id', '--directory', ng.KEYS]).strip()
        return {
            'version': json.loads(MARKER.read_text())['version'],
            'current': str((PREFIX / 'current').readlink()),
            'exe': exe,
            'ledger': ledger(),
            'issuer_rows': int(scalar("SELECT count(*) FROM blindpass_authority.recovery_authority WHERE tenant_id='" + state['tenant'] + "'")),
            'issuer_ids': scalar("SELECT string_agg(DISTINCT issuer_key_id,',') FROM blindpass_authority.recovery_authority WHERE tenant_id='" + state['tenant'] + "'"),
            'issuer_on_disk': issuer_disk,
            'holders_at_current': int(scalar("SELECT count(*) FROM blindpass_authority.active_process WHERE tenant_id='" + state['tenant']
                                             + "' AND epoch=" + epoch + " AND revision=" + revision)),
            'props': {prop: ng.show(prop) for prop in ['ActiveState', 'Restart', 'User', 'NoNewPrivileges', 'ProtectSystem', 'LimitCORE', 'Type']},
            'identity': ng.identity(),
        }

    def session_counts():
        import sqlite3
        with sqlite3.connect('file:' + str(ng.DATA / 'controller.db') + '?mode=ro', uri=True) as connection:
            return connection.execute("SELECT count(*), sum(revoked_at IS NULL) FROM operator_sessions").fetchone()

    def stage_and_restore(archive):
        """The shipped restore unit with the operator's offline custody (native quickstart, restore step 2-3)."""
        RESTORE_STATE.mkdir(mode=0o700); os.chown(RESTORE_STATE, user.pw_uid, user.pw_gid)
        (RESTORE_STATE / 'archives').mkdir(mode=0o700); os.chown(RESTORE_STATE / 'archives', user.pw_uid, user.pw_gid)
        staged = RESTORE_STATE / 'archives' / archive.name
        shutil.copy2(archive, staged); os.chown(staged, user.pw_uid, user.pw_gid); staged.chmod(0o600)
        custody = Path('/etc/blindpass/controller-restore'); arguments = Path('/etc/blindpass/controller-restore.env')
        custody.mkdir(mode=0o700, exist_ok=True)
        for name, source in (('recipient-key', ng.OFFLINE_KEY), ('signing-certificate', ng.OFFLINE_SIGNER)):
            shutil.copy2(source, custody / name); (custody / name).chmod(0o600)
        arguments.write_text(''.join(name + '=' + value + '\n' for name, value in {
            'BLINDPASS_RESTORE_ARCHIVE': str(staged), 'BLINDPASS_RESTORE_DESTINATION': str(RESTORE_ROOT),
            'BLINDPASS_RESTORE_TENANT_ID': state['tenant'], 'BLINDPASS_RESTORE_OWNER_ID': ng.OWNER,
            'BLINDPASS_RESTORE_RECOVERY_ID': 'p07rb' + secrets.token_hex(3)}.items()))
        arguments.chmod(0o600)
        try:
            subprocess.run(['systemctl', 'reset-failed', ng.RESTORE_UNIT], stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
            ng.run(['systemctl', 'start', ng.RESTORE_UNIT])
            assert ng.show('Result', ng.RESTORE_UNIT) == 'success'
        finally:
            shutil.rmtree(custody, ignore_errors=True); arguments.unlink(missing_ok=True)
            subprocess.run(['systemctl', 'reset-failed', ng.RESTORE_UNIT], stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
        receipt = json.loads((RESTORE_ROOT / 'restore.json').read_text())
        assert receipt['phase'] == 'recovery_required' and receipt['activation_permitted'] is False and receipt['backend'] == 'sqlite', receipt
        return receipt

    def place_restored():
        """Native quickstart restore step 4: copy the restored keys and data into place, owned by the service account."""
        for source, target in ((RESTORE_ROOT / 'keys', ng.KEYS), (RESTORE_ROOT / 'data', ng.DATA)):
            assert not target.exists(), 'the damaged state must have been moved aside'
            ng.run(['cp', '-a', source, target])
            for path in [target, *target.rglob('*')]:
                os.chown(path, user.pw_uid, user.pw_gid, follow_symlinks=False)
            target.chmod(0o700)
        shutil.rmtree(RESTORE_ROOT)

    # ------------------------------------------------------------------ RB01: previous release baseline
    ng.case = 'RB01'
    assert ng.show('ActiveState') == 'active'
    ng.ready(); ng.same_identity()
    assert json.loads(MARKER.read_text())['version'] == '0.1.0' and (PREFIX / 'current').readlink() == Path('0.1.0')
    before = facts()
    token = admin_json('bootstrap-token')['bootstrap_token']
    password = secrets.token_urlsafe(24)
    secrets_seen.extend([token, password])
    status, body, _ = http('POST', '/api/v3/admin/bootstrap', {'username': 'rbadmin', 'display_name': 'Rollback rehearsal administrator', 'password': password},
                           {'origin': ORIGIN, 'x-blindpass-bootstrap-token': token})
    assert status in (200, 201), 'bootstrap answered ' + str(status)
    status, _, previous_session, _ = login('rbadmin', password, '192.0.2.10')
    assert status == 200 and previous_session and session_status(previous_session) == 200
    # The automatic pre-upgrade backup exists only for an older schema; for a candidate with the same schema the
    # operator takes and verifies one by hand immediately before the upgrade.
    known = set((ng.DATA / 'backups').glob('*.bpbackup'))
    ng.run(['systemctl', 'start', ng.BACKUP]); assert ng.show('Result', ng.BACKUP) == 'success'
    fresh = sorted(set((ng.DATA / 'backups').glob('*.bpbackup')) - known)
    assert len(fresh) == 1, 'the backup unit did not publish exactly one new archive'
    ng.backup_verify(fresh[0])
    keep_archive = ng.ROOT / 'rollback-archive.bpbackup'
    shutil.copy2(fresh[0], keep_archive); keep_archive.chmod(0o600)
    note('RB01', version=before['version'], ledger=before['ledger'], exe=before['exe'], sessions=session_counts(),
         archive_verified='yes')
    ng.passed('RB01')

    # ------------------------------------------------------------------ RB02: candidate upgrade, then a defect
    ng.case = 'RB02'
    candidate = ng.ROOT / 'candidate-bundle'; shutil.copytree(ng.BUNDLE, candidate)
    manifest = json.loads((candidate / 'manifest.json').read_text())
    manifest['version'] = '0.1.1'; (candidate / 'manifest.json').write_text(json.dumps(manifest))
    ng.run(['systemctl', 'stop', ng.SERVICE])
    result = json.loads(ng.install('--upgrade', bundle=candidate))
    assert result['ok'] and result['upgraded'] is True and result['version'] == '0.1.1'
    ng.fence()
    ng.run(['systemctl', 'start', UPGRADE_UNIT])
    assert ng.show('Result', UPGRADE_UNIT) == 'success'
    assert not (ng.DATA / 'pre-upgrade-backups').exists(), 'an unchanged schema must not take an automatic backup'
    ng.activate(); ng.run(['systemctl', 'start', ng.SERVICE]); ng.ready(); ng.same_identity()
    candidate_facts = facts()
    assert candidate_facts['version'] == '0.1.1' and candidate_facts['current'] == '0.1.1' and '/0.1.1/' in candidate_facts['exe']
    assert session_status(previous_session) == 200, 'a session from before the upgrade survives the upgrade'
    status, _, bad_session, _ = login('rbadmin', password, '192.0.2.11')
    assert status == 200 and bad_session and session_status(bad_session) == 200
    note('RB02', version=candidate_facts['version'], ledger=candidate_facts['ledger'], exe=candidate_facts['exe'],
         sessions=session_counts(), defect='declared; the candidate session is suspect and the defective release must not keep serving')
    ng.passed('RB02')

    # ------------------------------------------------------------------ RB03: what a software-only rollback can and cannot do
    ng.case = 'RB03'
    # Documented step 2 said "the previous archive can be reinstalled". Rehearse exactly that.
    ng.run(['systemctl', 'stop', ng.SERVICE])
    plain = ng.install(success=False, capture_stderr=True)
    upgrade = ng.install('--upgrade', success=False, capture_stderr=True)
    assert 'downgrade is restore-only' in plain and 'downgrade is restore-only' in upgrade, 'refusal reason changed'
    assert json.loads(MARKER.read_text())['version'] == '0.1.1' and (PREFIX / 'current').readlink() == Path('0.1.1')
    observe('installer_reinstalls_previous_archive_over_candidate', False, 'both forms refused: downgrade is restore-only')
    # The software-only operation that does exist: remove the programs and put the installed artifact back over the
    # retained state (what an operator does to replace damaged binaries). It must not touch credentials.
    ng.run(['python3', candidate / 'deploy/native/controller-install.py', '--uninstall'])
    assert not (PREFIX / '0.1.0').exists(), 'uninstall must have removed the older program tree'
    ng.run(['python3', candidate / 'deploy/native/controller-install.py', '--bundle', candidate])
    ng.activate()
    started = json.loads(ng.run(['python3', candidate / 'deploy/native/controller-install.py', '--bundle', candidate, '--start']))
    assert started['ok'] and started['started'] and started['ready'], started
    ng.ready(); ng.same_identity()
    # Documented in the native quickstart: the backup timer is disabled again by a reinstall; the operator re-enables it.
    timer_after_reinstall = ng.show('UnitFileState', ng.BACKUP_TIMER)
    ng.run(['systemctl', 'enable', '--now', ng.BACKUP_TIMER])
    note('RB03', backup_timer_after_reinstall=timer_after_reinstall, backup_timer_after_reenable=ng.show('UnitFileState', ng.BACKUP_TIMER))
    still = {'before_upgrade_session': session_status(previous_session), 'candidate_session': session_status(bad_session)}
    observe('software_reinstall_alone_revokes_no_credentials', still['before_upgrade_session'] == 200 and still['candidate_session'] == 200,
            'sessions_after_reinstall=' + json.dumps(still, sort_keys=True))
    # The documented revoke step for operator sessions: reset the operator's password by username.
    first_reset = admin_json('reset-password', 'rbadmin'); secrets_seen.append(first_reset['temporary_password'])
    revoked = {'before_upgrade_session': session_status(previous_session), 'candidate_session': session_status(bad_session)}
    observe('revoke_step_revokes_sessions_after_software_rollback', all(value != 200 for value in revoked.values()), json.dumps(revoked, sort_keys=True))
    ng.passed('RB03')

    # ------------------------------------------------------------------ RB04: restore-based rollback (documented step 3)
    ng.case = 'RB04'
    node = 'nd_p07rollback01'
    old_epoch = int(ledger().split(':')[1])
    ng.run(['systemctl', 'stop', ng.SERVICE]); ng.fence()
    revision = scalar("SELECT revision FROM blindpass_authority.recovery_authority WHERE tenant_id='" + state['tenant'] + "'")
    reserved = scalar("SELECT epoch||':'||phase FROM blindpass_authority.reserve_recovery('" + state['tenant'] + "','" + state['issuer'] + "','" + ng.OWNER + "'," + revision + ",1)")
    assert reserved.endswith(':recovering'), reserved
    rollback_epoch = int(reserved.split(':')[0]); assert rollback_epoch > old_epoch
    # A node that enrolled while the candidate ran and cannot report during a restore: its trust row is in the authority.
    ng.psql(sql="INSERT INTO blindpass_authority.broker_trust (tenant_id,issuer_key_id,node_id,key_version,signing_public,recipient_public,state,revision) VALUES ('"
                + state['tenant'] + "','" + state['issuer'] + "','" + node + "',1,'" + secrets.token_urlsafe(32)[:43] + "','" + secrets.token_urlsafe(32)[:43] + "','active',1)")
    shutil.move(str(ng.DATA), str(ng.ROOT / 'bad-release-data')); shutil.move(str(ng.KEYS), str(ng.ROOT / 'bad-release-keys'))
    stage_and_restore(keep_archive)
    place_restored()
    note('RB04', restored_session_rows=session_counts(), before_start='yes')
    (ng.DATA / 'backups').mkdir(mode=0o700); os.chown(ng.DATA / 'backups', user.pw_uid, user.pw_gid)
    shutil.copy2(keep_archive, ng.DATA / 'backups' / keep_archive.name)
    os.chown(ng.DATA / 'backups' / keep_archive.name, user.pw_uid, user.pw_gid); (ng.DATA / 'backups' / keep_archive.name).chmod(0o600)
    ng.run(['systemctl', 'reset-failed', ng.SERVICE]); ng.run(['systemctl', 'start', ng.SERVICE])
    for _ in range(120):
        if subprocess.run(['runuser', '-u', 'blindpass', '--', ng.BLINDPASS, 'admin', 'recovery', 'status', '--socket', ADMIN_SOCKET],
                          stdin=subprocess.DEVNULL, capture_output=True, timeout=60).returncode == 0: break
        time.sleep(.5)
    else:
        raise AssertionError('recovering controller did not answer on its admin socket')
    ng.never_ready(3)
    # Review: the controller's own listing of what the restored state quarantines.
    status = admin_json('recovery', 'status')
    assert status['activation_permitted'] is False and 'source_stop_missing' in status['gaps'], status
    items = admin_json('recovery', 'review', 'list')['items']
    categories = {}
    for item in items:
        categories[item['category']] = categories.get(item['category'], 0) + 1
    note('RB04', review_categories=json.dumps(categories, sort_keys=True), gaps=','.join(status['gaps']))
    admin('recovery', 'review', 'complete', '--operator', 'p07-operator', success=False)
    for category in sorted(categories):
        decision = {'operator': 'accept', 'operation': 'accept', 'workload': 'revoke'}.get(category, 'reject')
        admin_json('recovery', 'review', 'decide', '--category', category, '--decision', decision, '--operator', 'p07-operator', '--note', 'P07-E03 rollback rehearsal')
    admin('recovery', 'review', 'complete', '--operator', 'p07-operator', success=False)       # the node is still uncovered
    assert 'node_uncovered' in admin_json('recovery', 'status')['gaps']
    admin_json('recovery', 'waive-node', node, '--operator', 'p07-operator', '--note', 'no real node exists in the guest')
    admin_json('recovery', 'review', 'complete', '--operator', 'p07-operator')
    assert admin_json('recovery', 'status')['gaps'] == ['source_stop_missing']
    ng.run(['systemctl', 'stop', ng.SERVICE])
    attested = subprocess.run(['runuser', '-u', 'postgres', '--', 'psql', '-X', '-q', '-t', '-A', '-v', 'ON_ERROR_STOP=1', '-d', ng.AUTH_DB,
                               '-v', 'tenant=' + state['tenant'], '-v', 'owner=' + ng.OWNER, '-v', 'issuer=' + state['issuer'],
                               '-v', 'host=p07-rollback-host', '-v', 'by=p07-admin', '-v', 'note=candidate stopped and fenced',
                               '-f', str(ng.SQL / 'authority-recover-attest.sql')], stdin=subprocess.DEVNULL, capture_output=True, timeout=90)
    assert attested.returncode == 0, 'attestation refused although the candidate service is stopped'
    activated = subprocess.run(['runuser', '-u', 'postgres', '--', 'psql', '-X', '-q', '-t', '-A', '-v', 'ON_ERROR_STOP=1', '-d', ng.AUTH_DB,
                                '-v', 'tenant=' + state['tenant'], '-v', 'owner=' + ng.OWNER, '-v', 'issuer=' + state['issuer'],
                                '-f', str(ng.SQL / 'authority-recover-activate.sql')], stdin=subprocess.DEVNULL, capture_output=True, timeout=90)
    assert activated.returncode == 0 and 'activated recovery epoch' in activated.stdout.decode(), 'activation refused with every gate met'
    ng.run(['systemctl', 'reset-failed', ng.SERVICE]); ng.run(['systemctl', 'start', ng.SERVICE]); ng.ready()
    after = facts()
    note('RB04', ledger=after['ledger'], version=after['version'], exe=after['exe'], sessions=session_counts(),
         node_state=scalar("SELECT state FROM blindpass_authority.broker_trust WHERE tenant_id='" + state['tenant'] + "' AND node_id='" + node + "'"))
    ng.passed('RB04')

    # ------------------------------------------------------------------ RB05: what the rollback restored
    ng.case = 'RB05'
    same_keys = after['identity']['keys'] == before['identity']['keys'] and after['identity']['meta'][0][0] == before['identity']['meta'][0][0]
    observe('identity_restored', same_keys and after['issuer_on_disk'] == before['issuer_on_disk'] and after['issuer_ids'] == before['issuer_ids'],
            'keys_byte_identical=' + str(after['identity']['keys'] == before['identity']['keys']))
    lifecycle = (after['ledger'].startswith('active:' + str(rollback_epoch) + ':') and after['props'] == {**before['props']}
                 and ng.show('UnitFileState', ng.BACKUP_TIMER) == 'enabled')
    observe('lifecycle_integrity', lifecycle, 'ledger=' + after['ledger'] + ' props_equal=' + str(after['props'] == before['props']))
    observe('previous_program_version_restored', after['version'] == '0.1.0' and after['current'] == '0.1.0' and '/0.1.0/' in (after['exe'] or ''),
            'running=' + str(after['version']) + ' exe=' + str(after['exe']))
    observe('single_issuer', after['issuer_rows'] == 1 and after['holders_at_current'] <= 1 and ',' not in after['issuer_ids'],
            'issuer_rows=' + str(after['issuer_rows']) + ' holders_at_current=' + str(after['holders_at_current']))
    # The defective release's state cannot serve again: the ledger and the controller refuse it (stale source).
    ng.run(['systemctl', 'stop', ng.SERVICE])
    shutil.move(str(ng.DATA), str(ng.ROOT / 'rolled-back-data')); shutil.move(str(ng.KEYS), str(ng.ROOT / 'rolled-back-keys'))
    shutil.move(str(ng.ROOT / 'bad-release-data'), str(ng.DATA)); shutil.move(str(ng.ROOT / 'bad-release-keys'), str(ng.KEYS))
    ng.activate(); ng.failed_start()
    ng.run(['systemctl', 'stop', ng.SERVICE])
    shutil.move(str(ng.DATA), str(ng.ROOT / 'bad-release-data')); shutil.move(str(ng.KEYS), str(ng.ROOT / 'bad-release-keys'))
    shutil.move(str(ng.ROOT / 'rolled-back-data'), str(ng.DATA)); shutil.move(str(ng.ROOT / 'rolled-back-keys'), str(ng.KEYS))
    ng.run(['systemctl', 'reset-failed', ng.SERVICE]); ng.activate(); ng.run(['systemctl', 'start', ng.SERVICE]); ng.ready()
    observe('defective_release_state_refused', True, 'the candidate state is refused after the rollback epoch (start exited)')
    final = facts()
    assert final['issuer_rows'] == 1 and final['issuer_on_disk'] == before['issuer_on_disk']
    # Sessions: what the restored controller does with each.
    states = {'created_before_the_backup': session_status(previous_session), 'created_by_the_candidate': session_status(bad_session)}
    observe('candidate_session_gone_after_restore', states['created_by_the_candidate'] != 200, json.dumps(states, sort_keys=True))
    note('RB05', sessions_before_revoke=json.dumps(states, sort_keys=True), session_rows=session_counts())
    ng.passed('RB05')

    # ------------------------------------------------------------------ RB06: operator recovery and the documented revoke step
    ng.case = 'RB06'
    listed = admin_json('operators', 'list', '--json')
    assert 'rbadmin' in json.dumps(listed)
    status, _, live_session, _ = login('rbadmin', password, '192.0.2.20')
    note('RB06', login_with_previous_password=status)
    assert status == 200 and live_session, 'the administrator cannot sign in after the rollback'
    # Lock the account everywhere: more failures than the account-wide budget from six addresses.
    for index in range(54):
        failed, *_ = login('rbadmin', WRONG_PASSWORD, '198.51.100.' + str(index % 6 + 1))
        assert failed in (401, 423), failed
    locked, _, _, headers = login('rbadmin', password, '203.0.113.50')
    note('RB06', locked_answer=locked, retry_after_present=bool(headers.get('Retry-After')))
    assert locked == 423 and headers.get('Retry-After'), 'the account was not locked'
    shown = json.dumps(admin_json('operators', 'list', '--json'))
    assert 'account_locked_seconds' in shown
    reset = admin_json('reset-password', 'RBADMIN')                  # by username, any letter case
    temporary = reset['temporary_password']; secrets_seen.append(temporary)
    assert reset['must_change_password'] is True
    observe('revoke_step_revokes_existing_sessions', session_status(live_session) != 200 and session_status(previous_session) != 200,
            'live=' + str(session_status(live_session)) + ' before_backup=' + str(session_status(previous_session)))
    old, *_ = login('rbadmin', password, '203.0.113.50')
    status, body, temporary_session, _ = login('rbadmin', temporary, '203.0.113.50')
    assert old == 401 and status == 200 and body['must_change_password'] is True
    new_password = secrets.token_urlsafe(24); secrets_seen.append(new_password)
    status, _, _ = http('POST', '/api/v3/admin/session/change-password', {'current_password': temporary, 'new_password': new_password},
                        {'origin': ORIGIN, 'cookie': 'bp_session=' + temporary_session + '; bp_csrf=' + body['csrf_token'], 'x-csrf-token': body['csrf_token']})
    assert status in (200, 204), 'forced password change answered ' + str(status)
    final_login, *_ = login('rbadmin', new_password, '203.0.113.51')
    observe('operator_recovery_after_lockout', locked == 423 and old == 401 and final_login == 200,
            'locked=' + str(locked) + ' old_password=' + str(old) + ' after_change=' + str(final_login))
    note('RB06', node_trust_after_rollback=scalar("SELECT state FROM blindpass_authority.broker_trust WHERE tenant_id='" + state['tenant'] + "' AND node_id='" + node + "'"))
    ng.passed('RB06')

    # ------------------------------------------------------------------ RB07: nothing secret reached the journal
    ng.case = 'RB07'
    journal = ng.run(['journalctl', '-u', ng.SERVICE, '-o', 'cat', '--no-pager'])
    canary_log_scan.assert_log_clean('P07-RB07 controller journal', journal, secrets_seen + [ng.OFFLINE_KEY.read_text()],
                                     markers=['PRIVATE KEY-----'], min_bytes=32)
    for leftover in ('bad-release-data', 'bad-release-keys'):
        shutil.rmtree(ng.ROOT / leftover, ignore_errors=True)
    shutil.rmtree(RESTORE_STATE, ignore_errors=True)
    ng.passed('RB07')

    # ------------------------------------------------------------------ RB08: probe, the only route that returns the previous binaries
    # Informational: after the required observations. The installer refuses to reinstall an older artifact over an
    # installation (RB03), so the one route left is to purge, install the previous archive fresh and restore into it.
    # This probes how far that goes with the shipped tools; it is not part of the pass condition.
    ng.case = 'RB08'
    step = 'stop'
    try:
        ng.run(['systemctl', 'stop', ng.SERVICE])
        step = 'purge'
        ng.run(['python3', candidate / 'deploy/native/controller-install.py', '--uninstall', '--purge', '--confirm-purge', 'blindpass-controller'])
        step = 'fresh install of the previous archive'
        ng.install('--public-url', ORIGIN, '--authority-url-file', ng.AUTH_URL, '--tenant-id', state['tenant'], '--owner-id', ng.OWNER,
                   '--tls-cert', ng.CERT, '--tls-key', ng.KEY)
        assert json.loads(MARKER.read_text())['version'] == '0.1.0'
        step = 'reserve the recovery epoch'
        ng.fence()
        revision = scalar("SELECT revision FROM blindpass_authority.recovery_authority WHERE tenant_id='" + state['tenant'] + "'")
        assert scalar("SELECT phase FROM blindpass_authority.reserve_recovery('" + state['tenant'] + "','" + state['issuer'] + "','" + ng.OWNER + "'," + revision + ",1)") == 'recovering'
        step = 'restore with the previous release restore unit'
        stage_and_restore(keep_archive)
        step = 'place the restored state'
        shutil.rmtree(ng.KEYS); shutil.rmtree(ng.DATA)       # the installer created both, empty and private
        place_restored()
        step = 'start the previous release'
        subprocess.run(['systemctl', 'start', ng.SERVICE], stdin=subprocess.DEVNULL, capture_output=True, timeout=60)
        condition, state_now = ng.show('ConditionResult'), ng.show('ActiveState')
        refusals = {name: ng.install(*flags, success=False, capture_stderr=True, bundle=bundle).strip().splitlines()[-1][:140]
                    for name, flags, bundle in [('start', ['--start'], ng.BUNDLE), ('initialize', ['--initialize'], ng.BUNDLE), ('upgrade', ['--upgrade'], candidate)]}
        recorded = json.loads(MARKER.read_text())
        note('RB08', previous_version_installed=recorded['version'], restored_state_in_place='yes', service_start_condition_result=condition,
             service_state=state_now, installer_record_initialized=recorded['initialized'], installer_refusals=json.dumps(refusals, sort_keys=True))
        observe('previous_release_reachable_by_purge_and_restore_with_shipped_tools', condition == 'yes' and recorded['initialized'] is True,
                'the restored installation is not initialized as far as the installer and the unit are concerned')
    except Exception as error:      # a probe: whatever stops it is the finding, and the required observations are already printed
        detail = {}
        if step.startswith('restore'):
            detail = {'restore_unit_condition_result': ng.show('ConditionResult', ng.RESTORE_UNIT), 'restore_unit_state': ng.show('ActiveState', ng.RESTORE_UNIT)}
        note('RB08', stopped_at=step.replace(' ', '_'), error=type(error).__name__, marker_initialized=json.loads(MARKER.read_text()).get('initialized'),
             initialized_file_present=Path('/etc/blindpass/controller-initialized').exists(), **detail)
        observe('previous_release_reachable_by_purge_and_restore_with_shipped_tools', False, 'stopped at step: ' + step)
    shutil.rmtree(candidate, ignore_errors=True)

    required = ['previous_program_version_restored', 'identity_restored', 'lifecycle_integrity', 'candidate_session_gone_after_restore',
                'operator_recovery_after_lockout', 'single_issuer', 'software_reinstall_alone_revokes_no_credentials',
                'revoke_step_revokes_existing_sessions', 'revoke_step_revokes_sessions_after_software_rollback', 'defective_release_state_refused']
    missing = [name for name in required if not OBSERVATIONS.get(name)]
    print('P07-E03 summary ' + json.dumps({name: OBSERVATIONS.get(name) for name in required}, sort_keys=True), flush=True)
    print('P07-E03 ' + ('PASS: every required observation was made' if not missing else 'NOT PASSED: ' + ','.join(missing)), flush=True)
    return missing
