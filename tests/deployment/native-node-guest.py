#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""P06-NN, inside the disposable CONTROLLER guest only: the packaged native controller serving a
real node that runs in a second guest. tests/fleet/p06-native-node-vm.py drives it stage by stage
over SSH; every stage prints a fixed `P06-NN-RESULT {json}` line and never a secret.

It reuses the helpers of native-guest.py (the guest's own PostgreSQL stands in for the recovery
authority; it is NOT independent of the controller host)."""
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shutil
import sqlite3
import subprocess
import sys
import time

_spec = importlib.util.spec_from_file_location('native_guest', '/root/p06-native/native-guest.py')
ng = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ng)

CA = ng.PRIVATE/'ca.pem'
LEAF_CERT, LEAF_KEY = ng.CERT, ng.KEY
ng.CERT = CA   # ng.get() verifies the listener against the test CA
RESTORE_STATE = Path('/var/lib/blindpass/controller-restore')
RESTORE_ROOT = RESTORE_STATE/'root'
SOURCE_DATA = Path('/var/lib/blindpass/p06-source-data')
SOURCE_KEYS = Path('/etc/blindpass/p06-source-keys')
PARK = ng.ROOT/'parked-restored'
STATE = ng.ROOT/'nn-state.json'
ADMIN_SOCKET = '/run/blindpass-controller/admin.sock'
STALE_UNIT = 'p06-stale-source.service'
STALE_ENV = Path('/etc/blindpass/p06-stale-source.env')
KEY_NAMES = ['root-secret', 'agent-jwt-secret', 'issuer-key']


def result(**values):
    print('P06-NN-RESULT '+json.dumps(values, sort_keys=True), flush=True)


def scalar(sql):
    return ng.psql(sql=sql).strip()


def ledger():
    state = ng.authority_state()
    return scalar("SELECT phase||':'||epoch||':'||revision FROM blindpass_authority.recovery_authority WHERE tenant_id='"+state['tenant']+"'")


def key_hashes(directory):
    return {name: hashlib.sha256((directory/name).read_bytes()).hexdigest() for name in KEY_NAMES}


def saved():
    return json.loads(STATE.read_text())


def save(**values):
    current = json.loads(STATE.read_text()) if STATE.exists() else {}
    current.update(values)
    STATE.write_text(json.dumps(current)); STATE.chmod(0o600)


def reasons_since(unit, since):
    """Fixed startup-failure reasons the controller logged for `unit` (JSON log lines only)."""
    text = subprocess.run(['journalctl', '-u', unit, '-o', 'cat', '--no-pager', '--since', '@'+str(int(since))],
                          stdin=subprocess.DEVNULL, capture_output=True, timeout=60).stdout.decode(errors='replace')
    found = re.findall(r'"startup_failed"[^\n]*?"reason":"([a-z_]+)"', text) or re.findall(r'"reason":"([a-z_]+)"', text)
    return found


def setup(public_url):
    ng.case = 'NN00'
    assert os.getuid() == 0 and Path('/run/systemd/system').is_dir()
    assert not ng.DATA.exists() and not ng.KEYS.exists()
    ng.PRIVATE.mkdir(mode=0o700)
    staged = Path('/tmp/p06-nn')
    for name, target in (('leaf.pem', LEAF_CERT), ('leaf.key', LEAF_KEY), ('ca.pem', CA)):
        shutil.copyfile(staged/name, target); target.chmod(0o600)
    shutil.rmtree(staged)
    ng.authority_setup()
    ng.install('--verify-only')
    first = json.loads(ng.install('--public-url', public_url, *ng.AUTH_ARGS, '--initialize-keys',
                                  '--tls-cert', LEAF_CERT, '--tls-key', LEAF_KEY))
    assert first['keys_initialized'] is True and first['issuer_key_id'].startswith('ed25519-')
    ng.register(first['issuer_key_id'])
    # Documented operator step for a remote direct-TLS deployment (native-quickstart.md): the installer
    # starts on loopback; the operator edits the protected config. Nothing else is changed.
    text = ng.CONFIG.read_text()
    assert 'BLINDPASS_LISTEN=127.0.0.1:3200\n' in text
    ng.CONFIG.write_text(text.replace('BLINDPASS_LISTEN=127.0.0.1:3200\n', 'BLINDPASS_LISTEN=0.0.0.0:3200\n'))
    assert json.loads(ng.install('--initialize'))['initialized'] is True
    ng.unready_start_refused(ng.install('--start', success=False, capture_stderr=True)); ng.never_ready(3)
    ng.run(['systemctl', 'stop', ng.SERVICE]); ng.activate(); ng.run(['systemctl', 'start', ng.SERVICE])
    ng.ready()
    listening = ng.run(['ss', '-Htln', 'sport = :3200']).split()
    assert any(value == '0.0.0.0:3200' for value in listening), 'the controller does not listen on all interfaces'
    # Backup custody exactly as the native lifecycle: signing credential and recipient certificate on the
    # host; the recipient private key and the signer certificate stay in PRIVATE.
    signing_private = ng.PRIVATE/'backup-signing.pem'; recipient_certificate = ng.PRIVATE/'backup-recipient-certificate.pem'
    ng.run([ng.BLINDPASS, 'backup', 'key-init', '--role', 'signing', '--output', signing_private, '--certificate-output', ng.OFFLINE_SIGNER])
    ng.run([ng.BLINDPASS, 'backup', 'key-init', '--role', 'recipient', '--output', ng.OFFLINE_KEY, '--certificate-output', recipient_certificate])
    for source, target in ((signing_private, ng.SIGNING), (recipient_certificate, ng.RECIPIENT)):
        ng.run(['sh', '-c', 'umask 077; set -C; cat "$1" > "$2"', 'p06-copy', source, target])
    with os.fdopen(os.open(ng.BACKUP_ENABLED, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb'):
        pass
    save(original_keys=key_hashes(ng.KEYS))
    ng.passed('NN00')
    result(issuer=first['issuer_key_id'], listen='0.0.0.0:3200', ledger=ledger())


def backup():
    ng.case = 'NN-backup'
    assert ng.show('ActiveState') == 'active'
    known = set((ng.DATA/'backups').glob('*.bpbackup'))
    started = time.monotonic()
    ng.run(['systemctl', 'start', ng.BACKUP])
    elapsed = time.monotonic()-started
    assert ng.show('Result', ng.BACKUP) == 'success'
    fresh = sorted(set((ng.DATA/'backups').glob('*.bpbackup'))-known)
    assert len(fresh) == 1, 'the backup unit did not publish exactly one new archive'
    archive = fresh[0]
    ng.backup_verify(archive)
    ng.backup_verify(archive, ng.SIGNING, success=False)   # the host's own signing credential never opens it
    user = pwd.getpwnam('blindpass')
    RESTORE_STATE.mkdir(mode=0o700); os.chown(RESTORE_STATE, user.pw_uid, user.pw_gid)
    (RESTORE_STATE/'archives').mkdir(mode=0o700); os.chown(RESTORE_STATE/'archives', user.pw_uid, user.pw_gid)
    target = RESTORE_STATE/'archives'/archive.name
    shutil.copy2(archive, target); os.chown(target, user.pw_uid, user.pw_gid); target.chmod(0o600)
    keep = ng.ROOT/'recovered-archive.bpbackup'; shutil.copy2(archive, keep); keep.chmod(0o600)
    save(archive=archive.name)
    ng.ready()   # the controller kept serving through the packaged backup job
    ng.passed('NN-backup')
    result(archive=archive.name, bytes=archive.stat().st_size, seconds=round(elapsed, 3))


def lose():
    """Fence in the authority, stop, reserve recovery and park the source's state (kept byte-intact)."""
    ng.case = 'NN-fence'
    state = ng.authority_state()
    ng.run(['systemctl', 'stop', ng.SERVICE])
    ng.fence()
    fenced = ledger()
    revision = scalar("SELECT revision FROM blindpass_authority.recovery_authority WHERE tenant_id='"+state['tenant']+"'")
    reserved = scalar("SELECT epoch||':'||phase FROM blindpass_authority.reserve_recovery('"+state['tenant']+"','"+state['issuer']+"','"+ng.OWNER+"',"+revision+",1)")
    assert reserved.endswith(':recovering'), reserved
    db_hash = hashlib.sha256((ng.DATA/'controller.db').read_bytes()).hexdigest()
    shutil.move(str(ng.DATA), str(SOURCE_DATA)); shutil.move(str(ng.KEYS), str(SOURCE_KEYS))
    save(epoch=int(reserved.split(':')[0]), source_db_sha256=db_hash)
    ng.passed('NN-fence')
    result(epoch=int(reserved.split(':')[0]), fenced_ledger=fenced, ledger=ledger())


def restore_unit(recovery_id, key=None, signer=None, success=True):
    """Run the shipped blindpass-controller-restore.service with the operator's offline custody."""
    if RESTORE_ROOT.exists():
        shutil.rmtree(RESTORE_ROOT)
    custody = Path('/etc/blindpass/controller-restore'); arguments = Path('/etc/blindpass/controller-restore.env')
    custody.mkdir(mode=0o700, exist_ok=True)
    for name, source in (('recipient-key', key or ng.OFFLINE_KEY), ('signing-certificate', signer or ng.OFFLINE_SIGNER)):
        shutil.copy2(source, custody/name); (custody/name).chmod(0o600)
    state = ng.authority_state()
    arguments.write_text(''.join(name+'='+value+'\n' for name, value in {
        'BLINDPASS_RESTORE_ARCHIVE': str(RESTORE_STATE/'archives'/saved()['archive']), 'BLINDPASS_RESTORE_DESTINATION': str(RESTORE_ROOT),
        'BLINDPASS_RESTORE_TENANT_ID': state['tenant'], 'BLINDPASS_RESTORE_OWNER_ID': ng.OWNER,
        'BLINDPASS_RESTORE_RECOVERY_ID': recovery_id}.items()))
    arguments.chmod(0o600)
    try:
        subprocess.run(['systemctl', 'reset-failed', ng.RESTORE_UNIT], stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
        ng.run(['systemctl', 'start', ng.RESTORE_UNIT], success)
        assert ng.show('Result', ng.RESTORE_UNIT) == ('success' if success else 'exit-code'), 'unexpected restore unit result'
    finally:
        shutil.rmtree(custody, ignore_errors=True); arguments.unlink(missing_ok=True)
        subprocess.run(['systemctl', 'reset-failed', ng.RESTORE_UNIT], stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
    assert not Path('/run/credentials/'+ng.RESTORE_UNIT).exists(), 'restore credential copy outlived the unit'
    assert not Path('/run/blindpass-controller-restore').exists(), 'restore staging outlived the unit'
    return json.loads((RESTORE_ROOT/'restore.json').read_text()) if success else None


def wait_recovering():
    for _ in range(120):
        if subprocess.run(['runuser', '-u', 'blindpass', '--', ng.BLINDPASS, 'admin', 'recovery', 'status', '--socket', ADMIN_SOCKET],
                          stdin=subprocess.DEVNULL, capture_output=True, timeout=60).returncode == 0:
            return
        time.sleep(.5)
    raise AssertionError('recovering controller did not answer on its admin socket')


def restore():
    ng.case = 'NN-restore'
    assert not ng.DATA.exists() and not ng.KEYS.exists(), 'the source state was not parked'
    # Host custody (signing credential as the recipient key) cannot open the archive; nothing is published.
    restore_unit('p06nn'+secrets.token_hex(3), key=ng.SIGNING, success=False)
    assert not RESTORE_ROOT.exists() or not any(RESTORE_ROOT.iterdir()), 'a refused restore left state behind'
    # The unit never runs on its own: without the operator's arguments file and offline custody it is skipped.
    subprocess.run(['systemctl', 'reset-failed', ng.RESTORE_UNIT], stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
    ng.run(['systemctl', 'start', ng.RESTORE_UNIT])
    assert ng.show('ConditionResult', ng.RESTORE_UNIT) == 'no' and ng.show('ActiveState', ng.RESTORE_UNIT) == 'inactive'
    assert not RESTORE_ROOT.exists(), 'restore published state without operator input'
    receipt = restore_unit('p06nn'+secrets.token_hex(3))
    assert receipt['phase'] == 'recovery_required' and receipt['activation_permitted'] is False and receipt['backend'] == 'sqlite', receipt
    user = pwd.getpwnam('blindpass')
    for source, target in ((RESTORE_ROOT/'keys', ng.KEYS), (RESTORE_ROOT/'data', ng.DATA)):
        ng.run(['cp', '-a', source, target])
        for path in [target, *target.rglob('*')]:
            os.chown(path, user.pw_uid, user.pw_gid, follow_symlinks=False)
        target.chmod(0o700)
    shutil.rmtree(RESTORE_ROOT)
    (ng.DATA/'backups').mkdir(mode=0o700); os.chown(ng.DATA/'backups', user.pw_uid, user.pw_gid)
    kept = ng.DATA/'backups'/saved()['archive']
    shutil.copy2(ng.ROOT/'recovered-archive.bpbackup', kept); os.chown(kept, user.pw_uid, user.pw_gid); kept.chmod(0o600)
    identical = key_hashes(ng.KEYS) == saved()['original_keys']
    assert identical, 'restored keys differ from the source keys'
    ng.run(['systemctl', 'reset-failed', ng.SERVICE])
    ng.run(['systemctl', 'start', ng.SERVICE]); wait_recovering(); ng.never_ready(3)
    ng.passed('NN-restore')
    result(receipt_phase=receipt['phase'], keys_identical=identical, ledger=ledger())


def serve():
    """Start the (activated) controller and report when it answered ready, by this guest's clock."""
    ng.case = 'NN-serve'
    subprocess.run(['systemctl', 'reset-failed', ng.SERVICE], stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
    started_ms = int(time.time()*1000); started = time.monotonic()
    ng.run(['systemctl', 'start', ng.SERVICE]); ng.ready()
    result(started_ms=started_ms, ready_seconds=round(time.monotonic()-started, 3), ledger=ledger())


def activate_serve():
    """Ordinary re-activation (P06-D12: one activation per start) and start; used after a deliberate stop."""
    ng.case = 'NN-serve'
    ng.run(['systemctl', 'stop', ng.SERVICE])
    ng.activate()
    serve()


def stale_transient():
    """Start the ORIGINAL state as a second instance of the packaged unit while the restored controller serves."""
    ng.case = 'NN-stale'
    ng.ready()
    before = ledger()
    text = ng.run(['systemctl', 'cat', ng.SERVICE])
    unit = '\n'.join(line for line in text.splitlines() if not re.match(r'^# /', line))+'\n'
    for old, new in [('ReadOnlyPaths=/etc/blindpass/keys', 'ReadOnlyPaths='+str(SOURCE_KEYS)),
                     ('/etc/blindpass/keys/', str(SOURCE_KEYS)+'/'),
                     ('StateDirectory=blindpass/controller', 'StateDirectory=blindpass/p06-source-data'),
                     ('ReadWritePaths=/var/lib/blindpass/controller /run/blindpass-controller',
                      'ReadWritePaths=/var/lib/blindpass/p06-source-data /run/p06-stale-source'),
                     ('RuntimeDirectory=blindpass-controller', 'RuntimeDirectory=p06-stale-source'),
                     ('EnvironmentFile=/etc/blindpass/controller.env', 'EnvironmentFile='+str(STALE_ENV))]:
        assert old in unit, 'the packaged unit no longer contains '+old
        unit = unit.replace(old, new)
    env = ng.CONFIG.read_text()
    for old, new in [('BLINDPASS_LISTEN=0.0.0.0:3200', 'BLINDPASS_LISTEN=127.0.0.1:3201'),
                     ('BLINDPASS_KEYS_DIR='+str(ng.KEYS), 'BLINDPASS_KEYS_DIR='+str(SOURCE_KEYS)),
                     ('BLINDPASS_DATA_DIR='+str(ng.DATA), 'BLINDPASS_DATA_DIR='+str(SOURCE_DATA)),
                     ('BLINDPASS_ADMIN_SOCKET_PATH=/run/blindpass-controller/admin.sock', 'BLINDPASS_ADMIN_SOCKET_PATH=/run/p06-stale-source/admin.sock')]:
        assert old in env, 'the controller config no longer contains '+old.split('=')[0]
        env = env.replace(old, new)
    gid = pwd.getpwnam('blindpass').pw_gid
    STALE_ENV.write_text(env); os.chown(STALE_ENV, 0, gid); STALE_ENV.chmod(0o640)
    unit_path = Path('/etc/systemd/system/'+STALE_UNIT)
    unit_path.write_text(unit)
    since = time.time()
    try:
        ng.run(['systemctl', 'daemon-reload'])
        subprocess.run(['systemctl', 'start', STALE_UNIT], stdin=subprocess.DEVNULL, capture_output=True, timeout=60)
        for _ in range(100):
            state = ng.show('ActiveState', STALE_UNIT)
            if state in ('failed', 'inactive'):
                break
            time.sleep(.2)
        else:
            raise AssertionError('the original state is still running as a second instance')
        failing = [ng.show('Result', STALE_UNIT), ng.show('ExecMainStatus', STALE_UNIT)]
        reasons = reasons_since(STALE_UNIT, since)
        listening = ng.run(['ss', '-Htln', 'sport = :3201']).strip()
        assert not listening, 'the original state bound a listener'
        assert ng.get('/readyz')[0] == 200, 'the restored controller stopped serving'
    finally:
        subprocess.run(['systemctl', 'stop', STALE_UNIT], stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
        subprocess.run(['systemctl', 'reset-failed', STALE_UNIT], stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
        unit_path.unlink(missing_ok=True); STALE_ENV.unlink(missing_ok=True)
        subprocess.run(['systemctl', 'daemon-reload'], stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
    ng.ready()
    assert ledger() == before, 'the second instance changed the authority record'
    ng.passed('NN-stale-transient')
    result(unit_result=failing[0], exit_status=failing[1], reasons=reasons, ledger=before)


def stale_swap():
    """Stop the restored controller, put the ORIGINAL state into the service paths, grant it an ordinary
    activation and start: the state itself must be refused. Then put the restored state back."""
    ng.case = 'NN-stale'
    ng.run(['systemctl', 'stop', ng.SERVICE])
    PARK.mkdir(mode=0o700)
    shutil.move(str(ng.DATA), str(PARK/'data')); shutil.move(str(ng.KEYS), str(PARK/'keys'))
    shutil.move(str(SOURCE_DATA), str(ng.DATA)); shutil.move(str(SOURCE_KEYS), str(ng.KEYS))
    since = time.time()
    ng.activate()
    ng.failed_start()
    reasons = reasons_since(ng.SERVICE, since)
    ng.run(['systemctl', 'stop', ng.SERVICE])
    unchanged = hashlib.sha256((ng.DATA/'controller.db').read_bytes()).hexdigest() == saved()['source_db_sha256']
    shutil.move(str(ng.DATA), str(SOURCE_DATA)); shutil.move(str(ng.KEYS), str(SOURCE_KEYS))
    shutil.move(str(PARK/'data'), str(ng.DATA)); shutil.move(str(PARK/'keys'), str(ng.KEYS))
    PARK.rmdir()
    ng.passed('NN-stale-swap')
    result(reasons=reasons, source_db_unchanged=unchanged, ledger=ledger())


def rows():
    """Read-only SQLite query for the host harness: stdin is {"sql": ..., "params": [...]}."""
    request = json.loads(sys.stdin.read())
    with sqlite3.connect('file:'+str(ng.DATA/'controller.db')+'?mode=ro', uri=True) as connection:
        print(json.dumps(connection.execute(request['sql'], request['params']).fetchall()))


def cli(*args):
    completed = subprocess.run(['runuser', '-u', 'blindpass', '--', ng.BLINDPASS, 'admin', 'recovery', *args, '--socket', ADMIN_SOCKET],
                               stdin=subprocess.DEVNULL, capture_output=True, timeout=120)
    sys.stdout.buffer.write(completed.stdout); sys.stderr.buffer.write(completed.stderr)
    sys.exit(completed.returncode)


def script(name, *assignments):
    ng.wait_authority()
    state = ng.authority_state()
    variables = {'tenant': state['tenant'], 'owner': ng.OWNER, 'issuer': state['issuer']}
    variables.update(dict(item.split('=', 1) for item in assignments))
    completed = subprocess.run(['runuser', '-u', 'postgres', '--', 'psql', '-X', '-q', '-t', '-A', '-v', 'ON_ERROR_STOP=1', '-d', ng.AUTH_DB,
                                *[arg for key, value in variables.items() for arg in ('-v', key+'='+value)], '-f', str(ng.SQL/name)],
                               stdin=subprocess.DEVNULL, capture_output=True, timeout=90)
    sys.stdout.buffer.write(completed.stdout); sys.stderr.buffer.write(completed.stderr)
    sys.exit(completed.returncode)


def sql():
    ng.wait_authority()
    completed = subprocess.run(['runuser', '-u', 'postgres', '--', 'psql', '-X', '-q', '-t', '-A', '-v', 'ON_ERROR_STOP=1', '-d', ng.AUTH_DB, '-f', '-'],
                               input=sys.stdin.buffer.read(), capture_output=True, timeout=90)
    sys.stdout.buffer.write(completed.stdout); sys.stderr.buffer.write(completed.stderr)
    sys.exit(completed.returncode)


def scan():
    """Stdin: a JSON list of canary strings. Prints counts only."""
    canaries = json.loads(sys.stdin.read())
    canaries.append((ng.ROOT/'authority-password').read_text())
    assert len(canaries) >= 4 and all(len(value) >= 12 for value in canaries), 'the scan has no canaries to look for'
    units = [ng.SERVICE, ng.BACKUP, ng.RESTORE_UNIT, STALE_UNIT, 'blindpass-controller-initialize.service']
    journal = subprocess.run(['journalctl', *[arg for unit in units for arg in ('-u', unit)], '-o', 'cat', '--no-pager'],
                             stdin=subprocess.DEVNULL, capture_output=True, timeout=120).stdout.decode(errors='replace')
    try:
        ng.canary_log_scan.assert_log_clean('P06-NN controller guest journal', journal, canaries, markers=['PRIVATE KEY-----'], min_bytes=256)
    except ng.canary_log_scan.LogScanError as error:
        print('P06-NN FAIL scan: ' + str(error), flush=True)
        sys.exit(1)
    hits = sum(journal.count(value) for value in canaries)
    pem = journal.count('PRIVATE KEY-----')
    result(canaries=len(canaries), journal_bytes=len(journal), hits=hits, pem_private_keys=pem)
    sys.exit(0 if hits == 0 and pem == 0 else 1)


LOOP_IMAGE = Path('/var/lib/blindpass/p06-data.img')


def loop_data():
    """Move the controller's data directory onto its own small ext4 filesystem (a loop mount), as an operator
    would give it a dedicated volume. The recovery authority's PostgreSQL stays on the root filesystem, like the
    separate authority host of a production layout, so filling the data volume cannot also stop the authority."""
    ng.case = 'NN-loop'
    ng.run(['systemctl', 'stop', ng.SERVICE])
    original = os.stat(ng.DATA)
    staging = ng.ROOT/'loop-staging'
    staging.mkdir(exist_ok=True)
    LOOP_IMAGE.unlink(missing_ok=True)
    ng.run(['truncate', '-s', '96M', LOOP_IMAGE])
    ng.run(['mkfs.ext4', '-q', '-m', '0', LOOP_IMAGE])
    ng.run(['mount', '-o', 'loop', LOOP_IMAGE, staging])
    ng.run(['cp', '-a', str(ng.DATA)+'/.', staging])
    os.chown(staging, original.st_uid, original.st_gid); os.chmod(staging, original.st_mode & 0o7777)
    ng.run(['umount', staging])
    ng.run(['mount', '-o', 'loop', LOOP_IMAGE, ng.DATA])
    mounted = subprocess.run(['findmnt', '-n', '-o', 'SOURCE,FSTYPE', str(ng.DATA)], stdin=subprocess.DEVNULL, capture_output=True, timeout=30).stdout.decode().split()
    assert mounted and mounted[-1] == 'ext4', 'the data directory is not on its own filesystem'
    assert (ng.DATA/'controller.db').exists(), 'the database did not move with the data directory'
    stat = os.statvfs(ng.DATA)
    result(filesystem=mounted[-1], size_bytes=stat.f_blocks*stat.f_frsize)


FILL = ng.DATA/'p06-disk-fill.bin'


def fill_disk():
    """Take every free block of the controller's data filesystem, including the root reserve, so the
    unprivileged service user cannot write. Prints the remaining space for that user."""
    ng.case = 'NN-fill'
    FILL.unlink(missing_ok=True)
    stat = os.statvfs(ng.DATA)
    # Allocating every free block can itself fail on the last metadata block; a partial fill is enough
    # as long as the service user is then unable to write (asserted below).
    subprocess.run(['fallocate', '-l', str((stat.f_bfree-64)*stat.f_frsize), str(FILL)], stdin=subprocess.DEVNULL, capture_output=True, timeout=90)
    subprocess.run(['sh', '-c', 'cat /dev/zero >> '+str(FILL)], stdin=subprocess.DEVNULL, capture_output=True, timeout=90)
    os.sync()
    left = os.statvfs(ng.DATA)
    probe = subprocess.run(['runuser', '-u', 'blindpass', '--', 'sh', '-c', 'head -c 1048576 /dev/zero > '+str(ng.DATA/'p06-space-probe')],
                           stdin=subprocess.DEVNULL, capture_output=True, timeout=60)
    (ng.DATA/'p06-space-probe').unlink(missing_ok=True)
    assert probe.returncode != 0, 'the service user can still write after the fill'
    result(available_bytes=left.f_bavail*left.f_frsize, journal_since_ms=int(time.time()*1000))


def free_disk():
    ng.case = 'NN-free'
    FILL.unlink(missing_ok=True)
    os.sync()
    left = os.statvfs(ng.DATA)
    result(available_bytes=left.f_bavail*left.f_frsize)


def fault_state():
    """Service identity and database health, for comparing before and after a fault. The integrity
    check opens a private copy so it cannot write to the live WAL database."""
    ng.case = 'NN-state'
    shown = dict(line.split('=', 1) for line in subprocess.run(
        ['systemctl', 'show', ng.SERVICE, '-p', 'MainPID', '-p', 'NRestarts', '-p', 'InvocationID', '-p', 'ActiveState'],
        stdin=subprocess.DEVNULL, capture_output=True, timeout=30).stdout.decode().splitlines())
    copy = ng.ROOT/'integrity-copy.db'
    with sqlite3.connect('file:'+str(ng.DATA/'controller.db')+'?mode=ro', uri=True) as live, sqlite3.connect(copy) as target:
        live.backup(target)
    with sqlite3.connect(copy) as connection:
        integrity = connection.execute('PRAGMA integrity_check').fetchall()
        sessions = connection.execute('SELECT COUNT(*) FROM controller_meta').fetchone()[0]
    copy.unlink()
    result(main_pid=shown['MainPID'], restarts=shown['NRestarts'], invocation=shown['InvocationID'], active=shown['ActiveState'],
           integrity=integrity[0][0] if len(integrity) == 1 else 'multiple', meta_rows=sessions)


def backup_state():
    """Archives and residue under the controller's backup directory, for before/after comparison."""
    ng.case = 'NN-backup-state'
    archives = sorted(path.name for path in (ng.DATA/'backups').glob('*.bpbackup'))
    residue = sorted(path.name for root in (ng.DATA, ng.DATA/'backups') for path in root.iterdir() if path.name.startswith('.backup-'))
    result(archives=archives, residue=residue)


def backup_attempt():
    """Start the packaged backup unit and report how it ended; nothing is asserted here."""
    ng.case = 'NN-backup-attempt'
    subprocess.run(['systemctl', 'reset-failed', ng.BACKUP], stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
    started = time.monotonic()
    done = subprocess.run(['systemctl', 'start', ng.BACKUP], stdin=subprocess.DEVNULL, capture_output=True, timeout=900)
    elapsed = time.monotonic()-started
    journal = subprocess.run(['journalctl', '-u', ng.BACKUP, '-o', 'cat', '--no-pager', '--since', '@'+str(int(time.time()-elapsed-5))],
                             stdin=subprocess.DEVNULL, capture_output=True, timeout=60).stdout.decode(errors='replace')
    lines = sorted({line[:160] for line in journal.splitlines() if line.startswith('blindpass') and 'PRIVATE KEY' not in line})
    backups = sorted(path.name for path in (ng.DATA/'backups').glob('*.bpbackup'))
    verified = None
    if done.returncode == 0 and backups:
        try:
            ng.backup_verify(ng.DATA/'backups'/backups[-1]); verified = True
        except Exception:
            verified = False
    result(start_exit=done.returncode, unit_result=ng.show('Result', ng.BACKUP), exit_status=ng.show('ExecMainStatus', ng.BACKUP),
           seconds=round(elapsed, 2), verified=verified, messages=lines[:6], secret_in_journal=('PRIVATE KEY' in journal or ng.OFFLINE_KEY.read_text() in journal))


JOURNAL_IMAGE = Path('/var/lib/blindpass/p06-journal.img')
JOURNAL_DIR = Path('/var/log/journal')
JOURNAL_FILL = JOURNAL_DIR/'p06-journal-fill.bin'


def loop_journal():
    """Give the persistent journal its own small ext4 volume so it can be filled without touching the root filesystem."""
    ng.case = 'NN-loop-journal'
    JOURNAL_DIR.mkdir(exist_ok=True)
    JOURNAL_IMAGE.unlink(missing_ok=True)
    ng.run(['truncate', '-s', '48M', JOURNAL_IMAGE])
    ng.run(['mkfs.ext4', '-q', '-m', '0', JOURNAL_IMAGE])
    ng.run(['mount', '-o', 'loop', JOURNAL_IMAGE, JOURNAL_DIR])
    os.chmod(JOURNAL_DIR, 0o2755); shutil.chown(JOURNAL_DIR, 'root', 'systemd-journal')
    # A restart (not stop and start) keeps the services' stdout streams to journald alive.
    ng.run(['systemctl', 'restart', 'systemd-journald.service'])
    ng.run(['journalctl', '--flush'])
    subprocess.run(['logger', '-t', 'p06-journal', 'journal-volume-ready'], stdin=subprocess.DEVNULL, timeout=30)
    time.sleep(1); ng.run(['journalctl', '--sync'])
    seen = subprocess.run(['journalctl', '-t', 'p06-journal', '-o', 'cat', '--no-pager'], stdin=subprocess.DEVNULL, capture_output=True, timeout=30).stdout.decode()
    assert 'journal-volume-ready' in seen, 'the journal did not start on its own volume'
    result(size_bytes=os.statvfs(JOURNAL_DIR).f_blocks*os.statvfs(JOURNAL_DIR).f_frsize)


def fill_journal():
    ng.case = 'NN-fill-journal'
    JOURNAL_FILL.unlink(missing_ok=True)
    subprocess.run(['sh', '-c', 'cat /dev/zero > '+str(JOURNAL_FILL)], stdin=subprocess.DEVNULL, capture_output=True, timeout=120)
    os.sync()
    free = os.statvfs(JOURNAL_DIR).f_bavail*os.statvfs(JOURNAL_DIR).f_frsize
    assert free < 65536, 'the journal volume is not full'
    for index in range(5):
        subprocess.run(['logger', '-t', 'p06-journal', 'during-full-%d' % index], stdin=subprocess.DEVNULL, timeout=30)
    result(free_bytes=free)


def free_journal():
    ng.case = 'NN-free-journal'
    JOURNAL_FILL.unlink(missing_ok=True)
    os.sync()
    subprocess.run(['logger', '-t', 'p06-journal', 'after-free'], stdin=subprocess.DEVNULL, timeout=30)
    time.sleep(2); ng.run(['journalctl', '--sync'])
    seen = subprocess.run(['journalctl', '-t', 'p06-journal', '-o', 'cat', '--no-pager'], stdin=subprocess.DEVNULL, capture_output=True, timeout=30).stdout.decode()
    result(logging_resumed='after-free' in seen, kept_before_fill='journal-volume-ready' in seen)


def journald_stop():
    """Stop journald and its sockets entirely, as an operator might: the services' stdout streams are dropped."""
    ng.case = 'NN-journald-stop'
    ng.run(['systemctl', 'stop', 'systemd-journald.service', 'systemd-journald.socket', 'systemd-journald-dev-log.socket', 'systemd-journald-audit.socket'])
    result(stopped=True)


def journald_start():
    ng.case = 'NN-journald-start'
    ng.run(['systemctl', 'start', 'systemd-journald.socket', 'systemd-journald-dev-log.socket', 'systemd-journald-audit.socket', 'systemd-journald.service'])
    result(started=True)


def local_ready():
    """Is the controller answering inside its own guest, is anything listening, and what are its threads doing?"""
    ng.case = 'NN-local-ready'
    pid = int(ng.show('MainPID'))
    answered = True
    try:
        ng.ready()
    except BaseException:
        answered = False
    listening = bool(subprocess.run(['ss', '-ltnH', 'sport = :8443'], stdin=subprocess.DEVNULL, capture_output=True, timeout=30).stdout.strip())
    states = {}
    for task in Path('/proc/%d/task' % pid).iterdir():
        try:
            state = (task/'stat').read_text().rsplit(')', 1)[1].split()[0]
        except OSError:
            continue
        states[state] = states.get(state, 0)+1
    stdout_target = os.readlink('/proc/%d/fd/1' % pid)[:20] if Path('/proc/%d/fd/1' % pid).exists() else 'none'
    sockets = subprocess.run(['ss', '-ltnpH'], stdin=subprocess.DEVNULL, capture_output=True, timeout=30).stdout.decode(errors='replace')
    mine = [line.split()[3] for line in sockets.splitlines() if 'pid=%d,' % pid in line]
    fds = len(list(Path('/proc/%d/fd' % pid).iterdir()))
    waits = {}
    for task in Path('/proc/%d/task' % pid).iterdir():
        try:
            channel = (task/'wchan').read_text().strip() or 'running'
        except OSError:
            continue
        waits[channel] = waits.get(channel, 0)+1
    result(answered=answered, listening=listening, listeners=mine, open_fds=fds, wait_channels=waits, thread_states=states, stdout=stdout_target)


def journal():
    """Print the controller-side journal of this disposable fixture for the host to export (P07_RUN only)."""
    units = [ng.SERVICE, ng.BACKUP, ng.RESTORE_UNIT, STALE_UNIT, 'blindpass-controller-initialize.service']
    sys.stdout.buffer.write(subprocess.run(['journalctl', *[arg for unit in units for arg in ('-u', unit)], '-o', 'cat', '--no-pager'],
                                           stdin=subprocess.DEVNULL, capture_output=True, timeout=120).stdout)


COMMANDS = {'local-ready': local_ready, 'journald-stop': journald_stop, 'journald-start': journald_start, 'backup-state': backup_state, 'backup-attempt': backup_attempt, 'loop-journal': loop_journal, 'fill-journal': fill_journal, 'free-journal': free_journal, 'loop-data': loop_data, 'fill-disk': fill_disk, 'free-disk': free_disk, 'fault-state': fault_state, 'setup': setup, 'backup': backup, 'lose': lose, 'restore': restore, 'serve': serve, 'activate-serve': activate_serve,
            'stale-transient': stale_transient, 'stale-swap': stale_swap, 'rows': rows, 'cli': cli, 'script': script, 'sql': sql, 'scan': scan, 'journal': journal}


def main():
    try:
        COMMANDS[sys.argv[1]](*sys.argv[2:])
    except SystemExit:
        raise
    except Exception as error:
        import traceback
        frames = [frame for frame in traceback.extract_tb(error.__traceback__) if frame.filename == __file__]
        line = frames[-1].lineno if frames else 0
        print('P06-'+ng.case+' FAIL line='+str(line)+' type='+type(error).__name__+' (private guest diagnostics withheld)', flush=True)
        sys.exit(1)


if __name__ == '__main__':
    main()
