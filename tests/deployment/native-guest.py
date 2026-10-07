#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""P06-N01–N10, inside a disposable real-systemd guest only. No secret output."""
import hashlib
import http.client
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shutil
import sqlite3
import ssl
import stat
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request

# P07-I04/F2: fail-closed log assertions; copied next to this file in the guest.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import canary_log_scan  # noqa: E402

ROOT = Path('/root/p06-native')
BUNDLE = ROOT / 'bundle'
DATA = Path('/var/lib/blindpass/controller')
KEYS = Path('/etc/blindpass/keys')
CONFIG = Path('/etc/blindpass/controller.env')
PRIVATE = ROOT / 'private'
OFFLINE_KEY = PRIVATE / 'backup-recipient.pem'
OFFLINE_SIGNER = PRIVATE / 'backup-signing-certificate.pem'
CERT = PRIVATE / 'cert.pem'
KEY = PRIVATE / 'key.pem'
REFERENCE = ROOT / 'reference.json'
SERVICE = 'blindpass-controller.service'
BACKUP = 'blindpass-controller-backup.service'
RESTORE_UNIT = 'blindpass-controller-restore.service'
BACKUP_TIMER = 'blindpass-controller-backup.timer'
BACKUP_CHECK = 'blindpass-controller-backup-credential-check.service'
# ADR 0013: the host holds a signing credential and the recipient certificate; the
# recipient private key and the signer certificate stay in PRIVATE (the "offline" side).
SIGNING = Path('/etc/blindpass/controller-backup-signing-credential')
RECIPIENT = Path('/etc/blindpass/controller-backup-recipient-certificate')
CUSTODY = (SIGNING, RECIPIENT)
BLINDPASS = '/opt/blindpass/controller/current/bin/blindpass'
BACKUP_ENABLED = Path('/etc/blindpass/controller-backup-enabled')
AUTHORITY_DIR = Path('/etc/blindpass/controller-authority')
AUTH_DB, AUTH_ROLE = 'p06_authority', 'p06_runtime'
TENANT, OWNER = 'p06_native_tenant', 'p06_native_owner'
AUTH_URL = ROOT / 'authority-url'
AUTH_STATE = ROOT / 'authority.json'
SQL = Path('/srv/p06-authority-sql')
AUTH_ARGS = ['--authority-url-file', AUTH_URL, '--tenant-id', TENANT, '--owner-id', OWNER]
case = 'setup'


def run(args, success=True, capture_stderr=False):
    result = subprocess.run([str(value) for value in args], stdin=subprocess.DEVNULL,
                            capture_output=True, timeout=90)
    if success and result.returncode != 0:
        diagnostics = ROOT/'private-diagnostics.txt'
        diagnostics.write_bytes(result.stdout+result.stderr); diagnostics.chmod(0o600)
        # Public operation label only; never arbitrary argument values/output.
        print('P06-'+case+' failed_executable='+Path(str(args[0])).name,flush=True)
        if str(args[0]) == 'systemctl' and args[1] in ['start','stop','show','reset-failed','enable','disable']:
            print('P06-'+case+' failed_systemctl_operation='+args[1],flush=True)
    if success: assert result.returncode == 0, 'command failed'
    else: assert result.returncode != 0, 'command unexpectedly accepted'
    return (result.stdout+result.stderr if capture_stderr else result.stdout).decode()


def psql(file=None, sql=None, variables=None, success=True, database=AUTH_DB):
    # The disposable guest's own PostgreSQL stands in for the independent
    # authority; the administrator is the local postgres superuser.
    args = ['runuser','-u','postgres','--','psql','-X','-q','-t','-A','-v','ON_ERROR_STOP=1','-d',database]
    for key,value in (variables or {}).items(): args += ['-v',key+'='+value]
    args += ['-f',file] if file else ['-c',sql]
    result = subprocess.run([str(value) for value in args],stdin=subprocess.DEVNULL,capture_output=True,timeout=90)
    output = (result.stdout+result.stderr).decode()
    if success and result.returncode != 0:
        # Authority errors are fixed SQL messages; never print other output.
        for line in output.splitlines():
            if 'ERROR:' in line or 'FATAL:' in line or line.startswith('psql:'):
                print('P06-'+case+' authority_error='+line[:200].replace(str(ROOT),'[root]'),flush=True)
    if success: assert result.returncode == 0, 'authority command failed'
    else: assert result.returncode != 0, 'authority command unexpectedly accepted'
    return output


def authority_setup():
    SQL.parent.mkdir(mode=0o755,exist_ok=True); SQL.mkdir(mode=0o755,exist_ok=True)
    for name in ['recovery-authority.sql','authority-runtime-role.sql','authority-register.sql',
                 'authority-activate.sql','authority-fence.sql','authority-recover-attest.sql',
                 'authority-recover-status.sql','authority-recover-activate.sql']:
        shutil.copy(BUNDLE/'deploy/controller'/name,SQL/name); (SQL/name).chmod(0o644)
    run(['systemctl','start','postgresql'])
    for _ in range(60):
        if subprocess.run(['runuser','-u','postgres','--','pg_isready','-q'],capture_output=True).returncode == 0: break
        time.sleep(1)
    password = secrets.token_hex(24)
    psql(sql="CREATE ROLE "+AUTH_ROLE+" LOGIN PASSWORD '"+password+"'",database='postgres')
    psql(sql='CREATE DATABASE '+AUTH_DB,database='postgres')
    psql(file=SQL/'recovery-authority.sql')
    psql(file=SQL/'authority-runtime-role.sql',variables={'runtime_role':AUTH_ROLE})
    AUTH_URL.write_text('postgresql://'+AUTH_ROLE+':'+password+'@127.0.0.1:5432/'+AUTH_DB+'\n'); AUTH_URL.chmod(0o600)
    (ROOT/'authority-password').write_text(password); (ROOT/'authority-password').chmod(0o600)


def wait_authority():
    # After a reboot the guest's PostgreSQL may still be recovering.
    for _ in range(120):
        if subprocess.run(['runuser','-u','postgres','--','pg_isready','-q'],capture_output=True).returncode == 0: return
        time.sleep(1)
    raise AssertionError('authority database did not become ready')


def authority_state():
    return json.loads(AUTH_STATE.read_text())


def register(issuer, tenant=TENANT):
    psql(file=SQL/'authority-register.sql',variables={'tenant':tenant,'owner':OWNER,'issuer':issuer})
    AUTH_STATE.write_text(json.dumps({'issuer':issuer,'tenant':tenant})); AUTH_STATE.chmod(0o600)


def authority_call(script, success=True):
    wait_authority()
    state = authority_state()
    return psql(file=SQL/script,variables={'tenant':state['tenant'],'owner':OWNER,'issuer':state['issuer']},success=success)


def activate(success=True): return authority_call('authority-activate.sql',success)


def fence(success=True): return authority_call('authority-fence.sql',success)


def restart_service():
    # One activation grants one start; the previous holder must be gone.
    run(['systemctl','stop',SERVICE]); activate(); run(['systemctl','start',SERVICE])


def never_ready(seconds=3):
    deadline = time.monotonic()+seconds
    while time.monotonic() < deadline:
        try:
            status,body,_ = get('/readyz')
            assert not (status == 200 and json.loads(body)['ok'] is True), 'controller became ready without an activation'
        except (OSError,ValueError,urllib.error.URLError,http.client.HTTPException): pass
        time.sleep(.25)


def fresh_authority_install(tenant, *extra):
    # First stage: keys and the public issuer identifier; the administrator then
    # registers it; second stage creates the database; start needs an activation.
    first = json.loads(install('--public-url','https://localhost:3200','--authority-url-file',AUTH_URL,
                               '--tenant-id',tenant,'--owner-id',OWNER,'--initialize-keys',*extra))
    register(first['issuer_key_id'],tenant)
    second = json.loads(install('--initialize'))
    assert second['initialized'] is True
    return second


def install(*args, success=True, bundle=BUNDLE, capture_stderr=False):
    return run(['python3', bundle/'deploy/native/controller-install.py', '--bundle',bundle,*args],success,capture_stderr)


def fenced_start_refused(output):
    # P07 slice 7: the activation was consumed (or another holder exists): the process exits `startup_failed fenced`
    # before it binds a listener, and --start refuses with the journal's reason and the next step.
    assert '"ok": false' in output and '"started": false' in output, 'start refusal must say ok=false on stdout'
    assert 'startup_failed reason=fenced' in output, 'the fenced reason must come from the journal'
    assert 'authority-activate.sql' in output, 'the next step must be named'
    assert '"ok": true' not in output
    assert show('ActiveState') in ['failed','inactive'], 'the exited service must not look active'


def unready_start_refused(output):
    # P07 slice 7: a fenced record that was never activated runs the controller as a diagnostic process (healthz 200,
    # readyz 503 recovery_required); --start must not report that as a start.
    assert '"ok": false' in output and '"started": false' in output, 'start refusal must say ok=false on stdout'
    assert 'running but not ready' in output and 'recovery_required' in output, 'the readiness reason must be named'
    assert 'authority-activate.sql' in output, 'the next step must be named'
    assert '"ok": true' not in output
    assert show('ActiveState') == 'active', 'the diagnostic process keeps running'


def uninstall(*args, success=True):
    return run(['python3', BUNDLE/'deploy/native/controller-install.py','--uninstall',*args],success)


def show(prop, service=SERVICE):
    return run(['systemctl','show',service,'--property='+prop,'--value']).strip()


def failed_start():
    # Type=exec confirms exec, not application readiness; a lost DB can fail
    # just after systemctl has returned success. Observe the actual unit.
    subprocess.run(['systemctl','start',SERVICE],capture_output=True,timeout=60)
    for _ in range(40):
        if show('ActiveState') in ['failed','inactive'] or show('SubState') == 'auto-restart' and show('Result') != 'success': return
        time.sleep(.1)
    print('P06-N06 unit state='+show('ActiveState')+' substate='+show('SubState')+' result='+show('Result'),flush=True)
    raise AssertionError('lost-state service remained active')


def get(path, tls=True, headers=None):
    context = ssl.create_default_context(cafile=str(CERT)) if tls else None
    request = urllib.request.Request(('https' if tls else 'http')+'://localhost:3200'+path,headers=headers or {})
    try:
        with urllib.request.urlopen(request,context=context,timeout=3) as response:
            return response.status,response.read(),response.headers
    except urllib.error.HTTPError as error:
        return error.code,error.read(),error.headers


def ready():
    last = 'no response'
    for _ in range(40):
        try:
            status,body,_ = get('/readyz')
            if status == 200 and json.loads(body)['ok'] is True: return
            last = str(status)+' '+body.decode(errors='replace')[:300]
        except (OSError,ValueError) as error: last = type(error).__name__
        time.sleep(.25)
    # Fixed readiness envelope only; no credentials are present in it.
    print('P06-'+case+' last_readiness='+last+' unit='+show('ActiveState')+'/'+show('SubState'),flush=True)
    raise AssertionError('readiness deadline exceeded')


def identity():
    with sqlite3.connect('file:'+str(DATA/'controller.db')+'?mode=ro',uri=True) as connection:
        rows = connection.execute('SELECT tenant_id,issuer_epoch FROM controller_meta').fetchall()
    return {'keys':{name:hashlib.sha256((KEYS/name).read_bytes()).hexdigest()
                    for name in ['root-secret','agent-jwt-secret','issuer-key']},
            'meta':rows,'config':hashlib.sha256(CONFIG.read_bytes()).hexdigest()}


def saved_identity(): return json.loads(REFERENCE.read_text())


def same_identity():
    assert json.loads(json.dumps(identity())) == saved_identity(), 'identity/config changed'


def passed(name): print('P06-'+name+' PASS',flush=True)


def backup_verify(archive, key=None, signer=None, success=True):
    # Transient D-Bus argv is passed literally; resolve the credential paths
    # from the environment rather than unit-file ExecStart specifiers. Only the
    # operator's offline recipient key opens an archive (ADR 0013).
    result = run(['systemd-run','--wait','--pipe','--collect','--unit=p06-backup-verify-'+str(time.monotonic_ns()),
                  '--uid=blindpass','--property=LoadCredential=recipient-key:'+str(key or OFFLINE_KEY),
                  '--property=LoadCredential=signing-certificate:'+str(signer or OFFLINE_SIGNER),
                  '--property=ProtectSystem=strict','--property=ReadWritePaths='+str(DATA),
                  '--property=NoNewPrivileges=yes','--property=PrivateTmp=yes','--property=LimitCORE=0',
                  '/bin/sh','-c','exec "$1" backup verify --archive "$2" --recipient-key-file "$CREDENTIALS_DIRECTORY/recipient-key" --signing-certificate-file "$CREDENTIALS_DIRECTORY/signing-certificate" --work-directory "$3"',
                  'p06-verify',BLINDPASS,archive,DATA],success,
                 capture_stderr=not success)
    if success:
        assert json.loads(result)['verified'] is True
    else:
        assert 'blindpass-controller: backup cryptographic operation failed' in result, 'wrong key failed before authentication'


def native_backup():
    user = pwd.getpwnam('blindpass')
    os_id = dict(line.split('=',1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)['ID'].strip('"')
    library = 'libssl3t64' if os_id == 'ubuntu' else 'libssl3'
    print('P06-B10 openssl='+run(['openssl','version']).strip(),flush=True)
    for line in run(['dpkg-query','-W','-f=${Package} ${Version}\n','openssl',library]).splitlines():
        print('P06-B10 package='+line,flush=True)
    with sqlite3.connect(DATA/'controller.db') as connection:
        connection.execute('CREATE TABLE native_backup_payload (id INTEGER PRIMARY KEY, dummy BLOB NOT NULL)')
        connection.execute('INSERT INTO native_backup_payload VALUES (1, zeroblob(8388608))')
    signing_private = PRIVATE/'backup-signing.pem'; recipient_certificate = PRIVATE/'backup-recipient-certificate.pem'
    run([BLINDPASS,'backup','key-init','--role','signing','--output',signing_private,'--certificate-output',OFFLINE_SIGNER])
    run([BLINDPASS,'backup','key-init','--role','recipient','--output',OFFLINE_KEY,'--certificate-output',recipient_certificate])
    for path in (signing_private,OFFLINE_SIGNER,OFFLINE_KEY,recipient_certificate):
        assert path.stat().st_mode & 0o777 == 0o600
    # A key-init never replaces existing credentials.
    run([BLINDPASS,'backup','key-init','--role','recipient','--output',OFFLINE_KEY,'--certificate-output',recipient_certificate],success=False)
    # Only the signing credential and the recipient's certificate are installed on the host.
    for source,target in ((signing_private,SIGNING),(recipient_certificate,RECIPIENT)):
        copy = ['sh','-c','umask 077; set -C; cat "$1" > "$2"','p06-copy',source,target]
        run(copy)
        run(copy,success=False)
        assert target.stat().st_mode & 0o777 == 0o600 and target.read_bytes() == source.read_bytes()
    assert b'PRIVATE KEY' not in RECIPIENT.read_bytes() and b'PRIVATE KEY' in SIGNING.read_bytes()
    offline = OFFLINE_KEY
    with os.fdopen(os.open(BACKUP_ENABLED,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'wb'):
        pass
    # The daemon stays active while the shipped hardened unit snapshots it.
    assert show('ActiveState') == 'active'
    started = time.monotonic(); run(['systemctl','start',BACKUP]); elapsed = time.monotonic()-started
    assert show('Result',BACKUP) == 'success' and show('ExecMainStatus',BACKUP) == '0'
    assert show('ActiveState',BACKUP) == 'inactive'
    assert show('TimeoutStartUSec',BACKUP) == '15min'
    for prop,value in [('User','blindpass'),('NoNewPrivileges','yes'),('ProtectSystem','strict'),
                       ('CapabilityBoundingSet',''),('LimitCORE','0'),('KillMode','control-group')]:
        assert show(prop,BACKUP) == value, 'backup hardening mismatch'
    output = DATA/'backups'
    archives = list(output.iterdir())
    assert len(archives) == 1 and archives[0].name.endswith('.bpbackup')
    assert archives[0].stat().st_size > 8388608
    for path in [output,archives[0]]:
        info = path.stat()
        assert info.st_uid == user.pw_uid and stat.S_IMODE(info.st_mode) == (0o700 if path.is_dir() else 0o600)
    assert not Path('/run/credentials/'+BACKUP).exists(), 'credential copy outlived the unit'
    backup_verify(archives[0])
    # A different recipient key, and the host's own signing credential, never open it.
    wrong = PRIVATE/'wrong-backup-recipient.pem'
    run([BLINDPASS,'backup','key-init','--role','recipient','--output',wrong,'--certificate-output',PRIVATE/'wrong-backup-recipient-certificate.pem'])
    backup_verify(archives[0],wrong,success=False)
    backup_verify(archives[0],SIGNING,success=False)
    assert not any(path.name.startswith('.backup-') for path in DATA.iterdir())
    with sqlite3.connect(DATA/'controller.db') as connection:
        assert connection.execute('SELECT length(dummy) FROM native_backup_payload WHERE id=1').fetchone()[0] == 8388608
    ready(); same_identity()
    journal = run(['journalctl','-u',BACKUP,'-o','cat','--no-pager'])
    assert '"verified":true' in journal
    canary_log_scan.assert_log_clean('P06-N backup unit journal',journal,[offline.read_text()],markers=['BEGIN PRIVATE KEY'],require=['"verified":true'])
    run(['systemctl','enable','--now',BACKUP_TIMER])
    assert show('UnitFileState',BACKUP_TIMER) == 'enabled' and show('ActiveState',BACKUP_TIMER) == 'active'
    print('P06-B08 native_backup_seconds='+format(elapsed,'.3f'),flush=True)


def before_reboot():
    global case
    case = 'N01'
    assert os.getuid() == 0 and Path('/run/systemd/system').is_dir()
    assert not DATA.exists() and not KEYS.exists()
    install('--verify-only')
    bad = ROOT / 'tampered'; shutil.copytree(BUNDLE,bad)
    with (bad/'bin/blindpass').open('ab') as target: target.write(b'P06-DUMMY-TAMPER')
    authority_setup()
    install('--public-url','https://localhost:3200','--initialize-keys',*AUTH_ARGS,success=False,bundle=bad)
    assert not DATA.exists() and not KEYS.exists() and not AUTHORITY_DIR.exists()
    try: pwd.getpwnam('blindpass'); raise AssertionError('preflight created account')
    except KeyError: pass
    shutil.rmtree(bad)
    malformed = ROOT/'malformed.pem'; malformed.write_bytes(b'P06-DUMMY-TLS-CANARY'); malformed.chmod(0o600)
    install('--public-url','https://localhost:3200','--tls-cert',malformed,'--tls-key',malformed,'--initialize-keys',*AUTH_ARGS,success=False)
    assert not KEYS.exists() and not DATA.exists() and not AUTHORITY_DIR.exists(); malformed.unlink()
    run(['useradd','--system','--home-dir','/nonexistent','--shell','/bin/sh','blindpass'])
    install('--public-url','https://localhost:3200','--initialize-keys',*AUTH_ARGS,success=False)
    assert not KEYS.exists() and not DATA.exists()
    run(['userdel','blindpass'])
    collision = Path('/etc/systemd/system/blindpass-controller.service')
    collision.write_bytes(b'# P06-DUMMY-UNMANAGED-UNIT\n')
    install('--public-url','https://localhost:3200','--initialize-keys',*AUTH_ARGS,success=False)
    assert collision.read_bytes() == b'# P06-DUMMY-UNMANAGED-UNIT\n' and not KEYS.exists()
    collision.unlink()
    # Unsafe or incomplete authority provisioning is refused before any account,
    # key or state exists, and never echoes the credential.
    password = (ROOT/'authority-password').read_text()
    exposed = ROOT/'authority-exposed'; exposed.write_text(AUTH_URL.read_text()); exposed.chmod(0o640)
    remote = ROOT/'authority-remote'; remote.write_text('postgresql://'+AUTH_ROLE+':'+password+'@db.authority.invalid:5432/'+AUTH_DB+'\n'); remote.chmod(0o600)
    refusals = [install('--public-url','https://localhost:3200','--initialize-keys','--authority-url-file',exposed,'--tenant-id',TENANT,'--owner-id',OWNER,success=False),
                install('--public-url','https://localhost:3200','--initialize-keys','--authority-url-file',remote,'--tenant-id',TENANT,'--owner-id',OWNER,success=False),
                install('--public-url','https://localhost:3200','--initialize-keys','--authority-url-file',AUTH_URL,'--owner-id',OWNER,success=False),
                install('--public-url','https://localhost:3200','--initialize-keys','--authority-url-file',AUTH_URL,'--tenant-id','bad id','--owner-id',OWNER,success=False),
                install('--public-url','https://localhost:3200','--initialize-keys',success=False)]
    assert all(password not in output for output in refusals)
    exposed.unlink(); remote.unlink()
    try: pwd.getpwnam('blindpass'); raise AssertionError('authority refusal created an account')
    except KeyError: pass
    assert not KEYS.exists() and not DATA.exists() and not AUTHORITY_DIR.exists() and not CONFIG.exists()
    passed(case)
    case = 'N02'
    PRIVATE.mkdir(mode=0o700)
    run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','2','-keyout',KEY,
         '-out',CERT,'-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1'])
    KEY.chmod(0o600); CERT.chmod(0o600)
    other_key = PRIVATE/'mismatched.pem'
    run(['openssl','genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:2048','-out',other_key])
    other_key.chmod(0o600)
    install('--public-url','https://localhost:3200','--initialize-keys',*AUTH_ARGS,'--tls-cert',CERT,'--tls-key',other_key,success=False)
    assert not KEYS.exists() and not DATA.exists() and not AUTHORITY_DIR.exists(); other_key.unlink()
    # Keys first; the database cannot be created before the administrator
    # registers the printed issuer, and a fenced start is never ready.
    first = json.loads(install('--public-url','https://localhost:3200',*AUTH_ARGS,'--initialize-keys','--tls-cert',CERT,'--tls-key',KEY))
    assert first['keys_initialized'] is True and first['initialized'] is False and first['issuer_key_id'].startswith('ed25519-')
    install('--initialize',success=False); assert not (DATA/'controller.db').exists()
    register(first['issuer_key_id'])
    install('--initialize-keys',success=False)
    result = json.loads(install('--initialize'))
    assert result['ok'] is True and result['initialized'] is True
    print('P06-N02 install='+json.dumps(result,sort_keys=True),flush=True)
    password = (ROOT/'authority-password').read_text()
    assert password not in CONFIG.read_text()
    for unit in [SERVICE,'blindpass-controller-initialize.service','blindpass-controller-reconcile-clock.service']:
        assert password not in Path('/etc/systemd/system/'+unit).read_text()
    info = AUTHORITY_DIR.stat(); assert info.st_uid == 0 and info.st_mode & 0o777 == 0o700
    info = (AUTHORITY_DIR/'authority-url').stat(); assert info.st_uid == 0 and info.st_mode & 0o777 == 0o600
    unready_start_refused(install('--start',success=False,capture_stderr=True)); never_ready(4)   # NS1: never activated: diagnostic process, not ready
    run(['systemctl','stop',SERVICE]); activate(); run(['systemctl','start',SERVICE])
    ready()
    canary_log_scan.assert_log_clean('P06-N controller journal',run(['journalctl','-u',SERVICE,'-o','cat','--no-pager']),[password],min_bytes=32)
    assert pwd.getpwnam('blindpass').pw_uid != 0
    for directory in [KEYS,DATA]:
        info = directory.stat(); assert info.st_mode & 0o777 == 0o700 and info.st_uid == pwd.getpwnam('blindpass').pw_uid
    for file in KEYS.iterdir(): assert file.stat().st_mode & 0o777 == 0o600
    assert CONFIG.stat().st_mode & 0o777 == 0o640 and CONFIG.stat().st_uid == 0
    status,body,headers = get('/')
    assert status == 200 and b'<!doctype html' in body.lower() and headers.get('Content-Security-Policy')
    status,body,_ = get('/?id=P06-DUMMY-LINK&metadata_sig=P06-DUMMY-SIG&submit_sig=P06-DUMMY-SIG')
    assert status == 200 and b'<!doctype html' in body.lower()
    caps = json.loads(get('/api/v3/capabilities')[1]); assert caps['version'] == '0.1.0'
    try: get('/readyz',tls=False); raise AssertionError('plaintext listener accepted')
    except (OSError,urllib.error.URLError,http.client.HTTPException): pass
    REFERENCE.write_text(json.dumps(identity())); REFERENCE.chmod(0o600)
    passed(case)
    case = 'N03'
    for prop,value in [('User','blindpass'),('Group','blindpass'),('ProtectSystem','strict'),
                       ('NoNewPrivileges','yes'),('PrivateTmp','yes'),('CapabilityBoundingSet',''),
                       ('UMask','0077'),('LimitCORE','0'),('KillMode','control-group')]:
        assert show(prop) == value, 'unit property mismatch'
    pid = show('MainPID'); assert int(pid)>0
    status = dict(line.split(':',1) for line in Path('/proc/'+pid+'/status').read_text().splitlines() if ':' in line)
    assert int(status['Uid'].split()[0]) == pwd.getpwnam('blindpass').pw_uid
    assert int(status['CapEff'].strip(),16) == 0 and status['NoNewPrivs'].strip() == '1'
    admin = Path('/run/blindpass-controller/admin.sock').stat()
    assert stat.S_ISSOCK(admin.st_mode) and admin.st_mode & 0o777 == 0o600
    assert admin.st_uid == pwd.getpwnam('blindpass').pw_uid
    run(['runuser','-u','blindpass','--','test','-r','/etc/blindpass/controller-tls/key.pem'],success=False)
    # Enter the actual service mount namespace; write probes run as its real UID.
    prefix = ['nsenter','--target',pid,'--mount','--','runuser','-u','blindpass','--','sh','-c']
    run(prefix+['printf P06-DUMMY-WRITE > /etc/blindpass/keys/write-probe'],success=False)
    run(prefix+['printf P06-DUMMY-WRITE > /etc/blindpass/controller.env'],success=False)
    run(prefix+['printf P06-DUMMY-WRITE > /opt/blindpass/controller/write-probe'],success=False)
    run(prefix+['printf P06-DUMMY-WRITE > /var/lib/blindpass/controller/write-probe'])
    assert (DATA/'write-probe').read_text() == 'P06-DUMMY-WRITE'; (DATA/'write-probe').unlink()
    assert not (KEYS/'write-probe').exists()
    # Real root-owned ACL file with an extra reader must remain refused even
    # when the service UID itself can open it. No key material is copied.
    unsafe = Path('/etc/blindpass/p06-unsafe-credential')
    unsafe.write_bytes(b'P06-DUMMY-ACL-SECRET-CANARY-000000'); unsafe.chmod(0o400)
    uid = pwd.getpwnam('blindpass').pw_uid; runner = pwd.getpwnam('p06runner').pw_uid
    entries = [(1,4,0xffffffff),(2,4,uid),(2,4,runner),(4,0,0xffffffff),(16,4,0xffffffff),(32,0,0xffffffff)]
    acl = struct.pack('<I',2)+b''.join(struct.pack('<HHI',*entry) for entry in entries)
    os.setxattr(unsafe,'system.posix_acl_access',acl)
    run(['systemd-run','--wait','--pipe','--unit=p06-unsafe-acl','--uid=blindpass',
         '--property=EnvironmentFile=/etc/blindpass/controller.env',
         '--setenv=BLINDPASS_ROOT_SECRET_FILE='+str(unsafe),
         '/opt/blindpass/controller/current/bin/blindpass-controller','check-config'],success=False)
    unsafe.unlink()
    passed(case)
    case = 'N04-restart'
    start = time.monotonic(); run(['systemctl','stop',SERVICE]); duration = time.monotonic()-start
    assert duration < 10
    print('P06-N04 stop_seconds='+format(duration,'.3f'),flush=True)
    # A used active revision is never replayed: a restart alone is not ready.
    run(['systemctl','start',SERVICE]); never_ready(4)
    restart_service(); ready(); same_identity()
    assert show('UnitFileState') == 'enabled' and show('Restart') == 'no'
    (ROOT/'boot-id').write_text(Path('/proc/sys/kernel/random/boot_id').read_text())
    passed(case)


def native_faults():
    """Slice 9 fault subset on the packaged native SQLite controller, matching the Compose F1-F3
    scenarios: abrupt process death, a 20 s process suspend and loss of the database. None may
    change identity, keys or state; the first two need no more than a fresh activation."""
    global case
    case = 'NF1'
    run(['systemctl','stop',SERVICE]); activate(); run(['systemctl','start',SERVICE]); ready(); same_identity()
    run(['systemctl','kill','--signal=SIGKILL','--kill-whom=main',SERVICE])
    for _ in range(100):
        if show('ActiveState') in ['failed','inactive']: break
        time.sleep(.1)
    assert show('ActiveState') in ['failed','inactive'], 'SIGKILL did not stop the service'
    run(['systemctl','reset-failed',SERVICE]); run(['systemctl','start',SERVICE]); never_ready(4)
    run(['systemctl','stop',SERVICE])
    deadline = time.monotonic()+30
    while True:
        try: activate(); break
        except AssertionError:
            assert time.monotonic() < deadline, 'authority never released the killed owner'
            time.sleep(1)
    started = time.monotonic(); run(['systemctl','start',SERVICE]); ready(); recovered = time.monotonic()-started
    assert recovered < 15, 'readiness after SIGKILL exceeded 15 s'
    same_identity()
    print(f'P06-NF1 native: SIGKILL needs a fresh activation, then ready in {recovered:.3f}s (bound 15s), identity/keys/state unchanged',flush=True)
    passed('NF1')
    case = 'NF2'
    run(['systemctl','kill','--signal=SIGSTOP','--kill-whom=main',SERVICE])
    try: time.sleep(20)
    finally: run(['systemctl','kill','--signal=SIGCONT','--kill-whom=main',SERVICE])
    resumed = time.monotonic(); outcome = 'ready'
    try: ready()
    except AssertionError:
        outcome = 'fenced'
        run(['systemctl','stop',SERVICE]); activate(); run(['systemctl','start',SERVICE]); ready()
    same_identity()
    print(f'P06-NF2 native: 20s process suspend left the controller {outcome} ({time.monotonic()-resumed:.3f}s after resume); identity/keys/state unchanged',flush=True)
    passed('NF2')
    case = 'NF3'
    run(['systemctl','stop',SERVICE])
    DATA.rename(ROOT/'faults-saved-data')
    activate(); started = time.monotonic(); failed_start(); took = time.monotonic()-started
    journal = run(['journalctl','-u',SERVICE,'-o','cat','--no-pager','--since','-90s'])
    reasons = re.findall(r'"reason":"([a-z_]+)"',journal)
    assert reasons and reasons[-1] == 'state_missing', reasons
    assert not (DATA/'controller.db').exists(), 'a lost database was silently recreated'
    subprocess.run(['systemctl','stop',SERVICE],stdin=subprocess.DEVNULL,capture_output=True,timeout=60)
    if DATA.exists(): shutil.rmtree(DATA)
    (ROOT/'faults-saved-data').rename(DATA)
    run(['systemctl','reset-failed',SERVICE]); activate(); run(['systemctl','start',SERVICE]); ready(); same_identity()
    print(f'P06-NF3 native: lost database refused with an activation in place, reason state_missing ({took:.1f}s), never recreated; restored state serves again',flush=True)
    passed('NF3')


def after_reboot(power_loss=False, tool_faults=False, credential_faults=False, recovery=False, faults=False, rollback=False):
    global case
    case = 'N04-reboot'
    assert Path('/proc/sys/kernel/random/boot_id').read_text() != (ROOT/'boot-id').read_text()
    # The enabled unit could not replay the pre-reboot revision.
    run(['systemctl','stop',SERVICE])
    run(['systemctl','start','blindpass-controller-reconcile-clock.service'],success=False)   # record is active
    fence(); run(['systemctl','start','blindpass-controller-reconcile-clock.service'])
    activate(); run(['systemctl','start',SERVICE]); ready(); same_identity()
    passed(case)
    case = 'N05'
    install('--start'); ready(); same_identity()
    install('--initialize',success=False); same_identity()
    changed = ROOT/'changed'; shutil.copytree(BUNDLE,changed)
    manifest = json.loads((changed/'manifest.json').read_text())
    for version in ['0.2.0','0.0.9']:
        manifest['version']=version; (changed/'manifest.json').write_text(json.dumps(manifest))
        install('--start',success=False,bundle=changed); same_identity()
    manifest['version']='0.1.0'; manifest['source_dirty']=False
    (changed/'manifest.json').write_text(json.dumps(manifest))
    install('--start',success=False,bundle=changed); same_identity(); shutil.rmtree(changed)
    passed(case)
    case = 'N05b'
    # P07 slice 7 (cold-operator finding): a restart without a fresh activation exits fenced one second after
    # systemctl returned; --start must say so and exit non-zero; after an activation it must report started+ready.
    run(['systemctl','stop',SERVICE])
    failed_start()                                    # NS2: plain restart, no activation: exits startup_failed/fenced
    fenced_start_refused(install('--start',success=False,capture_stderr=True))
    run(['systemctl','reset-failed',SERVICE])
    activate()
    started = json.loads(install('--start'))          # NS3: activated start is waited for and reported
    assert started['ok'] is True and started['started'] is True and started['ready'] is True, started
    ready(); same_identity()
    again = json.loads(install('--start'))            # NS4: idempotent while running
    assert again['ok'] is True and again['started'] is True, again
    passed(case)
    case = 'N06'
    run(['systemctl','stop',SERVICE])
    KEYS.rename(ROOT/'saved-keys')
    activate(); failed_start()
    install('--initialize',success=False); install('--start',success=False)
    assert not KEYS.exists()
    (ROOT/'saved-keys').rename(KEYS)
    run(['systemctl','reset-failed',SERVICE])
    DATA.rename(ROOT/'saved-data')
    activate(); failed_start()
    install('--initialize',success=False); install('--start',success=False)
    assert not (DATA/'controller.db').exists()
    run(['systemctl','stop',SERVICE]); shutil.rmtree(DATA)
    (ROOT/'saved-data').rename(DATA)
    run(['systemctl','reset-failed',SERVICE]); activate(); run(['systemctl','start',SERVICE]); ready(); same_identity()
    passed(case)
    case = 'N07'
    timer = 'blindpass-controller-backup.timer'; backup = 'blindpass-controller-backup.service'
    assert show('UnitFileState',timer) == 'disabled' and show('ActiveState',timer) == 'inactive'
    run(['systemctl','start',backup]); assert show('ActiveState',backup) == 'inactive'
    assert show('ExecMainStartTimestampMonotonic',backup) == '0' and not (DATA/'backups').exists()
    assert not SIGNING.exists() and not RECIPIENT.exists()
    passed(case)
    case = 'B08'
    native_backup()
    passed(case)
    if tool_faults:
        native_tool_faults()
    if credential_faults:
        native_credential_faults()
    if recovery:
        native_recovery()
    if faults:
        native_faults()
    if rollback:
        # P07-E03: the release-level rollback rehearsal (tests/deployment/native_rollback.py). It runs instead of the
        # uninstall/upgrade/purge tail because it upgrades and restores the same guest itself.
        import native_rollback
        if native_rollback.rehearse(sys.modules[__name__]):
            sys.exit(3)         # a required observation is missing: never let the harness print its overall PASS
        return
    if power_loss:
        return
    after_backup()


def native_recovery():
    """P06-D30..D32 on the packaged native controller: authenticated backup, total loss of the
    controller state, restore, operator review, source-stop attestation and activation.

    The restore runs through the shipped blindpass-controller-restore.service (operator-supplied
    arguments file and offline custody); the authority is the guest's own PostgreSQL (not
    independent). No real node exists in the guest: one broker trust row is seeded and covered
    only by a named waiver."""
    global case
    case = 'NR01'
    restore_state = Path('/var/lib/blindpass/controller-restore')
    restore_root = restore_state/'root'
    admin_socket = '/run/blindpass-controller/admin.sock'
    state = authority_state()
    node_id = 'nd_p06nativerecovery01'
    original = identity()

    def scalar(sql): return psql(sql=sql).strip()

    def identity_keys():
        return {name:hashlib.sha256((KEYS/name).read_bytes()).hexdigest() for name in ['root-secret','agent-jwt-secret','issuer-key']}

    def ledger(): return scalar("SELECT phase||':'||epoch||':'||revision FROM blindpass_authority.recovery_authority WHERE tenant_id='"+state['tenant']+"'")

    def script(name, **extra):
        wait_authority()
        result = subprocess.run(['runuser','-u','postgres','--','psql','-X','-q','-t','-A','-v','ON_ERROR_STOP=1','-d',AUTH_DB,
                                 *[arg for key,value in {'tenant':state['tenant'],'owner':OWNER,'issuer':state['issuer'],**extra}.items() for arg in ('-v',key+'='+value)],
                                 '-f',str(SQL/name)],stdin=subprocess.DEVNULL,capture_output=True,timeout=90)
        return result

    def refused_with(result, *gates, label):
        text = result.stderr.decode()
        if result.returncode == 0: print('P06-NR accepted what must be refused: '+label,flush=True)
        assert result.returncode != 0, label+': the authority accepted what it must refuse'
        for gate in gates:
            if gate not in text: print('P06-NR refusal lacks gate '+gate+': '+label,flush=True)
            assert gate in text, label+': refusal does not name '+gate
        return text

    def cli(*args, success=True):
        result = subprocess.run(['runuser','-u','blindpass','--',BLINDPASS,'admin','recovery',*args,'--socket',admin_socket],
                                stdin=subprocess.DEVNULL,capture_output=True,timeout=120)
        if (result.returncode == 0) != success:
            # CLI refusals are fixed strings; print only the verb, its options' names and the first line.
            err = result.stderr.decode(errors='replace').splitlines()
            print('P06-NR cli '+' '.join(a for a in args if a.startswith('-') or a in ('status','review','list','decide','complete','waive-node'))+
                  ' expected_success='+str(success)+' rc='+str(result.returncode)+' stderr='+(err[0][:80] if err else ''),flush=True)
        assert (result.returncode == 0) == success, 'recovery command '+args[0]+(' failed' if success else ' was accepted')
        return result

    def cli_json(*args): return json.loads(cli(*args).stdout.decode())

    def wait_recovering():
        for _ in range(120):
            if subprocess.run(['runuser','-u','blindpass','--',BLINDPASS,'admin','recovery','status','--socket',admin_socket],
                              stdin=subprocess.DEVNULL,capture_output=True,timeout=60).returncode == 0: return
            time.sleep(.5)
        raise AssertionError('recovering controller did not answer on its admin socket')

    def lose_everything(tag):
        run(['systemctl','stop',SERVICE])
        shutil.move(str(DATA),str(ROOT/('lost-data-'+tag))); shutil.move(str(KEYS),str(ROOT/('lost-keys-'+tag)))

    def restore(recovery_id, key=None, signer=None, success=True):
        """Run the shipped blindpass-controller-restore.service with the operator's offline custody."""
        if restore_root.exists(): shutil.rmtree(restore_root)
        custody = Path('/etc/blindpass/controller-restore'); arguments = Path('/etc/blindpass/controller-restore.env')
        custody.mkdir(mode=0o700, exist_ok=True)
        for name,source in (('recipient-key',key or OFFLINE_KEY),('signing-certificate',signer or OFFLINE_SIGNER)):
            shutil.copy2(source,custody/name); (custody/name).chmod(0o600)
        arguments.write_text(''.join(name+'='+value+'\n' for name,value in {
            'BLINDPASS_RESTORE_ARCHIVE':str(restore_state/'archives'/archive.name),'BLINDPASS_RESTORE_DESTINATION':str(restore_root),
            'BLINDPASS_RESTORE_TENANT_ID':state['tenant'],'BLINDPASS_RESTORE_OWNER_ID':OWNER,'BLINDPASS_RESTORE_RECOVERY_ID':recovery_id}.items()))
        arguments.chmod(0o600)
        try:
            subprocess.run(['systemctl','reset-failed',RESTORE_UNIT],stdin=subprocess.DEVNULL,capture_output=True,timeout=30)
            run(['systemctl','start',RESTORE_UNIT],success)
            assert show('Result',RESTORE_UNIT) == ('success' if success else 'exit-code'), 'unexpected restore unit result'
        finally:
            shutil.rmtree(custody,ignore_errors=True); arguments.unlink(missing_ok=True)
            subprocess.run(['systemctl','reset-failed',RESTORE_UNIT],stdin=subprocess.DEVNULL,capture_output=True,timeout=30)
        assert not Path('/run/credentials/'+RESTORE_UNIT).exists(), 'restore credential copy outlived the unit'
        assert not Path('/run/blindpass-controller-restore').exists(), 'restore staging outlived the unit'
        # The receipt the command wrote into the restored root (the unit's journal also carries it).
        return json.loads((restore_root/'restore.json').read_text()) if success else None

    def install_restored():
        user = pwd.getpwnam('blindpass')
        for source,target in ((restore_root/'keys',KEYS),(restore_root/'data',DATA)):
            run(['cp','-a',source,target])
            for path in [target,*target.rglob('*')]: os.chown(path,user.pw_uid,user.pw_gid,follow_symlinks=False)
            target.chmod(0o700)
        shutil.rmtree(restore_root)

    def start_recovering():
        run(['systemctl','reset-failed',SERVICE])
        run(['systemctl','start',SERVICE]); wait_recovering(); never_ready(3)

    def reserve():
        run(['systemctl','stop',SERVICE]); fence()
        revision = scalar("SELECT revision FROM blindpass_authority.recovery_authority WHERE tenant_id='"+state['tenant']+"'")
        reserved = scalar("SELECT epoch||':'||phase FROM blindpass_authority.reserve_recovery('"+state['tenant']+"','"+state['issuer']+"','"+OWNER+"',"+revision+",1)")
        assert reserved.endswith(':recovering'), reserved
        return int(reserved.split(':')[0])

    def seed_node(node):
        psql(sql="INSERT INTO blindpass_authority.broker_trust (tenant_id,issuer_key_id,node_id,key_version,signing_public,recipient_public,state,revision) VALUES ('"+state['tenant']+"','"+state['issuer']+"','"+node+"',1,'"+secrets.token_urlsafe(32)[:43]+"','"+secrets.token_urlsafe(32)[:43]+"','active',1)")

    def review_and_activate(label, expect_activations, node):
        """Refusals, review, waiver, attestation, activation. The recovering service is running."""
        before = ledger()
        refused_with(script('authority-activate.sql'),label='ordinary activation of a recovering record')
        refused_with(script('authority-recover-activate.sql'),'source_stop_missing','review_incomplete','node_uncovered',label='early recovery activation')
        refused_with(script('authority-recover-attest.sql',host='p06-native-source',by='p06-admin',note='premature'),label='attestation while a controller holds the guard')
        assert ledger() == before, 'refusals changed the authority record'
        status = cli_json('status')
        assert set(status['gaps']) >= {'source_stop_missing','review_incomplete','node_uncovered'} and status['activation_permitted'] is False, status
        items = cli_json('review','list')['items']
        categories = sorted({i['category'] for i in items})
        if not any(i['category'] == 'operator' for i in items):
            print('P06-NR review categories='+','.join(categories),flush=True)
        assert any(i['category'] == 'operator' for i in items)
        assert cli('review','complete','--operator','p06-operator',success=False).returncode != 0
        for category in sorted({i['category'] for i in items}):
            decision = {'operator':'accept','operation':'accept','workload':'revoke'}.get(category,'reject')
            cli_json('review','decide','--category',category,'--decision',decision,'--operator','p06-operator','--note','native recovery rehearsal')
        assert cli('review','complete','--operator','p06-operator',success=False).returncode != 0, 'completion accepted an uncovered node'
        assert 'node_uncovered' in cli_json('status')['gaps']
        cli('waive-node','no-such-node','--operator','p06-operator','--note','x',success=False)
        cli_json('waive-node',node,'--operator','p06-operator','--note','no real node exists in the guest')
        done = cli_json('review','complete','--operator','p06-operator')
        assert cli_json('status')['gaps'] == ['source_stop_missing'], cli_json('status')['gaps']
        late = [i for i in items if i['category'] == 'operator'][0]
        cli('review','decide','--category','operator','--subject',late['subject_id'],'--decision','reject','--operator','p06-operator',success=False)
        run(['systemctl','stop',SERVICE])
        text = refused_with(script('authority-recover-activate.sql'),'source_stop_missing',label='activation without attestation')
        assert 'review_incomplete' not in text and 'node_uncovered' not in text
        attested = script('authority-recover-attest.sql',host='p06-native-source-host',by='p06-admin',note='source service stopped and fenced')
        assert attested.returncode == 0, 'attestation refused although the service is stopped'
        row = scalar("SELECT host_id||':'||attested_by FROM blindpass_authority.recovery_source_stop ORDER BY epoch DESC LIMIT 1")
        assert row == 'p06-native-source-host:p06-admin', row
        activated = script('authority-recover-activate.sql')
        assert activated.returncode == 0 and 'activated recovery epoch' in activated.stdout.decode(), 'activation refused with every gate met'
        refused_with(script('authority-recover-activate.sql'),label='second recovery activation')
        run(['systemctl','reset-failed',SERVICE]); run(['systemctl','start',SERVICE]); ready()
        assert scalar("SELECT string_agg(epoch::text,',' ORDER BY epoch) FROM blindpass_authority.recovery_activations") == expect_activations
        print('P06-NR '+label+' review='+json.dumps(done['summary'],sort_keys=True)+' attested='+row+' activations='+expect_activations,flush=True)

    # NR01: an operator account exists (so the review has something to decide), a fresh authenticated
    # backup is taken through the shipped unit, the archive leaves the state directory and the controller
    # loses everything it owns. The bootstrap credential is never printed or stored.
    assert show('ActiveState') == 'active'
    bootstrap = subprocess.run(['runuser','-u','blindpass','--',BLINDPASS,'admin','bootstrap','--socket',admin_socket],
                               stdin=subprocess.DEVNULL,capture_output=True,timeout=60)
    assert bootstrap.returncode == 0 and bootstrap.stdout, 'admin bootstrap failed'
    known = set((DATA/'backups').glob('*.bpbackup'))
    run(['systemctl','start',BACKUP]); assert show('Result',BACKUP) == 'success'
    fresh = sorted(set((DATA/'backups').glob('*.bpbackup'))-known)
    assert len(fresh) == 1, 'the backup unit did not publish exactly one new archive'
    archive = fresh[0]; backup_verify(archive)
    user = pwd.getpwnam('blindpass')
    restore_state.mkdir(mode=0o700); os.chown(restore_state,user.pw_uid,user.pw_gid)
    (restore_state/'archives').mkdir(mode=0o700); os.chown(restore_state/'archives',user.pw_uid,user.pw_gid)
    target = restore_state/'archives'/archive.name
    shutil.copy2(archive,target); os.chown(target,user.pw_uid,user.pw_gid); target.chmod(0o600)
    keep_archive = ROOT/'recovered-archive.bpbackup'; shutil.copy2(archive,keep_archive); keep_archive.chmod(0o600)
    first_epoch = reserve()
    seed_node(node_id)
    lose_everything('one')
    assert not DATA.exists() and not KEYS.exists()
    # The host's own custody (signing credential, recipient certificate) cannot open the archive.
    restore('p06nr'+secrets.token_hex(3),key=SIGNING,success=False)
    assert not restore_root.exists() or not any(restore_root.iterdir()), 'a refused restore left state behind'
    # The unit never runs on its own: without the operator's arguments file and offline custody it is skipped.
    subprocess.run(['systemctl','reset-failed',RESTORE_UNIT],stdin=subprocess.DEVNULL,capture_output=True,timeout=30)
    run(['systemctl','start',RESTORE_UNIT])
    assert show('ConditionResult',RESTORE_UNIT) == 'no' and show('ActiveState',RESTORE_UNIT) == 'inactive', 'restore ran without operator input'
    assert not restore_root.exists(), 'restore published state without operator input'
    receipt = restore('p06nr'+secrets.token_hex(3))
    for prop,value in [('User','blindpass'),('Group','blindpass'),('Type','oneshot'),('NoNewPrivileges','yes'),('ProtectSystem','strict'),
                       ('PrivateTmp','yes'),('MemoryDenyWriteExecute','yes'),('CapabilityBoundingSet',''),('UMask','0077'),
                       ('LimitCORE','0'),('KillMode','control-group'),('RuntimeDirectory','blindpass-controller-restore'),
                       ('Result','success'),('ActiveState','inactive')]:
        assert show(prop,RESTORE_UNIT) == value, 'restore unit property mismatch '+prop
    unit_text = run(['systemctl','cat',RESTORE_UNIT])
    assert 'controller-backup-signing-credential' not in unit_text and 'LoadCredential=root-secret' not in unit_text
    assert receipt['phase'] == 'recovery_required' and receipt['activation_permitted'] is False and receipt['backend'] == 'sqlite', receipt
    install_restored()
    assert identity_keys() == original['keys'], 'restored keys differ from the source keys'
    # The operator keeps the archives directory it had (not part of the restored state).
    (DATA/'backups').mkdir(mode=0o700); os.chown(DATA/'backups',user.pw_uid,user.pw_gid)
    shutil.copy2(keep_archive,DATA/'backups'/archive.name); os.chown(DATA/'backups'/archive.name,user.pw_uid,user.pw_gid); (DATA/'backups'/archive.name).chmod(0o600)
    print('P06-NR01 restored under reserved recovery epoch '+str(first_epoch)+' with the offline custody only; host custody refused; keys byte-identical; receipt phase=recovery_required',flush=True)
    passed('NR01')

    case = 'NR02'
    start_recovering()
    review_and_activate('NR02 first recovery',str(first_epoch),node_id)
    now = identity()
    assert now['keys'] == original['keys'] and now['meta'][0][0] == original['meta'][0][0], 'identity changed'
    passed('NR02')

    # NR03: the pre-restore state is refused by the ledger and the controller.
    case = 'NR03'
    run(['systemctl','stop',SERVICE])
    shutil.move(str(DATA),str(ROOT/'restored-data')); shutil.move(str(KEYS),str(ROOT/'restored-keys'))
    shutil.move(str(ROOT/'lost-data-one'),str(DATA)); shutil.move(str(ROOT/'lost-keys-one'),str(KEYS))
    activate(); failed_start()
    run(['systemctl','stop',SERVICE])
    shutil.move(str(DATA),str(ROOT/'lost-data-one')); shutil.move(str(KEYS),str(ROOT/'lost-keys-one'))
    shutil.move(str(ROOT/'restored-data'),str(DATA)); shutil.move(str(ROOT/'restored-keys'),str(KEYS))
    run(['systemctl','reset-failed',SERVICE]); activate(); run(['systemctl','start',SERVICE]); ready()
    passed('NR03')

    # NR04: restore-based rollback rehearsal; every recovery epoch needs its own review and attestation.
    case = 'NR04'
    second_epoch = reserve()
    assert second_epoch > first_epoch
    # The first recovery's waiver revoked that node's trust in the authority, so the rollback epoch has no
    # active node until one is trusted again: seed a second one so the gate is exercised for this epoch too.
    assert scalar("SELECT state FROM blindpass_authority.broker_trust WHERE tenant_id='"+state['tenant']+"' AND node_id='"+node_id+"'") == 'revoked'
    second_node = 'nd_p06nativerecovery02'; seed_node(second_node)
    lose_everything('two')
    shutil.rmtree(restore_state/'archives'); (restore_state/'archives').mkdir(mode=0o700)
    os.chown(restore_state/'archives',user.pw_uid,user.pw_gid)
    shutil.copy2(keep_archive,target); os.chown(target,user.pw_uid,user.pw_gid); target.chmod(0o600)
    receipt = restore('p06nr'+secrets.token_hex(3))
    assert receipt['phase'] == 'recovery_required' and receipt['activation_permitted'] is False
    install_restored()
    (DATA/'backups').mkdir(mode=0o700); os.chown(DATA/'backups',user.pw_uid,user.pw_gid)
    shutil.copy2(keep_archive,DATA/'backups'/archive.name); os.chown(DATA/'backups'/archive.name,user.pw_uid,user.pw_gid); (DATA/'backups'/archive.name).chmod(0o600)
    start_recovering()
    assert 'source_stop_missing' in cli_json('status')['gaps'] and cli_json('status')['activation_permitted'] is False
    review_and_activate('NR04 rollback recovery',str(first_epoch)+','+str(second_epoch),second_node)
    assert identity()['keys'] == original['keys']
    passed('NR04')

    case = 'NR05'
    journal = run(['journalctl','-u',SERVICE,'-o','cat','--no-pager'])
    password = (ROOT/'authority-password').read_text()
    canary_log_scan.assert_log_clean('P06-NR05 controller journal',journal,[password,OFFLINE_KEY.read_text()],markers=['PRIVATE KEY-----'],min_bytes=32)
    assert not restore_root.exists() and not Path('/run/blindpass-controller-restore').exists(), 'restore staging outlived its unit'
    # The lost states were private to the service account; remove them with the restore state.
    for leftover in ('lost-data-one','lost-keys-one','lost-data-two','lost-keys-two'):
        shutil.rmtree(ROOT/leftover,ignore_errors=True)
    shutil.rmtree(restore_state,ignore_errors=True)
    refreshed = identity(); REFERENCE.write_text(json.dumps(refreshed)); REFERENCE.chmod(0o600)
    passed('NR05')


def native_credential_faults():
    global case
    case = 'NB07'
    run(['systemctl','disable','--now',BACKUP_TIMER])
    output = DATA/'backups'
    archive = next(output.glob('*.bpbackup'))
    original = hashlib.sha256(archive.read_bytes()).digest()

    def refusal(name):
        print('P06-NB07 checking='+name+' expected_refusal=True',flush=True)
        before = show('ExecMainStartTimestampMonotonic',BACKUP)
        started = time.monotonic()
        run(['systemctl','start',BACKUP],success=False)
        assert time.monotonic()-started < 10
        assert show('Result',BACKUP_CHECK) == 'exit-code'
        assert show('ExecMainStartTimestampMonotonic',BACKUP) == before, 'backup executed despite unsafe original custody'
        assert list(output.iterdir()) == [archive]
        assert hashlib.sha256(archive.read_bytes()).digest() == original
        ready(); same_identity()
        # The dependency-refused backup never ran and may already be unloaded.
        # Reset only the failed preflight, whose failure we just inspected.
        run(['systemctl','reset-failed',BACKUP_CHECK])
        passed('NB07-'+name)

    for target,label in ((SIGNING,'signing'),(RECIPIENT,'recipient')):
        target.chmod(0o644)
        try:
            refusal(label+'-mode')
        finally:
            target.chmod(0o600)
        user = pwd.getpwnam('blindpass')
        os.chown(target,user.pw_uid,user.pw_gid)
        try:
            refusal(label+'-owner')
        finally:
            os.chown(target,0,0)
        linked = PRIVATE/'linked-recovery'
        os.link(target,linked)
        try:
            refusal(label+'-hardlink')
        finally:
            linked.unlink()
        for kind in ['symlink','fifo','oversized']:
            saved = PRIVATE/'original-recovery'
            target.rename(saved)
            try:
                if kind == 'symlink':
                    target.symlink_to(saved)
                elif kind == 'fifo':
                    os.mkfifo(target,0o600)
                else:
                    with target.open('xb') as file:
                        target.chmod(0o600)
                        file.write(b'P06-DUMMY-OVERSIZED-'+bytes(16384))
                refusal(label+'-'+kind)
            finally:
                target.unlink()
                saved.rename(target)
    BACKUP_ENABLED.chmod(0o644)
    try:
        refusal('marker-mode')
    finally:
        BACKUP_ENABLED.chmod(0o600)
    parent = SIGNING.parent
    mode = stat.S_IMODE(parent.stat().st_mode)
    parent.chmod(mode | 0o020)
    try:
        refusal('parent-mode')
    finally:
        parent.chmod(mode)
    run(['systemctl','start',BACKUP_CHECK])
    assert show('Result',BACKUP_CHECK) == 'success'
    backup_verify(archive)
    passed(case)


def native_tool_faults():
    global case
    case = 'NB06'
    run(['systemctl','disable','--now',BACKUP_TIMER])
    output = DATA/'backups'
    archives = list(output.glob('*.bpbackup'))
    assert len(archives) == 1
    archive = archives[0]
    original_archive = hashlib.sha256(archive.read_bytes()).digest()
    executable = Path('/usr/bin/openssl')
    saved = PRIVATE/'openssl-original'
    original_executable = hashlib.sha256(executable.read_bytes()).digest()
    original_mode = executable.stat().st_mode
    executable.rename(saved)
    try:
        started = time.monotonic()
        run(['systemctl','start',BACKUP],success=False)
        missing_elapsed = time.monotonic()-started
        assert missing_elapsed < 10 and show('ExecMainStatus',BACKUP) == '1'
        invocation = show('InvocationID',BACKUP)
        journal = run(['journalctl','_SYSTEMD_INVOCATION_ID='+invocation,'-o','cat','--no-pager'])
        assert 'blindpass-controller: backup tool unavailable' in journal
        assert list(output.iterdir()) == [archive]
        assert not Path('/run/credentials/'+BACKUP).exists()
        ready(); same_identity()
        passed('NB06-missing')

        # Exec preserves the actual tool PID and its inherited limits. The
        # fixture does not read its private stdin descriptor or print anything.
        with executable.open('xb') as file:
            file.write(b'#!/bin/sh\nexec /bin/sleep 300\n')
        executable.chmod(0o755)
        run(['systemctl','reset-failed',BACKUP])
        started = time.monotonic()
        run(['systemctl','start','--no-block',BACKUP])
        # The ordered custody dependency runs before the backup cgroup exists.
        # Observe this queued start; never retry the start operation itself.
        expected_group = '/system.slice/'+BACKUP
        while True:
            group = show('ControlGroup',BACKUP)
            procs = Path('/sys/fs/cgroup')/group.lstrip('/')/'cgroup.procs'
            if group == expected_group and procs.is_file():
                break
            assert time.monotonic()-started < 10, 'backup cgroup startup deadline'
            assert show('ActiveState',BACKUP) != 'failed', 'backup failed before tool observation'
            time.sleep(.05)
        sleeping = None
        requests = 0
        while time.monotonic()-started < 70:
            try:
                pids = procs.read_text().splitlines()
            except FileNotFoundError:
                pids = []
            for pid in pids:
                process = Path('/proc')/pid
                try:
                    if process.joinpath('cmdline').read_bytes().split(b'\0')[:2] == [b'/bin/sleep',b'300']:
                        sleeping = (pid, process.joinpath('stat').read_text().rsplit(')',1)[1].split()[19])
                        status = process.joinpath('status').read_text()
                        assert 'NoNewPrivs:\t1' in status
                        core = next(line for line in process.joinpath('limits').read_text().splitlines() if line.startswith('Max core file size'))
                        assert core.split()[4:6] == ['0','0']
                except FileNotFoundError:
                    pass
            if sleeping and not pids:
                break
            status,body,_ = get('/readyz')
            assert status == 200 and json.loads(body)['ok'] is True
            requests += 1
            time.sleep(.2)
        stalled_elapsed = time.monotonic()-started
        assert sleeping and 60 <= stalled_elapsed < 70 and requests > 10
        assert show('ActiveState',BACKUP) == 'failed' and show('ExecMainStatus',BACKUP) == '1'
        process = Path('/proc')/sleeping[0]/'stat'
        assert not process.exists() or process.read_text().rsplit(')',1)[1].split()[19] != sleeping[1], 'timed-out child was not reaped'
        invocation = show('InvocationID',BACKUP)
        journal = run(['journalctl','_SYSTEMD_INVOCATION_ID='+invocation,'-o','cat','--no-pager'])
        assert 'blindpass-controller: backup tool timed out' in journal
        assert list(output.iterdir()) == [archive]
        assert not Path('/run/credentials/'+BACKUP).exists()
        assert hashlib.sha256(archive.read_bytes()).digest() == original_archive
        ready(); same_identity()
        with sqlite3.connect(DATA/'controller.db') as connection:
            assert connection.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
            assert connection.execute('SELECT length(dummy) FROM native_backup_payload WHERE id=1').fetchone()[0] == 8388608
        print('P06-NB06 missing_seconds='+format(missing_elapsed,'.3f')+' stalled_seconds='+format(stalled_elapsed,'.3f')+' successful_ready_probes='+str(requests)+' child_reaped=True private_staging_removed=True',flush=True)
    finally:
        if executable.exists():
            executable.unlink()
        saved.rename(executable)
    assert hashlib.sha256(executable.read_bytes()).digest() == original_executable
    assert executable.stat().st_mode == original_mode
    run(['systemctl','reset-failed',BACKUP])
    backup_verify(archive)
    passed(case)


def service_python(code):
    """Run Python as the service account, so state files never become root-owned."""
    return run(['runuser','-u','blindpass','--','python3','-c',code])


def native_upgrade():
    """P06-N10: forward upgrade with an automatic verified pre-upgrade backup.
    The same verified binaries are repacked as 0.1.1; the older schema is a real
    schema-18 database made by removing the schema-19 and schema-20 tables and marker."""
    global case
    case = 'N10'
    unit = 'blindpass-controller-upgrade.service'
    upgraded = ROOT/'upgrade-bundle'; shutil.copytree(BUNDLE,upgraded)
    manifest = json.loads((upgraded/'manifest.json').read_text())
    manifest['version'] = '0.1.1'; (upgraded/'manifest.json').write_text(json.dumps(manifest))
    install('--upgrade',success=False,bundle=upgraded)          # controller still running
    assert show('ActiveState') == 'active'; same_identity()
    run(['systemctl','stop',SERVICE])
    older = ROOT/'older-bundle'; shutil.copytree(BUNDLE,older)
    manifest['version'] = '0.0.9'; (older/'manifest.json').write_text(json.dumps(manifest))
    install('--upgrade',success=False,bundle=older)             # downgrade is restore-only
    install('--upgrade',success=False)                          # the installed artifact is not an upgrade
    for target in CUSTODY:
        target.chmod(0o644); install('--upgrade',success=False,bundle=upgraded); target.chmod(0o600)
    install('--upgrade','--start',success=False,bundle=upgraded)
    marker = lambda: json.loads(Path('/etc/blindpass/controller-install.json').read_text())
    assert marker()['version'] == '0.1.0', 'refused upgrades changed the install record'
    assert Path('/opt/blindpass/controller/current').readlink() == Path('0.1.0')
    result = json.loads(install('--upgrade',bundle=upgraded))
    assert result['ok'] and result['upgraded'] is True and result['version'] == '0.1.1'
    assert Path('/opt/blindpass/controller/current').readlink() == Path('0.1.1')
    assert Path('/opt/blindpass/controller/0.1.0').is_dir() and Path('/opt/blindpass/controller/0.1.1').is_dir()
    assert marker()['version'] == '0.1.1' and set(marker()['versions']) == {'0.1.0','0.1.1'}
    assert Path('/etc/systemd/system/'+unit).is_file()
    same_identity()
    # The stopped controller's record is still active: migration needs the fence.
    run(['systemctl','start',unit],success=False)
    assert not (DATA/'pre-upgrade-backups').exists()
    fence()
    # Make the stored schema genuinely older (18): schemas 19 and 20 only add tables.
    service_python('import sqlite3; c=sqlite3.connect("/var/lib/blindpass/controller/controller.db"); '
                   '[c.execute("DROP TABLE "+t) for t in ("cross_fulfillment_payloads","cross_fulfillments","controller_recovery_intents","controller_recovery_reports")]; '
                   'c.execute("UPDATE controller_meta SET schema_version=18 WHERE id=1"); c.commit(); '
                   'c.execute("PRAGMA wal_checkpoint(TRUNCATE)"); c.close()')
    version = lambda: int(service_python('import sqlite3; print(sqlite3.connect("file:/var/lib/blindpass/controller/controller.db?mode=ro",uri=True)'
                                          '.execute("SELECT schema_version FROM controller_meta").fetchone()[0])'))
    assert version() == 18
    # No recovery key, no upgrade: the older schema is untouched.
    last_start = show('ExecMainStartTimestampMonotonic',unit)   # the earlier refused run set it
    for target in CUSTODY:
        saved = ROOT/'upgrade-custody.pem'; target.rename(saved)
        run(['systemctl','start',unit]); assert show('ExecMainStartTimestampMonotonic',unit) == last_start, 'unit ran without '+target.name
        assert version() == 18
        saved.rename(target)
    run(['systemctl','start',unit])
    assert show('Result',unit) == 'success' and show('ExecMainStatus',unit) == '0'
    assert version() == 20
    backups = sorted((DATA/'pre-upgrade-backups').iterdir())
    assert len(backups) == 1 and re.fullmatch(r'pre-upgrade-\d{13}-v18',backups[0].name)
    archives = list(backups[0].glob('*.bpbackup')); assert len(archives) == 1
    backup_verify(archives[0])
    for path in [DATA/'pre-upgrade-backups',backups[0],archives[0]]:
        info = path.stat()
        assert info.st_uid == pwd.getpwnam('blindpass').pw_uid and stat.S_IMODE(info.st_mode) == (0o700 if path.is_dir() else 0o600)
    journal = run(['journalctl','-u',unit,'-o','cat','--no-pager'])
    assert '"from_schema":18' in journal and '"backup_taken":true' in journal
    canary_log_scan.assert_log_clean('P06-U upgrade unit journal',journal,[str(DATA)],markers=['BEGIN PRIVATE KEY'],require=['"from_schema":18'])
    assert not Path('/run/credentials/'+unit).exists(), 'credential copy outlived the unit'
    # Repeating a completed upgrade takes no further backup.
    run(['systemctl','start',unit]); assert len(list((DATA/'pre-upgrade-backups').iterdir())) == 1
    # The upgraded controller needs the usual fresh activation and keeps its identity.
    run(['systemctl','start',SERVICE]); never_ready(4)
    run(['systemctl','stop',SERVICE]); activate(); run(['systemctl','start',SERVICE]); ready(); same_identity()
    assert not any(path.name.startswith('.backup-') for path in DATA.iterdir())
    shutil.rmtree(upgraded); shutil.rmtree(older)
    passed(case)


def after_backup():
    global case
    case = 'N08'
    other = Path('/etc/systemd/system/blindpass-backup.service')
    sentinel = b'# P06 unrelated broker backup probe sentinel\n[Unit]\nDescription=P06 untouched probe\n'
    other.write_bytes(sentinel)
    protected = ROOT/'protected'; protected.write_bytes(b'P06-DUMMY-PURGE-SENTINEL')
    uninstall(); assert not Path('/usr/local/bin/blindpass').is_symlink()
    uninstall()  # Already removed programs/units; retained identity is unchanged.
    same_identity(); assert other.read_bytes() == sentinel
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in CUSTODY) and BACKUP_ENABLED.exists()
    assert (AUTHORITY_DIR/'authority-url').is_file(), 'uninstall removed retained authority custody'
    install('--initialize',success=False); activate(); install('--start'); ready(); same_identity()
    assert other.read_bytes() == sentinel
    assert show('UnitFileState',BACKUP_TIMER) == 'disabled'
    backup_verify(next((DATA/'backups').glob('*.bpbackup')))
    passed(case)
    native_upgrade()

    case = 'N09'
    uninstall('--purge','--confirm-purge','wrong',success=False)
    assert show('ActiveState') == 'active'; same_identity()
    for target in CUSTODY:
        saved = ROOT/'saved-custody.pem'; target.rename(saved)
        target.symlink_to(protected)
        uninstall('--purge','--confirm-purge','blindpass-controller',success=False)
        assert show('ActiveState') == 'active' and protected.read_bytes() == b'P06-DUMMY-PURGE-SENTINEL'
        target.unlink(); saved.rename(target)
        target.chmod(0o644)
        uninstall('--purge','--confirm-purge','blindpass-controller',success=False)
        assert show('ActiveState') == 'active'
        target.chmod(0o600)
    (DATA/'unsafe').symlink_to(protected)
    uninstall('--purge','--confirm-purge','blindpass-controller',success=False)
    assert show('ActiveState') == 'active' and protected.read_bytes() == b'P06-DUMMY-PURGE-SENTINEL'
    (DATA/'unsafe').unlink()
    uninstall('--purge','--confirm-purge','blindpass-controller')
    assert not KEYS.exists() and not DATA.exists() and not CONFIG.exists()
    assert not Path('/opt/blindpass/controller/0.1.1').exists(), 'purge left an upgraded program tree'
    assert not Path('/etc/blindpass/controller-tls').exists() and not AUTHORITY_DIR.exists()
    assert not SIGNING.exists() and not RECIPIENT.exists() and not BACKUP_ENABLED.exists()
    assert OFFLINE_KEY.is_file() and OFFLINE_SIGNER.is_file(), 'purge removed separate offline custody'
    assert other.read_bytes() == sentinel and protected.read_bytes() == b'P06-DUMMY-PURGE-SENTINEL'
    assert json.loads(Path('/etc/blindpass/controller-install.json').read_text())['purged'] is True
    # Explicit confirmed purge permits a new tenant, never a restoration shortcut.
    fresh_authority_install(TENANT+'_2','--tls-cert',CERT,'--tls-key',KEY)
    activate(); install('--start')
    ready(); assert identity()['keys'] != saved_identity()['keys'] and identity()['meta'] != saved_identity()['meta']
    uninstall('--purge','--confirm-purge','blindpass-controller')
    passed(case)


def power_loss_prepare():
    global case
    case = 'NB05-prepare'
    run(['systemctl','disable','--now',BACKUP_TIMER])
    output = DATA/'backups'
    archives = list(output.glob('*.bpbackup'))
    assert len(archives) == 1
    run(['runuser','-u','blindpass','--','python3','-c',
         'import sqlite3; c=sqlite3.connect("/var/lib/blindpass/controller/controller.db"); c.execute("UPDATE native_backup_payload SET dummy = zeroblob(201326592) WHERE id=1"); c.commit(); c.close()'])
    reference = {'identity': identity(), 'archive': archives[0].name,
                 'archive_hash': hashlib.sha256(archives[0].read_bytes()).hexdigest(),
                 'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text()}
    (ROOT/'power-reference.json').write_text(json.dumps(reference))
    (ROOT/'power-reference.json').chmod(0o600)
    # Only the known-good source/reference are flushed before the fault job.
    os.sync()
    started = time.monotonic()
    run(['systemctl','start','--no-block',BACKUP])
    # Resolve the exact unit cgroup during capture, before encryption output
    # appears, allowing the ordered custody dependency to finish. A D-Bus query
    # after observing output can miss the short write. Do not retry the start.
    while True:
        group = show('ControlGroup',BACKUP)
        cgroup = Path('/sys/fs/cgroup')/group.lstrip('/')
        if group == '/system.slice/'+BACKUP and (cgroup/'cgroup.procs').is_file():
            break
        assert time.monotonic()-started < 10, 'backup cgroup startup deadline'
        assert show('ActiveState',BACKUP) != 'failed', 'backup failed before encryption observation'
        time.sleep(.05)
    deadline = started+30
    observed = None
    while time.monotonic() < deadline:
        for path in output.rglob('encrypted.der'):
            try:
                if path.stat().st_size > 1024*1024:
                    (cgroup/'cgroup.freeze').write_text('1')
                    observed = path
                    break
            except FileNotFoundError:
                pass
        if observed:
            break
        time.sleep(.001)
    if observed is None:
        print('P06-NB05 progress_missing available_bytes='+str(os.statvfs(DATA).f_bavail*os.statvfs(DATA).f_frsize),flush=True)
        for name in ['controller.db','controller.db-wal','controller.db-shm']:
            path = DATA/name
            if path.exists():
                info = path.stat()
                print('P06-NB05 source_file='+name+' uid='+str(info.st_uid)+' mode='+oct(stat.S_IMODE(info.st_mode))+' bytes='+str(info.st_size),flush=True)
    assert observed is not None, 'encryption progress deadline exceeded'
    # Type=oneshot retains its start job until encryption finishes; systemd's
    # FreezeUnit API refuses a unit with a pending job. As guest Root, freeze
    # only the exact service cgroup directly and observe the kernel event.
    freeze_deadline = time.monotonic()+5
    while 'frozen 1' not in (cgroup/'cgroup.events').read_text():
        assert time.monotonic() < freeze_deadline, 'kernel freezer deadline exceeded'
        time.sleep(.005)
    plain_bytes = (observed.parent.parent/'archive.tar').stat().st_size
    partial_bytes = observed.stat().st_size
    print('P06-NB05 observed_sizes partial_bytes='+str(partial_bytes)+' plaintext_archive_bytes='+str(plain_bytes),flush=True)
    # openssl writes the ciphertext in one large write(2) that the freezer cannot split:
    # the frozen size is the last whole page of the final file, so it can exceed the
    # plaintext size by the envelope overhead (a second recipient adds about 500 bytes).
    # Incomplete encryption is proven by the live `-encrypt` child below, not by size.
    assert 1024*1024 < partial_bytes <= plain_bytes + 8192
    encrypting = False
    for pid in (cgroup/'cgroup.procs').read_text().splitlines():
        args = Path('/proc/'+pid+'/cmdline').read_bytes().split(b'\0')
        if args and args[0] == b'/usr/bin/openssl' and b'-encrypt' in args:
            encrypting = True
    assert encrypting, 'no frozen encryption child observed'
    assert list(output.glob('*.bpbackup')) == archives
    # No sync, thaw, stop or guest shutdown after freezing partial encryption.
    print('P06-NB05 encryption_progress_observed=True child_frozen=True partial_bytes='+str(partial_bytes)+' plaintext_archive_bytes='+str(plain_bytes),flush=True)


def power_loss_recover():
    global case
    case = 'NB05-recover'
    reference = json.loads((ROOT/'power-reference.json').read_text())
    assert Path('/proc/sys/kernel/random/boot_id').read_text() != reference['boot_id']
    assert json.loads(json.dumps(identity())) == reference['identity']
    output = DATA/'backups'
    archive = output/reference['archive']
    assert list(output.glob('*.bpbackup')) == [archive]
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == reference['archive_hash']
    user = pwd.getpwnam('blindpass')
    residues = list(output.glob('.backup-*'))
    assert residues, 'no persisted interruption staging was observed'
    for directory in residues:
        for path in [directory,*directory.rglob('*')]:
            info = path.lstat()
            expected = 0o700 if stat.S_ISDIR(info.st_mode) else 0o600
            assert (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode))
            assert info.st_uid == user.pw_uid and stat.S_IMODE(info.st_mode) == expected
    assert not Path('/run/credentials/'+BACKUP).exists()
    assert show('ActiveState',BACKUP_TIMER) == 'inactive'
    # A new boot must retain the inherited clock fence until reconciliation.
    # The enabled unit already failed on the used revision; grant one start.
    run(['systemctl','stop',SERVICE]); activate(); run(['systemctl','start',SERVICE])
    for _ in range(40):
        try:
            status,_,_ = get('/readyz')
            if status == 503:
                break
            assert status != 200, 'new boot became ready before reconciliation'
        except OSError:
            pass
        time.sleep(.25)
    else:
        raise AssertionError('clock-fenced readiness was not observed')
    cleanup = run(['runuser','-u','blindpass','--','/opt/blindpass/controller/current/bin/blindpass',
                   'backup','cleanup','--work-directory',output])
    assert json.loads(cleanup)['removed_staging_directories'] == len(residues)
    assert list(output.iterdir()) == [archive]
    backup_verify(archive)
    with sqlite3.connect(DATA/'controller.db') as connection:
        assert connection.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
        assert connection.execute('SELECT length(dummy) FROM native_backup_payload WHERE id=1').fetchone()[0] == 201326592
    run(['systemctl','stop',SERVICE])
    fence(); run(['systemctl','start','blindpass-controller-reconcile-clock.service'])
    activate(); run(['systemctl','start',SERVICE]); ready(); same_identity()
    print('P06-NB05 private_residues='+str(len(residues))+' prior_archive_verified=True identity_payload_keys_intact=True credentials_gone=True',flush=True)
    passed('NB05')
    after_backup()


def main():
    try:
        if sys.argv[1] == 'before-reboot': before_reboot()
        elif sys.argv[1] == 'after-reboot': after_reboot()
        elif sys.argv[1] == 'after-reboot-power-loss': after_reboot(power_loss=True)
        elif sys.argv[1] == 'after-reboot-tool-faults': after_reboot(tool_faults=True)
        elif sys.argv[1] == 'after-reboot-credential-faults': after_reboot(credential_faults=True)
        elif sys.argv[1] == 'after-reboot-recovery': after_reboot(recovery=True)
        elif sys.argv[1] == 'after-reboot-faults': after_reboot(faults=True)
        elif sys.argv[1] == 'after-reboot-rollback': after_reboot(rollback=True)
        elif sys.argv[1] == 'power-loss-prepare': power_loss_prepare()
        elif sys.argv[1] == 'power-loss-recover': power_loss_recover()
        else: raise AssertionError('unknown stage')
    except Exception as error:
        import traceback
        frames = [frame for frame in traceback.extract_tb(error.__traceback__) if frame.filename == __file__ or Path(frame.filename).name == 'native_rollback.py']
        frame = frames[-1]
        print('P06-'+case+' FAIL line='+str(frame.lineno)+' file='+Path(frame.filename).name+' type='+type(error).__name__+' (private guest diagnostics withheld)',flush=True)
        if case == 'N02' and Path('/etc/systemd/system/blindpass-controller-initialize.service').exists():
            # Numeric metadata only, inside the failing unit's credential namespace.
            probe = Path('/etc/systemd/system/blindpass-controller-initialize.service.d/probe.conf')
            probe.parent.mkdir(exist_ok=True)
            probe.write_text('[Service]\nExecStartPre=/usr/bin/stat -c P06-CREDENTIAL:%u:%g:%a:%h:%s %d/root-secret\nExecStartPre=/usr/bin/namei -l %d/root-secret\n')
            subprocess.run(['systemctl','daemon-reload'],capture_output=True)
            subprocess.run(['systemctl','start','blindpass-controller-initialize.service'],capture_output=True,timeout=60)
        sys.exit(1)


if __name__ == '__main__':
    main()
