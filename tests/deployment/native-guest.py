#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""P06-N01–N09, inside a disposable real-systemd guest only. No secret output."""
import hashlib
import http.client
import json
import os
from pathlib import Path
import pwd
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

ROOT = Path('/root/p06-native')
BUNDLE = ROOT / 'bundle'
DATA = Path('/var/lib/blindpass/controller')
KEYS = Path('/etc/blindpass/keys')
CONFIG = Path('/etc/blindpass/controller.env')
PRIVATE = ROOT / 'private'
CERT = PRIVATE / 'cert.pem'
KEY = PRIVATE / 'key.pem'
REFERENCE = ROOT / 'reference.json'
SERVICE = 'blindpass-controller.service'
case = 'setup'


def run(args, success=True):
    result = subprocess.run([str(value) for value in args], stdin=subprocess.DEVNULL,
                            capture_output=True, timeout=90)
    if success and result.returncode != 0:
        diagnostics = ROOT/'private-diagnostics.txt'
        diagnostics.write_bytes(result.stdout+result.stderr); diagnostics.chmod(0o600)
    if success: assert result.returncode == 0, 'command failed'
    else: assert result.returncode != 0, 'command unexpectedly accepted'
    return result.stdout.decode()


def install(*args, success=True, bundle=BUNDLE):
    return run(['python3', bundle/'deploy/native/controller-install.py', '--bundle',bundle,*args],success)


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
    for _ in range(40):
        try:
            status,body,_ = get('/readyz')
            if status == 200 and json.loads(body)['ok'] is True: return
        except (OSError,ValueError): pass
        time.sleep(.25)
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


def before_reboot():
    global case
    case = 'N01'
    assert os.getuid() == 0 and Path('/run/systemd/system').is_dir()
    assert not DATA.exists() and not KEYS.exists()
    install('--verify-only')
    bad = ROOT / 'tampered'; shutil.copytree(BUNDLE,bad)
    with (bad/'bin/blindpass').open('ab') as target: target.write(b'P06-DUMMY-TAMPER')
    install('--public-url','https://localhost:3200','--initialize',success=False,bundle=bad)
    assert not DATA.exists() and not KEYS.exists()
    try: pwd.getpwnam('blindpass'); raise AssertionError('preflight created account')
    except KeyError: pass
    shutil.rmtree(bad)
    malformed = ROOT/'malformed.pem'; malformed.write_bytes(b'P06-DUMMY-TLS-CANARY'); malformed.chmod(0o600)
    install('--public-url','https://localhost:3200','--tls-cert',malformed,'--tls-key',malformed,'--initialize',success=False)
    assert not KEYS.exists() and not DATA.exists(); malformed.unlink()
    run(['useradd','--system','--home-dir','/nonexistent','--shell','/bin/sh','blindpass'])
    install('--public-url','https://localhost:3200','--initialize',success=False)
    assert not KEYS.exists() and not DATA.exists()
    run(['userdel','blindpass'])
    collision = Path('/etc/systemd/system/blindpass-controller.service')
    collision.write_bytes(b'# P06-DUMMY-UNMANAGED-UNIT\n')
    install('--public-url','https://localhost:3200','--initialize',success=False)
    assert collision.read_bytes() == b'# P06-DUMMY-UNMANAGED-UNIT\n' and not KEYS.exists()
    collision.unlink()
    passed(case)
    case = 'N02'
    PRIVATE.mkdir(mode=0o700)
    run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','2','-keyout',KEY,
         '-out',CERT,'-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1'])
    KEY.chmod(0o600); CERT.chmod(0o600)
    other_key = PRIVATE/'mismatched.pem'
    run(['openssl','genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:2048','-out',other_key])
    other_key.chmod(0o600)
    install('--public-url','https://localhost:3200','--initialize','--tls-cert',CERT,'--tls-key',other_key,success=False)
    assert not KEYS.exists() and not DATA.exists(); other_key.unlink()
    result = json.loads(install('--public-url','https://localhost:3200','--initialize','--start','--tls-cert',CERT,'--tls-key',KEY))
    assert result['ok'] is True and result['initialized'] is True
    print('P06-N02 install='+json.dumps(result,sort_keys=True),flush=True)
    ready()
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
    run(['systemctl','start',SERVICE]); ready(); same_identity()
    assert show('UnitFileState') == 'enabled'
    (ROOT/'boot-id').write_text(Path('/proc/sys/kernel/random/boot_id').read_text())
    passed(case)


def after_reboot():
    global case
    case = 'N04-reboot'
    assert Path('/proc/sys/kernel/random/boot_id').read_text() != (ROOT/'boot-id').read_text()
    run(['systemctl','stop',SERVICE])
    run(['systemctl','start','blindpass-controller-reconcile-clock.service'])
    run(['systemctl','start',SERVICE]); ready(); same_identity()
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
    case = 'N06'
    run(['systemctl','stop',SERVICE])
    KEYS.rename(ROOT/'saved-keys')
    failed_start()
    install('--initialize',success=False); install('--start',success=False)
    assert not KEYS.exists()
    (ROOT/'saved-keys').rename(KEYS)
    run(['systemctl','reset-failed',SERVICE])
    DATA.rename(ROOT/'saved-data')
    failed_start()
    install('--initialize',success=False); install('--start',success=False)
    assert not (DATA/'controller.db').exists()
    run(['systemctl','stop',SERVICE]); shutil.rmtree(DATA)
    (ROOT/'saved-data').rename(DATA)
    run(['systemctl','reset-failed',SERVICE]); run(['systemctl','start',SERVICE]); ready(); same_identity()
    passed(case)
    case = 'N07'
    timer = 'blindpass-controller-backup.timer'; backup = 'blindpass-controller-backup.service'
    assert show('UnitFileState',timer) == 'disabled' and show('ActiveState',timer) == 'inactive'
    run(['systemctl','start',backup]); assert show('ActiveState',backup) == 'inactive'
    assert show('ExecMainStartTimestampMonotonic',backup) == '0' and not (DATA/'backups').exists()
    assert not Path('/etc/blindpass/controller-backup-recovery-key').exists()
    passed(case)
    case = 'N08'
    other = Path('/etc/systemd/system/blindpass-backup.service')
    sentinel = b'# P06 unrelated broker backup probe sentinel\n[Unit]\nDescription=P06 untouched probe\n'
    other.write_bytes(sentinel)
    protected = ROOT/'protected'; protected.write_bytes(b'P06-DUMMY-PURGE-SENTINEL')
    uninstall(); assert not Path('/usr/local/bin/blindpass').is_symlink()
    uninstall()  # Already removed programs/units; retained identity is unchanged.
    same_identity(); assert other.read_bytes() == sentinel
    install('--initialize',success=False); install('--start'); ready(); same_identity()
    assert other.read_bytes() == sentinel
    passed(case)
    case = 'N09'
    uninstall('--purge','--confirm-purge','wrong',success=False)
    assert show('ActiveState') == 'active'; same_identity()
    (DATA/'unsafe').symlink_to(protected)
    uninstall('--purge','--confirm-purge','blindpass-controller',success=False)
    assert show('ActiveState') == 'active' and protected.read_bytes() == b'P06-DUMMY-PURGE-SENTINEL'
    (DATA/'unsafe').unlink()
    uninstall('--purge','--confirm-purge','blindpass-controller')
    assert not KEYS.exists() and not DATA.exists() and not CONFIG.exists()
    assert not Path('/etc/blindpass/controller-tls').exists()
    assert other.read_bytes() == sentinel and protected.read_bytes() == b'P06-DUMMY-PURGE-SENTINEL'
    assert json.loads(Path('/etc/blindpass/controller-install.json').read_text())['purged'] is True
    # Explicit confirmed purge permits a new tenant, never a restoration shortcut.
    install('--public-url','https://localhost:3200','--initialize','--start','--tls-cert',CERT,'--tls-key',KEY)
    ready(); assert identity()['keys'] != saved_identity()['keys'] and identity()['meta'] != saved_identity()['meta']
    uninstall('--purge','--confirm-purge','blindpass-controller')
    passed(case)


try:
    if sys.argv[1] == 'before-reboot': before_reboot()
    elif sys.argv[1] == 'after-reboot': after_reboot()
    else: raise AssertionError('unknown stage')
except Exception as error:
    import traceback
    frames = [frame for frame in traceback.extract_tb(error.__traceback__) if frame.filename == __file__]
    frame = frames[-1]
    print('P06-'+case+' FAIL line='+str(frame.lineno)+' type='+type(error).__name__+' (private guest diagnostics withheld)',flush=True)
    if case == 'N02' and Path('/etc/systemd/system/blindpass-controller-initialize.service').exists():
        # Numeric metadata only, inside the failing unit's credential namespace.
        probe = Path('/etc/systemd/system/blindpass-controller-initialize.service.d/probe.conf')
        probe.parent.mkdir(exist_ok=True)
        probe.write_text('[Service]\nExecStartPre=/usr/bin/stat -c P06-CREDENTIAL:%u:%g:%a:%h:%s %d/root-secret\nExecStartPre=/usr/bin/namei -l %d/root-secret\n')
        subprocess.run(['systemctl','daemon-reload'],capture_output=True)
        subprocess.run(['systemctl','start','blindpass-controller-initialize.service'],capture_output=True,timeout=60)
    sys.exit(1)
