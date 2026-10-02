#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Native controller lifecycle. No shell evaluation or implicit trust repair."""
import argparse
import fcntl
import grp
import hashlib
import json
import os
from pathlib import Path
import platform
import pwd
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit

PREFIX = Path('/opt/blindpass/controller')
CONFIG = Path('/etc/blindpass/controller.env')
MARKER = Path('/etc/blindpass/controller-install.json')
KEYS = Path('/etc/blindpass/keys')
DATA = Path('/var/lib/blindpass/controller')
TLS = Path('/etc/blindpass/controller-tls')
UNIT_DIR = Path('/etc/systemd/system')
UNITS = ['blindpass-controller.service', 'blindpass-controller-initialize.service',
         'blindpass-controller-reconcile-clock.service',
         'blindpass-controller-backup.service', 'blindpass-controller-backup.timer']
NATIVE_FILES = UNITS + ['blindpass-controller.sysusers', 'blindpass-controller.tmpfiles',
                        'controller-install.py', 'install.sh', 'uninstall.sh']
INITIALIZED = Path('/etc/blindpass/controller-initialized')
TLS_DROPIN = b'[Service]\nLoadCredential=tls-cert:/etc/blindpass/controller-tls/cert.pem\nLoadCredential=tls-key:/etc/blindpass/controller-tls/key.pem\nEnvironment=BLINDPASS_TLS_CERT_FILE=%d/tls-cert\nEnvironment=BLINDPASS_TLS_KEY_FILE=%d/tls-key\n'
TLS_UNITS = ['blindpass-controller.service', 'blindpass-controller-initialize.service',
             'blindpass-controller-reconcile-clock.service']


class Refusal(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Refusal(message)


def read_regular(path, limit=None):
    # Check every parent component without following symlinks. Installation
    # sources are operator-selected; publication uses a root-owned staging dir.
    for parent in reversed(path.absolute().parents):
        require(not parent.is_symlink(), 'linked path refused')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as source:
        info = os.fstat(source.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'nonregular or linked file refused')
        require(limit is None or info.st_size <= limit, 'oversized input refused')
        payload = source.read() if limit is None else source.read(limit + 1)
        require(limit is None or len(payload) <= limit, 'oversized input refused')
        return payload


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate metadata field refused')
        result[key] = value
    return result


def verify_bundle(root):
    require(root.is_dir() and not root.is_symlink(), 'unsafe bundle directory')
    manifest = json.loads(read_regular(root / 'manifest.json', 2 * 1024 * 1024), object_pairs_hook=unique_object)
    require(isinstance(manifest, dict) and isinstance(manifest.get('controller'), dict), 'invalid controller metadata')
    require(manifest.get('format_version') == 1 and manifest.get('profile') == 'controller', 'wrong bundle profile')
    version = manifest.get('version', '')
    require(isinstance(version, str) and re.fullmatch(r'\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?', version), 'unsafe bundle version')
    arch = manifest.get('architecture')
    require(arch in ['x86_64','aarch64'] and arch == platform.machine(), 'bundle architecture mismatch')
    require(manifest.get('controller', {}).get('console_embedded') is True
            and manifest.get('controller', {}).get('input_embedded') is True, 'embedded UI required')
    members = manifest.get('members')
    require(isinstance(members, dict) and len(members) <= 4096, 'invalid member inventory')
    for name in NATIVE_FILES:
        require('deploy/native/' + name in members, 'native lifecycle member absent')
    actual = set()
    for count, path in enumerate(root.rglob('*')):
        require(count < 8192, 'oversized bundle inventory')
        require(not path.is_symlink(), 'linked bundle member refused')
        if path.is_file():
            actual.add(path.relative_to(root).as_posix())
        else:
            require(path.is_dir(), 'nonregular bundle member refused')
    require(actual == set(members) | {'manifest.json'}, 'incomplete or unlisted bundle member')
    total_size = 0
    for name, record in members.items():
        require(isinstance(name,str) and isinstance(record,dict), 'invalid member metadata')
        relative = Path(name)
        require(not relative.is_absolute() and '..' not in relative.parts and relative.as_posix() == name, 'unsafe member path')
        payload = read_regular(root / relative, 128 * 1024 * 1024)
        total_size += len(payload)
        require(total_size <= 256 * 1024 * 1024, 'oversized controller bundle')
        mode = stat.S_IMODE((root / relative).stat().st_mode)
        require(mode in [0o644, 0o755] and f'{mode:04o}' == record.get('mode'), 'unsafe member mode')
        require(len(payload) == record.get('size') and hashlib.sha256(payload).hexdigest() == record.get('sha256'), 'bundle integrity mismatch')
    machine = 62 if arch == 'x86_64' else 183
    for name in ['bin/blindpass', 'bin/blindpass-controller']:
        require(name in members, 'controller executables absent')
        payload = read_regular(root / name, 128 * 1024 * 1024)
        require(len(payload) > 20 and payload[:4] == b'\x7fELF'
                and struct.unpack('<H', payload[18:20])[0] == machine, 'executable architecture mismatch')
    return manifest


def command(args, action):
    result = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=60)
    require(result.returncode == 0, action + ' failed; inspect sanitized service diagnostics')
    return result.stdout.strip()


def root_directory(path, mode=0o755):
    if path != Path('/'):
        root_directory(path.parent)
    if not path.exists():
        require(not path.is_symlink(), 'unsafe installation directory')
        path.mkdir(mode=mode)
        path.chmod(mode)
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022, 'unsafe installation directory')


def marker():
    if not MARKER.exists():
        require(not MARKER.is_symlink(), 'unsafe installation record')
        return None
    info = MARKER.lstat()
    root_directory(MARKER.parent)
    require(info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600, 'unsafe installation record')
    record = json.loads(read_regular(MARKER, 1024 * 1024), object_pairs_hook=unique_object)
    require(isinstance(record,dict) and isinstance(record.get('uid'),int)
            and isinstance(record.get('initialized'),bool) and isinstance(record.get('purged'),bool)
            and re.fullmatch(r'\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?', record.get('version','')),
            'invalid installation record')
    return record


def account():
    user = pwd.getpwnam('blindpass')
    require(0 < user.pw_uid < 1000 and 0 < user.pw_gid < 1000 and user.pw_gid == grp.getgrnam('blindpass').gr_gid
            and user.pw_dir == '/nonexistent' and user.pw_shell in ['/usr/sbin/nologin','/sbin/nologin'], 'unsafe existing controller account')
    require(os.getgrouplist('blindpass', user.pw_gid) == [user.pw_gid], 'controller account has extra privileges')
    status = command(['passwd','--status','blindpass'], 'account status check').split()
    require(len(status) >= 2 and status[1] == 'L', 'controller login must remain locked')
    return user


def private_directory(path, user, create=True):
    root_directory(path.parent)
    if not path.exists():
        require(create and not path.is_symlink(), 'retained controller directory is missing')
        path.mkdir(mode=0o700)
        os.chown(path, user.pw_uid, user.pw_gid)
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == user.pw_uid
            and info.st_gid == user.pw_gid and stat.S_IMODE(info.st_mode) == 0o700, 'unsafe controller directory')


def publish_file(path, payload, mode=0o644, gid=0):
    root_directory(path.parent)
    if path.exists() or path.is_symlink():
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == 0,
                'unsafe managed file refused')
    descriptor, temporary = tempfile.mkstemp(prefix='.blindpass-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as target:
            target.write(payload)
            os.fchmod(target.fileno(), mode)
            os.fchown(target.fileno(), 0, gid)
            target.flush(); os.fsync(target.fileno())
        os.replace(temporary, path)
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try: os.fsync(descriptor)
        finally: os.close(descriptor)
    finally:
        Path(temporary).unlink(missing_ok=True)


def safe_origin(value):
    parsed = urlsplit(value or '')
    require(parsed.scheme == 'https' and parsed.hostname and not parsed.username and not parsed.password
            and parsed.path in ['', '/'] and not parsed.query and not parsed.fragment
            and all(33 <= ord(character) < 127 and character not in '"\\%#' for character in value), 'explicit HTTPS origin required')
    require(parsed.port is None or 0 < parsed.port <= 65535, 'invalid HTTPS port')
    return value.rstrip('/')


def check_tls_pair(inputs):
    if not inputs: return
    # Maintained OpenSSL parsers validate the captured input before account or
    # trust creation. Child stdin/memory holds the PEM only for this operation;
    # stdout contains a public key, and all diagnostics remain private.
    public = []
    for name, args in [('cert.pem',['x509','-pubkey','-noout']), ('key.pem',['pkey','-pubout','-passin','pass:'])]:
        result = subprocess.run(['openssl',*args], input=inputs[name], capture_output=True, timeout=10)
        require(result.returncode == 0 and result.stdout, 'invalid or encrypted TLS input')
        public.append(result.stdout.strip())
    require(public[0] == public[1], 'TLS certificate and private key mismatch')
    result = subprocess.run(['openssl','x509','-noout','-checkend','0'], input=inputs['cert.pem'], capture_output=True, timeout=10)
    require(result.returncode == 0, 'expired TLS certificate refused')


def validate_units(native, tls, fresh=False):
    for name in UNITS:
        target = UNIT_DIR/name
        if target.exists() or target.is_symlink():
            require(not fresh and read_regular(target,32768) == native[name], 'unmanaged or modified controller unit')
        dropins = UNIT_DIR/(name+'.d')
        if dropins.exists() or dropins.is_symlink():
            root_directory(dropins)
            require(not fresh, 'unmanaged controller drop-in')
            for path in dropins.iterdir():
                require(tls and name in TLS_UNITS and path.name == 'tls.conf'
                        and read_regular(path,8192) == TLS_DROPIN, 'unmanaged or modified controller drop-in')


def validate_installed(root, expected_hash):
    root_directory(root)
    require(hashlib.sha256(read_regular(root/'manifest.json',2*1024*1024)).hexdigest() == expected_hash,
            'installed artifact mismatch')
    verify_bundle(root)
    for path in root.rglob('*'):
        info = path.lstat()
        require(info.st_uid == 0 and info.st_gid == 0 and not info.st_mode & 0o022,
                'installed artifact custody changed')


def install(options):
    bundle = options.bundle.absolute()
    manifest = verify_bundle(bundle)  # Before any account or state mutation.
    source = bundle / 'deploy/native'
    native = {name: read_regular(source / name, 65536) for name in NATIVE_FILES}
    tls_inputs = {}
    require(bool(options.tls_cert) == bool(options.tls_key), 'both private TLS files required')
    for name, path, limit in [('cert.pem', options.tls_cert, 256*1024), ('key.pem', options.tls_key, 16*1024)]:
        if path:
            info = path.lstat()
            require(stat.S_IMODE(info.st_mode) & 0o077 == 0, 'private TLS input required')
            tls_inputs[name] = read_regular(path.absolute(), limit)
    check_tls_pair(tls_inputs)
    previous = marker()
    purged = previous is not None and previous.get('purged') is True
    manifest_hash = hashlib.sha256(read_regular(bundle / 'manifest.json', 2 * 1024 * 1024)).hexdigest()
    if previous and not purged:
        require(not options.initialize or not previous['initialized'] and not INITIALIZED.exists(), 'established installation cannot be reinitialized')
        require(previous['version'] == manifest['version'] and previous['manifest_sha256'] == manifest_hash,
                'artifact upgrade/downgrade requires the verified upgrade path')
        user = account()
        require(user.pw_uid == previous['uid'] and CONFIG.exists(), 'retained installation custody is incomplete')
        info = CONFIG.lstat()
        require(info.st_uid == 0 and info.st_gid == user.pw_gid and stat.S_IMODE(info.st_mode) == 0o640,
                'unsafe retained controller configuration')
        read_regular(CONFIG, 32768)
        private_directory(KEYS, user, create=False); private_directory(DATA, user, create=False)
        if previous['initialized']:
            require(INITIALIZED.exists(), 'retained initialization record is missing')
            info = INITIALIZED.lstat()
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == 0
                    and stat.S_IMODE(info.st_mode) == 0o600, 'unsafe initialization record')
            for name in ['root-secret','agent-jwt-secret','issuer-key']:
                info = (KEYS/name).lstat()
                require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == user.pw_uid
                        and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size == 32, 'retained keys are missing or unsafe')
            require((DATA/'controller.db').is_file() and not (DATA/'controller.db').is_symlink(), 'retained database is missing')
        if options.public_url:
            require(safe_origin(options.public_url) == previous['public_url'], 'endpoint changes require explicit migration')
        if options.ui_url:
            require(safe_origin(options.ui_url) == previous['ui_url'], 'endpoint changes require explicit migration')
        require(not options.tls_cert and not options.tls_key, 'certificate replacement requires controlled rotation')
        validate_units(native, previous['tls'])
    else:
        public_url = safe_origin(options.public_url)
        ui_url = safe_origin(options.ui_url or options.public_url)
        # A fresh account or unit collision is never adopted implicitly.
        if purged:
            user = account()
            require(user.pw_uid == previous['uid'], 'controller account changed')
        else:
            try:
                pwd.getpwnam('blindpass')
            except KeyError:
                pass
            else:
                raise Refusal('unmanaged controller account already exists')
            try:
                grp.getgrnam('blindpass')
            except KeyError:
                pass
            else:
                raise Refusal('unmanaged controller group already exists')
        require(not CONFIG.exists() and not CONFIG.is_symlink(), 'unmanaged controller config already exists')
        for unit in UNITS:
            require(not (UNIT_DIR / unit).exists() and not (UNIT_DIR / unit).is_symlink(), 'unmanaged controller unit already exists')
        validate_units(native, bool(tls_inputs), fresh=True)
        for path in [KEYS, DATA, TLS]:
            require(not path.exists() and not path.is_symlink(), 'unmanaged controller state already exists')
        root_directory(CONFIG.parent)
        root_directory(PREFIX)
        require(not any((PREFIX / name).exists() or (PREFIX / name).is_symlink() for name in ['current', manifest['version']]), 'unmanaged program path already exists')
        for name in ['blindpass','blindpass-controller']:
            link = Path('/usr/local/bin') / name
            require(not link.exists() and not link.is_symlink(), 'unmanaged program link already exists')
        for path in [Path('/usr/lib/sysusers.d/blindpass-controller.conf'), Path('/usr/lib/tmpfiles.d/blindpass-controller.conf')]:
            if path.exists():
                require(purged and read_regular(path,8192) == native['blindpass-controller.sysusers' if 'sysusers' in str(path) else 'blindpass-controller.tmpfiles'], 'unmanaged lifecycle config exists')
        publish_file(Path('/usr/lib/sysusers.d/blindpass-controller.conf'), native['blindpass-controller.sysusers'])
        command(['systemd-sysusers', '/usr/lib/sysusers.d/blindpass-controller.conf'], 'account creation')
        user = account()
        previous = {'version': manifest['version'], 'manifest_sha256': manifest_hash, 'uid': user.pw_uid,
                    'public_url': public_url, 'ui_url': ui_url, 'initialized': False, 'purged': False, 'tls': bool(tls_inputs)}
        # Record custody before key initialization. Interrupted setup is never
        # mistaken for a fresh controller on a later installer invocation.
        publish_file(MARKER, json.dumps(previous).encode(), 0o600)
        private_directory(KEYS, user); private_directory(DATA, user)
        values = {'BLINDPASS_LISTEN': '127.0.0.1:3200', 'BLINDPASS_PUBLIC_URL': public_url, 'BLINDPASS_UI_BASE_URL': ui_url,
                  'BLINDPASS_KEYS_DIR': str(KEYS), 'BLINDPASS_DATA_DIR': str(DATA),
                  'BLINDPASS_ADMIN_SOCKET_PATH': '/run/blindpass-controller/admin.sock', 'BLINDPASS_LOG_FORMAT': 'json',
                  'BLINDPASS_PROXY_REQUIRED': '0' if options.tls_cert else '1', 'BLINDPASS_TRUST_PROXY': '127.0.0.1,::1'}
        if tls_inputs:
            root_directory(TLS, 0o700)
            for name, payload in tls_inputs.items(): publish_file(TLS / name, payload, 0o600)
        publish_file(CONFIG, '\n'.join(f'{key}={value}' for key,value in values.items()).encode()+b'\n', 0o640, user.pw_gid)
    private_directory(KEYS, user); private_directory(DATA, user)
    root_directory(PREFIX)
    destination = PREFIX / manifest['version']
    if destination.exists():
        validate_installed(destination, manifest_hash)
    else:
        temporary = Path(tempfile.mkdtemp(prefix='.install-', dir=PREFIX))
        try:
            for name, record in manifest['members'].items():
                payload = read_regular(bundle / name, 128*1024*1024)
                require(hashlib.sha256(payload).hexdigest() == record['sha256'], 'bundle changed during copy')
                publish_file(temporary / name, payload, int(record['mode'],8))
            manifest_bytes = read_regular(bundle / 'manifest.json',2*1024*1024)
            require(hashlib.sha256(manifest_bytes).hexdigest() == manifest_hash, 'bundle changed during copy')
            publish_file(temporary / 'manifest.json', manifest_bytes)
            verify_bundle(temporary)
            temporary.chmod(0o755)
            temporary.rename(destination)
        finally:
            if temporary.exists(): shutil.rmtree(temporary)
    current = PREFIX / 'current'
    if current.is_symlink():
        require(current.readlink() == Path(manifest['version']), 'unmanaged program selector')
    else:
        require(not current.exists(), 'unmanaged program selector')
        current.symlink_to(manifest['version'], target_is_directory=True)
    for name in ['blindpass','blindpass-controller']:
        link = Path('/usr/local/bin') / name
        if link.is_symlink():
            require(link.readlink() == PREFIX / 'current/bin' / name, 'unmanaged program link')
        else:
            require(not link.exists(), 'unmanaged program link')
            link.symlink_to(PREFIX / 'current/bin' / name)
    source = destination / 'deploy/native'
    if previous['initialized']:
        command(['runuser','-u','blindpass','--',str(destination/'bin/blindpass'),'keys','check','--directory',str(KEYS)], 'retained keys check')
    for unit in UNITS:
        publish_file(UNIT_DIR / unit, read_regular(source / unit, 32768))
    publish_file(Path('/usr/lib/tmpfiles.d/blindpass-controller.conf'), read_regular(source / 'blindpass-controller.tmpfiles',8192))
    if previous['tls']:
        require(TLS.is_dir() and not TLS.is_symlink(), 'retained TLS custody is incomplete')
        for unit in TLS_UNITS:
            publish_file(UNIT_DIR / (unit+'.d/tls.conf'), TLS_DROPIN)
    command(['systemctl','daemon-reload'], 'unit reload')
    if options.initialize:
        require(not previous['initialized'] and not any(KEYS.iterdir()) and not any(DATA.iterdir()), 'initialization requires never-used empty state')
        command(['runuser','-u','blindpass','--',str(destination / 'bin/blindpass'),'keys','init','--directory',str(KEYS)], 'explicit keys initialization')
        command(['systemctl','start','blindpass-controller-initialize.service'], 'explicit database initialization')
        require((DATA/'controller.db').is_file(), 'initialization did not publish state')
        publish_file(INITIALIZED, b'', 0o600)
        previous['initialized'] = True
        publish_file(MARKER,json.dumps(previous).encode(),0o600)
    if options.start:
        require(previous['initialized'], 'explicit initialization required before starting')
        command(['systemctl','enable','--now','blindpass-controller.service'], 'controller start')
    print(json.dumps({'ok':True,'version':manifest['version'],'initialized':previous['initialized'],'backup_timer':'disabled unless separately configured'}))


def uninstall(options):
    previous = marker()
    require(previous is not None, 'no managed controller installation record')
    user = account()
    require(user.pw_uid == previous['uid'], 'controller account changed')
    # Validate all destructive targets before stopping/removing the program.
    destination = PREFIX / previous['version']
    if destination.exists():
        validate_installed(destination, previous['manifest_sha256'])
        validate_units({name: read_regular(destination/'deploy/native'/name,32768) for name in UNITS}, previous['tls'])
        require(hashlib.sha256(read_regular(destination/'manifest.json',2*1024*1024)).hexdigest() == previous['manifest_sha256'], 'installed artifact mismatch')
        for unit in UNITS:
            target = UNIT_DIR / unit
            if target.exists() or target.is_symlink():
                require(read_regular(target,32768) == read_regular(destination/'deploy/native'/unit,32768), 'modified unit requires manual review')
    else:
        require(not any((UNIT_DIR/unit).exists() for unit in UNITS), 'installed artifact is missing')
    for unit in TLS_UNITS:
        dropin = UNIT_DIR / (unit+'.d/tls.conf')
        if dropin.exists() or dropin.is_symlink(): require(read_regular(dropin,8192) == TLS_DROPIN, 'modified TLS drop-in requires manual review')
    if options.purge:
        for directory in [KEYS,DATA]:
            if directory.exists() or directory.is_symlink(): private_directory(directory,user,create=False)
        for directory in [KEYS,DATA,TLS]:
            if directory.exists() or directory.is_symlink():
                require(not directory.is_symlink(), 'linked state prevents purge')
                for path in [directory, *directory.rglob('*')]:
                    info = path.lstat()
                    require(not stat.S_ISLNK(info.st_mode) and info.st_uid in [0,user.pw_uid]
                            and (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode) and info.st_nlink == 1), 'unsafe state prevents purge')
    for unit in UNITS:
        if (UNIT_DIR / unit).exists():
            command(['systemctl','disable','--now',unit], 'controller stop')
    if destination.exists():
        verify_bundle(destination)
        for unit in UNITS:
            target = UNIT_DIR / unit
            if target.exists():
                require(read_regular(target,32768) == read_regular(destination / 'deploy/native' / unit,32768), 'modified unit requires manual review')
                target.unlink()
        shutil.rmtree(destination)
    for path, expected in [(PREFIX / 'current',Path(previous['version']))] + [(Path('/usr/local/bin')/name,PREFIX/'current/bin'/name) for name in ['blindpass','blindpass-controller']]:
        if path.is_symlink():
            require(path.readlink() == expected, 'unmanaged program link')
            path.unlink()
        else:
            require(not path.exists(), 'unmanaged program path')
    for unit in TLS_UNITS:
        dropin = UNIT_DIR / (unit+'.d/tls.conf')
        if dropin.exists():
            require(not dropin.is_symlink(), 'unsafe TLS drop-in')
            dropin.unlink()
            if not any(dropin.parent.iterdir()): dropin.parent.rmdir()
    Path('/usr/lib/tmpfiles.d/blindpass-controller.conf').unlink(missing_ok=True)
    command(['systemctl','daemon-reload'], 'unit reload')
    if options.purge:
        require(options.confirm_purge == 'blindpass-controller', 'purge requires --confirm-purge blindpass-controller')
        for directory in [KEYS,DATA,TLS]:
            if directory.exists():
                require(not directory.is_symlink(), 'linked state prevents purge')
                shutil.rmtree(directory)
        CONFIG.unlink(missing_ok=True); INITIALIZED.unlink(missing_ok=True)
        previous['purged'] = True
        publish_file(MARKER,json.dumps(previous).encode(),0o600)
    print(json.dumps({'ok':True,'state':'purged' if options.purge else 'retained','account':'retained'}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path)
    parser.add_argument('--verify-only', action='store_true')
    parser.add_argument('--initialize', action='store_true')
    parser.add_argument('--start', action='store_true')
    parser.add_argument('--public-url'); parser.add_argument('--ui-url')
    parser.add_argument('--tls-cert', type=Path); parser.add_argument('--tls-key', type=Path)
    parser.add_argument('--uninstall', action='store_true')
    parser.add_argument('--purge', action='store_true'); parser.add_argument('--confirm-purge')
    options = parser.parse_args()
    if options.verify_only:
        require(options.bundle is not None and not options.uninstall, 'bundle required for preflight')
        manifest = verify_bundle(options.bundle.absolute())
        print(json.dumps({'ok':True,'profile':'controller','version':manifest['version'],'architecture':manifest['architecture']}))
        return
    require(os.geteuid() == 0 and Path('/run/systemd/system').is_dir(), 'root on a real systemd host required')
    os_release = dict(line.split('=',1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    require((os_release.get('ID','').strip('"'), os_release.get('VERSION_ID','').strip('"')) in [('debian','12'),('ubuntu','24.04')], 'native OS profile requires review')
    require(not options.purge or options.uninstall and options.confirm_purge == 'blindpass-controller', 'confirmed uninstall required for purge')
    os.umask(0o077)
    root_directory(Path('/run/blindpass-controller-install'),0o700)
    descriptor = os.open('/run/blindpass-controller-install/lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    with os.fdopen(descriptor,'w') as lock:
        info = os.fstat(lock.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600, 'unsafe installation lock')
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if options.uninstall: uninstall(options)
        else:
            require(options.bundle is not None, 'bundle required')
            install(options)


if __name__ == '__main__':
    try:
        main()
    except (Refusal, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print('blindpass install: '+(str(error) if isinstance(error,Refusal) else 'operation refused; no private diagnostics'),file=sys.stderr)
        sys.exit(1)
