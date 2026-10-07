#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Native controller lifecycle. No shell evaluation or implicit trust repair."""
import argparse
import fcntl
import grp
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import platform
import pwd
import re
import shutil
import stat
import ssl
import struct
import subprocess
import sys
import tempfile
import time
from urllib.parse import parse_qsl, urlsplit

PREFIX = Path('/opt/blindpass/controller')
CONFIG = Path('/etc/blindpass/controller.env')
MARKER = Path('/etc/blindpass/controller-install.json')
KEYS = Path('/etc/blindpass/keys')
DATA = Path('/var/lib/blindpass/controller')
TLS = Path('/etc/blindpass/controller-tls')
AUTHORITY_DIR = Path('/etc/blindpass/controller-authority')
AUTHORITY_URL = AUTHORITY_DIR / 'authority-url'
UNIT_DIR = Path('/etc/systemd/system')
UNITS = ['blindpass-controller.service', 'blindpass-controller-initialize.service',
         'blindpass-controller-reconcile-clock.service', 'blindpass-controller-upgrade.service',
         'blindpass-controller-restore.service',
         'blindpass-controller-backup-credential-check.service',
         'blindpass-controller-backup.service', 'blindpass-controller-backup.timer']
NATIVE_FILES = UNITS + ['blindpass-controller.sysusers', 'blindpass-controller.tmpfiles',
                        'controller-install.py', 'controller-backup-credential-check.py', 'install.sh', 'uninstall.sh']
INITIALIZED = Path('/etc/blindpass/controller-initialized')
# ADR 0013: the backup host holds a signing credential and only the recipient's
# certificate; the recipient private key stays offline and is never installed.
BACKUP_SIGNING = Path('/etc/blindpass/controller-backup-signing-credential')
BACKUP_RECIPIENT = Path('/etc/blindpass/controller-backup-recipient-certificate')
BACKUP_CUSTODY = (BACKUP_SIGNING, BACKUP_RECIPIENT)
BACKUP_ENABLED = Path('/etc/blindpass/controller-backup-enabled')
TLS_DROPIN = b'[Service]\nLoadCredential=tls-cert:/etc/blindpass/controller-tls/cert.pem\nLoadCredential=tls-key:/etc/blindpass/controller-tls/key.pem\nEnvironment=BLINDPASS_TLS_CERT_FILE=%d/tls-cert\nEnvironment=BLINDPASS_TLS_KEY_FILE=%d/tls-key\n'
TLS_UNITS = ['blindpass-controller.service', 'blindpass-controller-initialize.service',
             'blindpass-controller-reconcile-clock.service', 'blindpass-controller-upgrade.service']
# The authority credential is delivered like the TLS material: a root-only file
# copied by systemd into each unit's private credential directory.
AUTHORITY_UNITS = TLS_UNITS


def authority_dropin(tenant_id, owner_id):
    # Identity and credential are delivered only to the units that claim the
    # authority. The shared environment file and the offline backup unit never
    # carry them (a partial authority setting is refused by the controller).
    for label, value in (('tenant ID', tenant_id), ('owner ID', owner_id)):
        require(isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9_-]{1,128}', value) is not None,
                label + ' must match [A-Za-z0-9_-]{1,128}')
    return ('[Service]\nLoadCredential=authority-url:/etc/blindpass/controller-authority/authority-url\n'
            'Environment=BLINDPASS_AUTHORITY_URL_FILE=%d/authority-url\n'
            'Environment=BLINDPASS_CONTROLLER_TENANT_ID=' + tenant_id + '\n'
            'Environment=BLINDPASS_CONTROLLER_OWNER_ID=' + owner_id + '\n').encode()


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


CONTROLLER_UNIT = 'blindpass-controller.service'
START_TIMEOUT_DEFAULT = 20
START_TIMEOUT_MAX = 300
LISTEN_DEFAULT = ('127.0.0.1', 3200)  # the installer writes BLINDPASS_LISTEN=127.0.0.1:3200


def listen_address():
    """The loopback address of the configured listener.

    The operator may edit BLINDPASS_LISTEN (for example to listen on all interfaces); the probe follows the port but
    only ever contacts loopback, like the controller's own `healthcheck`.
    """
    try:
        text = read_regular(CONFIG, 64 * 1024).decode()
    except (OSError, UnicodeError, Refusal):
        return LISTEN_DEFAULT
    value = None
    for line in text.splitlines():
        if line.startswith('BLINDPASS_LISTEN='): value = line.partition('=')[2].strip()
    try:
        host, separator, port = (value or '').rpartition(':')
        number = int(port)
        if not separator or not 1 <= number <= 65535: return LISTEN_DEFAULT
        address = ipaddress.ip_address(host.strip('[]'))
    except ValueError:
        return LISTEN_DEFAULT
    return ('::1' if address.version == 6 else '127.0.0.1', number)


def start_timeout(value):
    try:
        seconds = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError('--start-timeout must be a whole number of seconds from 1 to %d' % START_TIMEOUT_MAX)
    if not 1 <= seconds <= START_TIMEOUT_MAX:
        raise argparse.ArgumentTypeError('--start-timeout must be a whole number of seconds from 1 to %d' % START_TIMEOUT_MAX)
    return seconds


def loopback_status(path, tls):
    """GET a status-only controller path on the configured loopback listener.

    Returns (status, reason): the HTTP status or None when nothing answers, and the fixed-vocabulary `reason` of a
    readiness body when it matches [a-z_]{1,48}. No credential is sent. The built-in TLS certificate names the public
    host, not 127.0.0.1, so a TLS probe checks liveness and readiness only and does not verify the certificate.
    """
    host, port = listen_address()
    try:
        if tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            connection = http.client.HTTPSConnection(host, port, timeout=2, context=context)
        else:
            connection = http.client.HTTPConnection(host, port, timeout=2)
        try:
            connection.request('GET', path, headers={'Host': 'localhost', 'Connection': 'close'})
            response = connection.getresponse()
            reason = None
            try:
                body = json.loads(response.read(4096))
                value = body.get('reason') if isinstance(body, dict) else None
                if isinstance(value, str) and re.fullmatch(r'[a-z_]{1,48}', value): reason = value
            except ValueError:
                pass
            return response.status, reason
        finally:
            connection.close()
    except (OSError, http.client.HTTPException):
        return None, None


def unit_state(run):
    result = run(['systemctl', 'show', '-p', 'ActiveState', '-p', 'SubState', '-p', 'Result', '-p', 'InvocationID', '--', CONTROLLER_UNIT],
                 stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30)
    state = {}
    for line in (result.stdout or '').splitlines():
        key, separator, value = line.partition('=')
        if separator: state[key] = value
    return state


def startup_failure_reason(run, invocation):
    """The fixed-vocabulary `reason` of the last startup_failed event this invocation logged, else None."""
    if not re.fullmatch(r'[0-9a-f]{32}', invocation or ''): return None
    result = run(['journalctl', '--no-pager', '-o', 'cat', '-n', '200', '-u', CONTROLLER_UNIT, '_SYSTEMD_INVOCATION_ID=' + invocation],
                 stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30)
    reason = None
    for line in (result.stdout or '').splitlines():
        try: event = json.loads(line)
        except ValueError: continue
        if isinstance(event, dict) and event.get('event') == 'startup_failed':
            value = event.get('reason')
            reason = value if isinstance(value, str) and re.fullmatch(r'[a-z_]{1,48}', value) else None
    return reason


def wait_for_start(timeout, tls, run=subprocess.run, probe=loopback_status, sleep=time.sleep, now=time.monotonic):
    """Wait a bounded time for the started unit to be active AND ready; refuse otherwise.

    `systemctl enable --now` returns once systemd has exec'd the process (Type=exec), so the process can still exit
    a moment later. Two different failures follow an authority-backed start:
    * the activation was already consumed or another holder exists: the process exits `startup_failed` / `fenced`
      before it binds a listener (the unit becomes inactive/failed);
    * the authority record is fenced and was never activated (or the state is restored): the controller keeps
      running as a diagnostic process, `/healthz` answers 200 and `/readyz` answers 503 `recovery_required`.
    Neither is a successful start; only an active unit whose `/readyz` answers 200 is.
    """
    deadline = now() + timeout
    last_ready = None
    while True:
        state = unit_state(run)
        active = state.get('ActiveState')
        if active in ('failed', 'inactive'):
            reason = startup_failure_reason(run, state.get('InvocationID'))
            message = 'the controller did not stay running: unit %s/%s result=%s' % (active, state.get('SubState', '?'), state.get('Result', '?'))
            if reason: message += '; startup_failed reason=' + reason
            if reason == 'fenced':
                message += ('. Every start of the authority-backed controller consumes one activation: run authority-activate.sql '
                            'for this start (docs/deploy/native-quickstart.md), then systemctl start ' + CONTROLLER_UNIT)
            else:
                message += '. Inspect: journalctl -u ' + CONTROLLER_UNIT
            raise Refusal(message)
        if active == 'active' and probe('/healthz', tls)[0] == 200:
            status, reason = probe('/readyz', tls)
            if status == 200:
                return {'started': True, 'ready': True}
            last_ready = (status, reason)
        if now() >= deadline:
            if last_ready is not None:
                message = 'the controller is running but not ready: /readyz answered %s' % (last_ready[0] if last_ready[0] is not None else 'nothing')
                if isinstance(last_ready[1], str) and re.fullmatch(r'[a-z_]{1,48}', last_ready[1]): message += ' reason=' + last_ready[1]
                message += ('. A fenced authority record that was never activated, a consumed activation or a restored state all look like this: '
                            'stop the service, run authority-activate.sql for this start (docs/deploy/native-quickstart.md; a restored state needs '
                            'the recovery activation instead, docs/deploy/recovery-activation.md), then start it. Inspect: journalctl -u ' + CONTROLLER_UNIT)
                raise Refusal(message)
            raise Refusal('the controller is %s but /healthz did not answer within %d s. Inspect: systemctl status %s; journalctl -u %s'
                          % (active or 'unknown', timeout, CONTROLLER_UNIT, CONTROLLER_UNIT))
        sleep(0.5)


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


def safe_identifier(value, label):
    require(isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9_-]{1,128}', value) is not None,
            label + ' must match [A-Za-z0-9_-]{1,128}')
    return value


def check_authority_url(raw):
    """Static admission of the authority connection URL. The controller repeats
    and extends these checks at runtime; nothing here echoes the URL."""
    require(isinstance(raw, bytes) and 0 < len(raw) <= 16 * 1024 + 1, 'authority URL has an invalid size')
    try:
        text = raw.decode('ascii')
    except UnicodeDecodeError:
        raise Refusal('authority URL must be ASCII') from None
    if text.endswith('\n'):
        text = text[:-1]
    require(0 < len(text) <= 16 * 1024 and all(33 <= ord(character) < 127 for character in text),
            'authority URL must be one printable line')
    parsed = urlsplit(text)
    require(parsed.scheme in ('postgres', 'postgresql') and parsed.hostname and not parsed.fragment,
            'authority URL must name a PostgreSQL host')
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    require('host' not in query and 'hostaddr' not in query, 'authority host must be in the URL authority')
    host = parsed.hostname
    try:
        local = ipaddress.ip_address(host).is_loopback
    except ValueError:
        local = host.lower() == 'localhost'
    require(local or query.get('sslmode') in ('verify-ca', 'verify-full'),
            'a remote authority requires sslmode=verify-ca or verify-full')
    return text


def read_authority_input(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) & 0o077 == 0, 'private authority URL file required')
    return check_authority_url(read_regular(path.absolute(), 16 * 1024 + 1))


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


def validate_units(native, tls, fresh=False, authority=None):
    for name in UNITS:
        target = UNIT_DIR/name
        if target.exists() or target.is_symlink():
            require(not fresh and read_regular(target,32768) == native[name], 'unmanaged or modified controller unit')
        dropins = UNIT_DIR/(name+'.d')
        if dropins.exists() or dropins.is_symlink():
            root_directory(dropins)
            require(not fresh, 'unmanaged controller drop-in')
            for path in dropins.iterdir():
                allowed = {}
                if tls and name in TLS_UNITS: allowed['tls.conf'] = TLS_DROPIN
                if authority and name in AUTHORITY_UNITS: allowed['authority.conf'] = authority_dropin(*authority)
                require(path.name in allowed and read_regular(path,8192) == allowed[path.name],
                        'unmanaged or modified controller drop-in')


def validate_installed(root, expected_hash):
    root_directory(root)
    require(hashlib.sha256(read_regular(root/'manifest.json',2*1024*1024)).hexdigest() == expected_hash,
            'installed artifact mismatch')
    verify_bundle(root)
    for path in root.rglob('*'):
        info = path.lstat()
        require(info.st_uid == 0 and info.st_gid == 0 and not info.st_mode & 0o022,
                'installed artifact custody changed')


def version_key(version):
    """Release ordering: numeric core, then a final release above any prerelease."""
    match = re.fullmatch(r'(\d+)\.(\d+)\.(\d+)(?:-([a-zA-Z0-9.-]+))?', version)
    require(match is not None, 'unsafe bundle version')
    core = tuple(int(part) for part in match.group(1, 2, 3))
    return core, 1 if match.group(4) is None else 0, match.group(4) or ''


def plan_artifact(previous, manifest, manifest_hash, upgrade):
    """Return 'same' or 'upgrade'; every other artifact change is refused.
    Downgrade is restore-only from a pre-upgrade backup, never an install."""
    same = previous['version'] == manifest['version'] and previous['manifest_sha256'] == manifest_hash
    if not upgrade:
        require(same, 'a different artifact requires --upgrade; downgrade is restore-only')
        return 'same'
    require(not same, 'artifact is already installed')
    require(previous.get('initialized') and previous.get('authority'),
            'upgrade requires an initialized authority-backed installation')
    require(version_key(manifest['version']) > version_key(previous['version']),
            'downgrade is restore-only from a pre-upgrade backup')
    return 'upgrade'


def require_upgrade_custody():
    """Metadata-only checks before any upgrade mutation: the controller is stopped
    and the original recovery credential is unexposed (it is never read here)."""
    state = subprocess.run(['systemctl', 'is-active', 'blindpass-controller.service'], capture_output=True, text=True)
    require(state.stdout.strip() in ('inactive', 'failed', 'unknown'), 'stop the controller before an upgrade')
    root_directory(BACKUP_SIGNING.parent)
    for path in BACKUP_CUSTODY:
        require(path.exists() and not path.is_symlink(), 'upgrade requires the protected backup signing credential and recipient certificate')
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(descriptor)
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == 0
                    and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= 16384,
                    'unsafe backup custody prevents upgrade')
        finally:
            os.close(descriptor)


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
    mode = 'same'
    if previous and not purged:
        require(not options.initialize or not previous['initialized'] and not INITIALIZED.exists(), 'established installation cannot be reinitialized')
        mode = plan_artifact(previous, manifest, manifest_hash, options.upgrade)
        if mode == 'upgrade':
            require(not options.initialize and not options.initialize_keys and not options.start,
                    'an upgrade installs only; migrate, activate and start are separate steps')
            require_upgrade_custody()
        user = account()
        require(user.pw_uid == previous['uid'] and CONFIG.exists(), 'retained installation custody is incomplete')
        info = CONFIG.lstat()
        require(info.st_uid == 0 and info.st_gid == user.pw_gid and stat.S_IMODE(info.st_mode) == 0o640,
                'unsafe retained controller configuration')
        read_regular(CONFIG, 32768)
        private_directory(KEYS, user, create=False); private_directory(DATA, user, create=False)
        if previous['initialized'] or previous.get('keys_initialized'):
            for name in ['root-secret','agent-jwt-secret','issuer-key']:
                info = (KEYS/name).lstat()
                require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == user.pw_uid
                        and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size == 32, 'retained keys are missing or unsafe')
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
        require(not options.authority_url_file and not options.tenant_id and not options.owner_id,
                'authority changes require a controlled authority review')
        if previous.get('authority'):
            root_directory(AUTHORITY_DIR, 0o700)
            info = AUTHORITY_URL.lstat()
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == 0
                    and stat.S_IMODE(info.st_mode) == 0o600, 'unsafe retained authority custody')
        else:
            require(not options.initialize and not options.initialize_keys and not options.start,
                    'installation predates authority provisioning; uninstall with purge and reinstall')
        installed = native
        if mode == 'upgrade':
            old_root = PREFIX / previous['version']
            validate_installed(old_root, previous['manifest_sha256'])
            installed = {name: read_regular(old_root / 'deploy/native' / name, 65536)
                         for name in UNITS if (old_root / 'deploy/native' / name).exists()}
        validate_units(installed, previous['tls'], authority=(previous['tenant_id'], previous['owner_id']) if previous.get('authority') else None)
    else:
        public_url = safe_origin(options.public_url)
        ui_url = safe_origin(options.ui_url or options.public_url)
        require(options.authority_url_file is not None and options.tenant_id and options.owner_id,
                'authority URL file, tenant ID and owner ID are required')
        tenant_id = safe_identifier(options.tenant_id, 'tenant ID')
        owner_id = safe_identifier(options.owner_id, 'owner ID')
        authority_url = read_authority_input(options.authority_url_file)
        require(not AUTHORITY_DIR.exists() and not AUTHORITY_DIR.is_symlink(), 'unmanaged controller authority state already exists')
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
        validate_units(native, bool(tls_inputs), fresh=True, authority=(tenant_id, owner_id))
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
                    'public_url': public_url, 'ui_url': ui_url, 'initialized': False, 'purged': False, 'tls': bool(tls_inputs),
                    'authority': True, 'tenant_id': tenant_id, 'owner_id': owner_id, 'keys_initialized': False,
                    'versions': [manifest['version']]}
        # Record custody before key initialization. Interrupted setup is never
        # mistaken for a fresh controller on a later installer invocation.
        publish_file(MARKER, json.dumps(previous).encode(), 0o600)
        private_directory(KEYS, user); private_directory(DATA, user)
        values = {'BLINDPASS_LISTEN': '127.0.0.1:3200', 'BLINDPASS_PUBLIC_URL': public_url, 'BLINDPASS_UI_BASE_URL': ui_url,
                  'BLINDPASS_KEYS_DIR': str(KEYS), 'BLINDPASS_DATA_DIR': str(DATA),
                  'BLINDPASS_ADMIN_SOCKET_PATH': '/run/blindpass-controller/admin.sock', 'BLINDPASS_LOG_FORMAT': 'json',
                  'BLINDPASS_PROXY_REQUIRED': '0' if options.tls_cert else '1', 'BLINDPASS_TRUST_PROXY': '127.0.0.1,::1'}
        root_directory(AUTHORITY_DIR, 0o700)
        publish_file(AUTHORITY_URL, authority_url.encode() + b'\n', 0o600)
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
        accepted = [Path(manifest['version'])]
        if mode == 'upgrade':
            accepted.append(Path(previous['version']))
        require(current.readlink() in accepted, 'unmanaged program selector')
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
    if previous['initialized'] or previous.get('keys_initialized'):
        command(['runuser','-u','blindpass','--',str(destination/'bin/blindpass'),'keys','check','--directory',str(KEYS)], 'retained keys check')
    for unit in UNITS:
        publish_file(UNIT_DIR / unit, read_regular(source / unit, 32768))
    publish_file(Path('/usr/lib/tmpfiles.d/blindpass-controller.conf'), read_regular(source / 'blindpass-controller.tmpfiles',8192))
    if previous['tls']:
        require(TLS.is_dir() and not TLS.is_symlink(), 'retained TLS custody is incomplete')
        for unit in TLS_UNITS:
            publish_file(UNIT_DIR / (unit+'.d/tls.conf'), TLS_DROPIN)
    if previous.get('authority'):
        require(AUTHORITY_URL.is_file() and not AUTHORITY_URL.is_symlink(), 'retained authority custody is incomplete')
        for unit in AUTHORITY_UNITS:
            publish_file(UNIT_DIR / (unit+'.d/authority.conf'),
                         authority_dropin(previous['tenant_id'], previous['owner_id']))
    command(['systemctl','daemon-reload'], 'unit reload')
    if mode == 'upgrade':
        # New units are in place and the new tree is verified; switch the selector
        # atomically, then record it. A rerun of the same archive completes a
        # switch that was interrupted before the record was written.
        if current.readlink() != Path(manifest['version']):
            selector = PREFIX / '.current-upgrade'
            selector.unlink(missing_ok=True)
            selector.symlink_to(manifest['version'], target_is_directory=True)
            os.replace(selector, current)
        previous['versions'] = sorted(set(previous.get('versions', [previous['version']])) | {previous['version'], manifest['version']})
        previous['version'] = manifest['version']
        previous['manifest_sha256'] = manifest_hash
        publish_file(MARKER, json.dumps(previous).encode(), 0o600)
    issuer_key_id = None
    if options.initialize_keys:
        require(not previous['initialized'] and not previous.get('keys_initialized')
                and not any(KEYS.iterdir()) and not any(DATA.iterdir()), 'key initialization requires never-used empty state')
        command(['runuser','-u','blindpass','--',str(destination / 'bin/blindpass'),'keys','init','--directory',str(KEYS)], 'explicit keys initialization')
        previous['keys_initialized'] = True
        publish_file(MARKER,json.dumps(previous).encode(),0o600)
    if options.initialize_keys or (previous.get('keys_initialized') and not previous['initialized']):
        issuer_key_id = command(['runuser','-u','blindpass','--',str(destination / 'bin/blindpass'),'keys','issuer-id','--directory',str(KEYS)], 'issuer identifier')
        require(re.fullmatch(r'ed25519-[A-Za-z0-9_-]{43}', issuer_key_id) is not None, 'unexpected issuer identifier')
    if options.initialize:
        require(previous.get('keys_initialized') and not previous['initialized'] and not any(DATA.iterdir()),
                'database initialization requires initialized keys, an administrator-registered authority and an empty data directory')
        command(['systemctl','start','blindpass-controller-initialize.service'], 'explicit database initialization')
        require((DATA/'controller.db').is_file(), 'initialization did not publish state')
        publish_file(INITIALIZED, b'', 0o600)
        previous['initialized'] = True
        publish_file(MARKER,json.dumps(previous).encode(),0o600)
    if options.start:
        require(previous['initialized'], 'explicit initialization required before starting')
        command(['systemctl','enable','--now','blindpass-controller.service'], 'controller start')
        try:
            started = wait_for_start(options.start_timeout, bool(previous.get('tls')))
        except Refusal as refusal:
            # The installation itself completed; only the start failed. Say so on stdout and exit non-zero.
            print(json.dumps({'ok':False,'started':False,'version':manifest['version'],'installed':True,'start_error':str(refusal)}))
            raise
    summary = {'ok':True,'version':manifest['version'],'upgraded':mode == 'upgrade','keys_initialized':bool(previous.get('keys_initialized')),
               'initialized':previous['initialized'],'backup_timer':'disabled unless separately configured'}
    if options.start: summary.update(started)
    if issuer_key_id and not previous['initialized']:
        summary['issuer_key_id'] = issuer_key_id
        summary['next'] = 'register the tenant, owner and issuer in the authority, then run with --initialize'
    print(json.dumps(summary))


def uninstall(options):
    previous = marker()
    require(previous is not None, 'no managed controller installation record')
    user = account()
    require(user.pw_uid == previous['uid'], 'controller account changed')
    # Validate all destructive targets before stopping/removing the program.
    destination = PREFIX / previous['version']
    if destination.exists():
        validate_installed(destination, previous['manifest_sha256'])
        validate_units({name: read_regular(destination/'deploy/native'/name,32768) for name in UNITS}, previous['tls'],
                       authority=(previous['tenant_id'], previous['owner_id']) if previous.get('authority') else None)
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
        dropin = UNIT_DIR / (unit+'.d/authority.conf')
        if dropin.exists() or dropin.is_symlink():
            require(previous.get('authority') and read_regular(dropin,8192) == authority_dropin(previous['tenant_id'], previous['owner_id']),
                    'modified authority drop-in requires manual review')
    if options.purge:
        # Recovery material is retained on ordinary uninstall. Exact purge
        # includes these managed paths, but unsafe custody must refuse before
        # stopping the controller or deleting any state.
        for path, limit in [(BACKUP_SIGNING,16384),(BACKUP_RECIPIENT,16384),(BACKUP_ENABLED,128)]:
            if path.exists() or path.is_symlink():
                root_directory(path.parent)
                descriptor = os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
                try:
                    info = os.fstat(descriptor)
                    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                            and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600
                            and info.st_size <= limit,
                            'unsafe backup recovery custody prevents purge')
                    # Validate custody without reading credential plaintext.
                finally:
                    os.close(descriptor)
        for directory in [KEYS,DATA]:
            if directory.exists() or directory.is_symlink(): private_directory(directory,user,create=False)
        for directory in [KEYS,DATA,TLS,AUTHORITY_DIR]:
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
    for other in sorted(set(previous.get('versions', [])) - {previous['version']}):
        path = PREFIX / other
        if path.exists():
            require(not path.is_symlink(), 'unmanaged program path')
            verify_bundle(path)
            shutil.rmtree(path)
    for path, expected in [(PREFIX / 'current',Path(previous['version']))] + [(Path('/usr/local/bin')/name,PREFIX/'current/bin'/name) for name in ['blindpass','blindpass-controller']]:
        if path.is_symlink():
            require(path.readlink() == expected, 'unmanaged program link')
            path.unlink()
        else:
            require(not path.exists(), 'unmanaged program path')
    for unit in TLS_UNITS:
        for name in ('tls.conf', 'authority.conf'):
            dropin = UNIT_DIR / (unit+'.d/'+name)
            if dropin.exists():
                require(not dropin.is_symlink(), 'unsafe unit drop-in')
                dropin.unlink()
                if not any(dropin.parent.iterdir()): dropin.parent.rmdir()
    Path('/usr/lib/tmpfiles.d/blindpass-controller.conf').unlink(missing_ok=True)
    command(['systemctl','daemon-reload'], 'unit reload')
    if options.purge:
        require(options.confirm_purge == 'blindpass-controller', 'purge requires --confirm-purge blindpass-controller')
        for directory in [KEYS,DATA,TLS,AUTHORITY_DIR]:
            if directory.exists():
                require(not directory.is_symlink(), 'linked state prevents purge')
                shutil.rmtree(directory)
        CONFIG.unlink(missing_ok=True); INITIALIZED.unlink(missing_ok=True)
        BACKUP_SIGNING.unlink(missing_ok=True); BACKUP_RECIPIENT.unlink(missing_ok=True); BACKUP_ENABLED.unlink(missing_ok=True)
        previous['purged'] = True
        publish_file(MARKER,json.dumps(previous).encode(),0o600)
    print(json.dumps({'ok':True,'state':'purged' if options.purge else 'retained','account':'retained'}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path)
    parser.add_argument('--verify-only', action='store_true')
    parser.add_argument('--initialize-keys', action='store_true',
                        help='create the controller keys and print the issuer key ID to register in the authority')
    parser.add_argument('--initialize', action='store_true',
                        help='create the controller database; requires initialized keys and an administrator-registered authority')
    parser.add_argument('--authority-url-file', type=Path, help='private file holding the runtime authority PostgreSQL URL')
    parser.add_argument('--tenant-id'); parser.add_argument('--owner-id')
    parser.add_argument('--start', action='store_true',
                        help='enable and start the controller, then wait for it to be active and answering; exits non-zero '
                             'with the startup_failed reason if it exits (an authority-backed start needs a fresh activation)')
    parser.add_argument('--start-timeout', type=start_timeout, default=START_TIMEOUT_DEFAULT, metavar='SECONDS',
                        help='how long --start waits for the controller (default %d, 1 to %d)' % (START_TIMEOUT_DEFAULT, START_TIMEOUT_MAX))
    parser.add_argument('--upgrade', action='store_true',
                        help='install a newer artifact over an initialized installation while the controller is stopped; '
                             'schema migration and its automatic backup run later through blindpass-controller-upgrade.service')
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
