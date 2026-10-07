#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""P06-AO01..AO08: the packaged operator sequence against a disposable authority.

Runs the real `blindpass` and `blindpass-controller` binaries with the native
layout (BLINDPASS_KEYS_DIR/DATA_DIR) and the shipped administrator SQL files:
keys init -> keys issuer-id -> register -> migrate -> activate -> serve ->
restart refusal -> re-activation. Uses the existing Docker PostgreSQL fixture
only through `docker exec psql`, creates its own database and roles, and drops
them. Dummy credentials only; nothing is printed that contains them.
"""
import argparse
import os
from pathlib import Path
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--admin-container', default='blindpass-postgres')
    parser.add_argument('--admin-user', default='blindpass')
    parser.add_argument('--admin-database', default='blindpass')
    parser.add_argument('--port', type=int, default=5433)
    parser.add_argument('--controller', type=Path, default=ROOT / 'target/debug/blindpass-controller')
    parser.add_argument('--cli', type=Path, default=ROOT / 'target/debug/blindpass')
    parser.add_argument('--log', type=Path, required=True)
    options = parser.parse_args()
    for binary in (options.controller, options.cli):
        if not binary.is_file():
            parser.error(f'{binary} is missing; run cargo build first')

    suffix = secrets.token_hex(8)
    database = f'p06_ao_{suffix}'
    owner_role = f'p06_ao_owner_{suffix}'
    runtime_role = f'p06_ao_runtime_{suffix}'
    owner_password = 'P06-DUMMY-' + secrets.token_hex(24)
    runtime_password = 'P06-DUMMY-' + secrets.token_hex(24)
    tenant, owner = f'ao_tenant_{suffix}', f'ao_owner_{suffix}'
    work = Path(tempfile.mkdtemp(prefix='p06-ao-'))
    work.chmod(0o700)
    log = options.log.open('x')
    results = []

    def say(line):
        print(line)
        log.write(line + '\n')
        log.flush()

    def psql(database_name, sql=None, file=None, variables=None, role=None):
        command = ['docker', 'exec', '-i', '-e', 'PGOPTIONS=-c lock_timeout=5000 -c statement_timeout=15000',
                   options.admin_container, 'psql', '-X', '-q', '-t', '-A', '-U', options.admin_user,
                   '-d', database_name, '-v', 'ON_ERROR_STOP=1']
        for key, value in (variables or {}).items():
            command += ['-v', f'{key}={value}']
        payload = sql if sql is not None else Path(file).read_text()
        if role:
            payload = f'SET ROLE {role};\n' + payload
        command += ['-f', '-']
        return subprocess.run(command, input=payload, text=True, capture_output=True, timeout=60)

    def check(name, condition, detail=''):
        results.append((name, bool(condition)))
        say(f'{name} {"ok" if condition else "FAILED"} {detail}'.rstrip())
        if not condition:
            raise AssertionError(name)

    keys = work / 'keys'
    data = work / 'data'
    data.mkdir(mode=0o700)
    secrets_dir = work / 'secrets'
    secrets_dir.mkdir(mode=0o700)
    authority_url_file = secrets_dir / 'authority-url'
    listen = f'127.0.0.1:{39000 + secrets.randbelow(900)}'
    environment = {
        'PATH': os.environ.get('PATH', '/usr/bin'),
        'BLINDPASS_LISTEN': listen,
        'BLINDPASS_PUBLIC_URL': 'https://controller.ao.invalid',
        'BLINDPASS_UI_BASE_URL': 'https://controller.ao.invalid',
        'BLINDPASS_KEYS_DIR': str(keys),
        'BLINDPASS_DATA_DIR': str(data),
        'BLINDPASS_ADMIN_SOCKET_PATH': str(work / 'admin.sock'),
        'BLINDPASS_PROXY_REQUIRED': '1',
        'BLINDPASS_TRUST_PROXY': '127.0.0.1,::1',
        'BLINDPASS_AUTHORITY_URL_FILE': str(authority_url_file),
        'BLINDPASS_CONTROLLER_TENANT_ID': tenant,
        'BLINDPASS_CONTROLLER_OWNER_ID': owner,
    }

    def run(binary, *args, expect=0, timeout=60):
        completed = subprocess.run([str(binary), *args], env=environment, text=True,
                                   capture_output=True, timeout=timeout, stdin=subprocess.DEVNULL)
        if expect is not None:
            ok = (completed.returncode == 0) if expect == 0 else (completed.returncode != 0)
            if not ok:
                say(f'unexpected status {completed.returncode} for {args[0]}')
        return completed

    def ready():
        return run(options.controller, 'healthcheck', expect=None, timeout=10).returncode == 0

    def start_serve():
        process = subprocess.Popen([str(options.controller), 'serve'], env=environment, text=True,
                                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        return process

    def wait_for(predicate, seconds=15):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if predicate():
                return True
            time.sleep(0.25)
        return False

    def stop(process):
        if process.poll() is None:
            process.send_signal(signal.SIGTERM)
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()

    created_database = created_roles = False
    server = None
    try:
        created_roles = True
        for role, password in ((owner_role, owner_password), (runtime_role, runtime_password)):
            completed = psql(options.admin_database, f"CREATE ROLE {role} LOGIN PASSWORD '{password}';")
            assert completed.returncode == 0, 'role setup failed'
        created_database = True
        assert psql(options.admin_database, f'CREATE DATABASE {database} OWNER {owner_role};').returncode == 0
        provision = psql(database, 'SET ROLE ' + owner_role + ';\n' + (ROOT / 'deploy/controller/recovery-authority.sql').read_text())
        assert provision.returncode == 0, 'authority layout failed'
        grants = psql(database, 'SET ROLE ' + owner_role + ';\n' + (ROOT / 'deploy/controller/authority-runtime-role.sql').read_text(),
                      variables={'runtime_role': runtime_role})
        check('AO00-runtime-role-grants-apply', grants.returncode == 0, grants.stderr.strip()[:200])
        authority_url_file.write_text(f'postgresql://{runtime_role}:{runtime_password}@127.0.0.1:{options.port}/{database}')
        authority_url_file.chmod(0o600)

        # AO01: explicit key initialization, then the public issuer identifier.
        check('AO01-keys-init', run(options.cli, 'keys', 'init').returncode == 0)
        issuer = run(options.cli, 'keys', 'issuer-id').stdout.strip()
        check('AO01-issuer-id-format', issuer.startswith('ed25519-') and len(issuer) == 51, issuer[:12] + '...')

        # AO02: nothing starts before registration; registration is exactly once.
        check('AO02-migrate-refused-before-registration', run(options.controller, 'migrate', expect=1).returncode != 0
              and not (data / 'controller.db').exists())
        variables = {'tenant': tenant, 'owner': owner, 'issuer': issuer}
        register = psql(database, file=ROOT / 'deploy/controller/authority-register.sql', variables=variables,
                        role=owner_role)
        check('AO02-register', register.returncode == 0, register.stderr.strip()[:200])
        again = psql(database, file=ROOT / 'deploy/controller/authority-register.sql', variables=variables, role=owner_role)
        check('AO02-repeated-registration-refused', again.returncode != 0)

        # AO03: the fenced record permits the single database initialization.
        check('AO03-migrate-creates-database-once', run(options.cli, 'migrate').returncode == 0
              and (data / 'controller.db').is_file())

        # AO04: a fenced serve is diagnostic only, never ready; activation refuses
        # while that holder is live.
        server = start_serve()
        check('AO04-fenced-serve-is-not-ready', not wait_for(ready, 6) and server.poll() is None)
        wrong = psql(database, file=ROOT / 'deploy/controller/authority-activate.sql',
                     variables={**variables, 'issuer': 'ed25519-' + 'A' * 43}, role=owner_role)
        check('AO04-activation-with-wrong-identity-refused', wrong.returncode != 0)
        live = psql(database, file=ROOT / 'deploy/controller/authority-activate.sql', variables=variables, role=owner_role)
        check('AO04-activation-refused-while-a-holder-is-live', live.returncode != 0, live.stderr.strip()[:120])
        stop(server)

        # AO05: one activation grants one start.
        activated = psql(database, file=ROOT / 'deploy/controller/authority-activate.sql', variables=variables, role=owner_role)
        check('AO05-activation-succeeds-with-no-holder', activated.returncode == 0 and 'activated revision' in activated.stdout,
              activated.stderr.strip()[:200])
        server = start_serve()
        check('AO05-activated-serve-becomes-ready', wait_for(ready, 20))
        live = psql(database, file=ROOT / 'deploy/controller/authority-activate.sql', variables=variables, role=owner_role)
        check('AO05-activation-refused-while-serving', live.returncode != 0)
        stop(server)

        # AO06: the used revision is never replayed after the process ends.
        server = start_serve()
        check('AO06-restart-without-reactivation-is-not-ready', not wait_for(ready, 6))
        stop(server)

        # AO07: a fresh activation grants exactly one more start.
        again = psql(database, file=ROOT / 'deploy/controller/authority-activate.sql', variables=variables, role=owner_role)
        check('AO07-reactivation-after-stop', again.returncode == 0, again.stderr.strip()[:200])
        server = start_serve()
        check('AO07-second-start-ready', wait_for(ready, 20))
        stop(server)

        # AO09: fencing cuts off a live controller; maintenance then needs a fenced record.
        activated = psql(database, file=ROOT / 'deploy/controller/authority-activate.sql', variables=variables, role=owner_role)
        assert activated.returncode == 0
        server = start_serve()
        check('AO09-third-start-ready', wait_for(ready, 20))
        refused_maintenance = run(options.controller, 'reconcile-clock', expect=1)
        check('AO09-maintenance-refused-while-active', refused_maintenance.returncode != 0)
        fenced = psql(database, file=ROOT / 'deploy/controller/authority-fence.sql', variables=variables, role=owner_role)
        check('AO09-fence-with-a-live-holder', fenced.returncode == 0 and 'fenced revision' in fenced.stdout, fenced.stderr.strip()[:200])
        check('AO09-live-controller-loses-readiness', wait_for(lambda: not ready(), 10))
        stop(server)
        again = psql(database, file=ROOT / 'deploy/controller/authority-fence.sql', variables=variables, role=owner_role)
        check('AO09-fencing-a-fenced-record-is-refused', again.returncode != 0)
        check('AO09-maintenance-after-fence', run(options.controller, 'reconcile-clock').returncode == 0)
        activated = psql(database, file=ROOT / 'deploy/controller/authority-activate.sql', variables=variables, role=owner_role)
        check('AO09-reactivation-after-maintenance', activated.returncode == 0)

        # AO08: a recovering record is never activated by this script.
        psql(database, f"SET ROLE {owner_role}; UPDATE blindpass_authority.recovery_authority SET phase='fenced', revision=revision+1 WHERE tenant_id='{tenant}';")
        reserve = psql(database, f"SET ROLE {owner_role}; UPDATE blindpass_authority.recovery_authority SET phase='recovering', revision=revision+1, epoch=epoch+1 WHERE tenant_id='{tenant}';")
        recovering = psql(database, file=ROOT / 'deploy/controller/authority-activate.sql', variables=variables, role=owner_role)
        check('AO08-recovering-record-is-not-activated', reserve.returncode == 0 and recovering.returncode != 0)
        say('P06-AO result: all checks passed')
        return 0
    except AssertionError as error:
        say(f'P06-AO result: FAILED at {error}')
        return 1
    finally:
        if server is not None:
            stop(server)
        if created_database:
            psql(options.admin_database, f'DROP DATABASE IF EXISTS {database} WITH (FORCE);')
        if created_roles:
            for role in (runtime_role, owner_role):
                psql(options.admin_database, f'DROP ROLE IF EXISTS {role};')
        shutil.rmtree(work, ignore_errors=True)
        log.close()


if __name__ == '__main__':
    sys.exit(main())
