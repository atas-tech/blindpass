#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""P07 slice-2 execution (S03-S05, P07-I02, P07-I03) on the shipped SQLite Compose profile.

Stands up the shipped Compose files behind the shipped nginx edge example (real TLS), then drives
real Chromium (tests/deployment/p07-profile-browser.mjs) and distinct-address probe containers
(tests/deployment/p07-probe.py). Only disposable, uniquely named Docker resources are used and all
are removed at the end. Credentials are disposable canaries; nothing prints them. Sanitized
results go to --out (default ~/.cache/canary-scan-p07/runs/g2); the canary scanner then looks at
the run directory.
"""
import argparse
import base64
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
import canary_log_scan  # noqa: E402

_spec = importlib.util.spec_from_file_location('compose_up', HERE / 'compose-up.py')
compose_up = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(compose_up)
run, docker, wait = compose_up.run, compose_up.docker, compose_up.wait

RESULTS = []
SUBNET = '172.29.86'
AUTHORITY_IMAGE = 'postgres:16-alpine@sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea'


def check(row, name, ok, **detail):
    RESULTS.append({'row': row, 'name': name, 'ok': bool(ok), **detail})
    print(('PASS ' if ok else 'FAIL ') + row + ': ' + name, flush=True)
    return ok


def counts(results):
    seen = {}
    for item in results:
        seen[item['status']] = seen.get(item['status'], 0) + 1
    return seen


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--image', default='blindpass-p07-controller:s06')
    parser.add_argument('--helper-image', default='blindpass-p06-edge:local')
    parser.add_argument('--out', default=str(Path.home() / '.cache/canary-scan-p07/runs/g2'))
    parser.add_argument('--steps', default='bootstrap,s03,s04,s05,forced,slow')
    parser.add_argument('--profile', choices=['sqlite', 'postgres'], default='sqlite')
    parser.add_argument('--keep', action='store_true', help='leave the stack running for debugging')
    arguments = parser.parse_args()
    steps = set(arguments.steps.split(','))
    profile = arguments.profile
    out = Path(arguments.out)
    if out.exists():
        raise SystemExit('refusing to reuse an existing --out directory')
    out.mkdir(parents=True, mode=0o700)
    image, helper = arguments.image, arguments.helper_image
    project = 'blindpass-p07-' + profile[:2] + '-' + secrets.token_hex(4)
    network = project + '_edge'
    edge_name = project + '-edge'
    authority_name = project + '-authority'
    authority_host = 'authority.p07.invalid'
    tenant, owner = 'p07_tenant', 'p07_owner'
    operator_password = 'P07-OPERATOR-' + secrets.token_hex(12)
    next_password = 'P07-NEXT-' + secrets.token_hex(12)
    wrong_password = 'P07-WRONG-' + secrets.token_hex(12)
    authority_password = secrets.token_hex(24)
    canaries = [operator_password, next_password, wrong_password]
    username = 'p07admin'
    with tempfile.TemporaryDirectory(prefix=project + '-') as directory:
        root = Path(directory)
        config = root / 'config'; config.mkdir(mode=0o700)
        authority_dir = root / 'authority'; authority_dir.mkdir(mode=0o700)
        authority_tls = root / 'authority-tls'; authority_tls.mkdir(mode=0o700)
        probe_dir = root / 'probe'; probe_dir.mkdir(mode=0o755)
        private_dir = root / 'private'; private_dir.mkdir(mode=0o700)
        password_file = root / 'pg-password'; password_file.write_text(secrets.token_hex(32)); password_file.chmod(0o600)
        (config / 'database.url').write_text('postgresql://blindpass:' + password_file.read_text() + '@postgres:5432/blindpass')
        (config / 'database.url').chmod(0o600)
        run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=p07 authority ca',
             '-addext', 'basicConstraints=critical,CA:TRUE', '-keyout', str(authority_tls / 'ca.key'), '-out', str(authority_tls / 'ca.pem')])
        run(['openssl', 'req', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=' + authority_host, '-keyout', str(authority_tls / 'server.key'),
             '-out', str(authority_tls / 'server.csr')])
        (authority_tls / 'ext.cnf').write_text('subjectAltName=DNS:' + authority_host + '\nbasicConstraints=CA:FALSE\n')
        run(['openssl', 'x509', '-req', '-in', str(authority_tls / 'server.csr'), '-CA', str(authority_tls / 'ca.pem'), '-CAkey', str(authority_tls / 'ca.key'),
             '-CAcreateserial', '-days', '1', '-extfile', str(authority_tls / 'ext.cnf'), '-out', str(authority_tls / 'server.crt')])
        shutil.copy(authority_tls / 'ca.pem', authority_dir / 'authority-ca.pem')
        for path in authority_tls.iterdir():
            path.chmod(0o600)
        cert = root / 'fullchain.pem'; key = root / 'private-key.pem'
        run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=blindpass.example',
             '-addext', 'subjectAltName=DNS:blindpass.example,DNS:input.example',
             '-addext', 'basicConstraints=critical,CA:FALSE', '-keyout', str(key), '-out', str(cert)])
        cert.chmod(0o600); key.chmod(0o600)
        shutil.copy(cert, probe_dir / 'fullchain.pem'); (probe_dir / 'fullchain.pem').chmod(0o644)
        shutil.copy(HERE / 'p07-probe.py', probe_dir / 'p07-probe.py'); (probe_dir / 'p07-probe.py').chmod(0o644)
        public_key = run(['openssl', 'x509', '-in', str(cert), '-pubkey', '-noout']).stdout
        der = run(['openssl', 'pkey', '-pubin', '-outform', 'der'], data=public_key).stdout
        spki = base64.b64encode(hashlib.sha256(der).digest()).decode()
        env = dict(os.environ, BLINDPASS_CONTROLLER_IMAGE=image, BLINDPASS_PUBLIC_URL='https://blindpass.example',
                   BLINDPASS_UI_BASE_URL='https://input.example', BLINDPASS_TRUST_PROXY=SUBNET + '.3',
                   BLINDPASS_CONTROLLER_IP=SUBNET + '.2', BLINDPASS_EDGE_SUBNET=SUBNET + '.0/24',
                   BLINDPASS_POSTGRES_PASSWORD_FILE=str(password_file), BLINDPASS_DATABASE_CONFIG_DIR=str(config),
                   BLINDPASS_CONTROLLER_TENANT_ID=tenant, BLINDPASS_CONTROLLER_OWNER_ID=owner,
                   BLINDPASS_AUTHORITY_CONFIG_DIR=str(authority_dir))
        base = ['docker', 'compose', '--project-name', project, '--file', str(ROOT / ('deploy/controller/compose.' + profile + '.yml')),
                '--file', str(ROOT / 'deploy/controller/compose.initialize.yml')]

        def compose(*args, **kwargs):
            return run(base + list(args), env=env, **kwargs)

        def controller():
            return compose('ps', '--all', '--quiet', 'controller').stdout.decode().strip()

        def ready():
            name = controller()
            return bool(name) and docker('exec', name, 'blindpass-controller', 'healthcheck', success=False, timeout=5).returncode == 0

        def authority_psql(sql=None, file=None, variables=None, success=True, database='authority'):
            command = ['docker', 'exec', '-i', authority_name, 'psql', '-X', '-q', '-t', '-A', '-h', '127.0.0.1', '-U', 'postgres', '-d', database, '-v', 'ON_ERROR_STOP=1']
            for key_, value in (variables or {}).items():
                command += ['-v', key_ + '=' + value]
            command += ['-f', '-']
            return run(command, data=(sql if sql is not None else (ROOT / 'deploy/controller' / file).read_text()).encode(), success=success)

        issuer = ''

        def variables():
            return {'tenant': tenant, 'owner': owner, 'issuer': issuer}

        def authority_start():
            docker('run', '--detach', '--name', authority_name, '--network', network, '--network-alias', authority_host, '--ip', SUBNET + '.5',
                   '--user', '0', '--mount', 'type=bind,src=' + str(authority_tls) + ',dst=/tls',
                   '--entrypoint', '/bin/sh', '-e', 'POSTGRES_PASSWORD=' + secrets.token_hex(16), AUTHORITY_IMAGE,
                   '-ec', 'install -d -m 0700 -o postgres -g postgres /pgtls && install -m 0600 -o postgres -g postgres /tls/server.key /pgtls/server.key '
                          '&& install -m 0644 -o postgres -g postgres /tls/server.crt /pgtls/server.crt '
                          '&& exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/pgtls/server.crt -c ssl_key_file=/pgtls/server.key')
            wait(lambda: docker('exec', authority_name, 'pg_isready', '-U', 'postgres', success=False).returncode == 0, 60, 'authority did not start')
            wait(lambda: authority_psql('SELECT 1', success=False, database='postgres').returncode == 0, 60, 'authority not accepting commands')
            authority_psql('CREATE DATABASE authority', database='postgres')
            authority_psql(file='recovery-authority.sql')
            authority_psql("CREATE ROLE p07_runtime LOGIN PASSWORD '" + authority_password + "'")
            authority_psql(file='authority-runtime-role.sql', variables={'runtime_role': 'p07_runtime'})
            (authority_dir / 'authority-url').write_text('postgresql://p07_runtime:' + authority_password + '@' + authority_host + ':5432/authority?sslmode=verify-full&sslrootcert=/authority/authority-ca.pem')
            for path in authority_dir.iterdir():
                path.chmod(0o600)
            docker('run', '--rm', '--user', '0', '--mount', 'type=bind,src=' + str(authority_dir) + ',dst=/authority',
                   '--entrypoint', '/bin/sh', helper, '-ec', 'chown -R 10001:10001 /authority')

        port = 0

        def edge_start():
            nonlocal port
            nginx = (ROOT / 'deploy/proxy/nginx.conf.example').read_text().replace('127.0.0.1:3200', 'controller:3200').replace('/etc/nginx/blindpass/', '/fixture/')
            (root / 'nginx.conf').write_text('events {}\nhttp {\n' + nginx + '\n}\n')
            docker('run', '--detach', '--name', edge_name, '--network', network, '--ip', SUBNET + '.3', '--publish', '127.0.0.1::443',
                   '--mount', 'type=bind,src=' + str(root) + ',dst=/fixture,readonly', helper, 'nginx', '-c', '/fixture/nginx.conf', '-g', 'daemon off;')
            port = int(docker('port', edge_name, '443/tcp').stdout.decode().strip().rsplit(':', 1)[1])

            def serving():
                try:
                    return edge_request('blindpass.example', '/readyz')[0] == 200
                except (OSError, http.client.HTTPException):
                    return False
            wait(serving, 20, 'HTTPS edge did not become ready')

        def edge_request(host, path='/', headers=None):
            context = ssl.create_default_context(cafile=str(cert))
            with socket.create_connection(('127.0.0.1', port), timeout=8) as tcp:
                with context.wrap_socket(tcp, server_hostname=host) as tls:
                    values = {'Host': host, 'Connection': 'close', **(headers or {})}
                    tls.sendall(('GET ' + path + ' HTTP/1.1\r\n' + ''.join(k + ': ' + v + '\r\n' for k, v in values.items()) + '\r\n').encode())
                    response = http.client.HTTPResponse(tls); response.begin()
                    return response.status, dict(response.getheaders()), response.read()

        def probe(host, *args, env_extra=None):
            command = ['docker', 'run', '--rm', '--network', network, '--ip', SUBNET + '.' + str(host),
                       '--mount', 'type=bind,src=' + str(probe_dir) + ',dst=/probe,readonly', '-e', 'P07_EDGE_ADDRESS=' + SUBNET + '.3']
            for name, value in (env_extra or {}).items():
                command += ['-e', name + '=' + value]
            command += ['--entrypoint', 'python3', helper, '/probe/p07-probe.py', *args]
            result = run(command, timeout=600)
            lines = [json.loads(line) for line in result.stdout.decode().splitlines() if line.startswith('{')]
            (out / ('probe-' + str(host) + '-' + str(int(time.time() * 1000)) + '.jsonl')).write_text('\n'.join(json.dumps(line) for line in lines) + '\n')
            return lines

        def db(sql):
            """Read-only query against the profile's own store. SQL uses single-quoted literals only."""
            if profile == 'postgres':
                qualified = re.sub(r'\b(FROM) (\w+)', r'\1 controller.\2', sql)
                result = compose('exec', '-T', 'postgres', 'psql', '-U', 'blindpass', '-d', 'blindpass', '-At', '-F', '\t', '-c', qualified)
                rows = [line.split('\t') for line in result.stdout.decode().splitlines() if line != '']
                return [[int(value) if re.fullmatch(r'-?\d+', value) else (None if value == '' else value) for value in row] for row in rows]
            code = ("import sqlite3,json\nc=sqlite3.connect('file:/data/controller.db?mode=ro',uri=True,timeout=20)\n"
                    'print(json.dumps(c.execute(' + repr(sql) + ').fetchall()))')
            result = docker('run', '--rm', '--user', '10001:10001', '--mount', 'type=volume,src=' + project + '_blindpass-data,dst=/data',
                            '--entrypoint', 'python3', helper, '-c', code)
            return json.loads(result.stdout)

        def node(step, **overrides):
            cfg = {'port': port, 'spki': spki, 'username': username, 'password': operator_password, 'outDir': str(out),
                   'controllerContainer': controller(), **overrides}
            path = private_dir / 'node-cfg.json'
            path.write_text(json.dumps(cfg)); path.chmod(0o600)
            result = subprocess.run(['node', str(HERE / 'p07-profile-browser.mjs'), step], cwd=ROOT,
                                    env=dict(os.environ, P07_CFG=str(path)), capture_output=True, timeout=600)
            text = result.stdout.decode(errors='replace')
            sys.stdout.write(text)
            (out / (step + overrides.get('stepSuffix', '') + '.stdout.txt')).write_text(text)
            summary_path = out / (step + overrides.get('stepSuffix', '') + '.summary.json')
            summary = json.loads(summary_path.read_text()) if summary_path.exists() else {'checks': []}
            for entry in summary['checks']:
                RESULTS.append({'row': 'chromium-' + step, 'name': entry['name'], 'ok': entry['ok']})
            if result.returncode != 0:
                sys.stdout.write(result.stderr.decode(errors='replace')[-1500:])
            return summary

        try:
            docker('run', '--rm', '--user', '0', '--mount', 'type=bind,src=' + str(config) + ',dst=/config',
                   '--entrypoint', '/bin/sh', helper, '-ec', 'chown -R 10001:10001 /config')
            compose('run', '--rm', '--no-deps', 'controller', 'check-config', success=False)
            authority_start()
            compose('--profile', 'initialize', 'run', '--rm', 'keys-init')
            issuer = compose('run', '--rm', '--no-deps', 'controller', 'keys', 'issuer-id', '--directory', '/keys').stdout.decode().strip()
            authority_psql(file='authority-register.sql', variables=variables())
            compose('run', '--rm', 'controller', 'migrate')
            authority_psql(file='authority-activate.sql', variables=variables())
            compose('up', '--detach', 'controller')
            wait(ready, 90 if profile == 'postgres' else 30, 'controller did not become ready')
            edge_start()
            print('stack ready; edge port', port, flush=True)

            # ---- bootstrap abuse (S05) and operator creation ------------------------------------
            if 'bootstrap' in steps:
                token = json.loads(compose('exec', '-T', 'controller', 'blindpass', 'admin', 'bootstrap-token').stdout)['bootstrap_token']
                canaries.append(token)
                flood = []
                first_429 = []
                for index in range(11):
                    lines = probe(10 + index, 'bootstrap', '--attempts', '11', env_extra={'P07_PW': operator_password})
                    flood.append(counts(lines))
                    first_429.append(next((line['i'] for line in lines if line['status'] == 429), None))
                fresh = probe(30, 'bootstrap', '--attempts', '1', env_extra={'P07_PW': operator_password})
                good = probe(31, 'bootstrap', '--attempts', '1', '--token-env', 'P07_TOKEN', '--username', username,
                             env_extra={'P07_PW': operator_password, 'P07_TOKEN': token})
                check('S05-bootstrap', 'wrong tokens from many addresses end in 429 after the per-peer budget, with bounded rows',
                      all(position is not None and position <= 11 for position in first_429), firstTooMany=first_429, perAddress=flood)
                check('S05-bootstrap', 'a fresh address is also refused once the global budget is spent',
                      fresh[0]['status'] == 429, status=fresh[0]['status'], note='informational: global budget is 100 failures per 15 min')
                check('S05-bootstrap', 'the valid token still bootstraps the operator after the flood (not burned, not refused)',
                      good[0]['status'] in (200, 201), status=good[0]['status'])
                rows = db("SELECT COUNT(*) FROM rate_windows WHERE key LIKE 'bootstrap-fail%'")[0][0]
                check('S05-bootstrap', 'limiter state stays bounded (at most 257 rows)', rows <= 257, rows=rows)
                reuse = probe(32, 'bootstrap', '--attempts', '1', '--token-env', 'P07_TOKEN', '--username', 'second' + secrets.token_hex(2),
                              env_extra={'P07_PW': operator_password, 'P07_TOKEN': token})
                used = db('SELECT COUNT(*), COUNT(used_at) FROM bootstrap_tokens')[0]
                check('S05-bootstrap', 'the used token is single use: the row is marked used and a second bootstrap is never 200', reuse[0]['status'] in (409, 429) and used[1] == used[0] and used[0] >= 1,
                      secondStatus=reuse[0]['status'], tokenRows=used[0], usedRows=used[1])

            operator_id = db('SELECT id FROM operators WHERE username = ' + repr(username))[0][0]

            if 's03' in steps:
                node('s03')
            if 's04' in steps:
                status, headers, _ = edge_request('blindpass.example', '/readyz')
                check('S04', 'edge HSTS on /readyz is exactly max-age=31536000', headers.get('Strict-Transport-Security') == 'max-age=31536000', served=headers.get('Strict-Transport-Security'))
                forged = {'X-Forwarded-Proto': 'http', 'Forwarded': 'proto=http', 'X-Forwarded-Host': 'wrong.invalid'}
                status, headers, _ = edge_request('blindpass.example', '/readyz', forged)
                check('S04', 'client-supplied forwarding headers do not change HSTS at the edge', headers.get('Strict-Transport-Security') == 'max-age=31536000')
                unknown_host = edge_request('blindpass.example', '/', {'Host': 'wrong.invalid'})[0]
                check('S04', 'an unknown Host is refused by the edge (421)', unknown_host == 421, status=unknown_host)
                direct = ('import urllib.request,urllib.error,json,sys\n'
                          'def get(headers):\n'
                          '    r=urllib.request.Request("http://controller:3200/readyz",headers=headers)\n'
                          '    try:\n'
                          '        x=urllib.request.urlopen(r); return [x.status,x.headers.get("Strict-Transport-Security")]\n'
                          '    except urllib.error.HTTPError as e: return [e.code,e.headers.get("Strict-Transport-Security")]\n'
                          'print(json.dumps({"trusted_http":get({"Host":"blindpass.example","X-Forwarded-Host":"blindpass.example","X-Forwarded-Proto":"http","X-Forwarded-For":"203.0.113.9"}),'
                          '"trusted_https":get({"Host":"blindpass.example","X-Forwarded-Host":"blindpass.example","X-Forwarded-Proto":"https","X-Forwarded-For":"203.0.113.9"})}))')
                trusted = json.loads(docker('exec', edge_name, 'python3', '-c', direct).stdout)
                untrusted = json.loads(docker('run', '--rm', '--network', network, '--ip', SUBNET + '.4', '--entrypoint', 'python3', helper, '-c',
                                              direct.replace('"trusted_http"', '"u_http"').replace('"trusted_https"', '"u_https"')).stdout)
                check('S04', 'the controller emits no HSTS for a trusted peer that says the client used plain HTTP', trusted['trusted_http'][1] is None, result=trusted['trusted_http'])
                check('S04', 'the controller emits max-age=31536000 only for a trusted peer reporting HTTPS (edge hides and re-adds it)', trusted['trusted_https'][1] == 'max-age=31536000', result=trusted['trusted_https'])
                check('S04', 'an untrusted peer on the internal port is refused (403) and gets no HSTS', untrusted['u_https'][0] == 403 and untrusted['u_https'][1] is None, result=untrusted)
                node('s04')

            # ---- lock shapes through the edge from distinct source addresses (S05) -------------
            attackers = {}
            if 's05' in steps:
                env_wrong = {'P07_PW': wrong_password}
                a_lines = probe(40, 'login', '--users', username, '--attempts', '12', '--password-env', 'P07_PW', env_extra=env_wrong)
                attackers['A'] = a_lines
                first_423 = next((line['i'] for line in a_lines if line['status'] == 423), None)
                check('S05-lock', 'one address is locked for the account after 10 failures (423 with Retry-After)',
                      first_423 is not None and first_423 <= 11 and all(line['retry_after'] for line in a_lines if line['status'] == 423),
                      statuses=[line['status'] for line in a_lines], firstLocked=first_423, retryAfter=next((line['retry_after'] for line in a_lines if line['status'] == 423), None))
                b_lines = probe(41, 'login', '--users', username, '--attempts', '1', '--password-env', 'P07_PW', env_extra={'P07_PW': operator_password})
                check('S05-lock', 'a legitimate sign-in from another address succeeds while the attacker pair is locked', b_lines[0]['status'] == 200, status=b_lines[0]['status'])
                rows = db("SELECT key FROM rate_windows WHERE key LIKE 'operator-login-%'")
                kinds = {}
                for (key,) in rows:
                    kinds[key.split(':')[0]] = kinds.get(key.split(':')[0], 0) + 1
                pair_rows = sorted(key.rsplit(':', 1)[-1][:8] for (key,) in rows if key.startswith('operator-login-src:') or key.startswith('operator-login-slock:'))
                ip_rows = [key for (key,) in rows if key.startswith('operator-login-ipfail:')]
                check('S05-lock', 'after one attacker address failed 12 times only that address and its (account, source) pair hold limiter rows; the legitimate address holds none',
                      len(ip_rows) == 1 and kinds.get('operator-login-slock') == 1, rowKinds=kinds, ipRows=len(ip_rows), pairSourcePrefixes=pair_rows)
                # Unknown username locks exactly like a real one (no 423-versus-401 oracle).
                i_lines = probe(42, 'login', '--users', 'nobody' + secrets.token_hex(3), '--attempts', '12', '--password-env', 'P07_PW', env_extra=env_wrong)
                check('S05-lock', 'an unknown username answers the same status sequence as a real account (no 423-versus-401 oracle)',
                      [line['status'] for line in i_lines] == [line['status'] for line in a_lines], real=[line['status'] for line in a_lines], unknown=[line['status'] for line in i_lines])
                # Account-wide lock from many sources.
                spread = []
                for index in range(6):
                    spread.append(probe(50 + index, 'login', '--users', username, '--attempts', '10', '--password-env', 'P07_PW', env_extra=env_wrong))
                legit = probe(41, 'login', '--users', username, '--attempts', '1', '--password-env', 'P07_PW', env_extra={'P07_PW': operator_password})
                # Seven attacking addresses (A and six more) plus the unknown-name probe I: the controller must hold one
                # per-address failure row and one per-(account, source) row for each, not one shared row.
                account_hash = hashlib.sha256(username.encode()).hexdigest()
                ip_distinct = db("SELECT COUNT(DISTINCT key) FROM rate_windows WHERE key LIKE 'operator-login-ipfail:%'")[0][0]
                # A pair's failure counter becomes a lock row when it reaches the limit, so count both families.
                pair_distinct = db("SELECT COUNT(DISTINCT key) FROM rate_windows WHERE key LIKE 'operator-login-src:" + account_hash + ":%' OR key LIKE 'operator-login-slock:" + account_hash + ":%'")[0][0]
                check('S05-lock', 'the controller held a separate failure row per client address and per (account, source) behind the trusted proxy',
                      ip_distinct >= 7 and pair_distinct >= 5, perAddressRows=ip_distinct, perAccountSourceRows=pair_distinct)
                check('S05-lock', 'guessing spread over six addresses locks the account for every source (423 for the legitimate address too)',
                      legit[0]['status'] == 423 and bool(legit[0]['retry_after']), legit=legit[0], perAddress=[counts(lines) for lines in spread])
                node('locked', expectLocked=True, stepSuffix='-423')
                # Recovery through the packaged admin socket.
                reset = json.loads(compose('exec', '-T', 'controller', 'blindpass', 'admin', 'reset-password', operator_id).stdout)
                temporary = reset.get('temporary_password', '')
                canaries.append(temporary)
                left_rows = db("SELECT key FROM rate_windows WHERE key LIKE 'operator-login-fail:%' OR key LIKE 'operator-login-lock:%' OR key LIKE 'operator-login-src:%' OR key LIKE 'operator-login-slock:%'")
                account_key = hashlib.sha256(username.encode()).hexdigest()
                left = [key.split(':')[0] + ':' + ('account' if account_key in key else 'other') for (key,) in left_rows]
                check('S05-lock', 'the packaged admin-socket reset-password issues a temporary password and clears every limiter row of that account', bool(temporary) and not [row for row in left if row.endswith(':account')], rowsLeft=left)
                after_a = probe(40, 'login', '--users', username, '--attempts', '1', '--password-env', 'P07_PW', env_extra=env_wrong)
                check('S05-lock', 'the previously locked attacker address is no longer locked after the reset (401, not 423)', after_a[0]['status'] == 401, status=after_a[0]['status'])
                node('forced', temporaryPassword=temporary, nextPassword=next_password)
                # Per-address ceiling across many usernames.
                names = ','.join('nobody' + secrets.token_hex(3) for _ in range(40))
                h_lines = probe(70, 'login', '--users', names, '--attempts', '33', '--password-env', 'P07_PW', env_extra=env_wrong)
                first_429 = next((line['i'] for line in h_lines if line['status'] == 429), None)
                check('S05-lock', 'one address guessing many usernames hits the per-address ceiling (429 after 30 failures)', first_429 is not None and 28 <= first_429 <= 33, statuses=counts(h_lines), firstTooMany=first_429)
                other = probe(71, 'login', '--users', username, '--attempts', '1', '--password-env', 'P07_PW', env_extra=env_wrong)
                check('S05-lock', 'another address is unaffected by that ceiling (401, not 429)', other[0]['status'] == 401, status=other[0]['status'])
                node('locked', password=next_password, expectLocked=False, stepSuffix='-ok')

            if 'slow' in steps:
                sessions_before = db('SELECT COUNT(*) FROM operator_sessions')[0][0]
                approvals_before = [db('SELECT COUNT(*) FROM ' + table)[0][0] for table in ('approvals', 'operation_approvals')]
                summary = node('slow', password=next_password)
                time.sleep(6)
                wait(ready, 60, 'controller did not recover after unpause')
                sessions_after = db('SELECT COUNT(*) FROM operator_sessions')[0][0]
                approvals_after = [db('SELECT COUNT(*) FROM ' + table)[0][0] for table in ('approvals', 'operation_approvals')]
                check('S05-slow', 'the paused-controller sign-in changed no approval state', approvals_before == approvals_after, before=approvals_before, after=approvals_after)
                check('S05-slow', 'session rows after the timeout (informational: a stalled request the controller reads after unpause may create an unreachable session)',
                      True, before=sessions_before, after=sessions_after, delta=sessions_after - sessions_before, slow=summary.get('slow'))

            # ---- canary scan over everything this run left behind ------------------------------
            logs_dir = out / 'logs'; logs_dir.mkdir()
            controller_log = compose('logs', '--no-color').stdout
            (logs_dir / 'compose.log').write_bytes(controller_log)
            edge_log = docker('logs', edge_name)
            if (edge_log.stdout + edge_log.stderr).strip():
                (logs_dir / 'edge.log').write_bytes(edge_log.stdout + edge_log.stderr)
            else:
                # The shipped nginx example sets `access_log off` and `error_log /dev/null crit`, so an empty capture is the
                # property under test; the offline scanner rejects empty logs on purpose, so record the reason as a note.
                (out / 'notes').mkdir()
                (out / 'notes' / 'edge-empty-by-design.txt').write_text('the shipped nginx example writes no request or error logs (access_log off; error_log /dev/null crit)\n')
            authority_log = docker('logs', authority_name)
            (logs_dir / 'authority.log').write_bytes(authority_log.stdout + authority_log.stderr)
            data_export = out / 'data'; data_export.mkdir()
            if profile == 'postgres':
                # A text dump of the controller schema stands in for the data file: the scanner reads text and the database is the sink.
                dump = compose('exec', '-T', 'postgres', 'pg_dump', '-U', 'blindpass', '-d', 'blindpass', '--schema=controller').stdout
                (data_export / 'controller-schema.sql').write_bytes(dump)
                (data_export / 'controller-schema.sql').chmod(0o600)
            else:
                # The live WAL holds the newest rows, so the export copies the database, its -wal and its -shm together.
                copy = ('import os,shutil\nfor suffix in ("", "-wal", "-shm"):\n'
                        '    if os.path.exists("/data/controller.db"+suffix):\n'
                        '        shutil.copy("/data/controller.db"+suffix,"/export/controller.db"+suffix)\n'
                        '        os.chown("/export/controller.db"+suffix,' + str(os.getuid()) + ',' + str(os.getgid()) + '); os.chmod("/export/controller.db"+suffix,0o600)')
                docker('run', '--rm', '--user', '0', '--mount', 'type=volume,src=' + project + '_blindpass-data,dst=/data,readonly',
                       '--mount', 'type=bind,src=' + str(data_export) + ',dst=/export', '--entrypoint', 'python3', helper, '-c', copy)
            (out / 'canaries.txt').write_text('\n'.join(canaries) + '\n'); (out / 'canaries.txt').chmod(0o600)
            try:
                canary_log_scan.assert_log_clean('P07 controller compose logs', controller_log, canaries, markers=[b'PRIVATE KEY-----'], require=[b'controller'])
                check('canary', 'controller logs hold no operator, wrong-guess, next or bootstrap canary (positive control passed)', True)
            except AssertionError as error:
                check('canary', 'controller logs hold no canary: ' + str(error)[:160], False)
            try:
                canary_log_scan.assert_log_clean('P07 edge logs', edge_log.stdout + edge_log.stderr, canaries, min_bytes=16,
                                                 allow_empty='the shipped nginx example sets access_log off and error_log /dev/null crit in every server block')
                check('canary', 'edge logs hold no canary (empty by design)', True)
            except AssertionError as error:
                check('canary', 'edge logs hold no canary: ' + str(error)[:160], False)
            offline = subprocess.run([str(ROOT / 'scripts/tests/canary-scan.sh'), '--canaries', str(out / 'canaries.txt'), '--logs',
                                      '--exclude', '*/canaries.txt', '--exclude', '*/scan-offline.json', '--report', str(out / 'scan-offline.json'), str(out)],
                                     capture_output=True, text=True, timeout=600)
            (out / 'scan-offline.txt').write_text(offline.stdout[-4000:])
            check('canary', 'the offline fail-closed scanner (canary-scan.sh) over the run directory: logs, probe output, browser summaries, request lists and the controller database copy',
                  offline.returncode == 0, exit=offline.returncode, summary=offline.stdout.splitlines()[0][:200] if offline.stdout else '')
            if arguments.keep:
                print('kept stack', project, 'port', port, 'out', out, flush=True)
                return finish(out, project)
        finally:
            if not arguments.keep:
                for name in (edge_name, authority_name):
                    docker('rm', '--force', name, success=False)
                compose('down', '--volumes', '--remove-orphans', success=False, timeout=180)
            for path, name in ((config, '/config'), (authority_dir, '/authority')):
                docker('run', '--rm', '--user', '0', '--mount', 'type=bind,src=' + str(path) + ',dst=' + name, '--entrypoint', '/bin/sh', helper,
                       '-ec', 'chown -R ' + str(os.getuid()) + ':' + str(os.getgid()) + ' ' + name, success=False)
    return finish(out, project)


def finish(out, project):
    (out / 'results.json').write_text(json.dumps({'project': project, 'date': time.strftime('%Y-%m-%dT%H:%M:%S%z'), 'results': RESULTS}, indent=1))
    failed = [entry for entry in RESULTS if not entry['ok']]
    print(f'{len(RESULTS) - len(failed)} passed, {len(failed)} failed', flush=True)
    for entry in failed:
        print('FAILED', entry['row'], entry['name'], flush=True)
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
