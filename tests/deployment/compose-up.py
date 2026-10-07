#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Actual P06 OCI/profile gates. All credentials/output remain private in memory.

Uses only uniquely named disposable Docker resources. Requires Docker host access,
the candidate image, and the edge prerequisite built from edge.Dockerfile.
"""
import argparse
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import ssl
import subprocess
import tarfile
import tempfile
import time

import canary_log_scan
import split_custody

ROOT = Path(__file__).resolve().parents[2]
CANARY = b'P06-DUMMY-CONTAINER-EXPOSURE-CANARY'
RUNTIME_BASE = 'debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251'


def run(args, *, env=None, data=None, timeout=90, success=True):
    result = subprocess.run(args, env=env, input=data, capture_output=True, timeout=timeout)
    if success and result.returncode:
        # Never replay raw command output, argv or configuration in failures, unless a
        # developer explicitly asks for diagnostics of a disposable fixture run.
        if os.environ.get('BLINDPASS_HARNESS_DIAGNOSTICS')=='1':
            print('HARNESS-DIAGNOSTIC '+' '.join(map(str,args[:6]))+' :: '+result.stderr[-800:].decode(errors='replace'),flush=True)
        raise AssertionError('scoped deployment command failed: '+args[0])
    return result


def docker(*args, **kwargs):
    return run(['docker', *args], **kwargs)


def wait(check, timeout, description):
    expires = time.monotonic()+timeout
    while True:
        if check():
            assert time.monotonic()<=expires, description
            return
        assert time.monotonic()<expires, description
        time.sleep(0.2)


def image_gate(image, root):
    config = json.loads(docker('image','inspect',image).stdout)[0]['Config']
    assert config['User']=='10001:10001'
    assert config['Entrypoint']==['/usr/local/bin/blindpass-entrypoint']
    assert config['Healthcheck']['Test']==['CMD','/usr/local/bin/blindpass-controller','healthcheck']
    assert not any('PASSWORD=' in value or 'SECRET=' in value for value in config['Env'])
    info = json.loads(docker('run','--rm',image,'--build-info').stdout)
    assert info['console_embedded'] and info['input_embedded']
    docker('run','--rm','--entrypoint','/bin/sh',image,'-ec',
           'test "$(id -u):$(id -g)" = 10001:10001; '
           'test "$(stat -c %a:%u:%g /keys)" = 700:10001:10001; '
           'test "$(stat -c %a:%u:%g /data)" = 700:10001:10001; '
           'test -f /usr/share/doc/blindpass/assets/Inter-OFL.txt; '
           'test -s /usr/share/doc/blindpass/third-party/npm/inventory.json; '
           'test -s /usr/share/doc/blindpass/third-party/rust/inventory.json; '
           '! command -v node; ! command -v curl; ! command -v redis-server; '
           'test ! -e /usr/local/bin/blindpass-broker; '
           'test ! -e /run/docker.sock; '
           'test -z "$(find /keys /data -type f -print -quit)"; '
           'ldd /usr/local/bin/blindpass-controller | grep -q libcrypto.so.3; '
           # ADR 0011 toolkit: exact pinned PGDG packages, no cluster, absolute-path binaries only.
           'bin=/usr/lib/postgresql/16/bin; '
           'for tool in pg_dump pg_restore initdb pg_ctl postgres; do test -x "$bin/$tool"; done; '
           'test "$("$bin/pg_dump" --version | cut -d" " -f3)" = 16.15; '
           'test "$("$bin/postgres" --version | cut -d" " -f3)" = 16.15; '
           'test "$(dpkg-query -W -f=\'${Version}\' postgresql-16)" = 16.15-1.pgdg12+2; '
           'test "$(dpkg-query -W -f=\'${Version}\' postgresql-client-16)" = 16.15-1.pgdg12+2; '
           'test "$(dpkg-query -W -f=\'${Version}\' postgresql-common)" = 293.pgdg12+1; '
           'test "$(dpkg-query -W -f=\'${Version}\' libpq5)" = 18.6-1.pgdg12+2; '
           'test ! -e /var/lib/postgresql/16/main; test ! -e /etc/postgresql/16/main; '
           'test ! -e /etc/apt/sources.list.d/pgdg.list')
    archive=root/'image.tar'
    docker('image','save','--output',str(archive),image,timeout=90)
    # Debian's libgnutls contains a public built-in self-test key. Bind this
    # single exception to the identical binary in the pinned official base.
    # The multiarch directory and base platform follow the image under test.
    machine=docker('image','inspect','--format','{{.Architecture}}',image).stdout.decode().strip()
    triplet={'amd64':'x86_64-linux-gnu','arm64':'aarch64-linux-gnu'}[machine]
    gnutls=f'usr/lib/{triplet}/libgnutls.so.30.34.3'
    base=RUNTIME_BASE
    if machine!='amd64':
        # The local image store keeps one platform per index digest, so address
        # the other platform's manifest inside the same pinned index.
        index=json.loads(docker('buildx','imagetools','inspect','--raw',RUNTIME_BASE).stdout)
        digest=[m['digest'] for m in index['manifests'] if m['platform']['os']=='linux' and m['platform']['architecture']==machine]
        assert len(digest)==1, 'pinned runtime base has no unique platform manifest'
        base='debian@'+digest[0]
    base_digest=docker('run','--rm','--platform',f'linux/{machine}','--entrypoint','sha256sum',base,'/'+gnutls).stdout.split()[0].decode()
    with tarfile.open(archive) as outer:
        # Scan every exported blob/layer, including deleted lower-layer content.
        for member in outer:
            if not member.isfile(): continue
            content=outer.extractfile(member).read()
            if re.search(rb'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----\r?\n[A-Za-z0-9+/]{64}',content):
                with tarfile.open(fileobj=io.BytesIO(content)) as layer:
                    for entry in layer:
                        if not entry.isfile(): continue
                        payload=layer.extractfile(entry).read()
                        if re.search(rb'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----\r?\n[A-Za-z0-9+/]{64}',payload):
                            assert entry.name==gnutls and hashlib.sha256(payload).hexdigest()==base_digest, 'private PEM added to image'
            with io.BytesIO(content) as stream:
                tail=b''
                while chunk:=stream.read(1024*1024):
                    combined=tail+chunk
                    assert CANARY not in combined, 'build context canary leaked into image'
                    tail=combined[-128:]
    archive.unlink()
    print('PASS P06-O01 image UID/layout/embedded UI/licenses/libraries; all exported layers scanned',flush=True)


def profile_gate(profile, image, helper, scenario='profile'):
    project='blindpass-p06-'+profile+'-'+secrets.token_hex(4)
    network=project+'_edge'
    subnet='172.29.'+('61' if profile=='sqlite' else '62')
    edge_name=project+'-edge'
    with tempfile.TemporaryDirectory(prefix=project+'-') as directory:
        root=Path(directory)
        config=root/'config'; config.mkdir(mode=0o700)
        password=secrets.token_hex(32)
        password_file=root/'pg-password'; password_file.write_text(password); password_file.chmod(0o600)
        (config/'database.url').write_text('postgresql://blindpass:'+password+'@postgres:5432/blindpass')
        (config/'database.url').chmod(0o600)
        authority_dir=root/'authority'; authority_dir.mkdir(mode=0o700)
        authority_tls=root/'authority-tls'; authority_tls.mkdir(mode=0o700)
        authority_name=project+'-authority'
        authority_host='authority.p06.invalid'
        authority_password=secrets.token_hex(24)
        tenant='p06_'+profile+'_tenant'; owner='p06_'+profile+'_owner'
        # A remote-style authority: verified TLS is mandatory for a non-loopback host.
        run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=p06 authority ca',
             '-addext','basicConstraints=critical,CA:TRUE','-keyout',str(authority_tls/'ca.key'),'-out',str(authority_tls/'ca.pem')])
        run(['openssl','req','-newkey','rsa:2048','-nodes','-subj','/CN='+authority_host,'-keyout',str(authority_tls/'server.key'),
             '-out',str(authority_tls/'server.csr')])
        (authority_tls/'ext.cnf').write_text('subjectAltName=DNS:'+authority_host+'\nbasicConstraints=CA:FALSE\n')
        run(['openssl','x509','-req','-in',str(authority_tls/'server.csr'),'-CA',str(authority_tls/'ca.pem'),'-CAkey',str(authority_tls/'ca.key'),
             '-CAcreateserial','-days','1','-extfile',str(authority_tls/'ext.cnf'),'-out',str(authority_tls/'server.crt')])
        shutil.copy(authority_tls/'ca.pem',authority_dir/'authority-ca.pem')
        for path in authority_tls.iterdir(): path.chmod(0o600)
        cert=root/'fullchain.pem'; key=root/'private-key.pem'
        run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=blindpass.example',
             '-addext','subjectAltName=DNS:blindpass.example,DNS:input.example',
             '-addext','basicConstraints=critical,CA:FALSE','-keyout',str(key),'-out',str(cert)])
        cert.chmod(0o600); key.chmod(0o600)
        env=dict(os.environ, BLINDPASS_CONTROLLER_IMAGE=image, BLINDPASS_PUBLIC_URL='https://blindpass.example', BLINDPASS_UI_BASE_URL='https://input.example', BLINDPASS_TRUST_PROXY=subnet+'.3',
                 BLINDPASS_CONTROLLER_IP=subnet+'.2',BLINDPASS_EDGE_SUBNET=subnet+'.0/24',
                 BLINDPASS_POSTGRES_PASSWORD_FILE=str(password_file),BLINDPASS_DATABASE_CONFIG_DIR=str(config),
                 BLINDPASS_CONTROLLER_TENANT_ID=tenant,BLINDPASS_CONTROLLER_OWNER_ID=owner,BLINDPASS_AUTHORITY_CONFIG_DIR=str(authority_dir))
        base=['docker','compose','--project-name',project,'--file',str(ROOT/'deploy/controller'/('compose.'+profile+'.yml')),
              '--file',str(ROOT/'deploy/controller/compose.initialize.yml')]
        recovery=root/'recovery'; recovery.mkdir(mode=0o700)
        offline=root/'offline'; offline.mkdir(mode=0o700)
        env['BLINDPASS_BACKUP_RECOVERY_DIR']=str(recovery)
        base+=['--file',str(ROOT/('deploy/controller/compose.upgrade-'+profile+'.yml'))]
        if scenario=='handoff':
            # The overlay requires its variables at render time, so only this scenario includes it.
            base+=['--file',str(ROOT/'deploy/controller/compose.handoff-sqlite.yml')]
            env.update(BLINDPASS_HANDOFF_TRANSFER_DIR=str(root),BLINDPASS_HANDOFF_STAGING_DIR=str(root),
                       BLINDPASS_HANDOFF_ID='p06hcplaceholder',BLINDPASS_HANDOFF_ARCHIVE='placeholder.bpbackup')
        if scenario=='recovery':
            # Backup and restore overlays need their variables at render time, so only this scenario includes them.
            base+=['--file',str(ROOT/('deploy/controller/compose.backup-'+profile+'.yml')),
                   '--file',str(ROOT/('deploy/controller/compose.restore-'+profile+'.yml'))]
            env.update(BLINDPASS_RESTORE_ARCHIVE_DIR=str(root),BLINDPASS_RESTORE_STAGING_DIR=str(root),
                       BLINDPASS_RESTORE_ARCHIVE='placeholder.bpbackup',BLINDPASS_RESTORE_ID='p06recplaceholder')
        def compose(*args,**kwargs): return run(base+list(args),env=env,**kwargs)
        def controller(): return compose('ps','--all','--quiet','controller').stdout.decode().strip()
        def ready():
            name=controller()
            return bool(name) and docker('exec',name,'blindpass-controller','healthcheck',success=False,timeout=5).returncode==0
        def metadata():
            query='SELECT tenant_id, issuer_epoch, schema_version FROM controller_meta WHERE id=1'
            if profile=='postgres':
                return compose('exec','-T','postgres','psql','-U','blindpass','-d','blindpass','-At','-c',query).stdout
            # A cleanly stopped WAL database has no -shm to attach on a read-only mount; fall back to an
            # immutable read, valid because nothing writes while the controller is stopped.
            code='import sqlite3,json\n'\
                 'def read(uri): return json.dumps(sqlite3.connect(uri,uri=True).execute('+repr(query)+').fetchall())\n'\
                 'try: print(read("file:/data/controller.db?mode=ro"))\n'\
                 'except sqlite3.OperationalError: print(read("file:/data/controller.db?mode=ro&immutable=1"))'
            return docker('run','--rm','--user','10001:10001','--mount','type=volume,src='+project+'_blindpass-data,dst=/data,readonly',
                          '--entrypoint','python3',helper,'-c',code).stdout
        def keys_digest():
            return docker('run','--rm','--user','10001:10001','--mount','type=volume,src='+project+'_blindpass-keys,dst=/keys,readonly',
                          '--entrypoint','python3',helper,'-c',
                          'from pathlib import Path; import hashlib; h=hashlib.sha256(); '
                          '[h.update(p.read_bytes()) for p in sorted(Path("/keys").iterdir())]; print(h.hexdigest())').stdout
        def keys_edit(code):
            docker('run','--rm','--user','10001:10001','--mount','type=volume,src='+project+'_blindpass-keys,dst=/keys',
                   '--entrypoint','python3',helper,'-c','from pathlib import Path; import os; '+code)
        def request(host,path='/',headers=None):
            context=ssl.create_default_context(cafile=str(cert))
            # Connect to the published loopback port but validate configured SNI.
            import socket
            with socket.create_connection(('127.0.0.1',port),timeout=8) as tcp:
                with context.wrap_socket(tcp,server_hostname=host) as tls:
                    values={'Host':host,'Connection':'close',**(headers or {})}
                    tls.sendall(('GET '+path+' HTTP/1.1\r\n'+''.join(k+': '+v+'\r\n' for k,v in values.items())+'\r\n').encode())
                    response=http.client.HTTPResponse(tls); response.begin()
                    return response.status,dict(response.getheaders()),response.read()
        def edge_start(kind):
            nonlocal port, edge_silent
            nginx=(ROOT/'deploy/proxy/nginx.conf.example').read_text().replace('127.0.0.1:3200','controller:3200')
            caddy=(ROOT/'deploy/proxy/Caddyfile.example').read_text().replace('127.0.0.1:3200','controller:3200')
            nginx=nginx.replace('/etc/nginx/blindpass/','/fixture/')
            # The shipped nginx example logs nothing by design; the Caddy example does log, and must show log content.
            edge_silent=('the shipped nginx example sets access_log off and error_log /dev/null crit in every server block'
                    if kind=='nginx' and nginx.count('access_log off;')>=2 and nginx.count('error_log /dev/null crit;')>=2 else None)
            caddy=caddy.replace('/etc/caddy/blindpass/','/fixture/')
            (root/'nginx.conf').write_text('events {}\nhttp {\n'+nginx+'\n}\n')
            (root/'Caddyfile').write_text(caddy)
            command=['nginx','-c','/fixture/nginx.conf','-g','daemon off;'] if kind=='nginx' else ['caddy','run','--config','/fixture/Caddyfile','--adapter','caddyfile']
            docker('run','--detach','--name',edge_name,'--network',network,'--ip',subnet+'.3',
                   '--publish','127.0.0.1::443','--mount','type=bind,src='+str(root)+',dst=/fixture,readonly',helper,*command)
            port=int(docker('port',edge_name,'443/tcp').stdout.decode().strip().rsplit(':',1)[1])
            def serving():
                try: return request('blindpass.example','/readyz')[0]==200
                except (OSError,http.client.HTTPException): return False
            try:
                wait(serving,15,'HTTPS edge did not become ready')
            except AssertionError:
                # At this point only fixed readiness requests have been sent.
                output=docker('logs',edge_name)
                diagnostic=(output.stdout+output.stderr).decode(errors='replace').replace(str(root),'[fixture]')
                print('edge startup diagnostic: '+diagnostic,flush=True)
                try:
                    status,_,body=request('blindpass.example','/readyz')
                    print('fixed readiness diagnostic: '+str(status)+' '+body.decode(errors='replace')[:300],flush=True)
                except (OSError,http.client.HTTPException) as error:
                    print('fixed readiness transport diagnostic: '+type(error).__name__,flush=True)
                raise
        def authority_psql(sql=None, file=None, variables=None, success=True, database='authority'):
            command=['docker','exec','-i',authority_name,'psql','-X','-q','-t','-A','-h','127.0.0.1','-U','postgres','-d',database,'-v','ON_ERROR_STOP=1']
            for key_,value in (variables or {}).items(): command+=['-v',key_+'='+value]
            command+=['-f','-']
            return run(command,data=(sql if sql is not None else (ROOT/'deploy/controller'/file).read_text()).encode(),success=success)
        def authority_start():
            # Same Docker network as the controller; aliased host verified by TLS.
            docker('run','--detach','--name',authority_name,'--network',network,'--network-alias',authority_host,'--ip',subnet+'.5',
                   '--user','0','--mount','type=bind,src='+str(authority_tls)+',dst=/tls',
                   '--entrypoint','/bin/sh','-e','POSTGRES_PASSWORD='+secrets.token_hex(16),'postgres:16-alpine@sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea',
                   '-ec','install -d -m 0700 -o postgres -g postgres /pgtls && install -m 0600 -o postgres -g postgres /tls/server.key /pgtls/server.key '
                         '&& install -m 0644 -o postgres -g postgres /tls/server.crt /pgtls/server.crt '
                         '&& exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/pgtls/server.crt -c ssl_key_file=/pgtls/server.key')
            wait(lambda: docker('exec',authority_name,'pg_isready','-U','postgres',success=False).returncode==0,60,'authority did not start')
            # The image's init-phase server has no TCP listener; only the final server answers on 127.0.0.1.
            wait(lambda: authority_psql('SELECT 1',success=False,database='postgres').returncode==0,60,'authority not accepting commands')
            authority_psql('CREATE DATABASE authority',database='postgres')
            authority_psql(file='recovery-authority.sql')
            authority_psql("CREATE ROLE p06_runtime LOGIN PASSWORD '"+authority_password+"'")
            authority_psql(file='authority-runtime-role.sql',variables={'runtime_role':'p06_runtime'})
            (authority_dir/'authority-url').write_text('postgresql://p06_runtime:'+authority_password+'@'+authority_host+':5432/authority?sslmode=verify-full&sslrootcert=/authority/authority-ca.pem')
            for path in authority_dir.iterdir(): path.chmod(0o600)
            docker('run','--rm','--user','0','--mount','type=bind,src='+str(authority_dir)+',dst=/authority',
                   '--entrypoint','/bin/sh',helper,'-ec','chown -R 10001:10001 /authority')
        issuer=''
        projectb={}
        def authority_variables(): return {'tenant':tenant,'owner':owner,'issuer':issuer}
        def activate(success=True): return authority_psql(file='authority-activate.sql',variables=authority_variables(),success=success)
        def fence(success=True): return authority_psql(file='authority-fence.sql',variables=authority_variables(),success=success)
        def upgrade_gate():
            # P06-U: locked SQLite upgrade of a genuinely older (schema 18) database.
            split_custody.provision(docker,image,helper,recovery,offline)
            split_custody.assert_host_holds_no_decrypt_key(docker,helper,recovery)
            volume='type=volume,src='+project+'_blindpass-data,dst=/data'
            def data_python(code,write=False):
                mount=volume if write else volume+',readonly'
                return docker('run','--rm','--user','10001:10001','--mount',mount,'--entrypoint','python3',helper,'-c',code).stdout.decode().strip()
            def schema():
                return int(data_python('import sqlite3\ndef r(u): return sqlite3.connect(u,uri=True).execute("SELECT schema_version FROM controller_meta").fetchone()[0]\n'
                                       'try: print(r("file:/data/controller.db?mode=ro"))\nexcept sqlite3.OperationalError: print(r("file:/data/controller.db?mode=ro&immutable=1"))'))
            def upgrade(success=True): return compose('--profile','upgrade','run','--rm','controller-upgrade',success=success,timeout=300)
            compose('stop','controller')
            # The previous holder is gone but its record is still active: no migration yet.
            upgrade(success=False); assert schema()==20
            fence()
            data_python('import sqlite3; c=sqlite3.connect("/data/controller.db"); '
                        '[c.execute("DROP TABLE "+t) for t in ("cross_fulfillment_payloads","cross_fulfillments","controller_recovery_intents","controller_recovery_reports")]; '
                        'c.execute("UPDATE controller_meta SET schema_version=18 WHERE id=1"); c.commit(); '
                        'c.execute("PRAGMA wal_checkpoint(TRUNCATE)"); c.close()',write=True)
            assert schema()==18
            # Without the protected key the older schema is never touched.
            def recovery_move(source,target):
                docker('run','--rm','--user','10001:10001','--mount','type=bind,src='+str(recovery)+',dst=/recovery',
                       '--entrypoint','mv',helper,'/recovery/'+source,'/recovery/'+target)
            recovery_move('signing.pem','held.pem')
            upgrade(success=False); assert schema()==18
            recovery_move('held.pem','signing.pem')
            output=upgrade().stdout.decode()
            assert '"from_schema":18' in output and '"backup_taken":true' in output and schema()==19
            listing=data_python('from pathlib import Path; import json; r=Path("/data/pre-upgrade-backups"); '
                                'print(json.dumps({d.name:[f.name for f in d.iterdir()] for d in r.iterdir()}))')
            backups=json.loads(listing); assert len(backups)==1, 'one pre-upgrade backup expected'
            name,files=next(iter(backups.items())); assert re.fullmatch(r'pre-upgrade-\d{13}-v18',name)
            archive=[f for f in files if f.endswith('.bpbackup')]; assert len(archive)==1
            # Only the operator's offline material opens the archive; the job's own custody cannot.
            opened=['--volume',str(offline)+':/offline:ro']
            refused=compose('--profile','upgrade','run','--rm','--no-deps','controller-upgrade','backup','verify','--archive','/data/pre-upgrade-backups/'+name+'/'+archive[0],
                            '--recipient-key-file','/recovery/signing.pem','--signing-certificate-file','/recovery/signing-certificate.pem','--work-directory','/data/pre-upgrade-backups/'+name,success=False)
            assert refused.returncode!=0, 'the backup host credential opened its own archive'
            verified=compose('--profile','upgrade','run','--rm','--no-deps',*opened,'controller-upgrade','backup','verify','--archive','/data/pre-upgrade-backups/'+name+'/'+archive[0],
                             *split_custody.OFFLINE_OPEN,'--work-directory','/data/pre-upgrade-backups/'+name)
            assert json.loads(verified.stdout)['schema_version']==18 and json.loads(verified.stdout)['verified'] is True
            upgrade(); assert len(json.loads(data_python('from pathlib import Path; import json; print(json.dumps(sorted(d.name for d in Path("/data/pre-upgrade-backups").iterdir())))')))==1
            # An upgraded controller still needs a fresh activation and keeps its identity.
            compose('up','--detach','--force-recreate','controller')
            time.sleep(4); assert not ready(), 'controller became ready without an activation after upgrade'
            compose('stop','controller'); activate()
            compose('up','--detach','--force-recreate','controller'); wait(ready,20,'controller did not start after upgrade')
            assert metadata()==before and keys_digest()==key_hash
            logs=compose('logs','--no-color').stdout
            canary_log_scan.assert_log_clean('P06-U sqlite compose logs',logs,[authority_password],markers=[b'PRIVATE KEY-----'],require=[b'controller'])
            print('PASS P06-U Compose SQLite: schema18 upgraded after a verified encrypted backup, retained identity, fresh activation required',flush=True)
        def upgrade_gate_postgres():
            # P06-U: locked PostgreSQL upgrade of a genuinely older (schema 18) store.
            split_custody.provision(docker,image,helper,recovery,offline)
            split_custody.assert_host_holds_no_decrypt_key(docker,helper,recovery)
            def sql(statement): return compose('exec','-T','postgres','psql','-U','blindpass','-d','blindpass','-X','-q','-At','-v','ON_ERROR_STOP=1','-c',statement).stdout.decode().strip()
            def schema(): return int(sql('SELECT schema_version FROM controller_meta WHERE id=1'))
            def upgrade(success=True): return compose('--profile','upgrade','run','--rm','controller-upgrade',success=success,timeout=600)
            def recovery_move(source,target):
                docker('run','--rm','--user','10001:10001','--mount','type=bind,src='+str(recovery)+',dst=/recovery',
                       '--entrypoint','mv',helper,'/recovery/'+source,'/recovery/'+target)
            def backups():
                return json.loads(docker('run','--rm','--user','10001:10001','--mount','type=volume,src='+project+'_blindpass-data,dst=/data,readonly',
                    '--entrypoint','python3',helper,'-c','from pathlib import Path; import json; r=Path("/data/pre-upgrade-backups"); '
                    'print(json.dumps({d.name:[f.name for f in d.iterdir()] for d in r.iterdir()} if r.exists() else {}))').stdout)
            compose('stop','controller')
            # The previous holder is gone but its record is still active: no migration yet.
            upgrade(success=False); assert schema()==20
            fence()
            sql('DROP TABLE cross_fulfillment_payloads, cross_fulfillments, controller_recovery_intents, controller_recovery_reports; UPDATE controller_meta SET schema_version=18 WHERE id=1')
            assert schema()==18
            # Without the protected key the older schema is never touched.
            recovery_move('signing.pem','held.pem')
            upgrade(success=False); assert schema()==18 and not backups()
            recovery_move('held.pem','signing.pem')
            output=upgrade().stdout.decode()
            assert '"from_schema":18' in output and '"backup_taken":true' in output and schema()==19
            taken=backups(); assert len(taken)==1, 'one pre-upgrade backup expected'
            name,files=next(iter(taken.items())); assert re.fullmatch(r'pre-upgrade-\d{13}-v18',name)
            archive=[f for f in files if f.endswith('.bpbackup')]; assert len(archive)==1
            opened=['--volume',str(offline)+':/offline:ro']
            refused=compose('--profile','upgrade','run','--rm','--no-deps','controller-upgrade','backup','verify','--archive','/data/pre-upgrade-backups/'+name+'/'+archive[0],
                            '--recipient-key-file','/recovery/signing.pem','--signing-certificate-file','/recovery/signing-certificate.pem','--work-directory','/data/pre-upgrade-backups/'+name,success=False,timeout=600)
            assert refused.returncode!=0, 'the backup host credential opened its own archive'
            verified=compose('--profile','upgrade','run','--rm','--no-deps',*opened,'controller-upgrade','backup','verify','--archive','/data/pre-upgrade-backups/'+name+'/'+archive[0],
                             *split_custody.OFFLINE_OPEN,'--work-directory','/data/pre-upgrade-backups/'+name,timeout=600)
            result=json.loads(verified.stdout); assert result['schema_version']==18 and result['verified'] is True
            upgrade(); assert len(backups())==1
            compose('up','--detach','--force-recreate','controller')
            time.sleep(4); assert not ready(), 'controller became ready without an activation after upgrade'
            compose('stop','controller'); activate()
            compose('up','--detach','--force-recreate','controller'); wait(ready,20,'controller did not start after upgrade')
            assert metadata()==before and keys_digest()==key_hash
            logs=compose('logs','--no-color').stdout
            canary_log_scan.assert_log_clean('P06-U postgres compose logs',logs,[authority_password],markers=[b'PRIVATE KEY-----'],require=[b'controller'])
            print('PASS P06-U Compose PostgreSQL: schema18 upgraded after a verified encrypted backup, retained identity, fresh activation required',flush=True)
        def handoff_gate():
            # P06-D28: planned same-owner handoff between two Compose projects that share one authority.
            # Project B is a second, independent project (own volumes, network and containers) that
            # receives the staged keys and database and takes over the authority record.
            def own(path):
                docker('run','--rm','--user','0','--mount','type=bind,src='+str(path)+',dst=/d','--entrypoint','/bin/sh',helper,'-ec','chown -R 10001:10001 /d')
            def listing(path):
                return json.loads(docker('run','--rm','--user','10001:10001','--mount','type=bind,src='+str(path)+',dst=/d,readonly',
                                         '--entrypoint','python3',helper,'-c','import os,json; print(json.dumps(sorted(os.listdir("/d"))))').stdout)
            split_custody.provision(docker,image,helper,recovery,offline)
            split_custody.assert_host_holds_no_decrypt_key(docker,helper,recovery)
            transfer=root/'handoff-transfer'; staging=root/'handoff-staging'
            for path in (transfer,staging): path.mkdir(mode=0o700); own(path)
            env['BLINDPASS_HANDOFF_TRANSFER_DIR']=str(transfer); env['BLINDPASS_HANDOFF_STAGING_DIR']=str(staging)
            project_b=project+'-b'; subnet_b='172.29.63'
            env_b=dict(env,BLINDPASS_TRUST_PROXY=subnet_b+'.3',BLINDPASS_CONTROLLER_IP=subnet_b+'.2',BLINDPASS_EDGE_SUBNET=subnet_b+'.0/24')
            base_b=['docker','compose','--project-name',project_b,'--file',str(ROOT/'deploy/controller/compose.sqlite.yml'),
                    '--file',str(ROOT/'deploy/controller/compose.handoff-sqlite.yml')]
            def compose_b(*args,**kwargs): return run(base_b+list(args),env=env_b,**kwargs)
            def controller_b(): return compose_b('ps','--all','--quiet','controller').stdout.decode().strip()
            def ready_b():
                name=controller_b()
                return bool(name) and docker('exec',name,'blindpass-controller','healthcheck',success=False,timeout=5).returncode==0
            def metadata_b():
                query='SELECT tenant_id, issuer_epoch, schema_version FROM controller_meta WHERE id=1'
                code='import sqlite3,json\ndef read(uri): return json.dumps(sqlite3.connect(uri,uri=True).execute('+repr(query)+').fetchall())\n'\
                     'try: print(read("file:/data/controller.db?mode=ro"))\nexcept sqlite3.OperationalError: print(read("file:/data/controller.db?mode=ro&immutable=1"))'
                return docker('run','--rm','--user','10001:10001','--mount','type=volume,src='+project_b+'_blindpass-data,dst=/data,readonly',
                              '--entrypoint','python3',helper,'-c',code).stdout
            def keys_digest_b():
                return docker('run','--rm','--user','10001:10001','--mount','type=volume,src='+project_b+'_blindpass-keys,dst=/keys,readonly',
                              '--entrypoint','python3',helper,'-c',
                              'from pathlib import Path; import hashlib; h=hashlib.sha256(); '
                              '[h.update(p.read_bytes()) for p in sorted(Path("/keys").iterdir())]; print(h.hexdigest())').stdout
            def source_marker():
                return docker('run','--rm','--user','10001:10001','--mount','type=volume,src='+project+'_blindpass-data,dst=/data,readonly',
                              '--entrypoint','python3',helper,'-c','import os; print(os.path.exists("/data/handoff-marker.json"))').stdout.decode().strip()=='True'
            def job(name,*,success=True,use=None,timeout=300):
                return (use or compose)('--profile','handoff','run','--rm',name,success=success,timeout=timeout)
            def summary(result): return json.loads(result.stdout.decode().strip().splitlines()[-1])
            compose('stop','controller'); fence()
            first='p06hc'+secrets.token_hex(3); env['BLINDPASS_HANDOFF_ID']=first
            exported=summary(job('controller-handoff-export'))
            assert exported['handoff']=='exported' and exported['handoff_id']==first and source_marker()
            assert summary(job('controller-handoff-export'))['archive_sha256']==exported['archive_sha256'], 'repeated export changed the archive'
            env['BLINDPASS_HANDOFF_ID']='p06hc'+secrets.token_hex(3)
            assert job('controller-handoff-export',success=False).returncode!=0, 'a second handoff id was exported while a marker exists'
            env['BLINDPASS_HANDOFF_ID']=first
            assert compose('run','--rm','controller','migrate',success=False).returncode!=0, 'a retired source migrated'
            print('PASS P06-H1 Compose SQLite: fenced source exported and retired; repeat export idempotent, a second handoff id and migrate refused',flush=True)
            assert summary(job('controller-handoff-abort'))['handoff']=='aborted'
            assert not source_marker() and listing(transfer)==[], 'abort left the marker or the transfer package'
            activate(); compose('up','--detach','--force-recreate','controller'); wait(ready,20,'the aborted source did not serve again')
            assert metadata()==before and keys_digest()==key_hash
            compose('stop','controller'); fence()
            second='p06hc'+secrets.token_hex(3); env['BLINDPASS_HANDOFF_ID']=second
            exported=summary(job('controller-handoff-export')); env['BLINDPASS_HANDOFF_ARCHIVE']=exported['archive']
            print('PASS P06-H2 Compose SQLite: abort before activation removed marker and package, the source served again with identity/keys unchanged, then exported again',flush=True)
            # The backup host's directory cannot open the package; only the offline material can.
            assert job('controller-handoff-import',success=False).returncode!=0, 'host custody imported the package'
            assert listing(staging)==[], 'a refused import left staged state'
            env['BLINDPASS_BACKUP_RECOVERY_DIR']=str(offline)
            imported=summary(job('controller-handoff-import'))
            assert imported['handoff']=='imported' and imported['activation_required'] is True and imported['backend']=='sqlite'
            assert listing(staging)==['root']
            assert job('controller-handoff-import',success=False).returncode!=0, 'a second import into the staged root was accepted'
            env['BLINDPASS_BACKUP_RECOVERY_DIR']=str(recovery)
            record=authority_psql("SELECT phase||':'||epoch FROM blindpass_authority.recovery_authority").stdout.decode().strip()
            assert record.startswith('fenced:'), record
            # Destination project: empty volumes, the shared authority on its network, install, then activate.
            compose_b('up','--no-start','controller')
            docker('network','connect','--alias',authority_host,'--ip',subnet_b+'.5',project_b+'_edge',authority_name)
            assert json.loads(job('controller-handoff-install',use=compose_b).stdout.decode().strip().splitlines()[-1])=={'handoff':'installed'}
            assert job('controller-handoff-install',use=compose_b,success=False).returncode!=0, 'install overwrote non-empty destination volumes'
            print('PASS P06-H3 Compose SQLite: archive verified and imported into a new staging root with the record still fenced; destination volumes installed once and a second install refused',flush=True)
            activate(); started=time.monotonic(); compose_b('up','--detach','controller')
            wait(ready_b,30,'the destination project did not become ready')
            took=time.monotonic()-started
            assert metadata_b()==before and keys_digest_b()==key_hash
            assert compose_b('exec','-T','controller','blindpass','admin','bootstrap',success=False).returncode!=0, 'the destination lost its administrator'
            print(f'PASS P06-H4 Compose SQLite: second project ready {took:.3f}s after activation with the same tenant/issuer/schema and key bytes; administrator carried over',flush=True)
            compose('up','--detach','--force-recreate','controller'); time.sleep(4)
            assert not ready(), 'the stale source became ready while the destination holds the record'
            assert ready_b(), 'a stale source start disturbed the destination'
            assert job('controller-handoff-abort',success=False).returncode!=0, 'abort succeeded after the destination activated'
            assert source_marker(), 'a refused abort removed the marker'
            compose('stop','controller'); compose_b('stop','controller'); activate()
            refused=compose('run','--rm','controller','serve',success=False,timeout=60)
            assert refused.returncode!=0 and b'"reason":"handoff_retired"' in refused.stdout+refused.stderr, 'stale source was not refused by its retirement marker'
            activate(); compose_b('up','--detach','--force-recreate','controller'); wait(ready_b,30,'the destination did not restart')
            assert metadata_b()==before and keys_digest_b()==key_hash
            logs=compose('logs','--no-color').stdout+compose_b('logs','--no-color').stdout
            canary_log_scan.assert_log_clean('P06-H5 sqlite handoff compose logs',logs,[authority_password,temporary_password],markers=[b'PRIVATE KEY-----'],require=[b'controller'])
            print('PASS P06-H5 Compose SQLite: stale source refused while the destination ran (not ready, destination undisturbed), abort refused after activation, and refused by its retirement marker with the record freshly activated; destination restarted; no credentials in logs',flush=True)
        def recovery_gate():
            # P06-D30..D32 on the shipped profile: authenticated backup, total loss of the controller's
            # state, restore through the shipped restore jobs under a reserved recovery epoch, operator
            # review, source-stop attestation and activation. No real node exists in Compose, so one node
            # is seeded into the authority's broker trust; it is covered only by an explicit named waiver
            # (the real relay path is exercised in the QEMU harnesses).
            def own(path): split_custody.own(docker,helper,path)
            split_custody.provision(docker,image,helper,recovery,offline)
            split_custody.assert_host_holds_no_decrypt_key(docker,helper,recovery)
            archives=root/'recovery-archives'; staging=root/'recovery-staging'
            for path in (archives,staging): path.mkdir(mode=0o700); own(path)
            env['BLINDPASS_RESTORE_ARCHIVE_DIR']=str(archives); env['BLINDPASS_RESTORE_STAGING_DIR']=str(staging)
            volume_data=project+'_blindpass-data'; volume_keys=project+'_blindpass-keys'
            node_id='nd_p06recovery0001'
            def sql(statement): return compose('exec','-T','postgres','psql','-U','blindpass','-d','blindpass','-X','-q','-At','-v','ON_ERROR_STOP=1','-c',statement).stdout.decode().strip()
            def volume_python(volume,code,write=False):
                return docker('run','--rm','--user','10001:10001','--mount','type=volume,src='+volume+',dst=/v'+('' if write else ',readonly'),
                              '--entrypoint','python3',helper,'-c',code)
            def cli(*args,success=True):
                return compose('exec','-T','controller','blindpass','admin','recovery',*args,success=success)
            def cli_json(*args): return json.loads(cli(*args).stdout.decode())
            def script(name,**extra):
                return authority_psql(file=name,variables={**authority_variables(),**extra},success=False)
            def refused_with(result,*gates,label):
                text=result.stderr.decode()
                assert result.returncode!=0, label+': the authority accepted what it must refuse'
                for gate in gates: assert gate in text, label+': refusal does not name '+gate
                return text
            def ledger(): return authority_psql("SELECT phase||':'||epoch||':'||revision FROM blindpass_authority.recovery_authority WHERE tenant_id='"+tenant+"'").stdout.decode().strip()
            compose('stop','controller')
            # 1. authenticated, split-custody backup through the shipped job; the archive leaves the volume.
            compose('--profile','backup','run','--rm','controller-backup',timeout=300)
            archive_name=json.loads(docker('run','--rm','--user','10001:10001','--mount','type=volume,src='+volume_data+',dst=/v,readonly',
                '--mount','type=bind,src='+str(archives)+',dst=/out','--entrypoint','python3',helper,'-c',
                'import pathlib,shutil,json\nfound=sorted(pathlib.Path("/v/backups").rglob("*.bpbackup"))\nassert len(found)==1,found\n'
                'shutil.copy(found[0],"/out/"+found[0].name)\nprint(json.dumps(found[0].name))').stdout.decode().strip())
            env['BLINDPASS_RESTORE_ARCHIVE']=archive_name
            print('PASS P06-RC1 Compose '+profile+': authenticated split-custody backup of a running controller',flush=True)
            # 2. fence, reserve the recovery epoch, then lose everything the controller owns.
            fence()
            revision=authority_psql("SELECT revision FROM blindpass_authority.recovery_authority WHERE tenant_id='"+tenant+"'").stdout.decode().strip()
            reserved=authority_psql("SELECT epoch||':'||phase FROM blindpass_authority.reserve_recovery('"+tenant+"','"+issuer+"','"+owner+"',"+revision+",1)").stdout.decode().strip()
            assert reserved.endswith(':recovering'), reserved
            reserved_epoch=int(reserved.split(':')[0])
            # The authority trusts one active broker that no restored controller has ever heard from: the
            # activation gate must refuse until that node is covered by a relay receipt or waived by name.
            authority_psql("INSERT INTO blindpass_authority.broker_trust (tenant_id,issuer_key_id,node_id,key_version,signing_public,recipient_public,state,revision) VALUES (:'tenant',:'issuer','"+node_id+"',1,'"+secrets.token_urlsafe(32)[:43]+"','"+secrets.token_urlsafe(32)[:43]+"','active',1)",variables=authority_variables())
            volume_python(volume_keys,'import pathlib,shutil\n[shutil.rmtree(p) if p.is_dir() else p.unlink() for p in pathlib.Path("/v").iterdir()]',write=True)
            volume_python(volume_data,'import pathlib,shutil\n[shutil.rmtree(p) if p.is_dir() else p.unlink() for p in pathlib.Path("/v").iterdir()]',write=True)
            if profile=='postgres': sql('DROP SCHEMA controller CASCADE')
            # 3. restore through the shipped jobs with the OFFLINE material only; the backup host's directory cannot open it.
            env['BLINDPASS_RESTORE_ID']='p06rc'+secrets.token_hex(3)
            assert compose('--profile','restore','run','--rm','controller-restore',success=False,timeout=300).returncode!=0, 'host custody restored the archive'
            env['BLINDPASS_BACKUP_RECOVERY_DIR']=str(offline)
            receipt=json.loads(compose('--profile','restore','run','--rm','controller-restore',timeout=600).stdout.decode().strip().splitlines()[-1])
            assert receipt['phase']=='recovery_required' and receipt['activation_permitted'] is False and receipt['backend']==profile, receipt
            assert json.loads(compose('--profile','restore','run','--rm','controller-restore-install',timeout=300).stdout.decode().strip().splitlines()[-1])=={'restore':'installed'}
            assert compose('--profile','restore','run','--rm','controller-restore-install',success=False).returncode!=0, 'install overwrote non-empty destination volumes'
            env['BLINDPASS_BACKUP_RECOVERY_DIR']=str(recovery)
            assert keys_digest()==key_hash, 'restored keys differ from the source keys'
            print(f'PASS P06-RC2 Compose {profile}: all controller state lost, restored through the shipped jobs under reserved recovery epoch {reserved_epoch}; offline custody required; keys byte-identical; install refuses non-empty volumes',flush=True)
            # 4. the restored controller starts fenced and answers only recovery-required.
            compose('up','--detach','--force-recreate','controller')
            wait(lambda: bool(controller()) and docker('exec',controller(),'blindpass','admin','recovery','status',success=False,timeout=10).returncode==0,30,'recovering controller did not start')
            time.sleep(2); assert not ready(), 'the recovering controller reported ready'
            gaps=cli_json('status')['gaps']
            assert set(gaps)>={'source_stop_missing','review_incomplete','node_uncovered'}, gaps
            print('PASS P06-RC3 Compose '+profile+': restored controller is recovering (not ready); precheck lists '+','.join(sorted(gaps)),flush=True)
            # 5. refusals at the packaged level.
            before_ledger=ledger()
            refused_with(script('authority-activate.sql'),label='ordinary activation of a recovering record')
            refused_with(script('authority-recover-activate.sql'),'source_stop_missing','review_incomplete','node_uncovered',label='early recovery activation')
            refused_with(script('authority-recover-attest.sql',host='p06-source',by='p06-admin',note='premature'),label='attestation while a controller holds the guard')
            assert ledger()==before_ledger, 'refusals changed the authority record'
            listing=cli_json('review','list')['items']
            assert listing and any(i['category']=='operator' for i in listing), 'review list is empty'
            undecided=cli('review','complete','--operator','p06-operator',success=False)
            assert undecided.returncode!=0, 'complete accepted an undecided review'
            for category in sorted({i['category'] for i in listing}):
                cli_json('review','decide','--category',category,'--decision',{'operator':'accept','operation':'accept','workload':'revoke'}.get(category,'reject'),'--operator','p06-operator','--note','packaged recovery rehearsal')
            uncovered=cli('review','complete','--operator','p06-operator',success=False)
            assert uncovered.returncode!=0, 'complete accepted a node that is neither covered nor waived'
            assert 'node_uncovered' in cli_json('status')['gaps'], 'the uncovered node left the precheck'
            cli_json('waive-node',node_id,'--operator','p06-operator','--note','no real node exists in Compose')
            done=cli_json('review','complete','--operator','p06-operator')
            assert cli_json('status')['gaps']==['source_stop_missing'], cli_json('status')['gaps']
            print('PASS P06-RC4 Compose '+profile+f': ordinary activation, early recovery activation and a premature attestation refused with the ledger unchanged; undecided and uncovered-node completions refused; waiver by name then completion ({done["summary"]}); only source_stop_missing remains',flush=True)
            # 6. stop, attest, activate, serve.
            compose('stop','controller')
            text=refused_with(script('authority-recover-activate.sql'),'source_stop_missing',label='activation without attestation')
            assert 'review_incomplete' not in text and 'node_uncovered' not in text
            attested=script('authority-recover-attest.sql',host='p06-source-host',by='p06-admin',note='source stack stopped and fenced from the authority')
            assert attested.returncode==0, 'attestation refused although every controller is stopped'
            row=authority_psql("SELECT host_id||':'||attested_by FROM blindpass_authority.recovery_source_stop ORDER BY epoch DESC LIMIT 1").stdout.decode().strip()
            assert row=='p06-source-host:p06-admin', row
            activated=script('authority-recover-activate.sql')
            assert activated.returncode==0 and 'activated recovery epoch' in activated.stdout.decode(), 'recovery activation refused with every gate met'
            refused_with(script('authority-recover-activate.sql'),label='second recovery activation')
            started=time.monotonic(); compose('up','--detach','--force-recreate','controller')
            wait(ready,30,'the activated controller did not become ready'); took=time.monotonic()-started
            assert keys_digest()==key_hash
            compose('stop','controller')
            def identity(raw):
                text=raw.decode().strip()
                row=json.loads(text)[0] if profile=='sqlite' else text.split('|')
                return str(row[0]),str(row[2])
            assert identity(metadata())==identity(before), (identity(metadata()),identity(before))
            print(f'PASS P06-RC5 Compose {profile}: attested ({row}) and activated; the controller serves {took:.1f}s after start with the same tenant, schema and key bytes; ordinary activation and a second recovery activation refused',flush=True)
            # 6b. stale source: restore the SAME archive into a SECOND Compose project with fresh volumes
            # (same authority), activate it through review, attestation and activation, then prove the
            # original stack (stopped, volumes intact) can no longer be activated or served.
            project_b=project+'-r'
            subnet_b='172.29.'+('71' if profile=='sqlite' else '72')
            env_b=dict(env,BLINDPASS_EDGE_SUBNET=subnet_b+'.0/24',BLINDPASS_CONTROLLER_IP=subnet_b+'.2',BLINDPASS_TRUST_PROXY=subnet_b+'.3')
            base_b=base[:2]+['--project-name',project_b]+base[4:]
            projectb.update(base=base_b,env=env_b)
            def compose_b(*args,**kwargs): return run(base_b+list(args),env=env_b,**kwargs)
            def controller_b(): return compose_b('ps','--all','--quiet','controller').stdout.decode().strip()
            def ready_b():
                name=controller_b()
                return bool(name) and docker('exec',name,'blindpass-controller','healthcheck',success=False,timeout=5).returncode==0
            def cli_b(*args,success=True): return compose_b('exec','-T','controller','blindpass','admin','recovery',*args,success=success)
            def cli_json_b(*args): return json.loads(cli_b(*args).stdout.decode())
            original_data=volume_python(volume_data,'import pathlib,hashlib\nh=hashlib.sha256()\n[h.update(p.read_bytes()) for p in sorted(pathlib.Path("/v").rglob("controller.db"))]\nprint(h.hexdigest())').stdout.decode().strip() if profile=='sqlite' else ''
            compose('stop','controller'); fence()
            revision=authority_psql("SELECT revision FROM blindpass_authority.recovery_authority WHERE tenant_id='"+tenant+"'").stdout.decode().strip()
            third=authority_psql("SELECT epoch||':'||phase FROM blindpass_authority.reserve_recovery('"+tenant+"','"+issuer+"','"+owner+"',"+revision+",1)").stdout.decode().strip()
            assert third.endswith(':recovering') and int(third.split(':')[0])>reserved_epoch, third
            b_epoch=int(third.split(':')[0])
            compose_b('create','controller')
            docker('network','connect','--alias',authority_host,'--ip',subnet_b+'.5',project_b+'_edge',authority_name)
            if profile=='postgres':
                # The documented operator step: the init hook's empty `controller` schema must go before a restore.
                compose_b('up','--detach','--wait','postgres',timeout=120)
                compose_b('exec','-T','postgres','psql','-U','blindpass','-d','blindpass','-X','-q','-v','ON_ERROR_STOP=1','-c','DROP SCHEMA controller CASCADE')
            staging_b=root/'recovery-staging-b'; staging_b.mkdir(mode=0o700); own(staging_b)
            env_b.update(BLINDPASS_RESTORE_STAGING_DIR=str(staging_b),BLINDPASS_RESTORE_ID='p06rb'+secrets.token_hex(3),BLINDPASS_BACKUP_RECOVERY_DIR=str(offline))
            receipt_b=json.loads(compose_b('--profile','restore','run','--rm','controller-restore',timeout=600).stdout.decode().strip().splitlines()[-1])
            assert receipt_b['phase']=='recovery_required' and receipt_b['activation_permitted'] is False, receipt_b
            assert json.loads(compose_b('--profile','restore','run','--rm','controller-restore-install',timeout=300).stdout.decode().strip().splitlines()[-1])=={'restore':'installed'}
            env_b['BLINDPASS_BACKUP_RECOVERY_DIR']=str(recovery)
            compose_b('up','--detach','controller')
            wait(lambda: bool(controller_b()) and docker('exec',controller_b(),'blindpass','admin','recovery','status',success=False,timeout=10).returncode==0,30,'second-project controller did not start')
            time.sleep(2); assert not ready_b(), 'the recovering second-project controller reported ready'
            for category in sorted({i['category'] for i in cli_json_b('review','list')['items']}):
                cli_json_b('review','decide','--category',category,'--decision',{'operator':'accept','operation':'accept','workload':'revoke'}.get(category,'reject'),'--operator','p06-operator','--note','second project rehearsal')
            cli_json_b('waive-node',node_id,'--operator','p06-operator','--note','no real node exists in Compose')
            cli_json_b('review','complete','--operator','p06-operator')
            assert cli_json_b('status')['gaps']==['source_stop_missing'], cli_json_b('status')['gaps']
            compose_b('stop','controller')
            attested=script('authority-recover-attest.sql',host='p06-source-host-a',by='p06-admin',note='original stack stopped; moving to a second project')
            assert attested.returncode==0, 'attestation refused although both stacks are stopped'
            activated=script('authority-recover-activate.sql')
            assert activated.returncode==0 and 'activated recovery epoch' in activated.stdout.decode(), 'second-project activation refused with every gate met'
            compose_b('up','--detach','--force-recreate','controller')
            wait(ready_b,30,'the activated second-project controller did not become ready')
            # The original stack: the authority refuses its activation while the new owner holds the guard...
            refused_with(script('authority-activate.sql'),label='activation of the original stack while the restored stack serves')
            compose('up','--detach','--force-recreate','controller')
            time.sleep(6)
            assert not ready(), 'the stale original controller became ready beside the restored one'
            held_logs=compose('logs','--no-color','controller').stdout.decode(errors='replace')
            held_reason=[line.split('] ',1)[-1][:160] for line in held_logs.splitlines() if 'refus' in line.lower() or 'fenc' in line.lower() or 'epoch' in line.lower() or 'authority' in line.lower()][-1:]
            assert '"startup_failed"' in held_logs and '"reason":"fenced"' in held_logs, 'the original stack was not refused as fenced: '+str(held_reason)
            print('RC8 original stack while the restored stack holds the guard: not ready; log: '+(held_reason[0] if held_reason else '(no matching log line)'),flush=True)
            assert ready_b(), 'the restored stack stopped serving'
            compose('stop','controller')
            # ...and an administrator who stops the restored stack and activates again still cannot revive the
            # original volumes: its recorded epoch is older than the authority's.
            compose_b('stop','controller')
            stale=activate(success=False)
            stale_note='the authority refused an ordinary activation'
            if stale.returncode==0:
                compose('up','--detach','--force-recreate','controller'); time.sleep(8)
                assert not ready(), 'the stale original stack served after an ordinary activation'
                stale_logs=compose('logs','--no-color','controller').stdout.decode(errors='replace')
                stale_reason=[line.split('] ',1)[-1][:160] for line in stale_logs.splitlines() if line.strip()][-1:]
                assert '"reason":"recovery_required"' in stale_logs, 'the stale stack was not refused as recovery_required: '+str(stale_reason)
                stale_note='the authority accepted an ordinary activation but the original controller never became ready (last log: '+(stale_reason[0] if stale_reason else 'none')+')'
                compose('stop','controller')
                compose_b('stop','controller'); activate()
            print('RC8 stale-source probe after the restored stack stopped: '+stale_note,flush=True)
            compose_b('up','--detach','--force-recreate','controller')
            wait(ready_b,30,'the restored stack did not serve after the stale-source probes')
            if profile=='sqlite':
                after=volume_python(volume_data,'import pathlib,hashlib\nh=hashlib.sha256()\n[h.update(p.read_bytes()) for p in sorted(pathlib.Path("/v").rglob("controller.db"))]\nprint(h.hexdigest())').stdout.decode().strip()
                assert after==original_data, 'the stale source database was modified'
            compose_b('stop','controller')
            docker('network','disconnect','--force',project_b+'_edge',authority_name)
            compose_b('down','--volumes','--remove-orphans')
            print(f'PASS P06-RC8 Compose {profile}: the same archive restored into a second project under epoch {b_epoch} and activated; the original stack never starts serving (startup_failed:fenced while the restored stack holds the guard; startup_failed:recovery_required after an ordinary authority activation); the restored stack keeps serving'+('; the original SQLite database is byte-unchanged' if profile=='sqlite' else ''),flush=True)
            # 7. restore-based rollback: fence again, reserve a higher epoch, restore the same archive again.
            compose('stop','controller'); fence()
            revision=authority_psql("SELECT revision FROM blindpass_authority.recovery_authority WHERE tenant_id='"+tenant+"'").stdout.decode().strip()
            second=authority_psql("SELECT epoch||':'||phase FROM blindpass_authority.reserve_recovery('"+tenant+"','"+issuer+"','"+owner+"',"+revision+",1)").stdout.decode().strip()
            assert second.endswith(':recovering') and int(second.split(':')[0])>reserved_epoch, second
            volume_python(volume_keys,'import pathlib,shutil\n[shutil.rmtree(p) if p.is_dir() else p.unlink() for p in pathlib.Path("/v").iterdir()]',write=True)
            volume_python(volume_data,'import pathlib,shutil\n[shutil.rmtree(p) if p.is_dir() else p.unlink() for p in pathlib.Path("/v").iterdir()]',write=True)
            if profile=='postgres': sql('DROP SCHEMA controller CASCADE')
            # The restore destination must not exist: clear the previous staged root (the operator does the same).
            docker('run','--rm','--user','10001:10001','--mount','type=bind,src='+str(staging)+',dst=/s','--entrypoint','/bin/sh',helper,'-ec','rm -rf /s/root')
            env['BLINDPASS_RESTORE_ID']='p06rc'+secrets.token_hex(3); env['BLINDPASS_BACKUP_RECOVERY_DIR']=str(offline)
            compose('--profile','restore','run','--rm','controller-restore',timeout=600)
            compose('--profile','restore','run','--rm','controller-restore-install',timeout=300)
            env['BLINDPASS_BACKUP_RECOVERY_DIR']=str(recovery)
            compose('up','--detach','--force-recreate','controller')
            wait(lambda: bool(controller()) and docker('exec',controller(),'blindpass','admin','recovery','status',success=False,timeout=10).returncode==0,30,'rolled-back controller did not start')
            assert not ready() and 'source_stop_missing' in cli_json('status')['gaps']
            epochs=authority_psql("SELECT string_agg(epoch::text,',' ORDER BY epoch) FROM blindpass_authority.recovery_activations").stdout.decode().strip()
            assert epochs==str(reserved_epoch)+','+str(b_epoch), epochs
            print(f'PASS P06-RC6 Compose {profile}: restore-based rollback: fenced, reserved higher epoch {second.split(":")[0]}, the same archive restored again; the controller is recovering again and needs its own review, attestation and activation (activations so far: {epochs})',flush=True)
            logs=compose('logs','--no-color').stdout
            canary_log_scan.assert_log_clean('P06-RC7 '+profile+' compose logs',logs,[authority_password,temporary_password,CANARY],markers=[b'PRIVATE KEY-----'],require=[b'controller'])
            print('PASS P06-RC7 Compose '+profile+': no credential, key material or canary in any container log',flush=True)
        def edge_logs_clean():
            # An empty capture is accepted only when the caller asserted that this edge is configured to log nothing
            # (P07 finding F2: the earlier `secret in logs` passed on a capture that held nothing).
            logs=docker('logs',edge_name).stdout+docker('logs',edge_name).stderr
            canary_log_scan.assert_log_clean('P06 edge logs',logs,[CANARY,password],min_bytes=16,allow_empty=edge_silent)
        port=0
        edge_silent=None
        try:
            # Docker owns only this disposable bind directory; never existing host config.
            docker('run','--rm','--user','0','--mount','type=bind,src='+str(config)+',dst=/config',
                   '--entrypoint','/bin/sh',helper,'-ec','chown -R 10001:10001 /config')
            assert compose('run','--rm','--no-deps','controller','check-config',success=False).returncode!=0
            authority_start()
            compose('--profile','initialize','run','--rm','keys-init')
            assert compose('--profile','initialize','run','--rm','keys-init',success=False).returncode!=0, 'keys overwritten'
            issuer=compose('run','--rm','--no-deps','controller','keys','issuer-id','--directory','/keys').stdout.decode().strip()
            assert re.fullmatch(r'ed25519-[A-Za-z0-9_-]{43}',issuer)
            # No database before the administrator registers the issuer.
            assert compose('run','--rm','controller','migrate',success=False).returncode!=0, 'migrate ran without registration'
            authority_psql(file='authority-register.sql',variables=authority_variables())
            assert compose('run','--rm','controller','serve',success=False).returncode!=0, 'serve silently initialized state'
            compose('run','--rm','controller','migrate')
            started=time.monotonic(); activate(); compose('up','--detach','controller')
            wait(ready,15,'controller readiness exceeded 15 seconds')
            def docker_healthy():
                state=json.loads(docker('inspect',controller()).stdout)[0]['State']
                return state.get('Health',{}).get('Status')=='healthy'
            wait(docker_healthy,max(0,15-(time.monotonic()-started)),'Docker health status exceeded 15 seconds')
            print(f'PASS P06-O02/O03 {profile}: explicit private initialization, no startup regeneration; ready {time.monotonic()-started:.3f}s',flush=True)
            instance=controller()
            inspect=json.loads(docker('inspect',instance).stdout)[0]
            assert password not in json.dumps(inspect)
            host=inspect['HostConfig']; assert host['ReadonlyRootfs'] and not host['Privileged'] and host['CapDrop']==['ALL']
            assert not host['PortBindings']
            mounts={m['Destination']:m for m in inspect['Mounts']}
            assert not mounts['/keys']['RW'] and mounts['/data']['RW']
            docker('exec',instance,'/bin/sh','-ec',
                   'test "$(id -u):$(id -g)" = 10001:10001; '
                   'grep -q "CapEff:[[:space:]]*0000000000000000" /proc/1/status; '
                   'grep -q "NoNewPrivs:[[:space:]]*1" /proc/1/status; '
                   'test "$(stat -c %a:%u:%g /run/blindpass-controller/admin.sock)" = 600:10001:10001; '
                   'touch /data/write-probe /run/write-probe; rm /data/write-probe /run/write-probe; '
                   '! touch /keys/write-probe 2>/dev/null; ! touch /root-write-probe 2>/dev/null')
            print('PASS P06-O04 '+profile+': actual process UID/caps/NNP, private socket and mount write denials',flush=True)
            before=metadata(); key_hash=keys_digest()
            bootstrap=compose('exec','-T','controller','blindpass','admin','bootstrap').stdout
            assert bootstrap and password.encode() not in bootstrap
            temporary_password=json.loads(bootstrap)['temporary_password'].encode()
            if scenario=='handoff':
                temporary_password=json.loads(bootstrap)['temporary_password'].encode()
                handoff_gate(); return
            if scenario=='recovery':
                temporary_password=json.loads(bootstrap)['temporary_password'].encode()
                recovery_gate(); return
            # Credential output is captured only in memory and never printed.
            for kind in ['nginx','caddy']:
                edge_start(kind)
                forged={'Forwarded':'for=P06-DUMMY-CONTAINER-EXPOSURE-CANARY;proto=http',
                        'X-Forwarded-Proto':'http','X-Forwarded-Host':'wrong.invalid','X-Forwarded-For':'198.51.100.1, 198.51.100.2'}
                status,headers,body=request('blindpass.example',headers=forged)
                assert status==200 and b'<!doctype html>' in body.lower()
                assert headers.get('Strict-Transport-Security')=='max-age=31536000'
                assert any(k.lower()=='content-security-policy' for k in headers)
                assert request('input.example','/?id=p06-dummy&metadata_sig=p06-dummy&submit_sig=p06-dummy')[2]!=body
                assert request('blindpass.example',headers={'Host':'wrong.invalid'})[0] in [421,404]
                peer='import urllib.request,urllib.error; r=urllib.request.Request("http://controller:3200/",headers={"Host":"blindpass.example","X-Forwarded-Host":"blindpass.example","X-Forwarded-Proto":"https","X-Forwarded-For":"198.51.100.1"}); '\
                     '\ntry: urllib.request.urlopen(r); raise AssertionError("untrusted peer accepted")\nexcept urllib.error.HTTPError as e: assert e.code==403'
                docker('run','--rm','--network',network,'--ip',subnet+'.4','--entrypoint','python3',helper,'-c',peer)
                started=time.monotonic(); compose('stop','controller'); assert time.monotonic()-started<10
                failed_at=time.monotonic()
                assert request('blindpass.example','/?id='+CANARY.decode(),{'Authorization':'Bearer '+CANARY.decode()})[0] in [502,504]
                assert time.monotonic()-failed_at<8, 'edge backend failure exceeded configured timeout plus response slack'
                edge_logs_clean()
                # A used revision is never replayed: a recreate alone is not ready.
                compose('up','--detach','--force-recreate','controller')
                time.sleep(4); assert not ready(), 'controller became ready without an activation'
                compose('stop','controller'); activate()
                compose('up','--detach','--force-recreate','controller'); wait(ready,15,'controller recreate failed')
                assert metadata()==before and keys_digest()==key_hash
                assert compose('exec','-T','controller','blindpass','admin','bootstrap',success=False).returncode!=0
                edge_logs_clean(); docker('rm','--force',edge_name)
                print('PASS P06-O05/O06/O08 '+profile+' '+kind+': real TLS/header overwrite/peer denial, backend failure/privacy and retained identity/admin',flush=True)
            if profile=='sqlite': upgrade_gate()
            if profile=='postgres': upgrade_gate_postgres()
            if profile=='postgres':
                compose('stop','postgres')
                wait(lambda: not ready(),15,'PG outage failed to affect readiness')
                health='import urllib.request,json; r=urllib.request.urlopen("http://127.0.0.1:3200/healthz"); assert r.status==200 and json.load(r)["ok"]'
                docker('run','--rm','--network','container:'+controller(),'--entrypoint','python3',helper,'-c',health)
                compose('up','--detach','--force-recreate','postgres')
                wait(lambda: compose('exec','-T','postgres','pg_isready','-U','blindpass',success=False).returncode==0,60,'PG did not restart')
                # An unanswerable epoch check fences the owner (P06-D12): the database coming back does not
                # restore readiness; only a fresh administrator activation does.
                time.sleep(5); assert not ready(), 'controller regained readiness without activation after a store outage'
                compose('stop','controller'); activate()
                compose('up','--detach','--force-recreate','controller'); wait(ready,30,'PG recovery failed')
                assert metadata()==before and keys_digest()==key_hash
                print('PASS P06-O07 PostgreSQL outage: liveness retained/readiness denied/fenced until re-activation, unchanged identity',flush=True)
            def reactivate_and_start(bound):
                # A killed or fenced owner can be re-activated only once the authority stops seeing its
                # old backend; retry until that happens, then time activation to readiness.
                compose('stop','controller')
                deadline=time.monotonic()+30
                while activate(success=False).returncode!=0:
                    assert time.monotonic()<deadline, 'authority never released the killed owner'
                    time.sleep(1)
                started=time.monotonic(); compose('up','--detach','--force-recreate','controller')
                wait(ready,bound,'controller did not become ready after re-activation within '+str(bound)+'s')
                return time.monotonic()-started
            def parity_kill_and_suspend():
                # Slice 9 fault injection, identical for both profiles: abrupt process death, then a host
                # suspend. Neither may change identity, keys or state; both need no more than a fresh
                # administrator activation.
                instance=controller(); docker('kill',instance)
                assert not ready(), 'killed controller still reported ready'
                compose('up','--detach','--force-recreate','controller'); time.sleep(4)
                assert not ready(), 'controller became ready after SIGKILL without an activation'
                recovered=reactivate_and_start(15)
                assert metadata()==before and keys_digest()==key_hash
                print(f'PASS P06-F1 {profile}: SIGKILL needs a fresh activation, then ready in {recovered:.3f}s (bound 15s), identity/keys/state unchanged',flush=True)
                instance=controller(); docker('pause',instance)
                try: time.sleep(20)
                finally: docker('unpause',instance)
                resumed=time.monotonic(); outcome='ready'
                try: wait(ready,30,'not ready after a 20s suspend')
                except AssertionError:
                    outcome='fenced'
                    reactivate_and_start(15)
                assert metadata()==before and keys_digest()==key_hash
                print(f'PASS P06-F2 {profile}: 20s host suspend left the controller {outcome} ({time.monotonic()-resumed:.3f}s after resume); identity/keys/state unchanged',flush=True)
            def parity_disk_full():
                # Slice 9 serving disk-full. The store volume is replaced by a small tmpfs-backed volume (the
                # authority is a separate container and keeps its own disk), filled to ENOSPC while the
                # controller serves, then freed. P06-D12 applies: space alone does not unfence the owner.
                original=project+('_blindpass-data' if profile=='sqlite' else '_blindpass-postgres')
                logical='blindpass-data' if profile=='sqlite' else 'blindpass-postgres'
                small=project+'-small-store'; size='64M' if profile=='sqlite' else '256M'
                overlay=root/'compose.small-store.yml'
                def volume_job(*script, mounts):
                    args=['run','--rm','--user','0']
                    for source,target in mounts: args+=['--mount','type=volume,src='+source+',dst='+target]
                    return docker(*args,'--entrypoint','/bin/sh',helper,'-ec',*script,success=False,timeout=120)
                def loop_helper(script):
                    done=docker('run','--rm','--privileged','--mount','type=bind,src=/dev,dst=/dev','--mount','type=bind,src='+str(root)+',dst=/r,bind-propagation=rshared',
                                '--entrypoint','/bin/sh',helper,'-ec',script,success=False,timeout=120)
                    assert done.returncode==0, 'the loop-mounted store volume could not be changed'
                def swap_to_small():
                    compose('stop','controller')
                    if profile=='postgres': compose('stop','postgres')
                    # A tmpfs volume is recreated empty for every container, so the store lives in a loop-mounted
                    # ext4 image (no root needed on the host: a privileged helper mounts it with shared
                    # propagation), exposed to Compose as a bind-backed named volume.
                    image_file=root/'small-store.img'; mount_point=root/'small-store'; mount_point.mkdir()
                    run(['truncate','-s',size,str(image_file)]); run(['mkfs.ext4','-q','-F','-m','0',str(image_file)])
                    loop_helper('dev=$(losetup -f --show /r/small-store.img); mount -t ext4 $dev /r/small-store; echo $dev > /r/small-store.dev')
                    docker('volume','create','--driver','local','--opt','type=none','--opt','o=bind','--opt','device='+str(mount_point),small)
                    copied=volume_job('cp -a /src/. /dst/ && chown --reference=/src /dst && chmod --reference=/src /dst',mounts=[(original,'/src'),(small,'/dst')])
                    assert copied.returncode==0, 'the store did not copy to the small volume'
                    overlay.write_text('volumes:\n  '+logical+':\n    external: true\n    name: '+small+'\n')
                    base.extend(['--file',str(overlay)])
                def fill():
                    volume_job('dd if=/dev/zero of=/v/p06-fill bs=1M 2>/dev/null || true; dd if=/dev/zero of=/v/p06-fill2 bs=4k 2>/dev/null || true; dd if=/dev/zero of=/v/p06-fill3 bs=512 2>/dev/null || true; sync; test ! -e /v/p06-probe && ! (head -c 65536 /dev/zero > /v/p06-probe) 2>/dev/null',mounts=[(small,'/v')])
                    left=volume_job('rm -f /v/p06-probe; df -k /v | tail -1 | tr -s " " | cut -d" " -f4',mounts=[(small,'/v')]).stdout.decode().strip()
                    assert left.isdigit() and int(left)<64, 'the small volume was not filled (free KiB '+left+')'
                def reason():
                    # Plain HTTP from a helper holding the trusted proxy address to the controller's own listener.
                    code=('import json,urllib.request,urllib.error\n'
                          'try: r=urllib.request.urlopen(urllib.request.Request("http://'+subnet+'.2:3200/readyz",headers={"Host":"blindpass.example","X-Forwarded-Proto":"https","X-Forwarded-Host":"blindpass.example","X-Forwarded-For":"127.0.0.1"}),timeout=5); status=r.status; body=r.read()\n'
                          'except urllib.error.HTTPError as e: status=e.code; body=e.read()\n'
                          'except Exception: print("unreachable"); raise SystemExit\n'
                          'try: d=json.loads(body); print(status, d.get("reason") or d.get("status") or "")\n'
                          'except ValueError: print(status)')
                    return docker('run','--rm','--network',network,'--ip',subnet+'.3','--entrypoint','python3',helper,'-c',code,success=False,timeout=60).stdout.decode().strip() or 'unreachable'
                def login_status():
                    # A wrong-credential login still has to write its rate-limit row: it shows whether the write path works.
                    # A raw socket is used so a response that never arrives is told apart from an HTTP error.
                    script=root/'login-probe.py'
                    script.write_text('''import socket, sys, time
host, token = sys.argv[1], "a" * 43
body = '{"username":"p06-nobody","password":"P06-DUMMY-wrong"}'
head = ("POST /api/v3/admin/session/login HTTP/1.1\\r\\nHost: blindpass.example\\r\\nX-Forwarded-Proto: https\\r\\n"
        "X-Forwarded-Host: blindpass.example\\r\\nX-Forwarded-For: 127.0.0.1\\r\\nOrigin: https://blindpass.example\\r\\n"
        "Content-Type: application/json\\r\\nCookie: bp_csrf=" + token + "\\r\\nX-CSRF-Token: " + token + "\\r\\n"
        "Connection: close\\r\\nContent-Length: " + str(len(body)) + "\\r\\n\\r\\n" + body)
started = time.monotonic()
try:
    connection = socket.create_connection((host, 3200), timeout=40)
    connection.sendall(head.encode())
    data = b""
    while True:
        chunk = connection.recv(4096)
        if not chunk:
            break
        data += chunk
    result = data.split(b"\\r\\n", 1)[0].decode(errors="replace") if data else "closed with no response"
except Exception as error:
    result = "unreachable (" + type(error).__name__ + ")"
print(result + " after " + format(time.monotonic() - started, ".1f") + "s")
''')
                    return docker('run','--rm','--network',network,'--ip',subnet+'.3','--mount','type=bind,src='+str(script)+',dst=/probe.py,readonly',
                                  '--entrypoint','python3',helper,'/probe.py',subnet+'.2',success=False,timeout=90).stdout.decode().strip() or 'probe failed'
                swap_to_small()
                try:
                    if profile=='postgres': compose('up','--detach','postgres'); wait(lambda: compose('exec','-T','postgres','pg_isready','-U','blindpass',success=False).returncode==0,60,'PostgreSQL did not start on the small volume')
                    activate(); compose('up','--detach','controller')
                    try: wait(ready,30,'controller not ready on the small volume')
                    except AssertionError:
                        logs=compose('logs','--no-color','--tail','40','controller',success=False).stdout
                        print('F4 diagnostic reasons: '+str(re.findall(rb'"reason":"([a-z_]+)"',logs)[-5:]),flush=True)
                        if os.environ.get('BLINDPASS_HARNESS_DIAGNOSTICS')=='1': print('F4 diagnostic logs: '+logs[-700:].decode(errors='replace'),flush=True)
                        raise
                    assert metadata()==before and keys_digest()==key_hash
                    instance=controller(); fill()
                    probe=''
                    if profile=='postgres':
                        # An idle full volume does not stop reads, so PostgreSQL is made to try to extend its own
                        # files; it either errors (no PANIC) or crashes and restarts. Both are the fault.
                        storm=compose('exec','-T','postgres','psql','-U','blindpass','-d','blindpass','-c',
                                      "CREATE TABLE controller.p06_fill AS SELECT repeat('x',1000) AS filler FROM generate_series(1,400000)",success=False,timeout=120)
                        assert b'No space left' in storm.stderr or b'PANIC' in storm.stderr or storm.returncode!=0, 'PostgreSQL could still extend its files on the full volume'
                        try: wait(lambda: not ready(),30,'ready')
                        except AssertionError: probe=' (readiness stayed true: reads still work)'
                    else:
                        wait(lambda: not ready(),60,'the controller stayed ready on a full store volume')
                    during=reason()+probe; writes=login_status(); writes+='; then '+login_status()+'; then readiness '+reason()
                    if os.environ.get('BLINDPASS_HARNESS_DIAGNOSTICS')=='1': print('F4 diagnostic logs: '+'\n'.join(l[:420] for l in compose('logs','--no-color','--tail','60','controller',success=False).stdout.decode(errors='replace').splitlines() if '"level":"INFO"' not in l or 'POST' in l),flush=True)
                    assert docker('inspect','--format','{{.State.Running}}',instance).stdout.decode().strip()=='true', 'the controller process exited on a full store volume'
                    volume_job('rm -f /v/p06-fill /v/p06-fill2 /v/p06-fill3',mounts=[(small,'/v')])
                    if profile=='postgres':
                        wait(lambda: compose('exec','-T','postgres','pg_isready','-U','blindpass',success=False).returncode==0,120,'PostgreSQL did not recover after space was freed')
                        compose('exec','-T','postgres','psql','-U','blindpass','-d','blindpass','-c','DROP TABLE IF EXISTS controller.p06_fill',success=False)
                    if profile=='postgres': wait(lambda: compose('exec','-T','postgres','pg_isready','-U','blindpass',success=False).returncode==0,90,'PostgreSQL did not recover after space was freed')
                    time.sleep(15)
                    self_recovered=ready()
                    if not self_recovered:
                        held=reason()
                        assert held.startswith('503'), 'neither ready nor refusing after space was freed: '+held
                        recovered=reactivate_and_start(30)
                    else: held='ready'; recovered=0.0
                    assert metadata()==before and keys_digest()==key_hash
                    if profile=='sqlite':
                        check=docker('run','--rm','--user','10001:10001','--mount','type=volume,src='+small+',dst=/v,readonly','--entrypoint','python3',helper,'-c',
                                     'import sqlite3; print(sqlite3.connect("file:/v/controller.db?mode=ro&immutable=1",uri=True).execute("PRAGMA integrity_check").fetchone()[0])')
                        assert check.stdout.decode().strip()=='ok', 'integrity check failed after the fault'
                    print(f'PASS P06-F4 {profile}: store volume ({size} loop-mounted ext4, authority separate) full while serving: readiness {during}, a login attempt (a store write) answered {writes}, process kept running; after space was freed the controller was {"ready by itself" if self_recovered else "still "+held+" until one fresh activation, ready "+format(recovered,".1f")+"s after it"}; identity/keys/state unchanged'+('; SQLite integrity_check ok' if profile=='sqlite' else ''),flush=True)
                finally:
                    compose('stop','controller')
                    if profile=='postgres': compose('stop','postgres')
                    volume_job('rm -rf /dst/* /dst/.[!.]* 2>/dev/null; cp -a /src/. /dst/ && chown --reference=/src /dst && chmod --reference=/src /dst',mounts=[(small,'/src'),(original,'/dst')])
                    del base[-2:]
                    docker('volume','rm','--force',small,success=False)
                    loop_helper('umount /r/small-store; losetup -d $(cat /r/small-store.dev); rm -f /r/small-store.img /r/small-store.dev; rmdir /r/small-store')
                    if profile=='postgres': compose('up','--detach','postgres'); wait(lambda: compose('exec','-T','postgres','pg_isready','-U','blindpass',success=False).returncode==0,60,'PostgreSQL did not start on the original volume')
                    reactivate_and_start(30)
                    assert metadata()==before and keys_digest()==key_hash, 'state differs after the store returned to its original volume'
            parity_kill_and_suspend()
            parity_disk_full()
            compose('stop','controller')
            for change,restore in [
                ('Path("/keys/root-secret").rename("/keys/held")','Path("/keys/held").rename("/keys/root-secret")'),
                ('Path("/keys/root-secret").chmod(0o644)','Path("/keys/root-secret").chmod(0o600)'),
                ('Path("/keys/root-secret").rename("/keys/held"); Path("/keys/root-secret").symlink_to("agent-jwt-secret")',
                 'Path("/keys/root-secret").unlink(); Path("/keys/held").rename("/keys/root-secret")')]:
                keys_edit(change)
                try: assert compose('run','--rm','--no-deps','controller','serve',success=False).returncode!=0
                finally: keys_edit(restore)
            assert keys_digest()==key_hash and metadata()==before
            logs=compose('logs','--no-color').stdout
            assert authority_password.encode() not in logs and authority_password not in json.dumps(json.loads(docker('inspect',controller()).stdout)[0]['Config']['Env'])
            canary_log_scan.assert_log_clean('P06-O02 '+profile+' compose logs',logs,[CANARY,password,temporary_password,authority_password],markers=[b'PRIVATE KEY-----'],require=[b'controller'])
            print('PASS P06-O02 '+profile+': missing/exposed/linked keys refused, original keys/state preserved; logs contain no test credentials',flush=True)
            def parity_database_loss():
                # Loss of the controller database must never be repaired by silent re-initialization.
                compose('stop','controller')
                if profile=='sqlite':
                    docker('run','--rm','--user','10001:10001','--mount','type=volume,src='+project+'_blindpass-data,dst=/data',
                           '--entrypoint','python3',helper,'-c',
                           'from pathlib import Path; [p.unlink() for p in Path("/data").glob("controller.db*")]')
                else:
                    compose('exec','-T','postgres','psql','-U','blindpass','-d','blindpass','-v','ON_ERROR_STOP=1','-c','DROP SCHEMA controller CASCADE; CREATE SCHEMA controller')
                # A fresh activation is in place and keys are intact, so only the lost database can
                # explain a refusal.
                activate()
                started=time.monotonic()
                refused=compose('run','--rm','controller','serve',success=False,timeout=60)
                assert refused.returncode!=0, 'controller served after its database was lost'
                reason=re.findall(rb'"reason":"([a-z_]+)"',refused.stdout+refused.stderr)
                assert reason and not any(r in (b'authority_unavailable',b'authority_fenced',b'authority_not_active') for r in reason), reason
                took=time.monotonic()-started
                if profile=='sqlite':
                    left=docker('run','--rm','--user','10001:10001','--mount','type=volume,src='+project+'_blindpass-data,dst=/data,readonly',
                                '--entrypoint','python3',helper,'-c','from pathlib import Path; print(len(list(Path("/data").glob("controller.db*"))))').stdout.decode().strip()
                    assert left=='0', 'a lost database was silently recreated'
                else:
                    tables=compose('exec','-T','postgres','psql','-U','blindpass','-d','blindpass','-At','-c',"SELECT count(*) FROM pg_tables WHERE schemaname='controller'").stdout.decode().strip()
                    assert tables=='0', 'a lost database was silently recreated'
                output=refused.stdout+refused.stderr
                canary_log_scan.assert_log_clean('P06-F3 '+profile+' refused-start output',output,[CANARY,password],min_bytes=16)
                print(f'PASS P06-F3 {profile}: lost database refused with an activation in place, reason {reason[-1].decode()} ({took:.1f}s), and never silently recreated; no credentials in output',flush=True)
            parity_database_loss()
        finally:
            docker('rm','--force',edge_name,success=False)
            docker('volume','rm','--force',project+'-small-store',success=False)
            docker('rm','--force','--volumes',authority_name,success=False)
            compose('down','--volumes','--remove-orphans',success=False)
            if projectb: run(projectb['base']+['down','--volumes','--remove-orphans'],env=projectb['env'],success=False)
            if scenario=='handoff':
                run(['docker','compose','--project-name',project+'-b','--file',str(ROOT/'deploy/controller/compose.sqlite.yml'),
                     '--file',str(ROOT/'deploy/controller/compose.handoff-sqlite.yml'),'down','--volumes','--remove-orphans'],
                    env=dict(env,BLINDPASS_HANDOFF_TRANSFER_DIR=str(root),BLINDPASS_HANDOFF_STAGING_DIR=str(root)),success=False)
            docker('run','--rm','--user','0','--mount','type=bind,src='+str(config)+',dst=/config',
                   '--entrypoint','/bin/sh',helper,'-ec','chown -R '+str(os.getuid())+':'+str(os.getgid())+' /config',success=False)
            docker('run','--rm','--user','0','--mount','type=bind,src='+str(authority_dir)+',dst=/authority',
                   '--entrypoint','/bin/sh',helper,'-ec','chown -R '+str(os.getuid())+':'+str(os.getgid())+' /authority',success=False)
            docker('run','--rm','--user','0','--mount','type=bind,src='+str(recovery)+',dst=/recovery',
                   '--entrypoint','/bin/sh',helper,'-ec','chown -R '+str(os.getuid())+':'+str(os.getgid())+' /recovery',success=False)
            docker('run','--rm','--user','0','--mount','type=bind,src='+str(offline)+',dst=/offline',
                   '--entrypoint','/bin/sh',helper,'-ec','chown -R '+str(os.getuid())+':'+str(os.getgid())+' /offline',success=False)
            for name in ('handoff-transfer','handoff-staging','recovery-archives','recovery-staging','recovery-staging-b'):
                if (root/name).exists():
                    docker('run','--rm','--user','0','--mount','type=bind,src='+str(root/name)+',dst=/d',
                           '--entrypoint','/bin/sh',helper,'-ec','chown -R '+str(os.getuid())+':'+str(os.getgid())+' /d',success=False)
            for name in (project,project+'-r'):
                assert not docker('ps','--all','--quiet','--filter','label=com.docker.compose.project='+name).stdout.strip(), 'disposable containers remain'
                assert not docker('volume','ls','--quiet','--filter','label=com.docker.compose.project='+name).stdout.strip(), 'disposable volumes remain'


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--profile',choices=['sqlite','postgres'],required=True)
    parser.add_argument('--image',default='blindpass-p06-controller:local')
    parser.add_argument('--helper-image',default='blindpass-p06-edge:local')
    parser.add_argument('--scenario',choices=['profile','handoff','recovery'],default='profile',
                        help='handoff: the two-project P06-D28 handoff gate (sqlite profile); recovery: backup, loss, restore, review, attestation and activation on the shipped profile')
    args=parser.parse_args()
    if args.scenario=='handoff':
        assert args.profile=='sqlite', 'the Compose handoff gate is SQLite only'
        profile_gate(args.profile,args.image,args.helper_image,'handoff')
        print('PASS disposable profile resources removed',flush=True)
        return
    if args.scenario=='recovery':
        profile_gate(args.profile,args.image,args.helper_image,'recovery')
        print('PASS disposable profile resources removed',flush=True)
        return
    with tempfile.TemporaryDirectory(prefix='blindpass-p06-image-inspect-') as tmp:
        image_gate(args.image,Path(tmp))
    profile_gate(args.profile,args.image,args.helper_image)
    print('PASS disposable profile resources removed',flush=True)


if __name__=='__main__': main()
