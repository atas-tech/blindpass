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
import ssl
import subprocess
import tarfile
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
CANARY = b'P06-DUMMY-CONTAINER-EXPOSURE-CANARY'
RUNTIME_BASE = 'debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251'


def run(args, *, env=None, data=None, timeout=90, success=True):
    result = subprocess.run(args, env=env, input=data, capture_output=True, timeout=timeout)
    if success and result.returncode:
        # Never replay raw command output, argv or configuration in failures.
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
           'ldd /usr/local/bin/blindpass-controller | grep -q libcrypto.so.3')
    archive=root/'image.tar'
    docker('image','save','--output',str(archive),image,timeout=90)
    # Debian's libgnutls contains a public built-in self-test key. Bind this
    # single exception to the identical binary in the pinned official base.
    gnutls='usr/lib/x86_64-linux-gnu/libgnutls.so.30.34.3'
    base_digest=docker('run','--rm','--entrypoint','sha256sum',RUNTIME_BASE,'/'+gnutls).stdout.split()[0].decode()
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


def profile_gate(profile, image, helper):
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
        cert=root/'fullchain.pem'; key=root/'private-key.pem'
        run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=blindpass.example',
             '-addext','subjectAltName=DNS:blindpass.example,DNS:input.example',
             '-addext','basicConstraints=critical,CA:FALSE','-keyout',str(key),'-out',str(cert)])
        cert.chmod(0o600); key.chmod(0o600)
        env=dict(os.environ, BLINDPASS_CONTROLLER_IMAGE=image, BLINDPASS_TRUST_PROXY=subnet+'.3',
                 BLINDPASS_CONTROLLER_IP=subnet+'.2',BLINDPASS_EDGE_SUBNET=subnet+'.0/24',
                 BLINDPASS_POSTGRES_PASSWORD_FILE=str(password_file),BLINDPASS_DATABASE_CONFIG_DIR=str(config))
        base=['docker','compose','--project-name',project,'--file',str(ROOT/'deploy/controller'/('compose.'+profile+'.yml')),
              '--file',str(ROOT/'deploy/controller/compose.initialize.yml')]
        def compose(*args,**kwargs): return run(base+list(args),env=env,**kwargs)
        def controller(): return compose('ps','--all','--quiet','controller').stdout.decode().strip()
        def ready():
            name=controller()
            return bool(name) and docker('exec',name,'blindpass-controller','healthcheck',success=False,timeout=5).returncode==0
        def metadata():
            query='SELECT tenant_id, issuer_epoch, schema_version FROM controller_meta WHERE id=1'
            if profile=='postgres':
                return compose('exec','-T','postgres','psql','-U','blindpass','-d','blindpass','-At','-c',query).stdout
            code='import sqlite3,json; print(json.dumps(sqlite3.connect("file:/data/controller.db?mode=ro",uri=True).execute('+repr(query)+').fetchall()))'
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
            nonlocal port
            nginx=(ROOT/'deploy/proxy/nginx.conf.example').read_text().replace('127.0.0.1:3200','controller:3200')
            caddy=(ROOT/'deploy/proxy/Caddyfile.example').read_text().replace('127.0.0.1:3200','controller:3200')
            nginx=nginx.replace('/etc/nginx/blindpass/','/fixture/')
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
        def edge_logs_clean():
            logs=docker('logs',edge_name).stdout+docker('logs',edge_name).stderr
            assert CANARY not in logs and password.encode() not in logs
        port=0
        try:
            # Docker owns only this disposable bind directory; never existing host config.
            docker('run','--rm','--user','0','--mount','type=bind,src='+str(config)+',dst=/config',
                   '--entrypoint','/bin/sh',helper,'-ec','chown -R 10001:10001 /config')
            assert compose('run','--rm','--no-deps','controller','check-config',success=False).returncode!=0
            compose('--profile','initialize','run','--rm','keys-init')
            assert compose('--profile','initialize','run','--rm','keys-init',success=False).returncode!=0, 'keys overwritten'
            assert compose('run','--rm','controller','serve',success=False).returncode!=0, 'serve silently initialized state'
            compose('run','--rm','controller','migrate')
            started=time.monotonic(); compose('up','--detach','controller')
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
                compose('up','--detach','--force-recreate','controller'); wait(ready,15,'controller recreate failed')
                assert metadata()==before and keys_digest()==key_hash
                assert compose('exec','-T','controller','blindpass','admin','bootstrap',success=False).returncode!=0
                edge_logs_clean(); docker('rm','--force',edge_name)
                print('PASS P06-O05/O06/O08 '+profile+' '+kind+': real TLS/header overwrite/peer denial, backend failure/privacy and retained identity/admin',flush=True)
            if profile=='postgres':
                compose('stop','postgres')
                wait(lambda: not ready(),15,'PG outage failed to affect readiness')
                health='import urllib.request,json; r=urllib.request.urlopen("http://127.0.0.1:3200/healthz"); assert r.status==200 and json.load(r)["ok"]'
                docker('run','--rm','--network','container:'+controller(),'--entrypoint','python3',helper,'-c',health)
                compose('up','--detach','--force-recreate','postgres'); wait(ready,30,'PG recovery failed')
                assert metadata()==before and keys_digest()==key_hash
                print('PASS P06-O07 PostgreSQL outage: liveness retained/readiness denied/recovery with unchanged identity',flush=True)
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
            assert CANARY not in logs and password.encode() not in logs and temporary_password not in logs and b'PRIVATE KEY-----' not in logs
            print('PASS P06-O02 '+profile+': missing/exposed/linked keys refused, original keys/state preserved; logs contain no test credentials',flush=True)
        finally:
            docker('rm','--force',edge_name,success=False)
            compose('down','--volumes','--remove-orphans',success=False)
            docker('run','--rm','--user','0','--mount','type=bind,src='+str(config)+',dst=/config',
                   '--entrypoint','/bin/sh',helper,'-ec','chown -R '+str(os.getuid())+':'+str(os.getgid())+' /config',success=False)
            assert not docker('ps','--all','--quiet','--filter','label=com.docker.compose.project='+project).stdout.strip(), 'disposable containers remain'
            assert not docker('volume','ls','--quiet','--filter','label=com.docker.compose.project='+project).stdout.strip(), 'disposable volumes remain'


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--profile',choices=['sqlite','postgres'],required=True)
    parser.add_argument('--image',default='blindpass-p06-controller:local')
    parser.add_argument('--helper-image',default='blindpass-p06-edge:local')
    args=parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='blindpass-p06-image-inspect-') as tmp:
        image_gate(args.image,Path(tmp))
    profile_gate(args.profile,args.image,args.helper_image)
    print('PASS disposable profile resources removed',flush=True)


if __name__=='__main__': main()
