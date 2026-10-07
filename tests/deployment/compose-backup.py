#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""P06-CB02–CB04: actual shipped SQLite backup overlay, disposable resources only."""
import argparse
import json
import os
from pathlib import Path
import secrets
import tempfile
import time

import canary_log_scan
import split_custody

from importlib.util import module_from_spec, spec_from_file_location

ROOT=Path(__file__).resolve().parents[2]
spec=spec_from_file_location('compose_profile',ROOT/'tests/deployment/compose-up.py')
profile=module_from_spec(spec)
spec.loader.exec_module(profile)
docker=profile.docker
run=profile.run
wait=profile.wait


def backup_gate(image, helper, payload_bytes, faults):
    image_id=json.loads(docker('image','inspect',image).stdout)[0]['Id']
    print('Candidate image config: '+image_id,flush=True)
    project='blindpass-p06-backup-'+secrets.token_hex(4)
    job_name=project+'-capture'
    probe_name=project+'-requests'
    with tempfile.TemporaryDirectory(prefix=project+'-') as directory:
        root=Path(directory)
        recovery=root/'recovery'; recovery.mkdir(mode=0o700)
        wrong=root/'wrong'; wrong.mkdir(mode=0o700)
        absent=root/'absent'; absent.mkdir(mode=0o700)
        offline=root/'offline'; offline.mkdir(mode=0o700)
        wrong_offline=root/'wrong-offline'; wrong_offline.mkdir(mode=0o700)
        directories=[recovery,wrong,absent,offline,wrong_offline]
        env=dict(os.environ,BLINDPASS_CONTROLLER_IMAGE=image,BLINDPASS_PUBLIC_URL='https://blindpass.example',BLINDPASS_UI_BASE_URL='https://input.example',BLINDPASS_TRUST_PROXY='172.29.63.3',
                 BLINDPASS_CONTROLLER_IP='172.29.63.2',BLINDPASS_EDGE_SUBNET='172.29.63.0/24',
                 BLINDPASS_BACKUP_RECOVERY_DIR=str(recovery),
                 BLINDPASS_CONTROLLER_TENANT_ID='p06_backup_tenant',BLINDPASS_CONTROLLER_OWNER_ID='p06_backup_owner',
                 BLINDPASS_AUTHORITY_CONFIG_DIR=str(recovery))
        # This gate exercises backup/verification and serving load, not authority
        # provisioning (compose-up.py and the authority drivers do that). The serving
        # controller runs as an isolated test-mode fixture without an authority record.
        # P07 (N-03): test mode is refused on a BLINDPASS_PROXY_REQUIRED=1 profile, so the
        # fixture runs with it off; this gate does not exercise proxy ingress.
        fixture=root/'test-mode.yml'
        fixture.write_text('services:\n  controller:\n    environment: !override\n'
                           '      BLINDPASS_TEST_MODE: "1"\n      BLINDPASS_PROXY_REQUIRED: "0"\n'
                           '      BLINDPASS_PUBLIC_URL: ${BLINDPASS_PUBLIC_URL}\n      BLINDPASS_UI_BASE_URL: ${BLINDPASS_UI_BASE_URL}\n'
                           '      BLINDPASS_TRUST_PROXY: ${BLINDPASS_TRUST_PROXY}\n')
        base=['docker','compose','--project-name',project,'--file',str(ROOT/'deploy/controller/compose.sqlite.yml'),
              '--file',str(ROOT/'deploy/controller/compose.initialize.yml'),
              '--file',str(ROOT/'deploy/controller/compose.backup-sqlite.yml'),'--file',str(fixture)]
        def compose(*args,environment=None,**kwargs):
            return run(base+list(args),env=environment or env,**kwargs)
        def controller(): return compose('ps','--all','--quiet','controller').stdout.decode().strip()
        def ready():
            name=controller()
            return bool(name) and docker('exec',name,'blindpass-controller','healthcheck',success=False,timeout=5).returncode==0
        def helper_run(code,volume='data',write=False):
            mount='type=volume,src='+project+'_blindpass-'+volume+',dst=/'+volume+('' if write else ',readonly')
            return docker('run','--rm','--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges',
                          '--user','10001:10001','--mount',mount,'--entrypoint','python3',helper,'-c',code).stdout
        def custody(code,source=recovery,user='10001:10001'):
            return docker('run','--rm','--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges',
                          '--user',user,'--mount','type=bind,src='+str(source)+',dst=/recovery',
                          '--entrypoint','python3',helper,'-c',code)
        def inspect():
            return json.loads(helper_run('import sqlite3,json; from pathlib import Path; '
                'c=sqlite3.connect("file:/data/controller.db?mode=ro",uri=True); '
                'p=Path("/data/backups"); '
                'print(json.dumps({"identity":c.execute("SELECT tenant_id,issuer_epoch,schema_version FROM controller_meta WHERE id=1").fetchone(),'
                '"payload":c.execute("SELECT length(payload) FROM p06_backup_fixture").fetchone()[0],'
                '"integrity":c.execute("PRAGMA integrity_check").fetchone()[0],'
                '"directory":[p.stat().st_mode & 0o777,p.stat().st_uid],'
                '"members":[[f.name,f.stat().st_mode & 0o777,f.stat().st_uid,f.stat().st_size] for f in sorted(p.iterdir())]}))'))
        def verify(archive,offline_directory=None,success=True):
            # Opening needs the operator's offline material; the job's own custody cannot.
            result=compose('--profile','backup','run','--rm','--no-deps','--volume',str(offline_directory or offline)+':/offline:ro',
                           'controller-backup','backup','verify','--archive','/data/backups/'+archive,*split_custody.OFFLINE_OPEN,
                           '--work-directory','/data/backups',success=success,timeout=90)
            if success: assert json.loads(result.stdout)['verified'] is True
            return result
        def capture():
            # Actual requests arrive from the configured trusted edge peer,
            # concurrently with the separate offline backup process. HTTPS
            # edge certificate/header behavior is covered by compose-up.py.
            probe='''import json,signal,time,urllib.request
running=True
def stop(*_):
    global running
    running=False
signal.signal(signal.SIGTERM,stop)
attempts=failures=0
while running:
    request=urllib.request.Request("http://controller:3200/",headers={"Host":"blindpass.example","X-Forwarded-Host":"blindpass.example","X-Forwarded-Proto":"https","X-Forwarded-For":"198.51.100.1"})
    try:
        with urllib.request.urlopen(request,timeout=2) as response:
            assert response.status==200 and b"<!doctype html>" in response.read().lower()
    except Exception: failures+=1
    attempts+=1
    if attempts==1: print("probe_started",flush=True)
    time.sleep(0.02)
print(json.dumps({"attempts":attempts,"failures":failures}),flush=True)
'''
            docker('run','--detach','--name',probe_name,'--network',project+'_edge','--ip','172.29.63.3',
                   '--read-only','--user','10001:10001','--cap-drop','ALL','--security-opt','no-new-privileges',
                   '--entrypoint','python3',helper,'-c',probe)
            wait(lambda: b'probe_started' in docker('logs',probe_name).stdout,5,'concurrent request probe failed to start')
            started=time.monotonic()
            compose('--profile','backup','run','--detach','--no-deps','--name',job_name,'controller-backup')
            wait(lambda: not json.loads(docker('inspect',job_name).stdout)[0]['State']['Running'],30,'backup duration exceeded P06-I02 bound')
            elapsed=time.monotonic()-started
            assert elapsed<=30
            docker('stop','--time','5',probe_name)
            probe_value=json.loads(docker('logs',probe_name).stdout.splitlines()[-1])
            assert probe_value['attempts']>=2 and probe_value['failures']==0,'concurrent application request failed'
            assert json.loads(docker('inspect',probe_name).stdout)[0]['State']['ExitCode']==0
            docker('rm',probe_name)
            value=json.loads(docker('inspect',job_name).stdout)[0]
            assert value['Image']==image_id,'backup image changed during the gate'
            assert value['State']['ExitCode']==0,'actual backup job failed'
            host=value['HostConfig']
            assert value['Config']['User']=='10001:10001' and host['ReadonlyRootfs']
            assert host['NetworkMode']=='none' and host['CapDrop']==['ALL']
            assert 'no-new-privileges:true' in host['SecurityOpt']
            assert {'Name':'core','Hard':0,'Soft':0} in host['Ulimits']
            mounts={m['Destination']:m for m in value['Mounts']}
            assert not mounts['/keys']['RW'] and not mounts['/recovery']['RW'] and mounts['/data']['RW']
            output=docker('logs',job_name).stdout
            canary_log_scan.assert_log_clean('P06 backup job logs',output,[],markers=[b'PRIVATE KEY-----',b'BEGIN CERTIFICATE'],require=[b'"backup"',b'"verified"'],min_bytes=32)
            archive=json.loads(output)['backup']; assert json.loads(output)['verified'] is True
            docker('rm',job_name)
            return archive,elapsed,probe_value['attempts']
        def exhausted_container(archive,phase):
            # Mount only a private container tmpfs over the output directory.
            # Keep the original archive readable through a separate RO mount.
            quota={'capture':payload_bytes//2,'encryption':payload_bytes*5//2,
                   'verification':payload_bytes*3//2}[phase]
            override=root/'backup-fault.json'
            override.write_text(json.dumps({'services':{'controller-backup':{
                'tmpfs':['/data/backups:rw,noexec,nosuid,nodev,size='+str(quota)+',uid=10001,gid=10001,mode=0700'],
                'volumes':[{'type':'volume','source':'blindpass-data','target':'/source','read_only':True},
                           {'type':'bind','source':str(offline),'target':'/offline','read_only':True}]}}}))
            override.chmod(0o600)
            member={'capture':'database.sqlite','encryption':'encrypted.der','verification':'verified.tar'}[phase]
            minimum=16384 if phase=='capture' else 1024*1024
            # Inspect cleanup BEFORE container exit/unmount, so disappearing
            # tmpfs is never mistaken for ordinary error cleanup.
            watch='''set -u
umask 077
member="$1"
minimum="$2"
shift 2
/usr/local/bin/blindpass-controller backup "$@" &
worker=$!
observed=0
while kill -0 "$worker" 2>/dev/null; do
    if [ -n "$(find /data/backups -type f -name "$member" -size +"${minimum}"c -print -quit 2>/dev/null)" ]; then
        observed=1
        printf '%s\\n' P06_ACTUAL_FILE_PROGRESS
        break
    fi
    sleep 0.001
done
wait "$worker"
result=$?
[ "$result" -ne 0 ] && [ "$observed" -eq 1 ] || exit 91
[ -z "$(find /data/backups -mindepth 1 -print -quit)" ] || exit 92
printf '%s\\n' P06_POST_ERROR_CLEAN_BEFORE_UNMOUNT
exit "$result"
'''
            if phase=='verification':
                arguments=['verify','--archive','/source/backups/'+archive,'--work-directory','/data/backups',
                           *split_custody.OFFLINE_OPEN]
            else:
                arguments=['create','--output','/data/backups','--signing-credential-file','/recovery/signing.pem',
                           '--recipient-certificate-file','/recovery/recipient-certificate.pem']
            started=time.monotonic()
            result=compose('--file',str(override),'--profile','backup','run','--rm','--no-deps',
                           '--entrypoint','/bin/sh','controller-backup','-c',watch,'p06-fault',member,str(minimum),
                           *arguments,success=False,timeout=30)
            assert time.monotonic()-started<30
            expected=b'SQLite snapshot capture or validation failed' if phase=='capture' else b'backup cryptographic operation failed'
            assert result.returncode not in [0,91,92] and expected in result.stderr,'container did not reach the expected ENOSPC phase'
            assert b'P06_ACTUAL_FILE_PROGRESS' in result.stdout
            assert b'P06_POST_ERROR_CLEAN_BEFORE_UNMOUNT' in result.stdout
            canary_log_scan.assert_log_clean('P06 CB05 ENOSPC output '+phase,result.stdout+result.stderr,[],markers=[b'PRIVATE KEY-----'],require=[b'P06_ACTUAL_FILE_PROGRESS'],min_bytes=32)
            print('PASS P06-CB05 actual container '+phase+' ENOSPC; quota '+str(quota)+' bytes; output growth observed; cleanup before unmount',flush=True)
        try:
            # Chown only the private disposable bind directories, never host state.
            for source in directories:
                docker('run','--rm','--network','none','--read-only','--user','0','--mount',
                       'type=bind,src='+str(source)+',dst=/recovery','--entrypoint','/bin/sh',helper,
                       '-ec','chown 10001:10001 /recovery; chmod 0700 /recovery')
            for custody_directory,offline_directory in [(recovery,offline),(wrong,wrong_offline)]:
                split_custody.provision(docker,image,helper,custody_directory,offline_directory)
            split_custody.assert_host_holds_no_decrypt_key(docker,helper,recovery)
            compose('--profile','initialize','run','--rm','keys-init')
            compose('run','--rm','--no-deps','controller','migrate')
            compose('up','--detach','controller'); wait(ready,20,'serving controller failed readiness')
            helper_run('import sqlite3,os; os.umask(0o077); os.mkdir("/data/backups",0o700); '
                       'c=sqlite3.connect("/data/controller.db"); c.execute("PRAGMA journal_mode=WAL"); '
                       'c.execute("CREATE TABLE p06_backup_fixture (payload BLOB NOT NULL)"); '
                       'c.execute("INSERT INTO p06_backup_fixture VALUES(zeroblob('+str(payload_bytes)+'))"); c.commit()',write=True)
            before=inspect(); keys=helper_run('from pathlib import Path; import hashlib; '
                       'h=hashlib.sha256(); [h.update(p.read_bytes()) for p in sorted(Path("/keys").iterdir()) if p.is_file()]; '
                       'print(h.hexdigest())',volume='keys')
            source_container=json.loads(docker('inspect',controller()).stdout)[0]
            assert source_container['Image']==image_id,'serving image differs from backup candidate'
            assert '/recovery' not in [m['Destination'] for m in source_container['Mounts']]
            assert not any('RECOVERY' in v for v in source_container['Config']['Env'])
            version=docker('exec',controller(),'/usr/bin/openssl','version').stdout.decode().strip()
            packages=docker('exec',controller(),'dpkg-query','-W','-f=${Package} ${Version}\n','openssl','libssl3').stdout.decode().strip()
            archive,elapsed,attempts=capture(); verify(archive)
            after=inspect()
            assert after['identity']==before['identity'] and after['payload']==payload_bytes and after['integrity']=='ok'
            assert after['directory']==[0o700,10001]
            assert len(after['members'])==1 and after['members'][0][:3]==[archive,0o600,10001]
            assert after['members'][0][3]>payload_bytes and ready()
            print('PASS P06-CB02/P06-I02 actual offline non-root backup/verify; %d-byte source retained; creation %.3f s; %d concurrent requests, zero failures'%(payload_bytes,elapsed,attempts),flush=True)
            print('Runtime prerequisite: '+version+'; '+packages.replace('\n','; '),flush=True)
            failed=verify(archive,offline_directory=wrong_offline,success=False)
            assert failed.returncode!=0 and b'backup cryptographic operation failed' in failed.stderr
            # The backup host's own credential never opens what it wrote.
            host_open=compose('--profile','backup','run','--rm','--no-deps','controller-backup','backup','verify','--archive','/data/backups/'+archive,
                              '--recipient-key-file','/recovery/signing.pem','--signing-certificate-file','/recovery/signing-certificate.pem',
                              '--work-directory','/data/backups',success=False,timeout=90)
            assert host_open.returncode!=0 and b'backup cryptographic operation failed' in host_open.stderr
            custody('from pathlib import Path; Path("/recovery/recipient.pem").chmod(0o644)',source=offline)
            try:
                failed=verify(archive,success=False)
                assert failed.returncode!=0 and b'unsafe backup recovery credential' in failed.stderr
            finally: custody('from pathlib import Path; Path("/recovery/recipient.pem").chmod(0o600)',source=offline)
            custody('from pathlib import Path; Path("/recovery/signing.pem").chmod(0o644)')
            try:
                failed=compose('--profile','backup','run','--rm','--no-deps','controller-backup',success=False,timeout=90)
                assert failed.returncode!=0 and b'unsafe backup recovery credential' in failed.stderr
            finally: custody('from pathlib import Path; Path("/recovery/signing.pem").chmod(0o600)')
            failed=compose('--profile','backup','run','--rm','--no-deps','controller-backup',
                           environment=dict(env,BLINDPASS_BACKUP_RECOVERY_DIR=str(absent)),success=False,timeout=90)
            assert failed.returncode!=0 and b'unsafe backup recovery credential' in failed.stderr
            assert inspect()['members']==after['members']
            canary_log_scan.assert_log_clean('P06 CB03 compose logs',compose('logs','--no-color').stdout,[],markers=[b'PRIVATE KEY-----'],require=[b'controller'])
            print('PASS P06-CB03 actual wrong-offline/host-credential/missing/exposed custody refusal; ordinary controller has no recovery mount; no residue',flush=True)
            compose('up','--detach','--force-recreate','controller'); wait(ready,20,'recreated controller failed readiness')
            verify(archive); second,second_elapsed,second_attempts=capture(); assert second!=archive; verify(second)
            final=inspect()
            assert final['identity']==before['identity'] and len(final['members'])==2
            assert all(m[0].endswith('.bpbackup') and m[1:3]==[0o600,10001] for m in final['members'])
            assert helper_run('from pathlib import Path; import hashlib; h=hashlib.sha256(); '
                 '[h.update(p.read_bytes()) for p in sorted(Path("/keys").iterdir()) if p.is_file()]; print(h.hexdigest())',volume='keys')==keys
            print('PASS P06-CB04 retained identity/old verification and distinct repeated backup; creation %.3f s; %d concurrent requests, zero failures'%(second_elapsed,second_attempts),flush=True)
            if faults:
                for phase in ['capture','encryption','verification']:
                    exhausted_container(archive,phase)
                    assert inspect()==final,'container ENOSPC changed source or published archives'
                    assert ready(),'container ENOSPC interrupted ordinary serving'
                verify(archive); verify(second)
                print('PASS P06-CB05 original archives remain fully verifiable; serving/source identity and data unchanged',flush=True)
        finally:
            docker('rm','--force',job_name,success=False)
            docker('rm','--force',probe_name,success=False)
            compose('--profile','backup','--profile','initialize','down','--volumes','--remove-orphans',success=False)
            for source in directories:
                docker('run','--rm','--network','none','--read-only','--user','0','--mount',
                       'type=bind,src='+str(source)+',dst=/recovery','--entrypoint','/bin/sh',helper,'-ec',
                       'chown -R '+str(os.getuid())+':'+str(os.getgid())+' /recovery',success=False)
            assert not docker('ps','--all','--quiet','--filter','label=com.docker.compose.project='+project).stdout.strip()
            assert not docker('volume','ls','--quiet','--filter','label=com.docker.compose.project='+project).stdout.strip()
    print('PASS disposable Compose backup resources removed',flush=True)


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--image',default='blindpass-p06-controller:backup-sqlite')
    parser.add_argument('--helper-image',default='blindpass-p06-edge:local')
    parser.add_argument('--payload-bytes',type=int,default=8*1024*1024)
    parser.add_argument('--faults',action='store_true',help='Exercise actual per-container capture/encryption/decryption ENOSPC')
    args=parser.parse_args()
    if not 8*1024*1024<=args.payload_bytes<=192*1024*1024:
        parser.error('fixture payload must be between 8 and 192 MiB')
    backup_gate(args.image,args.helper_image,args.payload_bytes,args.faults)
