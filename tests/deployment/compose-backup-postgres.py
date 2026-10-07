#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""P06-PGC01–PGC04: shipped PostgreSQL backup overlay and the pinned toolkit in the
actual controller image, non-root and read-only, disposable resources only."""
import argparse
import json
import os
from pathlib import Path
import re
import secrets
import tempfile

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


def backup_gate(image, helper, payload_bytes):
    image_id=json.loads(docker('image','inspect',image).stdout)[0]['Id']
    print('Candidate image config: '+image_id,flush=True)
    project='blindpass-p06-pgbackup-'+secrets.token_hex(4)
    database_password=secrets.token_hex(24)
    with tempfile.TemporaryDirectory(prefix=project+'-') as directory:
        root=Path(directory)
        config=root/'config'; config.mkdir(mode=0o700)
        recovery=root/'recovery'; recovery.mkdir(mode=0o700)
        wrong=root/'wrong'; wrong.mkdir(mode=0o700)
        offline=root/'offline'; offline.mkdir(mode=0o700)
        wrong_offline=root/'wrong-offline'; wrong_offline.mkdir(mode=0o700)
        authority=root/'authority'; authority.mkdir(mode=0o700)
        password_file=root/'pg-password'; password_file.write_text(database_password); password_file.chmod(0o600)
        (config/'database.url').write_text('postgresql://blindpass:'+database_password+'@postgres:5432/blindpass')
        (config/'database.url').chmod(0o600)
        directories=[config,recovery,wrong,authority,offline,wrong_offline]
        env=dict(os.environ,BLINDPASS_CONTROLLER_IMAGE=image,BLINDPASS_PUBLIC_URL='https://blindpass.example',BLINDPASS_UI_BASE_URL='https://input.example',
                 BLINDPASS_TRUST_PROXY='172.29.64.3',BLINDPASS_CONTROLLER_IP='172.29.64.2',BLINDPASS_EDGE_SUBNET='172.29.64.0/24',
                 BLINDPASS_POSTGRES_PASSWORD_FILE=str(password_file),BLINDPASS_DATABASE_CONFIG_DIR=str(config),
                 BLINDPASS_BACKUP_RECOVERY_DIR=str(recovery),BLINDPASS_AUTHORITY_CONFIG_DIR=str(authority),
                 BLINDPASS_CONTROLLER_TENANT_ID='p06_pgbackup_tenant',BLINDPASS_CONTROLLER_OWNER_ID='p06_pgbackup_owner')
        base=['docker','compose','--project-name',project,'--file',str(ROOT/'deploy/controller/compose.postgres.yml'),
              '--file',str(ROOT/'deploy/controller/compose.initialize.yml'),
              '--file',str(ROOT/'deploy/controller/compose.backup-postgres.yml')]
        def compose(*args,environment=None,**kwargs):
            return run(base+list(args),env=environment or env,**kwargs)
        def chown(source,owner):
            docker('run','--rm','--network','none','--user','0','--mount','type=bind,src='+str(source)+',dst=/c',
                   '--entrypoint','/bin/sh',helper,'-ec','chown -R '+owner+' /c',success=False)
        def psql(sql,database='blindpass'):
            return compose('exec','-T','postgres','psql','-U','blindpass','-d',database,'-X','-q','-At','-v','ON_ERROR_STOP=1','-c',sql).stdout.decode().strip()
        def pg_ready():
            try: return psql('SELECT 1')=='1'
            except AssertionError: return False
        def job(*arguments,environment=None,success=True,timeout=300,volume=None):
            mount=['--volume',str(volume)+':/offline:ro'] if volume else []
            return compose('--profile','backup','run','--rm','--no-deps',*mount,'controller-backup',*arguments,
                           environment=environment,success=success,timeout=timeout)
        def listing():
            return json.loads(docker('run','--rm','--network','none','--read-only','--user','10001:10001',
                '--mount','type=volume,src='+project+'_blindpass-data,dst=/data,readonly','--entrypoint','python3',helper,'-c',
                'import json; from pathlib import Path; p=Path("/data/backups"); '
                'print(json.dumps([[f.name,f.stat().st_mode & 0o777,f.stat().st_uid,f.stat().st_size] for f in sorted(p.iterdir())] if p.exists() else []))').stdout)
        try:
            for source in directories: chown(source,'10001:10001')
            compose('up','--detach','postgres')
            wait(pg_ready,60,'PostgreSQL did not start')
            compose('--profile','initialize','run','--rm','keys-init')
            split_custody.provision(docker,image,helper,recovery,offline)
            split_custody.provision(docker,image,helper,wrong,wrong_offline)
            split_custody.assert_host_holds_no_decrypt_key(docker,helper,recovery)
            # Isolated fixture initialization in test mode; production initialization needs the authority (PW05).
            docker('run','--rm','--user','10001:10001','--network',project+'_database','--read-only',
                   '--cap-drop','ALL','--security-opt','no-new-privileges','-e','BLINDPASS_TEST_MODE=1','-e','BLINDPASS_PROXY_REQUIRED=0',
                   '-e','BLINDPASS_PUBLIC_URL=https://blindpass.example','-e','BLINDPASS_UI_BASE_URL=https://input.example',
                   '-e','BLINDPASS_DATABASE_URL_FILE=/config/database.url','--mount','type=bind,src='+str(config)+',dst=/config,readonly',
                   '--mount','type=volume,src='+project+'_blindpass-keys,dst=/keys','--entrypoint','/usr/local/bin/blindpass-controller',
                   image,'migrate')
            # A real payload so capture, encryption and restore verification are not trivial.
            psql("CREATE TABLE controller.p06_backup_payload (id integer primary key, payload bytea not null)")
            psql("INSERT INTO controller.p06_backup_payload SELECT 1, convert_to(repeat('p06', "+str(payload_bytes//3)+"), 'UTF8')")
            before=psql("SELECT (SELECT count(*) FROM controller.operators)||':'||(SELECT length(payload) FROM controller.p06_backup_payload)")
            result=job()
            summary=json.loads(result.stdout)
            assert summary['verified'] is True
            archive=summary['backup']
            canary_log_scan.assert_log_clean('P06 PG backup job output',result.stdout+result.stderr,[database_password],markers=[b'PRIVATE KEY-----'],require=[b'"verified"'],min_bytes=32)
            members=listing(); assert len(members)==1 and members[0][0]==archive and members[0][1]==0o600 and members[0][2]==10001
            print('PASS P06-PGC01 PostgreSQL backup created and verified by a complete isolated restore in the shipped image',flush=True)
            # PGC02: exact process properties of a real backup job, recorded from a detached run.
            name=project+'-inspect'
            compose('--profile','backup','run','--detach','--no-deps','--name',name,'controller-backup')
            wait(lambda: not json.loads(docker('inspect',name).stdout)[0]['State']['Running'],300,'backup job exceeded its bound')
            value=json.loads(docker('inspect',name).stdout)[0]
            assert value['State']['ExitCode']==0
            host=value['HostConfig']
            assert value['Config']['User']=='10001:10001' and host['ReadonlyRootfs'] and host['CapDrop']==['ALL']
            assert 'no-new-privileges:true' in host['SecurityOpt'] and not host['Privileged']
            assert {'Name':'core','Hard':0,'Soft':0} in host['Ulimits']
            mounts={m['Destination']:m for m in value['Mounts']}
            assert not mounts['/keys']['RW'] and not mounts['/recovery']['RW'] and not mounts['/config']['RW'] and mounts['/data']['RW']
            assert set(value['NetworkSettings']['Networks'])=={project+'_database'}, 'backup job must only use the internal database network'
            output=docker('logs',name).stdout
            canary_log_scan.assert_log_clean('P06 PG backup job logs',output,[database_password],markers=[b'PRIVATE KEY-----'],require=[b'"backup"'],min_bytes=32)
            assert database_password not in json.dumps(value['Config']['Env']) and database_password not in json.dumps(value['Config']['Cmd'])
            second=json.loads(output)['backup']
            docker('rm',name)
            members=listing(); assert len(members)==2 and {m[0] for m in members}=={archive,second}
            assert not [m for m in members if m[0].startswith('.backup-')], 'staging residue remained'
            print('PASS P06-PGC02 non-root read-only job, internal network only, no credential in env/args/logs, no residue',flush=True)
            # PGC03: operator verification, wrong key, plaintext absence.
            for item in (archive,second):
                verified=job('backup','verify','--archive','/data/backups/'+item,*split_custody.OFFLINE_OPEN,'--work-directory','/data/backups',volume=offline)
                value=json.loads(verified.stdout)
                assert value['verified'] is True and value['backend']=='postgres'
            job('backup','verify','--archive','/data/backups/'+archive,*split_custody.OFFLINE_OPEN,'--work-directory','/data/backups',
                volume=wrong_offline,success=False)
            # The backup host's own credential never opens what it wrote.
            job('backup','verify','--archive','/data/backups/'+archive,'--recipient-key-file','/recovery/signing.pem',
                '--signing-certificate-file','/recovery/signing-certificate.pem','--work-directory','/data/backups',success=False)
            raw=docker('run','--rm','--network','none','--read-only','--user','10001:10001','--mount','type=volume,src='+project+'_blindpass-data,dst=/data,readonly',
                       '--entrypoint','cat',helper,'/data/backups/'+archive).stdout
            for needle in (b'PGDMP',b'CREATE TABLE',b'p06_backup_payload',database_password.encode()):
                assert needle not in raw, 'plaintext in sealed archive'
            assert len(listing())==2, 'verification left residue'
            print('PASS P06-PGC03 operator verify (both archives), wrong offline key and the host credential refused, sealed archive has no plaintext',flush=True)
            # PGC04: failure closed. The database is stopped; the job fails and publishes nothing.
            # PGC05: output exhaustion at capture and at the restore-verification stage.
            override=root/'quota.json'
            def exhausted(size):
                override.write_text(json.dumps({'services':{'controller-backup':{
                    'tmpfs':['/data/backups:rw,noexec,nosuid,nodev,size='+str(size)+',uid=10001,gid=10001,mode=0700']}}}))
                return run(base+['--file',str(override),'--profile','backup','run','--rm','--no-deps','controller-backup'],
                           env=env,success=False,timeout=300)
            for size in (2*1024*1024, 40*1024*1024):
                result=exhausted(size)
                assert result.returncode!=0 and b'"verified":true' not in result.stdout, 'exhausted output was reported as a verified backup'
                assert database_password.encode() not in result.stdout+result.stderr
                assert len(listing())==2, 'exhaustion changed the published archives'
                assert psql("SELECT (SELECT count(*) FROM controller.operators)||':'||(SELECT length(payload) FROM controller.p06_backup_payload)")==before,'source changed'
            print('PASS P06-PGC05 output exhaustion at capture and at isolated-restore verification fails closed; archives and source unchanged',flush=True)
            compose('stop','postgres')
            job(success=False,timeout=120)
            assert len(listing())==2, 'a failed backup published or left files'
            compose('up','--detach','postgres')
            wait(pg_ready,60,'PostgreSQL did not restart')
            assert psql("SELECT (SELECT count(*) FROM controller.operators)||':'||(SELECT length(payload) FROM controller.p06_backup_payload)")==before,'source changed'
            print('PASS P06-PGC04 unreachable database fails closed with no published files; source unchanged',flush=True)
        finally:
            docker('rm','--force',project+'-inspect',success=False)
            compose('--profile','backup','--profile','initialize','down','--volumes','--remove-orphans',success=False)
            for source in directories: chown(source,str(os.getuid())+':'+str(os.getgid()))
            assert not docker('ps','--all','--quiet','--filter','label=com.docker.compose.project='+project).stdout.strip()
            assert not docker('volume','ls','--quiet','--filter','label=com.docker.compose.project='+project).stdout.strip()
    print('PASS disposable Compose PostgreSQL backup resources removed',flush=True)


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--image',default='blindpass-p06-controller:pg')
    parser.add_argument('--helper-image',default='blindpass-p06-edge:local')
    parser.add_argument('--payload-bytes',type=int,default=8*1024*1024)
    args=parser.parse_args()
    backup_gate(args.image,args.helper_image,args.payload_bytes)
