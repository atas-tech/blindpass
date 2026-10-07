#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""P06-O09: render the actual Compose files; inspect retained/new templates."""
import json
import os
from pathlib import Path
import subprocess
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]

class Configuration(unittest.TestCase):
    def test_p06_cb01_sqlite_backup_is_explicit_offline_and_has_separate_custody(self):
        arguments=['docker','compose','--profile','backup','-f',str(ROOT/'deploy/controller/compose.sqlite.yml'),
                   '-f',str(ROOT/'deploy/controller/compose.backup-sqlite.yml'),'config','--format','json']
        env=dict(os.environ, BLINDPASS_PUBLIC_URL='https://blindpass.example', BLINDPASS_UI_BASE_URL='https://input.example', BLINDPASS_CONTROLLER_TENANT_ID='tenant_1', BLINDPASS_CONTROLLER_OWNER_ID='owner_1', BLINDPASS_AUTHORITY_CONFIG_DIR='/tmp/p06-private-authority', BLINDPASS_TRUST_PROXY='172.29.6.3',
                 BLINDPASS_BACKUP_RECOVERY_DIR='/tmp/p06-private-recovery')
        result=subprocess.run(arguments,env=env,capture_output=True,text=True)
        self.assertEqual(result.returncode,0,'SQLite backup overlay failed to render')
        value=json.loads(result.stdout); job=value['services']['controller-backup']
        self.assertEqual(job['profiles'],['backup'])
        # ADR 0013: the backup host holds a signing credential and a certificate only.
        for flag in ['--signing-credential-file','--recipient-certificate-file']: self.assertIn(flag,job['command'])
        for flag in ['--recovery-key-file','--recipient-key-file']: self.assertNotIn(flag,job['command'])
        self.assertEqual(job['user'],'10001:10001')
        self.assertTrue(job['read_only'])
        self.assertEqual(job['cap_drop'],['ALL'])
        self.assertIn('no-new-privileges:true',job['security_opt'])
        self.assertEqual(job['network_mode'],'none')
        self.assertTrue(job['healthcheck']['disable'])
        self.assertNotIn('ports',job); self.assertNotIn('pid',job)
        core=job['ulimits']['core']
        # Compose JSON omits zero soft/hard values; the actual job gate also
        # checks Docker's applied limit, rather than assuming this rendering.
        self.assertEqual(core.get('soft',0),0)
        self.assertEqual(core.get('hard',0),0)
        self.assertIn('--kill-after=10s',job['entrypoint']); self.assertIn('15m',job['entrypoint'])
        mounts={entry['target']:entry for entry in job['volumes']}
        self.assertTrue(mounts['/keys']['read_only'])
        self.assertTrue(mounts['/recovery']['read_only'])
        self.assertFalse(mounts['/recovery']['bind']['create_host_path'])
        self.assertNotIn('/recovery',[entry['target'] for entry in value['services']['controller']['volumes']])
        self.assertFalse(any('docker.sock' in entry['source'] for entry in job['volumes']))
        env.pop('BLINDPASS_BACKUP_RECOVERY_DIR')
        result=subprocess.run(arguments,env=env,capture_output=True,text=True)
        self.assertNotEqual(result.returncode,0,'Missing recovery custody must refuse rendering')

    def test_p06_cb02_postgres_backup_job_is_offline_to_the_edge_and_reads_a_file_url(self):
        arguments=['docker','compose','--profile','backup','-f',str(ROOT/'deploy/controller/compose.postgres.yml'),
                   '-f',str(ROOT/'deploy/controller/compose.backup-postgres.yml'),'config','--format','json']
        env=dict(os.environ, BLINDPASS_PUBLIC_URL='https://blindpass.example', BLINDPASS_UI_BASE_URL='https://input.example', BLINDPASS_CONTROLLER_TENANT_ID='tenant_1', BLINDPASS_CONTROLLER_OWNER_ID='owner_1', BLINDPASS_AUTHORITY_CONFIG_DIR='/tmp/p06-private-authority', BLINDPASS_TRUST_PROXY='172.29.6.3',
                 BLINDPASS_POSTGRES_PASSWORD_FILE='/tmp/p06-private-password', BLINDPASS_DATABASE_CONFIG_DIR='/tmp/p06-private-config',
                 BLINDPASS_BACKUP_RECOVERY_DIR='/tmp/p06-private-recovery')
        result=subprocess.run(arguments,env=env,capture_output=True,text=True)
        self.assertEqual(result.returncode,0,'PostgreSQL backup overlay failed to render: '+result.stderr)
        value=json.loads(result.stdout); job=value['services']['controller-backup']
        self.assertEqual(job['profiles'],['backup'])
        # ADR 0013: the backup host holds a signing credential and a certificate only.
        for flag in ['--signing-credential-file','--recipient-certificate-file']: self.assertIn(flag,job['command'])
        for flag in ['--recovery-key-file','--recipient-key-file']: self.assertNotIn(flag,job['command'])
        self.assertEqual(job['user'],'10001:10001')
        self.assertTrue(job['read_only']); self.assertEqual(job['cap_drop'],['ALL'])
        self.assertIn('no-new-privileges:true',job['security_opt'])
        self.assertEqual(sorted(job['networks']),['database'],'the job must not join the public edge network')
        self.assertNotIn('ports',job); self.assertEqual(job['restart'],'no')
        self.assertEqual(job['environment']['BLINDPASS_DATABASE_URL_FILE'],'/config/database.url')
        self.assertFalse([key for key in job['environment'] if key.endswith('PASSWORD') or key=='BLINDPASS_DATABASE_URL'],'credentials must come from files')
        mounts={entry['target']:entry for entry in job['volumes']}
        for target in ['/keys','/config','/recovery']: self.assertTrue(mounts[target]['read_only'],target)
        self.assertFalse(any('docker.sock' in entry['source'] for entry in job['volumes']))
        self.assertNotIn('/recovery',[entry['target'] for entry in value['services']['controller']['volumes']])
        env.pop('BLINDPASS_BACKUP_RECOVERY_DIR')
        result=subprocess.run(arguments,env=env,capture_output=True,text=True)
        self.assertNotEqual(result.returncode,0,'Missing recovery custody must refuse rendering')

    def test_p06_cb03_postgres_profile_provisions_the_dedicated_controller_schema_on_first_init(self):
        env=dict(os.environ, BLINDPASS_PUBLIC_URL='https://blindpass.example', BLINDPASS_UI_BASE_URL='https://input.example', BLINDPASS_CONTROLLER_TENANT_ID='tenant_1', BLINDPASS_CONTROLLER_OWNER_ID='owner_1', BLINDPASS_AUTHORITY_CONFIG_DIR='/tmp/p06-private-authority', BLINDPASS_TRUST_PROXY='172.29.6.3',
                 BLINDPASS_POSTGRES_PASSWORD_FILE='/tmp/p06-private-password', BLINDPASS_DATABASE_CONFIG_DIR='/tmp/p06-private-config')
        result=subprocess.run(['docker','compose','-f',str(ROOT/'deploy/controller/compose.postgres.yml'),'config','--format','json'],env=env,capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        mounts={entry['target']:entry for entry in json.loads(result.stdout)['services']['postgres']['volumes']}
        init=mounts['/docker-entrypoint-initdb.d']
        self.assertTrue(init['read_only']); self.assertEqual(Path(init['source']),ROOT/'deploy/controller/postgres-init')
        script=(ROOT/'deploy/controller/postgres-init/10-controller-schema.sql').read_text()
        self.assertIn('CREATE SCHEMA controller AUTHORIZATION blindpass;',script)
        self.assertIn('ALTER ROLE blindpass SET search_path = controller;',script)

    def test_p06_up12_upgrade_job_is_opt_in_one_shot_and_keeps_recovery_custody_separate(self):
        arguments=['docker','compose','--profile','upgrade','-f',str(ROOT/'deploy/controller/compose.sqlite.yml'),
                   '-f',str(ROOT/'deploy/controller/compose.upgrade-sqlite.yml'),'config','--format','json']
        env=dict(os.environ, BLINDPASS_PUBLIC_URL='https://blindpass.example', BLINDPASS_UI_BASE_URL='https://input.example', BLINDPASS_CONTROLLER_TENANT_ID='tenant_1', BLINDPASS_CONTROLLER_OWNER_ID='owner_1', BLINDPASS_AUTHORITY_CONFIG_DIR='/tmp/p06-private-authority', BLINDPASS_TRUST_PROXY='172.29.6.3',
                 BLINDPASS_BACKUP_RECOVERY_DIR='/tmp/p06-private-recovery')
        result=subprocess.run(arguments,env=env,capture_output=True,text=True)
        self.assertEqual(result.returncode,0,'upgrade overlay failed to render: '+result.stderr)
        value=json.loads(result.stdout); job=value['services']['controller-upgrade']
        self.assertEqual(job['profiles'],['upgrade']); self.assertEqual(job['restart'],'no')
        self.assertEqual(job['user'],'10001:10001'); self.assertTrue(job['read_only'])
        self.assertEqual(job['cap_drop'],['ALL']); self.assertIn('no-new-privileges:true',job['security_opt'])
        self.assertNotIn('ports',job)
        self.assertEqual(job['command'][:1],['migrate'])
        self.assertIn('--pre-upgrade-backup-dir',job['command'])
        for flag in ['--signing-credential-file','--recipient-certificate-file']: self.assertIn(flag,job['command'])
        for flag in ['--recovery-key-file','--recipient-key-file']: self.assertNotIn(flag,job['command'])
        mounts={entry['target']:entry for entry in job['volumes']}
        for target in ['/keys','/authority','/recovery']: self.assertTrue(mounts[target]['read_only'],target)
        self.assertNotIn('/recovery',[entry['target'] for entry in value['services']['controller']['volumes']])
        self.assertNotIn('upgrade',value['services']['controller'].get('profiles',[]))
        env.pop('BLINDPASS_BACKUP_RECOVERY_DIR')
        result=subprocess.run(arguments,env=env,capture_output=True,text=True)
        self.assertNotEqual(result.returncode,0,'Missing recovery custody must refuse rendering')

    def test_p06_ho_config_handoff_jobs_are_opt_in_private_and_keep_custody_separate(self):
        arguments=['docker','compose','--profile','handoff','-f',str(ROOT/'deploy/controller/compose.sqlite.yml'),
                   '-f',str(ROOT/'deploy/controller/compose.handoff-sqlite.yml'),'config','--format','json']
        env=dict(os.environ, BLINDPASS_PUBLIC_URL='https://blindpass.example', BLINDPASS_UI_BASE_URL='https://input.example', BLINDPASS_CONTROLLER_TENANT_ID='tenant_1', BLINDPASS_CONTROLLER_OWNER_ID='owner_1', BLINDPASS_AUTHORITY_CONFIG_DIR='/tmp/p06-private-authority', BLINDPASS_TRUST_PROXY='172.29.6.3',
                 BLINDPASS_BACKUP_RECOVERY_DIR='/tmp/p06-private-recovery', BLINDPASS_HANDOFF_TRANSFER_DIR='/tmp/p06-private-transfer',
                 BLINDPASS_HANDOFF_STAGING_DIR='/tmp/p06-private-staging', BLINDPASS_HANDOFF_ID='p06_handoff_1', BLINDPASS_HANDOFF_ARCHIVE='archive.bpbackup')
        result=subprocess.run(arguments,env=env,capture_output=True,text=True)
        self.assertEqual(result.returncode,0,'handoff overlay failed to render: '+result.stderr)
        value=json.loads(result.stdout); services=value['services']
        names=['controller-handoff-export','controller-handoff-abort','controller-handoff-import','controller-handoff-install']
        for name in names:
            job=services[name]
            self.assertEqual(job['profiles'],['handoff'],name); self.assertEqual(job['restart'],'no',name)
            self.assertEqual(job['user'],'10001:10001',name); self.assertTrue(job['read_only'],name)
            self.assertEqual(job['cap_drop'],['ALL'],name); self.assertIn('no-new-privileges:true',job['security_opt'],name)
            self.assertNotIn('ports',job,name)
        for name in ['controller-handoff-export','controller-handoff-abort','controller-handoff-import']:
            self.assertEqual(services[name]['command'][:1],['handoff'])
        self.assertEqual(services['controller-handoff-export']['command'][1],'export')
        self.assertEqual(services['controller-handoff-abort']['command'][1],'abort')
        self.assertEqual(services['controller-handoff-import']['command'][1],'import')
        export=services['controller-handoff-export']['command']
        for flag in ['--signing-credential-file','--recipient-certificate-file']: self.assertIn(flag,export)
        for flag in ['--recovery-key-file','--recipient-key-file']: self.assertNotIn(flag,export)
        opened=services['controller-handoff-import']['command']
        for flag in ['--recipient-key-file','--signing-certificate-file','--staging-directory']: self.assertIn(flag,opened)
        self.assertNotIn('--recovery-key-file',opened)
        # Decrypted material is staged only on a dedicated tmpfs of the import job.
        staging=[entry for entry in services['controller-handoff-import']['tmpfs'] if entry.startswith('/restore-staging')]
        self.assertEqual(len(staging),1); self.assertIn('mode=0700',staging[0]); self.assertIn('uid=10001',staging[0])
        self.assertEqual(opened[opened.index('--staging-directory')+1],'/restore-staging')
        for name in ['controller-handoff-export','controller-handoff-abort','controller-handoff-install']:
            self.assertFalse([e for e in services[name].get('tmpfs',[]) if e.startswith('/restore-staging')],name)
        # Recovery custody never reaches the ordinary service, the abort job or the install job.
        for name in ['controller','controller-handoff-abort','controller-handoff-install']:
            self.assertNotIn('/recovery',[entry['target'] for entry in services[name]['volumes']],name)
        for name in ['controller-handoff-export','controller-handoff-import']:
            mounts={entry['target']:entry for entry in services[name]['volumes']}
            self.assertTrue(mounts['/recovery']['read_only'],name)
        # The import job can only read the transfer package; the install job has no network and can only read staging.
        import_mounts={entry['target']:entry for entry in services['controller-handoff-import']['volumes']}
        self.assertTrue(import_mounts['/transfer']['read_only']); self.assertFalse(import_mounts['/staging'].get('read_only',False))
        install=services['controller-handoff-install']; mounts={entry['target']:entry for entry in install['volumes']}
        self.assertEqual(install['network_mode'],'none'); self.assertNotIn('networks',install)
        self.assertTrue(mounts['/staging']['read_only']); self.assertNotIn('/authority',mounts)
        self.assertNotIn('handoff',services['controller'].get('profiles',[]))
        for name in ['BLINDPASS_HANDOFF_TRANSFER_DIR','BLINDPASS_HANDOFF_ID']:
            missing=dict(env); missing.pop(name)
            refused=subprocess.run(arguments,env=missing,capture_output=True,text=True)
            self.assertNotEqual(refused.returncode,0,name+' must be required to render')

    def test_p06_rc_config_restore_jobs_are_opt_in_private_and_use_offline_custody(self):
        for profile in ['sqlite','postgres']:
            arguments=['docker','compose','--profile','restore','-f',str(ROOT/('deploy/controller/compose.'+profile+'.yml')),
                       '-f',str(ROOT/('deploy/controller/compose.restore-'+profile+'.yml')),'config','--format','json']
            env=dict(os.environ, BLINDPASS_PUBLIC_URL='https://blindpass.example', BLINDPASS_UI_BASE_URL='https://input.example', BLINDPASS_CONTROLLER_TENANT_ID='tenant_1', BLINDPASS_CONTROLLER_OWNER_ID='owner_1', BLINDPASS_AUTHORITY_CONFIG_DIR='/tmp/p06-private-authority', BLINDPASS_TRUST_PROXY='172.29.6.3',
                     BLINDPASS_POSTGRES_PASSWORD_FILE='/tmp/p06-private-password', BLINDPASS_DATABASE_CONFIG_DIR='/tmp/p06-private-database',
                     BLINDPASS_BACKUP_RECOVERY_DIR='/tmp/p06-private-offline', BLINDPASS_RESTORE_ARCHIVE_DIR='/tmp/p06-private-archives',
                     BLINDPASS_RESTORE_STAGING_DIR='/tmp/p06-private-staging', BLINDPASS_RESTORE_ID='p06_restore_1', BLINDPASS_RESTORE_ARCHIVE='archive.bpbackup')
            result=subprocess.run(arguments,env=env,capture_output=True,text=True)
            self.assertEqual(result.returncode,0,profile+' restore overlay failed to render: '+result.stderr)
            services=json.loads(result.stdout)['services']
            restore=services['controller-restore']; install=services['controller-restore-install']
            for name,job in [('controller-restore',restore),('controller-restore-install',install)]:
                self.assertEqual(job['profiles'],['restore'],name); self.assertEqual(job['restart'],'no',name)
                self.assertEqual(job['user'],'10001:10001',name); self.assertTrue(job['read_only'],name)
                self.assertEqual(job['cap_drop'],['ALL'],name); self.assertIn('no-new-privileges:true',job['security_opt'],name)
                self.assertNotIn('ports',job,name)
            command=restore['command']; self.assertEqual(command[0],'restore')
            for flag in ['--recipient-key-file','--signing-certificate-file','--staging-directory','--destination','--authority-url-file','--tenant-id','--owner-id','--recovery-id']:
                self.assertIn(flag,command)
            self.assertNotIn('--recovery-key-file',command)
            self.assertEqual(command[command.index('--staging-directory')+1],'/restore-staging')
            self.assertEqual(('--database-url-file' in command),profile=='postgres')
            staging=[entry for entry in restore['tmpfs'] if entry.startswith('/restore-staging')]
            self.assertEqual(len(staging),1); self.assertIn('mode=0700',staging[0]); self.assertIn('uid=10001',staging[0])
            mounts={entry['target']:entry for entry in restore['volumes']}
            for target in ['/authority','/recovery','/archives']: self.assertTrue(mounts[target]['read_only'],profile+target)
            # The install job has no network, no authority, no recovery custody and only reads the staged root.
            install_mounts={entry['target']:entry for entry in install['volumes']}
            self.assertEqual(install['network_mode'],'none'); self.assertNotIn('networks',install)
            self.assertTrue(install_mounts['/staging']['read_only'])
            for target in ['/authority','/recovery','/archives']: self.assertNotIn(target,install_mounts,profile+target)
            self.assertNotIn('/recovery',[entry['target'] for entry in services['controller']['volumes']])
            self.assertNotIn('restore',services['controller'].get('profiles',[]))
            for name in ['BLINDPASS_BACKUP_RECOVERY_DIR','BLINDPASS_RESTORE_ID','BLINDPASS_RESTORE_ARCHIVE','BLINDPASS_RESTORE_STAGING_DIR']:
                missing=dict(env); missing.pop(name)
                refused=subprocess.run(arguments,env=missing,capture_output=True,text=True)
                self.assertNotEqual(refused.returncode,0,profile+' '+name+' must be required to render')

    def test_p06_up15_postgres_upgrade_job_is_opt_in_one_shot_and_off_the_ordinary_service(self):
        env=dict(os.environ, BLINDPASS_PUBLIC_URL='https://blindpass.example', BLINDPASS_UI_BASE_URL='https://input.example', BLINDPASS_CONTROLLER_TENANT_ID='tenant_1', BLINDPASS_CONTROLLER_OWNER_ID='owner_1', BLINDPASS_AUTHORITY_CONFIG_DIR='/tmp/p06-private-authority', BLINDPASS_TRUST_PROXY='172.29.6.3',
                 BLINDPASS_POSTGRES_PASSWORD_FILE='/tmp/p06-private-password', BLINDPASS_DATABASE_CONFIG_DIR='/tmp/p06-private-config',
                 BLINDPASS_BACKUP_RECOVERY_DIR='/tmp/p06-private-recovery')
        arguments=['docker','compose','--profile','upgrade','-f',str(ROOT/'deploy/controller/compose.postgres.yml'),
                   '-f',str(ROOT/'deploy/controller/compose.upgrade-postgres.yml'),'config','--format','json']
        result=subprocess.run(arguments,env=env,capture_output=True,text=True)
        self.assertEqual(result.returncode,0,'PostgreSQL upgrade overlay failed to render: '+result.stderr)
        value=json.loads(result.stdout); job=value['services']['controller-upgrade']
        self.assertEqual(job['profiles'],['upgrade']); self.assertEqual(job['restart'],'no')
        self.assertEqual(job['user'],'10001:10001'); self.assertTrue(job['read_only'])
        self.assertEqual(job['cap_drop'],['ALL']); self.assertNotIn('ports',job)
        self.assertEqual(job['command'][:1],['migrate'])
        self.assertEqual(job['environment']['BLINDPASS_DATABASE_URL_FILE'],'/config/database.url')
        self.assertFalse([key for key in job['environment'] if key.endswith('PASSWORD') or key=='BLINDPASS_DATABASE_URL'])
        mounts={entry['target']:entry for entry in job['volumes']}
        for target in ['/keys','/config','/authority','/recovery']: self.assertTrue(mounts[target]['read_only'],target)
        self.assertNotIn('/recovery',[entry['target'] for entry in value['services']['controller']['volumes']])
        env.pop('BLINDPASS_BACKUP_RECOVERY_DIR')
        result=subprocess.run(arguments,env=env,capture_output=True,text=True)
        self.assertNotEqual(result.returncode,0,'Missing recovery custody must refuse rendering')

    def rendered(self, profile):
        env = dict(os.environ, BLINDPASS_PUBLIC_URL='https://blindpass.example', BLINDPASS_UI_BASE_URL='https://input.example', BLINDPASS_CONTROLLER_TENANT_ID='tenant_1', BLINDPASS_CONTROLLER_OWNER_ID='owner_1', BLINDPASS_AUTHORITY_CONFIG_DIR='/tmp/p06-private-authority', BLINDPASS_TRUST_PROXY='172.29.6.3',
                   BLINDPASS_POSTGRES_PASSWORD_FILE='/tmp/p06-private-password',
                   BLINDPASS_DATABASE_CONFIG_DIR='/tmp/p06-private-config')
        result = subprocess.run(['docker','compose','--profile','initialize','-f',str(ROOT/'deploy/controller'/('compose.'+profile+'.yml')),
                                 '-f',str(ROOT/'deploy/controller/compose.initialize.yml'),'config','--format','json'],
                                env=env,capture_output=True,text=True)
        self.assertEqual(result.returncode,0,'Compose candidate failed to render')
        return json.loads(result.stdout)

    def test_p06_o09_each_profile_has_nonroot_private_mount_and_ingress_contract(self):
        for profile in ['sqlite','postgres']:
            value=self.rendered(profile); service=value['services']['controller']
            self.assertEqual(service['user'],'10001:10001')
            self.assertTrue(service['read_only'])
            self.assertEqual(service['cap_drop'],['ALL'])
            self.assertIn('no-new-privileges:true',service['security_opt'])
            self.assertFalse(service.get('privileged',False)); self.assertNotIn('pid',service)
            self.assertNotIn('ports',service)
            mounts={entry['target']:entry for entry in service['volumes']}
            self.assertTrue(mounts['/keys']['read_only']); self.assertFalse(mounts['/data'].get('read_only',False))
            self.assertTrue(any(item.startswith('/run:') and 'uid=10001' in item and 'mode=0700' in item for item in service['tmpfs']))
            self.assertEqual(service['environment']['BLINDPASS_PROXY_REQUIRED'],'1')
            self.assertEqual(service['environment']['BLINDPASS_TRUST_PROXY'],'172.29.6.3')
            self.assertNotIn('redis',value['services'])
            for entry in service['volumes']:
                self.assertNotIn('docker.sock',entry['source']); self.assertNotIn('/run/systemd',entry['source'])
            init=value['services']['keys-init']
            self.assertEqual(init['command'],['keys','init','--directory','/keys'])
            self.assertFalse(init['volumes'][0].get('read_only',False))
            if profile=='postgres':
                pg=value['services']['postgres']
                self.assertNotIn('POSTGRES_PASSWORD',pg['environment'])
                self.assertEqual(pg['environment']['POSTGRES_PASSWORD_FILE'],'/run/secrets/postgres-password')
                self.assertNotIn('ports',pg)
                self.assertEqual(service['depends_on']['postgres']['condition'],'service_healthy')
                self.assertEqual(service['environment']['BLINDPASS_DATABASE_URL_FILE'],'/config/database.url')

    def test_p06_o09_templates_preserve_separate_controller_profiles(self):
        for profile in ['sqlite','postgres']:
            tree=ET.parse(ROOT/'deploy/unraid'/('blindpass-controller-'+profile+'.xml')).getroot()
            self.assertEqual(tree.findtext('Privileged'),'false')
            params=tree.findtext('ExtraParams')
            for flag in ['--user=10001:10001','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges','--tmpfs=/run:']:
                self.assertIn(flag,params)
            self.assertNotIn('docker.sock',ET.tostring(tree).decode()); self.assertNotIn('/run/systemd',ET.tostring(tree).decode())
            configs={entry.get('Target'):entry for entry in tree.findall('Config')}
            self.assertEqual(configs['/keys'].get('Mode'),'ro')
            self.assertEqual(configs['BLINDPASS_PROXY_REQUIRED'].text,'1')
            self.assertNotIn('BLINDPASS_DATABASE_URL',configs)
            if profile=='postgres': self.assertEqual(configs['BLINDPASS_DATABASE_URL_FILE'].text,'/config/database.url')
            self.assertEqual(configs['/authority'].get('Mode'),'ro')
            self.assertEqual(configs['BLINDPASS_AUTHORITY_URL_FILE'].text,'/authority/authority-url')
            for name in ['BLINDPASS_CONTROLLER_TENANT_ID','BLINDPASS_CONTROLLER_OWNER_ID']:
                self.assertEqual(configs[name].get('Required'),'true')
            self.assertNotIn('BLINDPASS_AUTHORITY_URL',configs)

    def test_p06_ca01_authority_is_required_private_read_only_and_never_auto_restarted(self):
        for profile in ['sqlite','postgres']:
            service=self.rendered(profile)['services']['controller']
            env=service['environment']
            self.assertEqual(env['BLINDPASS_AUTHORITY_URL_FILE'],'/authority/authority-url')
            self.assertEqual((env['BLINDPASS_CONTROLLER_TENANT_ID'],env['BLINDPASS_CONTROLLER_OWNER_ID']),('tenant_1','owner_1'))
            self.assertNotIn('BLINDPASS_AUTHORITY_URL',env)
            mount={entry['target']:entry for entry in service['volumes']}['/authority']
            self.assertTrue(mount['read_only']); self.assertFalse(mount['bind']['create_host_path'])
            self.assertEqual(mount['source'],'/tmp/p06-private-authority')
            # A used active revision is never replayed: restart is an administrator action.
            self.assertEqual(service['restart'],'no')
            for missing in ['BLINDPASS_CONTROLLER_TENANT_ID','BLINDPASS_CONTROLLER_OWNER_ID','BLINDPASS_AUTHORITY_CONFIG_DIR']:
                env_without=dict(os.environ, BLINDPASS_PUBLIC_URL='https://blindpass.example', BLINDPASS_UI_BASE_URL='https://input.example',
                                 BLINDPASS_TRUST_PROXY='172.29.6.3', BLINDPASS_POSTGRES_PASSWORD_FILE='/tmp/p06-private-password',
                                 BLINDPASS_DATABASE_CONFIG_DIR='/tmp/p06-private-config', BLINDPASS_CONTROLLER_TENANT_ID='tenant_1',
                                 BLINDPASS_CONTROLLER_OWNER_ID='owner_1', BLINDPASS_AUTHORITY_CONFIG_DIR='/tmp/p06-private-authority')
                env_without.pop(missing)
                result=subprocess.run(['docker','compose','-f',str(ROOT/'deploy/controller'/('compose.'+profile+'.yml')),'config','--format','json'],
                                      env=env_without,capture_output=True,text=True)
                self.assertNotEqual(result.returncode,0,profile+' rendered without '+missing)

if __name__=='__main__': unittest.main()
