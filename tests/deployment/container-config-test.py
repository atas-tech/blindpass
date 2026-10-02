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
    def rendered(self, profile):
        env = dict(os.environ, BLINDPASS_TRUST_PROXY='172.29.6.3',
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

if __name__=='__main__': unittest.main()
