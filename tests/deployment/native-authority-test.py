#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""P06-NA01..NA10: native installer authority inputs and the upgrade plan. No root, systemd or network."""
import importlib.util
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('controller_install', ROOT / 'deploy/native/controller-install.py')
install = importlib.util.module_from_spec(spec)
spec.loader.exec_module(install)

LOCAL = 'postgresql://runtime:DUMMY@127.0.0.1:5433/authority'


class AuthorityInputs(unittest.TestCase):
    def test_p06_na01_local_and_verified_remote_urls_are_accepted(self):
        for url in [LOCAL, 'postgres://runtime:DUMMY@localhost/authority', 'postgresql://runtime:DUMMY@[::1]:5432/authority',
                    'postgresql://runtime:DUMMY@db.authority.invalid:5432/authority?sslmode=verify-full',
                    'postgresql://runtime:DUMMY@db.authority.invalid/authority?sslmode=verify-ca&sslrootcert=/etc/ssl/ca.pem']:
            self.assertEqual(install.check_authority_url((url + '\n').encode()), url)

    def test_p06_na02_unverified_remote_and_malformed_urls_are_refused_without_echo(self):
        bad = ['postgresql://runtime:DUMMY@db.authority.invalid/authority',
               'postgresql://runtime:DUMMY@db.authority.invalid/authority?sslmode=require',
               'postgresql://runtime:DUMMY@db.authority.invalid/authority?sslmode=prefer',
               'postgresql://runtime:DUMMY@10.0.0.9/authority?sslmode=disable',
               'mysql://runtime:DUMMY@127.0.0.1/authority', 'http://127.0.0.1/', LOCAL + ' extra', LOCAL + '\nsecond',
               'postgresql://', '', LOCAL + '?' + 'a' * 20000]
        for url in bad:
            with self.assertRaises(install.Refusal) as caught:
                install.check_authority_url(url.encode())
            self.assertNotIn('DUMMY', str(caught.exception))

    def test_p06_na03_identifiers_follow_the_ledger_pattern(self):
        for good in ['a', 'tenant_1', 'Owner-2', 'x' * 128]:
            self.assertEqual(install.safe_identifier(good, 'tenant'), good)
        for bad in ['', ' ', 'a b', 'a/b', 'a;b', "a'b", 'x' * 129, 'tenant\n', '../x', 'é']:
            with self.assertRaises(install.Refusal):
                install.safe_identifier(bad, 'tenant')

    def test_p06_na04_authority_dropin_carries_the_identity_and_credential_only_for_authority_units(self):
        text = install.authority_dropin('tenant_1', 'owner-2').decode()
        self.assertIn('LoadCredential=authority-url:/etc/blindpass/controller-authority/authority-url', text)
        self.assertIn('Environment=BLINDPASS_AUTHORITY_URL_FILE=%d/authority-url', text)
        self.assertIn('Environment=BLINDPASS_CONTROLLER_TENANT_ID=tenant_1', text)
        self.assertIn('Environment=BLINDPASS_CONTROLLER_OWNER_ID=owner-2', text)
        self.assertNotIn('postgres', text.replace('authority-url', ''))
        self.assertEqual(set(install.AUTHORITY_UNITS), {'blindpass-controller.service',
                         'blindpass-controller-initialize.service', 'blindpass-controller-reconcile-clock.service',
                         'blindpass-controller-upgrade.service'})
        # The offline backup unit and the shared environment file never see authority settings.
        self.assertNotIn('blindpass-controller-backup.service', install.AUTHORITY_UNITS)
        for name in ['controller.env.example']:
            self.assertNotIn('BLINDPASS_CONTROLLER_TENANT_ID=', (ROOT/'deploy/native'/name).read_text().replace('#',''))
        with self.assertRaises(install.Refusal):
            install.authority_dropin('bad id', 'owner')

    def test_p06_na05_authority_input_file_must_be_private_and_unlinked(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'authority-url'
            path.write_text(LOCAL)
            path.chmod(0o640)
            with self.assertRaises(install.Refusal):
                install.read_authority_input(path)
            path.chmod(0o600)
            self.assertEqual(install.read_authority_input(path), LOCAL)
            link = Path(directory) / 'link'
            link.symlink_to(path)
            with self.assertRaises((install.Refusal, OSError)):
                install.read_authority_input(link)
            hard = Path(directory) / 'hard'
            os.link(path, hard)
            with self.assertRaises(install.Refusal):
                install.read_authority_input(path)

    def test_p06_na06_cli_exposes_the_authority_and_two_stage_initialization_options(self):
        text = subprocess.run(['python3', str(ROOT / 'deploy/native/controller-install.py'), '--help'],
                              capture_output=True, text=True).stdout
        for option in ['--authority-url-file', '--tenant-id', '--owner-id', '--initialize-keys', '--initialize']:
            self.assertIn(option, text)


OLD = {'version': '0.1.0', 'manifest_sha256': 'a' * 64, 'initialized': True, 'authority': True, 'purged': False}


def new(version, digest='b' * 64):
    return {'version': version}, digest


class UpgradePlan(unittest.TestCase):
    def plan(self, previous, manifest, digest, upgrade):
        return install.plan_artifact(previous, manifest, digest, upgrade)

    def test_p06_na07_same_artifact_is_idempotent_and_any_other_needs_upgrade(self):
        self.assertEqual(self.plan(OLD, {'version': '0.1.0'}, 'a' * 64, False), 'same')
        for version, digest in [('0.1.1', 'b' * 64), ('0.0.9', 'b' * 64), ('0.1.0', 'b' * 64)]:
            with self.assertRaises(install.Refusal):
                self.plan(OLD, {'version': version}, digest, False)

    def test_p06_na08_upgrade_only_moves_forward_from_an_initialized_authority_install(self):
        self.assertEqual(self.plan(OLD, *new('0.1.1'), True), 'upgrade')
        self.assertEqual(self.plan(OLD, *new('0.1.10'), True), 'upgrade')
        self.assertEqual(self.plan(dict(OLD, version='0.1.9'), *new('0.1.10'), True), 'upgrade')
        self.assertEqual(self.plan(dict(OLD, version='0.2.0-rc1'), *new('0.2.0'), True), 'upgrade')
        for previous, version in [(OLD, '0.1.0'), (OLD, '0.0.9'), (dict(OLD, version='0.1.10'), '0.1.9'),
                                  (dict(OLD, version='0.2.0'), '0.2.0-rc1')]:
            with self.assertRaises(install.Refusal):
                self.plan(previous, *new(version), True)
        # Same content under --upgrade is not an upgrade.
        with self.assertRaises(install.Refusal):
            self.plan(OLD, {'version': '0.1.0'}, 'a' * 64, True)
        for broken in [dict(OLD, initialized=False), dict(OLD, authority=False)]:
            with self.assertRaises(install.Refusal):
                self.plan(broken, *new('0.1.1'), True)

    def test_p06_na09_the_upgrade_unit_is_managed_and_runs_the_locked_backup_migration(self):
        self.assertIn('blindpass-controller-upgrade.service', install.UNITS)
        unit = (ROOT / 'deploy/native/blindpass-controller-upgrade.service').read_text()
        self.assertIn('Conflicts=blindpass-controller.service', unit)
        self.assertIn('migrate --pre-upgrade-backup-dir /var/lib/blindpass/controller/pre-upgrade-backups '
                      '--signing-credential-file %d/signing-credential '
                      '--recipient-certificate-file %d/recipient-certificate', unit)
        self.assertIn('LoadCredential=signing-credential:/etc/blindpass/controller-backup-signing-credential', unit)
        self.assertIn('LoadCredential=recipient-certificate:/etc/blindpass/controller-backup-recipient-certificate', unit)
        # ADR 0013: no recipient private key and no single recovery key reach the unit.
        self.assertNotIn('recovery-key', unit)
        self.assertNotIn('recipient-key', unit)
        self.assertNotIn('Restart=', unit)

    def test_p06_na11_the_restore_unit_is_managed_hardened_and_holds_only_offline_custody(self):
        self.assertIn('blindpass-controller-restore.service', install.UNITS)
        unit = (ROOT / 'deploy/native/blindpass-controller-restore.service').read_text()
        for line in ['Conflicts=blindpass-controller.service',
                     'ConditionPathExists=/etc/blindpass/controller-restore.env',
                     'ConditionPathExists=/etc/blindpass/controller-restore/recipient-key',
                     'ConditionPathExists=/etc/blindpass/controller-restore/signing-certificate',
                     'EnvironmentFile=/etc/blindpass/controller-restore.env',
                     'LoadCredential=recipient-key:/etc/blindpass/controller-restore/recipient-key',
                     'LoadCredential=signing-certificate:/etc/blindpass/controller-restore/signing-certificate',
                     'LoadCredential=authority-url:/etc/blindpass/controller-authority/authority-url',
                     'User=blindpass', 'Type=oneshot', 'NoNewPrivileges=yes', 'PrivateTmp=yes',
                     'CapabilityBoundingSet=', 'MemoryDenyWriteExecute=yes', 'ProtectSystem=strict',
                     'RuntimeDirectory=blindpass-controller-restore', 'LimitCORE=0',
                     'StateDirectory=blindpass/controller-restore']:
            self.assertIn(line, unit.splitlines())
        # Tmpfs staging under /run, every argument explicit, host custody absent.
        self.assertIn('restore --archive ${BLINDPASS_RESTORE_ARCHIVE} --recipient-key-file %d/recipient-key '
                      '--signing-certificate-file %d/signing-certificate '
                      '--staging-directory /run/blindpass-controller-restore '
                      '--destination ${BLINDPASS_RESTORE_DESTINATION} --authority-url-file %d/authority-url '
                      '--tenant-id ${BLINDPASS_RESTORE_TENANT_ID} --owner-id ${BLINDPASS_RESTORE_OWNER_ID} '
                      '--recovery-id ${BLINDPASS_RESTORE_RECOVERY_ID}', unit)
        self.assertNotIn('controller-backup-signing-credential', unit)
        self.assertNotIn('LoadCredential=root-secret', unit)
        self.assertNotIn('Restart=', unit)
        # It is never started by the timer or the serving unit.
        self.assertNotIn('blindpass-controller-restore', (ROOT / 'deploy/native/blindpass-controller.service').read_text())
        self.assertNotIn('blindpass-controller-restore', (ROOT / 'deploy/native/blindpass-controller-backup.timer').read_text())

    def test_p06_na10_cli_exposes_upgrade(self):
        text = subprocess.run(['python3', str(ROOT / 'deploy/native/controller-install.py'), '--help'],
                              capture_output=True, text=True).stdout
        self.assertIn('--upgrade', text)


if __name__ == '__main__':
    unittest.main()
