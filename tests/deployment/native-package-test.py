#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""P06-N01 preflight: no privilege or host installation is used by these tests."""
import hashlib
import json
from pathlib import Path
import platform
import struct
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
ARCHITECTURE = platform.machine()


class Preflight(unittest.TestCase):
    def fixture(self, root):
        binary = b'\x7fELF' + bytes(14) + struct.pack('<H', 62 if ARCHITECTURE == 'x86_64' else 183) + bytes(64)
        members = {}
        for name in ['bin/blindpass', 'bin/blindpass-controller']:
            file = root / name
            file.parent.mkdir(exist_ok=True)
            file.write_bytes(binary)
            file.chmod(0o755)
            members[name] = {'sha256': hashlib.sha256(binary).hexdigest(), 'size': len(binary), 'mode': '0755'}
        for name in ['blindpass-controller.service', 'blindpass-controller-initialize.service',
                     'blindpass-controller-reconcile-clock.service', 'blindpass-controller-backup.service',
                     'blindpass-controller-backup.timer', 'blindpass-controller.sysusers',
                     'blindpass-controller.tmpfiles', 'controller-install.py', 'install.sh', 'uninstall.sh']:
            file = root / 'deploy/native' / name
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_bytes(b'# P06 inventory fixture\n'); file.chmod(0o644)
            members[file.relative_to(root).as_posix()] = {'sha256': hashlib.sha256(file.read_bytes()).hexdigest(), 'size': file.stat().st_size, 'mode':'0644'}
        manifest = {'format_version': 1, 'profile': 'controller', 'version': '0.1.0', 'architecture': ARCHITECTURE,
                    'controller': {'console_embedded': True, 'input_embedded': True}, 'members': members}
        (root / 'manifest.json').write_text(json.dumps(manifest))
        return manifest

    def invoke(self, root):
        return subprocess.run(['python3', str(ROOT / 'deploy/native/controller-install.py'), '--bundle', str(root), '--verify-only'], capture_output=True, text=True)

    def test_p06_n01_valid_controller_inventory_preflight(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root)
            output = self.invoke(root)
            self.assertEqual(output.returncode, 0, output.stderr)
            self.assertEqual(json.loads(output.stdout), {'ok': True, 'profile': 'controller', 'version': '0.1.0', 'architecture': ARCHITECTURE})

    def test_p06_n01_tamper_and_missing_members_refused(self):
        for action in ['tamper', 'missing', 'extra']:
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self.fixture(root)
                file = root / 'bin/blindpass'
                if action == 'tamper': file.write_bytes(b'P06-DUMMY-CANARY')
                elif action == 'missing': file.unlink()
                else: (root / 'unlisted').write_bytes(b'P06-DUMMY-CANARY')
                output = self.invoke(root)
                self.assertNotEqual(output.returncode, 0)
                self.assertNotIn(temporary, output.stderr)
                self.assertNotIn('P06-DUMMY-CANARY', output.stderr)

    def test_p06_n01_member_and_directory_links_refused(self):
        for action in ['symlink', 'hardlink', 'directory']:
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self.fixture(root)
                file = root / 'bin/blindpass'
                if action == 'hardlink': (root / 'alias').hardlink_to(file)
                elif action == 'symlink':
                    file.unlink(); file.symlink_to('blindpass-controller')
                else:
                    (root / 'bin').rename(root / 'actual'); (root / 'bin').symlink_to('actual', target_is_directory=True)
                self.assertNotEqual(self.invoke(root).returncode, 0)

    def test_p06_n01_wrong_profile_architecture_and_unsafe_version_refused(self):
        for field, value in [('profile','node'), ('architecture','unknown'), ('version','../../escape')]:
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                manifest = self.fixture(root)
                manifest[field] = value
                (root / 'manifest.json').write_text(json.dumps(manifest))
                self.assertNotEqual(self.invoke(root).returncode, 0)

    def test_p06_n01_manifest_traversal_or_member_mode_refused(self):
        for action in ['path', 'mode']:
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                manifest = self.fixture(root)
                if action == 'path': manifest['members']['../../escape'] = manifest['members']['bin/blindpass']
                else: (root / 'bin/blindpass').chmod(0o777)
                (root / 'manifest.json').write_text(json.dumps(manifest))
                self.assertNotEqual(self.invoke(root).returncode, 0)

    def test_p06_n01_incomplete_native_profile_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = self.fixture(root)
            name = 'deploy/native/blindpass-controller.service'
            del manifest['members'][name]; (root / name).unlink()
            (root / 'manifest.json').write_text(json.dumps(manifest))
            self.assertNotEqual(self.invoke(root).returncode, 0)

    def test_p06_n01_duplicate_metadata_and_missing_ui_refused(self):
        for action in ['duplicate','ui']:
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                manifest = self.fixture(root)
                if action == 'ui':
                    manifest['controller']['console_embedded'] = False
                    (root / 'manifest.json').write_text(json.dumps(manifest))
                else:
                    (root / 'manifest.json').write_text('{"profile":"node",'+json.dumps(manifest)[1:])
                self.assertNotEqual(self.invoke(root).returncode, 0)


if __name__ == '__main__':
    unittest.main()
