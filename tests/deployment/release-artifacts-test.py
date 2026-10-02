# SPDX-License-Identifier: AGPL-3.0-only
import importlib.util
import json
from pathlib import Path
import shutil
import platform
import subprocess
import tarfile
import tempfile
import unittest

ARCH = platform.machine()
WRONG_ARCH = 'aarch64' if ARCH == 'x86_64' else 'x86_64'
ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('release_artifacts', ROOT / 'scripts/release/release-artifacts.py')
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class ReleaseTests(unittest.TestCase):
    def test_p06_r02_inspects_actual_elf_and_rejects_wrong_architecture(self):
        elf = release.inspect_elf(Path('/usr/bin/true'), ARCH, maximum_glibc=(99, 99))
        self.assertIn('libc.so.6', elf['needed'])
        self.assertGreaterEqual(tuple(map(int, elf['glibc_max'].split('.'))), (2, 0))
        with self.assertRaises(release.ReleaseError):
            release.inspect_elf(Path('/usr/bin/true'), WRONG_ARCH, maximum_glibc=(99, 99))
        with self.assertRaises(release.ReleaseError):
            release.inspect_elf(Path('/usr/bin/true'), ARCH, maximum_glibc=(2, 0))

    def test_p06_r02_does_not_execute_elf_to_inspect_it(self):
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / 'candidate'
            shutil.copyfile('/usr/bin/true', candidate)
            candidate.chmod(0o600)
            self.assertIn('needed', release.inspect_elf(candidate, ARCH, maximum_glibc=(99, 99)))

    def test_p06_r03_missing_binary_and_nonelf_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'bad'
            with self.assertRaises(release.ReleaseError):
                release.inspect_elf(path, ARCH)
            path.write_text('P06-DUMMY-SECRET-DO-NOT-PACKAGE')
            with self.assertRaises(release.ReleaseError):
                release.inspect_elf(path, ARCH)

    def test_p06_r01_inventory_binds_content_and_preserves_private_source_exclusion(self):
        with tempfile.TemporaryDirectory() as directory:
            stage = Path(directory)
            (stage / 'bin').mkdir()
            (stage / 'bin/blindpass').write_bytes(b'fixture-executable')
            (stage / 'bin/blindpass').chmod(0o755)
            manifest = release.inventory(stage)
            self.assertEqual(manifest['bin/blindpass']['size'], 18)
            self.assertEqual(manifest['bin/blindpass']['mode'], '0755')
            self.assertEqual(manifest['bin/blindpass']['sha256'], release.digest(stage / 'bin/blindpass'))
            (stage / 'alias').symlink_to(stage / 'bin/blindpass')
            with self.assertRaises(release.ReleaseError):
                release.inventory(stage)

    def test_p06_r04_atomic_archive_does_not_replace_existing_release(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stage = root / 'blindpass-fixture'; stage.mkdir()
            (stage / 'manifest.json').write_text('{}')
            destination = root / 'release.tar.zst'
            release.publish_archive(stage, destination)
            before = destination.read_bytes()
            with self.assertRaises(release.ReleaseError):
                release.publish_archive(stage, destination)
            self.assertEqual(before, destination.read_bytes())
            self.assertFalse(any('.tmp' in p.name for p in root.iterdir()))
            unpacked = subprocess.run(['zstd', '-dc', str(destination)], check=True, capture_output=True).stdout
            tar = root / 'archive.tar'; tar.write_bytes(unpacked)
            with tarfile.open(tar) as archive:
                self.assertEqual(archive.getnames(), ['blindpass-fixture', 'blindpass-fixture/manifest.json'])

    def test_p06_r04_failure_never_publishes_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); stage = root / 'fixture'; stage.mkdir()
            destination = root / 'bad.tar.zst'
            with self.assertRaises(release.ReleaseError):
                release.publish_archive(stage, destination, compressor='/nonexistent/p06-zstd')
            self.assertFalse(destination.exists())
            self.assertFalse(any('.tmp' in p.name for p in root.iterdir()))

    def test_p06_r03_cli_missing_ui_or_binary_publishes_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'release'
            completed = subprocess.run([
                'python3', str(ROOT / 'scripts/release/release-artifacts.py'), '--profile', 'controller',
                '--bin-dir', directory, '--output-dir', str(output), '--arch', 'x86_64'
            ], capture_output=True, text=True)
            self.assertNotEqual(completed.returncode, 0)
            self.assertFalse(list(output.glob('*.tar.zst')))
            self.assertFalse((output / 'SHA256SUMS').exists())

    def test_p06_r05_only_reviewed_unused_npm_launchers_can_be_omitted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = root / 'source'; source.mkdir()
            (source / 'cli.js').write_text('fixture CLI')
            (source / 'launcher').symlink_to('cli.js')
            release.copy_tree(source, root / 'accepted', omitted_launchers={'launcher': 'cli.js'})
            self.assertTrue((root / 'accepted/cli.js').is_file())
            self.assertFalse((root / 'accepted/launcher').exists())
            (source / 'launcher').unlink()
            (source / 'launcher').symlink_to('/etc/passwd')
            with self.assertRaises(release.ReleaseError):
                release.copy_tree(source, root / 'denied', omitted_launchers={'launcher': 'cli.js'})


if __name__ == '__main__':
    unittest.main()
