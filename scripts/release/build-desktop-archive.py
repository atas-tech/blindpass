#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Package the tracked desktop approval app (P07-D2), never a checkout or test fixture.

The app is Quickshell QML, JavaScript and POSIX shell, so the archive holds no compiled
code; the x86_64 suffix follows the release naming plan and the tested profile.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tarfile
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[2]
APP = 'desktop/approval-app'
# Test fixtures and the test-only scenario runner never ship.
EXCLUDED_PREFIXES = (f'{APP}/tests/',)
EXCLUDED_FILES = {f'{APP}/e2e.qml'}
EXECUTABLE_PREFIX = f'{APP}/bin/'


class ReleaseError(Exception):
    pass


def run(args, cwd):
    try:
        return subprocess.run(args, check=True, capture_output=True, text=True, timeout=30, cwd=cwd).stdout
    except (OSError, subprocess.SubprocessError) as error:
        raise ReleaseError('artifact command failed') from error


def digest(path):
    hasher = hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            hasher.update(block)
    return hasher.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, default=ROOT)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--allow-dirty', action='store_true',
                        help='package a tree with uncommitted changes; the manifest records source_dirty=true')
    options = parser.parse_args()
    root = options.source_root.resolve()
    dirty = bool(run(['git', 'status', '--porcelain'], root).strip())
    if dirty and not options.allow_dirty:
        raise ReleaseError('refusing to package uncommitted changes; commit them or pass --allow-dirty for a local candidate')
    version = tomllib.loads((root / 'Cargo.toml').read_text())['workspace']['package']['version']
    if not re.fullmatch(r'\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?', version):
        raise ReleaseError('unsafe release version')
    tracked = run(['git', 'ls-files', '-z', '--', APP], root).split('\0')
    selected = sorted(name for name in tracked if name and name not in EXCLUDED_FILES
                      and not name.startswith(EXCLUDED_PREFIXES))
    if f'{APP}/shell.qml' not in selected:
        raise ReleaseError('approval app entry point missing from the tracked inventory')
    name = f'blindpass-approval-app-{version}-linux-x86_64'
    destination = options.output_dir / f'{name}.tar.zst'
    options.output_dir.mkdir(parents=True, exist_ok=True)
    if destination.exists() or destination.is_symlink():
        raise ReleaseError('release already exists; choose a new version/output directory')
    with tempfile.TemporaryDirectory(prefix='.staging-', dir=options.output_dir) as temporary:
        stage = Path(temporary) / name
        members = {}
        for tracked_name in selected:
            source = root / tracked_name
            if source.is_symlink() or not source.is_file():
                raise ReleaseError('symlink or non-regular member in the app inventory')
            relative = Path(tracked_name).relative_to(APP)
            target = stage / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source.read_bytes())
            target.chmod(0o755 if tracked_name.startswith(EXECUTABLE_PREFIX) else 0o644)
            members[relative.as_posix()] = {'sha256': digest(target), 'size': target.stat().st_size,
                                            'mode': f'{target.stat().st_mode & 0o777:04o}'}
        for source_name, target_name in (('packages/console/LICENSE', 'LICENSE'), ('LICENSES.md', 'LICENSES.md')):
            source = root / source_name
            if source.is_symlink() or not source.is_file():
                raise ReleaseError('required licence file absent or unsafe')
            (stage / target_name).write_bytes(source.read_bytes())
            (stage / target_name).chmod(0o644)
            members[target_name] = {'sha256': digest(stage / target_name), 'size': (stage / target_name).stat().st_size, 'mode': '0644'}
        manifest = {'format_version': 1, 'profile': 'desktop-approval-app', 'version': version, 'architecture': 'x86_64',
                    'architecture_note': 'QML, JavaScript and POSIX shell only; no compiled code',
                    'source_commit': run(['git', 'rev-parse', 'HEAD'], root).strip(), 'source_dirty': dirty,
                    'members': dict(sorted(members.items()))}
        (stage / 'manifest.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
        (stage / 'manifest.json').chmod(0o644)
        raw_descriptor, raw = tempfile.mkstemp(prefix='.archive-', suffix='.tmp', dir=options.output_dir)
        os.close(raw_descriptor)
        descriptor, compressed = tempfile.mkstemp(prefix='.archive-', suffix='.tmp', dir=options.output_dir)
        try:
            def canonical(info):
                info.uid = info.gid = 0
                info.uname = info.gname = 'root'
                info.mtime = 0
                info.mode = 0o755 if info.isdir() else info.mode & 0o755 | 0o644
                return info
            with tarfile.open(raw, 'w', format=tarfile.PAX_FORMAT) as archive:
                archive.add(stage, arcname=name, recursive=False, filter=canonical)
                for path in sorted(stage.rglob('*')):
                    archive.add(path, arcname=f'{name}/{path.relative_to(stage).as_posix()}', recursive=False, filter=canonical)
            with os.fdopen(descriptor, 'wb') as output:
                subprocess.run(['zstd', '-q', '-T1', '-6', '-c', raw], stdout=output, stderr=subprocess.DEVNULL, check=True)
                output.flush()
                os.fsync(output.fileno())
            os.link(compressed, destination)
        except (OSError, subprocess.SubprocessError) as error:
            raise ReleaseError('archive publication failed') from error
        finally:
            Path(raw).unlink(missing_ok=True)
            Path(compressed).unlink(missing_ok=True)
    print(f'{destination.name} sha256={digest(destination)}')


if __name__ == '__main__':
    try:
        main()
    except (ReleaseError, OSError, KeyError, ValueError) as error:
        print(f'release: {error if isinstance(error, ReleaseError) else "artifact filesystem operation failed"}',
              file=__import__('sys').stderr)
        raise SystemExit(1)
