#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Package build-owned binaries, not a checkout or runtime credential directory."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[2]
ARCHITECTURES = {'x86_64': 'Advanced Micro Devices X86-64', 'aarch64': 'AArch64'}
ALLOWED_LIBRARIES = {'libcrypto.so.3', 'libsystemd.so.0', 'libgcc_s.so.1', 'libc.so.6',
                     'libm.so.6', 'libstdc++.so.6', 'libdl.so.2', 'libpthread.so.0',
                     'librt.so.1', 'libatomic.so.1', 'ld-linux-x86-64.so.2', 'ld-linux-aarch64.so.1'}
# The pinned Playwright headless shell's direct libraries. Presence at runtime
# and sandbox capability still require the real-host P05/P06 gates.
BROWSER_LIBRARIES = ALLOWED_LIBRARIES | {
    'libglib-2.0.so.0', 'libgobject-2.0.so.0', 'libnspr4.so', 'libnss3.so',
    'libnssutil3.so', 'libgio-2.0.so.0', 'libatk-1.0.so.0', 'libatk-bridge-2.0.so.0',
    'libdbus-1.so.3', 'libexpat.so.1', 'libatspi.so.0', 'libX11.so.6',
    'libXcomposite.so.1', 'libXdamage.so.1', 'libXext.so.6', 'libXfixes.so.3',
    'libXrandr.so.2', 'libgbm.so.1', 'libxcb.so.1', 'libxkbcommon.so.0',
    'libudev.so.1', 'libasound.so.2',
}


class ReleaseError(Exception):
    pass


def run(args):
    try:
        return subprocess.run(args, check=True, capture_output=True, text=True, timeout=30).stdout
    except (OSError, subprocess.SubprocessError) as error:
        raise ReleaseError('artifact command failed') from error


def digest(path):
    hasher = hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            hasher.update(block)
    return hasher.hexdigest()


def inspect_elf(path, arch, maximum_glibc=(2, 36), allowed_libraries=ALLOWED_LIBRARIES, allow_origin=False):
    if arch not in ARCHITECTURES or not path.is_file() or path.is_symlink():
        raise ReleaseError('missing or unsafe binary')
    header = run(['readelf', '-hW', str(path)])
    machine = re.search(r'Machine:\s*(.*)', header)
    if not machine or machine.group(1).strip() != ARCHITECTURES[arch]:
        raise ReleaseError('binary architecture mismatch')
    dynamic = run(['readelf', '-dW', str(path)])
    needed = sorted(set(re.findall(r'\(NEEDED\).*?\[(.*?)\]', dynamic)))
    if not needed or set(needed) - allowed_libraries:
        raise ReleaseError('unreviewed dynamic library requirement')
    search_paths = re.findall(r'\((?:RPATH|RUNPATH)\).*?\[(.*?)\]', dynamic)
    if search_paths and (not allow_origin or any(path != '$ORIGIN' for path in search_paths)):
        raise ReleaseError('runtime search path is not allowed')
    versions = run(['readelf', '--version-info', '-W', str(path)])
    glibc = [tuple(map(int, v.split('.'))) for v in re.findall(r'\bGLIBC_(\d+(?:\.\d+)+)\b', versions)]
    if not glibc or max(glibc) > maximum_glibc:
        raise ReleaseError('binary exceeds Debian bookworm glibc baseline')
    maxima = {}
    for namespace, ceiling in [('GLIBCXX', (3, 4, 30)), ('CXXABI', (1, 3, 13)), ('OPENSSL', (3, 0, 0))]:
        found = [tuple(map(int, v.split('.'))) for v in re.findall(r'\b' + namespace + r'_(\d+(?:\.\d+)+)\b', versions)]
        if found and max(found) > ceiling:
            raise ReleaseError('binary exceeds bookworm C++/OpenSSL symbol baseline')
        maxima[namespace.lower() + '_max'] = '.'.join(map(str, max(found))) if found else None
    systemd = sorted(set(re.findall(r'\bLIBSYSTEMD_(\d+)\b', versions)), key=int)
    if systemd and int(systemd[-1]) > 252:
        raise ReleaseError('binary exceeds bookworm library symbol baseline')
    return {'machine': machine.group(1).strip(), 'needed': needed,
            'glibc_max': '.'.join(map(str, max(glibc))),
            'systemd_max': systemd[-1] if systemd else None, 'sha256': digest(path), **maxima}


def inventory(stage):
    members = {}
    for path in sorted(stage.rglob('*')):
        if path.is_symlink():
            raise ReleaseError('symlink in artifact')
        if path.is_dir():
            continue
        if not path.is_file():
            raise ReleaseError('non-regular artifact member')
        members[path.relative_to(stage).as_posix()] = {
            'sha256': digest(path), 'size': path.stat().st_size,
            'mode': f'{path.stat().st_mode & 0o777:04o}',
        }
    return members


def publish_archive(stage, destination, compressor='zstd'):
    """Publish with no-replace semantics only after compression and fsync."""
    if destination.exists() or destination.is_symlink():
        raise ReleaseError('release already exists; choose a new version/output directory')
    descriptor, temporary = tempfile.mkstemp(prefix='.archive-', suffix='.tmp', dir=destination.parent)
    raw_descriptor, raw = tempfile.mkstemp(prefix='.archive-', suffix='.tmp', dir=destination.parent)
    os.close(raw_descriptor)
    try:
        with tarfile.open(raw, 'w') as archive:
            def canonical(info):
                info.uid = info.gid = 0; info.uname = info.gname = 'root'; info.mtime = 0
                return info
            archive.add(stage, arcname=stage.name, filter=canonical)
        with os.fdopen(descriptor, 'wb') as output:
            subprocess.run([compressor, '-q', '-T1', '-6', '-c', raw], stdout=output,
                           stderr=subprocess.DEVNULL, check=True)
            output.flush(); os.fsync(output.fileno())
        os.link(temporary, destination)
        directory = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(directory)
        finally: os.close(directory)
    except (OSError, subprocess.SubprocessError) as error:
        raise ReleaseError('archive publication failed') from error
    finally:
        Path(temporary).unlink(missing_ok=True); Path(raw).unlink(missing_ok=True)


def copy_file(source, target, executable=False):
    if not source.is_file() or source.is_symlink():
        raise ReleaseError('required artifact input absent or unsafe')
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    target.chmod(0o755 if executable else 0o644)


def copy_tree(source, target, omitted_launchers=None):
    if not source.is_dir() or source.is_symlink():
        raise ReleaseError('required runtime directory absent or unsafe')
    for file in sorted(source.rglob('*')):
        omitted = (omitted_launchers or {}).get(file.relative_to(source).as_posix())
        if omitted is not None:
            if not file.is_symlink() or str(file.readlink()) != omitted:
                raise ReleaseError('changed runtime launcher requires review')
            continue
        if file.is_symlink():
            raise ReleaseError('runtime symlinks require explicit review')
        if file.is_file():
            copy_file(file, target / file.relative_to(source), executable=bool(file.stat().st_mode & 0o111))
        elif not file.is_dir():
            raise ReleaseError('non-regular runtime input')


def prepare(profile, stage, options, version):
    binaries = ['blindpass-controller', 'blindpass'] if profile == 'controller' else [
        'blindpass-broker', 'blindpass-node', 'blindpass-provision', 'blindpass-credential-loader', 'blindpass-consumer',
        'blindpass-backup-probe', 'blindpass-workload-client']
    elf = {}
    for name in binaries:
        path = options.bin_dir / name
        elf[name] = inspect_elf(path, options.arch)
        copy_file(path, stage / 'bin' / name, executable=True)
    for name in binaries[:2]:
        if run([str(stage / 'bin' / name), '--version']).strip() != f'{name} {version}':
            raise ReleaseError('binary version mismatch')
    metadata = {}
    if profile == 'controller':
        try: info = json.loads(run([str(stage / 'bin/blindpass-controller'), '--build-info']))
        except ValueError as error: raise ReleaseError('invalid controller build metadata') from error
        if info.get('version') != version or not info.get('console_embedded') or not info.get('input_embedded'):
            raise ReleaseError('controller must embed both UI surfaces at this version')
        metadata['controller'] = info
        copy_file(ROOT / 'deploy/native/controller.env.example', stage / 'config/controller.env.example')
        copy_file(ROOT / 'deploy/native/controller.env.example', stage / 'deploy/native/controller.env.example')
        copy_file(ROOT / 'docs/deploy/release-layout.md', stage / 'docs/deploy/release-layout.md')
        copy_file(ROOT / 'docs/deploy/controller-ingress.md', stage / 'docs/deploy/controller-ingress.md')
        for name in ('nginx.conf.example', 'Caddyfile.example'):
            copy_file(ROOT / 'deploy/proxy' / name, stage / 'deploy/proxy' / name)
    else:
        if not options.node_root or not options.browser_root:
            raise ReleaseError('node profile requires reviewed Node root and pinned browser root')
        node = options.node_root / 'bin/node'
        node_version = run([str(node), '--version']).strip()
        if node_version not in ('v24.21.0', 'v26.10.0'):
            raise ReleaseError('unreviewed Node runtime version')
        elf['runtime/bin/node'] = inspect_elf(node, options.arch)
        copy_file(node, stage / 'lib/login/runtime/bin/node', executable=True)
        copy_file(options.node_root / 'LICENSE', stage / 'lib/login/runtime/LICENSE')
        helper_files = run(['git', '-C', str(ROOT), 'ls-files', '--', 'helpers/login/src']).splitlines()
        if not helper_files: raise ReleaseError('helper source inventory missing')
        for name in helper_files:
            if not name.endswith('.mjs'): raise ReleaseError('unreviewed helper source member')
            copy_file(ROOT / name, stage / 'lib/login/src' / Path(name).relative_to('helpers/login/src'))
        copy_file(ROOT / 'helpers/login/LICENSE', stage / 'lib/login/LICENSE')
        for package, expected in [('playwright', '1.58.2'), ('playwright-core', '1.58.2'), ('@playwright/mcp', '0.0.83')]:
            source = ROOT / 'node_modules' / package
            try: actual = json.loads((source / 'package.json').read_text())['version']
            except (OSError, ValueError, KeyError) as error: raise ReleaseError('missing runtime manifest') from error
            if actual != expected: raise ReleaseError('runtime package version mismatch')
            omitted = {'node_modules/.bin/playwright': '../playwright/cli.js',
                       'node_modules/.bin/playwright-core': '../playwright-core/cli.js'} if package == '@playwright/mcp' else {}
            copy_tree(source, stage / 'lib/login/node_modules' / package, omitted_launchers=omitted)
            if omitted: metadata['omitted_npm_cli_launchers'] = sorted(omitted)
        browser = options.browser_root / 'chromium_headless_shell-1208'
        if not (browser / 'chrome-headless-shell-linux64/LICENSE.headless_shell').is_file():
            raise ReleaseError('pinned browser license missing')
        copy_tree(browser, stage / 'lib/login/browsers/chromium_headless_shell-1208')
        for executable in browser.rglob('*'):
            if executable.is_file():
                with executable.open('rb') as source:
                    is_elf = source.read(4) == b'\x7fELF'
                if is_elf:
                    metadata.setdefault('browser_elf', {})[executable.relative_to(browser).as_posix()] = inspect_elf(
                        executable, options.arch, allowed_libraries=BROWSER_LIBRARIES, allow_origin=True)
        mcp = ROOT / 'packages/openclaw-plugin/dist'
        copy_file(mcp / 'mcp-server.mjs', stage / 'lib/login/mcp/mcp-server.mjs', executable=True)
        for name in ['LICENSE', 'THIRD_PARTY_NOTICES.md']:
            copy_file(mcp / name, stage / 'lib/login/mcp' / name)
        copy_tree(mcp / 'licenses', stage / 'lib/login/mcp/licenses')
        metadata['node_runtime_version'] = node_version
        metadata['host_support'] = 'unaccepted candidate; broker requires exact P01 profile and runtime checks'
        metadata['probe_units'] = 'P01 examples only; never enable as a production backup/workload'
        copy_file(ROOT / 'deploy/native/blindpass-node.env.example', stage / 'config/blindpass-node.env.example')
        for file in sorted((ROOT / 'deploy/native').iterdir()):
            if file.suffix in ('.service', '.socket', '.sysusers', '.tmpfiles') and not file.name.startswith('blindpass-controller'):
                copy_file(file, stage / 'deploy/native' / file.name)
    copy_file(ROOT / 'packages/console/LICENSE', stage / 'LICENSE')
    copy_file(ROOT / 'LICENSES.md', stage / 'LICENSES.md')
    metadata.update({'format_version': 1, 'profile': profile, 'version': version, 'architecture': options.arch,
                     'build_baseline': 'debian-bookworm/glibc-2.36', 'elf': elf,
                     'source_commit': run(['git', '-C', str(ROOT), 'rev-parse', 'HEAD']).strip(),
                     'source_dirty': bool(run(['git', '-C', str(ROOT), 'status', '--porcelain']).strip()),
                     'members': inventory(stage)})
    (stage / 'manifest.json').write_text(json.dumps(metadata, indent=2, sort_keys=True) + '\n')
    (stage / 'manifest.json').chmod(0o644)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', choices=['controller', 'node', 'all'], default='all')
    parser.add_argument('--bin-dir', type=Path, default=ROOT / 'target/release')
    parser.add_argument('--output-dir', type=Path, default=ROOT / 'dist/release')
    parser.add_argument('--arch', choices=ARCHITECTURES, required=True)
    parser.add_argument('--node-root', type=Path)
    parser.add_argument('--browser-root', type=Path)
    options = parser.parse_args()
    version = tomllib.loads((ROOT / 'Cargo.toml').read_text())['workspace']['package']['version']
    if not re.fullmatch(r'\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?', version):
        raise ReleaseError('unsafe release version')
    options.output_dir.mkdir(parents=True, exist_ok=True)
    profiles = ['controller', 'node'] if options.profile == 'all' else [options.profile]
    # Validate all profiles before publishing any of them.
    with tempfile.TemporaryDirectory(prefix='.staging-', dir=options.output_dir) as temporary:
        prepared = []
        for profile in profiles:
            name = f'blindpass-{profile}-{version}-linux-{options.arch}'
            stage = Path(temporary) / name; stage.mkdir()
            destination = options.output_dir / f'{name}.tar.zst'
            if destination.exists() or destination.is_symlink(): raise ReleaseError('release already exists')
            prepare(profile, stage, options, version)
            prepared.append((stage, destination))
        for stage, destination in prepared:
            publish_archive(stage, destination)
            print(f'{destination.name} sha256={digest(destination)}')


if __name__ == '__main__':
    try: main()
    except (ReleaseError, OSError) as error:
        # Do not print external command output, paths or build input contents.
        print(f'release: {error if isinstance(error, ReleaseError) else "artifact filesystem operation failed"}', file=__import__('sys').stderr)
        raise SystemExit(1)
