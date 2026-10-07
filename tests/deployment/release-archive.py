#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""P06-R01/R02/R03/R04: actual archive, manifest and extracted binary startup.
This is a loopback artifact gate, not a systemd/Compose deployment rehearsal.
"""
import argparse
import hashlib
import json
import re
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tarfile
import tempfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--bin-dir', type=Path, required=True)
parser.add_argument('--arch', choices=['x86_64', 'aarch64'], required=True)
options = parser.parse_args()


def invoke(args, **kwargs):
    return subprocess.run(args, check=True, stdout=subprocess.DEVNULL, **kwargs)


with tempfile.TemporaryDirectory(prefix='p06-artifact-') as temporary:
    root = Path(temporary)
    binaries = root / 'binaries'; binaries.mkdir()
    for name in ['blindpass', 'blindpass-controller']:
        shutil.copyfile(options.bin_dir / name, binaries / name)
        (binaries / name).chmod(0o755)
    canary = b'P06-DUMMY-ARCHIVE-EXCLUSION-' + os.urandom(24).hex().encode()
    (binaries / 'root-secret').write_bytes(canary)
    output = root / 'release'
    args = [str(ROOT / 'scripts/release/build-tarballs.sh'), '--profile', 'controller',
            '--arch', options.arch, '--bin-dir', str(binaries), '--output-dir', str(output),
            '--allow-dirty']
    invoke(args)
    invoke([str(ROOT / 'scripts/release/checksums.sh'), str(output)])
    invoke(['sha256sum', '--check', 'SHA256SUMS'], cwd=output)
    archives = list(output.glob('*.tar.zst')); assert len(archives) == 1
    original_digest = hashlib.sha256(archives[0].read_bytes()).digest()
    duplicate = subprocess.run(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    assert duplicate.returncode != 0
    assert hashlib.sha256(archives[0].read_bytes()).digest() == original_digest
    raw = root / 'archive.tar'
    with raw.open('wb') as stream:
        subprocess.run(
            ['zstd', '-dc', str(archives[0])], stdout=stream, check=True)
    extracted = root / 'extracted'; extracted.mkdir()
    with tarfile.open(raw) as archive:
        for member in archive:
            assert not member.issym() and not member.islnk()
            assert member.uid == member.gid == 0
            assert '..' not in Path(member.name).parts and not member.name.startswith('/')
            if member.isfile():
                assert canary not in archive.extractfile(member).read()
        archive.extractall(extracted, filter='data')
    package, = extracted.iterdir()
    manifest = json.loads((package / 'manifest.json').read_text())
    actual_members = {p.relative_to(package).as_posix() for p in package.rglob('*') if p.is_file()} - {'manifest.json'}
    assert set(manifest['members']) == actual_members
    for name, record in manifest['members'].items():
        file = package / name
        assert hashlib.sha256(file.read_bytes()).hexdigest() == record['sha256']
        assert file.stat().st_size == record['size']
        assert f'{file.stat().st_mode & 0o777:04o}' == record['mode']
    assert manifest['controller']['console_embedded'] and manifest['controller']['input_embedded']
    # P07 slice 7: the operator path ships complete. Every Markdown file in the extracted archive keeps only
    # absolute links or relative links that resolve inside it (links to repository-only files are pinned to the tag).
    for name in ('deploy/controller/compose.sqlite.yml', 'deploy/controller/compose.initialize.yml',
                 'deploy/controller/compose.postgres.yml', 'deploy/controller/.env.example',
                 'deploy/controller/postgres-init/10-controller-schema.sql', 'docs/deploy/compose-quickstart.md',
                 'docs/deploy/README.md', 'README.md'):
        assert (package / name).is_file(), f'operator file missing from the archive: {name}'
    for guide in sorted(package.rglob('*.md')):
        in_fence = False
        for line in guide.read_text().splitlines():
            if line.lstrip().startswith('```'):
                in_fence = not in_fence
                continue
            if in_fence:
                continue
            for link in re.findall(r'\]\(([^)\s]+)\)', line):
                if '://' in link or link.startswith(('#', 'mailto:')):
                    continue
                target = (guide.parent / link.split('#')[0]).resolve()
                assert target.is_relative_to(package.resolve()) and target.exists(), f'broken archive guide link: {guide.name} -> {link}'
    assert manifest['architecture'] == options.arch
    data = root / 'data'; data.mkdir(mode=0o700)
    keys = root / 'keys'
    cli = package / 'bin/blindpass'; controller = package / 'bin/blindpass-controller'
    invoke([str(cli), 'keys', 'init', '--directory', str(keys)])
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0)); port = reservation.getsockname()[1]
    origin = f'http://127.0.0.1:{port}'
    env = {k: v for k, v in os.environ.items() if not k.startswith('BLINDPASS_')}
    env.update({'BLINDPASS_KEYS_DIR': str(keys), 'BLINDPASS_DATA_DIR': str(data),
                'BLINDPASS_LISTEN': f'127.0.0.1:{port}', 'BLINDPASS_PUBLIC_URL': origin,
                'BLINDPASS_UI_BASE_URL': origin, 'BLINDPASS_ADMIN_SOCKET_PATH': str(root / 'admin.sock')})
    invoke([str(controller), 'check-config'], env=env)
    invoke([str(cli), 'migrate'], env=env)
    process = subprocess.Popen([str(controller), 'serve'], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 15
        while True:
            try:
                with urllib.request.urlopen(origin + '/readyz', timeout=1) as response:
                    assert response.status == 200
                    break
            except OSError:
                assert process.poll() is None, 'extracted controller exited'
                assert time.monotonic() < deadline, 'extracted controller readiness timeout'
                time.sleep(0.05)
        for path in ['/', '/?id=fixture&metadata_sig=dummy&submit_sig=dummy']:
            with urllib.request.urlopen(origin + path, timeout=2) as response:
                assert response.status == 200
                assert 'text/html' in response.headers.get('Content-Type', '')
                assert "default-src 'none'" in response.headers.get('Content-Security-Policy', '')
                assert '<html' in response.read().decode().lower()
        print('P06-R01/R02/R03/R04 PASS: actual archive, hashes, canary exclusion, no overwrite, extracted controller/CLI/UI startup')
    finally:
        process.terminate()
        try: process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill(); process.wait(); raise AssertionError('unbounded controller shutdown')
