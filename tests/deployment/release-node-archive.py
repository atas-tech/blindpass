#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""P06-R05 actual node archive/runtime gate; no fleet/workflow acceptance claim."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--bin-dir', type=Path, required=True)
parser.add_argument('--node-root', type=Path, required=True)
parser.add_argument('--browser-root', type=Path, required=True)
parser.add_argument('--arch', choices=['x86_64', 'aarch64'], required=True)
options = parser.parse_args()

with tempfile.TemporaryDirectory(prefix='p06-node-artifact-') as temporary:
    root = Path(temporary); output = root / 'release'
    subprocess.run([str(ROOT / 'scripts/release/build-tarballs.sh'), '--profile', 'node',
                    '--arch', options.arch, '--bin-dir', str(options.bin_dir), '--output-dir', str(output),
                    '--node-root', str(options.node_root), '--browser-root', str(options.browser_root)],
                   stdout=subprocess.DEVNULL, check=True)
    archive_path, = output.glob('*.tar.zst')
    raw = root / 'archive.tar'
    with raw.open('wb') as stream:
        subprocess.run(['zstd', '-dc', str(archive_path)], stdout=stream, check=True)
    extracted = root / 'extracted'; extracted.mkdir()
    with tarfile.open(raw) as archive:
        assert all(not member.issym() and not member.islnk() and
                   '..' not in Path(member.name).parts and not member.name.startswith('/') for member in archive)
        archive.extractall(extracted, filter='data')
    package, = extracted.iterdir()
    manifest = json.loads((package / 'manifest.json').read_text())
    assert manifest['architecture'] == options.arch
    assert 'examples only' in manifest['probe_units']
    actual = {file.relative_to(package).as_posix() for file in package.rglob('*') if file.is_file()} - {'manifest.json'}
    assert set(manifest['members']) == actual
    for name, member in manifest['members'].items():
        file = package / name
        assert hashlib.sha256(file.read_bytes()).hexdigest() == member['sha256']
        assert file.stat().st_size == member['size']
        assert f'{file.stat().st_mode & 0o777:04o}' == member['mode']
    login = package / 'lib/login'
    assert (login / 'runtime/LICENSE').read_bytes() == (options.node_root / 'LICENSE').read_bytes()
    for file in ['LICENSE', 'mcp/LICENSE', 'mcp/THIRD_PARTY_NOTICES.md', 'mcp/licenses/bundle-packages.json',
                 'node_modules/playwright/LICENSE', 'node_modules/playwright-core/LICENSE',
                 'browsers/chromium_headless_shell-1208/chrome-headless-shell-linux64/LICENSE.headless_shell']:
        assert (login / file).is_file(), 'runtime license/notice missing'
    for unit in (package / 'deploy/native').glob('*.service'):
        for command in re.findall(r'^ExecStart(?:Pre)?=(-?\S+)', unit.read_text(), re.M):
            command = command.removeprefix('-')
            if command.startswith('/usr/libexec/'):
                assert (package / 'bin' / Path(command).name).is_file(), 'unit executable absent'
            elif command.startswith('/usr/lib/blindpass/login/'):
                assert (login / command.removeprefix('/usr/lib/blindpass/login/')).is_file(), 'unit runtime absent'
            else:
                raise AssertionError('unreviewed service executable')
    env = {k: v for k, v in os.environ.items() if k not in ['NODE_OPTIONS', 'NODE_PATH', 'DEBUG', 'PWDEBUG', 'LD_PRELOAD', 'LD_LIBRARY_PATH']}
    env.update(HOME=str(root), PLAYWRIGHT_BROWSERS_PATH=str(login / 'browsers'))
    node = login / 'runtime/bin/node'
    module = root / 'module-check.mjs'
    module.write_text('''import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import { existsSync } from 'node:fs';
let step = 'module_resolution';
try {
const require = createRequire(process.env.P06_LOGIN + '/package.json');
const { chromium } = require('playwright');
step = 'pinned_headless_assets';
if (!existsSync(process.env.PLAYWRIGHT_BROWSERS_PATH + '/chromium_headless_shell-1208/chrome-headless-shell-linux64/chrome-headless-shell')) throw new Error('packaged headless browser missing');
step = 'private_helper_import';
await import(pathToFileURL(process.env.P06_LOGIN + '/src/private-login.mjs'));
step = 'stock_mcp_import';
await import(pathToFileURL(require.resolve('@playwright/mcp')));
step = 'sandboxed_browser_startup';
const browser = await chromium.launch({ headless: true, chromiumSandbox: true });
try {
  const page = await browser.newPage();
  await page.setContent('<p>P06 packaged runtime</p>');
  if (await page.textContent('p') !== 'P06 packaged runtime') throw new Error('packaged browser failed');
} finally { await browser.close(); }
} catch (error) {
  console.error('P06 runtime failure:', step, error.code ?? error.name);
  process.exit(1);
}
''')
    env['P06_LOGIN'] = str(login)
    subprocess.run([str(node), str(module)], env=env, stdout=subprocess.DEVNULL, timeout=30, check=True)
    subprocess.run([str(node), '--check', str(login / 'mcp/mcp-server.mjs')], env=env,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    print('P06-R05 PASS: actual archive/member/units/licenses, packaged module resolution and sandboxed Chromium startup')
