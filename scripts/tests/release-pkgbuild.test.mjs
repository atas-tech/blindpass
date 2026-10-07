// SPDX-License-Identifier: AGPL-3.0-only
// P07-D2: the Arch package template is rendered per release and fails closed unrendered.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const RENDER = path.join(ROOT, 'scripts/release/render-pkgbuild.sh');
const TEMPLATE = path.join(ROOT, 'desktop/packaging/arch/PKGBUILD');
const BUILDER = path.join(ROOT, 'scripts/release/build-desktop-archive.py');
const SHA = 'ab'.repeat(32);

function render(args) {
  const result = spawnSync('bash', [RENDER, ...args], { encoding: 'utf8' });
  return { status: result.status, stdout: result.stdout, out: `${result.stdout}${result.stderr}` };
}

const have = (command) => spawnSync('sh', ['-c', `command -v ${command}`]).status === 0;

test('P07-D2: the template holds placeholders, not a checksum that looks real', async () => {
  const text = await readFile(TEMPLATE, 'utf8');
  assert.match(text, /^pkgver=0\.0\.0$/m);
  assert.match(text, /^sha256sums=\('REPLACED-BY-THE-RELEASE-WORKFLOW'\)$/m);
  assert.ok(!/[0-9a-f]{64}/.test(text), 'template contains a 64-hex string');
  assert.match(text, /^arch=\('x86_64'\)$/m);
  assert.match(text, /^license=\('AGPL-3\.0-only'\)$/m);
  assert.equal(spawnSync('bash', ['-n', TEMPLATE]).status, 0, 'PKGBUILD is not valid bash');
});

test('P07-D2: rendering sets pkgver and the archive hash and nothing else', async () => {
  const result = render([TEMPLATE, '1.2.3', SHA]);
  assert.equal(result.status, 0, result.out);
  assert.match(result.stdout, /^pkgver=1\.2\.3$/m);
  assert.match(result.stdout, new RegExp(`^sha256sums=\\('${SHA}'\\)$`, 'm'));
  assert.ok(!result.stdout.includes('REPLACED-BY-THE-RELEASE-WORKFLOW'));
  const template = (await readFile(TEMPLATE, 'utf8')).split('\n');
  const rendered = result.stdout.split('\n');
  assert.equal(rendered.length, template.length);
  assert.equal(rendered.filter((line, i) => line !== template[i]).length, 2, 'only two lines may change');
});

test('P07-D2: rendering rejects malformed versions and hashes and an already rendered file', async () => {
  for (const version of ['', '1.2', 'v1.2.3', '1.2.3-rc.1', '1.2.3;id', '../1.2.3']) {
    assert.notEqual(render([TEMPLATE, version, SHA]).status, 0, `version ${JSON.stringify(version)}`);
  }
  for (const sha of ['', 'SKIP', 'AB'.repeat(32), 'ab'.repeat(31), '0'.repeat(64), `${SHA};id`]) {
    assert.notEqual(render([TEMPLATE, '1.2.3', sha]).status, 0, `sha ${JSON.stringify(sha)}`);
  }
  const dir = await mkdtemp(path.join(tmpdir(), 'blindpass-pkgbuild-'));
  try {
    const once = path.join(dir, 'PKGBUILD');
    await writeFile(once, render([TEMPLATE, '1.2.3', SHA]).stdout);
    const again = render([once, '1.2.4', 'cd'.repeat(32)]);
    assert.notEqual(again.status, 0);
    assert.match(again.out, /placeholder/);
    assert.notEqual(render([path.join(dir, 'absent'), '1.2.3', SHA]).status, 0);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('P07-D2: makepkg builds the rendered file from the real archive and rejects the unrendered template',
  { skip: !(have('makepkg') && have('fakeroot') && have('bsdtar') && have('zstd')) && 'makepkg, fakeroot, bsdtar or zstd unavailable' },
  async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'blindpass-makepkg-'));
    try {
      const outDir = path.join(dir, 'out');
      const build = spawnSync('python3', [BUILDER, '--output-dir', outDir, '--allow-dirty'], { encoding: 'utf8' });
      assert.equal(build.status, 0, build.stderr);
      const [archiveName] = await readdir(outDir);
      const version = archiveName.match(/^blindpass-approval-app-(\d+\.\d+\.\d+)-linux-x86_64\.tar\.zst$/)[1];
      const archive = path.join(outDir, archiveName);
      const sha = createHash('sha256').update(await readFile(archive)).digest('hex');
      // makepkg cannot reach GitHub here: point the source at the local archive, nothing else changes.
      const local = (text) => text.replace(/https:\/\/github\.com\/[^"]*\.tar\.zst/, `file://${archive}`);

      const work = path.join(dir, 'work');
      spawnSync('mkdir', [work]);
      const env = { PATH: process.env.PATH, HOME: dir, PKGDEST: path.join(dir, 'pkg'), SRCDEST: path.join(dir, 'src'), BUILDDIR: path.join(dir, 'build'), LANG: 'C' };
      for (const sub of ['pkg', 'src', 'build']) spawnSync('mkdir', [path.join(dir, sub)]);

      await writeFile(path.join(work, 'PKGBUILD'), local(await readFile(TEMPLATE, 'utf8')).replace('pkgver=0.0.0', `pkgver=${version}`));
      const unrendered = spawnSync('makepkg', ['--nodeps', '--nocheck', '--skippgpcheck', '-f'], { cwd: work, env, encoding: 'utf8' });
      assert.notEqual(unrendered.status, 0, 'the unrendered template built a package');
      assert.deepEqual(await readdir(path.join(dir, 'pkg')), [], 'a package was produced from the unrendered template');

      await writeFile(path.join(work, 'PKGBUILD'), local(render([TEMPLATE, version, sha]).stdout));
      const rendered = spawnSync('makepkg', ['--nodeps', '--nocheck', '--skippgpcheck', '-f'], { cwd: work, env, encoding: 'utf8' });
      assert.equal(rendered.status, 0, `${rendered.stdout}\n${rendered.stderr}`);
      const [pkg] = await readdir(path.join(dir, 'pkg'));
      const contents = spawnSync('bsdtar', ['-tvf', path.join(dir, 'pkg', pkg)], { encoding: 'utf8' }).stdout;
      for (const expected of ['usr/share/blindpass/approval-app/shell.qml', 'usr/share/blindpass/approval-app/bin/blindpass-approvals',
        'usr/share/blindpass/approval-app/lib/model.js', 'usr/share/licenses/blindpass-approval-app/LICENSE',
        'usr/bin/blindpass-approvals -> /usr/share/blindpass/approval-app/bin/blindpass-approvals']) {
        assert.ok(contents.includes(expected), `package lacks ${expected}`);
      }
      assert.ok(!/e2e\.qml|tests\//.test(contents), 'package carries test files');
    } finally { await rm(dir, { recursive: true, force: true }); }
  });
