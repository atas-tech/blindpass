// SPDX-License-Identifier: AGPL-3.0-only
// P07-D2: the desktop approval-app archive carries the shipped QML app and nothing else.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { spawnSync } from 'node:child_process';
import { chmod, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const BUILDER = path.join(ROOT, 'scripts/release/build-desktop-archive.py');
const VERSION = '0.3.7';
const NAME = `blindpass-approval-app-${VERSION}-linux-x86_64`;

function sh(command, args, cwd) {
  const result = spawnSync(command, args, { cwd, encoding: 'utf8' });
  assert.equal(result.status, 0, `${command} ${args.join(' ')}: ${result.stderr}`);
  return result.stdout;
}

// A throwaway git repository shaped like the parts of this one the builder reads.
async function sourceTree() {
  const root = await mkdtemp(path.join(tmpdir(), 'blindpass-desktop-src-'));
  const files = {
    'Cargo.toml': `[workspace.package]\nversion = "${VERSION}"\n`,
    'LICENSES.md': '# Licenses\n',
    'packages/console/LICENSE': 'GNU AFFERO GENERAL PUBLIC LICENSE\nVersion 3\n',
    'desktop/approval-app/shell.qml': '// shell\n',
    'desktop/approval-app/ApprovalApp.qml': '// app\n',
    'desktop/approval-app/README.md': '# app\n',
    'desktop/approval-app/bin/blindpass-approvals': '#!/bin/sh\nexit 0\n',
    'desktop/approval-app/bin/blindpass-session-store': '#!/bin/sh\nexit 0\n',
    'desktop/approval-app/lib/model.js': '// model\n',
    'desktop/approval-app/ui/Button.qml': '// button\n',
    'desktop/approval-app/e2e.qml': '// test-only runner\n',
    'desktop/approval-app/tests/tst_lib.qml': '// test\n',
    'desktop/omarchy-widget/Widget.qml': '// not part of this archive\n',
  };
  for (const [name, content] of Object.entries(files)) {
    await mkdir(path.dirname(path.join(root, name)), { recursive: true });
    await writeFile(path.join(root, name), content);
  }
  await chmod(path.join(root, 'desktop/approval-app/bin/blindpass-approvals'), 0o755);
  await chmod(path.join(root, 'desktop/approval-app/bin/blindpass-session-store'), 0o755);
  sh('git', ['init', '-q'], root);
  sh('git', ['-c', 'user.name=t', '-c', 'user.email=t@example.invalid', 'add', '-A'], root);
  sh('git', ['-c', 'user.name=t', '-c', 'user.email=t@example.invalid', 'commit', '-q', '-m', 'fixture'], root);
  return { root, cleanup: () => rm(root, { recursive: true, force: true }) };
}

function build(source, output, extra = []) {
  const result = spawnSync('python3', [BUILDER, '--source-root', source, '--output-dir', output, ...extra], { encoding: 'utf8' });
  return { status: result.status, out: `${result.stdout}${result.stderr}` };
}

function listing(archive) {
  return sh('tar', ['--zstd', '-tvf', archive], undefined).trim().split('\n');
}

test('P07-D2: the archive is named for the version, holds the app and licenses, and omits tests', async () => {
  const src = await sourceTree();
  const out = await mkdtemp(path.join(tmpdir(), 'blindpass-desktop-out-'));
  try {
    const result = build(src.root, out);
    assert.equal(result.status, 0, result.out);
    const archive = path.join(out, `${NAME}.tar.zst`);
    const lines = listing(archive);
    const names = lines.map((line) => line.split(/\s+/).slice(5).join(' ').replace(/ -> .*/, ''));
    for (const expected of ['shell.qml', 'ApprovalApp.qml', 'README.md', 'bin/blindpass-approvals', 'bin/blindpass-session-store',
      'lib/model.js', 'ui/Button.qml', 'LICENSE', 'LICENSES.md', 'manifest.json']) {
      assert.ok(names.includes(`${NAME}/${expected}`), `missing ${expected}`);
    }
    for (const forbidden of ['e2e.qml', 'tests/', 'Widget.qml', '.git']) {
      assert.ok(!names.some((n) => n.includes(forbidden)), `unexpected ${forbidden}`);
    }
    const mode = (member) => lines.find((line) => line.endsWith(`${NAME}/${member}`)).slice(0, 10);
    assert.equal(mode('bin/blindpass-approvals'), '-rwxr-xr-x');
    assert.equal(mode('shell.qml'), '-rw-r--r--');
    assert.ok(lines.every((line) => /\sroot\/root\s/.test(line)), 'owner is not normalized to root');
    assert.ok(lines.every((line) => !/^l/.test(line)), 'archive holds a symlink');
  } finally { await src.cleanup(); await rm(out, { recursive: true, force: true }); }
});

test('P07-D2: the manifest binds every member hash and the source revision', async () => {
  const src = await sourceTree();
  const out = await mkdtemp(path.join(tmpdir(), 'blindpass-desktop-out-'));
  try {
    assert.equal(build(src.root, out).status, 0);
    const extracted = await mkdtemp(path.join(tmpdir(), 'blindpass-desktop-x-'));
    try {
      sh('tar', ['--zstd', '-xf', path.join(out, `${NAME}.tar.zst`), '-C', extracted]);
      const manifest = JSON.parse(await readFile(path.join(extracted, NAME, 'manifest.json'), 'utf8'));
      assert.equal(manifest.profile, 'desktop-approval-app');
      assert.equal(manifest.version, VERSION);
      assert.equal(manifest.architecture, 'x86_64');
      assert.equal(manifest.architecture_note, 'QML, JavaScript and POSIX shell only; no compiled code');
      assert.equal(manifest.source_commit, sh('git', ['rev-parse', 'HEAD'], src.root).trim());
      assert.equal(manifest.source_dirty, false);
      const members = Object.keys(manifest.members);
      assert.ok(members.includes('shell.qml') && !members.includes('manifest.json'));
      for (const [member, info] of Object.entries(manifest.members)) {
        const bytes = await readFile(path.join(extracted, NAME, member));
        assert.equal(createHash('sha256').update(bytes).digest('hex'), info.sha256, member);
        assert.equal(bytes.length, info.size, member);
      }
    } finally { await rm(extracted, { recursive: true, force: true }); }
  } finally { await src.cleanup(); await rm(out, { recursive: true, force: true }); }
});

test('P07-D2: two builds of the same commit are byte-identical', async () => {
  const src = await sourceTree();
  const a = await mkdtemp(path.join(tmpdir(), 'blindpass-desktop-a-'));
  const b = await mkdtemp(path.join(tmpdir(), 'blindpass-desktop-b-'));
  try {
    assert.equal(build(src.root, a).status, 0);
    assert.equal(build(src.root, b).status, 0);
    const digest = async (dir) => createHash('sha256').update(await readFile(path.join(dir, `${NAME}.tar.zst`))).digest('hex');
    assert.equal(await digest(a), await digest(b));
  } finally { await src.cleanup(); await rm(a, { recursive: true, force: true }); await rm(b, { recursive: true, force: true }); }
});

test('P07-D2: refuses a dirty tree, an existing archive, a symlinked member and an unsafe version', async () => {
  const src = await sourceTree();
  const out = await mkdtemp(path.join(tmpdir(), 'blindpass-desktop-out-'));
  try {
    assert.equal(build(src.root, out).status, 0);
    const again = build(src.root, out);
    assert.notEqual(again.status, 0);
    assert.match(again.out, /already exists/);

    const dirtyOut = await mkdtemp(path.join(tmpdir(), 'blindpass-desktop-out-'));
    await writeFile(path.join(src.root, 'desktop/approval-app/shell.qml'), '// changed\n');
    const dirty = build(src.root, dirtyOut);
    assert.notEqual(dirty.status, 0);
    assert.match(dirty.out, /uncommitted/);
    const allowed = build(src.root, dirtyOut, ['--allow-dirty']);
    assert.equal(allowed.status, 0, allowed.out);
    sh('git', ['checkout', '-q', '--', '.'], src.root);

    const linkOut = await mkdtemp(path.join(tmpdir(), 'blindpass-desktop-out-'));
    await symlink('/etc/hostname', path.join(src.root, 'desktop/approval-app/lib/link.js'));
    sh('git', ['add', '-A'], src.root);
    sh('git', ['-c', 'user.name=t', '-c', 'user.email=t@example.invalid', 'commit', '-q', '-m', 'link'], src.root);
    const linked = build(src.root, linkOut);
    assert.notEqual(linked.status, 0);
    assert.match(linked.out, /symlink|unsafe/);

    await writeFile(path.join(src.root, 'Cargo.toml'), '[workspace.package]\nversion = "../1"\n');
    sh('git', ['-c', 'user.name=t', '-c', 'user.email=t@example.invalid', 'commit', '-q', '-am', 'version'], src.root);
    const badVersion = build(src.root, await mkdtemp(path.join(tmpdir(), 'blindpass-desktop-out-')));
    assert.notEqual(badVersion.status, 0);
    assert.match(badVersion.out, /version/);
    await rm(dirtyOut, { recursive: true, force: true }); await rm(linkOut, { recursive: true, force: true });
  } finally { await src.cleanup(); await rm(out, { recursive: true, force: true }); }
});
