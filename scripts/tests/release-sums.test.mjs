// SPDX-License-Identifier: AGPL-3.0-only
// P07-D2: the release inventory lists exactly the intended candidate assets.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { spawnSync } from 'node:child_process';
import { mkdir, mkdtemp, readFile, readdir, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const MAKE_SUMS = path.join(ROOT, 'scripts/release/make-sums.sh');
const VERSION = '0.1.0';

const REQUIRED = [
  `blindpass-controller-${VERSION}-linux-x86_64.tar.zst`,
  `blindpass-node-${VERSION}-linux-x86_64.tar.zst`,
  `blindpass-approval-app-${VERSION}-linux-x86_64.tar.zst`,
  `blindpass-mcp-server-${VERSION}.tgz`,
  `blindpass-controller-image-${VERSION}-linux-amd64.oci.tar`,
  `blindpass-controller-image-${VERSION}-linux-amd64.docker.tar`,
  'controller-image.digest',
  `LICENSES-${VERSION}.md`,
  'PKGBUILD',
  `blindpass-controller-image-${VERSION}.spdx.json`,
  `blindpass-mcp-server-${VERSION}.cdx.json`,
];

function run(args) {
  const result = spawnSync('bash', [MAKE_SUMS, ...args], { encoding: 'utf8', env: { PATH: process.env.PATH } });
  return { status: result.status, out: `${result.stdout}${result.stderr}` };
}

async function candidate(files = REQUIRED) {
  const dir = await mkdtemp(path.join(tmpdir(), 'blindpass-release-sums-'));
  for (const name of files) await writeFile(path.join(dir, name), `content of ${name}\n`);
  return { dir, cleanup: () => rm(dir, { recursive: true, force: true }) };
}

test('P07-D2: SHA256SUMS lists every candidate asset, sorted, in sha256sum format', async () => {
  const c = await candidate();
  try {
    const result = run([c.dir, VERSION]);
    assert.equal(result.status, 0, result.out);
    const lines = (await readFile(path.join(c.dir, 'SHA256SUMS'), 'utf8')).trimEnd().split('\n');
    assert.deepEqual(lines.map((line) => line.slice(66)), [...REQUIRED].sort((a, b) => (a < b ? -1 : 1)));
    for (const line of lines) assert.match(line, /^[0-9a-f]{64} {2}[A-Za-z0-9._-]+$/);
    const check = spawnSync('sha256sum', ['--check', '--strict', 'SHA256SUMS'], { cwd: c.dir, encoding: 'utf8' });
    assert.equal(check.status, 0, check.stderr);
    assert.deepEqual((await readdir(c.dir)).filter((n) => n.startsWith('.')), [], 'temporary file left behind');
  } finally { await c.cleanup(); }
});

test('P07-D2: both architectures are accepted and a lone half of a pair is not', async () => {
  const both = await candidate([...REQUIRED, `blindpass-controller-${VERSION}-linux-aarch64.tar.zst`, `blindpass-node-${VERSION}-linux-aarch64.tar.zst`]);
  const half = await candidate([...REQUIRED, `blindpass-controller-${VERSION}-linux-aarch64.tar.zst`]);
  try {
    assert.equal(run([both.dir, VERSION]).status, 0);
    const result = run([half.dir, VERSION]);
    assert.notEqual(result.status, 0);
    assert.match(result.out, /aarch64/);
  } finally { await both.cleanup(); await half.cleanup(); }
});

test('P07-D2: an unexpected, mis-versioned or non-regular file fails the inventory', async () => {
  for (const [label, mutate] of [
    ['unexpected file', async (dir) => writeFile(path.join(dir, 'notes.txt'), 'x')],
    ['credential-looking file', async (dir) => writeFile(path.join(dir, 'release.key'), 'x')],
    ['other version', async (dir) => writeFile(path.join(dir, 'blindpass-controller-0.2.0-linux-x86_64.tar.zst'), 'x')],
    ['symlink', async (dir) => symlink('/etc/hostname', path.join(dir, 'blindpass-node-extra'))],
    ['subdirectory', async (dir) => mkdir(path.join(dir, 'nested'))],
    ['stale signature', async (dir) => writeFile(path.join(dir, 'SHA256SUMS.sig'), 'x')],
    ['existing inventory', async (dir) => writeFile(path.join(dir, 'SHA256SUMS'), 'x')],
  ]) {
    const c = await candidate();
    try {
      await mutate(c.dir);
      const result = run([c.dir, VERSION]);
      assert.notEqual(result.status, 0, label);
      const sums = await readFile(path.join(c.dir, 'SHA256SUMS'), 'utf8').catch(() => '');
      assert.ok(label === 'existing inventory' ? sums === 'x' : sums === '', `${label}: inventory written or replaced`);
    } finally { await c.cleanup(); }
  }
});

test('P07-D2: every required asset is mandatory, including both SBOMs', async () => {
  for (const missing of REQUIRED) {
    const c = await candidate(REQUIRED.filter((name) => name !== missing));
    try {
      const result = run([c.dir, VERSION]);
      assert.notEqual(result.status, 0, `${missing} absent but inventory written`);
      assert.equal(await readFile(path.join(c.dir, 'SHA256SUMS'), 'utf8').catch(() => ''), '', `${missing}: partial inventory left`);
    } finally { await c.cleanup(); }
  }
});

test('P07-D2: unsafe arguments are rejected', async () => {
  const c = await candidate();
  try {
    for (const version of ['', '../0.1.0', '0.1', '0.1.0/x', 'v0.1.0', '0.1.0;rm']) {
      assert.notEqual(run([c.dir, version]).status, 0, `version ${JSON.stringify(version)}`);
    }
    assert.notEqual(run([path.join(c.dir, 'absent'), VERSION]).status, 0);
    assert.notEqual(run([]).status, 0);
  } finally { await c.cleanup(); }
});
