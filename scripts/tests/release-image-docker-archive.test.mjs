// SPDX-License-Identifier: AGPL-3.0-only
// P07 slice 7: a stock Docker (overlay2 store) cannot `docker load` the candidate OCI archive, so the release
// also ships a docker-load-format archive derived from it. The conversion verifies every descriptor, keeps
// the same config and layer bytes and is deterministic.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const CONVERT = path.join(ROOT, 'scripts/release/oci-to-docker-archive.py');
const TAG = 'ghcr.io/atas-tech/blindpass-controller:0.1.0';
const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');

async function archive({ tamperBlob = false, twoImages = false, noImage = false, noAttestation = false } = {}) {
  const dir = await mkdtemp(path.join(tmpdir(), 'blindpass-docker-archive-'));
  const blobs = path.join(dir, 'layout/blobs/sha256');
  await mkdir(blobs, { recursive: true });
  const put = async (value) => {
    const bytes = Buffer.isBuffer(value) ? value : Buffer.from(typeof value === 'string' ? value : JSON.stringify(value));
    const digest = sha(bytes);
    await writeFile(path.join(blobs, digest), bytes);
    return { digest: `sha256:${digest}`, size: bytes.length };
  };
  const layers = [await put('layer-one-bytes'), await put('layer-two-bytes')];
  const config = await put({ architecture: 'amd64', os: 'linux', rootfs: { type: 'layers', diff_ids: layers.map((l) => l.digest) } });
  const image = await put({ schemaVersion: 2, mediaType: 'application/vnd.oci.image.manifest.v1+json',
    config: { mediaType: 'application/vnd.oci.image.config.v1+json', ...config },
    layers: layers.map((l) => ({ mediaType: 'application/vnd.oci.image.layer.v1.tar+gzip', ...l })) });
  const attestation = await put({ schemaVersion: 2, mediaType: 'application/vnd.oci.image.manifest.v1+json',
    config: { mediaType: 'application/vnd.oci.image.config.v1+json', ...(await put({ architecture: 'unknown', os: 'unknown' })) }, layers: [] });
  const entries = [];
  if (!noImage) entries.push({ mediaType: 'application/vnd.oci.image.manifest.v1+json', ...image, platform: { architecture: 'amd64', os: 'linux' } });
  if (twoImages) entries.push({ mediaType: 'application/vnd.oci.image.manifest.v1+json', ...image, platform: { architecture: 'amd64', os: 'linux' } });
  if (!noAttestation) {
    entries.push({ mediaType: 'application/vnd.oci.image.manifest.v1+json', ...attestation, platform: { architecture: 'unknown', os: 'unknown' },
      annotations: { 'vnd.docker.reference.type': 'attestation-manifest', 'vnd.docker.reference.digest': image.digest } });
  }
  const index = await put({ schemaVersion: 2, mediaType: 'application/vnd.oci.image.index.v1+json', manifests: entries });
  await writeFile(path.join(dir, 'layout/index.json'), JSON.stringify({ schemaVersion: 2, manifests: [{ mediaType: 'application/vnd.oci.image.index.v1+json', ...index }] }));
  await writeFile(path.join(dir, 'layout/oci-layout'), JSON.stringify({ imageLayoutVersion: '1.0.0' }));
  if (tamperBlob) await writeFile(path.join(blobs, layers[1].digest.slice(7)), 'different-layer-bytes');
  const file = path.join(dir, 'image.oci.tar');
  assert.equal(spawnSync('tar', ['-cf', file, '-C', path.join(dir, 'layout'), '.']).status, 0);
  return { dir, file, layers, config, image, indexDigest: index.digest, cleanup: () => rm(dir, { recursive: true, force: true }) };
}

function convert(file, out, extra = []) {
  const run = spawnSync('python3', [CONVERT, '--archive', file, '--output', out, '--tag', TAG, ...extra], { encoding: 'utf8' });
  return { status: run.status, out: `${run.stdout}${run.stderr}` };
}

function listTar(file) {
  const run = spawnSync('tar', ['-tf', file], { encoding: 'utf8' });
  assert.equal(run.status, 0, run.stderr);
  return run.stdout.split('\n').filter(Boolean).map((n) => n.replace(/^\.\//, '')).sort();
}

function member(file, name) {
  const run = spawnSync('tar', ['-xOf', file, name], { encoding: null });
  assert.equal(run.status, 0, String(run.stderr));
  return run.stdout;
}

test('P07-slice7: the docker archive names the verified image, keeps the same config and layer bytes and tags it', async () => {
  const a = await archive();
  try {
    const out = path.join(a.dir, 'image.docker.tar');
    const run = convert(a.file, out);
    assert.equal(run.status, 0, run.out);
    const manifest = JSON.parse(member(out, 'manifest.json'));
    assert.equal(manifest.length, 1);
    assert.deepEqual(manifest[0].RepoTags, [TAG]);
    assert.equal(manifest[0].Config, `blobs/sha256/${a.config.digest.slice(7)}`);
    assert.deepEqual(manifest[0].Layers, a.layers.map((l) => `blobs/sha256/${l.digest.slice(7)}`));
    for (const blob of [a.config, ...a.layers]) {
      assert.equal(sha(member(out, `blobs/sha256/${blob.digest.slice(7)}`)), blob.digest.slice(7));
    }
    const names = listTar(out);
    assert.ok(names.includes('manifest.json') && names.includes('index.json') && names.includes('oci-layout'));
    assert.ok(!names.some((n) => n.includes(a.indexDigest.slice(7))), 'the multi-platform index and attestation must not be carried');
    assert.match(run.out, new RegExp(`image_id ${a.config.digest}`), 'the image id a docker load will report is printed');
  } finally { await a.cleanup(); }
});

test('P07-slice7: the conversion is deterministic and never replaces an existing output', async () => {
  const a = await archive();
  try {
    const one = path.join(a.dir, 'one.tar');
    const two = path.join(a.dir, 'two.tar');
    assert.equal(convert(a.file, one).status, 0);
    assert.equal(convert(a.file, two).status, 0);
    assert.equal(sha(await readFile(one)), sha(await readFile(two)));
    const before = sha(await readFile(one));
    const again = convert(a.file, one);
    assert.notEqual(again.status, 0, again.out);
    assert.equal(sha(await readFile(one)), before);
  } finally { await a.cleanup(); }
});

test('P07-slice7: a tampered blob, zero or two linux images or an unsafe tag is refused with nothing written', async () => {
  for (const [label, options] of [['tampered layer', { tamperBlob: true }], ['two linux/amd64 manifests', { twoImages: true }], ['no image manifest', { noImage: true }]]) {
    const a = await archive(options);
    try {
      const out = path.join(a.dir, 'refused.tar');
      const run = convert(a.file, out);
      assert.notEqual(run.status, 0, `${label}: ${run.out}`);
      assert.ok(!existsSync(out), `${label}: output written`);
    } finally { await a.cleanup(); }
  }
  const a = await archive();
  try {
    for (const tag of ['', 'UPPER/case:1', 'ghcr.io/atas-tech/x', 'ghcr.io/atas-tech/x:1;id', 'ghcr.io/atas-tech/x@sha256:abc']) {
      const out = path.join(a.dir, 'bad-tag.tar');
      const run = spawnSync('python3', [CONVERT, '--archive', a.file, '--output', out, '--tag', tag], { encoding: 'utf8' });
      assert.notEqual(run.status, 0, `tag ${JSON.stringify(tag)}`);
      assert.ok(!existsSync(out));
    }
    assert.notEqual(convert(path.join(a.dir, 'absent.tar'), path.join(a.dir, 'x.tar')).status, 0);
  } finally { await a.cleanup(); }
});

// Opt-in: the real candidate archive and a real Docker daemon. Set BLINDPASS_TEST_OCI_ARCHIVE to a release
// candidate `.oci.tar` and BLINDPASS_TEST_DOCKER_LOAD=1; the test loads it under a throwaway tag and removes it.
const realArchive = process.env.BLINDPASS_TEST_OCI_ARCHIVE;
test('P07-slice7: `docker load` accepts the converted real candidate and reports the config digest as the image id',
  { skip: !(process.env.BLINDPASS_TEST_DOCKER_LOAD === '1' && realArchive && existsSync(realArchive)) && 'opt-in: set BLINDPASS_TEST_DOCKER_LOAD=1 and BLINDPASS_TEST_OCI_ARCHIVE' },
  async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'blindpass-docker-load-'));
    const tag = 'blindpass-p07-docker-load-test:converted';
    try {
      const out = path.join(dir, 'image.docker.tar');
      const run = spawnSync('python3', [CONVERT, '--archive', realArchive, '--output', out, '--tag', tag], { encoding: 'utf8' });
      assert.equal(run.status, 0, `${run.stdout}${run.stderr}`);
      const id = /image_id (sha256:[0-9a-f]{64})/.exec(run.stdout)?.[1];
      assert.ok(id, run.stdout);
      const load = spawnSync('docker', ['load', '--input', out], { encoding: 'utf8' });
      assert.equal(load.status, 0, `${load.stdout}${load.stderr}`);
      const inspect = spawnSync('docker', ['image', 'inspect', '--format', '{{.Id}}', tag], { encoding: 'utf8' });
      assert.equal(inspect.stdout.trim(), id);
    } finally {
      spawnSync('docker', ['image', 'rm', tag]);
      await rm(dir, { recursive: true, force: true });
    }
  });
