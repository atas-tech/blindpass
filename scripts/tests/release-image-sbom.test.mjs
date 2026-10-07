// SPDX-License-Identifier: AGPL-3.0-only
// P07-D2: the controller image digest and SBOM come from the candidate OCI archive, bound and verified.
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
const EXTRACT = path.join(ROOT, 'scripts/release/extract-image-sbom.py');
const REPOSITORY = 'ghcr.io/atas-tech/blindpass-controller';
const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');

// A minimal OCI layout shaped like buildx output: index -> [image manifest, attestation manifest].
async function archive({ tamperBlob = false, extraTopLevel = false, noAttestation = false, wrongSubject = false } = {}) {
  const dir = await mkdtemp(path.join(tmpdir(), 'blindpass-oci-'));
  const blobs = path.join(dir, 'layout/blobs/sha256');
  await mkdir(blobs, { recursive: true });
  const put = async (value) => {
    const bytes = Buffer.isBuffer(value) ? value : Buffer.from(typeof value === 'string' ? value : JSON.stringify(value));
    const digest = sha(bytes);
    await writeFile(path.join(blobs, digest), bytes);
    return { digest: `sha256:${digest}`, size: bytes.length };
  };
  const layer = await put('layer-bytes');
  const config = await put({ architecture: 'amd64', os: 'linux', rootfs: { type: 'layers', diff_ids: [layer.digest] } });
  const image = await put({ schemaVersion: 2, mediaType: 'application/vnd.oci.image.manifest.v1+json',
    config: { mediaType: 'application/vnd.oci.image.config.v1+json', ...config },
    layers: [{ mediaType: 'application/vnd.oci.image.layer.v1.tar', ...layer }] });
  const statements = [];
  for (const name of ['sbom', 'sbom-ui', 'sbom-binaries']) {
    const statement = await put({ _type: 'https://in-toto.io/Statement/v0.1', predicateType: 'https://spdx.dev/Document',
      subject: [{ name: 'image', digest: { sha256: wrongSubject ? 'f'.repeat(64) : image.digest.slice(7) } }],
      predicate: { spdxVersion: 'SPDX-2.3', name, packages: [{ name: `pkg-${name}`, versionInfo: '1.0.0' }] } });
    statements.push({ mediaType: 'application/vnd.in-toto+json', ...statement, annotations: { 'in-toto.io/predicate-type': 'https://spdx.dev/Document' } });
  }
  const attestation = await put({ schemaVersion: 2, mediaType: 'application/vnd.oci.image.manifest.v1+json',
    config: { mediaType: 'application/vnd.oci.image.config.v1+json', ...(await put({ architecture: 'unknown', os: 'unknown' })) }, layers: statements });
  const entries = [{ mediaType: 'application/vnd.oci.image.manifest.v1+json', ...image, platform: { architecture: 'amd64', os: 'linux' } }];
  if (!noAttestation) {
    entries.push({ mediaType: 'application/vnd.oci.image.manifest.v1+json', ...attestation, platform: { architecture: 'unknown', os: 'unknown' },
      annotations: { 'vnd.docker.reference.type': 'attestation-manifest', 'vnd.docker.reference.digest': image.digest } });
  }
  const index = await put({ schemaVersion: 2, mediaType: 'application/vnd.oci.image.index.v1+json', manifests: entries });
  const top = [{ mediaType: 'application/vnd.oci.image.index.v1+json', ...index }];
  if (extraTopLevel) top.push({ mediaType: 'application/vnd.oci.image.index.v1+json', ...index });
  await writeFile(path.join(dir, 'layout/index.json'), JSON.stringify({ schemaVersion: 2, manifests: top }));
  await writeFile(path.join(dir, 'layout/oci-layout'), JSON.stringify({ imageLayoutVersion: '1.0.0' }));
  if (tamperBlob) await writeFile(path.join(blobs, layer.digest.slice(7)), 'different-layer-bytes');
  const file = path.join(dir, 'image.oci.tar');
  assert.equal(spawnSync('tar', ['-cf', file, '-C', path.join(dir, 'layout'), '.']).status, 0);
  return { dir, file, indexDigest: index.digest, cleanup: () => rm(dir, { recursive: true, force: true }) };
}

function extract(file, dir, extra = []) {
  const result = spawnSync('python3', [EXTRACT, '--archive', file, '--sbom-out', path.join(dir, 'sbom.json'),
    '--digest-out', path.join(dir, 'controller-image.digest'), '--repository', REPOSITORY, ...extra], { encoding: 'utf8' });
  return { status: result.status, out: `${result.stdout}${result.stderr}` };
}

test('P07-D2: the digest file names the verified top-level index digest and the SBOM bundles all three documents', async () => {
  const a = await archive();
  try {
    const run = extract(a.file, a.dir);
    assert.equal(run.status, 0, run.out);
    assert.equal(await readFile(path.join(a.dir, 'controller-image.digest'), 'utf8'), `${REPOSITORY}@${a.indexDigest}\n`);
    const bundle = JSON.parse(await readFile(path.join(a.dir, 'sbom.json'), 'utf8'));
    assert.equal(bundle.format, 'blindpass-oci-spdx-bundle-v1');
    assert.equal(bundle.image_index_digest, a.indexDigest);
    assert.deepEqual(Object.keys(bundle.documents).sort(), ['sbom', 'sbom-binaries', 'sbom-ui']);
    assert.equal(bundle.documents.sbom.spdxVersion, 'SPDX-2.3');
  } finally { await a.cleanup(); }
});

test('P07-D2: a tampered blob, extra top-level entry, missing attestation or wrong subject is refused with nothing written', async () => {
  for (const [label, options] of [['tampered blob', { tamperBlob: true }], ['two top-level entries', { extraTopLevel: true }],
    ['no attestation', { noAttestation: true }], ['attestation for another image', { wrongSubject: true }]]) {
    const a = await archive(options);
    try {
      const run = extract(a.file, a.dir);
      assert.notEqual(run.status, 0, `${label}: ${run.out}`);
      assert.ok(!existsSync(path.join(a.dir, 'sbom.json')) && !existsSync(path.join(a.dir, 'controller-image.digest')), `${label}: output written`);
    } finally { await a.cleanup(); }
  }
});

test('P07-D2: unsafe repository names, missing archives and existing outputs are refused', async () => {
  const a = await archive();
  try {
    for (const repository of ['', 'ghcr.io/Atas-Tech/x', 'ghcr.io/atas-tech/x@sha256:abc', 'ghcr.io/atas-tech/x;id', 'http://ghcr.io/atas-tech/x']) {
      const run = spawnSync('python3', [EXTRACT, '--archive', a.file, '--sbom-out', path.join(a.dir, 's.json'), '--digest-out', path.join(a.dir, 'd'), '--repository', repository], { encoding: 'utf8' });
      assert.notEqual(run.status, 0, `repository ${JSON.stringify(repository)}`);
    }
    assert.notEqual(extract(path.join(a.dir, 'absent.tar'), a.dir).status, 0);
    assert.equal(extract(a.file, a.dir).status, 0);
    const again = extract(a.file, a.dir);
    assert.notEqual(again.status, 0);
    assert.match(again.out, /already exists|refusing/);
  } finally { await a.cleanup(); }
});

// The real candidate archive from the P06 attested build, when this machine still has one.
const REAL = process.env.BLINDPASS_TEST_OCI_ARCHIVE ?? '/tmp/blindpass-p06-controller-sbom-final.tar';
test('P07-D2: the real P06 attested controller archive yields a digest and the three SPDX inventories',
  { skip: !existsSync(REAL) && `no archive at ${REAL} (set BLINDPASS_TEST_OCI_ARCHIVE)` },
  async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'blindpass-oci-real-'));
    try {
      const run = extract(REAL, dir);
      assert.equal(run.status, 0, run.out);
      assert.match(await readFile(path.join(dir, 'controller-image.digest'), 'utf8'), new RegExp(`^${REPOSITORY}@sha256:[0-9a-f]{64}\\n$`));
      const bundle = JSON.parse(await readFile(path.join(dir, 'sbom.json'), 'utf8'));
      assert.deepEqual(Object.keys(bundle.documents).sort(), ['sbom', 'sbom-binaries', 'sbom-ui']);
      assert.ok(bundle.documents.sbom.packages.some((p) => p.name === 'libssl3'));
    } finally { await rm(dir, { recursive: true, force: true }); }
  });
