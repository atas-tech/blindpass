// SPDX-License-Identifier: AGPL-3.0-only
// P07-D3: the npm candidate is an esbuild bundle with no runtime dependencies, so `npm sbom` would describe
// an empty tree. The SBOM is built from the bundle's own licence inventory (dist/licenses/bundle-packages.json,
// written by scripts/bundle-mcp-notices.mjs from the emitted compiler inputs) and checks every listed licence
// file against its recorded hash before it describes anything.
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
const SCRIPT = path.join(ROOT, 'scripts/release/bundle-sbom.mjs');
const sha = (text) => createHash('sha256').update(text).digest('hex');

async function packageFixture({ inventory, manifest = { name: '@blindpass/example', version: '1.2.3', license: 'MIT' }, texts = {}, raw } = {}) {
  const dir = await mkdtemp(path.join(tmpdir(), 'blindpass-sbom-'));
  await mkdir(path.join(dir, 'dist/licenses'), { recursive: true });
  await writeFile(path.join(dir, 'package.json'), JSON.stringify(manifest));
  const defaults = [
    { name: '@hpke/core', version: '1.8.0', license: 'MIT', text: 'hpke licence\n' },
    { name: 'zod', version: '3.25.76', license: 'MIT', text: 'zod 3 licence\n' },
    { name: 'zod', version: '4.6.5', license: 'MIT', text: 'zod 4 licence\n' },
    { name: '@legacy/apache-package', version: '2.8.0', license: 'Apache-2.0', text: 'apache text\n' },
  ];
  const entries = inventory ?? defaults.map(({ name, version, license, text }) => {
    const file = `licenses/npm-${name.replace('@', '').replace('/', '-')}-${version}-LICENSE`;
    texts[file] = text;
    return { name, version, license, files: [{ path: file, sha256: sha(text) }] };
  });
  for (const [file, text] of Object.entries(texts)) await writeFile(path.join(dir, 'dist', file), text);
  await writeFile(path.join(dir, 'dist/licenses/bundle-packages.json'), raw ?? `${JSON.stringify(entries, null, 2)}\n`);
  return { dir, entries, cleanup: () => rm(dir, { recursive: true, force: true }) };
}
const run = (...args) => spawnSync(process.execPath, [SCRIPT, ...args], { encoding: 'utf8' });
async function generate(fixture, out) {
  const result = run('--package', fixture.dir, '--out', out);
  return { ...result, document: result.status === 0 ? JSON.parse(await readFile(out, 'utf8')) : undefined };
}

test('P07-D3: the SBOM is CycloneDX 1.5, deterministic, and describes the bundled components', async () => {
  const fixture = await packageFixture(); const out = path.join(fixture.dir, 'bundle.cdx.json');
  try {
    const { status, stderr, document } = await generate(fixture, out);
    assert.equal(status, 0, stderr);
    assert.equal(document.bomFormat, 'CycloneDX');
    assert.equal(document.specVersion, '1.5');
    assert.equal(document.version, 1);
    // Nothing that changes between two builds of the same commit: no timestamp, serial number or host.
    assert.equal(document.serialNumber, undefined);
    assert.equal(document.metadata.timestamp, undefined);
    assert.deepEqual(JSON.parse(JSON.stringify(document.metadata.component)).purl, 'pkg:npm/%40blindpass/example@1.2.3');
    assert.equal(document.metadata.component.type, 'application');
    assert.deepEqual(document.metadata.component.licenses, [{ license: { id: 'MIT' } }]);
    const purls = document.components.map((c) => c.purl);
    assert.deepEqual(purls, ['pkg:npm/%40hpke/core@1.8.0', 'pkg:npm/%40legacy/apache-package@2.8.0', 'pkg:npm/zod@3.25.76', 'pkg:npm/zod@4.6.5']);
    assert.equal(new Set(document.components.map((c) => c['bom-ref'])).size, document.components.length);
    const core = document.components[0];
    assert.deepEqual([core.type, core.group, core.name, core.version], ['library', '@hpke', 'core', '1.8.0']);
    assert.deepEqual(core.licenses, [{ license: { id: 'MIT' } }]);
    assert.deepEqual(core.properties, [{ name: 'blindpass:license-file', value: `licenses/npm-hpke-core-1.8.0-LICENSE sha256:${sha('hpke licence\n')}` }]);
    assert.deepEqual(document.dependencies, [{ ref: 'pkg:npm/%40blindpass/example@1.2.3', dependsOn: purls }]);
    const second = path.join(fixture.dir, 'second.cdx.json');
    assert.equal(run('--package', fixture.dir, '--out', second).status, 0);
    assert.equal(await readFile(second, 'utf8'), await readFile(out, 'utf8'), 'two runs differ');
  } finally { await fixture.cleanup(); }
});

test('P07-D3: a licence expression is kept as an expression, not forced into a single id', async () => {
  const text = 'dual\n';
  const fixture = await packageFixture({ inventory: [{ name: 'dual', version: '1.0.0', license: 'MIT OR Apache-2.0', files: [{ path: 'licenses/npm-dual-1.0.0-LICENSE', sha256: sha(text) }] }],
    texts: { 'licenses/npm-dual-1.0.0-LICENSE': text } });
  try {
    const { status, stderr, document } = await generate(fixture, path.join(fixture.dir, 'out.json'));
    assert.equal(status, 0, stderr);
    assert.deepEqual(document.components[0].licenses, [{ expression: 'MIT OR Apache-2.0' }]);
  } finally { await fixture.cleanup(); }
});

test('P07-D3: bad input fails closed with no SBOM written', async () => {
  const good = { name: 'a', version: '1.0.0', license: 'MIT', files: [{ path: 'licenses/npm-a-1.0.0-LICENSE', sha256: sha('a\n') }] };
  const texts = { 'licenses/npm-a-1.0.0-LICENSE': 'a\n' };
  const cases = {
    'invalid JSON': { raw: '{not json' },
    'not an array': { raw: '{"name":"a"}' },
    'empty inventory': { inventory: [] },
    'missing name': { inventory: [{ ...good, name: undefined }] },
    'missing version': { inventory: [{ ...good, version: undefined }] },
    'unsafe name': { inventory: [{ ...good, name: '../../etc/passwd' }] },
    'unsafe version (purl injection)': { inventory: [{ ...good, version: '1.0.0?download_url=http://evil' }] },
    'licence outside the approved list': { inventory: [{ ...good, license: 'AGPL-3.0-only' }] },
    'licence is not an SPDX id': { inventory: [{ ...good, license: 'See LICENSE file' }] },
    'no licence files': { inventory: [{ ...good, files: [] }] },
    'licence file missing from the package': { inventory: [{ ...good, files: [{ path: 'licenses/npm-a-1.0.0-GONE', sha256: sha('a\n') }] }] },
    'licence file hash differs': { inventory: [{ ...good, files: [{ path: 'licenses/npm-a-1.0.0-LICENSE', sha256: sha('b\n') }] }] },
    'licence path escapes the package': { inventory: [{ ...good, files: [{ path: '../package.json', sha256: sha('x') }] }] },
    'duplicate name and version': { inventory: [good, good] },
    'bad manifest': { manifest: { name: '@blindpass/example' } },
  };
  for (const [label, options] of Object.entries(cases)) {
    const fixture = await packageFixture({ texts: { ...texts }, ...options });
    const out = path.join(fixture.dir, 'out.json');
    try {
      const result = run('--package', fixture.dir, '--out', out);
      assert.equal(result.status, 1, `${label}: ${result.stdout}${result.stderr}`);
      assert.match(result.stderr, /^bundle SBOM refused:/, label);
      assert.equal(existsSync(out), false, `${label}: a file was written`);
    } finally { await fixture.cleanup(); }
  }
});

test('P07-D3: the command refuses to overwrite and to run without exact arguments', async () => {
  const fixture = await packageFixture(); const out = path.join(fixture.dir, 'bundle.cdx.json');
  try {
    assert.equal(run('--package', fixture.dir, '--out', out).status, 0);
    const before = await readFile(out, 'utf8');
    const again = run('--package', fixture.dir, '--out', out);
    assert.equal(again.status, 1);
    assert.match(again.stderr, /already exists/);
    assert.equal(await readFile(out, 'utf8'), before);
    for (const args of [[], ['--package', fixture.dir], ['--out', out], ['--package', fixture.dir, '--out', out, '--extra'], ['--package', path.join(fixture.dir, 'absent'), '--out', path.join(fixture.dir, 'o2.json')]]) {
      assert.notEqual(run(...args).status, 0, JSON.stringify(args));
    }
  } finally { await fixture.cleanup(); }
});

test('P07-D3: the real bundle inventory yields one component per bundled package, the zod 4 package, and no payment packages', async (t) => {
  const inventory = path.join(ROOT, 'packages/openclaw-plugin/dist/licenses/bundle-packages.json');
  if (!existsSync(inventory)) { t.skip('the bundle is not built in this checkout'); return; }
  const dir = await mkdtemp(path.join(tmpdir(), 'blindpass-sbom-real-'));
  try {
    // The SBOM describes the staged package the release packs, not the plugin directory.
    const stage = await mkdtemp(path.join(tmpdir(), 'blindpass-sbom-stage-'));
    try {
      const staged = spawnSync('bash', [path.join(ROOT, 'scripts/publish_dist.sh'), '--skip-build', '--skip-validate', '--stage-dir', stage], { encoding: 'utf8' });
      assert.equal(staged.status, 0, `${staged.stdout}${staged.stderr}`);
      const generated = run('--package', stage, '--out', path.join(dir, 'real.cdx.json'));
      assert.equal(generated.status, 0, generated.stderr);
      const document = JSON.parse(await readFile(path.join(dir, 'real.cdx.json'), 'utf8'));
      assert.equal(document.components.length, JSON.parse(await readFile(inventory, 'utf8')).length);
      assert.equal(document.metadata.component.purl, `pkg:npm/%40blindpass/mcp-server@${JSON.parse(await readFile(path.join(stage, 'package.json'), 'utf8')).version}`);
      const purls = new Set(document.components.map((c) => c.purl));
      for (const purl of ['pkg:npm/zod@4.6.5', 'pkg:npm/%40hpke/core@1.8.0', 'pkg:npm/%40modelcontextprotocol/server@2.2.0']) assert.ok(purls.has(purl), purl);
      assert.deepEqual([...purls].filter((purl) => /%40x402\/|pkg:npm\/viem@/.test(purl)), [], 'no payment package may be bundled');
      assert.ok(document.components.every((c) => c.licenses?.length === 1 && c.properties?.length >= 1));
    } finally { await rm(stage, { recursive: true, force: true }); }
  } finally { await rm(dir, { recursive: true, force: true }); }
});
