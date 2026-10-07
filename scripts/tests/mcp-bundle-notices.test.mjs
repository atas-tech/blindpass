// SPDX-License-Identifier: MIT
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { execFileSync, spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateMcpBundleNotices } from '../bundle-mcp-notices.mjs';

async function fixture() {
  const root = await mkdtemp(path.join(tmpdir(), 'blindpass-mcp-notices-'));
  await mkdir(path.join(root, 'node_modules/example'), { recursive: true });
  await writeFile(path.join(root, 'node_modules/example/package.json'), JSON.stringify({ name: 'example', version: '1.0.0', license: 'MIT' }));
  await writeFile(path.join(root, 'node_modules/example/LICENSE'), 'Copyright fixture authors\nMIT permission fixture\n');
  await mkdir(path.join(root, 'packages/mcp-server'), { recursive: true });
  await writeFile(path.join(root, 'packages/mcp-server/THIRD_PARTY_NOTICES.md'), '# Approved upstream notices\n');
  await writeFile(path.join(root, 'meta.json'), JSON.stringify({ outputs: { 'bundle.mjs': { inputs: {
    'node_modules/example/index.mjs': { bytesInOutput: 10 }, 'node_modules/unused/index.mjs': { bytesInOutput: 0 },
  } } } }));
  return { root, metadataFile: path.join(root, 'meta.json'), dist: path.join(root, 'dist') };
}
test('M01 bundle notice inventory preserves emitted upstream texts without machine paths', async () => {
  const options = await fixture();
  try {
    await generateMcpBundleNotices(options);
    const inventory = JSON.parse(await readFile(path.join(options.dist, 'licenses/bundle-packages.json')));
    assert.equal(inventory.length, 1); assert.equal(inventory[0].name, 'example');
    const bytes = await readFile(path.join(options.dist, inventory[0].files[0].path), 'utf8');
    assert.match(bytes, /Copyright fixture authors/);
    assert.match(inventory[0].files[0].sha256, /^[a-f0-9]{64}$/);
    assert.ok(!(await readFile(path.join(options.dist, 'THIRD_PARTY_NOTICES.md'), 'utf8')).includes(options.root));
  } finally { await rm(options.root, { recursive: true, force: true }); }
});
test('M01 bundle rejects missing notices, unapproved license and AGPL workspace implementation', async () => {
  for (const mode of ['missing', 'unapproved', 'agpl']) {
    const options = await fixture();
    try {
      if (mode === 'missing') await rm(path.join(options.root, 'node_modules/example/LICENSE'));
      if (mode === 'unapproved') await writeFile(path.join(options.root, 'node_modules/example/package.json'), JSON.stringify({ name: 'example', version: '1.0.0', license: 'UNLICENSED' }));
      if (mode === 'agpl') {
        await mkdir(path.join(options.root, 'packages/controller'), { recursive: true });
        await writeFile(path.join(options.root, 'packages/controller/package.json'), JSON.stringify({ name: 'controller', license: 'AGPL-3.0-only' }));
        await writeFile(options.metadataFile, JSON.stringify({ outputs: { 'bundle.mjs': { inputs: { 'packages/controller/src/index.mjs': { bytesInOutput: 10 } } } } }));
      }
      await assert.rejects(generateMcpBundleNotices(options), /mcp_bundle_boundary_unavailable/);
    } finally { await rm(options.root, { recursive: true, force: true }); }
  }
});

// The boundary guard is an allowlist: a workspace input may enter the MIT bundle
// only from a package that is explicitly listed AND declares MIT. Everything
// else (other workspaces, helpers, crates, scripts, docs, root files) is refused.
async function withInputs(inputs, setup = async () => {}) {
  const options = await fixture();
  await setup(options.root);
  await writeFile(options.metadataFile, JSON.stringify({ outputs: { 'bundle.mjs': { inputs: Object.fromEntries(
    inputs.map((source) => [source, { bytesInOutput: 10 }])) } } }));
  return options;
}
const workspacePackage = (root, directory, manifest) => mkdir(path.join(root, directory), { recursive: true })
  .then(() => writeFile(path.join(root, directory, 'package.json'), JSON.stringify(manifest)));

test('M01 allowlist accepts only explicitly listed MIT workspace packages', async () => {
  const options = await withInputs(['node_modules/example/index.mjs', 'packages/mcp-server/src/index.mjs', 'packages/openclaw-plugin/mcp-server.mjs',
    'packages/gateway/dist/identity.js', 'packages/agent-skill/dist/index.js'], async (root) => {
    for (const name of ['mcp-server', 'openclaw-plugin', 'gateway', 'agent-skill']) await workspacePackage(root, `packages/${name}`, { name: name === 'mcp-server' ? '@blindpass/mcp-server-lib' : `@blindpass/${name}`, license: 'MIT' });
  });
  try { assert.equal((await generateMcpBundleNotices(options)).length, 1); } finally { await rm(options.root, { recursive: true, force: true }); }
});

test('M01 allowlist rejects an unlisted MIT workspace, relicensed listed packages and non-package workspace paths', async () => {
  const cases = {
    'unlisted MIT workspace package': { inputs: ['packages/console/src/main.ts'], setup: (root) => workspacePackage(root, 'packages/console', { name: '@blindpass/console', license: 'MIT' }) },
    'unlisted AGPL workspace package': { inputs: ['packages/agpl-fixture/src/index.ts'], setup: (root) => workspacePackage(root, 'packages/agpl-fixture', { name: '@blindpass/agpl-fixture', license: 'AGPL-3.0-only' }) },
    'listed package relicensed': { inputs: ['packages/mcp-server/src/index.mjs'], setup: (root) => workspacePackage(root, 'packages/mcp-server', { name: '@blindpass/mcp-server-lib', license: 'AGPL-3.0-only' }) },
    // The published bundle owns the public name; the library directory may no longer claim it.
    'library directory claiming the public bundle name': { inputs: ['packages/mcp-server/src/index.mjs'], setup: (root) => workspacePackage(root, 'packages/mcp-server', { name: '@blindpass/mcp-server', license: 'MIT' }) },
    'listed package without manifest': { inputs: ['packages/gateway/dist/identity.js'], setup: async () => {} },
    'helper workspace': { inputs: ['helpers/login/src/worker.mjs'], setup: (root) => workspacePackage(root, 'helpers/login', { name: '@blindpass/login-helper', license: 'MIT' }) },
    'Rust crate path': { inputs: ['crates/blindpass-core/src/lib.rs'], setup: async () => {} },
    'repository script': { inputs: ['scripts/bundle-mcp-notices.mjs'], setup: async () => {} },
    'test harness': { inputs: ['tests/browser-handoff/stock-mcp-client.mjs'], setup: async () => {} },
    'documentation or asset path': { inputs: ['assets/ui/tokens.css'], setup: async () => {} },
    'root file outside every package': { inputs: ['index.mjs'], setup: async () => {} },
    'workspace package reached through node_modules': { inputs: ['node_modules/@blindpass/console/dist/index.js'],
      setup: async (root) => { await mkdir(path.join(root, 'node_modules/@blindpass/console'), { recursive: true });
        await writeFile(path.join(root, 'node_modules/@blindpass/console/package.json'), JSON.stringify({ name: '@blindpass/console', version: '0.1.0', license: 'MIT' }));
        await writeFile(path.join(root, 'node_modules/@blindpass/console/LICENSE'), 'MIT fixture\n'); } },
    'path escaping the repository root': { inputs: ['../outside/index.mjs'], setup: async () => {} },
  };
  for (const [name, { inputs, setup }] of Object.entries(cases)) {
    const options = await withInputs(inputs, setup);
    try { await assert.rejects(generateMcpBundleNotices(options), /mcp_bundle_boundary_unavailable/, name); }
    finally { await rm(options.root, { recursive: true, force: true }); }
  }
});

test('M01 the real MCP bundle inputs satisfy the allowlist and every emitted package has a license text', async (t) => {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
  const esbuild = path.join(root, 'node_modules/.bin/esbuild');
  if (!existsSync(esbuild)) { t.skip('esbuild is not installed in this checkout'); return; }
  const scratch = await mkdtemp(path.join(tmpdir(), 'blindpass-mcp-real-bundle-'));
  try {
    const metadataFile = path.join(scratch, 'meta.json');
    execFileSync(esbuild, [path.join(root, 'packages/openclaw-plugin/mcp-server.mjs'), '--bundle', '--platform=node', '--format=esm', '--target=node20',
      `--metafile=${metadataFile}`, `--outfile=${path.join(scratch, 'mcp-server.mjs')}`, '--log-level=error'], { cwd: root, stdio: 'ignore' });
    const inventory = await generateMcpBundleNotices({ root, metadataFile, dist: path.join(scratch, 'dist') });
    assert.ok(inventory.length > 0 && inventory.every((entry) => entry.files.length > 0));
    assert.ok(inventory.some((entry) => entry.name === '@modelcontextprotocol/server'));
    assert.ok(!inventory.some((entry) => entry.name.startsWith('@blindpass/')));
  } finally { await rm(scratch, { recursive: true, force: true }); }
});

// The standalone resolver is bundled too (it imports ./encrypted-store.mjs), so its compiler inputs go through
// the same boundary as the MCP entrypoint; a second metadata file may not add AGPL code or an unlisted workspace.
test('M01 several bundle metadata files are checked and their packages merged into one inventory', async () => {
  const options = await fixture();
  try {
    const second = path.join(options.root, 'resolver-meta.json');
    await mkdir(path.join(options.root, 'packages/openclaw-plugin'), { recursive: true });
    await writeFile(path.join(options.root, 'packages/openclaw-plugin/package.json'), JSON.stringify({ name: '@blindpass/openclaw-plugin', license: 'MIT' }));
    await writeFile(second, JSON.stringify({ outputs: { 'resolver.mjs': { inputs: {
      'packages/openclaw-plugin/blindpass-resolver.mjs': { bytesInOutput: 10 }, 'packages/openclaw-plugin/encrypted-store.mjs': { bytesInOutput: 10 },
      'node_modules/example/index.mjs': { bytesInOutput: 4 } } } } }));
    const inventory = await generateMcpBundleNotices({ ...options, metadataFile: [options.metadataFile, second] });
    assert.deepEqual(inventory.map((entry) => entry.name), ['example'], 'a package used by both bundles is listed once');
  } finally { await rm(options.root, { recursive: true, force: true }); }
});

test('M01 a second metadata file with AGPL or unlisted workspace code is refused, and so is an unreadable one', async () => {
  for (const input of ['packages/controller/src/index.mjs', 'packages/console/src/main.ts', 'crates/blindpass-core/src/lib.rs']) {
    const options = await fixture();
    try {
      const second = path.join(options.root, 'resolver-meta.json');
      await workspacePackage(options.root, 'packages/controller', { name: 'controller', license: 'AGPL-3.0-only' });
      await writeFile(second, JSON.stringify({ outputs: { 'resolver.mjs': { inputs: { [input]: { bytesInOutput: 10 } } } } }));
      await assert.rejects(generateMcpBundleNotices({ ...options, metadataFile: [options.metadataFile, second] }), /mcp_bundle_boundary_unavailable/, input);
    } finally { await rm(options.root, { recursive: true, force: true }); }
  }
  const options = await fixture();
  try {
    await assert.rejects(generateMcpBundleNotices({ ...options, metadataFile: [options.metadataFile, path.join(options.root, 'absent.json')] }), /mcp_bundle_boundary_unavailable/);
    await assert.rejects(generateMcpBundleNotices({ ...options, metadataFile: [] }), /mcp_bundle_boundary_unavailable/);
  } finally { await rm(options.root, { recursive: true, force: true }); }
});

test('M01 the command accepts one or more metadata files followed by the dist directory', async () => {
  const options = await fixture();
  const script = path.join(path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..'), 'bundle-mcp-notices.mjs');
  try {
    // The command resolves paths against the real repository root, so a fixture input is refused: this only
    // proves the argument shape is parsed and a bad one fails closed with the fixed message.
    const refused = spawnSync(process.execPath, [script, options.metadataFile, options.dist], { encoding: 'utf8' });
    assert.equal(refused.status, 1);
    assert.equal(refused.stderr.trim(), 'mcp_bundle_boundary_unavailable');
    assert.equal(spawnSync(process.execPath, [script, options.dist], { encoding: 'utf8' }).status, 1);
    assert.equal(spawnSync(process.execPath, [script], { encoding: 'utf8' }).status, 1);
  } finally { await rm(options.root, { recursive: true, force: true }); }
});
