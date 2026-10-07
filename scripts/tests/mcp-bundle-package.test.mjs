// SPDX-License-Identifier: AGPL-3.0-only
// P07-D3 (revised by the owner 2026-10-06): the public npm package @blindpass/mcp-server is the staged
// OpenClaw/MCP esbuild bundle (it has a bin, so `npx` works); the workspace library behind it is the
// private, unpublished @blindpass/mcp-server-lib.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { spawnSync } from 'node:child_process';
import { chmod, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const LIB_DIR = path.join(ROOT, 'packages/mcp-server');
const PLUGIN_DIR = path.join(ROOT, 'packages/openclaw-plugin');
const CHECK = path.join(ROOT, 'scripts/release/check-npm-pack.mjs');
const CONTEXT = path.join(ROOT, 'scripts/release/check-publish-context.mjs');
const VERIFY = path.join(ROOT, 'scripts/release/verify-npm-candidate.mjs');
const PUBLISH_DIST = path.join(ROOT, 'scripts/publish_dist.sh');
const BUILD_BUNDLE = path.join(ROOT, 'scripts/build_bundle.sh');

const rootManifest = JSON.parse(await readFile(path.join(ROOT, 'package.json'), 'utf8'));
const libManifest = JSON.parse(await readFile(path.join(LIB_DIR, 'package.json'), 'utf8'));
const APPROVED = { GITHUB_ACTIONS: 'true', GITHUB_WORKFLOW: 'Release', GITHUB_REPOSITORY: 'atas-tech/blindpass',
  GITHUB_REF: 'refs/tags/v0.1.0', BLINDPASS_RELEASE_APPROVED: '1' };

function run(command, args, options = {}) {
  const result = spawnSync(command, args, { encoding: 'utf8', cwd: options.cwd ?? ROOT, env: { PATH: process.env.PATH, ...options.env }, timeout: options.timeout ?? 120_000 });
  return { status: result.status, out: `${result.stdout}${result.stderr}`, stdout: result.stdout, stderr: result.stderr };
}
const check = (args, cwd = ROOT) => run(process.execPath, [CHECK, ...args], { cwd });

// The staged bundle needs the built dist. Build it the way the other packaging tests do when it is missing.
async function ensureDist() {
  if (existsSync(path.join(PLUGIN_DIR, 'dist/mcp-server.mjs'))) return;
  const build = run('bash', [BUILD_BUNDLE], { timeout: 600_000 });
  assert.equal(build.status, 0, build.out);
}

async function stage() {
  await ensureDist();
  const dir = await mkdtemp(path.join(tmpdir(), 'blindpass-stage-bundle-'));
  const staged = run('bash', [PUBLISH_DIST, '--skip-build', '--skip-validate', '--stage-dir', dir]);
  assert.equal(staged.status, 0, staged.out);
  return { dir, manifest: JSON.parse(await readFile(path.join(dir, 'package.json'), 'utf8')), cleanup: () => rm(dir, { recursive: true, force: true }) };
}

// ---- the workspace library is private and renamed ----------------------------------------------------------

test('P07-D3: the workspace library is @blindpass/mcp-server-lib, private, with no publication surface', () => {
  assert.equal(libManifest.name, '@blindpass/mcp-server-lib');
  assert.equal(libManifest.private, true);
  for (const key of ['publishConfig', 'files', 'bin', 'bugs', 'homepage', 'repository']) assert.equal(libManifest[key], undefined, `library still declares ${key}`);
  for (const script of ['prepack', 'prepublishOnly', 'publish']) assert.equal(libManifest.scripts?.[script], undefined, `library still has a ${script} script`);
  assert.equal(libManifest.scripts.build, 'node --check src/index.mjs');
  assert.equal(libManifest.scripts.test, 'node --test tests/*.test.mjs');
  assert.equal(libManifest.engines.node, '^24.21.0 || ^26.10.0');
  assert.equal(libManifest.engines.node, rootManifest.engines.node);
  assert.deepEqual(libManifest.dependencies, { '@modelcontextprotocol/server': '2.2.0', zod: '4.6.5' });
});

test('P07-D3: no workspace package other than the staged bundle uses the public name', async () => {
  for (const group of ['packages', 'helpers']) {
    for (const entry of await readdir(path.join(ROOT, group), { withFileTypes: true })) {
      if (!entry.isDirectory()) continue;
      const file = path.join(ROOT, group, entry.name, 'package.json');
      if (!existsSync(file)) continue;
      assert.notEqual(JSON.parse(await readFile(file, 'utf8')).name, '@blindpass/mcp-server', `${group}/${entry.name} still claims the public package name`);
    }
  }
  const text = await readFile(path.join(ROOT, 'packages/mcp-server/README.md'), 'utf8');
  assert.ok(!/--workspace=@blindpass\/mcp-server(?!-lib)/.test(text), 'README still tells readers to run the old workspace name');
});

test('P07-D3: the lockfile carries the rename and nothing else about this package', async () => {
  const lock = JSON.parse(await readFile(path.join(ROOT, 'package-lock.json'), 'utf8')).packages;
  assert.equal(lock['packages/mcp-server'].name, '@blindpass/mcp-server-lib');
  assert.deepEqual(lock['node_modules/@blindpass/mcp-server-lib'], { resolved: 'packages/mcp-server', link: true });
  assert.equal(lock['node_modules/@blindpass/mcp-server'], undefined);
  assert.deepEqual(lock['packages/mcp-server'].dependencies, libManifest.dependencies);
});

// ---- the staged bundle is the public package --------------------------------------------------------------

test('P07-D3: release versions agree across workspace, skill, plugin manifest and package', async () => {
  const cargo = (await readFile(path.join(ROOT, 'Cargo.toml'), 'utf8')).match(/^\[workspace\.package\][^[]*?^version = "([^"]+)"/ms)[1];
  const skill = (await readFile(path.join(PLUGIN_DIR, 'skills/blindpass/SKILL.md'), 'utf8')).match(/^version:\s*"?([^"\n]+)"?\s*$/m)[1];
  const plugin = JSON.parse(await readFile(path.join(PLUGIN_DIR, 'openclaw.plugin.json'), 'utf8')).version;
  const pluginPackage = JSON.parse(await readFile(path.join(PLUGIN_DIR, 'package.json'), 'utf8')).version;
  assert.deepEqual([skill, plugin, pluginPackage], [cargo, cargo, cargo]);
  assert.equal(libManifest.version, cargo);
});

test('P07-D3: the staged package.json is a deliberate public bundle package', async () => {
  const s = await stage();
  try {
    const m = s.manifest;
    assert.equal(m.name, '@blindpass/mcp-server');
    assert.notEqual(m.private, true);
    assert.equal(m.license, 'MIT');
    assert.equal(m.type, 'module');
    // `npx @blindpass/mcp-server` runs the bin named like the unscoped package when the bins differ.
    assert.deepEqual(m.bin, { 'mcp-server': './dist/mcp-server.mjs', 'blindpass-mcp-server': './dist/mcp-server.mjs', 'blindpass-resolver': './dist/blindpass-resolver.mjs' });
    // Contributor instructions (AGENTS.md) and client config examples that default to an unverified endpoint stay out.
    assert.deepEqual(m.files, ['dist', 'SKILL.md', 'openclaw.plugin.json', 'scripts', 'LICENSE', 'README.md']);
    assert.deepEqual(m.publishConfig, { access: 'public', provenance: true });
    assert.equal(m.repository?.url, 'git+https://github.com/atas-tech/blindpass.git');
    assert.equal(m.bugs?.url, 'https://github.com/atas-tech/blindpass/issues');
    assert.equal(m.homepage, 'https://github.com/atas-tech/blindpass#readme');
    assert.equal(m.engines?.node, '^24.21.0 || ^26.10.0');
    assert.equal(m.dependencies, undefined, 'the bundle is self-contained: no runtime dependencies');
    assert.equal(m.scripts.prepack, 'node .release/check-npm-pack.mjs --self-contained --quiet');
    assert.equal(m.scripts.prepublishOnly, 'node .release/check-publish-context.mjs');
    // The guards the scripts name travel with the stage, byte for byte, but are not part of the package.
    for (const name of ['check-npm-pack.mjs', 'check-publish-context.mjs']) {
      assert.equal(await readFile(path.join(s.dir, '.release', name), 'utf8'), await readFile(path.join(ROOT, 'scripts/release', name), 'utf8'));
    }
    const dry = JSON.parse(run('npm', ['pack', '--json', '--dry-run', '--ignore-scripts'], { cwd: s.dir }).stdout)[0].files.map((f) => f.path);
    assert.ok(!dry.some((p) => p.startsWith('.release/') || p === 'AGENTS.md' || p.startsWith('agents/')), 'a guard or contributor file is packed');
    assert.ok(dry.includes('dist/mcp-server.mjs') && dry.includes('dist/blindpass-resolver.mjs') && dry.includes('LICENSE'));
  } finally { await s.cleanup(); }
});

test('P07 F-3: the staged package names no default SPS endpoint, and a dist that still does is never staged', async () => {
  const s = await stage();
  try {
    const manifest = JSON.parse(await readFile(path.join(s.dir, 'openclaw.plugin.json'), 'utf8'));
    assert.equal(Object.hasOwn(manifest.configSchema.properties.SPS_BASE_URL, 'default'), false, 'the staged manifest declares a default endpoint');
    for (const file of ['openclaw.plugin.json', 'dist/blindpass.mjs', 'dist/mcp-server.mjs', 'dist/index.mjs', 'dist/openclaw.plugin.json']) {
      assert.ok(!(await readFile(path.join(s.dir, file), 'utf8')).includes('sps.blindpass.dev'), `${file} names the legacy SPS host`);
    }
  } finally { await s.cleanup(); }
  // A dist built before F-3 carries the default: staging refuses it instead of shipping it.
  const stale = await mkdtemp(path.join(tmpdir(), 'blindpass-stale-dist-'));
  try {
    const out = path.join(stale, 'dist');
    const built = run('bash', [BUILD_BUNDLE], { env: { BLINDPASS_BUNDLE_OUT: out }, timeout: 600_000 });
    assert.equal(built.status, 0, built.out);
    const seeded = path.join(out, 'mcp-server.mjs');
    await writeFile(seeded, `${await readFile(seeded, 'utf8')}\n// "https://sps.blindpass.dev"\n`);
    const refused = run('bash', [PUBLISH_DIST, '--skip-build', '--skip-validate', '--stage-dir', path.join(stale, 'stage')], { env: { BLINDPASS_BUNDLE_OUT: out } });
    assert.notEqual(refused.status, 0, 'a dist with the default endpoint was staged');
    assert.match(refused.out, /default SPS endpoint/);
  } finally { await rm(stale, { recursive: true, force: true }); }
});

test('P07-D3: every licence file in the staged bundle is listed by its notices, and every listed file exists', async () => {
  const s = await stage();
  try {
    const dist = path.join(s.dir, 'dist');
    const notices = await readFile(path.join(dist, 'THIRD_PARTY_NOTICES.md'), 'utf8');
    const inventory = JSON.parse(await readFile(path.join(dist, 'licenses/bundle-packages.json'), 'utf8'));
    const listed = new Set([...notices.matchAll(/\]\((licenses\/[^)\s]+)\)/g)].map((m) => m[1]));
    for (const pkg of inventory) for (const file of pkg.files) listed.add(file.path);
    for (const file of await readdir(path.join(dist, 'licenses'))) {
      if (file === 'bundle-packages.json') continue;
      assert.ok(listed.has(`licenses/${file}`), `licenses/${file} ships but no notice lists it`);
    }
    for (const rel of listed) assert.ok(existsSync(path.join(dist, rel)), `${rel} is listed but missing`);
    assert.ok(!listed.has('licenses/x402-Apache-LICENSE'), 'the x402 licence text ships only with bundled x402 packages, which were removed');
    assert.deepEqual(inventory.filter((p) => /^@x402\/|^viem$|^@noble\/|^abitype$|^ox$/.test(p.name)), [], 'no payment or wallet package may be bundled');
    assert.match(await readFile(path.join(s.dir, 'LICENSE'), 'utf8'), /^MIT License/);
  } finally { await s.cleanup(); }
});

test('P07-D3: the prepack guard runs under npm pack and keeps stdout clean for `npm pack --json`', async () => {
  const s = await stage();
  try {
    assert.match(s.manifest.scripts.prepack, / --quiet$/);
    const pack = run('npm', ['pack', '--json', '--dry-run'], { cwd: s.dir });
    assert.equal(pack.status, 0, pack.out);
    const listing = JSON.parse(pack.stdout); // throws if the guard wrote anything else to stdout
    assert.equal(listing[0].name, '@blindpass/mcp-server');
    assert.match(pack.stderr, /pack check OK: @blindpass\/mcp-server@/, 'the guard did not run');
    // The guard really is the prepack hook: a stage that fails the check cannot be packed.
    await writeFile(path.join(s.dir, 'dist/mcp-server.mjs'), '#!/usr/bin/env node\nimport"left-pad";\n');
    const refused = run('npm', ['pack', '--json', '--dry-run'], { cwd: s.dir });
    assert.notEqual(refused.status, 0, refused.out);
    assert.match(refused.out, /undeclared dependency left-pad/);
  } finally { await s.cleanup(); }
});

test('P07-D3: both declared bins run from the stage with no node_modules', async () => {
  const s = await stage();
  try {
    const resolver = run(process.execPath, [path.join(s.dir, 'dist/blindpass-resolver.mjs'), '--help'], { cwd: s.dir });
    assert.equal(resolver.status, 0, resolver.out);
    assert.doesNotMatch(resolver.out, /ERR_MODULE_NOT_FOUND|Cannot find module/);
    assert.match(resolver.stderr, /Usage: blindpass-resolver/);
    for (const bin of ['mcp-server.mjs', 'blindpass-resolver.mjs']) {
      assert.equal((await readFile(path.join(s.dir, 'dist', bin), 'utf8')).split('\n')[0], '#!/usr/bin/env node', `${bin} lacks a node shebang`);
    }
  } finally { await s.cleanup(); }
});

test('P07-D3: a fresh build_bundle.sh run writes bins that start on their own, with the resolver bundled', async () => {
  const parent = await mkdtemp(path.join(tmpdir(), 'blindpass-fresh-build-'));
  const out = path.join(parent, 'dist');
  try {
    const build = run('bash', [BUILD_BUNDLE], { env: { BLINDPASS_BUNDLE_OUT: out }, timeout: 600_000 });
    assert.equal(build.status, 0, build.out);
    const resolver = await readFile(path.join(out, 'blindpass-resolver.mjs'), 'utf8');
    assert.equal(resolver.split('\n')[0], '#!/usr/bin/env node');
    assert.ok(!/from\s*["']\.\.?\//.test(resolver), 'the resolver still imports a sibling file');
    // Run from a directory that has none of the plugin sources next to it.
    const help = run(process.execPath, [path.join(out, 'blindpass-resolver.mjs'), '--help'], { cwd: parent });
    assert.equal(help.status, 0, help.out);
    assert.match(help.stderr, /Usage: blindpass-resolver/);
    const inventory = JSON.parse(await readFile(path.join(out, 'licenses/bundle-packages.json'), 'utf8'));
    const bundled = new Set(inventory.map((entry) => entry.name));
    for (const name of ['@modelcontextprotocol/server', '@hpke/core', 'hpke-js', 'jose', 'zod']) assert.ok(bundled.has(name), `${name} must be bundled`);
    assert.ok(inventory.length >= 10 && inventory.every((entry) => entry.files.length > 0));
    // A non-empty output directory is never overwritten or deleted.
    const again = run('bash', [BUILD_BUNDLE], { env: { BLINDPASS_BUNDLE_OUT: out } });
    assert.notEqual(again.status, 0);
    assert.match(again.out, /not empty/);
    assert.ok(existsSync(path.join(out, 'blindpass-resolver.mjs')));
  } finally { await rm(parent, { recursive: true, force: true }); }
});

test('P07-D3: the staged package passes the pack check, as a directory and as the packed tarball', async () => {
  const s = await stage();
  try {
    const dir = check(['--dir', s.dir, '--self-contained']);
    assert.equal(dir.status, 0, dir.out);
    assert.match(dir.out, /pack check OK: @blindpass\/mcp-server@/);
    assert.ok(!/AGENTS\.md|agents\/|\.release\//.test(dir.out), 'excluded files appear in the packed set');
    const out = await mkdtemp(path.join(tmpdir(), 'blindpass-bundle-tgz-'));
    try {
      const pack = run('npm', ['pack', '--silent', '--pack-destination', out], { cwd: s.dir });
      assert.equal(pack.status, 0, pack.out); // the prepack guard ran here
      const tarball = path.join(out, (await readdir(out)).find((n) => n.endsWith('.tgz')));
      const tar = check(['--tarball', tarball, '--self-contained']);
      assert.equal(tar.status, 0, tar.out);
    } finally { await rm(out, { recursive: true, force: true }); }
  } finally { await s.cleanup(); }
});

// ---- checker rules, on fixtures ---------------------------------------------------------------------------

const goodLibrary = {
  name: '@blindpass/example', version: '1.0.0', type: 'module', license: 'MIT', main: 'src/index.mjs',
  files: ['src/', 'LICENSE'], engines: { node: '^24.21.0 || ^26.10.0' },
  publishConfig: { access: 'public', provenance: true }, dependencies: { zod: '4.6.5' },
};

async function fixture(overrides = {}, files = {}, base = {
  'src/index.mjs': "import { z } from 'zod';\nimport { helper } from './helper.mjs';\nexport const x = [z, helper];\n",
  'src/helper.mjs': "import { readFile } from 'node:fs/promises';\nexport const helper = readFile;\n", LICENSE: 'MIT\n',
}, manifest = goodLibrary) {
  const dir = await mkdtemp(path.join(tmpdir(), 'blindpass-pack-'));
  for (const [name, content] of Object.entries({ ...base, ...files })) {
    if (content === null) continue;
    await mkdir(path.dirname(path.join(dir, name)), { recursive: true });
    await writeFile(path.join(dir, name), content);
  }
  const merged = { ...manifest, ...overrides };
  for (const key of Object.keys(merged)) if (merged[key] === undefined) delete merged[key];
  await writeFile(path.join(dir, 'package.json'), JSON.stringify(merged));
  return { dir, cleanup: () => rm(dir, { recursive: true, force: true }) };
}

const goodBundle = {
  name: '@blindpass/bundle', version: '1.0.0', type: 'module', license: 'MIT', bin: { tool: './dist/tool.mjs' },
  files: ['dist', 'LICENSE'], engines: { node: '^24.21.0 || ^26.10.0' }, publishConfig: { access: 'public', provenance: true },
};
const bundleFiles = { 'dist/tool.mjs': '#!/usr/bin/env node\nimport{readFile as a}from"node:fs/promises";export{a};\n', LICENSE: 'MIT\n', 'src/index.mjs': null, 'src/helper.mjs': null };

test('P07-D3: a bin-only self-contained bundle passes; a plain library fixture still passes', async () => {
  const bundle = await fixture({}, bundleFiles, {}, goodBundle);
  const library = await fixture();
  try {
    const b = check(['--dir', bundle.dir, '--self-contained']); assert.equal(b.status, 0, b.out);
    // --quiet is the prepack form: one summary line on stderr, nothing on stdout.
    const quiet = check(['--dir', bundle.dir, '--self-contained', '--quiet']);
    assert.equal(quiet.status, 0, quiet.out); assert.equal(quiet.stdout, ''); assert.match(quiet.stderr, /^pack check OK: @blindpass\/bundle@1\.0\.0, \d+ file\(s\)\n$/);
    const l = check(['--dir', library.dir]); assert.equal(l.status, 0, l.out);
  } finally { await bundle.cleanup(); await library.cleanup(); }
});

test('P07-D3: bundle problems fail the pack check', async () => {
  for (const [label, overrides, files, args, expected] of [
    ['no entrypoint', { bin: undefined }, {}, [], /no entrypoint/],
    ['bin without a shebang', {}, { 'dist/tool.mjs': 'export const x = 1;\n' }, [], /shebang/],
    ['bin with a non-node shebang', {}, { 'dist/tool.mjs': '#!/bin/sh\nexit 0\n' }, [], /shebang/],
    ['bin target not packed', { bin: { tool: './dist/absent.mjs' } }, {}, [], /bin tool .* not in the packed set/],
    ['several different bins, none npx can choose', { bin: { tool: './dist/tool.mjs', other: './dist/other.mjs' } }, { 'dist/other.mjs': '#!/usr/bin/env node\nexport {};\n' }, [], /npx .* cannot determine the default executable/],
    ['self-contained bundle without any bin', { bin: undefined, main: 'dist/tool.mjs' }, {}, ['--self-contained'], /at least one bin/],
    ['dependency in a self-contained bundle', { dependencies: { zod: '4.6.5' } }, {}, ['--self-contained'], /self-contained/],
    ['peer dependency in a self-contained bundle', { peerDependencies: { zod: '4.6.5' } }, {}, ['--self-contained'], /self-contained/],
    ['bare import in a bundle', {}, { 'dist/tool.mjs': '#!/usr/bin/env node\nimport z from"zod";export{z};\n' }, ['--self-contained'], /undeclared dependency zod/],
    ['relative import of an unshipped file (the resolver defect)', {}, { 'dist/tool.mjs': '#!/usr/bin/env node\nimport { readManagedSecretStore } from "./encrypted-store.mjs";\nexport { readManagedSecretStore };\n' }, ['--self-contained'], /\.\/encrypted-store\.mjs is not in the packed set/],
    ['real require of an undeclared package in minified code', {}, { 'dist/tool.mjs': '#!/usr/bin/env node\nvar a=1;const b=require("left-pad");export{a,b};\n' }, ['--self-contained'], /undeclared dependency left-pad/],
    ['require of a variable', {}, { 'dist/tool.mjs': '#!/usr/bin/env node\nvar n="left-pad";const b=require(n);export{b};\n' }, ['--self-contained'], /non-literal/],
    ['require of a computed string that starts like a literal', {}, { 'dist/tool.mjs': '#!/usr/bin/env node\nvar n="pad";const b=require("left-"+n);export{b};\n' }, ['--self-contained'], /non-literal/],
    ['real dynamic import of an undeclared package', {}, { 'dist/tool.mjs': '#!/usr/bin/env node\nexport const f=()=>import("left-pad");\n' }, ['--self-contained'], /undeclared dependency left-pad/],
  ]) {
    const f = await fixture(overrides, { ...bundleFiles, ...files }, {}, goodBundle);
    try {
      const r = check(['--dir', f.dir, ...args]);
      assert.equal(r.status, 1, `${label}: ${r.out}`);
      assert.match(r.out, expected, label);
    } finally { await f.cleanup(); }
  }
});

test('P07-D3: several bins are fine when one is named like the package, or when they share a target', async () => {
  const named = await fixture({ bin: { bundle: './dist/tool.mjs', other: './dist/other.mjs' } }, { ...bundleFiles, 'dist/other.mjs': '#!/usr/bin/env node\nexport {};\n' }, {}, goodBundle);
  const alias = await fixture({ bin: { one: './dist/tool.mjs', two: './dist/tool.mjs' } }, bundleFiles, {}, goodBundle);
  try {
    assert.equal(check(['--dir', named.dir, '--self-contained']).status, 0);
    assert.equal(check(['--dir', alias.dir, '--self-contained']).status, 0);
  } finally { await named.cleanup(); await alias.cleanup(); }
});

test('P07-D3: require() text inside a string literal is not an import, a long minified line is not comment-stripped', async () => {
  const text = '#!/usr/bin/env node\nvar t={};t.code=\'require("ajv/dist/runtime/equal").default\';var u=`require("ajv-formats/dist/formats").${1}`;export{t,u};\n'
    + `var s="http://x";${'a=1;'.repeat(2000)}var k=1;/* ${'x'.repeat(10)} */ var q=2;//\nexport{s,k,q};import p from"left-pad";export{p};\n`;
  const f = await fixture({}, { ...bundleFiles, 'dist/tool.mjs': text }, {}, goodBundle);
  try {
    const r = check(['--dir', f.dir, '--self-contained']);
    assert.equal(r.status, 1, r.out);
    assert.match(r.out, /undeclared dependency left-pad/, 'the real import after a long line must still be found');
    assert.ok(!/ajv/.test(r.out), 'a string literal was treated as an import');
  } finally { await f.cleanup(); }
});

test('P07-D3: library-style checks still hold (workspace and undeclared imports, manifest mistakes)', async () => {
  for (const [label, overrides, files, expected] of [
    ['undeclared bare package', {}, { 'src/helper.mjs': "import x from '@blindpass/sdk';\nexport const helper = x;\n" }, /undeclared dependency @blindpass\/sdk/],
    ['relative import leaving the package', {}, { 'src/helper.mjs': "import x from '../../openclaw-plugin/x.mjs';\nexport const helper = x;\n" }, /outside the package/],
    ['non-literal dynamic import', {}, { 'src/helper.mjs': 'export const helper = (n) => import(n);\n' }, /non-literal/],
    ['private', { private: true }, {}, /private/],
    ['no files allowlist', { files: undefined }, {}, /files allowlist/],
    ['range dependency spec', { dependencies: { zod: '^4.6.5' } }, {}, /exact/],
    ['workspace package dependency', { dependencies: { zod: '4.6.5', '@blindpass/sdk': '1.0.0' } }, {}, /workspace package/],
    ['no provenance', { publishConfig: { access: 'public' } }, {}, /provenance/],
    ['key file in an allowlisted directory', {}, { 'src/id_rsa': 'KEY' }, /credential-looking/],
  ]) {
    const f = await fixture(overrides, files);
    try {
      const r = check(['--dir', f.dir]);
      assert.equal(r.status, 1, `${label}: ${r.out}`);
      assert.match(r.out, expected, label);
    } finally { await f.cleanup(); }
  }
});

test('P07-D3: tarball mode rejects a member outside the allowlist and a missing tarball', async () => {
  const bad = await mkdtemp(path.join(tmpdir(), 'blindpass-pack-bad-'));
  try {
    await mkdir(path.join(bad, 'package/dist'), { recursive: true });
    await mkdir(path.join(bad, 'package/tests'), { recursive: true });
    await writeFile(path.join(bad, 'package/package.json'), JSON.stringify(goodBundle));
    await writeFile(path.join(bad, 'package/dist/tool.mjs'), bundleFiles['dist/tool.mjs']);
    await writeFile(path.join(bad, 'package/LICENSE'), 'MIT\n');
    await writeFile(path.join(bad, 'package/tests/leak.test.mjs'), 'export {};\n');
    const out = path.join(bad, 'bad.tgz');
    assert.equal(spawnSync('tar', ['-czf', out, '-C', bad, 'package']).status, 0);
    const r = check(['--tarball', out, '--self-contained']);
    assert.equal(r.status, 1, r.out);
    assert.match(r.out, /not in the files allowlist: tests\/leak\.test\.mjs/);
    assert.equal(check(['--tarball', path.join(bad, 'absent.tgz'), '--self-contained']).status, 1);
  } finally { await rm(bad, { recursive: true, force: true }); }
});

// ---- publication guards ------------------------------------------------------------------------------------

test('P07-D3: prepublishOnly context guard refuses outside the approved workflow', () => {
  const guard = (env) => run(process.execPath, [CONTEXT], { env });
  assert.equal(guard({}).status, 1);
  assert.match(guard({}).stderr, /refus/);
  assert.equal(guard(APPROVED).status, 0, guard(APPROVED).stderr);
  for (const [label, change] of [['not CI', { GITHUB_ACTIONS: undefined }], ['other workflow', { GITHUB_WORKFLOW: 'CI' }],
    ['other repository', { GITHUB_REPOSITORY: 'someone/fork' }], ['branch ref', { GITHUB_REF: 'refs/heads/main' }],
    ['no approval marker', { BLINDPASS_RELEASE_APPROVED: undefined }], ['marker not 1', { BLINDPASS_RELEASE_APPROVED: 'true' }]]) {
    const env = { ...APPROVED, ...change };
    for (const key of Object.keys(env)) if (env[key] === undefined) delete env[key];
    assert.equal(guard(env).status, 1, label);
  }
});

// A fake npm records every call so no test can publish anything.
async function fakeNpm() {
  const dir = await mkdtemp(path.join(tmpdir(), 'blindpass-fake-npm-'));
  const log = path.join(dir, 'calls.log');
  await writeFile(path.join(dir, 'npm'), `#!/bin/sh\necho "$@" >> "${log}"\nexit 0\n`);
  await chmod(path.join(dir, 'npm'), 0o755);
  return { dir, log, cleanup: () => rm(dir, { recursive: true, force: true }) };
}
const calls = async (npm) => (existsSync(npm.log) ? (await readFile(npm.log, 'utf8')).trim() : '');

test('P07-D3: publish_dist.sh --publish-npm refuses outside the approved workflow and never calls npm', async () => {
  await ensureDist();
  const npm = await fakeNpm();
  const stageDir = await mkdtemp(path.join(tmpdir(), 'blindpass-publish-refused-'));
  try {
    const path_ = `${npm.dir}:${process.env.PATH}`;
    const refused = run('bash', [PUBLISH_DIST, '--publish-npm', '--skip-build', '--skip-validate', '--stage-dir', stageDir], { env: { PATH: path_ } });
    assert.notEqual(refused.status, 0, refused.out);
    assert.match(refused.out, /refus/);
    assert.equal(await calls(npm), '', 'npm was invoked');
    assert.deepEqual(await readdir(stageDir), [], 'work started before the refusal');
    // Each missing or wrong marker refuses on its own.
    for (const [label, change] of [['no approval marker', { BLINDPASS_RELEASE_APPROVED: undefined }], ['branch ref', { GITHUB_REF: 'refs/heads/main' }],
      ['not CI', { GITHUB_ACTIONS: undefined }], ['other workflow', { GITHUB_WORKFLOW: 'CI' }]]) {
      const env = { ...APPROVED, ...change, PATH: path_ };
      for (const key of Object.keys(env)) if (env[key] === undefined) delete env[key];
      const r = run('bash', [PUBLISH_DIST, '--publish-npm', '--skip-build', '--skip-validate', '--stage-dir', stageDir], { env });
      assert.notEqual(r.status, 0, label);
    }
    assert.equal(await calls(npm), '');
    // A dry run only prints, so it needs no approval and still calls nothing.
    const dry = run('bash', [PUBLISH_DIST, '--publish-npm', '--dry-run', '--skip-build', '--skip-validate', '--stage-dir', stageDir], { env: { PATH: path_ } });
    assert.equal(dry.status, 0, dry.out);
    assert.match(dry.out, /dry-run/);
    assert.equal(await calls(npm), '');
  } finally { await npm.cleanup(); await rm(stageDir, { recursive: true, force: true }); }
});

test('P07-D3: publish_dist.sh --publish-npm publishes only when the approved context is marked', async () => {
  await ensureDist();
  const npm = await fakeNpm();
  const stageDir = await mkdtemp(path.join(tmpdir(), 'blindpass-publish-approved-'));
  try {
    const r = run('bash', [PUBLISH_DIST, '--publish-npm', '--skip-build', '--skip-validate', '--stage-dir', stageDir], { env: { ...APPROVED, PATH: `${npm.dir}:${process.env.PATH}` } });
    assert.equal(r.status, 0, r.out);
    assert.equal(await calls(npm), 'publish --tag latest --access public');
  } finally { await npm.cleanup(); await rm(stageDir, { recursive: true, force: true }); }
});

test('P07-D3: the ClawHub credential and package checks are intact', async () => {
  const text = await readFile(path.join(ROOT, 'scripts/publish_clawhub.sh'), 'utf8');
  for (const needle of ['security validation failed: .env files found in dist', 'security validation failed: private key material found in dist',
    'security validation failed: node_modules found in dist', 'monorepo/absolute path leakage detected', 'local/dev SPS URL found in dist',
    'version synchronization check failed', 'clawhub CLI not found on PATH']) assert.ok(text.includes(needle), `publish_clawhub.sh lost: ${needle}`);
});

// ---- opt-in: the real registry-backed clean install, driven through the bin --------------------------------

test('P07-E01/R02: the packed bundle installs outside the repository and its bin completes MCP stdio calls',
  { skip: process.env.BLINDPASS_PACKAGE_INSTALL_TEST !== '1' && 'set BLINDPASS_PACKAGE_INSTALL_TEST=1 (installs from a local tarball; needs no registry but npm)' },
  async () => {
    const s = await stage();
    const out = await mkdtemp(path.join(tmpdir(), 'blindpass-candidate-'));
    try {
      const pack = run('npm', ['pack', '--silent', '--pack-destination', out], { cwd: s.dir });
      assert.equal(pack.status, 0, pack.out);
      const tarball = path.join(out, (await readdir(out)).find((n) => n.endsWith('.tgz')));
      const verify = run(process.execPath, [VERIFY, tarball, '--sbom', path.join(out, 'bundle.cdx.json')], { timeout: 240_000 });
      assert.equal(verify.status, 0, verify.out);
      for (const line of [/pack check OK/, /install OK: 1 package/, /bin links OK: mcp-server, blindpass-mcp-server, blindpass-resolver/, /bin mcp-server OK/, /initialize OK/, /tools\/list OK: 6 tool/, /tools\/call OK/, /bin blindpass-mcp-server OK/, /bin blindpass-resolver OK/, /npx default executable OK/, /sbom OK: bundle SBOM written: 19 component/, /candidate verified outside the repository/]) {
        assert.match(verify.stdout, line);
      }
    } finally { await rm(out, { recursive: true, force: true }); await s.cleanup(); }
  });

