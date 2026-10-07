// SPDX-License-Identifier: AGPL-3.0-only
// P07-D3: refuse to pack or accept an npm package that only works inside this monorepo.
//
//   node check-npm-pack.mjs                  check the package in the current directory (npm "prepack")
//   node check-npm-pack.mjs --dir DIR        check the package in DIR
//   node check-npm-pack.mjs --tarball FILE   check the actual packed bytes of an npm tarball
//   --self-contained                         the package is an esbuild bundle: it needs a bin and must
//                                            declare no dependencies of any kind
//   --quiet                                  print one summary line to stderr and no file list, so the guard
//                                            can run as `prepack` without corrupting `npm pack --json` stdout
//
// The packed set is the manifest's `files` allowlist (plus the files npm always packs). Every
// import in that set must resolve inside it: a relative path that stays in the package and in
// the set, a Node built-in, or a package named in `dependencies`. Anything the static scan
// cannot decide (a non-literal dynamic import, a #-prefixed internal specifier) fails.
//
// Every bin must be packed, start with `#!/usr/bin/env node`, and, when there are several different
// targets, one must be named like the unscoped package: that is the executable `npx <package>` runs
// (npm fails with "could not determine executable to run" otherwise).
//
// The scan reads raw text and does not parse JavaScript. It does not strip comments (a `//` or `/*` inside
// a string or regular expression would hide the code after it), so an import-looking comment fails closed.
// The one string-awareness it has: `require(` directly after a quote is the start of a string such as the
// code-generation templates bundlers carry (`'require("pkg").default'`), not a call.
import { spawnSync } from 'node:child_process';
import { builtinModules } from 'node:module';
import { lstatSync, mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

const CODE = /\.(?:mjs|cjs|js)$/;
const CREDENTIAL = /(?:^|\/)(?:\.env(?:\..*)?|id_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?|.*\.(?:pem|key|p12|pfx)|\.npmrc)$/i;
const ALWAYS = (name) => name === 'package.json' || /^(?:readme|license|licence)(?:\.[^/]*)?$/i.test(name);
const EXACT = /^\d+\.\d+\.\d+$/;
const problems = [];
const fail = (message) => problems.push(message);

function parseArguments(argv) {
  const options = { dir: undefined, tarball: undefined, selfContained: false, quiet: false };
  const usage = () => { console.error('usage: check-npm-pack.mjs [--dir DIR | --tarball FILE] [--self-contained] [--quiet]'); process.exit(2); };
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === '--self-contained') options.selfContained = true;
    else if (argv[i] === '--quiet') options.quiet = true;
    else if (argv[i] === '--dir' && argv[i + 1] && options.dir === undefined) options.dir = path.resolve(argv[++i]);
    else if (argv[i] === '--tarball' && argv[i + 1] && options.tarball === undefined) options.tarball = path.resolve(argv[++i]);
    else usage();
  }
  if (options.dir !== undefined && options.tarball !== undefined) usage();
  options.dir ??= process.cwd();
  return options;
}

function walk(root, relative = '') {
  const found = [];
  for (const entry of readdirSync(path.join(root, relative), { withFileTypes: true })) {
    const child = relative ? `${relative}/${entry.name}` : entry.name;
    if (entry.name === 'node_modules' || entry.name === '.git') continue;
    if (entry.isSymbolicLink()) { fail(`symlink in the package: ${child}`); continue; }
    if (entry.isDirectory()) found.push(...walk(root, child));
    else if (entry.isFile()) found.push(child);
  }
  return found;
}

function allowlistMatcher(files) {
  const rules = files.map((entry) => {
    if (typeof entry !== 'string' || !entry || path.isAbsolute(entry) || entry.startsWith('!') || entry.includes('*')
      || entry.split('/').includes('..') || entry.startsWith('./')) { fail(`unsafe files entry: ${JSON.stringify(entry)}`); return null; }
    return { entry, directory: entry.endsWith('/'), name: entry.replace(/\/$/, '') };
  }).filter(Boolean);
  const allowed = (file) => ALWAYS(file) || rules.some((r) => (r.directory ? file.startsWith(`${r.name}/`) : file === r.name || file.startsWith(`${r.name}/`)));
  return { rules, allowed };
}

function specifiers(source) {
  const found = [];
  for (const m of source.matchAll(/\b(?:import|export)\b(?!\s*\()[^'"`;]*?\bfrom\s*(['"])([^'"\n]+)\1/g)) found.push([m[2], 'static']);
  for (const m of source.matchAll(/(?:^|[;\n}])\s*import\s*(['"])([^'"\n]+)\1/g)) found.push([m[2], 'static']);
  for (const m of source.matchAll(/\bimport\s*\(\s*(['"`])([^'"`\n]+)\1\s*\)/g)) found.push([m[2], 'dynamic']);
  // A call, not the beginning of a string: `require(` immediately after a quote is template text.
  const call = (m) => !/['"`]/.test(source[m.index - 1] ?? '');
  const calls = [...source.matchAll(/\brequire\s*\(/g)].filter(call);
  const literalCalls = [...source.matchAll(/\brequire\s*\(\s*(['"])([^'"\n]+)\1\s*\)/g)].filter(call);
  for (const m of literalCalls) found.push([m[2], 'require']);
  if (calls.length > literalCalls.length) found.push([null, 'non-literal']);
  const literal = (source.match(/\bimport\s*\(\s*['"`]/g) ?? []).length;
  const all = (source.match(/\bimport\s*\(/g) ?? []).length;
  if (all > literal) found.push([null, 'non-literal']);
  return found;
}

function packageName(specifier) {
  const parts = specifier.split('/');
  return specifier.startsWith('@') ? parts.slice(0, 2).join('/') : parts[0];
}

const SHEBANG = '#!/usr/bin/env node';

function checkManifest(manifest, set, dir, selfContained) {
  if (manifest.private === true) fail('manifest is private: a published package must not carry "private": true');
  for (const field of ['name', 'version', 'license']) if (typeof manifest[field] !== 'string' || !manifest[field]) fail(`manifest lacks ${field}`);
  if (!manifest.engines?.node) fail('manifest lacks engines.node');
  if (manifest.publishConfig?.access !== 'public') fail('publishConfig.access must be "public"');
  if (manifest.publishConfig?.provenance !== true) fail('publishConfig.provenance must be true (publication is attested from the release workflow)');
  const dependencies = manifest.dependencies ?? {};
  for (const [name, spec] of Object.entries(dependencies)) {
    if (name.startsWith('@blindpass/')) fail(`dependency ${name} is a workspace package that is not published with this one`);
    if (typeof spec !== 'string' || !EXACT.test(spec)) fail(`dependency ${name} must be an exact version (no lockfile ships with a published package), found ${JSON.stringify(spec)}`);
  }
  if (selfContained) {
    for (const field of ['dependencies', 'peerDependencies', 'optionalDependencies', 'bundleDependencies', 'bundledDependencies']) {
      const value = manifest[field];
      if (Array.isArray(value) ? value.length > 0 : Object.keys(value ?? {}).length > 0) fail(`a self-contained bundle must declare no ${field}`);
    }
  }
  const bins = typeof manifest.bin === 'string' ? { [String(manifest.name).replace(/^@[^/]+\//, '')]: manifest.bin } : manifest.bin ?? {};
  if (selfContained && Object.keys(bins).length === 0) fail('a self-contained bundle must expose at least one bin (npx runs a bin)');
  if (manifest.main === undefined && Object.keys(bins).length === 0 && manifest.exports === undefined) fail('manifest declares no entrypoint (main, bin or exports)');
  const targets = manifest.main === undefined ? [] : [['main', manifest.main]];
  for (const [key, value] of Object.entries(bins)) targets.push([`bin ${key}`, value]);
  const collect = (value, label) => {
    if (typeof value === 'string') targets.push([label, value]);
    else if (value && typeof value === 'object') for (const [k, v] of Object.entries(value)) collect(v, `${label} ${k}`);
  };
  if (manifest.exports !== undefined) collect(manifest.exports, 'exports');
  for (const [label, target] of targets) {
    if (typeof target !== 'string') { fail(`${label} is not a path`); continue; }
    const normal = path.posix.normalize(target.replace(/^\.\//, ''));
    if (!set.has(normal)) { fail(`${label} "${target}" is not in the packed set`); continue; }
    if (label.startsWith('bin ')) {
      let first = '';
      try { first = readFileSync(path.join(dir, normal), 'utf8').split('\n', 1)[0].replace(/\r$/, ''); } catch { /* reported as missing above */ }
      if (first !== SHEBANG) fail(`${label} "${target}" has no ${SHEBANG} shebang (npm links it as an executable)`);
    }
  }
  const distinct = new Set(Object.values(bins));
  const unscoped = String(manifest.name).replace(/^@[^/]+\//, '');
  if (distinct.size > 1 && !Object.hasOwn(bins, unscoped)) {
    fail(`npx ${manifest.name} cannot determine the default executable: the bins differ and none is named "${unscoped}"`);
  }
}

function checkImports(dir, set, manifest) {
  const dependencies = new Set(Object.keys(manifest.dependencies ?? {}));
  for (const file of [...set].filter((f) => CODE.test(f))) {
    for (const [specifier, kind] of specifiers(readFileSync(path.join(dir, file), 'utf8'))) {
      if (kind === 'non-literal') { fail(`${file}: non-literal dynamic import or require cannot be checked`); continue; }
      if (specifier.startsWith('#')) fail(`${file}: #-prefixed internal import ${specifier} cannot be checked`);
      else if (specifier.startsWith('.')) {
        const resolved = path.posix.normalize(path.posix.join(path.posix.dirname(file), specifier));
        if (resolved.startsWith('../') || resolved === '..') fail(`${file}: ${specifier} resolves outside the package`);
        else if (!set.has(resolved)) fail(`${file}: ${specifier} is not in the packed set`);
      } else if (specifier.startsWith('node:') || builtinModules.includes(specifier.split('/')[0])) continue;
      else if (!dependencies.has(packageName(specifier))) fail(`${file}: import of undeclared dependency ${packageName(specifier)}`);
    }
  }
}

function inspect(dir, tarballFiles, selfContained) {
  let manifest;
  try { manifest = JSON.parse(readFileSync(path.join(dir, 'package.json'), 'utf8')); } catch { fail('package.json is missing or not valid JSON'); return null; }
  if (!Array.isArray(manifest.files) || manifest.files.length === 0) { fail('manifest lacks a files allowlist'); return null; }
  const { rules, allowed } = allowlistMatcher(manifest.files);
  const present = tarballFiles ?? walk(dir);
  let set;
  if (tarballFiles) {
    set = new Set();
    for (const file of present) {
      if (!allowed(file)) fail(`file is not in the files allowlist: ${file}`);
      set.add(file);
    }
  } else {
    set = new Set(present.filter(allowed));
    for (const rule of rules) {
      if (!present.some((f) => (rule.directory ? f.startsWith(`${rule.name}/`) : f === rule.name || f.startsWith(`${rule.name}/`)))) fail(`files entry ${JSON.stringify(rule.entry)} matches nothing`);
    }
  }
  for (const file of set) if (CREDENTIAL.test(file)) fail(`credential-looking file in the packed set: ${file}`);
  checkManifest(manifest, set, dir, selfContained);
  checkImports(dir, set, manifest);
  return { manifest, set };
}

const options = parseArguments(process.argv.slice(2));
let result;
if (options.tarball) {
  try { if (!lstatSync(options.tarball).isFile()) throw new Error('not a file'); } catch { console.error(`pack check FAILED\n  - tarball is missing or not a regular file`); process.exit(1); }
  const extract = mkdtempSync(path.join(tmpdir(), 'blindpass-tarball-'));
  try {
    const listing = spawnSync('tar', ['-tzf', options.tarball], { encoding: 'utf8' });
    if (listing.status !== 0) fail('tarball cannot be listed');
    else {
      const names = listing.stdout.split('\n').filter(Boolean);
      for (const name of names) if (!name.startsWith('package/') || name.split('/').includes('..') || path.isAbsolute(name)) fail(`unsafe tarball member: ${name}`);
      if (spawnSync('tar', ['-xzf', options.tarball, '-C', extract, '--no-same-owner'], { encoding: 'utf8' }).status !== 0) fail('tarball cannot be extracted');
      else result = inspect(path.join(extract, 'package'), walk(path.join(extract, 'package')), options.selfContained);
    }
  } finally { rmSync(extract, { recursive: true, force: true }); }
} else result = inspect(options.dir, undefined, options.selfContained);

if (problems.length > 0) {
  console.error(`pack check FAILED\n${[...new Set(problems)].map((p) => `  - ${p}`).join('\n')}`);
  process.exit(1);
}
const summary = `pack check OK: ${result.manifest.name}@${result.manifest.version}, ${result.set.size} file(s)`;
if (options.quiet) console.error(summary);
else {
  console.log(summary);
  for (const file of [...result.set].sort()) console.log(`  ${file}`);
}
