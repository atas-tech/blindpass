// SPDX-License-Identifier: AGPL-3.0-only
// P07-E01/R02: install the packed @blindpass/mcp-server bundle candidate outside this repository and drive
// its executables the way a user on a clean host would.
//
//   node verify-npm-candidate.mjs TARBALL [--sbom FILE] [--keep]
//
// The candidate is the tarball of the staged esbuild bundle (scripts/publish_dist.sh): no runtime
// dependencies and several `bin` entries. This script:
//   1. inspects the tarball with check-npm-pack.mjs --self-contained;
//   2. installs it offline into an empty directory outside the repository (empty npm user and global
//      config, --ignore-scripts, no lockfile) and requires exactly one installed package;
//   3. runs each linked executable from node_modules/.bin: the MCP server over stdio (initialize,
//      tools/list, a tools/call) and the resolver (--help and one request);
//   4. runs `npx <tarball>` to prove npm chooses the default executable;
//   5. with --sbom FILE, writes the CycloneDX SBOM of what the bundle contains (bundle-sbom.mjs).
//
// With no broker, store or credential configured the tool call can only reach the fixed safe failure:
// the result must be isError with the text "Operation failed" and nothing else. That proves the tool
// path runs and fails closed; it does not prove a secret delivery (that is the VM and stock-client work).
import { spawn, spawnSync } from 'node:child_process';
import { accessSync, chmodSync, constants, existsSync, lstatSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const args = process.argv.slice(2);
const keep = args.includes('--keep');
const tarball = args[0] && !args[0].startsWith('--') ? path.resolve(args[0]) : undefined;
const sbomIndex = args.indexOf('--sbom');
const sbomOut = sbomIndex === -1 ? undefined : args[sbomIndex + 1];
const known = new Set([...(tarball ? [args[0]] : []), '--keep', '--sbom', ...(sbomOut ? [sbomOut] : [])]);
if (!tarball || (sbomIndex !== -1 && !sbomOut) || args.some((arg) => !known.has(arg))) {
  console.error('usage: verify-npm-candidate.mjs TARBALL [--sbom FILE] [--keep]'); process.exit(2);
}

const EXPECTED_TOOLS = ['confirm_delete_secret', 'delete_secret', 'fulfill_secret_exchange', 'list_secrets', 'request_secret', 'request_secret_exchange'];
const failures = [];
const note = (line) => console.log(line);
const fail = (line) => { failures.push(line); console.error(`FAIL: ${line}`); };

const inspected = spawnSync(process.execPath, [path.join(ROOT, 'scripts/release/check-npm-pack.mjs'), '--tarball', tarball, '--self-contained'], { encoding: 'utf8' });
if (inspected.status !== 0) { console.error(`${inspected.stdout}${inspected.stderr}`); process.exit(1); }
note(inspected.stdout.split('\n')[0]);

const dir = mkdtempSync(path.join(tmpdir(), 'blindpass-clean-host-'));
if (!path.relative(ROOT, dir).startsWith('..')) { console.error('refusing to install inside the repository'); process.exit(1); }
const userConfig = path.join(dir, 'user.npmrc');
const globalConfig = path.join(dir, 'global.npmrc');
writeFileSync(userConfig, '');
writeFileSync(globalConfig, '');
writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'clean-host-consumer', private: true, type: 'module' }));
// No credential, registry or monorepo setting reaches the install or the servers. PATH is only there to find node and npm.
const env = { PATH: process.env.PATH, HOME: dir, npm_config_userconfig: userConfig, npm_config_globalconfig: globalConfig, npm_config_cache: path.join(dir, '.npm-cache') };

function installedPackages() {
  const found = [];
  const visit = (nodeModules) => {
    if (!existsSync(nodeModules)) return;
    for (const entry of readdirSync(nodeModules, { withFileTypes: true })) {
      if (entry.name.startsWith('.')) continue;
      const base = path.join(nodeModules, entry.name);
      const scoped = entry.name.startsWith('@') ? readdirSync(base).map((n) => path.join(base, n)) : [base];
      for (const packageDir of scoped) {
        try { const m = JSON.parse(readFileSync(path.join(packageDir, 'package.json'), 'utf8')); found.push({ name: m.name, version: m.version }); } catch { /* not a package */ }
        visit(path.join(packageDir, 'node_modules'));
      }
    }
  };
  visit(path.join(dir, 'node_modules'));
  return found;
}

// Newline-delimited JSON-RPC over a child's stdio. Resolves with what the child did; never throws.
async function driveMcp(label, command, commandArgs, { strictStderr }) {
  const failuresBefore = failures.length;
  const child = spawn(command, commandArgs, { cwd: dir, env, stdio: ['pipe', 'pipe', 'pipe'] });
  let stderr = ''; let partial = ''; const lines = []; const waiting = new Map();
  child.stderr.on('data', (b) => { stderr += b; });
  child.stdin.on('error', () => {});
  child.on('error', (error) => fail(`${label}: cannot start (${error.code ?? error.message})`));
  child.stdout.on('data', (b) => {
    partial += b; let i;
    while ((i = partial.indexOf('\n')) !== -1) {
      const raw = partial.slice(0, i); partial = partial.slice(i + 1);
      let v; try { v = JSON.parse(raw); } catch { v = { unparsable: raw.slice(0, 80) }; }
      lines.push(v); if (v?.id !== undefined) { waiting.get(v.id)?.(v); waiting.delete(v.id); }
    }
  });
  const closed = new Promise((resolve) => child.once('close', (code, signal) => resolve({ code, signal })));
  const request = (id, method, params) => new Promise((resolve, reject) => {
    const timer = setTimeout(() => { waiting.delete(id); reject(new Error(`${method}: no reply within 30 s`)); }, 30_000);
    waiting.set(id, (v) => { clearTimeout(timer); resolve(v); });
    child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`);
  });
  const result = {};
  try {
    const init = await request(1, 'initialize', { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'blindpass-clean-host-check', version: '1' } });
    if (init.result?.serverInfo?.name !== 'blindpass') fail(`${label}: initialize returned ${JSON.stringify(init).slice(0, 200)}`);
    else { result.initialize = `server ${init.result.serverInfo.name} ${init.result.serverInfo.version}, protocol ${init.result.protocolVersion}`; note(`[${label}] initialize OK: ${result.initialize}`); }
    child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' })}\n`);
    if (label.startsWith('npx')) { result.ok = failures.length === failuresBefore; child.stdin.end(); await Promise.race([closed, new Promise((r) => setTimeout(r, 5000))]); child.kill('SIGKILL'); return result; }
    const list = await request(2, 'tools/list', {});
    const names = (list.result?.tools ?? []).map((t) => t.name).sort();
    if (JSON.stringify(names) !== JSON.stringify(EXPECTED_TOOLS)) fail(`${label}: tools/list returned ${JSON.stringify(names)}`);
    else note(`[${label}] tools/list OK: ${names.length} tool(s): ${names.join(', ')}`);
    const call = await request(3, 'tools/call', { name: 'list_secrets', arguments: {} });
    const text = call.result?.content?.map((c) => c.text).join('');
    if (call.result?.isError !== true || text !== 'Operation failed' || call.result.content.length !== 1) fail(`${label}: tools/call returned ${JSON.stringify(call).slice(0, 200)}`);
    else note(`[${label}] tools/call OK: list_secrets -> isError true, text "Operation failed" (no broker or store is configured, so only the fixed safe failure is reachable)`);
  } catch (error) { fail(`${label}: ${error.message}`); }
  child.stdin.end();
  const timer = setTimeout(() => child.kill('SIGKILL'), 5000);
  const exit = await closed; clearTimeout(timer);
  if (exit.code !== 0) fail(`${label}: exited ${exit.code ?? exit.signal} after stdin closed`);
  if (lines.some((l) => l?.unparsable !== undefined || l?.jsonrpc !== '2.0')) fail(`${label}: stdout carried a non-protocol line`);
  if (strictStderr && stderr.trim() !== '') fail(`${label}: wrote to stderr`);
  return result;
}

function runOnce(command, commandArgs, input) {
  return spawnSync(command, commandArgs, { cwd: dir, env, input, encoding: 'utf8', timeout: 30_000 });
}

try {
  const install = spawnSync('npm', ['install', '--offline', '--ignore-scripts', '--no-audit', '--no-fund', '--no-package-lock', tarball], { cwd: dir, env, encoding: 'utf8', timeout: 180_000 });
  if (install.status !== 0) { console.error(`${install.stdout}\n${install.stderr}`); failures.push('npm install failed'); throw new Error('install'); }
  const packages = installedPackages();
  if (packages.length !== 1 || packages[0].name !== '@blindpass/mcp-server') fail(`expected exactly @blindpass/mcp-server, found ${JSON.stringify(packages)}`);
  else note(`install OK: 1 package(s) under node_modules (offline, outside the repository): ${packages[0].name}@${packages[0].version}`);

  const packageDir = path.join(dir, 'node_modules/@blindpass/mcp-server');
  const manifest = JSON.parse(readFileSync(path.join(packageDir, 'package.json'), 'utf8'));
  const bins = typeof manifest.bin === 'string' ? { [manifest.name.replace(/^@[^/]+\//, '')]: manifest.bin } : manifest.bin ?? {};
  if (Object.keys(bins).length === 0) fail('the installed package has no bin');
  if (manifest.dependencies && Object.keys(manifest.dependencies).length > 0) fail('the installed package declares dependencies');
  const real = realpathSync(packageDir);
  for (const name of Object.keys(bins)) {
    const link = path.join(dir, 'node_modules/.bin', name);
    try {
      if (!lstatSync(link).isSymbolicLink() || !realpathSync(link).startsWith(`${real}${path.sep}`)) throw new Error('not a link into the package');
      accessSync(link, constants.X_OK);
    } catch (error) { fail(`bin ${name} is not an executable link into the package (${error.message})`); }
  }
  note(`bin links OK: ${Object.keys(bins).join(', ')} (executable, inside the package)`);

  if (failures.length === 0) {
    const bin = (name) => path.join(dir, 'node_modules/.bin', name);
    for (const name of ['mcp-server', 'blindpass-mcp-server']) {
      const before = failures.length;
      await driveMcp(name, bin(name), [], { strictStderr: true });
      if (failures.length === before) note(`bin ${name} OK`);
    }

    const help = runOnce(bin('blindpass-resolver'), ['--help'], '');
    if (help.status !== 0 || !/^Usage: blindpass-resolver/.test(help.stderr)) fail(`blindpass-resolver --help: exit ${help.status}, ${help.stderr.slice(0, 120)}`);
    const unsupported = runOnce(bin('blindpass-resolver'), [], '{"protocolVersion":2,"ids":["demo"]}');
    const read = runOnce(bin('blindpass-resolver'), [], '{"protocolVersion":1,"provider":"blindpass","ids":["demo"]}');
    let unsupportedBody; let readBody;
    try { unsupportedBody = JSON.parse(unsupported.stdout); readBody = JSON.parse(read.stdout); } catch { /* reported below */ }
    if (unsupported.status !== 0 || !/^Unsupported protocolVersion/.test(unsupportedBody?.errors?.__request__?.message ?? '')) fail(`blindpass-resolver request validation: ${unsupported.stdout.slice(0, 160)}`);
    // No store or key exists on a clean host: the read must fail closed with the fixed message and no value.
    else if (read.status !== 0 || JSON.stringify(readBody?.values) !== '{}' || readBody?.errors?.__request__?.message !== 'Managed store read failed.') fail(`blindpass-resolver store read: ${read.stdout.slice(0, 160)} ${read.stderr.slice(0, 120)}`);
    else note('bin blindpass-resolver OK: --help prints usage; a bad protocol version is rejected; a read with no store returns values {} and "Managed store read failed."');

    // P09: the migration CLI starts from the installed package with no sibling files; on an empty private
    // directory the dry run reports no credentials and writes nothing.
    {
      const migrate = bin('blindpass-openclaw-migrate');
      const usage = runOnce(migrate, ['--help'], '');
      if (usage.status !== 0 || !/^Usage: blindpass-openclaw-migrate/.test(usage.stdout)) fail(`blindpass-openclaw-migrate --help: exit ${usage.status}, ${usage.stdout.slice(0, 120)} ${usage.stderr.slice(0, 120)}`);
      else {
        const empty = mkdtempSync(path.join(tmpdir(), 'blindpass-migrate-empty-'));
        try {
          chmodSync(empty, 0o700);
          const dry = runOnce(migrate, ['--dry-run', '--config-dir', empty], '');
          if (dry.status !== 0 || !/No credential fields were found/.test(dry.stdout) || readdirSync(empty).length !== 0) fail(`blindpass-openclaw-migrate --dry-run: exit ${dry.status}, ${dry.stdout.slice(0, 120)} ${dry.stderr.slice(0, 120)}`);
          else note('bin blindpass-openclaw-migrate OK: --help prints usage; --dry-run on an empty private directory reports no credentials and writes nothing');
        } finally { rmSync(empty, { recursive: true, force: true }); }
      }
    }

    // npm chooses the default executable (the bin named like the package) exactly as it does for `npx @blindpass/mcp-server`.
    const npx = await driveMcp('npx', 'npx', ['--yes', '--offline', `file:${tarball}`], { strictStderr: false });
    if (npx.ok) note('npx default executable OK: `npx <package>` started the MCP server and answered initialize');
  }

  if (sbomOut && failures.length === 0) {
    const sbom = spawnSync(process.execPath, [path.join(ROOT, 'scripts/release/bundle-sbom.mjs'), '--package', packageDir, '--out', path.resolve(sbomOut)], { encoding: 'utf8' });
    if (sbom.status !== 0) fail(`SBOM generation failed: ${sbom.stderr.trim()}`); else note(`sbom OK: ${sbom.stdout.trim()}`);
  }
} catch (error) {
  if (error.message !== 'install') throw error;
} finally {
  if (keep) note(`kept ${dir}`); else rmSync(dir, { recursive: true, force: true });
}
if (failures.length > 0) process.exit(1);
note('candidate verified outside the repository');
