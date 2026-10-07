// SPDX-License-Identifier: MIT
import { createHash } from 'node:crypto';
import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const denied = () => new Error('mcp_bundle_boundary_unavailable');
const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');
// An unreadable or malformed manifest is a boundary failure, never a raw error.
const readManifest = async (file) => { try { return JSON.parse(await readFile(file, 'utf8')); } catch { throw denied(); } };
const approvedLicenses = new Set(['MIT', 'Apache-2.0', 'MIT OR Apache-2.0', 'ISC', 'BSD-2-Clause', 'BSD-3-Clause']);

// Allowlist, not denylist: the only repository code that may enter the MIT MCP
// bundle is the MIT workspace packages listed here, and each must still declare
// exactly that license in its own manifest. Any other workspace (MIT or not),
// helper, crate, script, test or root path is refused, so a new directory is
// excluded by default instead of silently included. Extending this list is a
// licensing-boundary decision (LICENSES.md, P05 MCP distribution boundary).
const WORKSPACE_ALLOWLIST = Object.freeze({
  'packages/mcp-server': { name: '@blindpass/mcp-server-lib', license: 'MIT' },
  'packages/openclaw-plugin': { name: '@blindpass/openclaw-plugin', license: 'MIT' },
  'packages/gateway': { name: '@blindpass/gateway', license: 'MIT' },
  'packages/agent-skill': { name: '@blindpass/agent-skill', license: 'MIT' },
});
const allowedWorkspaceNames = new Set(Object.values(WORKSPACE_ALLOWLIST).map((entry) => entry.name));

// The compiler metadata is build-owned, never runtime/client configuration.
// Preserve complete upstream texts for every emitted package, and admit only
// allowlisted MIT workspace code in this MIT runtime distribution.
export async function generateMcpBundleNotices({ root, metadataFile, dist }) {
  root = path.resolve(root); dist = path.resolve(dist);
  // One metadata file per bundled entrypoint (the MCP server and the standalone resolver). All of them go
  // through the same boundary, and a package used by several is listed once.
  const files = Array.isArray(metadataFile) ? metadataFile : [metadataFile];
  if (files.length === 0 || files.some((file) => typeof file !== 'string' || !file)) throw denied();
  const outputs = [];
  for (const file of files) outputs.push(...Object.values((await readManifest(file)).outputs ?? {}));
  const packages = new Map();
  for (const output of outputs) for (const [source, input] of Object.entries(output.inputs ?? {})) {
    if (input.bytesInOutput === 0) continue;
    const absolute = path.resolve(root, source);
    if (!absolute.startsWith(`${root}${path.sep}`)) throw denied();
    const relative = path.relative(root, absolute).split(path.sep).join('/');
    const index = relative.lastIndexOf('node_modules/');
    if (index >= 0) {
      const tail = relative.slice(index + 'node_modules/'.length).split('/');
      const length = tail[0].startsWith('@') ? 2 : 1;
      const packageRoot = path.join(root, relative.slice(0, index), 'node_modules', ...tail.slice(0, length));
      const pkg = await readManifest(path.join(packageRoot, 'package.json'));
      // A workspace package reached through its node_modules link is still
      // repository code and follows the workspace allowlist.
      if (typeof pkg.name !== 'string' || pkg.name.startsWith('@blindpass/') && !allowedWorkspaceNames.has(pkg.name)) throw denied();
      packages.set(`${pkg.name}@${pkg.version}`, { pkg, packageRoot });
    } else {
      const directory = relative.split('/').slice(0, 2).join('/');
      const expected = Object.hasOwn(WORKSPACE_ALLOWLIST, directory) ? WORKSPACE_ALLOWLIST[directory] : undefined;
      if (!expected) throw denied();
      const pkg = await readManifest(path.join(root, directory, 'package.json'));
      if (pkg.license !== expected.license || pkg.name !== expected.name) throw denied();
    }
  }
  await mkdir(path.join(dist, 'licenses'), { recursive: true });
  const inventory = []; const filenames = new Set();
  for (const { pkg, packageRoot } of [...packages.values()].sort((a, b) => a.pkg.name.localeCompare(b.pkg.name))) {
    if (!approvedLicenses.has(pkg.license) || !/^(?:@[a-z0-9_.-]+\/)?[a-z0-9_.-]+$/.test(pkg.name)
      || !/^[A-Za-z0-9.+_-]{1,64}$/.test(pkg.version)) throw denied();
    const files = [];
    const upstream = (await readdir(packageRoot)).filter((name) => /^(license|copying|notice)(?:[._-].*)?$/i.test(name));
    const texts = await Promise.all(upstream.map(async (name) => ({ name, bytes: await readFile(path.join(packageRoot, name)) })));
    if (texts.length === 0) throw denied();
    for (const { name, bytes } of texts) {
      if (!bytes.length || bytes.length > 262_144 || !/^[A-Za-z0-9_.-]+$/.test(name)) throw denied();
      const target = `licenses/npm-${pkg.name.replace('@', '').replace('/', '-')}-${pkg.version}-${name}`;
      if (filenames.has(target)) throw denied(); filenames.add(target);
      await writeFile(path.join(dist, target), bytes);
      files.push({ path: target, sha256: digest(bytes) });
    }
    inventory.push({ name: pkg.name, version: pkg.version, license: pkg.license, files });
  }
  await writeFile(path.join(dist, 'licenses/bundle-packages.json'), `${JSON.stringify(inventory, null, 2)}\n`);
  const existing = await readFile(path.join(root, 'packages/mcp-server/THIRD_PARTY_NOTICES.md'), 'utf8');
  const rows = inventory.map((pkg) => `| ${pkg.name} | ${pkg.version} | ${pkg.license} | ${pkg.files.map((file) => `[${path.basename(file.path)}](${file.path})`).join(', ')} |`).join('\n');
  await writeFile(path.join(dist, 'THIRD_PARTY_NOTICES.md'), `${existing}\n## Bundled runtime attributions\n\nGenerated from emitted compiler inputs; complete upstream texts are retained.\n\n| Package | Version | Metadata license | Files |\n|---|---|---|---|\n${rows}\n`);
  return inventory;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    // bundle-mcp-notices.mjs METADATA_FILE... DIST_DIR
    if (process.argv.length < 4) throw denied();
    const root = fileURLToPath(new URL('..', import.meta.url));
    await generateMcpBundleNotices({ root, metadataFile: process.argv.slice(2, -1), dist: process.argv.at(-1) });
  } catch { process.stderr.write('mcp_bundle_boundary_unavailable\n'); process.exitCode = 1; }
}
