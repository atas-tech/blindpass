// SPDX-License-Identifier: AGPL-3.0-only
// P07-D3: CycloneDX 1.5 SBOM for the npm bundle candidate.
//
//   node bundle-sbom.mjs --package DIR --out FILE
//
// The bundle has no runtime dependencies, so `npm sbom` would describe an empty tree. What ships inside
// it is recorded by scripts/bundle-mcp-notices.mjs at build time from the emitted compiler inputs:
// DIR/dist/licenses/bundle-packages.json (name, version, licence, licence files with SHA-256). This
// command checks every listed licence file against its recorded hash, then writes one component per
// bundled package. Same input, same bytes: no timestamp, serial number or host name. It refuses to
// overwrite an existing file and writes nothing when anything is wrong.
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// The SPDX identifiers the notices generator accepts for a bundled package (approvedLicenses there).
const LICENSES = new Set(['MIT', 'Apache-2.0', 'MIT OR Apache-2.0', 'ISC', 'BSD-2-Clause', 'BSD-3-Clause']);
const NAME = /^(?:@[a-z0-9_.-]+\/)?[a-z0-9_.-]+$/;
const VERSION = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/;
const LICENSE_FILE = /^licenses\/[A-Za-z0-9_.-]+$/;
const HASH = /^[0-9a-f]{64}$/;

class Refused extends Error {}
const refuse = (message) => { throw new Refused(message); };

const purl = (name, version) => `pkg:npm/${name.replace('@', '%40')}@${version}`;
const license = (id) => (id.includes(' ') ? { expression: id } : { license: { id } });

function readJson(file, what) {
  let text;
  try { text = readFileSync(file, 'utf8'); } catch { refuse(`${what} is missing: ${path.basename(file)}`); }
  try { return JSON.parse(text); } catch { return refuse(`${what} is not valid JSON`); }
}

export function buildBundleSbom(packageDir) {
  const manifest = readJson(path.join(packageDir, 'package.json'), 'package.json');
  if (typeof manifest.name !== 'string' || !NAME.test(manifest.name) || typeof manifest.version !== 'string' || !VERSION.test(manifest.version)
    || typeof manifest.license !== 'string' || !LICENSES.has(manifest.license)) refuse('package.json lacks a safe name, version or approved licence');
  const inventory = readJson(path.join(packageDir, 'dist/licenses/bundle-packages.json'), 'the bundle licence inventory');
  if (!Array.isArray(inventory) || inventory.length === 0) refuse('the bundle licence inventory is empty');
  const seen = new Set();
  const components = inventory.map((entry) => {
    if (!entry || typeof entry !== 'object' || typeof entry.name !== 'string' || !NAME.test(entry.name)
      || typeof entry.version !== 'string' || !VERSION.test(entry.version)) refuse('an inventory entry has no safe name or version');
    const id = `${entry.name}@${entry.version}`;
    if (seen.has(id)) refuse(`duplicate inventory entry ${id}`);
    seen.add(id);
    if (typeof entry.license !== 'string' || !LICENSES.has(entry.license)) refuse(`${id} has a licence outside the approved list`);
    if (!Array.isArray(entry.files) || entry.files.length === 0) refuse(`${id} lists no licence file`);
    const properties = entry.files.map((file) => {
      if (!file || typeof file.path !== 'string' || !LICENSE_FILE.test(file.path) || typeof file.sha256 !== 'string' || !HASH.test(file.sha256)) refuse(`${id} has a malformed licence file entry`);
      let bytes;
      try { bytes = readFileSync(path.join(packageDir, 'dist', file.path)); } catch { refuse(`${id}: licence file ${file.path} is missing from the package`); }
      if (createHash('sha256').update(bytes).digest('hex') !== file.sha256) refuse(`${id}: licence file ${file.path} differs from its recorded hash`);
      return { name: 'blindpass:license-file', value: `${file.path} sha256:${file.sha256}` };
    });
    const slash = entry.name.indexOf('/');
    return {
      type: 'library',
      'bom-ref': purl(entry.name, entry.version),
      ...(slash > 0 ? { group: entry.name.slice(0, slash) } : {}),
      name: slash > 0 ? entry.name.slice(slash + 1) : entry.name,
      version: entry.version,
      purl: purl(entry.name, entry.version),
      licenses: [license(entry.license)],
      properties,
    };
  }).sort((a, b) => (a.purl < b.purl ? -1 : a.purl > b.purl ? 1 : 0));
  const root = purl(manifest.name, manifest.version);
  const slash = manifest.name.indexOf('/');
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    version: 1,
    metadata: {
      component: {
        type: 'application',
        'bom-ref': root,
        ...(slash > 0 ? { group: manifest.name.slice(0, slash) } : {}),
        name: slash > 0 ? manifest.name.slice(slash + 1) : manifest.name,
        version: manifest.version,
        purl: root,
        licenses: [license(manifest.license)],
      },
    },
    components,
    dependencies: [{ ref: root, dependsOn: components.map((component) => component.purl) }],
  };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const args = process.argv.slice(2);
    if (args.length !== 4 || args[0] !== '--package' || args[2] !== '--out') refuse('usage: bundle-sbom.mjs --package DIR --out FILE');
    const out = path.resolve(args[3]);
    if (existsSync(out)) refuse(`${out} already exists; refusing to overwrite`);
    const document = buildBundleSbom(path.resolve(args[1]));
    writeFileSync(out, `${JSON.stringify(document, null, 2)}\n`, { flag: 'wx' });
    console.log(`bundle SBOM written: ${document.components.length} component(s) for ${document.metadata.component['bom-ref']}`);
  } catch (error) {
    console.error(`bundle SBOM refused: ${error instanceof Refused ? error.message : 'unexpected failure'}`);
    process.exit(1);
  }
}
