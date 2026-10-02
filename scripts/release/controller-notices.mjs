// SPDX-License-Identifier: AGPL-3.0-only
// Preserve upstream notice texts from the reviewed installed build inputs.
import { readdir, readFile, mkdir, writeFile } from 'node:fs/promises';
import { resolve, relative, join, dirname } from 'node:path';
import { createHash } from 'node:crypto';

const [input, output] = process.argv.slice(2);
if (!input || !output) throw new Error('notice input/output required');
const source = resolve(input);
const destination = resolve(output);
const inventory = [];
async function visit(directory) {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    // Workspace symlinks are handled by the explicit project notices.
    if (entry.isSymbolicLink()) continue;
    if (entry.isDirectory()) await visit(path);
    else if (entry.isFile() && /^(licen[sc]e|copying|copyright|notice|ofl)(?:[._-]|$)/i.test(entry.name)
      && !/\.(?:rs|[cm]?js|[cm]?ts|c|h|json)$/i.test(entry.name)) {
      const bytes = await readFile(path);
      const name = relative(source, path);
      const target = join(destination, name);
      await mkdir(dirname(target), { recursive: true });
      await writeFile(target, bytes, { mode: 0o644 });
      inventory.push({ path: name, sha256: createHash('sha256').update(bytes).digest('hex') });
    }
  }
}
await visit(source);
if (inventory.length === 0) throw new Error('upstream notice inventory empty');
inventory.sort((a, b) => a.path.localeCompare(b.path));
await writeFile(join(destination, 'inventory.json'), `${JSON.stringify(inventory, null, 2)}\n`);
console.log(`Preserved ${inventory.length} upstream notice files.`);
