// SPDX-License-Identifier: MIT
// zod is installed three times (this package, @modelcontextprotocol/server and
// @modelcontextprotocol/core). Schemas built here with z.fromJSONSchema are
// consumed by the SDK's own copy through the Standard Schema interface, so the
// copies must stay the identical reviewed release. The lockfile is not changed
// to dedupe them; this test fails if any copy drifts from the pin.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

function zodFrom(specifier) {
  const parent = fileURLToPath(import.meta.resolve(specifier));
  let directory = dirname(createRequire(parent).resolve('zod'));
  for (;;) {
    try {
      const manifest = JSON.parse(readFileSync(join(directory, 'package.json'), 'utf8'));
      if (manifest.name === 'zod') return { directory, version: manifest.version };
    } catch { /* keep walking */ }
    const next = dirname(directory); assert.notEqual(next, directory, 'zod manifest not found'); directory = next;
  }
}

test('P05 K zod resolves to the identical pinned 4.6.5 from this package, the SDK server and the SDK core', () => {
  const pinned = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).dependencies.zod;
  assert.equal(pinned, '4.6.5');
  const copies = { package: zodFrom('../src/index.mjs'), server: zodFrom('@modelcontextprotocol/server'), core: zodFrom('@modelcontextprotocol/core') };
  for (const [name, copy] of Object.entries(copies)) assert.equal(copy.version, pinned, `${name} copy at ${copy.directory}`);
});
