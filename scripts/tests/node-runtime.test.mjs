// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import test from 'node:test';
import { readdir, readFile } from 'node:fs/promises';
const range = '^24.21.0 || ^26.10.0';
test('P05-D7: workspace manifests and lock metadata share the tested Node lines', async () => {
  const paths = ['package.json'];
  for (const root of ['packages', 'helpers']) {
    for (const entry of await readdir(root, { withFileTypes: true })) {
      if (!entry.isDirectory()) continue;
      const path = `${root}/${entry.name}/package.json`;
      try { await readFile(path); paths.push(path); } catch (error) { if (error.code !== 'ENOENT') throw error; }
    }
  }
  const lock = JSON.parse(await readFile('package-lock.json', 'utf8'));
  for (const path of paths) {
    const manifest = JSON.parse(await readFile(path, 'utf8'));
    assert.equal(manifest.engines?.node, range, path);
    const key = path === 'package.json' ? '' : path.slice(0, -'/package.json'.length);
    assert.equal(lock.packages[key].engines?.node, range, key);
  }
});
test('P05-D7: CI retains both pinned runtime profiles', async () => {
  const workflow = await readFile('.github/workflows/ci.yml', 'utf8');
  assert.match(workflow, /node-version: \["24\.21\.0", "26\.10\.0"\]/);
  assert.match(workflow, /node-version: \$\{\{ matrix\.node-version \}\}/);
});
