// SPDX-License-Identifier: AGPL-3.0-only
// P07: the release documentation links resolve, and the known-limitations page states each deferred
// security item the owner chose to ship with, linked to the two security records that own the facts.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { existsSync } from 'node:fs';
import { readFile, readdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const RELEASE = path.join(ROOT, 'docs/release');
const pages = (await readdir(RELEASE)).filter((name) => name.endsWith('.md'));
const read = (name) => readFile(path.join(RELEASE, name), 'utf8');

test('P07: relative links in docs/release/*.md resolve to existing files', async () => {
  const broken = [];
  for (const name of pages) {
    const text = (await read(name)).replace(/```[\s\S]*?```/g, '');
    for (const match of text.matchAll(/\]\(([^)\s]+)\)/g)) {
      const target = match[1].split('#')[0];
      if (!target || /^[a-z][a-z0-9+.-]*:/i.test(target)) continue;
      if (!existsSync(path.resolve(RELEASE, target))) broken.push(`${name}: ${match[1]}`);
    }
  }
  assert.deepEqual(broken, []);
});

test('P07: no release page uses a machine-specific path or still describes the library as the public package', async () => {
  for (const name of pages) {
    const text = await read(name);
    assert.ok(!/\/home\/|\/Users\/|C:\\\\/.test(text), `${name} has a machine path`);
    assert.ok(!/@blindpass\/mcp-server`? is a library/.test(text), `${name} calls the public package a library`);
    assert.ok(!/it has no `bin`/.test(text), `${name} says the public package has no bin`);
  }
});

const DEFERRED = {
  'temporary passwords do not expire': /Temporary passwords do not expire/,
  'schema 20 and the owner deferral': /schema 20/,
  'test mode starts on a hand-edited profile': /BLINDPASS_PROXY_REQUIRED=0/,
  'the legacy images are excluded from release claims': /legacy[^.\n]*(?:SPS|`ui`|dashboard)[^.\n]*excluded from release claims|excluded from release claims[^.\n]*legacy/i,
  'lockout residual (5 or more addresses, 15 minutes, until a password reset)': /five or more[^.\n]*address[^.\n]*15 min[^.\n]*password reset|5 or more[^.\n]*address[^.\n]*15 min[^.\n]*password reset/i,
  'the confirmation code (about 12.6 bits, correlation aid only)': /12\.6 bits[^.\n]*correlation aid|correlation aid[^.\n]*12\.6 bits/i,
};

test('P07: known-limitations states each deferred security item, with both security records linked', async () => {
  const text = await read('known-limitations.md');
  const section = text.split(/^## /m).find((part) => part.startsWith('Deferred security items')) ?? '';
  assert.notEqual(section, '', 'no "Deferred security items" section');
  // Bullets wrap across lines in the source; match each on its flattened text.
  const bullets = section.split(/^- /m).slice(1).map((bullet) => bullet.replace(/\s*\n\s*/g, ' ').trim());
  assert.equal(bullets.length, 5, `expected 5 deferred items, found ${bullets.length}`);
  for (const [label, pattern] of Object.entries(DEFERRED)) assert.ok(bullets.some((bullet) => pattern.test(bullet)), label);
  // Each bullet links both records (the facts live there, not here).
  for (const bullet of bullets) {
    assert.match(bullet, /\]\(\.\.\/security\/finding-disposition\.md(?:#[^)]*)?\)/, `no finding-disposition link: ${bullet.slice(0, 60)}`);
    assert.match(bullet, /\]\(\.\.\/security\/operator-auth-and-headers\.md(?:#[^)]*)?\)/, `no operator-auth-and-headers link: ${bullet.slice(0, 60)}`);
  }
});

test('P07: known-limitations describes the public package as the npx bundle', async () => {
  const text = await read('known-limitations.md');
  assert.match(text, /@blindpass\/mcp-server`[^\n]*(?:bundle|esbuild)/);
  assert.match(text, /@blindpass\/mcp-server-lib/);
  assert.match(text, /private/i);
});
