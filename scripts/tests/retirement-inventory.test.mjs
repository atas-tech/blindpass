import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, utimesSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const script = path.join(root, 'scripts/retirement/inventory.sh');

function fixture(files, rules, { track = true } = {}) {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'retirement-inventory-'));
  execFileSync('git', ['init', '-q'], { cwd: dir });
  writeFileSync(path.join(dir, '.gitignore'), 'ignored/\n');
  for (const [name, content] of Object.entries(files)) {
    const target = path.join(dir, name);
    mkdirSync(path.dirname(target), { recursive: true });
    writeFileSync(target, content);
  }
  if (track) execFileSync('git', ['add', '-A'], { cwd: dir });
  const dispositions = path.join(dir, 'dispositions.tsv');
  writeFileSync(dispositions, rules);
  return { dir, dispositions, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

function run(f, args = []) {
  return spawnSync(script, ['--root', f.dir, '--dispositions', f.dispositions, ...args], { encoding: 'utf8' });
}

const rule = (glob, owner, disposition, status, note = 'n') => [glob, owner, disposition, status, note].join('\t');

test('the wrapper is executable and the generator is deterministic', () => {
  assert.ok(statSync(script).mode & 0o100, 'inventory.sh must be executable');
  const f = fixture({ 'a.md': 'SPS_X and sps-server\n', 'b/c.json': '{"x":"ioredis"}\n' },
    [rule('a.md', 'docs', 'archive', 'proposed'), rule('b/**', 'deploy', 'delete', 'proposed')].join('\n') + '\n');
  try {
    const first = run(f);
    assert.equal(first.status, 0, first.stderr);
    // File timestamps and creation order must not change the document.
    utimesSync(path.join(f.dir, 'a.md'), new Date(0), new Date(0));
    const second = run(f);
    assert.equal(second.stdout, first.stdout);
    assert.ok(first.stdout.indexOf('| a.md |') < first.stdout.indexOf('| b/c.json |'), 'rows sorted by path');
  } finally { f.cleanup(); }
});

test('a row carries hit counts per pattern, the owner and the first matching rule', () => {
  const f = fixture({
    'packages/sps-server/x.ts': 'import "sps-server"; SPS_A SPS_B sps_c\n',
    'packages/other/y.ts': 'SPS_Z\n'
  }, [
    rule('packages/sps-server/x.ts', 'legacy-sps', 'archive', 'accepted'),
    rule('packages/**', 'general', 'retain', 'proposed')
  ].join('\n') + '\n');
  try {
    const out = run(f).stdout;
    const x = out.split('\n').find((line) => line.startsWith('| packages/sps-server/x.ts |'));
    assert.ok(x, out);
    assert.match(x, /legacy-sps/);
    assert.match(x, /archive/);
    assert.match(x, /accepted/);
    assert.match(x, /SPS_ ×2/);
    assert.match(x, /sps_ ×1/);
    assert.match(x, /sps-server ×1/);
    const y = out.split('\n').find((line) => line.startsWith('| packages/other/y.ts |'));
    assert.match(y, /general/);
    assert.match(y, /retain/);
    assert.match(y, /proposed/);
  } finally { f.cleanup(); }
});

test('patterns cover the plan list and do not count redistribution as Redis', () => {
  const f = fixture({
    'redistribution.txt': 'You may redistribute this font. Redistribution is allowed.\n',
    'r.txt': 'REDIS_URL=redis://x ioredis\n',
    'u.txt': 'blindpass-sps-server.xml blindpass-dashboard.xml blindpass-redis.xml blindpass-postgres.xml blindpass-browser-ui.xml\n',
    'i.txt': 'ghcr.io/o/blindpass-sps-server:1 blindpass-dashboard blindpass-browser-ui\n',
    'd.txt': 'packages/dashboard and @blindpass/dashboard\n',
    'c.ts': 'class GatewaySpsClient extends SpsClient {}\n',
    'p.txt': 'the SPS and sps-bridge and sps-client\n',
    'none.txt': 'nothing about the legacy server here, only passwords and spsx\n'
  }, rule('**', 'all', 'retain', 'proposed') + '\n');
  try {
    const out = run(f).stdout;
    const row = (name) => out.split('\n').find((line) => line.startsWith(`| ${name} |`));
    assert.equal(row('redistribution.txt'), undefined);
    assert.equal(row('none.txt'), undefined);
    assert.match(row('r.txt'), /redis ×3/);
    assert.match(row('u.txt'), /unraid-template ×5/);
    assert.match(row('i.txt'), /legacy-image ×3/);
    assert.match(row('d.txt'), /dashboard-package ×2/);
    assert.match(row('c.ts'), /sps-ref ×2/);
    assert.match(row('p.txt'), /sps-ref ×3/);
  } finally { f.cleanup(); }
});

test('files without a rule are listed as undispositioned and fail --check', () => {
  const f = fixture({ 'a.md': 'sps-server\n', 'b.md': 'SPS_ONE\n' }, rule('a.md', 'docs', 'archive', 'accepted') + '\n');
  try {
    const out = run(f).stdout;
    assert.match(out, /\| b\.md \|.*UNDISPOSITIONED/);
    const check = run(f, ['--check']);
    assert.equal(check.status, 1);
    assert.match(check.stderr, /undispositioned: b\.md/);
    assert.doesNotMatch(check.stderr, /a\.md/);
    writeFileSync(f.dispositions, [rule('a.md', 'docs', 'archive', 'accepted'), rule('b.md', 'docs', 'retain', 'accepted')].join('\n') + '\n');
    assert.equal(run(f, ['--check']).status, 0);
  } finally { f.cleanup(); }
});

test('stale and shadowed rules fail --check so a removal commit must delete its own rule', () => {
  const f = fixture({ 'a.md': 'sps-server\n' }, [
    rule('**', 'docs', 'retain', 'accepted'),
    rule('a.md', 'docs', 'delete', 'accepted'),
    rule('gone/**', 'docs', 'delete', 'accepted')
  ].join('\n') + '\n');
  try {
    const check = run(f, ['--check']);
    assert.equal(check.status, 1);
    assert.match(check.stderr, /stale rule: a\.md/);
    assert.match(check.stderr, /stale rule: gone\/\*\*/);
    assert.doesNotMatch(check.stderr, /stale rule: \*\*/);
  } finally { f.cleanup(); }
});

test('--accepted fails while any matching rule is only proposed', () => {
  const f = fixture({ 'a.md': 'sps-server\n' }, rule('a.md', 'docs', 'retain', 'proposed') + '\n');
  try {
    assert.equal(run(f, ['--check']).status, 0);
    const accepted = run(f, ['--check', '--accepted']);
    assert.equal(accepted.status, 1);
    assert.match(accepted.stderr, /proposed: a\.md/);
  } finally { f.cleanup(); }
});

test('regeneration never writes the decisions file and bad rules are refused', () => {
  const rules = rule('a.md', 'docs', 'retain', 'proposed') + '\n';
  const f = fixture({ 'a.md': 'sps-server\n' }, rules);
  try {
    chmodSync(f.dispositions, 0o444);
    assert.equal(run(f).status, 0);
    assert.equal(readFileSync(f.dispositions, 'utf8'), rules);
    for (const bad of [
      rule('a.md', 'docs', 'remove', 'proposed'),
      rule('a.md', 'docs', 'retain', 'maybe'),
      'a.md\tdocs\tretain',
      rule('', 'docs', 'retain', 'proposed')
    ]) {
      chmodSync(f.dispositions, 0o644);
      writeFileSync(f.dispositions, `${bad}\n`);
      const result = run(f);
      assert.equal(result.status, 2, bad);
      assert.match(result.stderr, /dispositions\.tsv:1/);
    }
  } finally { f.cleanup(); }
});

test('the scan covers untracked files, skips ignored and binary files and its own outputs', () => {
  const f = fixture({
    'tracked.md': 'sps-server\n',
    'ignored/x.md': 'sps-server\n',
    'blob.bin': Buffer.from('sps-server\0\0binary'),
    'docs/release/retirement-inventory.md': 'sps-server\n',
    'scripts/retirement/notes.md': 'sps-server\n'
  }, rule('**', 'all', 'retain', 'proposed') + '\n');
  try {
    writeFileSync(path.join(f.dir, 'untracked.md'), 'SPS_X\n');
    writeFileSync(path.join(f.dir, 'gone.md'), 'sps-server\n');
    execFileSync('git', ['add', 'gone.md'], { cwd: f.dir });
    rmSync(path.join(f.dir, 'gone.md'));
    const out = run(f).stdout;
    const paths = out.split('\n').filter((line) => /^\| [^ ]+ \| \d+ \|/.test(line)).map((line) => line.split(' | ')[0].slice(2));
    assert.deepEqual(paths, ['tracked.md', 'untracked.md']);
  } finally { f.cleanup(); }
});

test('every file inside a legacy package is listed by path, including SQL and binary files', () => {
  const f = fixture({
    'packages/sps-server/src/db/migrations/001_init.sql': 'CREATE TABLE workspaces (id text);\n',
    'packages/dashboard/public/logo.png': Buffer.from('\x89PNG\0\0binary'),
    'packages/dashboard/src/clean.ts': 'export const x = 1;\n',
    'packages/gateway/src/clean.ts': 'export const y = 1;\n',
    'deploy/unraid/blindpass-postgres.xml': '<Container/>\n'
  }, rule('**', 'all', 'retain', 'proposed') + '\n');
  try {
    const out = run(f).stdout;
    const paths = out.split('\n').filter((line) => /^\| [^ ]+ \| \d+ \|/.test(line)).map((line) => line.split(' | ')[0].slice(2));
    assert.deepEqual(paths, [
      'deploy/unraid/blindpass-postgres.xml',
      'packages/dashboard/public/logo.png',
      'packages/dashboard/src/clean.ts',
      'packages/sps-server/src/db/migrations/001_init.sql'
    ]);
    assert.match(out.split('\n').find((line) => line.startsWith('| packages/dashboard/public/logo.png |')), /legacy-path ×1/);
  } finally { f.cleanup(); }
});

test('retained code that imports deleted code fails --check, and unfinished relocations fail --accepted', () => {
  const f = fixture({
    'packages/legacy/src/index.ts': 'export const legacy = 1; // sps-server\n',
    'packages/keep/src/ok.ts': 'import { legacy } from "../../legacy/src/index.js";\nexport { legacy };\n',
    'packages/keep/src/dyn.mjs': 'const m = await import("../../legacy/src/index.js");\nexport { m };\n',
    'packages/keep/src/bare.ts': 'import "@blindpass/legacy";\n',
    'packages/move/src/later.ts': 'export * from "../../legacy/src/index.js";\n// sps-server\n',
    'packages/keep/src/clean.ts': 'import path from "node:path";\nexport { path };\n// sps-server mentioned only in prose\n'
  }, [
    rule('packages/legacy/**', 'legacy', 'delete', 'accepted'),
    rule('packages/move/**', 'harness', 'relocate', 'accepted'),
    rule('packages/keep/**', 'keep', 'retain', 'accepted')
  ].join('\n') + '\n');
  try {
    const check = run(f, ['--check']);
    assert.equal(check.status, 1, check.stderr);
    assert.match(check.stderr, /retained-import: packages\/keep\/src\/ok\.ts imports \.\.\/\.\.\/legacy\/src\/index\.js \(deleted by packages\/legacy\/\*\*\)/);
    assert.match(check.stderr, /retained-import: packages\/keep\/src\/dyn\.mjs imports/);
    assert.match(check.stderr, /retained-import: packages\/keep\/src\/bare\.ts imports @blindpass\/legacy/);
    assert.doesNotMatch(check.stderr, /clean\.ts/);
    assert.doesNotMatch(check.stderr, /later\.ts/, 'a relocation in progress is not an error until --accepted');
    const accepted = run(f, ['--check', '--accepted']);
    assert.match(accepted.stderr, /relocation-pending: packages\/move\/src\/later\.ts imports/);
    // Once the retained files stop importing deleted code, only the unfinished relocation remains for --accepted.
    for (const name of ['ok.ts', 'dyn.mjs', 'bare.ts']) writeFileSync(path.join(f.dir, 'packages/keep/src', name), 'export {};\n// sps-server\n');
    execFileSync('git', ['add', '-A'], { cwd: f.dir });
    assert.equal(run(f, ['--check']).status, 0);
    assert.equal(run(f, ['--check', '--accepted']).status, 1);
    writeFileSync(path.join(f.dir, 'packages/move/src/later.ts'), 'export {};\n// sps-server\n');
    assert.equal(run(f, ['--check', '--accepted']).status, 0, run(f, ['--check', '--accepted']).stderr);
  } finally { f.cleanup(); }
});

test('the summary lists each rule with its file and hit counts', () => {
  const f = fixture({ 'a/1.md': 'sps-server sps-server\n', 'a/2.md': 'sps-server\n' },
    [rule('a/**', 'docs', 'archive', 'proposed', 'history'), rule('zzz/**', 'docs', 'delete', 'proposed', 'unused')].join('\n') + '\n');
  try {
    const out = run(f).stdout;
    assert.match(out, /\| `a\/\*\*` \| docs \| archive \| proposed \| 2 \| 3[^|]*\| history \|/);
    assert.match(out, /\| `zzz\/\*\*` \| docs \| delete \| proposed \| 0 \| 0[^|]*\| unused \|/);
  } finally { f.cleanup(); }
});
