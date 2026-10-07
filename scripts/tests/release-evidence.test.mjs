// SPDX-License-Identifier: AGPL-3.0-only
// P07-D9: the evidence matrix never turns missing, skipped or malformed evidence into a pass.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { spawnSync } from 'node:child_process';
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const COLLECT = path.join(ROOT, 'scripts/release/collect-evidence.sh');
const COMMIT = 'a'.repeat(40);

const CATALOG = {
  schema: 'blindpass-required-scenarios-v1',
  scenarios: [
    { id: 'S01', title: 'Confirmation code role', profiles: ['native-x86_64', 'compose-sqlite'] },
    { id: 'P07-I01', title: 'Finding disposition', profiles: ['any'] },
    { id: 'P06-ACCEPTED', title: 'P06 review row accepted', profiles: ['any'] },
  ],
};

function results(overrides = {}) {
  return {
    schema: 'blindpass-release-evidence-v1', commit: COMMIT, date: '2026-10-06', profile: 'native-x86_64',
    client: 'none', environment: 'Debian 12 guest, systemd 252',
    scenarios: [{ id: 'S01', result: 'pass', evidence: 'docs/testing/evidence/p07-s01.md' }],
    ...overrides,
  };
}

async function workspace(files) {
  const dir = await mkdtemp(path.join(tmpdir(), 'blindpass-evidence-'));
  await mkdir(path.join(dir, 'results'));
  await writeFile(path.join(dir, 'required.json'), JSON.stringify(CATALOG));
  for (const [name, value] of Object.entries(files)) {
    await writeFile(path.join(dir, 'results', name), typeof value === 'string' ? value : JSON.stringify(value));
  }
  return { dir, cleanup: () => rm(dir, { recursive: true, force: true }) };
}

function collect(w, extra = [], { commit = COMMIT } = {}) {
  const output = path.join(w.dir, 'evidence.md');
  const result = spawnSync('bash', [COLLECT, '0.1.0', '--commit', commit, '--required', path.join(w.dir, 'required.json'),
    '--results', path.join(w.dir, 'results'), '--output', output, ...extra], { encoding: 'utf8', env: { PATH: process.env.PATH } });
  return { status: result.status, out: `${result.stdout}${result.stderr}`, output };
}

const complete = {
  'native.json': results({ scenarios: [{ id: 'S01', result: 'pass', evidence: 'docs/testing/evidence/p07-s01-native.md' },
    { id: 'P07-I01', result: 'pass', evidence: 'docs/security/finding-disposition.md' },
    { id: 'P06-ACCEPTED', result: 'pass', evidence: 'https://example.invalid/review#row' }] }),
  'compose.json': results({ profile: 'compose-sqlite', scenarios: [{ id: 'S01', result: 'pass', evidence: 'docs/testing/evidence/p07-s01-compose.md' }] }),
};

test('P07-D9: complete passing evidence is eligible for review but never decides go/no-go', async () => {
  const w = await workspace(complete);
  try {
    const run = collect(w);
    assert.equal(run.status, 0, run.out);
    const text = await readFile(run.output, 'utf8');
    assert.match(text, /Release gate: ELIGIBLE FOR REVIEW/);
    assert.match(text, /Go\/no-go: NOT DECIDED/);
    assert.ok(!/Go\/no-go: (GO|NO-GO)\b/.test(text));
    assert.match(text, new RegExp(COMMIT));
    assert.match(text, /\| S01 \| compose-sqlite \|/);
    assert.match(text, /\| S01 \| native-x86_64 \|/);
    assert.match(text, /[0-9a-f]{64}.*native\.json/);
  } finally { await w.cleanup(); }
});

test('P07-D9: a required scenario/profile with no result is "not run" and blocks the gate', async () => {
  const w = await workspace({ 'native.json': complete['native.json'] });
  try {
    const run = collect(w);
    assert.equal(run.status, 3, run.out);
    const text = await readFile(run.output, 'utf8');
    assert.match(text, /Release gate: BLOCKED/);
    assert.match(text, /\| S01 \| compose-sqlite \| — \| not run \|/);
    assert.ok(!/\| S01 \| compose-sqlite \|[^\n]*\| pass \|/.test(text));
    assert.match(text, /Blocking: S01 on compose-sqlite \(not run\)/);
  } finally { await w.cleanup(); }
});

test('P07-D9: skip, unsupported and fail all block a required row and keep their reasons', async () => {
  for (const [result, reason] of [['skip', 'no KVM on the CI runner'], ['unsupported', 'profile not claimed this release'], ['fail', 'canary found in backup']]) {
    const w = await workspace({ 'native.json': complete['native.json'],
      'compose.json': results({ profile: 'compose-sqlite', scenarios: [{ id: 'S01', result, reason }] }) });
    try {
      const run = collect(w);
      assert.equal(run.status, 3, `${result}: ${run.out}`);
      const text = await readFile(run.output, 'utf8');
      assert.match(text, /Release gate: BLOCKED/);
      assert.match(text, new RegExp(`\\| S01 \\| compose-sqlite \\| none \\| ${result} \\| ${reason}`));
    } finally { await w.cleanup(); }
  }
});

test('P07-D9: unparsable or inconsistent input fails closed with no evidence written', async () => {
  const cases = {
    'invalid JSON': { 'bad.json': '{ not json' },
    'wrong schema': { 'bad.json': results({ schema: 'something-else' }) },
    'unknown top-level key': { 'bad.json': { ...results(), status: 'green' } },
    'unknown result value': { 'bad.json': results({ scenarios: [{ id: 'S01', result: 'passed', evidence: 'docs/x.md' }] }) },
    'pass without evidence': { 'bad.json': results({ scenarios: [{ id: 'S01', result: 'pass' }] }) },
    'skip without reason': { 'bad.json': results({ scenarios: [{ id: 'S01', result: 'skip' }] }) },
    'unsupported with blank reason': { 'bad.json': results({ scenarios: [{ id: 'S01', result: 'unsupported', reason: '  ' }] }) },
    'absolute evidence path': { 'bad.json': results({ scenarios: [{ id: 'S01', result: 'pass', evidence: '/home/someone/log.txt' }] }) },
    'parent-directory evidence path': { 'bad.json': results({ scenarios: [{ id: 'S01', result: 'pass', evidence: '../outside.md' }] }) },
    'http evidence link': { 'bad.json': results({ scenarios: [{ id: 'S01', result: 'pass', evidence: 'http://example.invalid/x' }] }) },
    'stale commit': { 'bad.json': results({ commit: 'b'.repeat(40) }) },
    'short commit': { 'bad.json': results({ commit: 'abc123' }) },
    'bad date': { 'bad.json': results({ date: 'yesterday' }) },
    'scenario not an object': { 'bad.json': results({ scenarios: ['S01'] }) },
    'empty scenarios': { 'bad.json': results({ scenarios: [] }) },
    'control character in reason': { 'bad.json': results({ scenarios: [{ id: 'S01', result: 'skip', reason: 'line\nbreak' }] }) },
    'non-json file in results': { 'good.json': complete['native.json'], 'notes.txt': 'free text' },
  };
  for (const [label, files] of Object.entries(cases)) {
    const w = await workspace(files);
    try {
      const run = collect(w);
      assert.equal(run.status, 1, `${label}: ${run.out}`);
      await assert.rejects(readFile(run.output), `${label}: evidence file written`);
    } finally { await w.cleanup(); }
  }
});

test('P07-D9: a symlinked result, an empty results directory and a missing catalog are refused', async () => {
  const w = await workspace({ 'native.json': complete['native.json'] });
  try {
    await symlink('/etc/hostname', path.join(w.dir, 'results', 'link.json'));
    assert.equal(collect(w).status, 1);
    await rm(path.join(w.dir, 'results', 'link.json'));
    await rm(path.join(w.dir, 'results', 'native.json'));
    const empty = collect(w);
    assert.equal(empty.status, 1, empty.out);
    await writeFile(path.join(w.dir, 'results', 'native.json'), JSON.stringify(complete['native.json']));
    await rm(path.join(w.dir, 'required.json'));
    assert.equal(collect(w).status, 1);
  } finally { await w.cleanup(); }
});

test('P07-D9: results for scenarios outside the catalog are shown but cannot satisfy it', async () => {
  const w = await workspace({ 'only-extra.json': results({ scenarios: [{ id: 'X99', result: 'pass', evidence: 'docs/x.md' }] }) });
  try {
    const run = collect(w);
    assert.equal(run.status, 3, run.out);
    const text = await readFile(run.output, 'utf8');
    assert.match(text, /Additional results/);
    assert.match(text, /X99/);
    assert.match(text, /\| S01 \| native-x86_64 \| — \| not run \|/);
  } finally { await w.cleanup(); }
});

test('P07-D9: duplicate rows are all listed and the worst one decides; output ignores file order', async () => {
  const files = { 'a.json': complete['native.json'], 'b.json': complete['compose.json'],
    'c.json': results({ profile: 'compose-sqlite', client: 'rerun', scenarios: [{ id: 'S01', result: 'fail' }] }) };
  const w = await workspace(files);
  try {
    const run = collect(w);
    assert.equal(run.status, 3, run.out);
    const text = await readFile(run.output, 'utf8');
    assert.match(text, /\| S01 \| compose-sqlite \| none \| pass \|/);
    assert.match(text, /\| S01 \| compose-sqlite \| rerun \| fail \|/);
    const w2 = await workspace({ 'a.json': files['c.json'], 'b.json': files['b.json'], 'c.json': files['a.json'] });
    try {
      const second = collect(w2);
      const strip = (t) => t.replace(/^\| [0-9a-f]{64} \| [a-z]\.json \|$/gm, '').replace(/\b[abc]\.json/g, 'F');
      assert.equal(strip(await readFile(second.output, 'utf8')), strip(text));
    } finally { await w2.cleanup(); }
  } finally { await w.cleanup(); }
});

test('P07-D9: a pipe or markup in a reason cannot break out of its table cell', async () => {
  const w = await workspace({ 'native.json': complete['native.json'],
    'compose.json': results({ profile: 'compose-sqlite', scenarios: [{ id: 'S01', result: 'skip', reason: 'a | b <script>x</script>' }] }) });
  try {
    const run = collect(w);
    const text = await readFile(run.output, 'utf8');
    assert.ok(!text.includes('<script>'));
    assert.match(text, /a \\\| b/);
  } finally { await w.cleanup(); }
});

test('P07-D9: refuses to replace an existing evidence file and a malformed version', async () => {
  const w = await workspace(complete);
  try {
    assert.equal(collect(w).status, 0);
    const again = collect(w);
    assert.equal(again.status, 1);
    assert.match(again.out, /refusing to replace/);
    const bad = spawnSync('bash', [COLLECT, 'v0.1.0', '--commit', COMMIT, '--required', path.join(w.dir, 'required.json'),
      '--results', path.join(w.dir, 'results')], { encoding: 'utf8' });
    assert.equal(bad.status, 2);
  } finally { await w.cleanup(); }
});

test('P07-D9: the shipped catalog lists the S, R and P07 scenarios with profiles', async () => {
  const catalog = JSON.parse(await readFile(path.join(ROOT, 'docs/release/required-scenarios.json'), 'utf8'));
  assert.equal(catalog.schema, 'blindpass-required-scenarios-v1');
  const ids = catalog.scenarios.map((s) => s.id);
  for (const id of ['S01', 'S02', 'S03', 'S04', 'S05', 'S06', 'S07', 'R01', 'R02', 'R03',
    'P07-I01', 'P07-I02', 'P07-I03', 'P07-I04', 'P07-I05', 'P07-I06', 'P07-E01', 'P07-E02', 'P07-E03', 'P07-E04',
    'P00-ACCEPTED', 'P01-ACCEPTED', 'P02-ACCEPTED', 'P03-ACCEPTED', 'P04-ACCEPTED', 'P05-ACCEPTED', 'P06-ACCEPTED']) {
    assert.ok(ids.includes(id), `catalog lacks ${id}`);
  }
  assert.equal(new Set(ids).size, ids.length, 'duplicate id in catalog');
  for (const s of catalog.scenarios) assert.ok(Array.isArray(s.profiles) && s.profiles.length > 0, s.id);
  // Evidence for the real catalog with no results at all must block, not pass.
  const w = await workspace({ 'native.json': complete['native.json'] });
  try {
    await writeFile(path.join(w.dir, 'required.json'), JSON.stringify(catalog));
    const run = collect(w);
    assert.equal(run.status, 3, run.out);
  } finally { await w.cleanup(); }
});
