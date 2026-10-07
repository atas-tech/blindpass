// SPDX-License-Identifier: AGPL-3.0-only
// P07.6: publication needs complete, regenerable evidence for the exact tested source.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { spawnSync } from 'node:child_process';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const GATE = path.join(ROOT, 'scripts/release/check-publish-gate.sh');
const COLLECT = path.join(ROOT, 'scripts/release/collect-evidence.sh');
const VERSION = '0.1.0';
const CATALOG = { schema: 'blindpass-required-scenarios-v1', scenarios: [{ id: 'S01', title: 'Code role', profiles: ['native-x86_64'] }] };

function git(repo, ...args) {
  const r = spawnSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@example.invalid', ...args], { cwd: repo, encoding: 'utf8' });
  assert.equal(r.status, 0, `git ${args.join(' ')}: ${r.stderr}`);
  return r.stdout.trim();
}

function results(commit, result = 'pass') {
  return { schema: 'blindpass-release-evidence-v1', commit, date: '2026-10-06', profile: 'native-x86_64', client: 'none', environment: 'Debian 12 guest',
    scenarios: [result === 'pass' ? { id: 'S01', result, evidence: 'docs/testing/evidence/s01.md' } : { id: 'S01', result, reason: 'rerun pending' }] };
}

// tested commit C0 (code), then an evidence-only commit with results and the generated evidence.md
async function repo({ result = 'pass', makeEvidence = true } = {}) {
  const dir = await mkdtemp(path.join(tmpdir(), 'blindpass-gate-'));
  git(dir, 'init', '-q', '-b', 'main');
  await mkdir(path.join(dir, 'docs/release'), { recursive: true });
  await writeFile(path.join(dir, 'docs/release/required-scenarios.json'), JSON.stringify(CATALOG));
  await writeFile(path.join(dir, 'code.txt'), 'tested source\n');
  git(dir, 'add', '-A'); git(dir, 'commit', '-q', '-m', 'tested source');
  const tested = git(dir, 'rev-parse', 'HEAD');
  const release = path.join(dir, 'docs/release', `v${VERSION}`);
  await mkdir(path.join(release, 'results'), { recursive: true });
  await writeFile(path.join(release, 'results/native.json'), JSON.stringify(results(tested, result)));
  if (makeEvidence) {
    spawnSync('bash', [COLLECT, VERSION, '--commit', tested, '--required', path.join(dir, 'docs/release/required-scenarios.json'),
      '--results', path.join(release, 'results'), '--output', path.join(release, 'evidence.md')], { encoding: 'utf8' });
  }
  return { dir, tested, release, commit: () => { git(dir, 'add', '-A'); git(dir, 'commit', '-q', '-m', 'evidence'); }, cleanup: () => rm(dir, { recursive: true, force: true }) };
}

function gate(r, version = VERSION) {
  const run = spawnSync('bash', [GATE, version, '--repo', r.dir], { encoding: 'utf8' });
  return { status: run.status, out: `${run.stdout}${run.stderr}` };
}

test('P07.6: complete evidence for an ancestor source commit with a docs-only difference passes', async () => {
  const r = await repo();
  try { r.commit(); const run = gate(r); assert.equal(run.status, 0, run.out); assert.match(run.out, /publication gate OK/); } finally { await r.cleanup(); }
});

test('P07.6: a blocked, missing or hand-edited evidence file refuses publication', async () => {
  const blocked = await repo({ result: 'skip' });
  const missing = await repo({ makeEvidence: false });
  const edited = await repo();
  try {
    blocked.commit(); missing.commit();
    assert.notEqual(gate(blocked).status, 0, 'a skipped required scenario passed the gate');
    const m = gate(missing); assert.notEqual(m.status, 0); assert.match(m.out, /evidence\.md/);
    const text = await readFile(path.join(edited.release, 'evidence.md'), 'utf8');
    await writeFile(path.join(edited.release, 'evidence.md'), text.replace('| pass |', '| pass | (edited) |'));
    edited.commit();
    const e = gate(edited); assert.notEqual(e.status, 0); assert.match(e.out, /regenerat/);
    // A forged "eligible" header over blocked results is caught by regeneration too.
    const forged = await readFile(path.join(blocked.release, 'evidence.md'), 'utf8').catch(() => '');
    assert.ok(!forged.includes('ELIGIBLE FOR REVIEW'), 'a blocked matrix claimed eligibility');
  } finally { await blocked.cleanup(); await missing.cleanup(); await edited.cleanup(); }
});

test('P07.6: code that changed after the tested commit refuses publication', async () => {
  const r = await repo();
  try {
    await writeFile(path.join(r.dir, 'code.txt'), 'changed after testing\n');
    r.commit();
    const run = gate(r); assert.notEqual(run.status, 0); assert.match(run.out, /outside docs\/release/);
  } finally { await r.cleanup(); }
});

test('P07.6: a source commit that is not an ancestor, or a malformed version, refuses publication', async () => {
  const r = await repo();
  try {
    r.commit();
    git(r.dir, 'checkout', '-q', '--orphan', 'other');
    git(r.dir, 'rm', '-rfq', '.');
    await mkdir(path.join(r.dir, 'docs/release'), { recursive: true });
    await writeFile(path.join(r.dir, 'docs/release/required-scenarios.json'), JSON.stringify(CATALOG));
    git(r.dir, 'add', '-A'); git(r.dir, 'commit', '-q', '-m', 'unrelated history');
    await mkdir(path.join(r.release, 'results'), { recursive: true });
    git(r.dir, 'checkout', '-q', 'main', '--', 'docs/release'); git(r.dir, 'commit', '-q', '-m', 'copy evidence');
    const run = gate(r); assert.notEqual(run.status, 0); assert.match(run.out, /not an ancestor/);
    for (const version of ['v0.1.0', '0.1', '../0.1.0']) assert.notEqual(gate(r, version).status, 0, version);
  } finally { await r.cleanup(); }
});
