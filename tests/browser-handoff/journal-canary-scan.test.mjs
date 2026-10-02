// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { assertScannedClean, detectCanaries, scanDirectory, scanJournal, unitPattern } from './journal-canary-scan.mjs';

const CANARY = 'P05-SCAN-CANARY-0123456789abcdef0123456789abcdef';
const COOKIE = 'cookie_value_0123456789abcdef0123456789abcdef';
// Representative `journalctl -o cat` output: units that log nothing still have
// systemd lifecycle lines.
const lifecycle = unit => [`Started ${unit}.service - BlindPass test unit.`, `${unit}.service: Deactivated successfully.`,
  `${unit}.service: Consumed 120ms CPU time.`].join('\n');
const clean = ['blindpass-login-helper@0-1111-0', 'blindpass-browser@0-2222-0'].map(lifecycle).join('\n');
const expected = ['blindpass-login-helper@*', 'blindpass-browser@*'];
const thrown = (code, extra = () => true) => error => error.message === code && !String(error.stack).includes(CANARY) && extra(error) === true;
const none = () => {};

test('scanner: empty or whitespace-only journal output fails closed', () => {
  for (const output of ['', '\n', ' \n\t\n', Buffer.alloc(0), Buffer.from('\n\n'), undefined, null]) {
    assert.throws(() => assertScannedClean({ output, canaries: [CANARY], expectedUnits: expected }), thrown('journal_scan_empty'));
  }
});

test('scanner: a missing expected unit fails closed (a lifecycle line is required for every unit)', () => {
  const onlyHelper = lifecycle('blindpass-login-helper@0-1111-0');
  assert.throws(() => assertScannedClean({ output: onlyHelper, canaries: [CANARY], expectedUnits: expected }), thrown('journal_scan_unit_missing'));
  // Mentioning a unit without a systemd lifecycle verb is not evidence that it ran.
  const bare = `${onlyHelper}\nblindpass-browser@0-2222-0.service is mentioned by an unrelated line`;
  assert.throws(() => assertScannedClean({ output: bare, canaries: [CANARY], expectedUnits: expected }), thrown('journal_scan_unit_missing'));
  // Another template with a similar prefix does not satisfy the expectation.
  const wrong = `${onlyHelper}\n${lifecycle('blindpass-browser-supervisor@0-2222-0')}`;
  assert.throws(() => assertScannedClean({ output: wrong, canaries: [CANARY], expectedUnits: expected }), thrown('journal_scan_unit_missing'));
  // Exact names must match exactly.
  assert.throws(() => assertScannedClean({ output: lifecycle('p05-browser-agent-other'), canaries: [CANARY], expectedUnits: ['p05-browser-agent.service'] }), thrown('journal_scan_unit_missing'));
  assertScannedClean({ output: lifecycle('p05-browser-agent'), canaries: [CANARY], expectedUnits: ['p05-browser-agent.service'] });
  assert.throws(() => assertScannedClean({ output: clean, canaries: [CANARY], expectedUnits: [] }), thrown('journal_scan_configuration'));
});

test('scanner: an injected canary is detected, including split-free binary and string forms', () => {
  for (const output of [`${clean}\nleak ${CANARY}\n`, Buffer.from(`${clean}\n${CANARY}`), `${CANARY}\n${clean}`]) {
    assert.throws(() => assertScannedClean({ output, canaries: [COOKIE, CANARY], expectedUnits: expected }), thrown('journal_canary_detected', error => !error.message.includes(CANARY)));
  }
  assert.equal(detectCanaries(`x ${CANARY} y`, [CANARY, COOKIE]), 1);
  assert.equal(detectCanaries(Buffer.from(`${CANARY}${COOKIE}`), [Buffer.from(CANARY), COOKIE]), 2);
  assert.equal(detectCanaries(clean, [CANARY, COOKIE]), 0);
});

test('scanner: clean data with all expected units passes and reports counts only', () => {
  const summary = assertScannedClean({ output: clean, canaries: [CANARY, COOKIE], expectedUnits: expected });
  assert.deepEqual(summary, { lines: 6, units: 2, canaries: 2, control: 'detected' });
  assert.ok(!JSON.stringify(summary).includes(CANARY));
  assertScannedClean({ output: Buffer.from(clean), canaries: [CANARY], expectedUnits: expected });
});

test('scanner: vacuous canaries are rejected instead of silently matching nothing or everything', () => {
  for (const canaries of [[], [''], [undefined], [null], [7], ['short'], [CANARY, ''], 'not-an-array', [Buffer.alloc(0)]]) {
    assert.throws(() => assertScannedClean({ output: clean, canaries, expectedUnits: expected }), thrown('journal_scan_configuration'));
    assert.throws(() => detectCanaries(clean, canaries), thrown('journal_scan_configuration'));
  }
});

test('scanner: a scanner that cannot detect its injected control fails the run', () => {
  const blind = () => 0;
  assert.throws(() => assertScannedClean({ output: clean, canaries: [CANARY], expectedUnits: expected, detect: blind }), thrown('journal_scanner_control_failed'));
  // A scanner that reports everything also fails: the control must be absent from the clean source.
  const noisy = () => 1;
  assert.throws(() => assertScannedClean({ output: clean, canaries: [CANARY], expectedUnits: expected, detect: noisy }), thrown('journal_scanner_control_failed'));
});

test('unitPattern: templates match only instances of that template and exact names stay exact', () => {
  assert.ok(unitPattern('blindpass-login-helper@*').test('blindpass-login-helper@0-1-2.service'));
  assert.ok(!unitPattern('blindpass-login-helper@*').test('blindpass-login-helper.service'));
  assert.ok(!unitPattern('blindpass-login-helper@*').test('xblindpass-login-helper@0.service'));
  assert.ok(unitPattern('p05-ai-codex.service').test('p05-ai-codex.service'));
  assert.ok(!unitPattern('p05-ai-codex.service').test('p05-ai-codex2.service'));
  assert.ok(unitPattern('p05-browser-agent').test('p05-browser-agent.service'));
  for (const bad of ['', 'a b', 'a;b', '../x', undefined]) assert.throws(() => unitPattern(bad), thrown('journal_scan_configuration'));
});

function fakeJournal({ lifecycleLines = clean, controlVisible = true, failures = 0 } = {}) {
  const calls = []; let reads = 0; let control; let controlUnit;
  const execFile = (file, args, options) => {
    calls.push([file, ...args]);
    if (file.endsWith('systemd-run')) {
      control = options.env.P05_JOURNAL_CONTROL; controlUnit = args.find(value => value.startsWith('--unit=')).slice(7);
      return '';
    }
    if (args.includes('--sync')) return '';
    reads++;
    assert.ok(args.includes('-o') && args.includes('cat') && args.includes('--no-pager'));
    const base = reads <= failures ? '' : lifecycleLines;
    const lines = controlVisible && control ? `${base}\nStarted ${controlUnit}.service - control.\n${control}\n` : `${base}\n`;
    return Buffer.from(lines);
  };
  return { execFile, calls, get reads() { return reads; } };
}

test('scanJournal: runs a real-journal control unit, requires it to be seen, then passes clean data', async () => {
  const journal = fakeJournal();
  const summary = await scanJournal({ units: expected, canaries: [CANARY], execFile: journal.execFile, sleep: none });
  assert.equal(summary.control, 'detected'); assert.equal(summary.units, 2);
  assert.ok(journal.calls.some(call => call[0].endsWith('systemd-run') && call.some(value => /^--unit=p05-journal-control-[a-f0-9]{16}$/.test(value))));
  const read = journal.calls.find(call => call.includes('--no-pager') && !call.includes('--sync'));
  for (const unit of expected) assert.ok(read.includes(unit));
  assert.ok(read.some(value => /^p05-journal-control-[a-f0-9]{16}$/.test(value)), 'control unit is part of the scanned query');
  assert.ok(!JSON.stringify(summary).includes(CANARY));
});

test('scanJournal: a journal that never shows the control unit output fails closed', async () => {
  const journal = fakeJournal({ controlVisible: false });
  await assert.rejects(scanJournal({ units: expected, canaries: [CANARY], execFile: journal.execFile, sleep: none, attempts: 3 }), thrown('journal_scan_control_missing'));
  assert.equal(journal.reads, 3);
});

test('scanJournal: waits for late lifecycle lines but fails when an expected unit never appears', async () => {
  const late = fakeJournal({ failures: 2 });
  assert.equal((await scanJournal({ units: expected, canaries: [CANARY], execFile: late.execFile, sleep: none, attempts: 5 })).control, 'detected');
  assert.equal(late.reads, 3);
  const missing = fakeJournal({ lifecycleLines: lifecycle('blindpass-login-helper@0-1111-0') });
  await assert.rejects(scanJournal({ units: expected, canaries: [CANARY], execFile: missing.execFile, sleep: none, attempts: 2 }), thrown('journal_scan_unit_missing'));
  const empty = fakeJournal({ lifecycleLines: '' });
  await assert.rejects(scanJournal({ units: expected, canaries: [CANARY], execFile: empty.execFile, sleep: none, attempts: 2 }), error => ['journal_scan_empty', 'journal_scan_unit_missing'].includes(error.message));
});

test('scanJournal: a leaked canary is reported without being reproduced, and is never retried away', async () => {
  const leaking = fakeJournal({ lifecycleLines: `${clean}\nsecret ${CANARY}` });
  await assert.rejects(scanJournal({ units: expected, canaries: [CANARY], execFile: leaking.execFile, sleep: none, attempts: 5 }), thrown('journal_canary_detected'));
  assert.equal(leaking.reads, 1);
});

async function tree(t) {
  const root = await mkdtemp(join(tmpdir(), 'blindpass-scan-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  return root;
}

test('scanDirectory: empty and missing directories fail closed where content is expected', async t => {
  const root = await tree(t);
  await assert.rejects(scanDirectory(root, [CANARY]), thrown('canary_scan_empty'));
  await assert.rejects(scanDirectory(join(root, 'missing'), [CANARY]), thrown('canary_scan_unreadable'));
  await mkdir(join(root, 'nested'));
  await assert.rejects(scanDirectory(root, [CANARY]), thrown('canary_scan_empty'), 'directories alone are not content');
  await writeFile(join(root, 'file'), 'plain');
  await assert.rejects(scanDirectory(join(root, 'file'), [CANARY]), thrown('canary_scan_unreadable'));
});

test('scanDirectory: required marker files must exist and be non-empty', async t => {
  const root = await tree(t);
  await writeFile(join(root, 'other'), 'x');
  await assert.rejects(scanDirectory(root, [CANARY], { required: ['.marker'] }), thrown('canary_scan_required_missing'));
  await writeFile(join(root, '.marker'), '');
  await assert.rejects(scanDirectory(root, [CANARY], { required: ['.marker'] }), thrown('canary_scan_required_missing'));
  await writeFile(join(root, '.marker'), 'marker');
  assert.deepEqual(await scanDirectory(root, [CANARY], { required: ['.marker'] }), { files: 2, canaries: 1, control: 'detected' });
  for (const bad of ['../x', '/etc/passwd', 'a/../b', '']) await assert.rejects(scanDirectory(root, [CANARY], { required: [bad] }), thrown('journal_scan_configuration'));
});

test('scanDirectory: nested canaries are detected, the control file never lingers and canary values are not reported', async t => {
  const root = await tree(t);
  await mkdir(join(root, 'a', 'b'), { recursive: true });
  await writeFile(join(root, 'a', 'b', 'artifact.txt'), `report ${CANARY} tail`);
  await assert.rejects(scanDirectory(root, [CANARY, COOKIE]), thrown('journal_canary_detected'));
  assert.deepEqual((await readdir(root)).sort(), ['a']);
  const clear = await tree(t); await writeFile(join(clear, 'artifact.txt'), 'nothing secret');
  assert.deepEqual(await scanDirectory(clear, [CANARY]), { files: 1, canaries: 1, control: 'detected' });
  assert.deepEqual(await readdir(clear), ['artifact.txt']);
});

test('scanDirectory: a scanner that cannot see its control file fails closed', async t => {
  const root = await tree(t); await writeFile(join(root, 'artifact.txt'), 'plain');
  await assert.rejects(scanDirectory(root, [CANARY], { detect: () => 0 }), thrown('journal_scanner_control_failed'));
  assert.deepEqual(await readdir(root), ['artifact.txt']);
});
