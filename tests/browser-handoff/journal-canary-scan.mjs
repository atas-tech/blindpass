// SPDX-License-Identifier: AGPL-3.0-only
// Shared canary scanner for the disposable-VM guests. Several scanned units log
// nothing (StandardOutput=null/inherit-to-socket, StandardError=null), so an empty
// or wrongly-selected journal would pass a plain `!journal.includes(canary)` check.
// A scan is therefore only accepted with positive controls:
//   1. the scanned source is non-empty;
//   2. every expected unit has at least one systemd lifecycle line in it;
//   3. the scanner detects an injected random control token (and does not report
//      it in the clean source);
//   4. for the journal, a transient control unit really logs the token through
//      journald and it is read back by the same journalctl query.
// Failures use fixed codes and never reproduce a canary or any scanned bytes.
import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { chown, lstat, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { join, isAbsolute } from 'node:path';

const MIN_CANARY_BYTES = 8;
// systemd lifecycle messages as printed by `journalctl -o cat` (which drops the
// unit field): "Started X.service - ...", "X.service: Deactivated successfully.",
// "Stopping/Stopped X.service", "X.service: Failed with result ...", etc.
const LIFECYCLE = /\b(?:Started|Starting|Stopping|Stopped|Finished|Deactivated|Consumed|Failed|Main process exited|Succeeded)\b/;
const UNIT_NAME = /^[A-Za-z0-9_.:\\-]{1,200}(?:@\*)?$/;
const fail = code => new Error(code);
const bytesOf = value => (Buffer.isBuffer(value) ? value : Buffer.from(String(value)));
const sleepFor = ms => new Promise(resolve => setTimeout(resolve, ms));

function validateCanaries(canaries) {
  if (!Array.isArray(canaries) || !canaries.length) throw fail('journal_scan_configuration');
  return canaries.map(value => {
    const bytes = typeof value === 'string' ? Buffer.from(value) : Buffer.isBuffer(value) ? value : undefined;
    if (!bytes || bytes.length < MIN_CANARY_BYTES) throw fail('journal_scan_configuration');
    return bytes;
  });
}

// Number of distinct canaries found in data. Never returns or throws a canary.
export function detectCanaries(data, canaries) {
  const needles = validateCanaries(canaries); const haystack = bytesOf(data);
  return needles.filter(needle => haystack.includes(needle)).length;
}

// "name@*" matches only instances of that template; other names match exactly
// (".service" is implied). The surrounding characters are constrained so that
// "blindpass-browser@" never matches "blindpass-browser-supervisor@...".
export function unitPattern(unit) {
  if (typeof unit !== 'string' || !UNIT_NAME.test(unit)) throw fail('journal_scan_configuration');
  const escape = text => text.replace(/[.\\]/g, '\\$&');
  const body = unit.endsWith('@*')
    ? `${escape(unit.slice(0, -1))}[A-Za-z0-9_.:\\\\-]+\\.service`
    : `${escape(unit.endsWith('.service') ? unit.slice(0, -8) : unit)}\\.service`;
  return new RegExp(`(?<![A-Za-z0-9_.:@\\\\-])${body}(?![A-Za-z0-9_.:@\\\\-])`);
}

const controlToken = () => `P05-SCAN-CONTROL-${randomBytes(16).toString('hex')}`;

// Verifies the controls above against one captured journal/text source.
export function assertScannedClean({ output, canaries, expectedUnits, detect = detectCanaries }) {
  validateCanaries(canaries);
  if (!Array.isArray(expectedUnits) || !expectedUnits.length) throw fail('journal_scan_configuration');
  const patterns = expectedUnits.map(unitPattern);
  const source = typeof output === 'string' ? Buffer.from(output) : Buffer.isBuffer(output) ? output : undefined;
  if (!source || !source.toString('utf8').trim()) throw fail('journal_scan_empty');
  // The scanner must see an injected token and must not see it in the clean source.
  const control = controlToken();
  if (detect(Buffer.concat([source, Buffer.from(`\n${control}\n`)]), [control]) !== 1 || detect(source, [control]) !== 0) {
    throw fail('journal_scanner_control_failed');
  }
  if (detect(source, canaries) > 0) throw fail('journal_canary_detected');
  const lines = source.toString('utf8').split('\n').filter(line => line.trim());
  if (!patterns.every(pattern => lines.some(line => LIFECYCLE.test(line) && pattern.test(line)))) throw fail('journal_scan_unit_missing');
  return { lines: lines.length, units: patterns.length, canaries: canaries.length, control: 'detected' };
}

// Reads the journal for `units` plus a transient control unit whose stdout is a
// random token, and scans it. Waits (bounded) for journald to catch up, but a
// canary is never retried away.
export async function scanJournal({ units, expectedUnits = units, canaries, execFile = execFileSync, sleep = sleepFor,
  attempts = 20, delayMs = 250, journalctl = '/usr/bin/journalctl', systemdRun = '/usr/bin/systemd-run' } = {}) {
  validateCanaries(canaries);
  if (!Array.isArray(units) || !units.length || !Number.isSafeInteger(attempts) || attempts < 1 || attempts > 100) throw fail('journal_scan_configuration');
  units.forEach(unitPattern);
  const controlUnit = `p05-journal-control-${randomBytes(8).toString('hex')}`; const token = `P05-JOURNAL-CONTROL-${randomBytes(16).toString('hex')}`;
  try {
    execFile(systemdRun, ['--quiet', '--wait', '--collect', `--unit=${controlUnit}`, '-E', 'P05_JOURNAL_CONTROL', '/usr/bin/printenv', 'P05_JOURNAL_CONTROL'],
      { env: { ...process.env, P05_JOURNAL_CONTROL: token }, stdio: ['ignore', 'ignore', 'ignore'] });
  } catch { throw fail('journal_scan_control_missing'); }
  let last;
  for (let attempt = 1; attempt <= attempts; attempt++) {
    let output;
    try {
      execFile(journalctl, ['--sync'], { stdio: ['ignore', 'ignore', 'ignore'] });
      output = execFile(journalctl, ['--no-pager', '-o', 'cat', ...units.flatMap(unit => ['-u', unit]), '-u', controlUnit],
        { maxBuffer: 64 * 1024 * 1024, stdio: ['ignore', 'pipe', 'ignore'] });
    } catch { throw fail('journal_scan_unreadable'); }
    const source = typeof output === 'string' ? Buffer.from(output) : output;
    if (Buffer.isBuffer(source) && detectCanaries(source, canaries) > 0) throw fail('journal_canary_detected');
    try {
      if (!Buffer.isBuffer(source) || !source.includes(Buffer.from(token))) throw fail('journal_scan_control_missing');
      return assertScannedClean({ output: source, canaries, expectedUnits });
    } catch (error) {
      if (!['journal_scan_control_missing', 'journal_scan_unit_missing', 'journal_scan_empty'].includes(error.message)) throw error;
      last = error;
    }
    if (attempt < attempts) await sleep(delayMs);
  }
  throw last;
}

async function walk(directory, visit) {
  let entries;
  try { entries = await readdir(directory, { withFileTypes: true }); } catch { throw fail('canary_scan_unreadable'); }
  for (const entry of entries) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) await walk(path, visit);
    else if (entry.isFile()) {
      let bytes;
      try { bytes = await readFile(path); } catch { throw fail('canary_scan_unreadable'); }
      try { await visit(entry.name, bytes); } finally { bytes.fill(0); }
    }
  }
}

// Scans every regular file below `directory`. The directory must be readable and
// contain content: `required` names marker files the harness placed there, and an
// otherwise empty tree fails (an agent output/home directory that silently lost
// its contents would pass a recursive "no canary found" loop). A control file
// holding a random token is written, must be found by the same walk, and is
// removed again before the real scan.
export async function scanDirectory(directory, canaries, { required = [], detect = detectCanaries } = {}) {
  validateCanaries(canaries);
  if (typeof directory !== 'string' || !isAbsolute(directory) || !Array.isArray(required)
    || required.some(name => typeof name !== 'string' || !name || isAbsolute(name) || name.split('/').includes('..') || name.includes('\0'))) {
    throw fail('journal_scan_configuration');
  }
  const control = controlToken(); const controlPath = join(directory, `.p05-scan-control-${randomBytes(8).toString('hex')}`);
  try { await writeFile(controlPath, control, { mode: 0o600, flag: 'wx' }); } catch { throw fail('canary_scan_unreadable'); }
  try {
    let seen = 0;
    await walk(directory, async (_name, bytes) => { seen += detect(bytes, [control]); });
    if (seen !== 1) throw fail('journal_scanner_control_failed');
  } finally { await rm(controlPath, { force: true }); }
  let files = 0;
  await walk(directory, async (_name, bytes) => {
    files++;
    if (detect(bytes, canaries) > 0) throw fail('journal_canary_detected');
  });
  for (const name of required) {
    let info;
    try { info = await lstat(join(directory, name)); } catch { throw fail('canary_scan_required_missing'); }
    if (!info.isFile() || info.size < 1) throw fail('canary_scan_required_missing');
  }
  if (files < 1) throw fail('canary_scan_empty');
  return { files, canaries: canaries.length, control: 'detected' };
}

// Non-secret marker that a harness drops into a directory whose contents it
// scans, so the scan can require that the directory still has content.
export async function writeScanMarker(directory, name = '.p05-scan-marker', { uid, gid } = {}) {
  await mkdir(directory, { recursive: true });
  const path = join(directory, name);
  await writeFile(path, 'p05-scan-marker\n', { mode: 0o600 });
  if (uid !== undefined) await chown(path, uid, gid);
  return path;
}
