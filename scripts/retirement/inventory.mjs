#!/usr/bin/env node
// Retirement inventory (P08.4). Lists every file that still refers to the legacy SPS stack, with the owner and
// the disposition a reviewer recorded for it. The scan is deterministic: it depends on file contents only, never
// on timestamps or ordering. Human decisions live in dispositions.tsv; this program only reads that file.
import { execFileSync } from 'node:child_process';
import { lstatSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DISPOSITIONS = new Map([
  ['retain', 'stays after retirement (retained client, contract, document or packaging), reworded where it still names SPS'],
  ['relocate', 'moves to a maintained package or harness before the legacy file is deleted'],
  ['delete', 'removed in slice 8 once the retirement gate passes'],
  ['archive', 'kept as read-only history (docs/legacy or evidence) and no longer an active path']
]);
const STATUSES = new Map([
  ['proposed', 'a proposal; the reviewer has not accepted it'],
  ['accepted', 'the reviewer accepted it in the phase review record']
]);
// This document and the generator inputs describe the patterns, so scanning them would never settle.
const EXCLUDED = ['docs/release/retirement-inventory.md', 'scripts/retirement/', 'scripts/tests/retirement-inventory.test.mjs'];
// Files that leave with a legacy package are listed by path even when their content never names SPS (SQL
// migrations, configs, binary assets), so a deletion rule cannot silently miss one.
const LEGACY_PATH = ['legacy-path', 'any file inside packages/sps-server or packages/dashboard, or one of the five legacy Unraid templates, whatever it contains',
  /^(?:packages\/(?:sps-server|dashboard)\/|deploy\/unraid\/blindpass-(?:sps-server|dashboard|redis|postgres|browser-ui)\.xml$)/];
const PATTERNS = [
  ['sps-server', 'package, directory or image name', [/sps-server/g]],
  ['SPS_', 'SPS_* environment variables', [/SPS_/g]],
  ['sps_', 'sps_* identifiers and token prefixes', [/sps_/g]],
  ['redis', 'Redis and ioredis, not "redistribute"', [/(?:\b|io)redis(?!tribut)/gi]],
  ['dashboard-package', 'packages/dashboard or @blindpass/dashboard', [/packages\/dashboard|@blindpass\/dashboard/g]],
  ['unraid-template', 'the five legacy Unraid template file names', [/blindpass-(?:sps-server|dashboard|redis|postgres|browser-ui)\.xml/g]],
  ['legacy-image', 'legacy image names (SPS API, dashboard, input page)', [/blindpass-(?:sps-server|dashboard|browser-ui)(?![\w.-])/g]],
  ['sps-ref', 'the word SPS, sps-bridge/-client/-base-url and SpsClient-style names',
    [/(?<![\w-])sps(?![\w-])|sps-(?:bridge|client|base-url)/gi, /Sps(?=[A-Z])/g]]
];

function usage(message) {
  if (message) process.stderr.write(`${message}\n`);
  process.stderr.write('usage: inventory.sh [--root DIR] [--dispositions FILE] [--check [--accepted]]\n');
  process.exit(2);
}

const options = { root: path.resolve(HERE, '../..'), dispositions: path.join(HERE, 'dispositions.tsv'), check: false, accepted: false };
for (let i = 2; i < process.argv.length; i += 1) {
  const arg = process.argv[i];
  if (arg === '--root') options.root = path.resolve(process.argv[++i] ?? usage('--root needs a directory'));
  else if (arg === '--dispositions') options.dispositions = path.resolve(process.argv[++i] ?? usage('--dispositions needs a file'));
  else if (arg === '--check') options.check = true;
  else if (arg === '--accepted') options.accepted = true;
  else usage(`unknown argument: ${arg}`);
}
if (options.accepted && !options.check) usage('--accepted only applies to --check');

function globToRegExp(glob) {
  let out = '';
  for (let i = 0; i < glob.length; i += 1) {
    const c = glob[i];
    if (c === '*') {
      if (glob[i + 1] === '*') {
        if (glob[i + 2] === '/') { out += '(?:.*/)?'; i += 2; } else { out += '.*'; i += 1; }
      } else out += '[^/]*';
    } else if (c === '?') out += '[^/]';
    else out += c.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  }
  return new RegExp(`^${out}$`);
}

function readRules(file) {
  let text;
  try { text = readFileSync(file, 'utf8'); } catch (error) {
    process.stderr.write(`cannot read ${file}: ${error.code ?? error.message}\n`);
    process.exit(2);
  }
  const rules = [];
  const errors = [];
  text.split('\n').forEach((raw, index) => {
    const line = raw.replace(/\r$/, '');
    if (line.trim() === '' || line.startsWith('#')) return;
    const fields = line.split('\t');
    const where = `${file}:${index + 1}`;
    if (fields.length < 5) { errors.push(`${where}: expected glob, owner, disposition, status and note separated by tabs`); return; }
    const [glob, owner, disposition, status, ...note] = fields;
    if (glob.trim() === '' || owner.trim() === '') { errors.push(`${where}: glob and owner must not be empty`); return; }
    if (!DISPOSITIONS.has(disposition)) { errors.push(`${where}: disposition must be one of ${[...DISPOSITIONS.keys()].join(', ')}`); return; }
    if (!STATUSES.has(status)) { errors.push(`${where}: status must be one of ${[...STATUSES.keys()].join(', ')}`); return; }
    rules.push({ glob, owner, disposition, status, note: note.join(' ').trim(), re: globToRegExp(glob), files: 0, hits: 0 });
  });
  if (errors.length > 0) {
    process.stderr.write(`${errors.join('\n')}\n`);
    process.exit(2);
  }
  return rules;
}

function listFiles(root) {
  let out;
  try {
    out = execFileSync('git', ['-C', root, 'ls-files', '-co', '--exclude-standard', '-z'], { maxBuffer: 256 * 1024 * 1024 });
  } catch (error) {
    process.stderr.write(`cannot list files under ${root}: ${error.message}\n`);
    process.exit(2);
  }
  return out.toString('utf8').split('\0').filter(Boolean)
    .filter((name) => !EXCLUDED.some((prefix) => (prefix.endsWith('/') ? name.startsWith(prefix) : name === prefix)));
}

const CODE_FILE = /\.[cm]?[jt]sx?$/;

// Static imports, re-exports, side-effect imports, dynamic import() and require() all load the target.
function importSpecifiers(text) {
  const found = new Set();
  for (const re of [
    /(?:^|\n)[ \t]*(?:import|export)\s[^;'"]*?from\s*["']([^"']+)["']/g,
    /(?:^|\n)[ \t]*import\s*["']([^"']+)["']/g,
    /\bimport\(\s*["']([^"']+)["']\s*\)/g,
    /\brequire\(\s*["']([^"']+)["']\s*\)/g
  ]) for (const match of text.matchAll(re)) found.add(match[1]);
  return [...found];
}

function importTarget(file, specifier) {
  if (specifier.startsWith('.')) return path.posix.normalize(path.posix.join(path.posix.dirname(file), specifier));
  const workspace = /^@blindpass\/([^/]+)/.exec(specifier);
  return workspace ? `packages/${workspace[1]}/index` : null;
}

function scan(root, name) {
  const full = path.join(root, name);
  let stat;
  try { stat = lstatSync(full); } catch { return null; } // tracked but deleted in the working tree
  if (!stat.isFile()) return null;
  const counts = [];
  let total = 0;
  let specifiers = [];
  if (LEGACY_PATH[2].test(name)) { counts.push([LEGACY_PATH[0], 1]); total += 1; }
  const buffer = readFileSync(full);
  if (!buffer.subarray(0, 8000).includes(0)) {
    const text = buffer.toString('utf8');
    for (const [id, , res] of PATTERNS) {
      let n = 0;
      for (const re of res) n += (text.match(re) ?? []).length;
      if (n > 0) { counts.push([id, n]); total += n; }
    }
    if (CODE_FILE.test(name)) specifiers = importSpecifiers(text);
  }
  return total > 0 || specifiers.length > 0 ? { name, total, counts, specifiers } : null;
}

const rules = readRules(options.dispositions);
const scanned = listFiles(options.root).map((name) => scan(options.root, name)).filter(Boolean)
  .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
const rows = scanned.filter((entry) => entry.total > 0);
const undispositioned = { files: 0, hits: 0 };
for (const row of rows) {
  row.rule = rules.find((rule) => rule.re.test(row.name)) ?? null;
  const bucket = row.rule ?? undispositioned;
  bucket.files += 1;
  bucket.hits += row.total;
}

// Code that is not itself being deleted must not load code that is. Files with no matching rule count as retained.
const deleteRules = rules.filter((rule) => rule.disposition === 'delete');
function importProblems() {
  const problems = [];
  for (const entry of scanned) {
    const rule = rules.find((candidate) => candidate.re.test(entry.name)) ?? null;
    if (rule?.disposition === 'delete') continue;
    for (const specifier of entry.specifiers) {
      const target = importTarget(entry.name, specifier);
      const deleted = target === null ? undefined : deleteRules.find((candidate) => candidate.re.test(target) || candidate.re.test(`${target}/`));
      if (deleted) {
        problems.push({ pending: rule?.disposition === 'relocate',
          text: `${rule?.disposition === 'relocate' ? 'relocation-pending' : 'retained-import'}: ${entry.name} imports ${specifier} (deleted by ${deleted.glob})` });
      }
    }
  }
  return problems;
}

if (options.check) {
  const problems = [];
  for (const row of rows) if (!row.rule) problems.push(`undispositioned: ${row.name}`);
  for (const rule of rules) if (rule.files === 0) problems.push(`stale rule: ${rule.glob} (matches no file with hits; delete it with the files it covered)`);
  for (const problem of importProblems()) if (!problem.pending || options.accepted) problems.push(problem.text);
  if (options.accepted) {
    for (const rule of rules) if (rule.files > 0 && rule.status !== 'accepted') problems.push(`proposed: ${rule.glob} (${rule.files} files)`);
  }
  if (problems.length > 0) {
    process.stderr.write(`${problems.join('\n')}\n`);
    process.exit(1);
  }
  process.stdout.write(`inventory ok: ${rows.length} files with hits, ${rules.length} rules${options.accepted ? ', all accepted' : ''}\n`);
  process.exit(0);
}

const cell = (value) => String(value).replace(/\|/g, '\\|');
const out = [];
out.push('# Retirement inventory');
out.push('');
out.push('Generated by `scripts/retirement/inventory.sh`; do not edit. Regenerate with `scripts/retirement/inventory.sh > docs/release/retirement-inventory.md`.');
out.push('The decisions are the ordered rules in `scripts/retirement/dispositions.tsv` (first matching rule wins). Regeneration only reads that file.');
out.push('');
out.push(`Scope: every file git lists as tracked, or untracked and not ignored, except this document, \`scripts/retirement/\` and its test. Symlinks are skipped, and binary files are matched by path only. ${rows.length} files hit a pattern below, ${rows.reduce((sum, row) => sum + row.total, 0)} hits in total.`);
out.push('');
out.push('| Pattern | Matches |');
out.push('|---|---|');
for (const [id, description] of [LEGACY_PATH, ...PATTERNS]) out.push(`| \`${id}\` | ${cell(description)} |`);
out.push('');
out.push('| Disposition | Meaning |');
out.push('|---|---|');
for (const [id, description] of DISPOSITIONS) out.push(`| \`${id}\` | ${cell(description)} |`);
out.push('');
out.push('| Status | Meaning |');
out.push('|---|---|');
for (const [id, description] of STATUSES) out.push(`| \`${id}\` | ${cell(description)} |`);
out.push('');
out.push('## Summary by rule');
out.push('');
out.push('| Rule | Owner | Disposition | Status | Files | Hits | Note |');
out.push('|---|---|---|---|---|---|---|');
for (const rule of rules) {
  out.push(`| \`${cell(rule.glob)}\` | ${cell(rule.owner)} | ${rule.disposition} | ${rule.status} | ${rule.files} | ${rule.hits} | ${cell(rule.note)} |`);
}
if (undispositioned.files > 0) out.push(`| (no rule) | — | UNDISPOSITIONED | — | ${undispositioned.files} | ${undispositioned.hits} | |`);
out.push('');
out.push('## Files');
out.push('');
out.push('| Path | Hits | Patterns | Owner | Disposition | Status |');
out.push('|---|---|---|---|---|---|');
for (const row of rows) {
  const patterns = row.counts.map(([id, n]) => `${id} ×${n}`).join(', ');
  const rule = row.rule;
  out.push(`| ${cell(row.name)} | ${row.total} | ${patterns} | ${rule ? cell(rule.owner) : '—'} | ${rule ? rule.disposition : 'UNDISPOSITIONED'} | ${rule ? rule.status : '—'} |`);
}
process.stdout.write(`${out.join('\n')}\n`);
