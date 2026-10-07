#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""P07-D9: assemble the release evidence matrix from recorded scenario results.

Only data supplied in the result files appears in the output: no clock, no network and no
inference. A required scenario/profile with no result is "not run"; skip, unsupported and
fail rows block it; malformed input stops the run with no output. The collector never
writes a go decision: that is the reviewer's signed row in the P07 review record.

Exit status: 0 eligible for review, 1 invalid input, 2 usage, 3 gate blocked (output written).
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
RESULTS_SCHEMA = 'blindpass-release-evidence-v1'
CATALOG_SCHEMA = 'blindpass-required-scenarios-v1'
RESULT_VALUES = ('pass', 'fail', 'skip', 'unsupported')
MAX_INPUT_BYTES = 1024 * 1024
NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}')
PROFILE = re.compile(r'[a-z0-9][a-z0-9._-]{0,63}')
EVIDENCE = re.compile(r'https://[^\s<>|]{1,300}|(?!/)(?!.*\.\.)[A-Za-z0-9._/-]{1,200}(?:#[A-Za-z0-9._-]{1,80})?')


class InvalidInput(Exception):
    pass


def text(value, label, limit=300, required=True):
    if not isinstance(value, str):
        raise InvalidInput(f'{label} must be a string')
    value = value.strip()
    if required and not value:
        raise InvalidInput(f'{label} must not be blank')
    if len(value) > limit or any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise InvalidInput(f'{label} is too long or holds control characters')
    return value


def load_json(path, label):
    if path.is_symlink() or not path.is_file():
        raise InvalidInput(f'{label} is missing or not a regular file')
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise InvalidInput(f'{label} is too large')
    raw = path.read_bytes()
    try:
        return json.loads(raw), hashlib.sha256(raw).hexdigest()
    except ValueError as error:
        raise InvalidInput(f'{label} is not valid JSON') from error


def exact_keys(value, allowed, required, label):
    if not isinstance(value, dict):
        raise InvalidInput(f'{label} must be an object')
    extra = set(value) - allowed
    missing = required - set(value)
    if extra or missing:
        raise InvalidInput(f'{label} has unexpected or missing keys')


def load_catalog(path):
    data, _ = load_json(path, 'required-scenario catalog')
    exact_keys(data, {'schema', 'scenarios', 'note'}, {'schema', 'scenarios'}, 'catalog')
    if data['schema'] != CATALOG_SCHEMA or not isinstance(data['scenarios'], list) or not data['scenarios']:
        raise InvalidInput('catalog schema or scenario list is invalid')
    catalog, seen = [], set()
    for entry in data['scenarios']:
        exact_keys(entry, {'id', 'title', 'profiles'}, {'id', 'title', 'profiles'}, 'catalog scenario')
        scenario = text(entry['id'], 'catalog id', 64)
        if not NAME.fullmatch(scenario) or scenario in seen:
            raise InvalidInput('catalog scenario id is malformed or duplicated')
        seen.add(scenario)
        profiles = entry['profiles']
        if not isinstance(profiles, list) or not profiles or any(not isinstance(p, str) or not (PROFILE.fullmatch(p)) for p in profiles) \
                or len(set(profiles)) != len(profiles):
            raise InvalidInput('catalog profiles are invalid')
        catalog.append({'id': scenario, 'title': text(entry['title'], 'catalog title', 120), 'profiles': profiles})
    return catalog


def load_results(directory, commit):
    if directory.is_symlink() or not directory.is_dir():
        raise InvalidInput('results directory is missing')
    rows, files = [], []
    for entry in sorted(directory.iterdir(), key=lambda p: p.name):
        if entry.is_symlink() or not entry.is_file() or not entry.name.endswith('.json'):
            raise InvalidInput(f'results directory holds a non-JSON or non-regular entry: {entry.name}')
        data, digest = load_json(entry, entry.name)
        exact_keys(data, {'schema', 'commit', 'date', 'profile', 'client', 'environment', 'scenarios'},
                   {'schema', 'commit', 'date', 'profile', 'client', 'environment', 'scenarios'}, entry.name)
        if data['schema'] != RESULTS_SCHEMA:
            raise InvalidInput(f'{entry.name}: unsupported schema')
        if data['commit'] != commit:
            raise InvalidInput(f'{entry.name}: results are for a different commit (stale or wrong candidate)')
        try:
            datetime.date.fromisoformat(data['date'])
        except (TypeError, ValueError) as error:
            raise InvalidInput(f'{entry.name}: date must be YYYY-MM-DD') from error
        if not re.fullmatch(r'\d{4}-\d{2}-\d{2}', data['date']):
            raise InvalidInput(f'{entry.name}: date must be YYYY-MM-DD')
        profile = text(data['profile'], f'{entry.name} profile', 64)
        if not PROFILE.fullmatch(profile):
            raise InvalidInput(f'{entry.name}: profile name is malformed')
        client = text(data['client'], f'{entry.name} client', 100)
        text(data['environment'], f'{entry.name} environment', 200)
        if not isinstance(data['scenarios'], list) or not data['scenarios']:
            raise InvalidInput(f'{entry.name}: scenarios must be a non-empty list')
        for scenario in data['scenarios']:
            exact_keys(scenario, {'id', 'result', 'reason', 'evidence'}, {'id', 'result'}, f'{entry.name} scenario')
            scenario_id = text(scenario['id'], 'scenario id', 64)
            if not NAME.fullmatch(scenario_id):
                raise InvalidInput(f'{entry.name}: scenario id is malformed')
            result = scenario['result']
            if result not in RESULT_VALUES:
                raise InvalidInput(f'{entry.name}: {scenario_id} result must be one of {", ".join(RESULT_VALUES)}')
            reason = text(scenario['reason'], f'{scenario_id} reason', required=result in ('skip', 'unsupported')) if 'reason' in scenario else ''
            if result in ('skip', 'unsupported') and not reason:
                raise InvalidInput(f'{entry.name}: {scenario_id} {result} needs a reason')
            evidence = ''
            if 'evidence' in scenario:
                evidence = text(scenario['evidence'], f'{scenario_id} evidence', 300)
                if not EVIDENCE.fullmatch(evidence):
                    raise InvalidInput(f'{entry.name}: {scenario_id} evidence must be a relative repository path or an https link')
            if result == 'pass' and not evidence:
                raise InvalidInput(f'{entry.name}: {scenario_id} pass needs an evidence reference')
            rows.append({'id': scenario_id, 'profile': profile, 'client': client, 'result': result,
                         'detail': evidence if result == 'pass' else (reason or evidence), 'date': data['date'], 'source': entry.name})
        files.append((digest, entry.name))
    if not files:
        raise InvalidInput('results directory holds no result files')
    return rows, files


def cell(value):
    value = value.replace('\\', '\\\\').replace('|', '\\|').replace('<', '&lt;').replace('>', '&gt;')
    return value or '—'


def render(version, commit, catalog, rows, files):
    required, blockers, table = set(), [], []
    consumed = set()
    for scenario in catalog:
        for profile in scenario['profiles']:
            required.add((scenario['id'], profile))
            matching = [(i, r) for i, r in enumerate(rows)
                        if r['id'] == scenario['id'] and (profile == 'any' or r['profile'] == profile)]
            if not matching:
                blockers.append(f'{scenario["id"]} on {profile} (not run)')
                table.append(f'| {cell(scenario["id"])} | {cell(profile)} | — | not run | no result recorded | — | — |')
                continue
            for index, row in matching:
                consumed.add(index)
                if row['result'] != 'pass':
                    blockers.append(f'{scenario["id"]} on {profile} ({row["result"]})')
                table.append(f'| {cell(row["id"])} | {cell(row["profile"] if profile == "any" else profile)} | {cell(row["client"])} '
                             f'| {row["result"]} | {cell(row["detail"])} | {row["date"]} | {cell(row["source"])} |')
    extra = [r for i, r in enumerate(rows) if i not in consumed]
    blockers = sorted(set(blockers))
    gate = 'BLOCKED' if blockers else 'ELIGIBLE FOR REVIEW'
    out = [f'# Release evidence — v{version}', '',
           f'**Source commit:** `{commit}`', '',
           f'**Release gate: {gate}**', '',
           '**Go/no-go: NOT DECIDED.** This file is generated from recorded results. It cannot grant a go decision: '
           'the reviewer records one, with its date and open limits, in the P07 review record. A passing matrix is a '
           'precondition for that review, not a substitute for it.', '']
    if blockers:
        out += ['## Blockers', ''] + [f'- Blocking: {b}' for b in blockers] + ['']
    out += ['## Required scenarios', '',
            '| ID | Profile | Client | Result | Reason / evidence | Date | Source |', '|---|---|---|---|---|---|---|'] + sorted(table) + ['']
    excluded = [r for r in rows if r['result'] in ('skip', 'unsupported')]
    out += ['## Exclusions', '']
    out += [f'- {cell(r["id"])} on {cell(r["profile"])} ({r["result"]}): {cell(r["detail"])}' for r in excluded] or ['- None recorded.']
    out += ['', '## Additional results (not part of the required matrix; they cannot satisfy it)', '']
    if extra:
        out += ['| ID | Profile | Client | Result | Reason / evidence | Date | Source |', '|---|---|---|---|---|---|---|']
        out += [f'| {cell(r["id"])} | {cell(r["profile"])} | {cell(r["client"])} | {r["result"]} | {cell(r["detail"])} | {r["date"]} | {cell(r["source"])} |'
                for r in sorted(extra, key=lambda r: (r['id'], r['profile'], r['client'], r['source']))]
    else:
        out.append('None.')
    out += ['', '## Inputs', '', '| sha256 | file |', '|---|---|']
    out += [f'| {digest} | {cell(name)} |' for digest, name in sorted(files, key=lambda f: (f[1], f[0]))]
    return '\n'.join(out) + '\n', gate


def publish(destination, content):
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() or destination.is_symlink():
        raise InvalidInput('refusing to replace an existing evidence file')
    descriptor, temporary = tempfile.mkstemp(prefix='.evidence-', suffix='.tmp', dir=destination.parent)
    try:
        with os.fdopen(descriptor, 'w') as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o644)
        os.link(temporary, destination)
    except FileExistsError as error:
        raise InvalidInput('refusing to replace an existing evidence file') from error
    finally:
        Path(temporary).unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('version', help='release version X.Y.Z (no leading v)')
    parser.add_argument('--commit', help='expected 40-hex source commit (default: git HEAD)')
    parser.add_argument('--required', type=Path, default=ROOT / 'docs/release/required-scenarios.json')
    parser.add_argument('--results', type=Path)
    parser.add_argument('--output', type=Path, help='write here (never replacing a file); default stdout')
    options = parser.parse_args()
    if not re.fullmatch(r'\d+\.\d+\.\d+(?:-[A-Za-z0-9.]+)?', options.version):
        parser.error('version must look like X.Y.Z')
    try:
        commit = options.commit or subprocess.run(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], check=True,
                                                  capture_output=True, text=True, timeout=30).stdout.strip()
        if not re.fullmatch(r'[0-9a-f]{40}', commit):
            raise InvalidInput('commit must be 40 lowercase hex characters')
        catalog = load_catalog(options.required)
        rows, files = load_results(options.results or ROOT / 'docs/release' / f'v{options.version}' / 'results', commit)
        content, gate = render(options.version, commit, catalog, rows, files)
        if options.output:
            publish(options.output, content)
        else:
            sys.stdout.write(content)
    except (InvalidInput, OSError, subprocess.SubprocessError) as error:
        print(f'collect-evidence: {error if isinstance(error, InvalidInput) else "input could not be read"}', file=sys.stderr)
        return 1
    if gate == 'BLOCKED':
        print('collect-evidence: release gate BLOCKED (see Blockers)', file=sys.stderr)
        return 3
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
