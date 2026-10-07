#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""P07-I04: tests for the opt-in evidence export CLI that the shell fleet harnesses call.

The CLI wraps tests/deployment/canary_log_scan.py (export and register_canaries) so that
p03-vm.sh can hand its logs, journals, state dumps and generated secrets to the offline scanner.
It must do nothing without P07_RUN, never print a value, and fail closed when it cannot register.
"""
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

CLI = Path(__file__).resolve().parent / 'p07_export.py'


def run(args, run_dir=None, extra_env=None):
    env = {k: v for k, v in os.environ.items() if k != 'P07_RUN'}
    if run_dir is not None:
        env['P07_RUN'] = str(run_dir)
    env.update(extra_env or {})
    return subprocess.run([sys.executable, str(CLI), *args], env=env, capture_output=True, text=True)


class ExportCli(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.run_dir = self.root / 'run'

    def write(self, name, data):
        path = self.root / name
        path.write_bytes(data if isinstance(data, bytes) else data.encode())
        return path

    def canaries(self):
        path = self.run_dir / 'canaries.txt'
        return path.read_bytes().splitlines() if path.exists() else []

    def test_without_p07_run_every_command_is_a_no_op(self):
        source = self.write('log.txt', 'a log line that is long enough to export\n')
        for args in (['file', 'logs', 'x', str(source)], ['bytes-canary', str(source)], ['text-canary', str(source)]):
            result = run(args)
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.run_dir.exists())

    def test_file_export_copies_bytes_private_and_prints_no_content(self):
        source = self.write('journal.txt', 'journal content that must not be echoed\n')
        result = run(['file', 'journals', 'guest-a', str(source)], self.run_dir)
        self.assertEqual(result.returncode, 0, result.stderr)
        exported = self.run_dir / 'journals' / 'guest-a.log'
        self.assertEqual(exported.read_bytes(), source.read_bytes())
        self.assertEqual(exported.stat().st_mode & 0o777, 0o600)
        self.assertNotIn('journal content', result.stdout + result.stderr)

    def test_file_export_fails_closed_on_missing_or_empty_input(self):
        self.assertNotEqual(run(['file', 'logs', 'x', str(self.root / 'absent')], self.run_dir).returncode, 0)
        empty = self.write('empty.txt', b'')
        self.assertNotEqual(run(['file', 'logs', 'x', str(empty)], self.run_dir).returncode, 0)

    def test_bytes_canary_registers_hex_and_both_base64_forms_without_printing_them(self):
        secret = bytes(range(1, 33))
        source = self.write('secret.bin', secret)
        result = run(['bytes-canary', str(source)], self.run_dir)
        self.assertEqual(result.returncode, 0, result.stderr)
        got = set(self.canaries())
        self.assertIn(secret.hex().encode(), got)
        self.assertIn(base64.b64encode(secret), got)
        self.assertIn(base64.urlsafe_b64encode(secret).rstrip(b'='), got)
        for value in got:
            self.assertNotIn(value.decode(), result.stdout + result.stderr)

    def test_text_canary_registers_the_single_line_and_rejects_unusable_values(self):
        good = self.write('token', 'ENROLL-' + 'abcdefghijklmnop' + '\n')
        self.assertEqual(run(['text-canary', str(good)], self.run_dir).returncode, 0)
        self.assertIn(b'ENROLL-abcdefghijklmnop', self.canaries())
        short = self.write('short', 'abc\n')
        self.assertNotEqual(run(['text-canary', str(short)], self.run_dir).returncode, 0)

    def test_json_canary_takes_string_leaves_and_skips_named_keys(self):
        document = {'local_admin': {'temporary_password': 'TEMP-' + 'qwertyuiop12', 'session_id': 'SESSION-' + 'asdfghjkl123',
                                    'csrf_token': 'CSRFVALUE-' + 'zxcvbnm12345'},
                    'agents': {'one': 'ak_' + 'agentkeyvalue99'}, 'count': 7, 'short': 'x'}
        source = self.write('seed.json', json.dumps(document))
        result = run(['json-canary', str(source), '--skip', 'csrf'], self.run_dir)
        self.assertEqual(result.returncode, 0, result.stderr)
        got = self.canaries()
        self.assertIn(b'TEMP-qwertyuiop12', got)
        self.assertIn(b'SESSION-asdfghjkl123', got)
        self.assertIn(b'ak_agentkeyvalue99', got)
        self.assertNotIn(b'CSRFVALUE-zxcvbnm12345', got)

    def test_secret_lines_registers_values_after_the_secret_prefix(self):
        source = self.write('key-canaries', 'identities 2\nsecret AbCdEfGhIjKlMnOpQrStUvWx\nsecret 0123456789abcdef0123456789abcdef\nother x\n')
        self.assertEqual(run(['secret-lines', str(source)], self.run_dir).returncode, 0)
        got = self.canaries()
        self.assertIn(b'AbCdEfGhIjKlMnOpQrStUvWx', got)
        self.assertIn(b'0123456789abcdef0123456789abcdef', got)

    def test_registering_nothing_usable_fails_closed(self):
        source = self.write('seed.json', json.dumps({'a': 'x', 'n': 3}))
        self.assertNotEqual(run(['json-canary', str(source)], self.run_dir).returncode, 0)

    def test_unknown_command_is_a_usage_error(self):
        self.assertEqual(run(['nope'], self.run_dir).returncode, 2)


class HarnessWrapper(unittest.TestCase):
    """p03-vm.sh calls p07 inside command substitutions (create_enrollment returns a node id on stdout)."""

    def test_p07_wrapper_never_writes_to_stdout(self):
        script = (Path(__file__).resolve().parent / 'p03-vm.sh').read_text()
        start = script.index('\np07() {') + 1
        wrapper = script[start:script.index('\n}\n', start) + 3]
        with tempfile.TemporaryDirectory() as tmp:
            secret = Path(tmp) / 'token'
            secret.write_text('AbCdEfGhIjKlMnOpQrStUvWx\n')
            run_dir = Path(tmp) / 'run'
            code = f'repo_root={str(CLI.parents[2])!r}\n{wrapper}\nout=$(p07 text-canary {str(secret)!r})\nprintf "[%s]" "$out"\n'
            result = subprocess.run(['bash', '-c', code], env={**os.environ, 'P07_RUN': str(run_dir)},
                                    capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, '[]', 'p07 output must not leak into command substitutions')


class HarnessSeedRegistration(unittest.TestCase):
    """The admin seed holds public identifiers (stored by design) and exactly two secrets."""

    def test_p03_seed_registers_only_its_secrets(self):
        script = (Path(__file__).resolve().parent / 'p03-vm.sh').read_text()
        lines = script.splitlines()
        start = next(n for n, l in enumerate(lines) if 'p07 json-canary' in l and 'admin_seed_file' in l)
        call = lines[start]
        while call.endswith('\\'):
            start += 1
            call = call[:-1] + ' ' + lines[start]
        skips = [part for flag, part in zip(call.split(), call.split()[1:]) if flag == '--skip']
        seed = {
            'workspace_id': 'f0e1d2c3-b4a5-4968-8778-695a4b3c2d1e',
            'user_id': '0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d',
            'agents': {'p03-synthetic-fixture': '1a2b3c4d-5e6f-4789-9abc-def012345678'},
            'local_admin': {
                'operator_id': '9f8e7d6c-5b4a-4392-8180-7f6e5d4c3b2a',
                'username': 'p03-local-admin',
                'temporary_password': 'Tmp-AbCdEfGhIjKlMnOpQrStUvWx',
                'session_id': 'ses_ZyXwVuTsRqPoNmLkJiHgFeDc',
                'csrf_token': 'csrf_MnBvCxZlKjHgFdSaPoIuYtRe',
            },
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'seed.json'
            path.write_text(json.dumps(seed))
            run_dir = Path(tmp) / 'run'
            args = ['json-canary', str(path)]
            for skip in skips:
                args += ['--skip', skip]
            result = run(args, run_dir)
            self.assertEqual(result.returncode, 0, result.stderr)
            registered = (run_dir / 'canaries.txt').read_text().split()
        self.assertEqual(sorted(registered), sorted([seed['local_admin']['temporary_password'],
                                                     seed['local_admin']['session_id']]))


if __name__ == '__main__':
    unittest.main()
