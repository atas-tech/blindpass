#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for check-core-limits.py (pilot S07: no crash artifact may carry process memory by default).

Run: python3 -m unittest scripts/tests/check_core_limits_test.py
"""
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

CHECK = Path(__file__).resolve().parent / 'check-core-limits.py'


class CoreLimitTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='core-limits-test-'))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def write(self, name, text):
        path = self.tmp / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def run_check(self, *args):
        done = subprocess.run([sys.executable, str(CHECK), *args, str(self.tmp)], capture_output=True, text=True)
        return done.returncode, done.stdout + done.stderr

    def test_unit_with_limitcore_zero_passes(self):
        self.write('a.service', '[Service]\nExecStart=/bin/true\nLimitCORE=0\n')
        code, out = self.run_check()
        self.assertEqual(code, 0, out)
        self.assertIn('1 units', out)

    def test_unit_without_limitcore_zero_fails_even_if_commented_or_infinite(self):
        for body in ('[Service]\nExecStart=/bin/true\n', '[Service]\n#LimitCORE=0\n', '[Service]\nLimitCORE=infinity\n',
                     '[Unit]\nLimitCORE=0\n[Service]\nExecStart=/bin/true\n'):
            with self.subTest(body=body):
                self.write('a.service', body)
                code, out = self.run_check()
                self.assertEqual(code, 1, out)
                self.assertIn('a.service', out)

    def test_compose_services_need_core_zero_with_anchors_resolved(self):
        self.write('compose.yml', 'x-job: &job\n  ulimits:\n    core: 0\nservices:\n  one:\n    <<: *job\n    image: x\n  two:\n    image: y\n    ulimits:\n      core: 0\n')
        code, out = self.run_check()
        self.assertEqual(code, 0, out)
        self.write('compose.yml', 'services:\n  one:\n    image: x\n    ulimits:\n      core: 0\n  postgres:\n    image: y\n')
        code, out = self.run_check()
        self.assertEqual(code, 1, out)
        self.assertIn('postgres', out)

    def test_soft_and_hard_zero_is_accepted_and_nonzero_is_not(self):
        self.write('compose.yml', 'services:\n  a:\n    ulimits:\n      core: {soft: 0, hard: 0}\n')
        self.assertEqual(self.run_check()[0], 0)
        self.write('compose.yml', 'services:\n  a:\n    ulimits:\n      core: {soft: 0, hard: -1}\n')
        self.assertEqual(self.run_check()[0], 1)

    def test_exception_needs_a_reason_and_is_reported(self):
        self.write('compose.yml', 'services:\n  postgres:\n    image: y\n')
        exceptions = self.tmp / 'exceptions.json'
        exceptions.write_text(json.dumps([{'path': '*compose.yml', 'service': 'postgres', 'reason': 'test fixture database, not a shipped profile'}]))
        code, out = self.run_check('--exceptions', str(exceptions))
        self.assertEqual(code, 0, out)
        self.assertIn('excepted', out)
        self.assertIn('not a shipped profile', out)
        exceptions.write_text(json.dumps([{'path': '*compose.yml', 'service': 'postgres', 'reason': ''}]))
        self.assertEqual(self.run_check('--exceptions', str(exceptions))[0], 2)

    def test_nothing_found_or_unparsable_input_fails_closed(self):
        code, out = self.run_check()
        self.assertEqual(code, 3, out)
        self.write('compose.yml', 'services: [unclosed\n')
        code, out = self.run_check()
        self.assertEqual(code, 3, out)


if __name__ == '__main__':
    unittest.main()
