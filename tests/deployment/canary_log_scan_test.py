#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""P07-I04 / finding F2: the harness log scans must fail closed.

Before this helper every P06 harness did `secret in text` against whatever a log capture returned,
so an empty, truncated or unreadable capture passed. These tests pin the replacement: an empty or
missing log fails, a scan whose finder is broken fails (positive control), and nothing the helper
prints or raises ever contains a canary.
"""
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import canary_log_scan as scan  # noqa: E402

CANARY = 'P07TEST-canary-9f2a41c7d8e0b653'
PASSWORD = 'p07test-Operator-Password-0a1b2c3d'
PEM = b'PRIVATE KEY-----'
LOG = ('controller-1  | started listening on 0.0.0.0:3200\n' * 8).encode()


def legacy_scan(log, secrets):
    """The shape every harness used before this helper: pass unless a secret appears."""
    return not any(secret in log for secret in secrets)


class FailClosed(unittest.TestCase):
    def test_legacy_scan_passes_an_empty_log_which_is_the_defect(self):
        self.assertTrue(legacy_scan(b'', [CANARY.encode(), PASSWORD.encode()]))

    def test_an_empty_log_fails(self):
        with self.assertRaises(scan.LogScanError) as error:
            scan.assert_log_clean('empty', b'', [CANARY, PASSWORD], markers=[PEM])
        self.assertIn('empty', str(error.exception))

    def test_none_and_whitespace_only_logs_fail(self):
        for log in (None, b'\n\n   \n', ''):
            with self.subTest(log=log), self.assertRaises(scan.LogScanError):
                scan.assert_log_clean('blank', log, [CANARY])

    def test_a_log_shorter_than_the_minimum_fails(self):
        with self.assertRaises(scan.LogScanError):
            scan.assert_log_clean('tiny', b'one line\n', [CANARY], min_bytes=64)

    def test_a_log_without_its_expected_content_fails(self):
        with self.assertRaises(scan.LogScanError) as error:
            scan.assert_log_clean('wrong-unit', LOG, [CANARY], require=[b'blindpass-broker'])
        self.assertIn('expected content', str(error.exception))

    def test_no_canaries_or_a_too_short_canary_fails(self):
        for canaries in ([], ['short'], [CANARY, '']):
            with self.subTest(canaries=canaries), self.assertRaises(scan.LogScanError):
                scan.assert_log_clean('nothing-to-look-for', LOG, canaries)

    def test_markers_alone_are_a_usable_scan_but_nothing_at_all_is_not(self):
        scan.assert_log_clean('markers-only', LOG, [], markers=[PEM])
        with self.assertRaises(scan.LogScanError):
            scan.assert_log_clean('nothing', LOG, [], markers=[])

    def test_an_empty_capture_is_accepted_only_with_a_stated_reason_it_is_by_design(self):
        # The shipped nginx edge sets `access_log off` and `error_log /dev/null`, so its capture is empty
        # by design. The caller must say why and the controls still run on the empty buffer.
        stats = scan.assert_log_clean('silent edge', b'', [CANARY], allow_empty='the edge config sets access_log off')
        self.assertEqual(stats['bytes'], 0)
        self.assertEqual(stats['control'], 'ok')
        self.assertEqual(stats['empty_by_design'], 'the edge config sets access_log off')

    def test_the_by_design_allowance_needs_a_real_reason_and_does_not_excuse_other_failures(self):
        for reason in ('', '   ', None):
            with self.subTest(reason=reason), self.assertRaises(scan.LogScanError):
                scan.assert_log_clean('silent edge', b'', [CANARY], allow_empty=reason)
        with self.assertRaises(scan.LogScanError):   # no capture at all is not an empty capture
            scan.assert_log_clean('silent edge', None, [CANARY], allow_empty='by design')
        with self.assertRaises(scan.LogScanError):   # expected content is still required
            scan.assert_log_clean('silent edge', b'', [CANARY], allow_empty='by design', require=[b'nginx'])
        with self.assertRaises(scan.LogScanError):   # and a canary in a non-empty capture still fails
            scan.assert_log_clean('silent edge', CANARY.encode(), [CANARY], allow_empty='by design')

    def test_a_clean_log_passes_and_reports_what_it_looked_at(self):
        stats = scan.assert_log_clean('clean', LOG, [CANARY, PASSWORD], markers=[PEM], require=[b'controller'])
        self.assertEqual(stats['bytes'], len(LOG))
        self.assertEqual(stats['canaries'], 2)
        self.assertEqual(stats['markers'], 1)
        self.assertEqual(stats['control'], 'ok')


class Detection(unittest.TestCase):
    def test_a_canary_in_the_log_fails_in_str_and_bytes_form(self):
        for canary in (CANARY, CANARY.encode()):
            with self.subTest(kind=type(canary).__name__), self.assertRaises(scan.LogScanError):
                scan.assert_log_clean('leak', LOG + b'token=' + CANARY.encode() + b'\n', [canary, PASSWORD])

    def test_a_marker_in_the_log_fails(self):
        with self.assertRaises(scan.LogScanError):
            scan.assert_log_clean('pem', LOG + b'-----BEGIN PRIVATE KEY-----\n', [CANARY], markers=[PEM])

    def test_the_failure_never_contains_a_secret_or_the_log_text(self):
        leaked = LOG + CANARY.encode() + b' ' + PASSWORD.encode()
        with self.assertRaises(scan.LogScanError) as error:
            scan.assert_log_clean('leak', leaked, [CANARY, PASSWORD], markers=[PEM])
        text = str(error.exception)
        for value in (CANARY, PASSWORD, 'started listening'):
            self.assertNotIn(value, text)
        self.assertIn('leak', text)

    def test_the_positive_control_catches_a_broken_finder(self):
        # A finder that sees nothing would pass every log. The control plants a random token in a
        # copy of the log and requires the very same finder to see it.
        with mock.patch.object(scan, '_hits', lambda data, values: []):
            with self.assertRaises(scan.LogScanError) as error:
                scan.assert_log_clean('broken-finder', LOG, [CANARY])
        self.assertIn('control', str(error.exception))

    def test_the_planted_token_control_is_independent_of_the_value_control(self):
        # A finder that finds every given value but not a token planted into the log itself (for
        # example one that only searches a fixed buffer) must still be caught by the token control.
        real = scan._hits

        def blind_to_the_log(data, values):
            return [] if any(value.startswith(b'P07-CONTROL-') for value in values) else real(data, values)

        with mock.patch.object(scan, '_hits', blind_to_the_log):
            with self.assertRaises(scan.LogScanError) as error:
                scan.assert_log_clean('blind-to-the-log', LOG, [CANARY])
        self.assertIn('planted token', str(error.exception))

    def test_the_control_tests_every_value_not_only_one_token(self):
        # A finder that cannot see one particular value (here: anything starting with p07test-)
        # must also be caught, so a value that cannot be found is never reported as absent.
        real = scan._hits

        def blind(data, values):
            return real(data, [value for value in values if not value.startswith(b'p07test-')])

        with mock.patch.object(scan, '_hits', blind):
            with self.assertRaises(scan.LogScanError):
                scan.assert_log_clean('blind-to-one', LOG, [CANARY, PASSWORD])


class Reading(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.dir = Path(self.directory.name)

    def test_a_missing_path_fails(self):
        with self.assertRaises(scan.LogScanError):
            scan.read_log(self.dir / 'absent.log')

    def test_a_directory_fails(self):
        with self.assertRaises(scan.LogScanError):
            scan.read_log(self.dir)

    @unittest.skipIf(os.geteuid() == 0, 'root can read mode 0 files')
    def test_an_unreadable_file_fails(self):
        path = self.dir / 'locked.log'
        path.write_bytes(LOG)
        path.chmod(0)
        with self.assertRaises(scan.LogScanError):
            scan.read_log(path)

    def test_a_readable_file_round_trips(self):
        path = self.dir / 'controller.log'
        path.write_bytes(LOG)
        self.assertEqual(scan.read_log(path), LOG)


class Persistence(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.run_dir = Path(self.directory.name) / 'run'

    def env(self, **values):
        return mock.patch.dict(os.environ, values, clear=False)

    def test_nothing_is_written_without_p07_run(self):
        with self.env():
            os.environ.pop('P07_RUN', None)
            scan.assert_log_clean('quiet', LOG, [CANARY])
        self.assertFalse(self.run_dir.exists())

    def test_with_p07_run_the_log_and_the_usable_canaries_are_exported_privately(self):
        short = 'tooshort1'            # 9 bytes: the offline scanner refuses canaries under 12
        flat = 'aaaaaaaaaaaaaaaa'      # 16 bytes but one distinct byte: refused as well
        with self.env(P07_RUN=str(self.run_dir)):
            stats = scan.register_canaries([short, flat, CANARY, PASSWORD])
            scan.assert_log_clean('P06-RC7 compose logs', LOG, [CANARY, PASSWORD], markers=[PEM])
        self.assertEqual(stats, {'registered': 2, 'skipped': 2})
        canaries = (self.run_dir / 'canaries.txt').read_text().splitlines()
        self.assertEqual(sorted(canaries), sorted([CANARY, PASSWORD]))
        exported = list((self.run_dir / 'logs').iterdir())
        self.assertEqual(len(exported), 1)
        self.assertEqual(exported[0].read_bytes(), LOG)
        self.assertEqual(stat.S_IMODE(exported[0].stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((self.run_dir / 'canaries.txt').stat().st_mode), 0o600)
        # Markers such as the PEM header are checked but are not canaries and are never registered.
        self.assertNotIn(PEM.decode(), (self.run_dir / 'canaries.txt').read_text())

    def test_registering_twice_does_not_duplicate_a_canary(self):
        with self.env(P07_RUN=str(self.run_dir)):
            scan.register_canaries([CANARY])
            scan.register_canaries([CANARY, PASSWORD])
        self.assertEqual(sorted((self.run_dir / 'canaries.txt').read_text().splitlines()), sorted([CANARY, PASSWORD]))

    def test_export_names_are_confined_to_the_run_directory(self):
        with self.env(P07_RUN=str(self.run_dir)):
            scan.export('../../escape', b'data', kind='logs')
        self.assertFalse((self.run_dir.parent / 'escape').exists())
        self.assertEqual(len(list((self.run_dir / 'logs').iterdir())), 1)

    def test_an_empty_by_design_capture_exports_its_reason_not_an_empty_log(self):
        # The offline scanner treats an empty log as an incomplete scan, so an allowed empty capture is
        # recorded as a note carrying the reason, and no empty log file is left for it to trip over.
        with self.env(P07_RUN=str(self.run_dir)):
            scan.assert_log_clean('P06 edge logs', b'', [CANARY], allow_empty='the edge config sets access_log off')
        self.assertFalse((self.run_dir / 'logs').exists())
        notes = list((self.run_dir / 'notes').iterdir())
        self.assertEqual(len(notes), 1)
        text = notes[0].read_text()
        self.assertIn('the edge config sets access_log off', text)
        self.assertIn('P06 edge logs', text)
        self.assertEqual(stat.S_IMODE(notes[0].stat().st_mode), 0o600)

    def test_a_leak_is_still_exported_so_it_can_be_investigated(self):
        with self.env(P07_RUN=str(self.run_dir)):
            with self.assertRaises(scan.LogScanError):
                scan.assert_log_clean('leaky', LOG + CANARY.encode(), [CANARY])
        self.assertEqual(len(list((self.run_dir / 'logs').iterdir())), 1)


if __name__ == '__main__':
    unittest.main()
