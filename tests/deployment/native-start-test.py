#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""P07 slice 7: `install.sh --start` must wait a bounded time and never report ok for an exited service.

The installer needs root and a real systemd host, so these tests drive its start-wait function with a fake
systemctl/journalctl runner, a fake loopback prober and a fake clock. The real-host proof is the native VM harness
(`tests/deployment/native-install.sh`, scenario NS1-NS4).
"""
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('controller_install', ROOT / 'deploy/native/controller-install.py')
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)

INVOCATION = '0123456789abcdef0123456789abcdef'


class Clock:
    def __init__(self):
        self.value = 0.0
        self.sleeps = []

    def now(self):
        return self.value

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.value += seconds


class FakeHost:
    """systemctl show / journalctl answers by scripted unit state, advancing one entry per poll."""

    def __init__(self, states, journal=None, health=(None, None)):
        self.states = list(states)
        self.journal = journal or ''
        self.calls = []
        self.health = health

    def run(self, args, **_):
        self.calls.append(list(args))
        if args[0] == 'systemctl':
            state = self.states.pop(0) if len(self.states) > 1 else self.states[0]
            text = ''.join(f'{key}={value}\n' for key, value in state.items())
            return subprocess.CompletedProcess(args, 0, text, '')
        if args[0] == 'journalctl':
            return subprocess.CompletedProcess(args, 0, self.journal, '')
        raise AssertionError(f'unexpected command {args}')

    def probe(self, path, tls):
        # Each path maps to a (status, reason) answer, a list of them consumed in order (the last repeats),
        # or None for connection refused.
        answer = {'/healthz': self.health[0], '/readyz': self.health[1]}[path]
        if isinstance(answer, list):
            value = answer.pop(0) if len(answer) > 1 else answer[0]
        else:
            value = answer
        return value if isinstance(value, tuple) else (value, None)


def active(): return {'ActiveState': 'active', 'SubState': 'running', 'Result': 'success', 'InvocationID': INVOCATION}
def failed(): return {'ActiveState': 'failed', 'SubState': 'failed', 'Result': 'exit-code', 'InvocationID': INVOCATION}
def inactive(): return {'ActiveState': 'inactive', 'SubState': 'dead', 'Result': 'success', 'InvocationID': INVOCATION}


def wait(host, clock, timeout=20, tls=False):
    return installer.wait_for_start(timeout, tls, run=host.run, probe=host.probe, sleep=clock.sleep, now=clock.now)


FENCED = '{"event":"startup_failed","reason":"fenced"}\n'


class StartWait(unittest.TestCase):
    def test_p07_ns_a_service_that_exits_after_start_is_refused_with_the_reason_and_next_step(self):
        # The dry-run case: systemctl returns once exec'd, the process then exits `startup_failed fenced`.
        clock = Clock()
        host = FakeHost([active(), failed()], journal='noise\n' + FENCED, health=(None, None))
        with self.assertRaises(installer.Refusal) as caught:
            wait(host, clock)
        message = str(caught.exception)
        self.assertIn('fenced', message)
        self.assertIn('authority-activate.sql', message)
        self.assertIn('failed', message)
        self.assertLess(clock.value, 20, 'an exited service must be reported without waiting out the timeout')
        self.assertNotIn('"ok": true', message)

    def test_p07_ns_the_journal_is_scoped_to_the_invocation_that_just_started(self):
        clock = Clock()
        host = FakeHost([failed()], journal=FENCED)
        with self.assertRaises(installer.Refusal):
            wait(host, clock)
        journal = [call for call in host.calls if call[0] == 'journalctl']
        self.assertTrue(journal, 'the failure reason must come from the journal')
        self.assertTrue(any(f'_SYSTEMD_INVOCATION_ID={INVOCATION}' in call for call in journal),
                        'a stale startup_failed event from an earlier start must not be reported')

    def test_p07_ns_an_unknown_or_unsafe_reason_is_not_echoed(self):
        for line in ['{"event":"startup_failed","reason":"../etc; rm -rf"}\n', '{"event":"startup_failed"}\n',
                     'not json\n', '{"event":"startup_failed","reason":"' + 'a' * 80 + '"}\n']:
            clock = Clock()
            host = FakeHost([inactive()], journal=line)
            with self.assertRaises(installer.Refusal) as caught:
                wait(host, clock)
            message = str(caught.exception)
            self.assertNotIn('rm -rf', message)
            self.assertNotIn('a' * 60, message)
            self.assertIn('journalctl -u blindpass-controller.service', message)
            self.assertNotIn('authority-activate.sql', message, 'the activation hint is only for the fenced reason')

    def test_p07_ns_an_active_service_that_answers_health_and_readiness_succeeds(self):
        clock = Clock()
        host = FakeHost([active()], health=(200, 200))
        result = wait(host, clock)
        self.assertEqual(result, {'started': True, 'ready': True})

    def test_p07_ns_a_running_service_that_never_becomes_ready_is_refused_with_the_reason_and_next_step(self):
        # A never-activated (fenced) record runs the controller as a diagnostic process: /healthz 200, /readyz 503
        # reason=recovery_required, forever. --start must not call that a successful start.
        clock = Clock()
        host = FakeHost([active()], health=(200, (503, 'recovery_required')))
        with self.assertRaises(installer.Refusal) as caught:
            wait(host, clock, timeout=5)
        message = str(caught.exception)
        self.assertIn('running but not ready', message)
        self.assertIn('recovery_required', message)
        self.assertIn('authority-activate.sql', message)
        self.assertGreaterEqual(clock.value, 5)
        self.assertLessEqual(clock.value, 6)

    def test_p07_ns_readiness_that_arrives_within_the_bound_is_a_success(self):
        clock = Clock()
        host = FakeHost([active()], health=(200, [(503, 'store_unavailable'), (503, 'store_unavailable'), (200, None)]))
        self.assertEqual(wait(host, clock), {'started': True, 'ready': True})
        self.assertGreater(clock.value, 0)

    def test_p07_ns_an_unsafe_readiness_reason_is_not_echoed(self):
        clock = Clock()
        host = FakeHost([active()], health=(200, (503, '../etc; rm -rf')))
        with self.assertRaises(installer.Refusal) as caught:
            wait(host, clock, timeout=2)
        self.assertNotIn('rm -rf', str(caught.exception))

    def test_p07_ns_a_service_that_is_active_but_never_answers_is_refused_after_the_bound(self):
        clock = Clock()
        host = FakeHost([active()], health=(None, None))
        with self.assertRaises(installer.Refusal) as caught:
            wait(host, clock, timeout=5)
        self.assertIn('did not answer', str(caught.exception))
        self.assertLessEqual(clock.value, 5 + 1, 'the wait must stay bounded by the timeout')
        self.assertGreaterEqual(clock.value, 5)

    def test_p07_ns_a_service_still_activating_keeps_the_wait_going(self):
        clock = Clock()
        activating = {'ActiveState': 'activating', 'SubState': 'start', 'Result': 'success', 'InvocationID': INVOCATION}
        host = FakeHost([activating, activating, active()], health=(200, 200))
        self.assertEqual(wait(host, clock), {'started': True, 'ready': True})

    def test_p07_ns_the_probe_follows_the_configured_port_but_only_ever_contacts_loopback(self):
        import tempfile
        cases = [('BLINDPASS_LISTEN=127.0.0.1:3200\n', ('127.0.0.1', 3200)),
                 ('A=1\nBLINDPASS_LISTEN=0.0.0.0:4010\nB=2\n', ('127.0.0.1', 4010)),
                 ('BLINDPASS_LISTEN=192.0.2.9:3300\n', ('127.0.0.1', 3300)),
                 ('BLINDPASS_LISTEN=[::]:3201\n', ('::1', 3201)),
                 ('BLINDPASS_LISTEN=not-an-address\n', ('127.0.0.1', 3200)),
                 ('', ('127.0.0.1', 3200))]
        original = installer.CONFIG
        try:
            with tempfile.TemporaryDirectory() as directory:
                for text, expected in cases:
                    config = Path(directory) / 'controller.env'
                    config.write_text(text); config.chmod(0o640)
                    installer.CONFIG = config
                    self.assertEqual(installer.listen_address(), expected, text)
                installer.CONFIG = Path(directory) / 'missing.env'
                self.assertEqual(installer.listen_address(), ('127.0.0.1', 3200))
        finally:
            installer.CONFIG = original

    def test_p07_ns_the_timeout_is_a_documented_bounded_option(self):
        help_text = subprocess.run(['python3', str(ROOT / 'deploy/native/controller-install.py'), '--help'],
                                   capture_output=True, text=True).stdout
        self.assertIn('--start-timeout', help_text)
        for value in ['0', '301', 'x']:
            result = subprocess.run(['python3', str(ROOT / 'deploy/native/controller-install.py'), '--start', '--start-timeout', value,
                                     '--bundle', '/nonexistent'], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0, value)
            self.assertIn('start-timeout', result.stderr, value)


if __name__ == '__main__':
    unittest.main()
