#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""P07-I04: the shared P06 controller-log scan keeps its fail-closed floor for controllers that served and
accepts a stale (fenced, retired or superseded) controller's single refusal line, and nothing less."""
import importlib.util
from pathlib import Path
import os
import sys
import tempfile
from types import SimpleNamespace
import unittest

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("p06_relay_vm", HERE / "p06-relay-vm.py")
relay = importlib.util.module_from_spec(_spec)
sys.modules["p06_relay_vm"] = relay
_spec.loader.exec_module(relay)

CANARIES = [f"p06-scan-canary-{index}-AbCdEfGhIjKlMnOp" for index in range(4)]
REFUSAL = b'{"event":"startup_failed","reason":"handoff_retired"}\n'
SERVED = b'{"event":"listening"}\n' * 20


class ScanLogs(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        os.environ.pop("P07_RUN", None)

    def rehearsal(self, *controllers):
        built = []
        for name, content in controllers:
            path = Path(self.tmp.name) / f"{name}.log"
            path.write_bytes(content)
            built.append(SimpleNamespace(name=name, log=path))
        return SimpleNamespace(
            canaries=list(CANARIES),
            authority=SimpleNamespace(owner_password="owner-AbCdEfGhIjKlMnOpQrSt", runtime_password="runtime-AbCdEfGhIjKlMnOpQrSt"),
            controllers=built,
            guest=lambda *args, **kwargs: SimpleNamespace(stdout=b"broker and node journal line for the scan\n" * 3),
        )

    def test_a_stale_controllers_single_refusal_line_is_accepted(self):
        relay.scan_logs(self.rehearsal(("source", SERVED), ("stale2", REFUSAL)))

    def test_a_controller_that_served_still_needs_the_floor(self):
        with self.assertRaises(relay.Failure) as caught:
            relay.scan_logs(self.rehearsal(("source", REFUSAL)))
        self.assertIn("too short", str(caught.exception))

    def test_an_empty_stale_log_fails(self):
        with self.assertRaises(relay.Failure):
            relay.scan_logs(self.rehearsal(("source", SERVED), ("stale", b"")))

    def test_a_short_stale_log_that_is_not_a_refusal_fails(self):
        with self.assertRaises(relay.Failure) as caught:
            relay.scan_logs(self.rehearsal(("source", SERVED), ("stale", b'{"event":"listening"}\n' * 2)))
        self.assertIn("lacks expected content", str(caught.exception))

    def test_a_canary_in_a_stale_log_fails(self):
        leak = REFUSAL + CANARIES[1].encode() + b"\n"
        with self.assertRaises(relay.Failure) as caught:
            relay.scan_logs(self.rehearsal(("source", SERVED), ("stale", leak)))
        self.assertIn("forbidden value", str(caught.exception))


class ControllerEnvironment(unittest.TestCase):
    """S07: the debug-logging success path needs RUST_LOG to reach the harness's controller."""

    def controller_env(self, rust_log):
        saved = os.environ.pop("RUST_LOG", None)
        self.addCleanup(lambda: os.environ.__setitem__("RUST_LOG", saved) if saved is not None else os.environ.pop("RUST_LOG", None))
        if rust_log is not None:
            os.environ["RUST_LOG"] = rust_log
        r = SimpleNamespace(dir=Path("/nonexistent-p06"), tenant="t", owner="o")
        return relay.Controller(r, "source", Path("/k"), Path("/d")).env()

    def test_rust_log_is_passed_through_when_set(self):
        self.assertEqual(self.controller_env("debug").get("RUST_LOG"), "debug")

    def test_rust_log_is_absent_when_unset(self):
        self.assertNotIn("RUST_LOG", self.controller_env(None))


if __name__ == "__main__":
    unittest.main()
