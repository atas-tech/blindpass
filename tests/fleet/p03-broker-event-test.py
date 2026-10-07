#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Exercise the exact guest assertion with disposable metadata-only fixtures."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


class BrokerEventAssertion(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="blindpass-p06-event-inspector-")
        self.addCleanup(self.directory.cleanup)
        self.queue = Path(self.directory.name) / "queue.jsonl"
        self.key = "P06_DUMMY_EVENT_00000001"
        source = Path(__file__).with_name("p03-guest.sh").read_text()
        body = source.split("    assert-broker-event)\n", 1)[1].split("        ;;", 1)[0]
        self.script = "set -Eeuo pipefail\nfail() { exit 1; }\n" + body.replace(
            "/var/lib/blindpass/broker/pending-node-events.jsonl", str(self.queue)
        )
        self.header = {"v": 5, "operation_owners": [{"event_key": self.key}]}
        self.event = {"idempotency_key": self.key, "kind": "operation_request",
                      "body": {"request_event_key": self.key}}

    def write(self, rows):
        self.queue.write_text("".join(json.dumps(row) + "\n" for row in rows))
        self.queue.chmod(0o600)

    def run_assertion(self):
        return subprocess.run(["bash", "-c", self.script, "assertion", self.key],
                              capture_output=True, timeout=5).returncode

    def test_header_correlation_does_not_duplicate_actual_event(self):
        self.write([self.header, self.event])
        self.assertEqual(self.run_assertion(), 0)

    def test_header_or_nested_reference_is_not_a_queued_event(self):
        for rows in [[self.header], [self.header, dict(self.event, idempotency_key="OTHER")]]:
            self.write(rows)
            self.assertNotEqual(self.run_assertion(), 0)

    def test_duplicate_and_malformed_event_records_refuse(self):
        for rows in [[self.header, self.event, self.event], [self.header, "malformed"]]:
            self.write(rows)
            self.assertNotEqual(self.run_assertion(), 0)
        self.write([self.header, self.event])
        self.queue.write_text(self.queue.read_text() + '{"idempotency_key":"OTHER"')
        self.assertNotEqual(self.run_assertion(), 0)

    def test_unsafe_custody_refuses_without_repair(self):
        self.write([self.header, self.event])
        # Even a header-free event must not pass from an unsafe file.
        self.write([self.event])
        self.queue.chmod(0o644)
        original = self.queue.read_bytes()
        self.assertNotEqual(self.run_assertion(), 0)
        self.assertEqual(self.queue.read_bytes(), original)
        self.assertEqual(self.queue.stat().st_mode & 0o777, 0o644)
        self.queue.chmod(0o600)
        os.link(self.queue, self.queue.with_name("alias"))
        self.assertNotEqual(self.run_assertion(), 0)
        self.assertEqual(self.queue.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
