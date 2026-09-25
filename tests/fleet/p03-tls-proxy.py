#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only

"""Small quiet TLS terminator for the disposable P03 QEMU guests."""

from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import argparse
import os
import ssl
import threading
import time


class ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, _format, *_args):
        return

    def do_GET(self):  # noqa: N802 - stdlib handler interface
        self._forward()

    def do_POST(self):  # noqa: N802 - stdlib handler interface
        self._forward()

    def _forward(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 0 or length > 1_048_576:
                self.send_error(413)
                return
            body = self.rfile.read(length) if length else None
            if self.command == "POST" and self.path == "/api/v3/node/session":
                with self.server.mismatch_lock:
                    force_protocol_mismatch = self.server.force_protocol_mismatch
                if force_protocol_mismatch:
                    if self.server.mismatch_marker:
                        marker_fd = os.open(
                            self.server.mismatch_marker,
                            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                            0o600,
                        )
                        with os.fdopen(marker_fd, "wb") as marker:
                            marker.write(b"P03-PROTOCOL-MISMATCH-RESPONSE\n")
                            marker.flush()
                            os.fsync(marker.fileno())
                    payload = b'{"error":"unsupported_protocol"}'
                    self.send_response(426)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(payload)))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(payload)
                    self.close_connection = True
                    return
            headers = {
                name: value
                for name, value in self.headers.items()
                if name.lower() not in {"connection", "content-length", "host", "transfer-encoding"}
            }
            connection = HTTPConnection("127.0.0.1", 3200, timeout=40)
            connection.request(self.command, self.path, body=body, headers=headers)
            response = connection.getresponse()
            payload = response.read(1_048_577)
            if len(payload) > 1_048_576:
                self.send_error(502)
                connection.close()
                return
            if self.command == "POST" and self.path == "/api/v3/node/events":
                with self.server.drop_lock:
                    if self.server.drop_first_events_response and not self.server.events_response_dropped:
                        self.server.events_response_dropped = True
                        if self.server.drop_marker:
                            marker_fd = os.open(
                                self.server.drop_marker,
                                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                                0o600,
                            )
                            with os.fdopen(marker_fd, "wb") as marker:
                                marker.write(b"P03-FIRST-EVENT-RESPONSE-DROPPED\n")
                                marker.flush()
                                os.fsync(marker.fileno())
                        time.sleep(self.server.drop_hold_seconds)
                        connection.close()
                        self.close_connection = True
                        return
            if self.command == "POST" and self.path == "/api/v3/node/poll":
                try:
                    response_body = json.loads(payload)
                    has_grant = any(
                        item.get("envelope", {}).get("kind") == "grant"
                        for item in response_body.get("documents", [])
                    )
                except (TypeError, ValueError, AttributeError):
                    has_grant = False
                if has_grant:
                    with self.server.grant_delay_lock:
                        delay_grant_response = (
                            self.server.delay_first_grant_response
                            and not self.server.grant_response_delayed
                        )
                        if delay_grant_response:
                            self.server.grant_response_delayed = True
                    if delay_grant_response:
                        if self.server.grant_marker:
                            marker_fd = os.open(
                                self.server.grant_marker,
                                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                                0o600,
                            )
                            with os.fdopen(marker_fd, "wb") as marker:
                                marker.write(b"P03-FIRST-GRANT-RESPONSE-HELD\n")
                                marker.flush()
                                os.fsync(marker.fileno())
                        time.sleep(self.server.grant_delay_seconds)
            self.send_response(response.status)
            for name, value in response.getheaders():
                if name.lower() in {"content-type", "cache-control"}:
                    self.send_header(name, value)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(payload)
            connection.close()
        except Exception:
            if not self.wfile.closed:
                self.send_error(502)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--certificate", required=True)
    parser.add_argument("--private-key", required=True)
    parser.add_argument("--drop-first-events-response", action="store_true")
    parser.add_argument("--drop-marker")
    parser.add_argument("--drop-hold-seconds", type=float, default=0.0)
    parser.add_argument("--force-protocol-mismatch", action="store_true")
    parser.add_argument("--mismatch-marker")
    parser.add_argument("--delay-first-grant-response", action="store_true")
    parser.add_argument("--grant-marker")
    parser.add_argument("--grant-delay-seconds", type=float, default=0.0)
    args = parser.parse_args()
    server = ThreadingHTTPServer(("0.0.0.0", 8443), ProxyHandler)
    server.daemon_threads = True
    server.drop_first_events_response = args.drop_first_events_response
    server.events_response_dropped = False
    server.drop_lock = threading.Lock()
    server.drop_marker = args.drop_marker
    server.drop_hold_seconds = max(0.0, min(args.drop_hold_seconds, 10.0))
    server.force_protocol_mismatch = args.force_protocol_mismatch
    server.mismatch_marker = args.mismatch_marker
    server.mismatch_lock = threading.Lock()
    server.delay_first_grant_response = args.delay_first_grant_response
    server.grant_response_delayed = False
    server.grant_delay_lock = threading.Lock()
    server.grant_marker = args.grant_marker
    server.grant_delay_seconds = max(0.0, min(args.grant_delay_seconds, 10.0))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(args.certificate, args.private_key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever(poll_interval=0.25)


if __name__ == "__main__":
    main()
