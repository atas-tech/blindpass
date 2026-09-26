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
            policy_inject_stale = False
            poll_ack_seq = None
            if self.command == "POST" and self.path == "/api/v3/node/poll":
                try:
                    poll_request = json.loads(body or b"{}")
                    candidate_ack = poll_request.get("ack_seq") if isinstance(poll_request, dict) else None
                    if isinstance(candidate_ack, int) and not isinstance(candidate_ack, bool):
                        poll_ack_seq = candidate_ack
                except (TypeError, ValueError):
                    pass
                with self.server.policy_replay_lock:
                    if (
                        self.server.policy_replay_new_seq is not None
                        and poll_ack_seq is not None
                        and poll_ack_seq >= self.server.policy_replay_new_seq
                    ):
                        if not self.server.policy_replay_sent:
                            policy_inject_stale = True
                        elif (
                            not self.server.policy_replay_acknowledged
                            and self.server.policy_replay_injected_seq is not None
                            and poll_ack_seq >= self.server.policy_replay_injected_seq
                        ):
                            self.server.policy_replay_acknowledged = True
                            self._append_policy_replay_marker(
                                f"acknowledged stale_version={self.server.stale_policy_version} "
                                f"new_version={self.server.policy_replay_new_version} "
                                f"seq={self.server.policy_replay_injected_seq}"
                            )
                with self.server.grant_replay_lock:
                    if (
                        self.server.grant_replay_sent
                        and not self.server.grant_replay_acknowledged
                        and poll_ack_seq is not None
                        and poll_ack_seq >= self.server.grant_replay_injected_seq
                    ):
                        self.server.grant_replay_acknowledged = True
                        self._append_grant_replay_marker(
                            f"acknowledged seq={self.server.grant_replay_injected_seq}"
                        )
            if self.command == "POST" and self.path == "/api/v3/node/poll":
                with self.server.poll_failure_lock:
                    if self.server.poll_failures_remaining > 0:
                        self.server.poll_failures_remaining -= 1
                        failure_number = (
                            self.server.poll_failures_total
                            - self.server.poll_failures_remaining
                        )
                    else:
                        failure_number = 0
                if failure_number > 0:
                    if self.server.poll_failure_marker:
                        marker_fd = os.open(
                            self.server.poll_failure_marker,
                            os.O_WRONLY | os.O_CREAT | os.O_APPEND,
                            0o600,
                        )
                        with os.fdopen(marker_fd, "ab") as marker:
                            marker.write(
                                f"{failure_number} {int(time.time() * 1000)}\n".encode()
                            )
                            marker.flush()
                            os.fsync(marker.fileno())
                    payload = b'{"error":"temporary_unavailable"}'
                    self.send_response(503)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(payload)))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(payload)
                    self.close_connection = True
                    return
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
                with self.server.time_reply_lock:
                    if self.server.saved_time_reply is not None and not self.server.time_reply_replayed:
                        self.server.replay_next_time_reply = True
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
                response_body_modified = False
                try:
                    response_body = json.loads(payload)
                except (TypeError, ValueError):
                    response_body = None
                if (
                    isinstance(response_body, dict)
                    and isinstance(response_body.get("time_reply"), dict)
                ):
                    marker_event = None
                    with self.server.time_reply_lock:
                        if self.server.saved_time_reply is None:
                            self.server.saved_time_reply = response_body["time_reply"]
                            marker_event = "captured"
                        elif (
                            self.server.replay_next_time_reply
                            and not self.server.time_reply_replayed
                        ):
                            response_body["time_reply"] = self.server.saved_time_reply
                            self.server.time_reply_replayed = True
                            self.server.replay_next_time_reply = False
                            marker_event = "replayed"
                    if marker_event:
                        if self.server.time_reply_marker:
                            marker_fd = os.open(
                                self.server.time_reply_marker,
                                os.O_WRONLY | os.O_CREAT | os.O_APPEND,
                                0o600,
                            )
                            with os.fdopen(marker_fd, "ab") as marker:
                                marker.write(
                                    f"{marker_event} {int(time.time() * 1000)}\n".encode()
                                )
                                marker.flush()
                                os.fsync(marker.fileno())
                    if marker_event == "replayed":
                        response_body_modified = True
                if isinstance(response_body, dict):
                    documents = response_body.get("documents")
                    if not isinstance(documents, list):
                        documents = []
                        response_body["documents"] = documents
                    with self.server.policy_replay_lock:
                        if self.server.policy_capture_path and not self.server.policy_captured:
                            for item in documents:
                                envelope = item.get("envelope") if isinstance(item, dict) else None
                                version = self._policy_version(envelope)
                                if version is not None:
                                    self._write_policy_capture(envelope)
                                    self.server.policy_captured = True
                                    self.server.captured_policy_version = version
                                    break
                        if self.server.stale_policy_envelope is not None:
                            for item in documents:
                                envelope = item.get("envelope") if isinstance(item, dict) else None
                                version = self._policy_version(envelope)
                                if (
                                    version is not None
                                    and self.server.policy_replay_new_seq is None
                                    and version > self.server.stale_policy_version
                                ):
                                    seq = item.get("seq")
                                    if isinstance(seq, int) and not isinstance(seq, bool):
                                        self.server.policy_replay_new_seq = seq
                                        self.server.policy_replay_new_version = version
                                        self._append_policy_replay_marker(
                                            f"new_policy version={version} seq={seq}"
                                        )
                                    break
                        if (
                            policy_inject_stale
                            and not self.server.policy_replay_sent
                            and self.server.stale_policy_envelope is not None
                        ):
                            highest_seq = poll_ack_seq if poll_ack_seq is not None else 0
                            for item in documents:
                                seq = item.get("seq") if isinstance(item, dict) else None
                                if isinstance(seq, int) and not isinstance(seq, bool):
                                    highest_seq = max(highest_seq, seq)
                            injected_seq = highest_seq + 1
                            documents.append({
                                "seq": injected_seq,
                                "envelope": self.server.stale_policy_envelope,
                            })
                            self.server.policy_replay_sent = True
                            self.server.policy_replay_injected_seq = injected_seq
                            self._append_policy_replay_marker(
                                f"injected stale_version={self.server.stale_policy_version} "
                                f"new_version={self.server.policy_replay_new_version} seq={injected_seq}"
                            )
                            response_body_modified = True
                    with self.server.grant_replay_lock:
                        if self.server.grant_capture_path and not self.server.grant_captured:
                            for item in documents:
                                envelope = item.get("envelope") if isinstance(item, dict) else None
                                if self._is_grant_revocation(envelope):
                                    self._write_signed_capture(self.server.grant_capture_path, envelope)
                                    self.server.grant_captured = True
                                    break
                        if (
                            self.server.replay_grant_revocation is not None
                            and not self.server.grant_replay_sent
                        ):
                            highest_seq = poll_ack_seq if poll_ack_seq is not None else 0
                            for item in documents:
                                seq = item.get("seq") if isinstance(item, dict) else None
                                if isinstance(seq, int) and not isinstance(seq, bool):
                                    highest_seq = max(highest_seq, seq)
                            injected_seq = highest_seq + 1
                            documents.append({
                                "seq": injected_seq,
                                "envelope": self.server.replay_grant_revocation,
                            })
                            self.server.grant_replay_sent = True
                            self.server.grant_replay_injected_seq = injected_seq
                            self._append_grant_replay_marker(f"injected seq={injected_seq}")
                            response_body_modified = True
                try:
                    has_grant = any(
                        item.get("envelope", {}).get("kind") == "grant"
                        for item in response_body.get("documents", [])
                    ) if isinstance(response_body, dict) else False
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
                if response_body_modified:
                    payload = json.dumps(
                        response_body,
                        separators=(",", ":"),
                        ensure_ascii=False,
                    ).encode()
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

    @staticmethod
    def _policy_version(envelope):
        if not isinstance(envelope, dict) or envelope.get("kind") != "policy_snapshot":
            return None
        policy_body = envelope.get("body")
        version = policy_body.get("policy_version") if isinstance(policy_body, dict) else None
        return version if isinstance(version, int) and not isinstance(version, bool) else None

    @staticmethod
    def _is_grant_revocation(envelope):
        if not isinstance(envelope, dict) or envelope.get("kind") != "revocation":
            return False
        body = envelope.get("body")
        return isinstance(body, dict) and isinstance(body.get("grant_id"), str)

    def _write_policy_capture(self, envelope):
        self._write_signed_capture(self.server.policy_capture_path, envelope)

    @staticmethod
    def _write_signed_capture(path, envelope):
        marker_fd = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        with os.fdopen(marker_fd, "w", encoding="utf-8") as capture:
            json.dump(envelope, capture, separators=(",", ":"), ensure_ascii=False)
            capture.write("\n")
            capture.flush()
            os.fsync(capture.fileno())

    def _append_policy_replay_marker(self, message):
        if not self.server.policy_replay_marker:
            return
        marker_fd = os.open(
            self.server.policy_replay_marker,
            os.O_WRONLY | os.O_CREAT | os.O_APPEND,
            0o600,
        )
        with os.fdopen(marker_fd, "ab") as marker:
            marker.write(f"{message} at={int(time.time() * 1000)}\n".encode())
            marker.flush()
            os.fsync(marker.fileno())

    def _append_grant_replay_marker(self, message):
        if not self.server.grant_replay_marker:
            return
        marker_fd = os.open(
            self.server.grant_replay_marker,
            os.O_WRONLY | os.O_CREAT | os.O_APPEND,
            0o600,
        )
        with os.fdopen(marker_fd, "ab") as marker:
            marker.write(f"{message} at={int(time.time() * 1000)}\n".encode())
            marker.flush()
            os.fsync(marker.fileno())


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
    parser.add_argument("--fail-first-node-polls", type=int, default=0)
    parser.add_argument("--poll-failure-marker")
    parser.add_argument("--replay-time-reply-on-reconnect", action="store_true")
    parser.add_argument("--time-reply-marker")
    parser.add_argument("--capture-policy-snapshot")
    parser.add_argument("--replay-policy-snapshot")
    parser.add_argument("--policy-replay-marker")
    parser.add_argument("--capture-grant-revocation")
    parser.add_argument("--replay-grant-revocation")
    parser.add_argument("--grant-replay-marker")
    args = parser.parse_args()
    if args.fail_first_node_polls < 0 or args.fail_first_node_polls > 10:
        parser.error("--fail-first-node-polls must be between 0 and 10")
    if args.fail_first_node_polls and not args.poll_failure_marker:
        parser.error("--poll-failure-marker is required with --fail-first-node-polls")
    if args.replay_time_reply_on_reconnect and not args.time_reply_marker:
        parser.error("--time-reply-marker is required with --replay-time-reply-on-reconnect")
    if args.capture_policy_snapshot and args.replay_policy_snapshot:
        parser.error("capture and replay policy snapshot modes are mutually exclusive")
    if args.replay_policy_snapshot and not args.policy_replay_marker:
        parser.error("--policy-replay-marker is required with --replay-policy-snapshot")
    if args.capture_grant_revocation and args.replay_grant_revocation:
        parser.error("capture and replay grant revocation modes are mutually exclusive")
    if args.replay_grant_revocation and not args.grant_replay_marker:
        parser.error("--grant-replay-marker is required with --replay-grant-revocation")
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
    server.poll_failures_remaining = args.fail_first_node_polls
    server.poll_failures_total = args.fail_first_node_polls
    server.poll_failure_lock = threading.Lock()
    server.poll_failure_marker = args.poll_failure_marker
    server.saved_time_reply = None
    server.replay_next_time_reply = False
    server.time_reply_replayed = False
    server.time_reply_lock = threading.Lock()
    server.time_reply_marker = args.time_reply_marker if args.replay_time_reply_on_reconnect else None
    server.policy_capture_path = args.capture_policy_snapshot
    server.policy_captured = False
    server.captured_policy_version = None
    server.stale_policy_envelope = None
    server.stale_policy_version = None
    server.policy_replay_new_seq = None
    server.policy_replay_new_version = None
    server.policy_replay_sent = False
    server.policy_replay_injected_seq = None
    server.policy_replay_acknowledged = False
    server.policy_replay_marker = args.policy_replay_marker
    server.policy_replay_lock = threading.Lock()
    server.grant_capture_path = args.capture_grant_revocation
    server.grant_captured = False
    server.replay_grant_revocation = None
    server.grant_replay_sent = False
    server.grant_replay_injected_seq = None
    server.grant_replay_acknowledged = False
    server.grant_replay_marker = args.grant_replay_marker
    server.grant_replay_lock = threading.Lock()
    if args.replay_policy_snapshot:
        try:
            with open(args.replay_policy_snapshot, encoding="utf-8") as source:
                server.stale_policy_envelope = json.load(source)
        except (OSError, ValueError) as error:
            parser.error(f"could not read signed policy snapshot: {error}")
        server.stale_policy_version = ProxyHandler._policy_version(server.stale_policy_envelope)
        if server.stale_policy_version is None:
            parser.error("saved policy snapshot is malformed")
    if args.replay_grant_revocation:
        try:
            with open(args.replay_grant_revocation, encoding="utf-8") as source:
                server.replay_grant_revocation = json.load(source)
        except (OSError, ValueError) as error:
            parser.error(f"could not read signed grant revocation: {error}")
        if not ProxyHandler._is_grant_revocation(server.replay_grant_revocation):
            parser.error("saved grant revocation is malformed")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(args.certificate, args.private_key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever(poll_interval=0.25)


if __name__ == "__main__":
    main()
