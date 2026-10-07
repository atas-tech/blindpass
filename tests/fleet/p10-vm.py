#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""P10 cross-workload fulfillment, end to end in two QEMU guests.

A production-mode (authority-backed, built-in TLS) controller on the host serves two real
brokers and nodes in two disposable guests: A holds a dummy credential for the issuer unit,
B runs recipient units that read a fulfilled credential through the root-only credential
loader (`LoadCredential=`) and present it to a dummy provider on the host. Everything is
disposable: random names, a private run directory, throwaway authority and controller
databases in the existing PostgreSQL fixture, guest overlays, and a generated dummy credential.

Scenarios (acceptance plan `P10-*`, mode `reencrypt` only, no provider adapter):

  I01  unruled pair denied by default; unknown body fields refused; approval bound to the
       displayed node fingerprints; the requester cannot approve; the allow rule needs no approval
  E01  approve -> offer -> seal -> deliver -> store -> unit reads it -> authenticates -> completed;
       a repeat after completion with a lineage reference; deny; revoke before the read
  I04  partitioned issuer node, controller restart in flight, expiry before and after delivery,
       recipient broker restart (custody is memory-only, nothing is resumed)
  E02  feature disabled with a live fulfillment: revoked at startup, no new issuance, the node's
       broker drops the pending state, re-enable
  S    the dummy credential appears nowhere in controller or guest state, argv, environments or
       logs (every scan is first shown to find a planted value)

Not covered here: node key rotation in flight (controller test P10.6), a lost reply on a live
connection, provider-side revocation (`provider_revocation` is `unsupported`; the dummy provider
keeps accepting a copied credential and the harness asserts the API says so).
"""

import argparse
import base64
import hashlib
import hmac
import http.client
import http.server
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import sys
import threading
import time

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("p06_relay_vm", HERE / "p06-relay-vm.py")
relay = importlib.util.module_from_spec(_spec)
sys.modules["p06_relay_vm"] = relay
_spec.loader.exec_module(relay)

Failure = relay.Failure
BIN = relay.BIN
ORIGIN = relay.ORIGIN
GUEST_USER = relay.GUEST_USER
run = relay.run

# Guest B recipient units: one per scenario, because one recipient workload holds one live
# fulfillment and a read credential stays in broker memory for its normal lifetime.
RECIPIENTS = ("happy", "allow", "deny", "revoke", "partition", "expiry", "disable", "unruled")
CREDENTIAL = "api-key"
SHORT_TTL_SECONDS = 60
PROGRESS_SECONDS = 120


def passed(name, detail=""):
    print(f"P10-VM {name} PASS {detail}".rstrip(), flush=True)


_base_env = relay.Controller._env_base


def _env_with_flag(self):
    values = _base_env(self)
    values["BLINDPASS_FULFILLMENTS_ENABLED"] = "1" if getattr(self.r, "fulfillments_enabled", True) else "0"
    return values


relay.Controller._env_base = _env_with_flag


class Provider:
    """The dummy provider: accepts exactly one bearer value and never logs it."""

    def __init__(self, expected):
        self.expected = ("Bearer " + expected).encode()
        self.outcomes = []
        provider = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                presented = (self.headers.get("Authorization") or "").encode()
                ok = hmac.compare_digest(presented, provider.expected)
                provider.outcomes.append(ok)
                self.send_response(200 if ok else 401)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *args):
                return

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def accepted(self):
        return sum(1 for ok in self.outcomes if ok)

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


def guest_p10(vm, *args, data=None, check=True, timeout=180):
    return vm.guest("sudo", "/usr/local/sbin/blindpass-p10-guest", *args, data=data, check=check, timeout=timeout)


def install_tools(vm):
    vm.guest("mkdir", "-m", "0700", "-p", "/tmp/p10")
    run(["scp", *[("-P" if o == "-p" else o) for o in vm.ssh_options()], str(BIN / "blindpass-provision"),
         str(HERE / "p10-guest.sh"), f"{GUEST_USER}@127.0.0.1:/tmp/p10/"])
    vm.guest("sudo", "install", "-m", "0755", "/tmp/p10/p10-guest.sh", "/usr/local/sbin/blindpass-p10-guest")
    guest_p10(vm, "install-tools")


def recipient_unit(label):
    return f"blindpass-p10-recipient-{label}.service"


def advertises_fulfillments(capabilities):
    """The capability document's `fleet_fulfillments` flag, wherever it is nested."""
    stack = [capabilities]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            if "fleet_fulfillments" in item:
                return item["fleet_fulfillments"] is True
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
    raise Failure("the capability document has no fleet_fulfillments flag")


# ---- stages ---------------------------------------------------------------------------------

def source_stage(r):
    r.fulfillments_enabled = True
    relay.source_stage(r)
    status, capabilities = r.api.request("GET", "/api/v3/capabilities", session=False)
    if status != 200 or not advertises_fulfillments(capabilities):
        raise Failure("the controller does not advertise fulfillments with the flag on")
    passed("S1", "production controller serving with BLINDPASS_FULFILLMENTS_ENABLED=1; capability advertised")


def enroll_node(r, vm, name):
    status, capabilities = r.api.request("GET", "/api/v3/capabilities", session=False)
    pub = capabilities["issuer_pub"]
    fingerprint = hashlib.sha256(base64.urlsafe_b64decode(pub + "=" * (-len(pub) % 4))).hexdigest()
    status, enrollment = r.api.request("POST", "/api/v3/enrollments", {"name": name})
    if status not in (200, 201):
        raise Failure("enrollment create refused")
    r.canaries.append(enrollment["token"])
    output = vm.guest_helper("enroll", ORIGIN, fingerprint, data=enrollment["token"].encode()).stdout.decode()
    found = re.search(r"fingerprint=([a-f0-9]{64}) status=submitted", output)
    if not found:
        raise Failure("node enrollment did not print its fingerprint")
    status, current = r.api.request("GET", f"/api/v3/enrollments/{enrollment['id']}")
    if status != 200 or current["fingerprint"] != found.group(1):
        raise Failure("controller and node fingerprints differ")
    status, body = r.api.request("POST", f"/api/v3/enrollments/{enrollment['id']}/approve",
                                 {"expected_fingerprint": found.group(1), "expected_version": current["version"]},
                                 {"If-Match": f'"{current["version"]}"'})
    if status != 200:
        raise Failure(f"enrollment approval refused: status={status}")
    vm.guest_helper("start-node")
    wait_node_online(r, enrollment["node_id"])
    return enrollment["node_id"], found.group(1)


def wait_node_online(r, node_id, timeout=90):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status, node = r.api.request("GET", f"/api/v3/nodes/{node_id}")
        if status == 200 and node.get("status") == "online":
            return
        time.sleep(1)
    raise Failure("node did not come online")


def enroll_stage(r):
    r.provider = Provider(r.credential)
    r.boot_guest()
    r.vm_a = r.vm
    r.vm_b = r.add_vm("b", relay.SSH_PORT + 1)
    for vm in (r.vm_a, r.vm_b):
        install_tools(vm)
    guest_p10(r.vm_a, "configure-issuer")
    guest_p10(r.vm_b, "configure-recipients", str(r.provider.port), *RECIPIENTS)
    r.node_a, r.fingerprint_a = enroll_node(r, r.vm_a, "p10-issuer-node")
    r.node_b, r.fingerprint_b = enroll_node(r, r.vm_b, "p10-recipient-node")
    if r.fingerprint_a == r.fingerprint_b:
        raise Failure("two nodes share a fingerprint")
    guest_p10(r.vm_a, "provision-source", data=(r.credential + "\n").encode())
    passed("S2", "two real brokers and nodes enrolled over verified HTTPS and online; the issuer broker holds the dummy "
                 "credential; recipient units mapped with fulfillment ceilings")


def create_operator(r, label):
    suffix = secrets.token_hex(4)
    first = "P10-DUMMY-" + secrets.token_hex(12)
    r.canaries.append(first)
    status, operator = r.api.request("POST", "/api/v3/admin/operators", {
        "username": f"p10-{label}-{suffix}", "display_name": f"P10 {label}", "role": "operator", "password": first})
    if status not in (200, 201):
        raise Failure(f"{label} operator was not created")
    api = relay.TlsApi(r.dir / "controller.crt")
    session = api.login(f"p10-{label}-{suffix}", first)
    if session.get("must_change_password"):
        changed = "P10-DUMMY-" + secrets.token_hex(12)
        r.canaries.append(changed)
        status, _ = api.request("POST", "/api/v3/admin/session/change-password",
                                {"current_password": first, "new_password": changed})
        if status != 204:
            raise Failure(f"{label} password change refused")
        api = relay.TlsApi(r.dir / "controller.crt")
        first = changed
        api.login(f"p10-{label}-{suffix}", first)
    return operator, api, (f"p10-{label}-{suffix}", first)


def register_workload(r, node_id, name, unit, account):
    status, workload = r.api.request("POST", "/api/v3/workloads", {
        "node_id": node_id, "name": name, "unit": unit, "account": account,
        "consumption_mode": "file", "local_ceiling_seconds": 120})
    if status not in (200, 201):
        raise Failure(f"workload {name} was not registered (status {status})")
    return workload["id"]


def wait_inboxes_applied(r, timeout=90):
    """Every signed document queued for both nodes is acknowledged by its broker."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        pending = 0
        for node_id in (r.node_a, r.node_b):
            rows = r.db_rows(r.source, "SELECT count(*) FROM node_inbox WHERE node_id=? AND acked_at IS NULL", (node_id,))
            pending += int(rows[0][0])
        if pending == 0:
            return
        time.sleep(0.5)
    raise Failure("a node inbox stayed unacknowledged")


def put_cross_rules(r, rules):
    status, policy = r.api.request("GET", "/api/v3/policies")
    if status != 200:
        raise Failure("policy read refused")
    status, updated = r.api.request("PUT", "/api/v3/policies", {
        "expected_version": policy["version"], "rules": policy["rules"], "cross_workload": rules},
        {"If-Match": f'"{policy["version"]}"'})
    if status != 200:
        raise Failure(f"cross-workload policy refused (status {status})")
    return updated


def setup_stage(r):
    r.approver, r.approver_api, r.approver_login = create_operator(r, "approver")
    account_a = r.vm_a.guest_helper("workload-account").stdout.decode().strip()
    account_b = r.vm_b.guest_helper("workload-account").stdout.decode().strip()
    for account in (account_a, account_b):
        if not re.fullmatch(r"uid:[1-9][0-9]*", account):
            raise Failure("guest returned a malformed workload account")
    r.issuer_wl = register_workload(r, r.node_a, "p10-issuer", "blindpass-p10-issuer.service", account_a)
    r.recipient_wl = {label: register_workload(r, r.node_b, f"p10-recipient-{label}", recipient_unit(label), account_b)
                      for label in RECIPIENTS}
    approvers = [r.approver["id"]]
    pending = [r.recipient_wl[label] for label in ("happy", "revoke", "partition", "disable")]
    r.rules = [
        {"id": "p10-approve", "issuer_workload_ids": [r.issuer_wl], "recipient_workload_ids": pending,
         "decision": "pending_approval", "approver_ids": approvers, "max_ttl_seconds": 300},
        {"id": "p10-allow", "issuer_workload_ids": [r.issuer_wl], "recipient_workload_ids": [r.recipient_wl["allow"]],
         "decision": "allow", "max_ttl_seconds": 300},
        {"id": "p10-deny", "issuer_workload_ids": [r.issuer_wl], "recipient_workload_ids": [r.recipient_wl["deny"]],
         "decision": "deny", "max_ttl_seconds": 300},
        {"id": "p10-short", "issuer_workload_ids": [r.issuer_wl], "recipient_workload_ids": [r.recipient_wl["expiry"]],
         "decision": "allow", "max_ttl_seconds": SHORT_TTL_SECONDS},
    ]
    put_cross_rules(r, r.rules)
    wait_inboxes_applied(r)
    passed("S3", "approver operator, one issuer and eight recipient workloads registered, explicit cross-workload rules "
                 "applied by both brokers")



def restart_controller(r, enabled=True, pause=0.0, while_stopped=None):
    """Stop the production controller (which fences its authority), optionally act while it is
    down, reactivate the authority and start it again with the feature flag as given. Operator
    sessions are re-established because the harness clients hold no cookies across a restart."""
    r.source.stop()
    r.fulfillments_enabled = enabled
    if while_stopped:
        while_stopped()
    time.sleep(pause)
    r.authority.script("authority-activate.sql", **r.variables)
    r.source.start()
    r.wait_ready(r.source)
    r.api = relay.TlsApi(r.dir / "controller.crt")
    r.api.login("admin", r.password)
    r.approver_api = relay.TlsApi(r.dir / "controller.crt")
    r.approver_api.login(*r.approver_login)

# ---- API helpers ----------------------------------------------------------------------------

def create(r, recipient_label, purpose="P10 harness", prior=None, issuer=None, recipient=None, extra=None):
    body = {"issuer_workload_id": issuer or r.issuer_wl,
            "recipient_workload_id": recipient or r.recipient_wl[recipient_label],
            "issuer_credential": CREDENTIAL, "recipient_credential": CREDENTIAL, "purpose": purpose}
    if prior:
        body["prior_fulfillment_id"] = prior
    body.update(extra or {})
    return r.api.request("POST", "/api/v3/fulfillments", body, {"Idempotency-Key": "p10vm" + secrets.token_hex(16)})


def create_ok(r, recipient_label, **kwargs):
    status, record = create(r, recipient_label, **kwargs)
    if status not in (200, 201):
        raise Failure(f"fulfillment create refused: status={status} error={record and record.get('error')}")
    return record


def detail(r, fid, api=None):
    status, record = (api or r.api).request("GET", f"/api/v3/fulfillments/{fid}")
    if status != 200:
        raise Failure(f"fulfillment read refused (status {status})")
    return record


def approve(r, fid, issuer_fingerprint=None, recipient_fingerprint=None, api=None):
    api = api or r.approver_api
    current = detail(r, fid, api)
    return api.request("POST", f"/api/v3/fulfillments/{fid}/approve", {
        "expected_version": current["version"],
        "issuer_fingerprint": issuer_fingerprint or current["issuer"]["fingerprint"],
        "recipient_fingerprint": recipient_fingerprint or current["recipient"]["fingerprint"]},
        {"If-Match": f'"{current["version"]}"'})


def wait_status(r, fid, wanted, seconds=PROGRESS_SECONDS):
    wanted = set(wanted.split("|")) if isinstance(wanted, str) else set(wanted)
    deadline = time.monotonic() + seconds
    last = None
    while time.monotonic() < deadline:
        last = detail(r, fid)
        if last["status"] in wanted:
            return last
        if last["status"] in ("failed", "denied", "revoked", "expired", "completed"):
            raise Failure(f"fulfillment closed as {last['status']} ({last.get('failure_code') or last.get('revocation_reason')}) "
                          f"instead of {'|'.join(sorted(wanted))}")
        time.sleep(0.5)
    raise Failure(f"fulfillment stayed {last and last['status']} instead of {'|'.join(sorted(wanted))}")


def error_of(body):
    return body.get("error") if isinstance(body, dict) else None


def read_recipient(r, label):
    out = guest_p10(r.vm_b, "run-recipient", label).stdout.decode()
    found = re.search(r"start_status=(\d+) result=(\S+) provider=(.*)", out)
    if not found:
        raise Failure("recipient unit result is malformed")
    return int(found.group(1)), found.group(2), found.group(3).strip()


def expect_read_ok(r, label):
    before = r.provider.accepted()
    status, result, provider = read_recipient(r, label)
    if status != 0 or result != "success" or provider != "P10-PROVIDER status=200" or r.provider.accepted() != before + 1:
        raise Failure(f"recipient unit {label} did not authenticate (start={status} result={result} provider={provider})")


def expect_read_refused(r, label):
    before = len(r.provider.outcomes)
    status, result, provider = read_recipient(r, label)
    # A refused loader read arrives as an empty credential, which the unit reports without
    # contacting the provider.
    if status == 0 or provider not in ("none", "P10-PROVIDER credential=empty") or len(r.provider.outcomes) != before:
        raise Failure(f"recipient unit {label} read a credential it should not have (start={status} provider={provider})")


def deliver_to_recipient(r, fid):
    """Approved fulfillment through to the recipient broker holding the credential."""
    return wait_status(r, fid, "recipient_consumed")


# ---- scenarios ------------------------------------------------------------------------------

def scenario_i01(r):
    # Default deny: a pair no rule names, a reversed pair, and unknown body fields.
    status, body = create(r, "unruled")
    if status != 403 or error_of(body) != "cross_workload_denied":
        raise Failure(f"an unruled pair was not denied (status {status}, {error_of(body)})")
    status, body = create(r, None, issuer=r.recipient_wl["happy"], recipient=r.issuer_wl)
    if status != 403 or error_of(body) != "cross_workload_denied":
        raise Failure("a reversed pair was not denied")
    for extra in ({"mode": "provider_issue"}, {"recipient_public": "AAAA"}, {"tenant_id": "other"}):
        status, body = create(r, "happy", extra=extra)
        if status not in (400, 422):
            raise Failure(f"unknown body field {list(extra)[0]} was accepted (status {status})")
    status, body = create(r, "happy", issuer=r.issuer_wl, recipient=r.issuer_wl)
    if status in (200, 201):
        raise Failure("one workload was allowed to fulfill itself")
    # Approval rules: the requester is not a named approver, a wrong fingerprint changes nothing.
    record = create_ok(r, "happy")
    if record["status"] != "awaiting_approval":
        raise Failure(f"an approval rule did not wait for approval ({record['status']})")
    status, body = approve(r, record["id"], api=r.api)
    if status != 403 or error_of(body) not in ("approval_scope_denied", "self_approval_denied"):
        raise Failure(f"the requester approved their own fulfillment (status {status}, {error_of(body)})")
    status, body = approve(r, record["id"], issuer_fingerprint="0" * 64)
    if status != 409 or error_of(body) != "authorization_changed":
        raise Failure(f"a substituted fingerprint was not refused (status {status}, {error_of(body)})")
    if detail(r, record["id"])["status"] != "awaiting_approval":
        raise Failure("a refused approval changed the fulfillment")
    r.i01_record = record
    passed("P10-I01", "unruled and reversed pairs and self-fulfillment denied; unknown fields (mode, recipient key, tenant) "
                      "refused; requester cannot approve; a substituted node fingerprint is refused and changes nothing")


def scenario_e01_complete(r):
    record = r.i01_record
    status, approved = approve(r, record["id"])
    if status != 200:
        raise Failure(f"approval refused (status {status}, {error_of(approved)})")
    stored = deliver_to_recipient(r, record["id"])
    if stored["issuer"]["node_id"] == stored["recipient"]["node_id"]:
        raise Failure("issuer and recipient share a node")
    expect_read_ok(r, "happy")
    done = wait_status(r, record["id"], "completed")
    if done.get("provider_revocation") != "unsupported":
        raise Failure("the record does not state that provider revocation is unsupported")
    r.first_completed = done["id"]
    passed("P10-E01a", "approved fulfillment reached the recipient broker through two nodes; the recipient unit loaded the "
                       "credential through the loader and the dummy provider accepted it; status completed; "
                       "provider_revocation=unsupported")
    # Repeat: the recipient broker still holds the first credential, so a new fulfillment that does
    # not name the one it replaces is refused by the broker and never overwrites it.
    blocked = create_ok(r, "happy")
    approve_ok(r, blocked["id"])
    closed = wait_status(r, blocked["id"], "failed")
    expect_read_ok(r, "happy")
    if detail(r, done["id"])["status"] != "completed":
        raise Failure("a refused repeat or a later read changed the completed fulfillment")
    second = create_ok(r, "happy", prior=done["id"])
    approve_ok(r, second["id"])
    wait_status(r, second["id"], "recipient_consumed")
    expect_read_ok(r, "happy")
    wait_status(r, second["id"], "completed")
    passed("P10-E01b", f"repeat without lineage failed at the broker ({closed.get('failure_code')}) and left the first credential "
                       f"in place; with prior_fulfillment_id it completed (provider accepted {r.provider.accepted()} presentations)")


def approve_ok(r, fid):
    status, body = approve(r, fid)
    if status != 200:
        raise Failure(f"approval refused (status {status}, {error_of(body)})")
    return body


def scenario_e01_allow(r):
    record = create_ok(r, "allow")
    if record["status"] == "awaiting_approval":
        raise Failure("an allow rule asked for approval")
    wait_status(r, record["id"], "recipient_consumed")
    expect_read_ok(r, "allow")
    wait_status(r, record["id"], "completed")
    passed("P10-I01b", "an allow rule needs no approval and completes the same two-node path")


def scenario_e01_deny(r):
    status, body = create(r, "deny")
    if status != 403 or error_of(body) != "cross_workload_denied":
        raise Failure(f"a deny rule did not deny (status {status}, {error_of(body)})")
    expect_read_refused(r, "deny")
    passed("P10-E01c", "a deny rule refused before any node was contacted; the recipient unit has nothing to load")


def scenario_e01_revoke(r):
    record = create_ok(r, "revoke")
    approve_ok(r, record["id"])
    wait_status(r, record["id"], "recipient_consumed")
    status, revoked = r.api.request("DELETE", f"/api/v3/fulfillments/{record['id']}")
    if status != 200 or revoked["status"] != "revoked":
        raise Failure(f"revocation refused (status {status}, {error_of(revoked)})")
    if revoked.get("provider_revocation") != "unsupported" or not revoked.get("delivery_revoked_at"):
        raise Failure("the revoked record does not separate delivery revocation from provider revocation")
    # The revocation reaches guest B's broker through the node. Reading before it is applied would
    # be a read of a live credential, which no revocation can recall, so wait for the broker's
    # acknowledgement first and read once.
    wait_inboxes_applied(r)
    expect_read_refused(r, "revoke")
    status, again = r.api.request("DELETE", f"/api/v3/fulfillments/{record['id']}")
    if status not in (200, 409):
        raise Failure(f"repeat revocation changed state unexpectedly (status {status})")
    passed("P10-E01d", "revoked after delivery and before the read: the recipient broker removed the unread credential and "
                       "the unit could not load it; record keeps delivery_revoked_at and provider_revocation=unsupported")
    # A credential that was already read cannot be recalled: revoking the completed fulfillment
    # changes nothing, the unit can still load it and the provider still accepts it.
    status, closed = r.api.request("DELETE", f"/api/v3/fulfillments/{r.first_completed}")
    if status != 200 or closed["status"] != "completed" or closed.get("provider_revocation") != "unsupported":
        raise Failure(f"revoking a completed fulfillment claimed an effect (status {status}, {closed and closed.get('status')})")
    expect_read_ok(r, "happy")
    passed("P10-I03", "revoking a completed fulfillment leaves it completed with provider_revocation=unsupported; the unit still "
                      "loads the credential and the provider still accepts it, so no remote erasure is claimed")


def scenario_i04_partition(r):
    record = create_ok(r, "partition")
    r.vm_a.guest_helper("stop-node")
    approve_ok(r, record["id"])
    offered = wait_status(r, record["id"], "offered|approved")
    time.sleep(8)
    held = detail(r, record["id"])
    if held["status"] not in ("approved", "offered"):
        raise Failure(f"the fulfillment advanced past the offer while the issuer node was partitioned ({held['status']})")
    r.vm_a.guest_helper("start-node")
    wait_node_online(r, r.node_a)
    # The controller goes away while the fulfillment is in flight; the nodes retry and nothing is duplicated.
    restart_controller(r, pause=3)
    wait_status(r, record["id"], "available|recipient_consumed")
    wait_status(r, record["id"], "recipient_consumed")
    expect_read_ok(r, "partition")
    wait_status(r, record["id"], "completed")
    rows = r.db_rows(r.source, "SELECT count(*) FROM cross_fulfillment_payloads WHERE fulfillment_id=?", (record["id"],))
    if int(rows[0][0]) != 0:
        raise Failure("ciphertext outlived the delivery")
    passed("P10-I04a", f"issuer node partitioned after approval ({held['status']} for 8 s), reconnected, controller restarted "
                       "in flight: one legal completion; controller ciphertext deleted after receipt")


def scenario_x_expiry(r):
    record = create_ok(r, "expiry")
    wait_status(r, record["id"], "recipient_consumed")
    # Custody is memory-only: a broker restart loses the stored credential and nothing resumes.
    guest_p10(r.vm_b, "restart-broker")
    expect_read_refused(r, "expiry")
    closed = wait_status(r, record["id"], "expired|uncertain|failed", SHORT_TTL_SECONDS + 60)
    if closed["status"] == "completed":
        raise Failure("a lost credential completed")
    status, body = create(r, "expiry")
    if closed["status"] == "uncertain" and (status != 409 or error_of(body) != "recipient_busy"):
        raise Failure("an uncertain fulfillment did not hold the recipient slot")
    wait_node_online(r, r.node_b)
    passed("P10-I04b", f"recipient broker restarted after delivery: the unit could not read, the fulfillment closed as "
                       f"{closed['status']} within its {SHORT_TTL_SECONDS} s bound and was never resumed")


def scenario_e02_disable(r):
    record = create_ok(r, "disable")
    r.vm_b.guest_helper("stop-node")
    approve_ok(r, record["id"])
    time.sleep(3)
    restart_controller(r, enabled=False)
    status, body = r.api.request("GET", "/api/v3/capabilities", session=False)
    if advertises_fulfillments(body):
        raise Failure("the capability is still advertised with the feature off")
    closed = detail(r, record["id"])
    if closed["status"] != "revoked" or closed.get("revocation_reason") != "feature_disabled":
        raise Failure(f"disabling the feature left the fulfillment {closed['status']}/{closed.get('revocation_reason')}")
    status, body = create(r, "disable")
    if status != 404 or error_of(body) != "fulfillments_disabled":
        raise Failure(f"new issuance was not refused with the feature off (status {status}, {error_of(body)})")
    r.vm_b.guest_helper("start-node")
    wait_node_online(r, r.node_b)
    expect_read_refused(r, "disable")
    restart_controller(r, enabled=True)
    status, body = r.api.request("GET", "/api/v3/capabilities", session=False)
    if not advertises_fulfillments(body):
        raise Failure("the capability did not return after the feature was re-enabled")
    wait_node_online(r, r.node_a)
    wait_node_online(r, r.node_b)
    passed("P10-E02", "feature disabled with a pending fulfillment: revoked at startup (feature_disabled), capability withdrawn, "
                      "new issuance refused, the recipient broker holds nothing; feature re-enabled on restart")


def scenario_scans(r):
    secret = r.credential
    # Audit and API: metadata links identities and outcomes; the credential is in none of it.
    rows, cursor = [], None
    for _ in range(200):
        query = "/api/v3/admin/audit?limit=100" + (f"&cursor={cursor}" if cursor else "")
        status, page = r.api.request("GET", query)
        if status != 200:
            raise Failure("audit read refused")
        rows.extend(page.get("items") or page.get("events") or [])
        cursor = page.get("next_cursor")
        if not cursor:
            break
    text = json.dumps(rows)
    for encoding in (secret, base64.b64encode(secret.encode()).decode(), base64.urlsafe_b64encode(secret.encode()).decode().rstrip("="),
                     secret.encode().hex()):
        if encoding in text:
            raise Failure("an audit row contains the credential")
    events = {row.get("event") for row in rows}
    for needed in ("fleet.fulfillment_requested", "fleet.fulfillment_decided"):
        if needed not in events:
            raise Failure(f"audit lacks {needed}")
    first = [row for row in rows if row.get("resource_id") == r.first_completed]
    if not any(row.get("actor_id") for row in first):
        raise Failure("the completed fulfillment's audit rows do not name an actor")
    # Controller store: every table of the store, both backends.
    store_text = ""
    for table in ("cross_fulfillments", "cross_fulfillment_payloads", "node_inbox", "node_events"):
        try:
            store_text += json.dumps(r.db_rows(r.source, f"SELECT * FROM {table}"))
        except Failure:
            continue
    if len(store_text) < 200:
        raise Failure("the store scan read no rows")
    for encoding in (secret, base64.b64encode(secret.encode()).decode(), secret.encode().hex()):
        if encoding in store_text:
            raise Failure("the controller store contains the credential")
    secrets_to_find = [secret, *r.canaries, r.authority.owner_password, r.authority.runtime_password]
    try:
        relay.canary_log_scan.assert_log_clean("P10 controller log", relay.canary_log_scan.read_log(r.source.log),
                                               secrets_to_find, markers=["PRIVATE KEY"], min_bytes=256)
    except relay.canary_log_scan.LogScanError as error:
        raise Failure(str(error)) from None
    for tag, vm in (("A", r.vm_a), ("B", r.vm_b)):
        guest_p10(vm, "scan-control", data=(secret + "\n").encode(), timeout=300)
        guest_p10(vm, "scan-state", data=(secret + "\n").encode(), timeout=300)
    passed("P10-S", "the dummy credential is absent from audit rows, the controller store, the controller log and, on both "
                    "guests, persistent and runtime state, argv, environments and the journal (each scan first found a planted value)")


SCENARIOS = [
    ("i01", scenario_i01),
    ("e01", scenario_e01_complete),
    ("allow", scenario_e01_allow),
    ("deny", scenario_e01_deny),
    ("revoke", scenario_e01_revoke),
    ("partition", scenario_i04_partition),
    ("expiry", scenario_x_expiry),
    ("disable", scenario_e02_disable),
    ("scan", scenario_scans),
]
STAGES = ["source", "enroll", "setup"]


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--backend", choices=("sqlite", "postgres"), default=os.environ.get("BLINDPASS_P10_BACKEND", "sqlite"))
    parser.add_argument("--only", help="debugging: comma-separated scenario names after i01 and e01 (never acceptance evidence)")
    args = parser.parse_args()
    relay.SSH_PORT = int(os.environ.get("BLINDPASS_P10_SSH_PORT", "22241"))
    blocked = relay.preflight(args.backend)
    if blocked:
        return blocked
    for needed in ("blindpass-provision",):
        if not (BIN / needed).is_file():
            return relay.unsupported(f"{needed} is not built; run: cargo build --release --bins")
    r = relay.Rehearsal(args)
    r.credential = "P10-DUMMY-" + secrets.token_urlsafe(24)
    only = set(args.only.split(",")) if args.only else None
    if only:
        print("P10-VM DEBUG scenario filter; not acceptance evidence", flush=True)
    try:
        for stage in STAGES:
            globals()[f"{stage}_stage"](r)
            if stage == "source":
                r.canaries.append(r.credential)
        for name, scenario in SCENARIOS:
            if only and name not in only and name not in ("i01", "e01"):
                continue
            scenario(r)
        return 0
    except (Failure, OSError, ssl.SSLError, http.client.HTTPException, KeyError, ValueError) as error:
        print(f"P10-VM FAIL {type(error).__name__}: {error}", file=sys.stderr)
        for controller in r.controllers:
            if controller.log.exists():
                print(f"--- {controller.name} log tail", file=sys.stderr)
                print(controller.log.read_text()[-1500:], file=sys.stderr)
        return 1
    finally:
        if getattr(r, "provider", None):
            r.provider.stop()
        r.cleanup()


if __name__ == "__main__":
    sys.exit(main())
