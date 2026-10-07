#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""P06 recovery with two real nodes, each a real broker and node in its own QEMU guest.

One production-mode (authority-backed, built-in TLS) controller on the host enrolls node A
and node B in two disposable guests, issues a real grant on A, is backed up, fenced and
restored under a recovering authority record, and then recovers according to the scenario:

  refusal   A relays and is covered; B never relays and is not waived. Review completion
            and recovery activation are both refused, the controller is not fenced and the
            authority record is unchanged.
  waiver    A relays; B never relays and is waived by name (broker trust revoked in the
            authority, who and why recorded). Activation succeeds. A is online and consumes an
            ordinary grant; B stays revoked, and a workload registration for B is refused
            while the identical request for A is accepted.
  both      A relays, activation is refused while B is uncovered, then B relays after A and
            both are covered. Both nodes come back online and each consumes an ordinary grant.

Every scenario also checks that the old source stays refused (waiver, both) and that no
credential reached a log. `--backend postgres` keeps the store in a PostgreSQL schema.

It reuses `p06-recovery-activation-vm.py` and `p06-relay-vm.py`. It is not a native-package,
Compose or remote-controller recovery, runs x86-64 KVM guests only and makes no provider API
call.
"""

import argparse
import base64
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import sys
import time

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("p06_recovery_activation_vm", HERE / "p06-recovery-activation-vm.py")
act = importlib.util.module_from_spec(_spec)
sys.modules["p06_recovery_activation_vm"] = act
_spec.loader.exec_module(act)
relay = act.relay

Failure = relay.Failure
SSH_PORT_B = int(os.environ.get("BLINDPASS_P06_SSH_PORT_B", "22232"))


def passed(name, detail=""):
    print(f"P06-RM {name} PASS {detail}".rstrip(), flush=True)


def node(r, node_id):
    rows = [n for n in act.cli_json(r, "status")["nodes"] if n["node_id"] == node_id]
    if len(rows) != 1:
        raise Failure("the authority does not list the node exactly once")
    return rows[0]


# ---- stages ------------------------------------------------------------------

def enroll_b_stage(r):
    """The second node: its own guest, enrolled over the same verified HTTPS controller."""
    r.node_a = r.node_id
    r.vm_a = r.vm
    vm = r.add_vm("b", SSH_PORT_B)
    r.vm_b = vm
    status, capabilities = r.api.request("GET", "/api/v3/capabilities", session=False)
    pub = capabilities["issuer_pub"]
    fingerprint = hashlib.sha256(base64.urlsafe_b64decode(pub + "=" * (-len(pub) % 4))).hexdigest()
    status, enrollment = r.api.request("POST", "/api/v3/enrollments", {"name": "p06-matrix-b"})
    if status not in (200, 201):
        raise Failure("second enrollment create refused")
    r.node_b = enrollment["node_id"]
    r.canaries.append(enrollment["token"])
    output = vm.guest_helper("enroll", relay.ORIGIN, fingerprint, data=enrollment["token"].encode()).stdout.decode()
    found = re.search(r"fingerprint=([a-f0-9]{64}) status=submitted", output)
    if not found:
        raise Failure("node B did not print its fingerprint")
    status, current = r.api.request("GET", f"/api/v3/enrollments/{enrollment['id']}")
    if status != 200 or current["fingerprint"] != found.group(1):
        raise Failure("controller and node B fingerprints differ")
    status, _ = r.api.request("POST", f"/api/v3/enrollments/{enrollment['id']}/approve",
                              {"expected_fingerprint": found.group(1), "expected_version": current["version"]},
                              {"If-Match": f'"{current["version"]}"'})
    if status != 200:
        raise Failure("node B enrollment approval refused")
    vm.guest_helper("start-node")
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        status, listing = r.api.request("GET", f"/api/v3/nodes/{r.node_b}")
        if status == 200 and listing.get("status") == "online":
            break
        time.sleep(1)
    else:
        raise Failure("node B did not come online")
    if r.node_a == r.node_b or found.group(1) == "":
        raise Failure("the two nodes share an identity")
    count = r.authority.scalar("SELECT count(*) FROM blindpass_authority.broker_trust WHERE state='active' AND node_id IN "
                               f"('{r.node_a}','{r.node_b}')")
    if count != "2":
        raise Failure("the authority does not hold active broker trust for both nodes")
    passed("M1", "two real broker+node pairs (guest A, guest B) enrolled over verified HTTPS; both online; the authority holds active broker trust for each")


def restore_stage(r):
    act.restore_stage(r)
    relay.run(["scp", *[("-P" if o == "-p" else o) for o in r.vm_b.ssh_options()], str(relay.BIN / "blindpass"),
               f"{relay.GUEST_USER}@127.0.0.1:/tmp/p03/blindpass"])
    r.vm_b.guest("chmod", "0755", "/tmp/p03/blindpass")


def relay_a_stage(r):
    result = relay.relay_command(r, vm=r.vm_a)
    out = result.stdout.decode().strip()
    if result.returncode != 0 or out != "recovery_relay state=covered pages=1 activation_permitted=false":
        raise Failure(f"node A relay did not complete: exit={result.returncode} stdout={out!r}")
    a, b = node(r, r.node_a), node(r, r.node_b)
    if a["receipt"] != "covered" or b["receipt"] == "covered" or a["waived"] or b["waived"]:
        raise Failure("only node A should be covered at this point")
    if "node_uncovered" not in act.open_gates(r):
        raise Failure("the precheck does not list the unreported node B as uncovered")
    passed("M2", f"{out}; the authority shows A covered and B {b['receipt']!r} (not waived); the precheck lists node_uncovered")


def uncovered_activation_refused(r, label):
    before = act.ledger(r)
    r.restored.stop()  # the administrator scripts need the tenant guard free
    try:
        text = act.refused_with(act.script(r, "authority-recover-activate.sql"), "node_uncovered", label=label)
    finally:
        r.restored.start()
        r.wait_ready(r.restored, expect=503)
    if act.ledger(r) != before:
        raise Failure(f"{label}: a refused activation changed the record")
    return text


def decide_everything(r):
    """Every review item decided, but no completion. Operators are accepted so the
    operator can log in after activation; the rest is rejected."""
    cli = act.cli
    act.cli_json(r, "review", "decide", "--category", "operation", "--decision", "reject", "--operator", "p06rm-operator")
    cli(r, "review", "decide", "--category", "operator", "--decision", "accept", "--operator", "p06rm-operator")
    for category in ("agent", "workload", "legacy_policy", "fleet_policy", "source_binding", "node_key_rotation"):
        cli(r, "review", "decide", "--category", category, "--decision", "reject", "--operator", "p06rm-operator")
    leftover = [i for i in act.cli_json(r, "review", "list")["items"] if i["decision"] is None]
    if leftover:
        raise Failure(f"review items left undecided: {sorted({i['category'] for i in leftover})}")


def refusal_stage(r):
    before = act.ledger(r)
    decide_everything(r)
    done = act.cli(r, "review", "complete", "--operator", "p06rm-operator", check=False)
    if done.returncode == 0 or done.stderr.decode().strip() != "blindpass: refused":
        raise Failure("review completion accepted a node that is neither covered nor waived")
    r.wait_ready(r.restored, expect=503)
    if "node_uncovered" not in act.open_gates(r) or act.ledger(r) != before:
        raise Failure("the refusal changed the gates or the record")
    passed("X1", "every review item decided, yet completion is refused while node B is neither covered nor waived; controller not fenced; record unchanged")
    text = uncovered_activation_refused(r, "activation with an uncovered node")
    for gate in ("source_stop_missing", "review_incomplete"):
        if gate not in text:
            raise Failure(f"the activation refusal does not also name {gate}")
    passed("X2", f"authority-recover-activate.sql refuses naming node_uncovered ({before} unchanged); the restored controller was restarted and stayed fenced")


def waiver_stage(r):
    before = act.ledger(r)
    decide_everything(r)
    blocked = act.cli(r, "review", "complete", "--operator", "p06rm-operator", check=False)
    if blocked.returncode == 0:
        raise Failure("completion accepted node B before it was covered or waived")
    r.wait_ready(r.restored, expect=503)
    passed("W1", "completion refused while B is neither covered nor waived (A already covered)")
    unknown = act.cli(r, "waive-node", "no-such-node", "--operator", "p06rm-operator", "--note", "x", check=False)
    if unknown.returncode == 0:
        raise Failure("a waiver for an unknown node was accepted")
    act.cli_json(r, "waive-node", r.node_b, "--operator", "p06rm-operator", "--note", "node B never came back")
    a, b = node(r, r.node_a), node(r, r.node_b)
    if not (b["waived"] and b["revoked"]) or a["waived"] or a["revoked"]:
        raise Failure("the waiver must revoke only node B")
    row = r.authority.scalar(f"SELECT waived_by||':'||note FROM blindpass_authority.recovery_node_waivers WHERE node_id='{r.node_b}'")
    if row != "p06rm-operator:node B never came back":
        raise Failure("the waiver row does not carry operator and note")
    states = r.authority.scalar("SELECT string_agg(node_id||'='||state, ',' ORDER BY node_id) FROM blindpass_authority.broker_trust")
    if f"{r.node_a}=active" not in states or f"{r.node_b}=revoked" not in states:
        raise Failure(f"authority broker trust is wrong after the waiver: {states}")
    done = act.cli_json(r, "review", "complete", "--operator", "p06rm-operator")
    if done["summary"]["nodes_revoked"] != 1:
        raise Failure("completion did not revoke exactly the waived node")
    rows = dict(r.db_rows(r.restored, "SELECT id,status FROM nodes"))
    if rows.get(r.node_b) != "revoked" or rows.get(r.node_a) == "revoked":
        raise Failure(f"controller node states are wrong after completion: {rows}")
    if act.ledger(r) != before:
        raise Failure("review completion changed the authority record")
    passed("W2", f"B waived by name (trust revoked in the authority, operator and note recorded, A untouched); completion revoked only B ({done['summary']})")


def both_uncovered_stage(r):
    before = act.ledger(r)
    text = uncovered_activation_refused(r, "activation with node B uncovered")
    if "source_stop_missing" not in text:
        raise Failure("the activation refusal does not list the other open gates")
    passed("C1", f"activation refused naming node_uncovered while only A is covered ({before} unchanged)")


def relay_b_stage(r):
    result = relay.relay_command(r, vm=r.vm_b)
    out = result.stdout.decode().strip()
    if result.returncode != 0 or not re.fullmatch(r"recovery_relay state=covered pages=\d+ activation_permitted=false", out):
        raise Failure(f"node B relay did not complete: exit={result.returncode} stdout={out!r}")
    a, b = node(r, r.node_a), node(r, r.node_b)
    if a["receipt"] != "covered" or b["receipt"] != "covered" or a["waived"] or b["waived"]:
        raise Failure("both nodes should be covered, neither waived")
    if "node_uncovered" in act.open_gates(r):
        raise Failure("node_uncovered is still listed with both nodes covered")
    if not re.fullmatch(r"recovery_relay state=covered pages=\d+ activation_permitted=false",
                        relay.relay_command(r, vm=r.vm_a).stdout.decode().strip()):
        raise Failure("B's relay disturbed node A's covered state")
    passed("C2", f"{out}; B relayed after A and both are covered by the authority; A's repeat relay still covered")


def activate_stage(r):
    act.activate_stage(r)


def serve_stage(r, expect_b):
    ready, elapsed = act.run_start_gate(r, "restored controller")
    rows = {row["id"]: row for row in act.lookup_node(r)}
    if set(rows) != {r.node_a, r.node_b} or rows[r.node_a]["status"] != "online":
        raise Failure("node A is not online at the activated controller")
    if expect_b == "online":
        deadline = time.monotonic() + 60
        while rows[r.node_b]["status"] != "online":
            if time.monotonic() > deadline:
                raise Failure("node B did not come online at the activated controller")
            time.sleep(1)
            rows = {row["id"]: row for row in act.lookup_node(r)}
        if act.guest_status(r, r.password).returncode != 0:
            raise Failure("`status --nodes --require-online` fails with both nodes active")
        detail = "both nodes online"
    else:
        seen = rows[r.node_b].get("last_seen_at")
        time.sleep(15)  # B's own reconnect attempts must not bring it back
        rows = {row["id"]: row for row in act.lookup_node(r)}
        if rows[r.node_b]["status"] != "revoked" or rows[r.node_b].get("last_seen_at") != seen:
            raise Failure("the waived node came back or was seen by the activated controller")
        if r.authority.scalar(f"SELECT state FROM blindpass_authority.broker_trust WHERE node_id='{r.node_b}'") != "revoked":
            raise Failure("the waived node's broker trust is not revoked")
        if act.guest_status(r, r.password).returncode != 0:
            raise Failure("revoked B must not fail the online gate for the active node A")
        detail = "A online, B stays revoked (its guest services still running and retrying)"
    passed("S1", f"activated controller ready {ready:.1f} s after start, {detail}; node A seen {elapsed:.1f} s after start through `status --nodes --require-online`")


def serve_online_stage(r):
    serve_stage(r, "online")


def serve_waived_stage(r):
    serve_stage(r, "revoked")


def grant_on(r, vm, node_id, label):
    previous = (r.vm, r.node_id, r.grant_id)
    r.vm, r.node_id = vm, node_id
    try:
        act.grant_stage(r)
    finally:
        r.vm, r.node_id = previous[0], previous[1]
    passed(f"G-{label}", f"an ordinary grant was approved, delivered to node {label} and consumed by a workload in guest {label} through the activated controller")


def grant_a_stage(r):
    grant_on(r, r.vm_a, r.node_a, "A")


def grant_b_stage(r):
    grant_on(r, r.vm_b, r.node_b, "B")


def b_refused_stage(r):
    suffix = secrets.token_hex(4)
    account = r.vm_a.guest_helper("workload-account").stdout.decode().strip()

    def register(node_id, unit):
        return r.api.request("POST", "/api/v3/workloads", {
            "node_id": node_id, "name": f"p06rm-{unit}", "unit": f"blindpass-p03-p06rm-{unit}.service", "account": account,
            "consumption_mode": "file", "local_ceiling_seconds": 120})
    control, _ = register(r.node_a, "a" + suffix)
    refused, body = register(r.node_b, "b" + suffix)
    if "node_unavailable" not in json.dumps(body):
        raise Failure("the refusal for node B does not carry the node_unavailable code")
    if control not in (200, 201):
        raise Failure(f"control: a workload registration for the active node A was refused ({control})")
    if refused in (200, 201) or refused >= 500:
        raise Failure(f"a workload registration for the waived node B was not cleanly refused ({refused})")
    passed("W3", f"the same workload registration is accepted for node A ({control}) and refused for the waived node B ({refused})")


def source_refused_stage(r):
    act.source_refused_stage(r)


def logs_stage(r):
    for vm in (r.vm_a, r.vm_b):
        r.vm = vm
        relay.scan_logs(r)
    r.vm = r.vm_a
    passed("L1", "no credential, token, authority password or PEM private key in the controller logs or either guest's broker and node journals")


COMMON = ["source", "enroll", "enroll_b", "grant", "restore", "relay_a"]
SCENARIOS = {
    "refusal": COMMON + ["refusal", "logs"],
    "waiver": COMMON + ["waiver", "activate", "serve_waived", "grant_a", "b_refused", "source_refused", "logs"],
    "both": COMMON + ["both_uncovered", "relay_b", "review", "activate", "serve_online", "grant_a", "grant_b",
                      "source_refused", "logs"],
}
PHASES = {
    "source": relay.source_stage, "enroll": relay.enroll_stage, "enroll_b": enroll_b_stage, "grant": relay.grant_stage,
    "restore": restore_stage, "relay_a": relay_a_stage, "refusal": refusal_stage, "waiver": waiver_stage,
    "both_uncovered": both_uncovered_stage, "relay_b": relay_b_stage, "review": act.review_stage,
    "activate": activate_stage, "serve_waived": serve_waived_stage, "serve_online": serve_online_stage,
    "grant_a": grant_a_stage, "grant_b": grant_b_stage, "b_refused": b_refused_stage,
    "source_refused": source_refused_stage, "logs": logs_stage,
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", choices=sorted(SCENARIOS), required=True)
    parser.add_argument("--until")
    parser.add_argument("--backend", choices=("sqlite", "postgres"), default=os.environ.get("BLINDPASS_P06_BACKEND", "sqlite"))
    args = parser.parse_args()
    stages = SCENARIOS[args.scenario]
    if args.until and args.until not in stages:
        parser.error("unknown stage for this scenario")
    blocked = relay.preflight(args.backend)
    if blocked:
        return blocked
    r = relay.Rehearsal(args)
    try:
        for stage in stages:
            PHASES[stage](r)
            if stage == args.until:
                break
        return 0
    except (Failure, OSError, ssl.SSLError, http.client.HTTPException, KeyError, ValueError, IndexError) as error:
        print(f"P06-RM FAIL {type(error).__name__}: {error}", file=sys.stderr)
        for controller in r.controllers:
            if controller.log.exists():
                print(f"--- {controller.name} log tail", file=sys.stderr)
                print(controller.log.read_text()[-1500:], file=sys.stderr)
        return 1
    finally:
        r.cleanup()


if __name__ == "__main__":
    sys.exit(main())
