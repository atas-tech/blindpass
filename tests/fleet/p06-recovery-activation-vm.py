#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""P06-D30..D32 protected recovery activation, end to end in a QEMU guest.

A production-mode (authority-backed, built-in TLS) controller on the host enrolls a
real broker and node in a disposable guest and issues one real grant. It is backed
up, fenced, stopped and restored under a recovering authority record. The guest node
then reports through `blindpass-node recovery-relay`, the operator reviews every
quarantined item, the administrator attests that the source is stopped, and the
authority administrator activates the record. The restored controller then serves,
the unchanged node comes back online and an ordinary grant is issued and consumed.

Scenarios (`--scenario`):
  main      gates and refusals, relay, review, attestation, activation, serving, an
            ordinary grant, the old source refused, then the restore-based rollback
            rehearsal (restore the original archive again from the activated state, with
            a grant the archive never saw, and activate that recovery too).
  waiver    the node never reports: it is waived by name, stays revoked, and the
            controller still activates and serves.

`--backend postgres` runs either scenario with the controller store in a PostgreSQL schema of
the docker fixture. Backup, verification and restore run in the pinned toolkit image (the host
has no PGDG toolkit); the controller process itself stays on the host.

It reuses the host and guest plumbing of `p06-relay-vm.py`. Nothing here is a
two-broker recovery, a Compose or native-package recovery, or a provider API call.
"""

import argparse
import http.client
import importlib.util
import json
import os
from pathlib import Path
import ssl
import sys
import time

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("p06_relay_vm", HERE / "p06-relay-vm.py")
relay = importlib.util.module_from_spec(_spec)
sys.modules["p06_relay_vm"] = relay
_spec.loader.exec_module(relay)

Failure = relay.Failure
BIN = relay.BIN
run = relay.run
ORIGIN = relay.ORIGIN
STATUS_BOUND_SECONDS = 120


def passed(name, detail=""):
    print(f"P06-RA {name} PASS {detail}".rstrip(), flush=True)


def ledger(r):
    return r.authority.scalar("SELECT phase||':'||epoch||':'||revision FROM blindpass_authority.recovery_authority")


def script(r, name, check=False, **extra):
    """An authority administrator script through psql; returns the completed process."""
    result = r.authority.psql((relay.ROOT / "deploy/controller" / name).read_text(),
                              variables={**r.variables, **extra}, check=False)
    if check and result.returncode:
        raise Failure(f"authority script {name} failed")
    return result


def refused_with(result, *gates, label):
    text = result.stderr.decode()
    if result.returncode == 0:
        raise Failure(f"{label}: the authority accepted what it must refuse")
    for gate in gates:
        if gate not in text:
            raise Failure(f"{label}: refusal does not name the open gate {gate}")
    return text


def cli(r, *args, check=True):
    """`blindpass admin recovery ...` against the recovering controller's local socket."""
    result = run([str(BIN / "blindpass"), "admin", "recovery", *args, "--socket", str(r.restored.admin_socket)],
                 check=False, timeout=120)
    if check and result.returncode:
        raise Failure(f"recovery command failed: {args[0]} ({result.stderr.decode().strip()[:80]})")
    return result


def cli_json(r, *args):
    return json.loads(cli(r, *args).stdout.decode())


def open_gates(r):
    return cli_json(r, "status")["gaps"]


def guest_status(r, password):
    return r.guest("/tmp/p03/blindpass", "status", "--nodes", "--require-online", "--controller-url", ORIGIN,
                   "--username", "admin", "--password-stdin", data=(password + "\n").encode(), check=False, timeout=60)


def wait_node_seen(r, since_ms, bound, what):
    started = time.monotonic()
    while True:
        result = guest_status(r, r.password)
        if result.returncode == 0:
            rows = json.loads(result.stdout.decode())["nodes"]
            seen = [row.get("last_seen_at") for row in rows if row.get("status") != "revoked"]
            if seen and all(isinstance(value, int) and value >= since_ms for value in seen):
                return time.monotonic() - started
        if time.monotonic() - started > bound:
            raise Failure(f"{what}: the node was not seen online by the activated controller within {bound} s")
        time.sleep(1)


def stale_source_refused(r, label):
    """The pre-restore controller (its keys and database) must never serve again."""
    stale = relay.Controller(r, f"stale-{label}", r.original.keys, r.original.data, database=r.original.database)
    r.controllers.append(stale)
    stale.start()
    try:
        stale.process.wait(timeout=20)
    except Exception:
        raise Failure("the old source kept running") from None
    if stale.process.returncode == 0:
        raise Failure("the old source exited cleanly")
    if '"event":"startup_failed"' not in stale.log.read_text():
        raise Failure("the old source did not report a startup failure")
    migrate = r.original.command("migrate", check=False)
    if migrate.returncode == 0:
        raise Failure("the old source migrated")


def run_start_gate(r, name):
    """Controller start/serve: ready, authority active, node seen by this controller."""
    since = int(time.time() * 1000)
    started = time.monotonic()
    r.restored.start()
    r.wait_ready(r.restored)
    ready_after = time.monotonic() - started
    elapsed = ready_after + wait_node_seen(r, since, STATUS_BOUND_SECONDS - ready_after, name)
    r.api = relay.TlsApi(r.dir / "controller.crt")
    r.api.login("admin", r.password)
    return ready_after, elapsed


def lookup_node(r):
    status, listing = r.api.request("GET", "/api/v3/nodes?limit=100")
    if status != 200:
        raise Failure("node listing refused")
    return listing["items"]


# ---- stages ------------------------------------------------------------------

def restore_stage(r):
    r.original = r.source
    r.archive_operation = r.operation_id  # the operation the archive holds (a later grant adds others)
    run(["scp", *[("-P" if o == "-p" else o) for o in r.ssh_options()], str(BIN / "blindpass"),
         f"{relay.GUEST_USER}@127.0.0.1:/tmp/p03/blindpass"])
    r.guest("chmod", "0755", "/tmp/p03/blindpass")
    relay.restore_stage(r)


def gates_stage(r):
    """Everything an operator or administrator might try before the gates are met."""
    before = ledger(r)
    text = refused_with(script(r, "authority-activate.sql"), label="ordinary activation of a recovering record")
    if ledger(r) != before:
        raise Failure("the ordinary activation script changed a recovering record")
    passed("G1", f"authority-activate.sql refuses the recovering record ({before}); ledger unchanged")
    text = refused_with(script(r, "authority-recover-activate.sql"), "source_stop_missing", "source_process_live",
                        "review_incomplete", "node_uncovered", label="early recovery activation")
    if ledger(r) != before:
        raise Failure("a refused recovery activation changed the record")
    passed("G2", "authority-recover-activate.sql with nothing done names all four open gates and changes nothing")
    attest = script(r, "authority-recover-attest.sql", host="p06ra-source-host", by="p06ra-admin", note="premature")
    if attest.returncode == 0 or r.authority.scalar("SELECT count(*) FROM blindpass_authority.recovery_source_stop") != "0":
        raise Failure("an attestation was accepted while the recovering controller held the guard")
    passed("G3", "attestation refused while a controller process holds the tenant guard; no row written")
    gates = open_gates(r)
    for gate in ("source_stop_missing", "review_incomplete", "node_uncovered", "review_undecided"):
        if gate not in gates:
            raise Failure(f"the controller precheck does not list {gate}: {gates}")
    if cli_json(r, "status")["activation_permitted"] is not False:
        raise Failure("the precheck permits activation")
    passed("G4", f"controller precheck lists fixed gate names {gates}")
    stale_source_refused(r, "before")
    if ledger(r) != before:
        raise Failure("an old-source start changed the recovering record")
    passed("G5", "the old source refuses to start while the record is recovering; record unchanged")


def relay_stage(r):
    result = relay.relay_command(r)
    out = result.stdout.decode().strip()
    if result.returncode != 0 or out != "recovery_relay state=covered pages=1 activation_permitted=false":
        raise Failure(f"relay did not complete: exit={result.returncode} stdout={out!r}")
    node = [n for n in cli_json(r, "status")["nodes"] if n["node_id"] == r.node_id][0]
    if node["receipt"] != "covered" or node["waived"]:
        raise Failure("the authority does not show the node as covered")
    if "node_uncovered" in open_gates(r):
        raise Failure("a covered node is still listed uncovered")
    passed("R1", f"{out}; the authority and the controller precheck show the node covered")


def review_stage(r):
    listing = cli_json(r, "review", "list")
    items = listing["items"]
    categories = sorted({item["category"] for item in items})
    if listing["total"] != len(items) or "operation" not in categories or "operator" not in categories:
        raise Failure(f"review list is incomplete: {categories}")
    if not any(i["category"] == "operation" and i["subject_id"] == r.archive_operation for i in items):
        raise Failure("the consumed operation is not listed for review")
    if any(i["decision"] is not None for i in items):
        raise Failure("items arrived already decided")
    undecided = cli(r, "review", "complete", "--operator", "p06ra-operator", check=False)
    if undecided.returncode == 0 or undecided.stderr.decode().strip() != "blindpass: refused":
        raise Failure("complete accepted an undecided review")
    unknown = cli(r, "review", "decide", "--category", "operation", "--subject", "no-such-operation",
                  "--decision", "accept", "--operator", "p06ra-operator", check=False)
    if unknown.returncode == 0:
        raise Failure("a decision for an item that does not exist was accepted")
    if not cli_json(r, "status")["gaps"]:
        raise Failure("the precheck lost its gates after refusals")
    r.wait_ready(r.restored, expect=503)  # refusals did not fence the controller
    passed("V1", f"{len(items)} items in {len(categories)} categories listed; complete refused while undecided; unknown item refused; controller not fenced")
    for category in categories:
        decision = {"operator": "accept", "operation": "accept", "workload": "revoke"}.get(category, "reject")
        out = cli_json(r, "review", "decide", "--category", category, "--decision", decision,
                       "--operator", "p06ra-operator", "--note", "reviewed by the rehearsal")
        if out["decided"] < 1:
            raise Failure(f"no undecided {category} item was decided")
    # A changed mind is allowed until completion.
    cli_json(r, "review", "decide", "--category", "operation", "--subject", r.archive_operation,
             "--decision", "revoke", "--operator", "p06ra-second", "--note", "changed")
    after = cli_json(r, "review", "list")["items"]
    row = [i for i in after if i["category"] == "operation" and i["subject_id"] == r.archive_operation][0]
    if row["decision"] != "revoke" or row["operator_id"] != "p06ra-second" or any(i["decision"] is None for i in after):
        raise Failure("decisions were not recorded with their deciding operator")
    done = cli_json(r, "review", "complete", "--operator", "p06ra-operator")
    if done["summary"]["items"] != len(after):
        raise Failure("completion did not cover every item")
    r.review_summary = done["summary"]
    status = cli_json(r, "status")
    if status["gaps"] != ["source_stop_missing"]:
        raise Failure(f"after completion only the attestation should remain, got {status['gaps']}")
    late = cli(r, "review", "decide", "--category", "operation", "--subject", r.archive_operation,
               "--decision", "accept", "--operator", "p06ra-operator", check=False)
    if late.returncode == 0:
        raise Failure("a decision was accepted after completion")
    r.wait_ready(r.restored, expect=503)
    passed("V2", f"every item decided with operator ids, a changed decision recorded, review completed ({done['summary']}); decisions closed; only source_stop_missing remains")


def activate_stage(r):
    r.restored.stop()
    before = ledger(r)
    text = refused_with(script(r, "authority-recover-activate.sql"), "source_stop_missing", label="activation without attestation")
    if "review_incomplete" in text or "node_uncovered" in text or "source_process_live" in text:
        raise Failure("refusal names gates that are met")
    passed("A1", "with the controller stopped, only the missing attestation blocks activation")
    refused_with(script(r, "authority-activate.sql"), label="ordinary activation after review")
    status = script(r, "authority-recover-status.sql", check=True).stdout.decode()
    if "source_stop_missing" not in status:
        raise Failure("the administrator precheck did not show the missing attestation")
    attest = script(r, "authority-recover-attest.sql", host="p06ra-source-host", by="p06ra-admin",
                    note="source host powered off and fenced from the network")
    if attest.returncode != 0:
        raise Failure("attestation refused although both controllers are stopped")
    row = r.authority.scalar("SELECT host_id||':'||attested_by FROM blindpass_authority.recovery_source_stop ORDER BY epoch DESC LIMIT 1")
    if row != "p06ra-source-host:p06ra-admin":
        raise Failure("attestation row does not record who and which host")
    status = script(r, "authority-recover-status.sql", check=True).stdout.decode()
    if "source_stop_missing" in status or "node_uncovered" in status or "review_incomplete" in status:
        raise Failure("the administrator precheck still lists a met gate")
    refused_with(script(r, "authority-activate.sql"), label="ordinary activation is still refused")
    if ledger(r) != before:
        raise Failure("refusals changed the recovering record")
    activated = script(r, "authority-recover-activate.sql")
    if activated.returncode != 0 or "activated recovery epoch" not in activated.stdout.decode():
        raise Failure("activation refused with every gate met")
    now = ledger(r)
    if not now.startswith("active:") or now.split(":")[1] != before.split(":")[1]:
        raise Failure(f"unexpected record after activation: {now}")
    refused_with(script(r, "authority-recover-activate.sql"), label="second activation")
    passed("A2", f"attested (who/host recorded) and activated: {before} -> {now}; ordinary script and a second activation refused")


def serve_stage(r):
    ready, elapsed = run_start_gate(r, "restored controller")
    status, _ = r.api.request("GET", "/readyz", session=False)
    if status != 200:
        raise Failure("the activated controller is not ready")
    rows = lookup_node(r)
    if [row["id"] for row in rows] != [r.node_id] or rows[0]["status"] != "online":
        raise Failure("the node is not online at the activated controller")
    r.node_key_version = rows[0]["key_version"]
    # The consumed operation stays uncertain; recovery never restores it.
    status, operation = r.api.request("GET", f"/api/v3/operations/{r.archive_operation}")
    if status != 200 or operation.get("status") not in ("uncertain", "revoked"):
        raise Failure("a recovered operation is not left uncertain or revoked")
    passed("S4", f"activated controller ready {ready:.1f} s after start; the unchanged node (key version {r.node_key_version}) passes `status --nodes --require-online` {elapsed:.1f} s after start; operator login works (accepted account re-enabled); recovered operation stays {operation['status']}")


def grant_stage(r):
    r.recovered_grant = r.grant_id
    r.source = r.restored  # the grant helper reads the serving controller's database
    relay.grant_stage(r)
    if r.grant_id == r.recovered_grant:
        raise Failure("no new grant was issued after the activation")
    passed("S5", "an ordinary grant was approved by a second operator, delivered to the node and consumed by a workload in the guest through the activated controller")


def source_refused_stage(r):
    activated = ledger(r)
    stale_source_refused(r, "after")
    status, _ = r.api.request("GET", "/readyz", session=False)
    if status != 200 or ledger(r) != activated:
        raise Failure("an old-source start disturbed the activated controller")
    passed("S6", "the old source refuses to serve and to migrate after activation; the activated controller stayed ready and the record unchanged")


def cycle(r, label, expect_intents):
    """One full recovery of the ORIGINAL archive: relay, review, attest, activate, serve."""
    relay_stage(r)
    intents = relay.sqlite_rows(r, "SELECT grant_id,mapping FROM controller_recovery_intents ORDER BY grant_id")
    if sorted(intents) != sorted(expect_intents):
        raise Failure(f"{label}: unexpected grant mapping {intents}")
    items = cli_json(r, "review", "list")["items"]
    pending = [i for i in items if i["category"] == "grant_intent"]
    if sorted(i["subject_id"] for i in pending) != sorted(g for g, m in expect_intents if m != "matched"):
        raise Failure(f"{label}: unreconciled grants are not exactly the grant_intent items")
    review_stage(r)
    activate_stage(r)
    serve_stage(r)
    return intents


def rollback_stage(r):
    """Restore the original archive again from the activated state: the documented
    rollback, which is restore-only. The archive never saw the grant issued after the
    first activation, so that grant must surface as an unreconciled intent."""
    r.source = r.original
    relay.fence_and_stop(r, r.restored)
    r.restored.stop()
    first = r.recovered_grant
    second = r.grant_id
    epoch = relay.reserve_and_restore(r, "restored_c")
    if epoch <= int(r.authority.scalar("SELECT min(epoch) FROM blindpass_authority.recovery_source_stop")):
        raise Failure("the rollback reservation is not higher than the first recovery")
    passed("B1", f"activated controller fenced and stopped; the original archive restored again under a higher recovery epoch ({epoch})")
    # The second recovery needs its own attestation row (a different epoch).
    intents = cycle(r, "rollback", [(first, "matched"), (second, "unknown")] if first != second else [(first, "matched")])
    epochs = r.authority.scalar("SELECT string_agg(epoch::text,',' ORDER BY epoch) FROM blindpass_authority.recovery_source_stop")
    activations = r.authority.scalar("SELECT string_agg(epoch::text,',' ORDER BY epoch) FROM blindpass_authority.recovery_activations")
    if epochs != activations or len(epochs.split(",")) != 2:
        raise Failure("each recovery epoch needs its own attestation and activation record")
    passed("B2", f"the rollback recovery reconciled the unknown grant through the review ({intents}), was attested and activated separately (epochs {activations}) and serves with the node online")


def waiver_stage(r):
    """The node never reports. It is waived by name, stays revoked, and recovery completes."""
    gates = open_gates(r)
    if "node_uncovered" not in gates:
        raise Failure("an unreported node is not listed as uncovered")
    cli_json(r, "review", "decide", "--category", "operation", "--decision", "reject", "--operator", "p06ra-operator")
    # Accounts are accepted so the operator can log in after activation; the rest is rejected.
    cli(r, "review", "decide", "--category", "operator", "--decision", "accept", "--operator", "p06ra-operator")
    for category in ("agent", "workload", "legacy_policy", "fleet_policy", "source_binding", "node_key_rotation"):
        cli(r, "review", "decide", "--category", category, "--decision", "reject", "--operator", "p06ra-operator")
    blocked = cli(r, "review", "complete", "--operator", "p06ra-operator", check=False)
    if blocked.returncode == 0:
        raise Failure("completion accepted an unreported, unwaived node")
    r.wait_ready(r.restored, expect=503)
    wrong = cli(r, "waive-node", "no-such-node", "--operator", "p06ra-operator", "--note", "x", check=False)
    if wrong.returncode == 0:
        raise Failure("a waiver for an unknown node was accepted")
    r.wait_ready(r.restored, expect=503)
    passed("W1", "completion refused while the node is neither covered nor waived; a waiver for an unknown node refused; controller not fenced")
    cli_json(r, "waive-node", r.node_id, "--operator", "p06ra-operator", "--note", "hardware lost in the fire")
    node = [n for n in cli_json(r, "status")["nodes"] if n["node_id"] == r.node_id][0]
    if not (node["waived"] and node["revoked"]):
        raise Failure("the waiver did not revoke the node's broker trust in the authority")
    row = r.authority.scalar(f"SELECT waived_by||':'||note FROM blindpass_authority.recovery_node_waivers WHERE node_id='{r.node_id}'")
    if row != "p06ra-operator:hardware lost in the fire":
        raise Failure("the waiver row does not carry operator and note")
    done = cli_json(r, "review", "complete", "--operator", "p06ra-operator")
    if done["summary"]["nodes_revoked"] != 1:
        raise Failure("completion did not revoke the waived node locally")
    if relay.sqlite_rows(r, "SELECT status,revoked_by FROM nodes WHERE id=?", (r.node_id,)) != [("revoked", "p06ra-operator")]:
        raise Failure("the waived node is not revoked in the controller database")
    late = cli(r, "waive-node", r.node_id, "--operator", "p06ra-operator", "--note", "late", check=False)
    if late.returncode == 0:
        raise Failure("a waiver was accepted after completion")
    passed("W2", f"node waived by name (broker trust revoked in the authority, who/why recorded); completion revoked it locally ({done['summary']})")


def waiver_activate_stage(r):
    activate_stage(r)


def waiver_serve_stage(r):
    r.restored.start()
    r.wait_ready(r.restored)
    r.api = relay.TlsApi(r.dir / "controller.crt")
    r.api.login("admin", r.password)
    rows = lookup_node(r)
    if [row["id"] for row in rows] != [r.node_id] or rows[0]["status"] != "revoked":
        raise Failure("the waived node is not revoked at the activated controller")
    time.sleep(15)  # the node's own reconnect attempts must not bring it back
    rows = lookup_node(r)
    if rows[0]["status"] != "revoked" or guest_status(r, r.password).returncode == 0:
        raise Failure("the waived node came back or the online gate passed")
    if r.authority.scalar(f"SELECT state FROM blindpass_authority.broker_trust WHERE node_id='{r.node_id}'") != "revoked":
        raise Failure("the waived node's broker trust is not revoked")
    passed("W3", "controller activated and ready without the waived node; the node stays revoked and the `status --nodes --require-online` gate fails for it; its broker trust stays revoked in the authority")


def logs_stage(r):
    relay.scan_logs(r)
    passed("L1", "no credential, token, authority password or PEM private key in any controller or guest log")


SCENARIOS = {
    "main": ["source", "enroll", "grant", "restore", "gates", "relay", "review", "activate", "serve", "grant2",
             "source_refused", "rollback", "logs"],
    "waiver": ["source", "enroll", "grant", "restore", "waiver", "waiver_activate", "waiver_serve", "logs"],
}
PHASES = {
    "source": relay.source_stage, "enroll": relay.enroll_stage, "grant": relay.grant_stage, "restore": restore_stage,
    "gates": gates_stage, "relay": relay_stage, "review": review_stage, "activate": activate_stage,
    "serve": serve_stage, "grant2": grant_stage, "source_refused": source_refused_stage,
    "rollback": rollback_stage, "waiver": waiver_stage, "waiver_activate": waiver_activate_stage,
    "waiver_serve": waiver_serve_stage, "logs": logs_stage,
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", choices=sorted(SCENARIOS), default="main")
    parser.add_argument("--until")
    parser.add_argument("--backend", choices=("sqlite", "postgres"), default=os.environ.get("BLINDPASS_P06_BACKEND", "sqlite"),
                        help="controller store: SQLite files, or a PostgreSQL schema restored through the toolkit image")
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
        print(f"P06-RA FAIL {type(error).__name__}: {error}", file=sys.stderr)
        for controller in r.controllers:
            if controller.log.exists():
                print(f"--- {controller.name} log tail", file=sys.stderr)
                print(controller.log.read_text()[-1500:], file=sys.stderr)
        return 1
    finally:
        r.cleanup()


if __name__ == "__main__":
    sys.exit(main())
