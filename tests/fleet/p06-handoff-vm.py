#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""P06-D28 planned same-owner handoff, end to end in a QEMU guest.

A production-mode (authority-backed, built-in TLS) controller on the host enrolls a
real broker and node in a disposable guest and issues one real grant. It is then
fenced, stopped and handed off to a second controller (new directories, same TLS
endpoint and certificate, same authority record and owner) with `blindpass handoff
export|import` and the existing `authority-activate.sql`. The guest node is never
re-enrolled.

Covered here: abort before activation and a re-export, interrupted export and import
(process killed at a failpoint, then repeated), refusals (a second handoff id, an
existing destination, a wrong owner), the stale source refusing to serve or
migrate, abort refusing after activation, the node reconnecting, a grant issued and
consumed after the handoff, the destination marker being consumed on first start,
and a credential scan of every log.

It reuses the host and guest plumbing of `p06-relay-vm.py`. The interrupted-step
cases need a controller built with `--features p02-test-failpoints`; point
BLINDPASS_P06_FAILPOINT_CONTROLLER at it, otherwise they are reported as skipped.
Nothing here is RR05, a recovery activation or a Compose handoff.
"""

import importlib.util
import json
import os
from pathlib import Path
import ssl
import http.client
import stat
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
FAILPOINT_BINARY = os.environ.get("BLINDPASS_P06_FAILPOINT_CONTROLLER")


def passed(name, detail=""):
    print(f"P06-HO {name} PASS {detail}".rstrip(), flush=True)


def skipped(name, detail):
    print(f"P06-HO {name} SKIPPED {detail}", flush=True)


def ledger(r):
    return r.authority.scalar("SELECT phase||':'||epoch||':'||revision FROM blindpass_authority.recovery_authority")


def json_line(result):
    lines = result.stdout.decode().strip().splitlines()
    if not lines:
        raise Failure("command printed no summary")
    return json.loads(lines[-1])


def handoff(r, controller, *args, check=True, timeout=300):
    """The operator CLI (`blindpass handoff ...`) with the controller's environment."""
    return run([str(BIN / "blindpass"), "handoff", *args], env=controller.env(), check=check, timeout=timeout)


def failpoint(r, controller, name, *args):
    """Run one controller maintenance command that is killed at a persistence boundary."""
    env = dict(controller.env(), BLINDPASS_TEST_MODE="1", BLINDPASS_TEST_FAILPOINT=name)
    result = run([FAILPOINT_BINARY, "handoff", *args], env=env, check=False, timeout=300)
    if result.returncode != 86:
        raise Failure(f"failpoint {name} did not stop the process (exit {result.returncode})")


def guest_status(r, password):
    """`blindpass status --nodes --require-online` run in the guest, which trusts the controller CA."""
    return r.guest("/tmp/p03/blindpass", "status", "--nodes", "--require-online", "--controller-url", ORIGIN,
                   "--username", "admin", "--password-stdin", data=(password + "\n").encode(), check=False, timeout=60)


def wait_node_seen(r, since_ms, bound, what):
    """Poll the guest status gate until it passes and every active node was seen by the
    serving controller after `since_ms`, so a last-seen value from the previous holder
    cannot satisfy the gate. Returns seconds from the call."""
    started = time.monotonic()
    while True:
        result = guest_status(r, r.password)
        if result.returncode == 0:
            try:
                rows = json.loads(result.stdout.decode())["nodes"]
            except (ValueError, KeyError):
                raise Failure("status output is not the documented JSON") from None
            seen = [row.get("last_seen_at") for row in rows if row.get("status") != "revoked"]
            if seen and all(isinstance(value, int) and value >= since_ms for value in seen):
                return time.monotonic() - started
        if time.monotonic() - started > bound:
            raise Failure(f"{what}: the node was not seen online by the new holder within {bound} s")
        time.sleep(1)


def node_rows(r):
    status, listing = r.api.request("GET", "/api/v3/nodes?limit=100")
    if status != 200:
        raise Failure("node listing refused")
    return listing["items"]


def source_phase(r):
    """Stage 1: a controller with an enrolled node and a consumed grant, plus the recovery key."""
    relay.source_stage(r)
    relay.enroll_stage(r)
    relay.grant_stage(r)
    r.first_grant = r.grant_id
    rows = node_rows(r)
    if [row["id"] for row in rows] != [r.node_id]:
        raise Failure("expected exactly the enrolled node before the handoff")
    r.node_key_version = rows[0]["key_version"]
    relay.provision_custody(r)
    r.transfer = r.dir / "transfer"
    r.transfer.mkdir(mode=0o700)
    run(["scp", *[("-P" if o == "-p" else o) for o in r.ssh_options()], str(BIN / "blindpass"),
         f"{relay.GUEST_USER}@127.0.0.1:/tmp/p03/blindpass"])
    r.guest("chmod", "0755", "/tmp/p03/blindpass")
    first = guest_status(r, r.password)
    if first.returncode != 0:
        raise Failure("the guest status check does not pass against the running source")
    passed("H0", f"source controller serving with node {r.node_id[:8]} online (key version {r.node_key_version}) and one consumed grant; guest status gate passes")


def export_phase(r):
    """Stage 2: fenced export, repeat, refusals, interrupted export."""
    before = ledger(r)
    relay.fence_and_stop(r, r.source)
    fenced = ledger(r)
    if not fenced.startswith("fenced:"):
        raise Failure("source record is not fenced")
    phase, epoch, revision = fenced.split(":")
    r.exported_record = fenced
    marker = r.source.data / "handoff-marker.json"
    r.handoff_id = "p06ho_" + os.urandom(4).hex()
    if FAILPOINT_BINARY:
        failpoint(r, r.source, "handoff_export_after_archive", "export", "--output", str(r.transfer),
                  *relay.seal_args(r), "--handoff-id", r.handoff_id)
        if marker.exists():
            raise Failure("an interrupted export left a source marker")
        if ledger(r) != fenced:
            raise Failure("an interrupted export changed the authority record")
        r.orphans = len(list(r.transfer.glob("*")))
        if r.orphans != 1:
            raise Failure("an interrupted export did not leave exactly the sealed archive")
        passed("H1a", "export killed after the archive was sealed: no retirement marker, authority record unchanged; one unreferenced sealed archive left in the package directory")
    else:
        r.orphans = 0
        skipped("H1a", "BLINDPASS_P06_FAILPOINT_CONTROLLER is not set")
    summary = json_line(handoff(r, r.source, "export", "--output", str(r.transfer),
                                *relay.seal_args(r), "--handoff-id", r.handoff_id))
    if summary.get("handoff") != "exported" or summary.get("handoff_id") != r.handoff_id:
        raise Failure("export summary is malformed")
    if (int(summary["epoch"]), int(summary["revision"])) != (int(epoch), int(revision)):
        raise Failure("export recorded a different authority record")
    if ledger(r) != fenced:
        raise Failure("export changed the authority record")
    if not marker.is_file() or stat.S_IMODE(marker.stat().st_mode) != 0o600:
        raise Failure("source retirement marker is missing or not private")
    r.export_summary = summary
    passed("H1", f"fenced source exported (epoch {epoch}, revision {revision}); retirement marker written 0600; authority record unchanged ({before} -> {fenced})")
    again = json_line(handoff(r, r.source, "export", "--output", str(r.transfer),
                              *relay.seal_args(r), "--handoff-id", r.handoff_id))
    if again["archive_sha256"] != summary["archive_sha256"] or again["archive"] != summary["archive"]:
        raise Failure("a repeated export produced a different archive")
    other = handoff(r, r.source, "export", "--output", str(r.transfer), *relay.seal_args(r),
                    "--handoff-id", "p06ho_other", check=False)
    if other.returncode == 0:
        raise Failure("a second handoff id was accepted while a marker exists")
    passed("H2", "the same handoff id repeats to the same archive digest; a different handoff id is refused while the marker exists")
    refused = r.source.command("migrate", check=False)
    if refused.returncode == 0:
        raise Failure("a retired source migrated")
    passed("H3", "a retired source refuses migrate")


def abort_phase(r):
    """Stage 3: abort before activation, source runs again, then a second export."""
    summary = r.export_summary
    result = handoff(r, r.source, "abort", "--handoff-id", r.handoff_id, "--output", str(r.transfer))
    marker = r.source.data / "handoff-marker.json"
    if marker.exists():
        raise Failure("abort left the retirement marker")
    # Abort removes this handoff's receipt and archive. An archive sealed by an interrupted
    # export is unknown to it and stays until the operator deletes the package directory.
    leftover = sorted(path.name for path in r.transfer.glob("*"))
    if any(name.startswith("handoff-") for name in leftover) or summary["archive"] in leftover:
        raise Failure("abort left this handoff's transfer files behind")
    if len(leftover) != r.orphans:
        raise Failure("abort removed or left an unexpected file")
    for name in leftover:
        (r.transfer / name).unlink()
    if ledger(r) != r.exported_record:
        raise Failure("abort changed the authority record")
    passed("H4", "abort before any activation removed the marker and the transfer package; record still the exported one")
    r.authority.script("authority-activate.sql", **r.variables)
    since = int(time.time() * 1000)
    r.source.start()
    r.wait_ready(r.source)
    wait_node_seen(r, since, 90, "aborted source")
    r.api = relay.TlsApi(r.dir / "controller.crt")
    r.api.login("admin", r.password)
    passed("H5", "after abort the original source activated again, served, and the same node came back online")
    relay.fence_and_stop(r, r.source)
    fenced = ledger(r)
    r.exported_record = fenced
    r.handoff_id = "p06ho_" + os.urandom(4).hex()
    r.export_summary = json_line(handoff(r, r.source, "export", "--output", str(r.transfer),
                                         *relay.seal_args(r), "--handoff-id", r.handoff_id))
    passed("H6", f"source fenced and exported again under a new handoff id ({fenced})")


def import_phase(r):
    """Stage 4: interrupted import, refusals, import."""
    summary = r.export_summary
    destination = r.dir / "handoff-destination"
    arguments = ["import", "--archive", str(r.transfer / summary["archive"]), "--receipt", str(r.transfer / summary["receipt"]),
                 *relay.open_args(r), "--destination", str(destination),
                 "--authority-url-file", str(r.dir / "authority-url"), "--tenant-id", r.tenant, "--owner-id", r.owner]
    if FAILPOINT_BINARY:
        failpoint(r, r.source, "handoff_import_before_publish", *arguments)
        if destination.exists():
            raise Failure("an interrupted import published a destination")
        if ledger(r) != r.exported_record:
            raise Failure("an interrupted import changed the authority record")
        passed("H7a", "import killed before publication: no destination root, authority record unchanged")
    else:
        skipped("H7a", "BLINDPASS_P06_FAILPOINT_CONTROLLER is not set")
    wrong = list(arguments)
    wrong[wrong.index("--owner-id") + 1] = r.owner + "_other"
    refused = handoff(r, r.source, *wrong, check=False)
    if refused.returncode == 0 or destination.exists():
        raise Failure("an import for a different owner was accepted")
    receipt = json_line(handoff(r, r.source, *arguments))
    if receipt.get("handoff") != "imported" or receipt.get("activation_required") is not True \
            or receipt.get("backend") != "sqlite":
        raise Failure("import summary is malformed")
    if ledger(r) != r.exported_record:
        raise Failure("import changed the authority record")
    for path in (destination, destination / "keys", destination / "data"):
        if stat.S_IMODE(path.stat().st_mode) != 0o700:
            raise Failure("destination layout is not private")
    marker = destination / "data" / "handoff-marker.json"
    if not marker.is_file() or stat.S_IMODE(marker.stat().st_mode) != 0o600:
        raise Failure("destination marker is missing or not private")
    again = handoff(r, r.source, *arguments, check=False)
    if again.returncode == 0:
        raise Failure("a second import into an existing destination was accepted")
    r.destination = destination
    passed("H7", "wrong-owner import refused, then imported into a new private root; record still fenced and unchanged; a second import into it refused")


def activate_phase(r):
    """Stage 5: activate, serve on the same endpoint, node reconnects, stale source refuses."""
    destination = relay.Controller(r, "handoff", r.destination / "keys", r.destination / "data")
    r.controllers.append(destination)
    r.successor = destination
    r.authority.script("authority-activate.sql", **r.variables)
    activated = ledger(r)
    since = int(time.time() * 1000)
    started = time.monotonic()
    destination.start()
    r.wait_ready(destination)
    ready_after = time.monotonic() - started
    marker = r.destination / "data" / "handoff-marker.json"
    if marker.exists():
        raise Failure("the destination marker was not consumed after its store opened")
    wait_node_seen(r, since, STATUS_BOUND_SECONDS - ready_after, "destination")
    elapsed = time.monotonic() - started
    r.reconnect_seconds = elapsed
    r.api = relay.TlsApi(r.dir / "controller.crt")
    r.api.login("admin", r.password)
    rows = node_rows(r)
    if [row["id"] for row in rows] != [r.node_id] or rows[0]["key_version"] != r.node_key_version:
        raise Failure("the destination reports a different node set or key version")
    passed("H8", f"authority {r.exported_record} -> {activated}; destination ready {ready_after:.1f} s after start and the unchanged node, seen by the destination itself, passes `status --nodes --require-online` {elapsed:.1f} s after start (bound {STATUS_BOUND_SECONDS} s); operator login and node key version carried over; no re-enrollment")
    r.stale_keys, r.stale_data = r.source.keys, r.source.data
    stale = relay.Controller(r, "stale", r.stale_keys, r.stale_data)
    stale.admin_socket = r.dir / "stale.admin.sock"
    r.controllers.append(stale)
    stale.start()
    try:
        stale.process.wait(timeout=20)
    except Exception:
        raise Failure("the stale source kept running") from None
    if stale.process.returncode == 0:
        raise Failure("the stale source exited cleanly")
    if '"event":"startup_failed"' not in stale.log.read_text():
        raise Failure("the stale source did not report a startup failure")
    status, _ = r.api.request("GET", "/readyz", session=False)
    if status != 200 or ledger(r) != activated:
        raise Failure("a stale source start disturbed the active destination")
    migrate = r.source.command("migrate", check=False)
    if migrate.returncode == 0:
        raise Failure("the stale source migrated")
    passed("H9", "while the destination holds the active record the stale source refuses to serve (it cannot register as a second active holder) and to migrate; the destination stayed ready and the record unchanged")
    abort = handoff(r, r.source, "abort", "--handoff-id", r.handoff_id, "--output", str(r.transfer), check=False)
    if abort.returncode == 0:
        raise Failure("abort succeeded after the destination activated")
    if not (r.source.data / "handoff-marker.json").is_file() or len(list(r.transfer.glob("*"))) != 2:
        raise Failure("a refused abort removed the marker or the package")
    passed("H10", "abort after activation refused; marker and transfer package untouched (rollback is restore-only)")


def grant_phase(r):
    """Stage 6: a grant is issued, approved and consumed through the destination."""
    r.source = r.successor  # the grant helper reads the serving controller's database
    r.canaries_before = len(r.canaries)
    relay.grant_stage(r)
    if r.grant_id == r.first_grant:
        raise Failure("no new grant was issued after the handoff")
    passed("H11", "a grant issued after the handoff was approved, delivered to the node and consumed by a workload in the guest")


def restart_phase(r):
    """Stage 7: the destination restarts on its own (marker already consumed) and stays reachable."""
    r.successor.stop()
    # A start consumes a revision, so a restart needs a fresh activation (D12: fail closed).
    r.authority.script("authority-activate.sql", **r.variables)
    active = ledger(r)
    stale = relay.Controller(r, "stale2", r.stale_keys, r.stale_data)
    stale.admin_socket = r.dir / "stale2.admin.sock"
    r.controllers.append(stale)
    stale.start()
    try:
        stale.process.wait(timeout=20)
    except Exception:
        raise Failure("the stale source kept running with no destination holding the record") from None
    if '"reason":"handoff_retired"' not in stale.log.read_text() or stale.process.returncode == 0:
        raise Failure("with the destination stopped the stale source was not refused by its retirement marker")
    if ledger(r) != active:
        raise Failure("a stale source start changed the authority record")
    passed("H12a", "with the destination stopped and the record freshly activated, the stale source still refuses, now by its retirement marker (reason handoff_retired); the authority record is unchanged")
    r.authority.script("authority-activate.sql", **r.variables)
    since = int(time.time() * 1000)
    r.successor.start()
    r.wait_ready(r.successor)
    wait_node_seen(r, since, 90, "restarted destination")
    passed("H12", "the destination restarted without its marker after the stale attempt and the node was seen online by it again")
    relay.scan_logs(r)
    passed("H13", "no credential, enrollment token, authority password or PEM private key appeared in any controller or guest log")


STAGES = ["source", "export", "abort", "import", "activate", "grant", "restart"]
PHASES = {"source": source_phase, "export": export_phase, "abort": abort_phase, "import": import_phase,
          "activate": activate_phase, "grant": grant_phase, "restart": restart_phase}


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--until", choices=STAGES, default=STAGES[-1])
    args = parser.parse_args()
    blocked = relay.preflight()
    if blocked:
        return blocked
    if FAILPOINT_BINARY and not Path(FAILPOINT_BINARY).is_file():
        return relay.unsupported("BLINDPASS_P06_FAILPOINT_CONTROLLER does not name a file")
    r = relay.Rehearsal(args)
    try:
        for stage in STAGES:
            PHASES[stage](r)
            if stage == args.until:
                break
        return 0
    except (Failure, OSError, ssl.SSLError, http.client.HTTPException, KeyError, ValueError) as error:
        print(f"P06-HO FAIL {type(error).__name__}: {error}", file=sys.stderr)
        for controller in r.controllers:
            if controller.log.exists():
                print(f"--- {controller.name} log tail", file=sys.stderr)
                print(controller.log.read_text()[-1500:], file=sys.stderr)
        return 1
    finally:
        r.cleanup()


if __name__ == "__main__":
    sys.exit(main())
