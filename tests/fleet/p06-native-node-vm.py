#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""P06 real node against the PACKAGED NATIVE controller, with the native stale-source refusal.

Two disposable QEMU/KVM guests (pinned images, KVM, one host):

  C  the controller guest. The packaged native controller (the freshly built bookworm-baseline
     archive, installed by `deploy/native/controller-install.py` exactly as the native lifecycle
     gate installs it) with built-in TLS signed by a throwaway test CA, the documented remote
     direct-TLS step (`BLINDPASS_LISTEN` edited in the protected config) and the guest's own
     PostgreSQL as the recovery authority (NOT independent of the controller host).
  N  the node guest. A real `blindpass-broker` and `blindpass-node` enrolled to C over verified
     HTTPS; the test CA is in N's system trust store.

Network: both guests use QEMU user networking. C forwards host 127.0.0.1:8443 to its listener
(guest port 3200); N resolves `p03-controller` to the QEMU gateway 10.0.2.2, which reaches that host
port. The operator's API calls come from the host through the same forward.

Flow: enroll, one approved and consumed grant, the packaged backup unit, fence, the original state
is parked, restore through the packaged `blindpass-controller-restore.service` into a SECOND
private path on C (then installed into the service paths), the recovering controller starts, the
node runs `blindpass-node recovery-relay`, operator review, source-stop attestation, activation,
the node is online (`blindpass status --nodes --require-online`), an ordinary grant, and the
ORIGINAL controller (state and keys parked at fence time) is refused both as a second instance of
the packaged unit while the restored one serves and when swapped into the service paths.

Scenarios (`--scenario`):
  main    covered node: uncovered completion refused, relay, review, attestation, activation,
          reconnect, an ordinary grant, original controller refused.
  waiver  the node never reports: waived by name, stays revoked, the controller still serves.

Credentials stay in private files and are never printed. The CA key never reaches a guest.
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
import shlex
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "deployment"))
import canary_log_scan  # noqa: E402
_spec = importlib.util.spec_from_file_location("p06_relay_vm", HERE / "p06-relay-vm.py")
relay = importlib.util.module_from_spec(_spec)
sys.modules["p06_relay_vm"] = relay
_spec.loader.exec_module(relay)

Failure = relay.Failure
ROOT = relay.ROOT
ORIGIN = relay.ORIGIN  # https://p03-controller:8443
PORT = relay.PORT
C_USER = "p06runner"
C_SSH_PORT = int(os.environ.get("BLINDPASS_P06_NN_CONTROLLER_SSH_PORT", "22262"))
N_SSH_PORT = int(os.environ.get("BLINDPASS_P06_NN_NODE_SSH_PORT", "22231"))
BLINDPASS = "/opt/blindpass/controller/current/bin/blindpass"
GUEST_DIR = "/root/p06-native"
STATUS_BOUND_SECONDS = 120
OPERATOR = "p06nn-operator"
OS_IDS = {"ubuntu-24.04", "debian-12"}
DEBUG = os.environ.get("BLINDPASS_P06_DEBUG") == "1"


def passed(name, detail=""):
    print(f"P06-NN {name} PASS {detail}".rstrip(), flush=True)


def wait(check, timeout, what, interval=0.3):
    deadline = time.monotonic() + timeout
    while True:
        if check():
            return
        if time.monotonic() > deadline:
            raise Failure(what)
        time.sleep(interval)


def scp_options(ssh_options):
    return [("-P" if option == "-p" else option) for option in ssh_options]


class ControllerGuest:
    """Guest C: ssh as the cloud-init user (never the `blindpass` service account) and sudo."""

    def __init__(self, r, ssh_port):
        self.r = r
        self.ssh_port = ssh_port
        self.dir = r.dir / "vm-c"
        self.ssh_key = self.dir / "ssh-key"
        self.qemu_pid = None

    def ssh_options(self):
        return ["-i", str(self.ssh_key), "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR", "-o", "ConnectTimeout=3", "-p", str(self.ssh_port)]

    def ssh(self, *command, data=None, check=True, timeout=300):
        try:
            return relay.run(["ssh", *self.ssh_options(), f"{C_USER}@127.0.0.1", " ".join(map(shlex.quote, map(str, command)))],
                             data=data, check=check, timeout=timeout)
        except Failure:
            raise Failure("controller guest command failed: " + " ".join(map(str, command))[:100]) from None

    def sudo(self, *command, data=None, check=True, timeout=300):
        return self.ssh("sudo", *command, data=data, check=check, timeout=timeout)

    def copy(self, *files, destination="/tmp/"):
        relay.run(["scp", "-q", *scp_options(self.ssh_options()), *map(str, files), f"{C_USER}@127.0.0.1:{destination}"], timeout=300)

    def nn(self, command, *args, data=None, check=True, timeout=600):
        """One stage of native-node-guest.py; a failing stage reports its fixed `P06-... FAIL` label."""
        completed = self.sudo("python3", f"{GUEST_DIR}/native-node-guest.py", command, *args, data=data, check=False, timeout=timeout)
        if check and completed.returncode != 0:
            labels = [line for line in completed.stdout.decode(errors="replace").splitlines() if re.match(r"P06-\S+ (FAIL|failed_)", line)]
            raise Failure(f"controller guest stage {command} failed" + (": " + " | ".join(labels[-3:]) if labels else ""))
        return completed

    def result(self, command, *args, data=None, timeout=600):
        out = self.nn(command, *args, data=data, timeout=timeout).stdout.decode()
        found = [line for line in out.splitlines() if line.startswith("P06-NN-RESULT ")]
        if not found:
            raise Failure(f"controller guest stage {command} printed no result")
        return json.loads(found[-1].split(" ", 1)[1])

    def boot(self, image, sha256, os_profile, archive):
        self.dir.mkdir(mode=0o700)
        if hashlib.sha256(Path(image).read_bytes()).hexdigest() != sha256:
            raise Failure("pinned controller guest image hash does not match")
        relay.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(self.ssh_key)])
        env = dict(os.environ, BLINDPASS_FLEET_GUEST_IMAGE=str(image), BLINDPASS_FLEET_GUEST_IMAGE_SHA256=sha256,
                   BLINDPASS_FLEET_SSH_KEY=str(self.ssh_key), BLINDPASS_FLEET_GUEST_USER=C_USER)
        image_dir = self.dir / "image"
        relay.run([str(ROOT / "tests/fleet/provision-guest.sh"), "--output-dir", str(image_dir)], env=env)
        # Source state, WAL, private crypto copies, the archive and the restored state must all fit.
        relay.run(["qemu-img", "resize", str(image_dir / "guest-overlay.qcow2"), "8G"])
        pidfile = self.dir / "qemu.pid"
        relay.run(["qemu-system-x86_64", "-name", "blindpass-p06-nn-controller", "-enable-kvm", "-cpu", "host", "-m", "2048", "-smp", "2",
                   "-drive", f"file={image_dir}/guest-overlay.qcow2,if=virtio,format=qcow2",
                   "-drive", f"file={image_dir}/seed.iso,if=virtio,media=cdrom,readonly=on,format=raw",
                   "-netdev", f"user,id=net0,hostfwd=tcp:127.0.0.1:{self.ssh_port}-:22,hostfwd=tcp:127.0.0.1:{PORT}-:3200",
                   "-device", "virtio-net-pci,netdev=net0",
                   "-display", "none", "-monitor", "none", "-serial", f"file:{self.dir}/serial.log",
                   "-pidfile", str(pidfile), "-daemonize"])
        self.qemu_pid = int(pidfile.read_text())
        wait(lambda: relay.run(["ssh", *self.ssh_options(), f"{C_USER}@127.0.0.1", "true"], check=False).returncode == 0,
             240, "controller guest did not become reachable", interval=2)
        # SSH can restart once while cloud-init finishes; the status wait is read-only.
        deadline = time.monotonic() + 240
        while True:
            done = relay.run(["ssh", *self.ssh_options(), f"{C_USER}@127.0.0.1", "sudo cloud-init status --wait >/dev/null 2>&1"],
                             check=False, timeout=200)
            if done.returncode == 0:
                break
            if done.returncode not in (255, 124) or time.monotonic() > deadline:
                raise Failure("cloud-init did not finish in the controller guest")
            time.sleep(1)
        actual = relay.run(["ssh", *self.ssh_options(), f"{C_USER}@127.0.0.1", ". /etc/os-release; printf '%s-%s' \"$ID\" \"$VERSION_ID\""]).stdout.decode().strip()
        if actual != os_profile:
            raise Failure(f"pinned controller guest OS mismatch: {actual}")
        self.sudo("timeout", "400s", "sh", "-c",
                  "apt-get -o Acquire::Retries=1 -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20 update >/dev/null 2>&1 && "
                  "DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=1 -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20 "
                  "install -y python3 openssl ca-certificates zstd curl util-linux postgresql postgresql-client >/dev/null 2>&1", timeout=450)
        r = self.r
        self.copy(archive, ROOT / "tests/deployment/native-guest.py", ROOT / "tests/deployment/native-node-guest.py",
                  ROOT / "tests/deployment/canary_log_scan.py")
        staged = self.dir / "tls"
        staged.mkdir(mode=0o700)
        for name in ("leaf.pem", "leaf.key"):
            shutil.copyfile(r.dir / name, staged / name)
        shutil.copyfile(r.dir / "controller.crt", staged / "ca.pem")
        self.ssh("mkdir", "-m", "0700", "/tmp/p06-nn")
        self.copy(staged / "leaf.pem", staged / "leaf.key", staged / "ca.pem", destination="/tmp/p06-nn/")
        self.sudo("sh", "-c", f"install -d -m 0700 {GUEST_DIR} && tar --zstd -xf /tmp/blindpass-controller-*.tar.zst -C {GUEST_DIR} && "
                  f"mv {GUEST_DIR}/blindpass-controller-* {GUEST_DIR}/bundle && cp /tmp/native-guest.py /tmp/native-node-guest.py /tmp/canary_log_scan.py {GUEST_DIR}/ && "
                  f"chmod 0700 {GUEST_DIR}/native-guest.py {GUEST_DIR}/native-node-guest.py")

    def diagnostics(self):
        """Fixed controller refusal strings, unit results and capacity only (never logs wholesale)."""
        try:
            for unit in ("blindpass-controller-backup.service", "blindpass-controller-restore.service", "blindpass-controller.service"):
                shown = self.sudo("systemctl", "show", unit, "--property=Result", "--property=ExecMainStatus", check=False).stdout.decode()
                print(f"--- {unit}: " + shown.replace("\n", " "), file=sys.stderr)
                journal = self.sudo("journalctl", "-u", unit, "-o", "cat", "--no-pager", "-n", "200", check=False).stdout.decode(errors="replace")
                keep = [line[:240] for line in journal.splitlines() if re.match(r"(blindpass-controller|blindpass|Failed to set up|.*No space)", line)
                        or '"startup_failed"' in line]
                print("\n".join(keep[-6:]), file=sys.stderr)
            print(self.sudo("df", "-h", "/var/lib/blindpass", "/run", check=False).stdout.decode(), file=sys.stderr)
        except Failure:
            pass

    def stop(self):
        if self.qemu_pid:
            try:
                os.kill(self.qemu_pid, 15)
            except ProcessLookupError:
                pass


class AuthorityView:
    """The authority is the controller guest's own PostgreSQL; this is the read side the shared stages use."""

    def __init__(self, c):
        self.c = c

    def scalar(self, sql):
        out = self.c.nn("sql", data=sql.encode(), check=True).stdout.decode()
        return "\n".join(line for line in out.splitlines() if not line.startswith("P06-")).strip()


class Run:
    """The attribute surface p06-relay-vm.py's shared stages (`enroll_stage`, `grant_stage`) expect."""

    def __init__(self, args):
        self.args = args
        self.dir = Path(tempfile.mkdtemp(prefix="blindpass-p06-nn."))
        self.dir.chmod(0o700)
        self.c = ControllerGuest(self, C_SSH_PORT)
        self.vm = relay.GuestVM(self, "n", N_SSH_PORT)
        self.vms = [self.vm]
        self.authority = AuthorityView(self.c)
        self.api = None
        self.source = None
        self.canaries = []
        self.node_seen = {}

    # ---- shared-stage plumbing (guest N is "the guest") -------------------------------------------
    def ssh_options(self):
        return self.vm.ssh_options()

    def guest(self, *command, data=None, check=True, timeout=180):
        return self.vm.guest(*command, data=data, check=check, timeout=timeout)

    def guest_helper(self, *command, data=None, check=True, timeout=180):
        return self.vm.guest_helper(*command, data=data, check=check, timeout=timeout)

    def boot_guest(self):
        env = {key: os.environ.get(key) for key in ("BLINDPASS_FLEET_GUEST_IMAGE", "BLINDPASS_FLEET_GUEST_IMAGE_SHA256")}
        os.environ["BLINDPASS_FLEET_GUEST_IMAGE"] = os.environ.get("BLINDPASS_P06_NODE_IMAGE", str(relay.IMAGE_DEFAULT))
        os.environ["BLINDPASS_FLEET_GUEST_IMAGE_SHA256"] = os.environ.get("BLINDPASS_P06_NODE_IMAGE_SHA256", relay.IMAGE_SHA_DEFAULT)
        try:
            self.vm.boot()
        finally:
            for key, value in env.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    def db_rows(self, controller, sql, params=()):
        out = self.c.nn("rows", data=json.dumps({"sql": sql, "params": list(params)}).encode()).stdout.decode()
        return [tuple(row) for row in json.loads(out.strip().splitlines()[-1])]

    # ---- the controller guest ---------------------------------------------------------------------
    def script(self, name, **extra):
        return self.c.nn("script", name, *[f"{key}={value}" for key, value in extra.items()], check=False)

    def cli(self, *args, check=True):
        completed = self.c.nn("cli", *args, check=False)
        if check and completed.returncode != 0:
            raise Failure(f"recovery command failed: {args[0]}")
        return completed

    def cli_json(self, *args):
        return json.loads(self.cli(*args).stdout.decode())

    def ledger(self):
        return self.authority.scalar(f"SELECT phase||':'||epoch||':'||revision FROM blindpass_authority.recovery_authority WHERE tenant_id='{self.tenant}'")

    def responding(self):
        try:
            return relay.TlsApi(self.dir / "controller.crt").request("GET", "/readyz", session=False)[0] in (200, 503)
        except (OSError, ssl.SSLError, http.client.HTTPException):
            return False

    def ready_status(self):
        try:
            return relay.TlsApi(self.dir / "controller.crt").request("GET", "/readyz", session=False)[0]
        except (OSError, ssl.SSLError, http.client.HTTPException):
            return None

    def cleanup(self):
        for vm in self.vms:
            vm.stop()
        self.c.stop()
        if os.environ.get("BLINDPASS_P06_KEEP_ARTIFACTS") == "1":
            print(f"P06-NN kept artifacts in {self.dir}", file=sys.stderr)
        else:
            shutil.rmtree(self.dir, ignore_errors=True)


def refused_with(result, *gates, label):
    text = result.stderr.decode()
    if result.returncode == 0:
        raise Failure(f"{label}: the authority accepted what it must refuse")
    for gate in gates:
        if gate not in text:
            raise Failure(f"{label}: refusal does not name the open gate {gate}")
    return text


def guest_status(r, password):
    return r.guest("/tmp/p03/blindpass", "status", "--nodes", "--require-online", "--controller-url", ORIGIN,
                   "--username", "admin", "--password-stdin", data=(password + "\n").encode(), check=False, timeout=60)


def login_patiently(api, password, username="admin"):
    """Operator login with the controller's own per-account limit (10 a minute) respected: wait out a 429."""
    for attempt in range(8):
        try:
            return api.login(username, password)
        except Failure as error:
            if "status 429" not in str(error) or attempt == 7:
                raise
            time.sleep(10)


def wait_node_seen(r, since_ms, bound, what):
    """Poll the node list through one operator session (a login per poll would trip the login limit during
    the minute-long reconnects seen under load), then run the `status --nodes --require-online` gate once."""
    started = time.monotonic()
    poll = relay.TlsApi(r.dir / "controller.crt")
    login_patiently(poll, r.password)
    while True:
        status, listing = poll.request("GET", "/api/v3/nodes?limit=100")
        if status == 200:
            seen = [row.get("last_seen_at") for row in listing["items"] if row.get("status") != "revoked"]
            if seen and all(isinstance(value, int) and value >= since_ms for value in seen):
                break
        if time.monotonic() - started > bound:
            raise Failure(f"{what}: the node was not seen online by the activated controller within {bound} s")
        time.sleep(1)
    elapsed = time.monotonic() - started
    # The CLI logs in too: it can meet the account limit right after a burst of harness logins, so a refusal
    # is retried (a status gate that fails because the node is offline keeps failing and ends the stage).
    for attempt in range(8):
        gate = guest_status(r, r.password)
        if gate.returncode == 0:
            return elapsed
        if attempt < 7:
            time.sleep(10)
    detail = (gate.stdout + gate.stderr).decode(errors="replace").replace(r.password, "[password]")[-200:]
    raise Failure(f"{what}: the node was listed but `status --nodes --require-online` failed ({detail.strip()})")


def list_nodes(r):
    status, listing = r.api.request("GET", "/api/v3/nodes?limit=100")
    if status != 200:
        raise Failure("node listing refused")
    return listing["items"]


def make_certificates(r):
    """A throwaway test CA (its key never leaves the host) and a leaf for the public name and localhost."""
    ca_key = r.dir / "ca.key"
    relay.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-quiet",
               "-keyout", str(ca_key), "-out", str(r.dir / "controller.crt"), "-subj", "/CN=p06-nn-test-ca",
               "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign"])
    relay.run(["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-quiet", "-keyout", str(r.dir / "leaf.key"),
               "-out", str(r.dir / "leaf.csr"), "-subj", f"/CN={relay.HOSTNAME}"])
    (r.dir / "leaf.ext").write_text(f"subjectAltName=DNS:{relay.HOSTNAME},DNS:localhost\nbasicConstraints=critical,CA:FALSE\n"
                                    "keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n")
    relay.run(["openssl", "x509", "-req", "-in", str(r.dir / "leaf.csr"), "-CA", str(r.dir / "controller.crt"), "-CAkey", str(ca_key),
               "-CAcreateserial", "-days", "2", "-out", str(r.dir / "leaf.pem"), "-extfile", str(r.dir / "leaf.ext")])
    ca_key.unlink()
    for name in ("controller.crt", "leaf.key", "leaf.pem"):
        (r.dir / name).chmod(0o600)


# ---- stages ----------------------------------------------------------------------------------

def source_stage(r):
    make_certificates(r)
    r.api = relay.TlsApi(r.dir / "controller.crt")
    r.c.boot(r.args.controller_image, r.args.controller_image_sha256, r.args.os, r.args.archive)
    setup = r.c.result("setup", ORIGIN, timeout=900)
    r.issuer = setup["issuer"]
    r.tenant = "p06_native_tenant"
    wait(lambda: r.ready_status() == 200, 60, "the controller is not ready through the host forward over verified HTTPS")
    bootstrap = r.c.sudo("runuser", "-u", "blindpass", "--", BLINDPASS, "admin", "bootstrap", "--socket",
                         "/run/blindpass-controller/admin.sock").stdout
    temporary = json.loads(bootstrap)["temporary_password"]
    r.canaries = [temporary]
    r.password = "P06-DUMMY-" + secrets.token_hex(12)
    r.canaries.append(r.password)
    r.api.login("admin", temporary)
    status, _ = r.api.request("POST", "/api/v3/admin/session/change-password",
                              {"current_password": temporary, "new_password": r.password})
    if status != 204:
        raise Failure("operator password change refused")
    r.api = relay.TlsApi(r.dir / "controller.crt")
    if r.api.login("admin", r.password).get("must_change_password"):
        raise Failure("operator still must change password")
    passed("S1", f"packaged native controller ({r.args.os}, built-in TLS from a test CA, listening on all interfaces by the documented config step, authority in the guest's own PostgreSQL) serving over verified HTTPS through the host forward on 127.0.0.1:{PORT}; operator session established")


def enroll_stage(r):
    relay.enroll_stage(r)
    relay.run(["scp", "-q", *scp_options(r.ssh_options()), str(relay.BIN / "blindpass"), f"{relay.GUEST_USER}@127.0.0.1:/tmp/p03/blindpass"])
    r.guest("chmod", "0755", "/tmp/p03/blindpass")
    r.node_key_version = list_nodes(r)[0]["key_version"]
    started = time.monotonic()
    if guest_status(r, r.password).returncode != 0:
        raise Failure("`status --nodes --require-online` failed for the enrolled node")
    passed("S2c", f"`blindpass status --nodes --require-online` passes from the node guest over verified HTTPS ({time.monotonic() - started:.1f} s); node key version {r.node_key_version}")


def grant_stage(r):
    relay.grant_stage(r)


def backup_stage(r):
    info = r.c.result("backup", timeout=600)
    r.archive_name = info["archive"]
    if guest_status(r, r.password).returncode != 0:
        raise Failure("the node was not online after the backup unit")
    passed("B1", f"packaged backup unit sealed one split-custody archive ({info['bytes']} bytes, {info['seconds']} s) while the controller kept serving and the node stayed online; the host's own signing credential cannot open it")


def fence_stage(r):
    info = r.c.result("lose")
    r.epoch = info["epoch"]
    r.fenced_at = time.monotonic()
    if not info["fenced_ledger"].startswith("fenced:") or not info["ledger"].startswith("recovering:"):
        raise Failure(f"unexpected authority records: {info}")
    if r.ready_status() is not None:
        raise Failure("the fenced source still answers")
    passed("F1", f"source fenced in the authority ({info['fenced_ledger']}), stopped and its state and keys parked byte-intact; recovery reserved ({info['ledger']})")


def restore_stage(r):
    info = r.c.result("restore", timeout=900)
    if info["receipt_phase"] != "recovery_required" or not info["keys_identical"]:
        raise Failure(f"restore result is wrong: {info}")
    wait(lambda: r.ready_status() == 503, 40, "the recovering controller did not answer 503")
    for path in ("/api/v3/capabilities", "/api/auth/me", "/"):
        if r.api.request("GET", path, session=False)[0] != 503:
            raise Failure("an ordinary route reopened on the recovering controller")
    passed("S3", f"archive restored through the packaged restore unit into a SECOND private path on the controller guest under recovery epoch {r.epoch} (host custody refused, no-operator-input skipped, keys byte-identical), installed into the service paths and started: the recovering controller answers 503 on the same name, port and certificate")


def gates_stage(r):
    before = r.ledger()
    refused_with(r.script("authority-activate.sql"), label="ordinary activation of a recovering record")
    if r.ledger() != before:
        raise Failure("the ordinary activation script changed a recovering record")
    refused_with(r.script("authority-recover-activate.sql"), "source_stop_missing", "review_incomplete", "node_uncovered",
                 label="early recovery activation")
    attest = r.script("authority-recover-attest.sql", host="p06nn-source-host", by="p06nn-admin", note="premature")
    if attest.returncode == 0 or r.authority.scalar("SELECT count(*) FROM blindpass_authority.recovery_source_stop") != "0":
        raise Failure("an attestation was accepted while the recovering controller held the guard")
    if r.ledger() != before:
        raise Failure("refusals changed the recovering record")
    gaps = r.cli_json("status")
    for gate in ("source_stop_missing", "review_incomplete", "node_uncovered"):
        if gate not in gaps["gaps"]:
            raise Failure(f"the controller precheck does not list {gate}: {gaps['gaps']}")
    if gaps["activation_permitted"] is not False:
        raise Failure("the precheck permits activation")
    passed("G1", f"ordinary activation, early recovery activation (names source_stop_missing, review_incomplete, node_uncovered) and a premature attestation refused with the record unchanged ({before}); precheck lists {gaps['gaps']}")


def decide_all(r):
    listing = r.cli_json("review", "list")
    items = listing["items"]
    categories = sorted({item["category"] for item in items})
    if listing["total"] != len(items) or "operation" not in categories or "operator" not in categories:
        raise Failure(f"review list is incomplete: {categories}")
    if not any(i["category"] == "operation" and i["subject_id"] == r.operation_id for i in items):
        raise Failure("the consumed operation is not listed for review")
    for category in categories:
        decision = {"operator": "accept", "operation": "accept", "workload": "revoke"}.get(category, "reject")
        out = r.cli_json("review", "decide", "--category", category, "--decision", decision,
                         "--operator", OPERATOR, "--note", "reviewed by the native two-guest rehearsal")
        if out["decided"] < 1:
            raise Failure(f"no undecided {category} item was decided")
    return categories


def uncovered_stage(r):
    if r.cli("review", "complete", "--operator", OPERATOR, check=False).returncode == 0:
        raise Failure("complete accepted an undecided review")
    categories = decide_all(r)
    if r.cli("review", "complete", "--operator", OPERATOR, check=False).returncode == 0:
        raise Failure("completion accepted a node that is neither covered nor waived")
    if "node_uncovered" not in r.cli_json("status")["gaps"]:
        raise Failure("the uncovered node left the precheck")
    if r.ready_status() != 503:
        raise Failure("a refused completion changed the recovering controller")
    passed("V1", f"{len(categories)} review categories decided; completion refused while undecided and while the real node is neither covered nor waived (node_uncovered stays listed)")


def relay_stage(r):
    result = relay.relay_command(r)
    out = result.stdout.decode().strip()
    if result.returncode != 0 or out != "recovery_relay state=covered pages=1 activation_permitted=false":
        raise Failure(f"relay did not complete: exit={result.returncode} stdout={out!r} stderr={result.stderr.decode()[-200:]!r}")
    node = [n for n in r.cli_json("status")["nodes"] if n["node_id"] == r.node_id][0]
    if node["receipt"] != "covered" or node["waived"]:
        raise Failure("the authority does not show the node as covered")
    if "node_uncovered" in r.cli_json("status")["gaps"]:
        raise Failure("a covered node is still listed uncovered")
    for path in ("/api/v3/capabilities", "/api/auth/me", "/api/v3/nodes", "/"):
        if r.api.request("GET", path, session=False)[0] != 503:
            raise Failure("an ordinary route reopened after the relay")
    passed("R1", f"{out} from the real node over verified HTTPS to the recovering packaged controller; the authority and the precheck show the node covered; ordinary routes still 503")


def complete_stage(r):
    done = r.cli_json("review", "complete", "--operator", OPERATOR)
    if r.cli_json("status")["gaps"] != ["source_stop_missing"]:
        raise Failure(f"after completion only the attestation should remain, got {r.cli_json('status')['gaps']}")
    if r.cli("review", "decide", "--category", "operation", "--subject", r.operation_id, "--decision", "accept",
             "--operator", OPERATOR, check=False).returncode == 0:
        raise Failure("a decision was accepted after completion")
    passed("V2", f"review completed ({done['summary']}) once the node was covered; decisions closed; only source_stop_missing remains")


def waiver_stage(r):
    decide_all(r)
    if "node_uncovered" not in r.cli_json("status")["gaps"]:
        raise Failure("an unreported node is not listed as uncovered")
    if r.cli("review", "complete", "--operator", OPERATOR, check=False).returncode == 0:
        raise Failure("completion accepted an unreported, unwaived node")
    if r.cli("waive-node", "no-such-node", "--operator", OPERATOR, "--note", "x", check=False).returncode == 0:
        raise Failure("a waiver for an unknown node was accepted")
    r.cli_json("waive-node", r.node_id, "--operator", OPERATOR, "--note", "hardware lost in the fire")
    node = [n for n in r.cli_json("status")["nodes"] if n["node_id"] == r.node_id][0]
    if not (node["waived"] and node["revoked"]):
        raise Failure("the waiver did not revoke the node's broker trust in the authority")
    done = r.cli_json("review", "complete", "--operator", OPERATOR)
    if done["summary"]["nodes_revoked"] != 1:
        raise Failure("completion did not revoke the waived node locally")
    passed("W1", f"completion refused while the real node is neither covered nor waived; unknown waiver refused; waiver by name revoked its broker trust, completion revoked it locally ({done['summary']})")


def activate_stage(r):
    r.c.sudo("systemctl", "stop", "blindpass-controller.service")
    before = r.ledger()
    text = refused_with(r.script("authority-recover-activate.sql"), "source_stop_missing", label="activation without attestation")
    if "review_incomplete" in text or "node_uncovered" in text or "source_process_live" in text:
        raise Failure("the refusal names gates that are met")
    refused_with(r.script("authority-activate.sql"), label="ordinary activation after review")
    attest = r.script("authority-recover-attest.sql", host="p06nn-source-host", by="p06nn-admin",
                      note="source service stopped and fenced from the authority")
    if attest.returncode != 0:
        raise Failure("attestation refused although the service is stopped")
    row = r.authority.scalar("SELECT host_id||':'||attested_by FROM blindpass_authority.recovery_source_stop ORDER BY epoch DESC LIMIT 1")
    if row != "p06nn-source-host:p06nn-admin":
        raise Failure("the attestation row does not record who and which host")
    if r.ledger() != before:
        raise Failure("refusals or attestation changed the recovering record")
    activated = r.script("authority-recover-activate.sql")
    if activated.returncode != 0 or "activated recovery epoch" not in activated.stdout.decode():
        raise Failure("activation refused with every gate met")
    now = r.ledger()
    if not now.startswith("active:") or now.split(":")[1] != before.split(":")[1]:
        raise Failure(f"unexpected record after activation: {now}")
    refused_with(r.script("authority-recover-activate.sql"), label="second recovery activation")
    passed("A1", f"only the missing attestation blocked activation; attested ({row}) and activated: {before} -> {now}; ordinary script and a second activation refused")


def serve_stage(r):
    served = r.c.result("serve")
    bound = STATUS_BOUND_SECONDS - served["ready_seconds"]
    if r.ready_status() != 200:
        raise Failure("the activated controller is not ready over verified HTTPS")
    elapsed = served["ready_seconds"] + wait_node_seen(r, served["started_ms"], bound, "restored controller")
    r.reconnect_seconds = elapsed
    r.api = relay.TlsApi(r.dir / "controller.crt")
    login_patiently(r.api, r.password)
    rows = list_nodes(r)
    if [row["id"] for row in rows] != [r.node_id] or rows[0]["status"] != "online":
        raise Failure("the node is not online at the activated controller")
    if rows[0]["key_version"] != r.node_key_version:
        raise Failure("the node's key version changed across recovery")
    status, operation = r.api.request("GET", f"/api/v3/operations/{r.operation_id}")
    if status != 200 or operation.get("status") not in ("uncertain", "revoked"):
        raise Failure("a recovered operation is not left uncertain or revoked")
    passed("S4", f"activated controller ready {served['ready_seconds']:.1f} s after start; the unchanged node (key version {r.node_key_version}) passes `status --nodes --require-online` {elapsed:.1f} s after start ({time.monotonic() - r.fenced_at:.0f} s after the source was fenced); operator login works; recovered operation stays {operation['status']}")


def grant2_stage(r):
    first = r.grant_id
    relay.grant_stage(r)
    if r.grant_id == first:
        raise Failure("no new grant was issued after the activation")
    passed("S5", "an ordinary grant was approved by a second operator, delivered to the node and consumed by a workload in the node guest through the activated packaged controller")


def stale_source_stage(r):
    activated = r.ledger()
    refusal = refused_with(r.script("authority-activate.sql"), label="ordinary activation while the restored controller serves")
    gate = next((line.split("ERROR:", 1)[1].strip()[:160] for line in refusal.splitlines() if "ERROR:" in line), "no ERROR line")
    transient = r.c.result("stale-transient")
    if not transient["reasons"] or transient["unit_result"] == "success":
        raise Failure(f"the original state as a second instance of the packaged unit was not refused with a reason: {transient}")
    if r.ledger() != activated or r.ready_status() != 200:
        raise Failure("the original state disturbed the serving controller or its record")
    if guest_status(r, r.password).returncode != 0:
        raise Failure("the node left online after the second instance was refused")
    passed("S6a", f"while the restored controller serves: the ordinary activation script was refused ({gate}) and the original state, started as a second instance of the packaged unit, did not run (unit result {transient['unit_result']}, exit {transient['exit_status']}, startup_failed reason {transient['reasons'][-1]}); the serving controller stayed ready, the record {activated} did not change and the node stayed online")
    swap = r.c.result("stale-swap")
    if not swap["reasons"] or not swap["source_db_unchanged"]:
        raise Failure(f"the original state in the service paths was not refused, or its database changed: {swap}")
    reconnect = r.c.result("activate-serve")
    since = reconnect["started_ms"]
    elapsed = reconnect["ready_seconds"] + wait_node_seen(r, since, STATUS_BOUND_SECONDS - reconnect["ready_seconds"], "restored controller after the stale-source drill")
    r.api = relay.TlsApi(r.dir / "controller.crt")
    login_patiently(r.api, r.password)
    if r.ledger().split(":")[0] != "active":
        raise Failure("the record is not active after the restored controller was re-activated")
    passed("S6b", f"the original state swapped into the service paths was refused after an ordinary activation (startup_failed reason {swap['reasons'][-1]}); its SQLite database is byte-unchanged; the restored state, re-activated once (P06-D12), serves again and the node is online {elapsed:.1f} s after start")


def browser_stage(r):
    """A stock Chromium signs in to the embedded console of the packaged controller over verified HTTPS."""
    certificate = (r.dir / "leaf.pem").read_bytes()  # the served leaf; controller.crt is the test CA
    public = subprocess.run(["openssl", "x509", "-pubkey", "-noout"], input=certificate, capture_output=True, check=True).stdout
    der = subprocess.run(["openssl", "pkey", "-pubin", "-outform", "der"], input=public, capture_output=True, check=True).stdout
    spki = base64.b64encode(hashlib.sha256(der).digest()).decode()
    environment = dict(os.environ, P06_CONSOLE_URL=relay.ORIGIN, P06_CONSOLE_RESOLVE=f"127.0.0.1:{PORT}", P06_CONSOLE_SPKI=spki,
                       P06_CONSOLE_USER="admin", P06_CONSOLE_PASSWORD=r.password, P06_CONSOLE_NODE_ID=r.node_id)
    if "BLINDPASS_PLAYWRIGHT_EXECUTABLE_PATH" not in environment and Path("/usr/bin/chromium").is_file():
        environment["BLINDPASS_PLAYWRIGHT_EXECUTABLE_PATH"] = "/usr/bin/chromium"
    completed = subprocess.run(["node", str(Path(__file__).resolve().parent / "p06-console-browser.mjs")], env=environment,
                               capture_output=True, timeout=240, cwd=Path(__file__).resolve().parents[2])
    out = completed.stdout.decode(errors="replace")
    line = next((x for x in out.splitlines() if x.startswith("P06-BROWSER")), "")
    if completed.returncode != 0 or "PASS" not in line:
        detail = (line or (out + completed.stderr.decode(errors="replace"))[-400:]).replace(r.password, "[password]")
        raise Failure(f"stock browser check failed (exit {completed.returncode}): {detail}")
    chrome = subprocess.run([environment.get("BLINDPASS_PLAYWRIGHT_EXECUTABLE_PATH", "chromium"), "--version"], capture_output=True, timeout=30).stdout.decode().strip()
    passed("BR1", f"{chrome or 'Chromium'} signed in to the embedded console of the packaged controller over verified HTTPS (public key pinned, no verification disabled): nodes page lists the node online, approvals page loads, no CSP violation and no request left the controller origin, UI sign-out returned to /login and the old cookie was rejected ({line.split('PASS ', 1)[1]})")


def new_session(r):
    api = relay.TlsApi(r.dir / "controller.crt")
    login_patiently(api, r.password)
    return api


def session_alive(api):
    return api.request("GET", "/api/v3/nodes?limit=1")[0] == 200


def ui_logout_stage(r):
    """Operator logout from the browser surface while the controller serves."""
    a, b = new_session(r), new_session(r)
    if not (session_alive(a) and session_alive(b)):
        raise Failure("fresh operator sessions are not usable")
    csrf = a.csrf
    a.csrf = None
    missing = a.request("POST", "/api/v3/admin/session/logout")[0]
    a.csrf = csrf
    foreign = a.request("POST", "/api/v3/admin/session/logout", headers={"Origin": "https://evil.example"})[0]
    if missing != 403 or foreign != 403 or not session_alive(a):
        raise Failure(f"a logout without CSRF or from a foreign origin was not refused with the session intact ({missing}, {foreign})")
    if a.request("POST", "/api/v3/admin/session/logout")[0] != 204:
        raise Failure("logout was refused")
    replay = relay.TlsApi(r.dir / "controller.crt")
    replay.cookies = {k: v for k, v in a.cookies.items() if v}
    replay.csrf = csrf
    if session_alive(a) or session_alive(replay):
        raise Failure("the logged-out session, or a replay of its cookie, is still accepted")
    if a.request("POST", "/api/v3/admin/session/logout")[0] not in (401, 403):
        raise Failure("a second logout of a dead session was not refused")
    if not session_alive(b) or r.ready_status() != 200:
        raise Failure("logging one session out disturbed another session or the controller")
    guest = guest_status(r, r.password)
    if guest.returncode != 0:
        raise Failure("the node left online after an operator logout")
    passed("U1", "logout without CSRF or from a foreign origin refused with the session intact; a real logout returned 204, the session and a replay of its cookie were rejected and a second logout refused; another session of the same operator and the node stayed online")


def disk_full_stage(r):
    """The controller's data filesystem fills while it serves, then frees; no restart is performed."""
    volume = r.c.result("loop-data")
    restarted = r.c.result("activate-serve")
    wait_node_seen(r, restarted["started_ms"], STATUS_BOUND_SECONDS, "controller on its own data volume")
    before = r.c.result("fault-state")
    ledger_before = r.ledger()
    victim, other = new_session(r), new_session(r)
    seen_since = int(time.time() * 1000)
    filled = r.c.result("fill-disk")
    started = time.monotonic()
    time.sleep(8)
    ready = r.api.request("GET", "/readyz", session=False)
    ready_reason = (ready[1] or {}).get("reason") or (ready[1] or {}).get("status")
    reads = other.request("GET", "/api/v3/nodes?limit=1")[0]
    login = relay.TlsApi(r.dir / "controller.crt")
    try:
        login_status = login.request("POST", "/api/v3/admin/session/login", {"username": "admin", "password": r.password},
                                     {"Cookie": "bp_csrf=" + "a" * 43, "X-CSRF-Token": "a" * 43}, session=False)[0]
    except (OSError, ssl.SSLError, http.client.HTTPException):
        login_status = None
    logout_status = victim.request("POST", "/api/v3/admin/session/logout")[0]
    if login_status == 200 and not session_alive(login):
        raise Failure("a login answered 200 under a full disk but its session is unusable")
    if logout_status == 204 and session_alive(victim):
        raise Failure("logout answered 204 under a full disk but the session still works")
    if logout_status not in (204, 503):
        raise Failure(f"logout under a full disk answered {logout_status}, neither success nor unavailable")
    passed("D1", f"the data directory on its own {volume['size_bytes'] // 2**20} MiB {volume['filesystem']} volume (authority PostgreSQL stays on the root filesystem) is full (service user has {filled['available_bytes']} bytes): readiness {ready[0]} reason {ready_reason}, authenticated read {reads}, new login {login_status}, logout {logout_status}; the serving process was not restarted")
    freed = r.c.result("free-disk")
    # P06-D12: an unanswerable epoch check fences the owner, so space alone does not bring it back; one
    # ordinary activation is the documented step. Either path is recorded, and neither may skip the check.
    time.sleep(20)
    self_recovered = r.ready_status() == 200
    held = None
    if not self_recovered:
        held = r.api.request("GET", "/readyz", session=False)
        reason = (held[1] or {}).get("reason") or (held[1] or {}).get("status")
        if held[0] != 503 or reason != "recovery_required":
            raise Failure(f"after space was freed the controller was neither ready nor fenced with recovery_required ({held[0]} {reason})")
        if r.ledger() != ledger_before:
            raise Failure("the authority record changed while the controller was fenced by the disk-full fault")
        reactivated = r.c.result("activate-serve")
        served_ms = reactivated["started_ms"]
        ready_seconds = reactivated["ready_seconds"]
    else:
        served_ms, ready_seconds = seen_since, 0.0
    recovered = time.monotonic() - started
    after = r.c.result("fault-state")
    if after["integrity"] != "ok" or after["active"] != "active":
        raise Failure(f"database not healthy after the fault: {after}")
    if logout_status == 503:
        if victim.request("POST", "/api/v3/admin/session/logout")[0] != 204 or session_alive(victim):
            raise Failure("logout could not be completed after space was freed")
    if not session_alive(other):
        raise Failure("an unrelated session was lost across the disk-full fault")
    r.api = new_session(r)
    if not session_alive(r.api):
        raise Failure("a new login does not work after space was freed")
    elapsed = ready_seconds + wait_node_seen(r, served_ms, STATUS_BOUND_SECONDS - ready_seconds, "controller after the disk-full fault")
    first = r.grant_id
    relay.grant_stage(r)
    if r.grant_id == first:
        raise Failure("no ordinary grant could be issued after the disk-full fault")
    path = ("the controller recovered by itself without an activation" if self_recovered else
            f"the controller stayed fenced (503 recovery_required, no restart, record unchanged) until one ordinary activation and start, ready {ready_seconds:.1f} s after it")
    passed("D2", f"space freed ({freed['available_bytes']} bytes free): {path}; SQLite integrity_check ok; an unrelated session survived, logout {'was retried to 204' if logout_status == 503 else 'had already completed'}, a new login works, the node was seen again {elapsed:.1f} s after the restart and an ordinary grant was approved, delivered and consumed ({recovered:.0f} s from the fault)")


def ai_task_stage(r):
    """The P05 managed Grafana workflow, with a stock Claude Code or Codex client when BLINDPASS_P05_AI_CLIENT is
    set, run in the node guest against the packaged controller in the other guest."""
    client = os.environ.get("BLINDPASS_P05_AI_CLIENT", "")
    if client not in ("", "claude", "codex"):
        raise Failure("BLINDPASS_P05_AI_CLIENT must be claude or codex")
    grafana = os.environ.get("P05_GRAFANA_HOME", "")
    if not (Path(grafana) / "bin/grafana").is_file():
        raise Failure("P05_GRAFANA_HOME does not name a verified Grafana distribution")
    root = Path(__file__).resolve().parents[2]
    node_bin = Path(subprocess.run(["node", "-p", "process.execPath"], capture_output=True, check=True).stdout.decode().strip())
    node_root = node_bin.parent.parent
    cache = subprocess.run(["node", "--input-type=module", "-e", 'import {chromium} from "playwright"; console.log(chromium.executablePath())'],
                           capture_output=True, check=True, cwd=root).stdout.decode().strip()
    browser_cache = Path(cache).parents[2]
    runtime = r.dir / "private-helper-runtime.tar.gz"
    relay.run(["tar", "-czf", str(runtime), "--transform=s,^helpers/login/,,", "--transform=s,^packages/openclaw-plugin/dist/,mcp/,",
               "--transform=s,^bin/,runtime/bin/,", "--transform=s,^\\./LICENSE$,runtime/LICENSE,",
               "--transform=s,^chromium_headless_shell-1208,browsers/chromium_headless_shell-1208,",
               "-C", str(root), "helpers/login/src", "helpers/login/LICENSE", "packages/openclaw-plugin/dist/mcp-server.mjs",
               "packages/openclaw-plugin/dist/LICENSE", "packages/openclaw-plugin/dist/THIRD_PARTY_NOTICES.md",
               "packages/openclaw-plugin/dist/licenses", "node_modules/playwright", "node_modules/playwright-core", "node_modules/@playwright/mcp",
               "-C", str(node_root), "bin/node", "./LICENSE", "-C", str(browser_cache), "chromium_headless_shell-1208"], timeout=300)
    grafana_tar = r.dir / "grafana-runtime.tar"
    relay.run(["tar", "-cf", str(grafana_tar), "-C", grafana, "bin", "conf", "public", "LICENSE", "NOTICE.md"], timeout=300)
    r.boot_guest()
    configuration = {"origin": ORIGIN, "username": "admin", "password": r.password,
                     "ca_path": "/usr/local/share/ca-certificates/blindpass-p03-controller.crt"}
    r.guest("sudo", "sh", "-c", "umask 077 && cat > /root/p06-remote-controller.json", data=json.dumps(configuration).encode())
    options = ["-P" if o == "-p" else o for o in r.vm.ssh_options()]
    deploy = root / "deploy"
    files = [runtime, grafana_tar, relay.BIN / "blindpass-broker", relay.BIN / "blindpass-node", relay.BIN / "blindpass-provision",
             root / "tests/fleet/p06-ai-guest.sh", deploy / "examples/browser-runtime.conf", deploy / "native/blindpass-broker.service",
             *sorted((deploy / "native").glob("blindpass-login*")), *sorted((deploy / "native").glob("blindpass-browser*")),
             *sorted((deploy / "native").glob("blindpass-session-revoker*")), *sorted((deploy / "native").glob("blindpass-runtime-manager*"))]
    relay.run(["scp", "-q", *options, *map(str, files), f"{relay.GUEST_USER}@127.0.0.1:/tmp/"], timeout=600)
    relay.run(["scp", "-q", "-r", *options, str(root / "tests/browser-handoff"), f"{relay.GUEST_USER}@127.0.0.1:/tmp/"], timeout=600)
    command = " ".join(shlex.quote(part) for part in ["sudo", "env", f"BLINDPASS_P05_AI_CLIENT={client}" if client else "BLINDPASS_P05_NO_AI=1",
                                                       "bash", "/tmp/p06-ai-guest.sh"])
    log = r.dir / "ai-guest.log"
    with log.open("wb") as handle:
        guest = subprocess.Popen(["ssh", *r.vm.ssh_options(), f"{relay.GUEST_USER}@127.0.0.1", command], stdout=handle, stderr=subprocess.STDOUT)
        client_code = 0
        client_output = ""
        if client:
            environment = dict(os.environ, BLINDPASS_FLEET_SSH_KEY=str(r.vm.ssh_key), BLINDPASS_P05_HELPER_SSH_PORT=str(N_SSH_PORT),
                               BLINDPASS_P05_GUEST_PID=str(guest.pid))
            completed = subprocess.run(["python3", str(root / "tests/browser-handoff/ai-client-task.py"), client], env=environment,
                                       capture_output=True, timeout=900, cwd=root)
            client_code = completed.returncode
            client_output = completed.stdout.decode(errors="replace")
        try:
            guest_code = guest.wait(timeout=900)
        except subprocess.TimeoutExpired:
            guest.kill()
            guest_code = -1
    text = log.read_bytes().decode(errors="replace")
    for secret in (r.password, *r.canaries):
        if secret and secret in text + client_output:
            raise Failure("a credential appeared in the AI-task output")
    markers = [line for line in text.splitlines() if line.startswith(("P05-", "P06-AI", "P06-REMOTE"))]
    if client_code != 0 or guest_code != 0:
        tail = [l[:220] for l in text.splitlines() if l.strip()][-70:]
        raise Failure(f"AI task failed (client exit {client_code}, guest exit {guest_code}): " + " | ".join(l[:700] for l in (markers + client_output.splitlines())[-12:])
                      + "\n--- guest log tail\n" + "\n".join(tail))
    expected = f"P05-AI-TASK client={client} " if client else "P05-MANAGED-FLEET-VM"
    if not any(line.startswith(expected) for line in markers):
        raise Failure("the managed application workflow printed no result")
    passed("AI1", f"{client or 'no AI client'}: " + " | ".join(l[:330] for l in markers if l.startswith(("P05-FLEET-BROWSER-VM", "P05-MANAGED-FLEET-VM", "P05-AI-TASK", "P06-AI"))) + (" | " + " ".join(client_output.split())[:300] if client_output else ""))


def backup_full_stage(r):
    """The packaged backup unit runs while the controller's data volume (which holds the backup directory) is full."""
    before = r.c.result("backup-state")
    ledger_before = r.ledger()
    since = int(time.time() * 1000)
    r.c.result("fill-disk")
    time.sleep(5)
    during = r.ready_status()
    attempt = r.c.result("backup-attempt")
    full = r.c.result("backup-state")
    if attempt["start_exit"] == 0 or attempt["unit_result"] == "success":
        raise Failure("the backup unit reported success on a full volume")
    if attempt["secret_in_journal"]:
        raise Failure("a credential appeared in the backup unit journal")
    if full["archives"] != before["archives"]:
        raise Failure(f"the failed backup changed the published archives: {before['archives']} -> {full['archives']}")
    if full["residue"]:
        raise Failure(f"the failed backup left temporary residue: {full['residue']}")
    r.c.result("free-disk")
    restarted = None
    if r.ready_status() != 200:
        if r.ledger() != ledger_before:
            raise Failure("the authority record changed while the backup failed")
        restarted = r.c.result("activate-serve")
        wait_node_seen(r, restarted["started_ms"], STATUS_BOUND_SECONDS, "controller after the backup-volume fault")
    r.api = new_session(r)
    if not session_alive(r.api):
        raise Failure("operator sessions do not work after the backup-volume fault")
    again = r.c.result("backup-attempt")
    after = r.c.result("backup-state")
    if again["start_exit"] != 0 or again["unit_result"] != "success" or again["verified"] is not True:
        raise Failure(f"the backup unit did not recover once space was freed: {again}")
    if len(after["archives"]) != len(before["archives"]) + 1 or after["residue"]:
        raise Failure("the recovered backup did not publish exactly one new verified archive")
    passed("BF1", f"backup unit on a full data volume: failed closed (exit {attempt['start_exit']}, result {attempt['unit_result']}, messages {attempt['messages']}), no archive published or changed, no temporary residue, nothing sensitive in its journal; while full the controller answered readiness {during}"
                  + (", then needed one fresh activation (P06-D12) after space was freed" if restarted else ", and stayed ready after space was freed")
                  + f"; the next backup succeeded in {again['seconds']} s and verified, publishing exactly one new archive")


def journal_full_stage(r):
    """The persistent journal's own volume fills while the controller serves; logging is lost, serving is not."""
    before = r.c.result("fault-state")
    volume = r.c.result("loop-journal")
    since = int(time.time() * 1000)
    filled = r.c.result("fill-journal")
    ready = r.ready_status()
    if ready != 200:
        unit = r.c.result("fault-state")
        raise Failure(f"readiness answered {ready} with a full journal volume (service {unit['active']}, restarts {unit['restarts']}, same invocation as before the fault: {unit['invocation'] == before['invocation']})")
    r.api = new_session(r)
    if not session_alive(r.api):
        raise Failure("an operator login does not work with a full journal volume")
    first = r.grant_id
    relay.grant_stage(r)
    if r.grant_id == first:
        raise Failure("no ordinary grant could be issued with a full journal volume")
    wait_node_seen(r, since, STATUS_BOUND_SECONDS, "controller with a full journal volume")
    freed = r.c.result("free-journal")
    if not freed["logging_resumed"]:
        raise Failure("journald did not resume logging after space was freed")
    passed("JF1", f"journal volume ({volume['size_bytes'] // 2**20} MiB, own ext4) filled to {filled['free_bytes']} bytes free: readiness {ready}, an operator login and an ordinary grant approved, delivered and consumed, the node stayed online; after space was freed journald logged again (messages from before the fill {'kept' if freed['kept_before_fill'] else 'not kept'})")


def journald_loss_stage(r):
    """journald is stopped outright (its stdout streams to the controller are dropped) while the controller serves."""
    before = r.c.result("fault-state")
    r.c.result("journald-stop")
    time.sleep(10)
    ready = r.ready_status()
    during = r.c.result("fault-state")
    local_during = r.c.result("local-ready")
    r.c.result("journald-start")
    time.sleep(3)
    after = r.ready_status()
    local_after = r.c.result("local-ready")
    same = all(before[key] == during[key] for key in ("main_pid", "restarts", "invocation"))
    passed("JL1", f"journald stopped for 10 s while serving: readiness {ready} during and {after} after it restarted; controller {during['active']}, same process: {same}; inside the guest during: {local_during}; after: {local_after}")


def revoked_serve_stage(r):
    served = r.c.result("serve")
    r.api = relay.TlsApi(r.dir / "controller.crt")
    wait(lambda: r.ready_status() == 200, 40, "the activated controller is not ready over verified HTTPS")
    login_patiently(r.api, r.password)
    rows = list_nodes(r)
    if [row["id"] for row in rows] != [r.node_id] or rows[0]["status"] != "revoked":
        raise Failure("the waived node is not revoked at the activated controller")
    time.sleep(15)  # the node's own reconnect attempts must not bring it back
    rows = list_nodes(r)
    if rows[0]["status"] != "revoked" or guest_status(r, r.password).returncode == 0:
        raise Failure("the waived node came back or the online gate passed")
    if r.authority.scalar(f"SELECT state FROM blindpass_authority.broker_trust WHERE node_id='{r.node_id}'") != "revoked":
        raise Failure("the waived node's broker trust is not revoked")
    passed("W2", f"controller activated and ready {served['ready_seconds']:.1f} s after start without the waived node; the node stays revoked and the `status --nodes --require-online` gate fails for it; its broker trust stays revoked in the authority")


def logs_stage(r):
    scan = r.c.result("scan", data=json.dumps(r.canaries).encode())
    if scan["hits"] or scan["pem_private_keys"]:
        raise Failure("a credential or PEM private key appeared in a controller log")
    journal = r.guest("sudo", "journalctl", "-u", "blindpass-broker.service", "-u", "blindpass-node.service",
                      "--no-pager", "-o", "cat", timeout=60).stdout.decode()
    # Fail closed (P07-I04, finding F2): an empty capture fails and the scan is first shown to see a planted token.
    try:
        canary_log_scan.assert_log_clean("P06-L1 node guest broker and node journal", journal, r.canaries,
                                         markers=["PRIVATE KEY-----"], min_bytes=32)
    except canary_log_scan.LogScanError as error:
        raise Failure(str(error)) from None
    if canary_log_scan.run_dir():   # P07_RUN: keep the controller guest's journal for the offline scanner
        canary_log_scan.export("P06-L1 controller guest journal", r.c.nn("journal").stdout)
    passed("L1", f"no operator or approver password, bootstrap password, enrollment token, authority password or PEM private key in the packaged controller, backup, restore or stale-instance journals ({scan['journal_bytes']} bytes scanned for {scan['canaries']} canaries) or in the node guest's broker/node journals")


SCENARIOS = {
    "main": ["source", "enroll", "grant", "backup", "fence", "restore", "gates", "uncovered", "relay", "complete",
             "activate", "serve", "grant2", "stale_source", "logs"],
    "serving-faults": ["source", "enroll", "grant", "backup", "fence", "restore", "gates", "uncovered", "relay", "complete",
                       "activate", "serve", "grant2", "browser", "ui_logout", "disk_full", "backup_full", "logs", "journal_full", "journald_loss"],
    "ai-task": ["source", "ai_task"],
    "waiver": ["source", "enroll", "grant", "backup", "fence", "restore", "waiver", "activate", "revoked_serve", "logs"],
}


def preflight(args):
    if os.geteuid() == 0:
        return relay.unsupported("run as the runner owner, not through sudo")
    for tool in ("qemu-system-x86_64", "qemu-img", "ssh", "scp", "ssh-keygen", "openssl", "cloud-localds"):
        if shutil.which(tool) is None:
            return relay.unsupported(f"{tool} is unavailable in PATH")
    if not (os.access("/dev/kvm", os.R_OK) and os.access("/dev/kvm", os.W_OK)):
        return relay.unsupported("/dev/kvm is unavailable or inaccessible")
    for binary in ("blindpass", "blindpass-broker", "blindpass-node", "blindpass-workload-client"):
        if not (relay.BIN / binary).is_file():
            return relay.unsupported(f"{binary} is missing from {relay.BIN}")
    if not Path(args.archive).is_file():
        return relay.unsupported("the native controller archive is missing")
    for image in (args.controller_image, os.environ.get("BLINDPASS_P06_NODE_IMAGE", str(relay.IMAGE_DEFAULT))):
        if not Path(image).is_file():
            return relay.unsupported(f"pinned guest image {image} is missing")
    for port in (PORT, C_SSH_PORT, N_SSH_PORT):
        with socket.socket() as probe:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                probe.bind(("127.0.0.1", port))
            except OSError:
                return relay.unsupported(f"127.0.0.1:{port} is already in use")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--archive", required=True, type=Path, help="native controller archive from scripts/release/build-tarballs.sh")
    parser.add_argument("--bin-dir", type=Path, help="directory with blindpass, blindpass-broker, blindpass-node, blindpass-workload-client "
                        "(the bookworm export the archive was built from); default target/release")
    parser.add_argument("--os", choices=sorted(OS_IDS), default="ubuntu-24.04", help="OS of the controller guest")
    parser.add_argument("--controller-image", default=os.environ.get("BLINDPASS_FLEET_GUEST_IMAGE", str(relay.IMAGE_DEFAULT)))
    parser.add_argument("--controller-image-sha256", default=os.environ.get("BLINDPASS_FLEET_GUEST_IMAGE_SHA256", relay.IMAGE_SHA_DEFAULT))
    parser.add_argument("--scenario", choices=sorted(SCENARIOS), default="main")
    parser.add_argument("--until")
    args = parser.parse_args()
    stages = SCENARIOS[args.scenario]
    if args.until and args.until not in stages:
        parser.error("unknown stage for this scenario")
    if args.bin_dir:
        relay.BIN = args.bin_dir.resolve()
    blocked = preflight(args)
    if blocked:
        return blocked
    r = Run(args)
    try:
        for stage in stages:
            globals()[f"{stage}_stage"](r)
            if stage == args.until:
                break
        print(f"P06-NN {args.scenario} {args.os} PASS", flush=True)
        return 0
    except (Failure, OSError, ssl.SSLError, http.client.HTTPException, KeyError, ValueError, IndexError, subprocess.TimeoutExpired) as error:
        print(f"P06-NN FAIL {type(error).__name__}: {error}", file=sys.stderr)
        if r.c.qemu_pid:
            r.c.diagnostics()
        try:
            # Broker and node log lines carry fixed event names only; the L1 scan covers the same journals.
            tail = r.guest("sudo", "journalctl", "-u", "blindpass-node.service", "-u", "blindpass-broker.service", "-n", "30",
                           "--no-pager", "-o", "cat", check=False, timeout=60).stdout.decode(errors="replace")
            print("--- node guest broker/node journal (last 30 lines)\n" + tail[-3000:], file=sys.stderr)
        except Exception:
            pass
        return 1
    finally:
        r.cleanup()


if __name__ == "__main__":
    sys.exit(main())
