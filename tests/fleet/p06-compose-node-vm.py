#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""P06 real broker and node against the shipped Compose profiles, through recovery.

The controller under test is the shipped Compose stack (`deploy/controller/compose.<profile>.yml`
with its initialize, backup and restore overlays, the pinned controller image, the authority in
its own TLS container) behind an nginx edge built from `deploy/proxy/nginx.conf.example`. A real
`blindpass-broker` and `blindpass-node` in a disposable QEMU guest enroll over verified HTTPS
through that edge, and one grant is approved and consumed. The shipped backup job seals an
archive; the source is fenced and stopped; the archive is restored into a SECOND Compose project
through the shipped restore jobs (the edge keeps its name, port and certificate and is only
pointed at the new project). The guest then runs `blindpass-node recovery-relay`, the operator
reviews, the administrator attests the source stop, the authority activates, the node comes back
online (`blindpass status --nodes --require-online`), an ordinary grant works, and the original
stack is refused.

Scenarios (`--scenario`):
  main    covered node: uncovered completion refused, relay, review, attestation, activation,
          reconnect, an ordinary grant, original stack refused.
  waiver  the node never reports: waived by name, stays revoked, the controller still serves.

Everything is disposable: random project names, a private run directory, a throwaway authority
container and a guest overlay. Credentials stay in private files and are never printed. The edge is
a test fixture (nginx with the shipped example's directives and the test names `p03-controller`
and `p03-input` on the fixed port 8443 the guest harness expects); it is not a production edge.
"""

import argparse
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "deployment"))
import split_custody  # noqa: E402

_spec = importlib.util.spec_from_file_location("p06_relay_vm", HERE / "p06-relay-vm.py")
relay = importlib.util.module_from_spec(_spec)
sys.modules["p06_relay_vm"] = relay
_spec.loader.exec_module(relay)

Failure = relay.Failure
ROOT = relay.ROOT
BIN = relay.BIN
ORIGIN = relay.ORIGIN  # https://p03-controller:8443
PUBLIC_HOST, UI_HOST, PORT = relay.HOSTNAME, "p03-input", relay.PORT
UI_URL = f"https://{UI_HOST}:{PORT}"
IMAGE = os.environ.get("BLINDPASS_P06_CONTROLLER_IMAGE", "blindpass-p06-controller:node")
HELPER = os.environ.get("BLINDPASS_P06_EDGE_IMAGE", "blindpass-p06-edge:local")
AUTHORITY_IMAGE = "postgres:16-alpine@sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea"
AUTHORITY_HOST = "authority.p06.invalid"
SUBNETS = {"sqlite": ("172.29.81", "172.29.82"), "postgres": ("172.29.83", "172.29.84")}
DEBUG = os.environ.get("BLINDPASS_P06_DEBUG") == "1"
STATUS_BOUND_SECONDS = 120


def passed(name, detail=""):
    print(f"P06-CN {name} PASS {detail}".rstrip(), flush=True)


def sh(args, *, env=None, data=None, timeout=120, check=True, label=None):
    result = subprocess.run(args, env=env, input=data, capture_output=True, timeout=timeout)
    if check and result.returncode:
        if DEBUG:
            print(f"P06-CN diagnostic ({label or args[0]}): " + result.stderr[-600:].decode(errors="replace"), file=sys.stderr)
        # Never replay argv or tool output: they can carry credentials.
        raise Failure(f"{label or Path(str(args[0])).name} failed (exit {result.returncode})")
    return result


def docker(*args, success=True, timeout=120, data=None):
    return sh(["docker", *args], check=success, timeout=timeout, data=data, label="docker " + " ".join(str(a) for a in args[:2]))


def wait(check, timeout, what, interval=0.3):
    deadline = time.monotonic() + timeout
    while True:
        if check():
            return
        if time.monotonic() > deadline:
            raise Failure(what)
        time.sleep(interval)


# ---- the authority (a TLS PostgreSQL container, as in the Compose gates) ---------------------

class Authority:
    database = "authority"

    def __init__(self, r):
        self.r = r
        self.name = f"blindpass-p06-cn-authority-{r.suffix}"
        self.role = "p06_runtime"
        self.password = secrets.token_hex(24)
        self.dir = r.dir / "authority"
        self.tls = r.dir / "authority-tls"
        self.created = False

    def psql(self, sql, *, variables=None, check=True, database=None):
        command = ["exec", "-i", self.name, "psql", "-X", "-q", "-t", "-A", "-h", "127.0.0.1", "-U", "postgres",
                   "-d", database or self.database, "-v", "ON_ERROR_STOP=1"]
        for key, value in (variables or {}).items():
            command += ["-v", f"{key}={value}"]
        command += ["-f", "-"]
        return sh(["docker", *command], data=sql.encode(), check=check, label="authority psql")

    def script(self, name, check=True, **extra):
        return self.psql((ROOT / "deploy/controller" / name).read_text(),
                         variables={**self.r.variables, **extra}, check=check)

    def scalar(self, sql):
        return self.psql(sql).stdout.decode().strip()

    def create_files(self):
        self.dir.mkdir(mode=0o700)
        self.tls.mkdir(mode=0o700)
        t = self.tls
        sh(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=p06 authority ca",
            "-addext", "basicConstraints=critical,CA:TRUE", "-keyout", str(t / "ca.key"), "-out", str(t / "ca.pem")])
        sh(["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-subj", f"/CN={AUTHORITY_HOST}",
            "-keyout", str(t / "server.key"), "-out", str(t / "server.csr")])
        (t / "ext.cnf").write_text(f"subjectAltName=DNS:{AUTHORITY_HOST}\nbasicConstraints=CA:FALSE\n")
        sh(["openssl", "x509", "-req", "-in", str(t / "server.csr"), "-CA", str(t / "ca.pem"), "-CAkey", str(t / "ca.key"),
            "-CAcreateserial", "-days", "1", "-extfile", str(t / "ext.cnf"), "-out", str(t / "server.crt")])
        shutil.copy(t / "ca.pem", self.dir / "authority-ca.pem")
        for path in t.iterdir():
            path.chmod(0o600)

    def start(self, stack):
        self.created = True
        docker("run", "--detach", "--name", self.name, "--network", stack.network, "--network-alias", AUTHORITY_HOST,
               "--ip", stack.authority_ip, "--user", "0", "--mount", f"type=bind,src={self.tls},dst=/tls",
               "--entrypoint", "/bin/sh", "-e", "POSTGRES_PASSWORD=" + secrets.token_hex(16), AUTHORITY_IMAGE,
               "-ec", "install -d -m 0700 -o postgres -g postgres /pgtls && install -m 0600 -o postgres -g postgres /tls/server.key /pgtls/server.key "
                      "&& install -m 0644 -o postgres -g postgres /tls/server.crt /pgtls/server.crt "
                      "&& exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/pgtls/server.crt -c ssl_key_file=/pgtls/server.key")
        wait(lambda: docker("exec", self.name, "pg_isready", "-U", "postgres", success=False).returncode == 0, 60, "authority did not start")
        wait(lambda: self.psql("SELECT 1", check=False, database="postgres").returncode == 0, 60, "authority not accepting commands")
        self.psql("CREATE DATABASE authority", database="postgres")
        self.psql((ROOT / "deploy/controller/recovery-authority.sql").read_text())
        self.psql(f"CREATE ROLE {self.role} LOGIN PASSWORD '{self.password}'")
        self.psql((ROOT / "deploy/controller/authority-runtime-role.sql").read_text(), variables={"runtime_role": self.role})
        (self.dir / "authority-url").write_text(
            f"postgresql://{self.role}:{self.password}@{AUTHORITY_HOST}:5432/authority?sslmode=verify-full&sslrootcert=/authority/authority-ca.pem")
        for path in self.dir.iterdir():
            path.chmod(0o600)
        split_custody.own(docker, HELPER, self.dir)

    def attach(self, stack):
        docker("network", "connect", "--alias", AUTHORITY_HOST, "--ip", stack.authority_ip, stack.network, self.name)


# ---- one Compose project -------------------------------------------------------------------

class Stack:
    def __init__(self, r, label, subnet):
        self.r = r
        self.label = label
        self.profile = r.profile
        self.project = f"blindpass-p06-cn-{r.profile}-{label}-{r.suffix}"
        self.network = self.project + "_edge"
        self.controller_ip, self.edge_ip, self.authority_ip = subnet + ".2", subnet + ".3", subnet + ".5"
        files = [f"compose.{r.profile}.yml", "compose.initialize.yml", f"compose.backup-{r.profile}.yml", f"compose.restore-{r.profile}.yml"]
        self.base = ["docker", "compose", "--project-name", self.project]
        for name in files:
            self.base += ["--file", str(ROOT / "deploy/controller" / name)]
        self.env = dict(
            os.environ, BLINDPASS_CONTROLLER_IMAGE=IMAGE, BLINDPASS_PUBLIC_URL=ORIGIN, BLINDPASS_UI_BASE_URL=UI_URL,
            BLINDPASS_TRUST_PROXY=self.edge_ip, BLINDPASS_CONTROLLER_IP=self.controller_ip,
            BLINDPASS_EDGE_SUBNET=subnet + ".0/24", BLINDPASS_POSTGRES_PASSWORD_FILE=str(r.dir / "pg-password"),
            BLINDPASS_DATABASE_CONFIG_DIR=str(r.dir / "config"), BLINDPASS_CONTROLLER_TENANT_ID=r.tenant,
            BLINDPASS_CONTROLLER_OWNER_ID=r.owner, BLINDPASS_AUTHORITY_CONFIG_DIR=str(r.dir / "authority"),
            BLINDPASS_BACKUP_RECOVERY_DIR=str(r.dir / "recovery"), BLINDPASS_RESTORE_ARCHIVE_DIR=str(r.dir / "archives"),
            BLINDPASS_RESTORE_STAGING_DIR=str(r.dir / f"staging-{label}"), BLINDPASS_RESTORE_ARCHIVE="placeholder.bpbackup",
            BLINDPASS_RESTORE_ID="p06cnplaceholder")
        self.created = False

    def compose(self, *args, check=True, timeout=120, data=None):
        self.created = True
        return sh([*self.base, *args], env=self.env, check=check, timeout=timeout, data=data,
                  label=f"compose[{self.label}] " + " ".join(str(a) for a in args[:4]))

    def cid(self):
        return self.compose("ps", "--all", "--quiet", "controller").stdout.decode().strip()

    def ready(self):
        name = self.cid()
        return bool(name) and docker("exec", name, "blindpass-controller", "healthcheck", success=False, timeout=10).returncode == 0

    def responding(self):
        name = self.cid()
        return bool(name) and docker("exec", name, "blindpass", "admin", "recovery", "status", success=False, timeout=10).returncode == 0

    def up(self):
        self.compose("up", "--detach", "--force-recreate", "controller")

    def stop(self):
        self.compose("stop", "controller")

    def cli(self, *args, check=True):
        return self.compose("exec", "-T", "controller", "blindpass", "admin", "recovery", *args, check=check, timeout=120)

    def cli_json(self, *args):
        return json.loads(self.cli(*args).stdout.decode())

    def logs(self):
        out = self.compose("logs", "--no-color", check=False, timeout=60)
        return (out.stdout + out.stderr).decode(errors="replace")

    def volume(self, kind):
        return f"{self.project}_blindpass-{kind}"

    def volume_python(self, kind, code, write=False):
        return docker("run", "--rm", "--user", "10001:10001", "--mount",
                      f"type=volume,src={self.volume(kind)},dst=/v" + ("" if write else ",readonly"),
                      "--entrypoint", "python3", HELPER, "-c", code)

    def database_hash(self):
        out = self.volume_python("data", "import pathlib,hashlib\nh=hashlib.sha256()\n"
                                 "[h.update(p.read_bytes()) for p in sorted(pathlib.Path('/v').rglob('controller.db'))]\nprint(h.hexdigest())")
        return out.stdout.decode().strip()

    def rows(self, sql, params=()):
        for value in params:
            if not re.fullmatch(r"[A-Za-z0-9_.:-]+", str(value)):
                raise Failure("unsafe query parameter")
        if self.profile == "sqlite":
            code = ("import sqlite3,json,sys\nc=sqlite3.connect('file:/v/controller.db?mode=ro',uri=True)\n"
                    "print(json.dumps(c.execute(sys.argv[1],json.loads(sys.argv[2])).fetchall()))")
            out = docker("run", "--rm", "--user", "10001:10001", "--mount", f"type=volume,src={self.volume('data')},dst=/v",
                         "--entrypoint", "python3", HELPER, "-c", code, sql, json.dumps(list(params)), timeout=60)
            return [tuple(row) for row in json.loads(out.stdout.decode())]
        parts = sql.split("?")
        text = parts[0] + "".join(f"'{value}'" + part for value, part in zip(params, parts[1:]))
        out = self.compose("exec", "-T", "postgres", "psql", "-X", "-q", "-t", "-A", "-U", "blindpass", "-d", "blindpass",
                           "-F", "\x1f", "-R", "\x1e", "-v", "ON_ERROR_STOP=1", "-c", "SET search_path = controller;" + text,
                           timeout=60).stdout.decode()
        out = out.replace("SET\n", "", 1) if out.startswith("SET\n") else out
        records = [rec for rec in out.strip("\n\x1e").split("\x1e") if rec != ""]
        return [tuple(rec.strip("\n").split("\x1f")) for rec in records]

    def down(self):
        if self.created:
            sh([*self.base, "down", "--volumes", "--remove-orphans"], env=self.env, check=False, timeout=180)


# ---- the edge (nginx with the shipped example's directives) --------------------------------------

class Edge:
    def __init__(self, r):
        self.r = r
        self.name = f"blindpass-p06-cn-edge-{r.suffix}"
        self.dir = r.dir / "edge"
        self.started = False

    def make_certificate(self):
        self.dir.mkdir(mode=0o700)
        sh(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-quiet",
            "-keyout", str(self.dir / "private-key.pem"), "-out", str(self.dir / "fullchain.pem"),
            "-subj", f"/CN={PUBLIC_HOST}", "-addext", f"subjectAltName=DNS:{PUBLIC_HOST},DNS:{UI_HOST}"])
        (self.dir / "private-key.pem").chmod(0o600)
        (self.dir / "fullchain.pem").chmod(0o600)
        shutil.copy(self.dir / "fullchain.pem", self.r.dir / "controller.crt")  # the guest and the host API trust it
        (self.r.dir / "controller.crt").chmod(0o600)

    def write_config(self, upstream):
        text = (ROOT / "deploy/proxy/nginx.conf.example").read_text()
        # The shipped example serves default-port origins; the harness endpoint carries :8443, which the
        # controller compares against BLINDPASS_PUBLIC_URL / BLINDPASS_UI_BASE_URL including the port.
        text = text.replace("Host blindpass.example;", f"Host {PUBLIC_HOST}:{PORT};").replace("Host input.example;", f"Host {UI_HOST}:{PORT};")
        text = text.replace("blindpass.example", PUBLIC_HOST).replace("input.example", UI_HOST)
        text = text.replace("127.0.0.1:3200", f"{upstream}:3200").replace("/etc/nginx/blindpass/", "/fixture/")
        if PUBLIC_HOST not in text or "127.0.0.1:3200" in text:
            raise Failure("edge configuration was not rewritten")
        (self.dir / "nginx.conf").write_text("events {}\nhttp {\n" + text + "\n}\n")

    def start(self, stack):
        self.started = True
        self.write_config(stack.controller_ip)
        docker("run", "--detach", "--name", self.name, "--network", stack.network, "--ip", stack.edge_ip,
               "--publish", f"127.0.0.1:{PORT}:443", "--mount", f"type=bind,src={self.dir},dst=/fixture,readonly",
               HELPER, "nginx", "-c", "/fixture/nginx.conf", "-g", "daemon off;")
        self.wait_answering()

    def wait_answering(self, expect=None):
        api = relay.TlsApi(self.r.dir / "controller.crt")

        def answering():
            try:
                status, _ = api.request("GET", "/readyz", session=False)
                return status == expect if expect else status in (200, 503)
            except (OSError, ssl.SSLError, http.client.HTTPException):
                return False
        wait(answering, 20, "edge did not answer with a controller response")

    def point(self, stack):
        """Same container, name, port and certificate; only the upstream project changes."""
        docker("network", "connect", "--ip", stack.edge_ip, stack.network, self.name)
        self.write_config(stack.controller_ip)
        docker("exec", self.name, "nginx", "-s", "reload")
        time.sleep(1)

    def logs(self):
        out = docker("logs", self.name, success=False)
        return (out.stdout + out.stderr).decode(errors="replace")


# ---- the rehearsal -----------------------------------------------------------------------

class Rehearsal(relay.Rehearsal):
    def __init__(self, args):
        args.backend = "sqlite"  # the relay base class only uses this for its host-controller toolkit paths
        super().__init__(args)
        self.profile = args.profile
        self.suffix = secrets.token_hex(4)
        self.tenant = f"p06cn_tenant_{self.suffix}"
        self.owner = f"p06cn_owner_{self.suffix}"
        self.authority = Authority(self)
        self.edge = Edge(self)
        subnets = SUBNETS[self.profile]
        self.a = Stack(self, "a", subnets[0])
        self.b = Stack(self, "b", subnets[1])
        self.active = self.a
        self.source = self.a  # relay.grant_stage passes it to db_rows, which reads the active stack
        self.canaries = []
        self.variables = {}
        self.owned = []
        self.node_seen = {}

    def db_rows(self, controller, sql, params=()):
        return self.active.rows(sql, params)

    def own_dir(self, name):
        path = self.dir / name
        path.mkdir(mode=0o700)
        split_custody.own(docker, HELPER, path)
        self.owned.append(path)
        return path

    def script(self, name, **extra):
        return self.authority.script(name, check=False, **extra)

    def ledger(self):
        return self.authority.scalar(f"SELECT phase||':'||epoch||':'||revision FROM blindpass_authority.recovery_authority WHERE tenant_id='{self.tenant}'")

    def cleanup(self):
        for vm in self.vms:
            vm.stop()
        docker("rm", "--force", self.edge.name, success=False)
        docker("rm", "--force", "--volumes", self.authority.name, success=False)
        for stack in (self.b, self.a):
            stack.down()
        keep = os.environ.get("BLINDPASS_P06_KEEP_ARTIFACTS") == "1"
        for path in [self.dir / "config", self.dir / "authority", self.dir / "recovery", self.dir / "offline", *self.owned]:
            if path.exists():
                docker("run", "--rm", "--user", "0", "--mount", f"type=bind,src={path},dst=/d", "--entrypoint", "/bin/sh", HELPER,
                       "-ec", f"chown -R {os.getuid()}:{os.getgid()} /d", success=False)
        if keep:
            print(f"P06-CN kept artifacts in {self.dir}", file=sys.stderr)
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


def list_nodes(r):
    status, listing = r.api.request("GET", "/api/v3/nodes?limit=100")
    if status != 200:
        raise Failure("node listing refused")
    return listing["items"]


# ---- stages ----------------------------------------------------------------------------------

def source_stage(r):
    a = r.a
    password = secrets.token_hex(32)
    (r.dir / "pg-password").write_text(password)
    (r.dir / "pg-password").chmod(0o600)
    config = r.dir / "config"
    config.mkdir(mode=0o700)
    (config / "database.url").write_text(f"postgresql://blindpass:{password}@postgres:5432/blindpass")
    (config / "database.url").chmod(0o600)
    split_custody.own(docker, HELPER, config)
    r.recovery = r.own_dir("recovery")
    r.offline = r.own_dir("offline")
    r.archives = r.own_dir("archives")
    for label in ("a", "b"):
        r.own_dir(f"staging-{label}")
    r.edge.make_certificate()
    r.api = relay.TlsApi(r.dir / "controller.crt")
    r.authority.create_files()
    if a.compose("run", "--rm", "--no-deps", "controller", "check-config", check=False).returncode == 0:
        raise Failure("check-config accepted a configuration without an authority")
    r.authority.start(a)
    a.compose("--profile", "initialize", "run", "--rm", "keys-init")
    if a.compose("--profile", "initialize", "run", "--rm", "keys-init", check=False).returncode == 0:
        raise Failure("keys-init overwrote existing keys")
    r.issuer = a.compose("run", "--rm", "--no-deps", "controller", "keys", "issuer-id", "--directory", "/keys").stdout.decode().strip()
    if not re.fullmatch(r"ed25519-[A-Za-z0-9_-]{43}", r.issuer):
        raise Failure("issuer id is malformed")
    r.variables = {"tenant": r.tenant, "owner": r.owner, "issuer": r.issuer}
    if a.compose("run", "--rm", "controller", "migrate", check=False).returncode == 0:
        raise Failure("migrate ran before the issuer was registered")
    r.authority.script("authority-register.sql")
    a.compose("run", "--rm", "controller", "migrate")
    r.authority.script("authority-activate.sql")
    a.compose("up", "--detach", "controller")
    wait(a.ready, 30, "the source controller did not become ready")
    r.edge.start(a)
    bootstrap = a.compose("exec", "-T", "controller", "blindpass", "admin", "bootstrap").stdout
    temporary = json.loads(bootstrap)["temporary_password"]
    r.canaries = [temporary, password, r.authority.password]
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
    ready = r.api.request("GET", "/readyz", session=False)[0]
    if ready != 200:
        raise Failure("the controller is not ready through the edge")
    passed("S1", f"shipped Compose {r.profile} stack (pinned image, authority container with verify-full TLS) serving through the nginx edge on 127.0.0.1:{PORT}; operator session established over verified HTTPS")


def enroll_stage(r):
    relay.enroll_stage(r)
    sh(["scp", *[("-P" if o == "-p" else o) for o in r.ssh_options()], str(BIN / "blindpass"),
        f"{relay.GUEST_USER}@127.0.0.1:/tmp/p03/blindpass"], label="scp blindpass")
    r.guest("chmod", "0755", "/tmp/p03/blindpass")
    r.node_key_version = list_nodes(r)[0]["key_version"]
    started = time.monotonic()
    result = guest_status(r, r.password)
    if result.returncode != 0:
        raise Failure("`status --nodes --require-online` failed for the enrolled node")
    passed("S2c", f"`blindpass status --nodes --require-online` passes from the guest over verified HTTPS ({time.monotonic() - started:.1f} s); node key version {r.node_key_version}")


def grant_stage(r):
    relay.grant_stage(r)


def backup_stage(r):
    a = r.a
    split_custody.provision(docker, IMAGE, HELPER, r.recovery, r.offline)
    split_custody.assert_host_holds_no_decrypt_key(docker, HELPER, r.recovery)
    a.compose("--profile", "backup", "run", "--rm", "controller-backup", timeout=300)
    if not a.ready():
        raise Failure("the controller stopped serving during the backup job")
    out = a.volume_python("data", "import pathlib,shutil,json\nfound=sorted(pathlib.Path('/v/backups').rglob('*.bpbackup'))\n"
                          "assert len(found)==1,found\nprint(json.dumps({'name':found[0].name,'size':found[0].stat().st_size}))")
    info = json.loads(out.stdout.decode().strip())
    docker("run", "--rm", "--user", "10001:10001", "--mount", f"type=volume,src={a.volume('data')},dst=/v,readonly",
           "--mount", f"type=bind,src={r.archives},dst=/out", "--entrypoint", "python3", HELPER, "-c",
           "import pathlib,shutil\nshutil.copy(next(pathlib.Path('/v/backups').rglob('*.bpbackup')),'/out/'+%r)" % info["name"])
    r.archive_name = info["name"]
    if guest_status(r, r.password).returncode != 0:
        raise Failure("the node was not online after the backup job")
    passed("B1", f"shipped backup job sealed one split-custody archive ({info['size']} bytes) while the controller kept serving and the node stayed online; the host custody directory holds no decrypt key")


def fence_stage(r):
    a = r.a
    if r.profile == "sqlite":
        r.source_hash = None
    r.authority.script("authority-fence.sql")
    a.stop()
    if r.profile == "sqlite":
        r.source_hash = a.database_hash()
    r.fenced_at = time.monotonic()
    ledger = r.ledger()
    if not ledger.startswith("fenced:"):
        raise Failure(f"the authority record is not fenced: {ledger}")
    passed("F1", f"source fenced in the authority ({ledger}) and stopped; its volumes stay intact")


def restore_stage(r):
    a, b = r.a, r.b
    revision = r.authority.scalar(f"SELECT revision FROM blindpass_authority.recovery_authority WHERE tenant_id='{r.tenant}'")
    reserved = r.authority.scalar(
        f"SELECT epoch||':'||phase FROM blindpass_authority.reserve_recovery('{r.tenant}','{r.issuer}','{r.owner}',{revision},1)")
    if not reserved.endswith(":recovering"):
        raise Failure("the authority did not reserve recovery")
    r.epoch = int(reserved.split(":")[0])
    b.compose("create", "controller")
    r.authority.attach(b)
    b.env["BLINDPASS_RESTORE_ARCHIVE"] = r.archive_name
    b.env["BLINDPASS_RESTORE_ID"] = "p06cn" + secrets.token_hex(3)
    # The backup host's custody directory cannot open the archive.
    if b.compose("--profile", "restore", "run", "--rm", "controller-restore", check=False, timeout=600).returncode == 0:
        raise Failure("host custody restored the archive")
    b.env["BLINDPASS_BACKUP_RECOVERY_DIR"] = str(r.offline)
    note = ""
    if r.profile == "postgres":
        b.compose("up", "--detach", "--wait", "postgres", timeout=180)
        refused = b.compose("--profile", "restore", "run", "--rm", "controller-restore", check=False, timeout=600)
        text = (refused.stdout + refused.stderr).decode()
        if refused.returncode == 0 or "holds an empty schema: drop it first" not in text:
            raise Failure("the Compose init hook's empty schema was not refused with its distinct reason")
        b.compose("exec", "-T", "postgres", "psql", "-U", "blindpass", "-d", "blindpass", "-X", "-q", "-v", "ON_ERROR_STOP=1",
                  "-c", "DROP SCHEMA controller CASCADE")
        note = "; the init hook's empty schema was refused with its fixed reason until dropped"
        docker("run", "--rm", "--user", "10001:10001", "--mount", f"type=bind,src={r.dir / 'staging-b'},dst=/s", "--entrypoint", "/bin/sh",
               HELPER, "-ec", "rm -rf /s/root")
    receipt = json.loads(b.compose("--profile", "restore", "run", "--rm", "controller-restore", timeout=600).stdout.decode().strip().splitlines()[-1])
    if receipt.get("phase") != "recovery_required" or receipt.get("activation_permitted") is not False or receipt.get("backend") != r.profile:
        raise Failure(f"restore receipt is not fenced: {receipt}")
    installed = json.loads(b.compose("--profile", "restore", "run", "--rm", "controller-restore-install", timeout=300).stdout.decode().strip().splitlines()[-1])
    if installed != {"restore": "installed"}:
        raise Failure("restore install did not report installed")
    if b.compose("--profile", "restore", "run", "--rm", "controller-restore-install", check=False).returncode == 0:
        raise Failure("install overwrote non-empty destination volumes")
    b.env["BLINDPASS_BACKUP_RECOVERY_DIR"] = str(r.recovery)
    r.edge.point(b)
    b.compose("up", "--detach", "controller")
    wait(b.responding, 40, "the restored controller did not start")
    r.active = b
    r.edge.wait_answering(expect=503)
    if b.ready():
        raise Failure("the recovering controller reported ready")
    passed("S3", f"archive restored into a SECOND Compose project under recovery epoch {r.epoch} through the shipped jobs (offline custody required, install refuses non-empty volumes{note}); the edge kept its name, port and certificate and now answers 503 for the recovering controller")


def stale_source_refused(r, label):
    a = r.a
    a.up()
    time.sleep(8)
    if a.ready():
        raise Failure(f"the original stack became ready ({label})")
    logs = a.compose("logs", "--no-color", "controller", check=False).stdout.decode(errors="replace")
    reasons = re.findall(r'"startup_failed"[^\n]*?"reason":"([a-z_]+)"', logs) or re.findall(r'"reason":"([a-z_]+)"', logs)
    if '"startup_failed"' not in logs or not reasons:
        raise Failure(f"the original stack did not report a startup failure ({label})")
    a.stop()
    return reasons[-1]


def gates_stage(r):
    b = r.b
    before = r.ledger()
    refused_with(r.script("authority-activate.sql"), label="ordinary activation of a recovering record")
    if r.ledger() != before:
        raise Failure("the ordinary activation script changed a recovering record")
    refused_with(r.script("authority-recover-activate.sql"), "source_stop_missing", "review_incomplete", "node_uncovered",
                 label="early recovery activation")
    attest = r.script("authority-recover-attest.sql", host="p06cn-source-host", by="p06cn-admin", note="premature")
    if attest.returncode == 0 or r.authority.scalar("SELECT count(*) FROM blindpass_authority.recovery_source_stop") != "0":
        raise Failure("an attestation was accepted while the recovering controller held the guard")
    if r.ledger() != before:
        raise Failure("refusals changed the recovering record")
    gaps = b.cli_json("status")
    for gate in ("source_stop_missing", "review_incomplete", "node_uncovered"):
        if gate not in gaps["gaps"]:
            raise Failure(f"the controller precheck does not list {gate}: {gaps['gaps']}")
    if gaps["activation_permitted"] is not False:
        raise Failure("the precheck permits activation")
    passed("G1", f"ordinary activation, early recovery activation (names source_stop_missing, review_incomplete, node_uncovered) and a premature attestation refused with the record unchanged ({before}); precheck lists {gaps['gaps']}")
    reason = stale_source_refused(r, "before activation")
    if r.ledger() != before:
        raise Failure("an old-source start changed the recovering record")
    if not b.responding():
        raise Failure("an old-source start disturbed the recovering controller")
    passed("G2", f"the original stack refuses to serve while the record is recovering (startup_failed, reason {reason}); record unchanged and the recovering controller undisturbed")


def decide_all(r, node_waived=False):
    b = r.b
    listing = b.cli_json("review", "list")
    items = listing["items"]
    categories = sorted({item["category"] for item in items})
    if listing["total"] != len(items) or "operation" not in categories or "operator" not in categories:
        raise Failure(f"review list is incomplete: {categories}")
    if not any(i["category"] == "operation" and i["subject_id"] == r.operation_id for i in items):
        raise Failure("the consumed operation is not listed for review")
    for category in categories:
        decision = {"operator": "accept", "operation": "accept", "workload": "revoke"}.get(category, "reject")
        out = b.cli_json("review", "decide", "--category", category, "--decision", decision,
                         "--operator", "p06cn-operator", "--note", "reviewed by the Compose rehearsal")
        if out["decided"] < 1:
            raise Failure(f"no undecided {category} item was decided")
    return categories


def uncovered_stage(r):
    b = r.b
    undecided = b.cli("review", "complete", "--operator", "p06cn-operator", check=False)
    if undecided.returncode == 0:
        raise Failure("complete accepted an undecided review")
    categories = decide_all(r)
    blocked = b.cli("review", "complete", "--operator", "p06cn-operator", check=False)
    if blocked.returncode == 0:
        raise Failure("completion accepted a node that is neither covered nor waived")
    if "node_uncovered" not in b.cli_json("status")["gaps"]:
        raise Failure("the uncovered node left the precheck")
    if not b.responding():
        raise Failure("a refused completion fenced the controller")
    passed("V1", f"{len(categories)} review categories decided; completion refused while undecided and while the node is neither covered nor waived (node_uncovered stays listed); controller not fenced")


def relay_stage(r):
    result = relay.relay_command(r)
    out = result.stdout.decode().strip()
    if result.returncode != 0 or out != "recovery_relay state=covered pages=1 activation_permitted=false":
        raise Failure(f"relay did not complete: exit={result.returncode} stdout={out!r} stderr={result.stderr.decode()[-200:]!r}")
    node = [n for n in r.b.cli_json("status")["nodes"] if n["node_id"] == r.node_id][0]
    if node["receipt"] != "covered" or node["waived"]:
        raise Failure("the authority does not show the node as covered")
    if "node_uncovered" in r.b.cli_json("status")["gaps"]:
        raise Failure("a covered node is still listed uncovered")
    for path in ("/api/v3/capabilities", "/api/auth/me", "/api/v3/nodes", "/"):
        if r.api.request("GET", path, session=False)[0] != 503:
            raise Failure("an ordinary route reopened after the relay")
    passed("R1", f"{out} from the real node in the guest over verified HTTPS through the edge; the authority and the precheck show the node covered; ordinary routes still 503")


def complete_stage(r):
    b = r.b
    done = b.cli_json("review", "complete", "--operator", "p06cn-operator")
    if b.cli_json("status")["gaps"] != ["source_stop_missing"]:
        raise Failure(f"after completion only the attestation should remain, got {b.cli_json('status')['gaps']}")
    if b.cli("review", "decide", "--category", "operation", "--subject", r.operation_id, "--decision", "accept",
             "--operator", "p06cn-operator", check=False).returncode == 0:
        raise Failure("a decision was accepted after completion")
    passed("V2", f"review completed ({done['summary']}) once the node was covered; decisions closed; only source_stop_missing remains")


def waiver_stage(r):
    b = r.b
    decide_all(r)
    if "node_uncovered" not in b.cli_json("status")["gaps"]:
        raise Failure("an unreported node is not listed as uncovered")
    if b.cli("review", "complete", "--operator", "p06cn-operator", check=False).returncode == 0:
        raise Failure("completion accepted an unreported, unwaived node")
    if b.cli("waive-node", "no-such-node", "--operator", "p06cn-operator", "--note", "x", check=False).returncode == 0:
        raise Failure("a waiver for an unknown node was accepted")
    b.cli_json("waive-node", r.node_id, "--operator", "p06cn-operator", "--note", "hardware lost in the fire")
    node = [n for n in b.cli_json("status")["nodes"] if n["node_id"] == r.node_id][0]
    if not (node["waived"] and node["revoked"]):
        raise Failure("the waiver did not revoke the node's broker trust in the authority")
    done = b.cli_json("review", "complete", "--operator", "p06cn-operator")
    if done["summary"]["nodes_revoked"] != 1:
        raise Failure("completion did not revoke the waived node locally")
    passed("W1", f"completion refused while the node is neither covered nor waived; unknown waiver refused; waiver by name revoked its broker trust, completion revoked it locally ({done['summary']})")


def activate_stage(r):
    b = r.b
    b.stop()
    before = r.ledger()
    text = refused_with(r.script("authority-recover-activate.sql"), "source_stop_missing", label="activation without attestation")
    if "review_incomplete" in text or "node_uncovered" in text or "source_process_live" in text:
        raise Failure("the refusal names gates that are met")
    refused_with(r.script("authority-activate.sql"), label="ordinary activation after review")
    attest = r.script("authority-recover-attest.sql", host="p06cn-source-host", by="p06cn-admin",
                      note="source Compose project stopped and fenced from the authority")
    if attest.returncode != 0:
        raise Failure("attestation refused although both stacks are stopped")
    row = r.authority.scalar("SELECT host_id||':'||attested_by FROM blindpass_authority.recovery_source_stop ORDER BY epoch DESC LIMIT 1")
    if row != "p06cn-source-host:p06cn-admin":
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
    b = r.b
    since = int(time.time() * 1000)
    started = time.monotonic()
    b.up()
    wait(b.ready, 40, "the activated controller did not become ready")
    ready_after = time.monotonic() - started
    status, _ = r.api.request("GET", "/readyz", session=False)
    if status != 200:
        raise Failure("the activated controller is not ready through the edge")
    elapsed = ready_after + wait_node_seen(r, since, STATUS_BOUND_SECONDS - ready_after, "restored controller")
    r.reconnect_seconds = elapsed
    r.api = relay.TlsApi(r.dir / "controller.crt")
    r.api.login("admin", r.password)
    rows = list_nodes(r)
    if [row["id"] for row in rows] != [r.node_id] or rows[0]["status"] != "online":
        raise Failure("the node is not online at the activated controller")
    if rows[0]["key_version"] != r.node_key_version:
        raise Failure("the node's key version changed across recovery")
    status, operation = r.api.request("GET", f"/api/v3/operations/{r.operation_id}")
    if status != 200 or operation.get("status") not in ("uncertain", "revoked"):
        raise Failure("a recovered operation is not left uncertain or revoked")
    sealed = r.fenced_at
    passed("S4", f"activated controller ready {ready_after:.1f} s after start; the unchanged node (key version {r.node_key_version}) passes `status --nodes --require-online` {elapsed:.1f} s after start ({time.monotonic() - sealed:.0f} s after the source was fenced); operator login works; recovered operation stays {operation['status']}")


def grant2_stage(r):
    first = r.grant_id
    relay.grant_stage(r)
    if r.grant_id == first:
        raise Failure("no new grant was issued after the activation")
    passed("S5", "an ordinary grant was approved by a second operator, delivered to the node and consumed by a workload in the guest through the activated Compose stack and the edge")


def source_refused_stage(r):
    b = r.b
    activated = r.ledger()
    refused_with(r.script("authority-activate.sql"), label="ordinary activation of the original stack while the restored stack serves")
    reason = stale_source_refused(r, "after activation")
    if not b.ready() or r.ledger() != activated:
        raise Failure("an old-source start disturbed the activated controller")
    note = ""
    if r.profile == "sqlite":
        if r.a.database_hash() != r.source_hash:
            raise Failure("the original SQLite database was modified")
        note = "; the original SQLite database is byte-unchanged"
    passed("S6", f"ordinary authority activation refused and the original stack not ready (startup_failed, reason {reason}) while the restored stack serves; the activated controller stayed ready and the record unchanged{note}")


def revoked_serve_stage(r):
    b = r.b
    b.up()
    wait(b.ready, 40, "the activated controller did not become ready")
    r.api = relay.TlsApi(r.dir / "controller.crt")
    r.api.login("admin", r.password)
    rows = list_nodes(r)
    if [row["id"] for row in rows] != [r.node_id] or rows[0]["status"] != "revoked":
        raise Failure("the waived node is not revoked at the activated controller")
    time.sleep(15)  # the node's own reconnect attempts must not bring it back
    rows = list_nodes(r)
    if rows[0]["status"] != "revoked" or guest_status(r, r.password).returncode == 0:
        raise Failure("the waived node came back or the online gate passed")
    if r.authority.scalar(f"SELECT state FROM blindpass_authority.broker_trust WHERE node_id='{r.node_id}'") != "revoked":
        raise Failure("the waived node's broker trust is not revoked")
    passed("W2", "controller activated and ready without the waived node; the node stays revoked and the `status --nodes --require-online` gate fails for it; its broker trust stays revoked in the authority")


def logs_stage(r):
    secrets_to_find = [*r.canaries, r.authority.password]
    if len(r.canaries) < 4 or any(len(value) < 12 for value in secrets_to_find):
        raise Failure("the log scan has no canaries to look for")
    journal = r.guest("sudo", "journalctl", "-u", "blindpass-broker.service", "-u", "blindpass-node.service",
                      "--no-pager", "-o", "cat", timeout=60).stdout.decode()
    # Fail closed: an empty, missing or truncated capture is a failure, and every scan is first shown
    # to see a planted token (P07-I04, finding F2).
    try:
        # The edge is the shipped nginx example, which logs nothing by design: say so only while that file still holds it.
        nginx_example = (ROOT / "deploy/proxy/nginx.conf.example").read_text()
        silent = ("the shipped nginx example sets access_log off and error_log /dev/null crit in every server block"
                  if nginx_example.count("access_log off;") >= 2 and nginx_example.count("error_log /dev/null crit;") >= 2 else None)
        for label, text, minimum, require, allow_empty in (
                ("controller A Compose logs", r.a.logs(), 32, [b"controller"], None),   # the fenced source logs one refusal line
                ("controller B Compose logs", r.b.logs(), 32, [b"controller"], None),
                ("edge logs", r.edge.logs(), 16, [], silent),
                ("guest broker and node journal", journal, 32, [], None)):
            relay.canary_log_scan.assert_log_clean("P06-L1 " + label, text, secrets_to_find, markers=["PRIVATE KEY-----"],
                                                   min_bytes=minimum, require=require, allow_empty=allow_empty)
    except relay.canary_log_scan.LogScanError as error:
        raise Failure(str(error)) from None
    passed("L1", "no operator or approver password, bootstrap password, enrollment token, database or authority password or PEM private key in any Compose, edge or guest broker/node log")


SCENARIOS = {
    "main": ["source", "enroll", "grant", "backup", "fence", "restore", "gates", "uncovered", "relay", "complete",
             "activate", "serve", "grant2", "source_refused", "logs"],
    "waiver": ["source", "enroll", "grant", "backup", "fence", "restore", "waiver", "activate", "revoked_serve", "logs"],
}


def preflight(profile):
    if os.geteuid() == 0:
        return relay.unsupported("run as the runner owner, not through sudo")
    for tool in ("docker", "qemu-system-x86_64", "qemu-img", "ssh", "scp", "ssh-keygen", "openssl", "cloud-localds"):
        if shutil.which(tool) is None:
            return relay.unsupported(f"{tool} is unavailable in PATH")
    if not (os.access("/dev/kvm", os.R_OK) and os.access("/dev/kvm", os.W_OK)):
        return relay.unsupported("/dev/kvm is unavailable or inaccessible")
    for binary in ("blindpass", "blindpass-broker", "blindpass-node", "blindpass-workload-client"):
        if not (BIN / binary).is_file():
            return relay.unsupported(f"{binary} is not built; run: cargo build --release -p blindpass-cli -p blindpass-broker -p blindpass-node")
    if not Path(os.environ.get("BLINDPASS_FLEET_GUEST_IMAGE", relay.IMAGE_DEFAULT)).is_file():
        return relay.unsupported("pinned guest image is missing")
    for image in (IMAGE, HELPER):
        if sh(["docker", "image", "inspect", image], check=False).returncode != 0:
            return relay.unsupported(f"image {image} is missing (build the controller and edge images: see tests/deployment/README.md)")
    with socket.socket() as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # a previous run leaves TIME-WAIT sockets
        try:
            probe.bind(("127.0.0.1", PORT))
        except OSError:
            return relay.unsupported(f"127.0.0.1:{PORT} is already in use")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--profile", choices=("sqlite", "postgres"), required=True)
    parser.add_argument("--scenario", choices=sorted(SCENARIOS), default="main")
    parser.add_argument("--until")
    args = parser.parse_args()
    stages = SCENARIOS[args.scenario]
    if args.until and args.until not in stages:
        parser.error("unknown stage for this scenario")
    blocked = preflight(args.profile)
    if blocked:
        return blocked
    r = Rehearsal(args)
    try:
        for stage in stages:
            globals()[f"{stage}_stage"](r)
            if stage == args.until:
                break
        return 0
    except (Failure, OSError, ssl.SSLError, http.client.HTTPException, KeyError, ValueError, IndexError, subprocess.TimeoutExpired) as error:
        print(f"P06-CN FAIL {type(error).__name__}: {error}", file=sys.stderr)
        for stack in (r.a, r.b):
            if stack.created:
                try:
                    print(f"--- {stack.label} controller log tail", file=sys.stderr)
                    print(stack.logs()[-1500:], file=sys.stderr)
                except Failure:
                    pass
        return 1
    finally:
        r.cleanup()


if __name__ == "__main__":
    sys.exit(main())
