#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""P06 RC09 actual recovery relay rehearsal.

A production-mode (authority-backed, built-in TLS) controller on the host enrolls a
real broker and node in a disposable QEMU/KVM guest, takes an authenticated backup,
is fenced and stopped, and is restored under a recovering authority record. The
guest then runs `blindpass-node recovery-relay` against the real broker control
socket and the restored controller over verified HTTPS.

Everything here is disposable: random names, a private run directory, a throwaway
authority database in the existing PostgreSQL fixture container and a guest overlay.
Credentials stay in private files and are never printed. This is the host side of
RC09-RR03/RR04 evidence; it is not RR05 (no packaged controller, no two-broker
recovery, no provider review or source-stop proof).
"""

import argparse
import hashlib
import http.client
import http.cookies
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests/deployment"))
import canary_log_scan  # noqa: E402  (P07-I04/F2: fail-closed log scans)
BIN = ROOT / "target/release"
PG_CONTAINER = "blindpass-postgres"
PG_PORT = 5433
HOSTNAME = "p03-controller"  # fixed by tests/fleet/p03-guest.sh
PORT = 8443
ORIGIN = f"https://{HOSTNAME}:{PORT}"
GUEST_USER = os.environ.get("BLINDPASS_FLEET_GUEST_USER", "blindpass")
SSH_PORT = int(os.environ.get("BLINDPASS_P06_SSH_PORT", "22231"))
IMAGE_DEFAULT = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share")) / "blindpass/vm-images/noble-server-cloudimg-amd64.img"
IMAGE_SHA_DEFAULT = "612b2c0cc1bc413a6cb8c38fd611794caf0f2b436c50013d8b3794db12ad7354"


class Failure(Exception):
    pass


def run(args, *, env=None, data=None, timeout=120, check=True, cwd=None):
    result = subprocess.run(args, env=env, input=data, capture_output=True, timeout=timeout, cwd=cwd)
    if check and result.returncode:
        if os.environ.get("BLINDPASS_P06_DEBUG") == "1" and args[0] in ("ssh", "scp", "docker"):
            # Guest output only: it never carries host credentials.
            print("P06-RR guest stderr: " + result.stderr.decode(errors="replace")[-600:], file=sys.stderr)
        # Never replay argv, environment or tool output: they can carry credentials.
        raise Failure(f"command failed: {Path(str(args[0])).name} {str(args[1]) if len(args) > 1 else ''}"[:80])
    return result


def private_write(path, content, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, "wb") as handle:
        handle.write(content if isinstance(content, bytes) else content.encode())


def passed(name, detail=""):
    stamp = time.strftime("%H:%M:%S", time.gmtime()) if os.environ.get("BLINDPASS_P06_DEBUG") == "1" else ""
    print(f"P06-RR {name} PASS {stamp} {detail}".replace("  ", " ").rstrip(), flush=True)


class Authority:
    """A throwaway independent authority database in the PostgreSQL fixture."""

    def __init__(self):
        suffix = secrets.token_hex(8)
        self.database = f"p06rr_{suffix}"
        self.owner_role = f"p06rr_o_{suffix}"
        self.runtime_role = f"p06rr_r_{suffix}"
        self.owner_password = "P06-DUMMY-" + secrets.token_hex(16)
        self.runtime_password = "P06-DUMMY-" + secrets.token_hex(16)
        self.created = False

    def psql(self, sql, *, database=None, variables=None, check=True, timeout=60):
        command = ["docker", "exec", "-i", "-e", "PGOPTIONS=-c lock_timeout=5000",
                   PG_CONTAINER, "psql", "-X", "-q", "-t", "-A", "-U", "blindpass",
                   "-d", database or self.database, "-v", "ON_ERROR_STOP=1"]
        for key, value in (variables or {}).items():
            command += ["-v", f"{key}={value}"]
        command += ["-f", "-"]
        return run(command, data=sql.encode(), check=check, timeout=timeout)

    def script(self, name, **variables):
        return self.psql((ROOT / "deploy/controller" / name).read_text(), variables=variables)

    def create(self):
        self.created = True
        self.psql(f"CREATE ROLE {self.owner_role} LOGIN PASSWORD '{self.owner_password}';"
                  f"CREATE ROLE {self.runtime_role} LOGIN PASSWORD '{self.runtime_password}';"
                  f"CREATE DATABASE {self.database} OWNER {self.owner_role};", database="blindpass")
        provision = (ROOT / "deploy/controller/recovery-authority.sql").read_text()
        self.psql(f"SET ROLE {self.owner_role};\n" + provision)
        self.psql((ROOT / "deploy/controller/authority-runtime-role.sql").read_text(),
                  variables={"runtime_role": self.runtime_role})

    def url(self):
        return f"postgresql://{self.runtime_role}:{self.runtime_password}@127.0.0.1:{PG_PORT}/{self.database}"

    def scalar(self, sql):
        return self.psql(sql).stdout.decode().strip()

    def drop(self):
        if not self.created:
            return
        self.psql(f"DROP DATABASE IF EXISTS {self.database} WITH (FORCE);"
                  f"DROP ROLE IF EXISTS {self.runtime_role};DROP ROLE IF EXISTS {self.owner_role};",
                  database="blindpass", check=False)


class PgStore:
    """Controller-store databases in the PostgreSQL fixture, one role with the dedicated
    `controller` schema as search_path (ADR 0011 / P06-D26). Superuser psql is used only
    for creation, inspection and cleanup; the controller connects as the store role."""

    def __init__(self, r):
        suffix = secrets.token_hex(6)
        self.r = r
        self.role = f"p06pg_r_{suffix}"
        self.password = "P06-DUMMY-" + secrets.token_hex(16)
        self.prefix = f"p06pg_{suffix}"
        self.databases = []
        self.created = False

    def admin(self, sql, database="blindpass", check=True):
        return self.r.authority.psql(sql, database=database, check=check)

    def create_role(self):
        self.created = True
        self.admin(f"CREATE ROLE {self.role} LOGIN PASSWORD '{self.password}';"
                   f"ALTER ROLE {self.role} SET search_path = controller;")

    def create_database(self, label, schema):
        name = f"{self.prefix}_{label}"
        self.databases.append(name)
        self.admin(f"CREATE DATABASE {name} OWNER {self.role};")
        if schema:
            self.admin(f"CREATE SCHEMA controller AUTHORIZATION {self.role};", database=name)
        return name

    def url_file(self, database):
        path = self.r.dir / f"{database}.url"
        private_write(path, f"postgresql://{self.role}:{self.password}@127.0.0.1:{PG_PORT}/{database}")
        return path

    def rows(self, database, sql, params=()):
        for value in params:
            if not re.fullmatch(r"[A-Za-z0-9_.:-]+", str(value)):
                raise Failure("unsafe query parameter")
        parts = sql.split("?")
        text = parts[0] + "".join(f"'{value}'" + part for value, part in zip(params, parts[1:]))
        command = ["docker", "exec", "-i", PG_CONTAINER, "psql", "-X", "-q", "-t", "-A", "-U", "blindpass",
                   "-d", database, "-F", "\x1f", "-R", "\x1e", "-v", "ON_ERROR_STOP=1", "-c",
                   "SET search_path = controller;" + text]
        out = run(command, timeout=60).stdout.decode()
        out = out.replace("SET\n", "", 1) if out.startswith("SET\n") else out
        records = [rec for rec in out.strip("\n\x1e").split("\x1e") if rec != ""]
        return [tuple(rec.strip("\n").split("\x1f")) for rec in records]

    def drop(self):
        if not self.created:
            return
        for name in self.databases:
            self.admin(f"DROP DATABASE IF EXISTS {name} WITH (FORCE);", check=False)
        self.admin(f"DROP ROLE IF EXISTS {self.role};", check=False)


class Controller:
    """A controller process with built-in TLS on the fixed loopback endpoint."""

    def __init__(self, rehearsal, name, keys, data, database=None):
        self.r = rehearsal
        self.name = name
        self.keys = keys
        self.data = data
        self.database = database  # PostgreSQL database name; None means the SQLite data directory
        self.process = None
        self.log = rehearsal.dir / f"{name}.log"
        self.admin_socket = rehearsal.dir / f"{name}.admin.sock"
        self.certificate = "controller"

    def env(self):
        r = self.r
        values = self._env_base()
        if self.database:
            values["BLINDPASS_DATABASE_URL_FILE"] = str(r.dir / f"{self.database}.url")
        else:
            values["BLINDPASS_DATA_DIR"] = str(self.data)
        return values

    def _env_base(self):
        r = self.r
        values = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "BLINDPASS_LISTEN": f"127.0.0.1:{PORT}",
            "BLINDPASS_PUBLIC_URL": ORIGIN,
            "BLINDPASS_UI_BASE_URL": ORIGIN,
            "BLINDPASS_TLS_CERT_FILE": str(r.dir / f"{self.certificate}.crt"),
            "BLINDPASS_TLS_KEY_FILE": str(r.dir / f"{self.certificate}.key"),
            "BLINDPASS_KEYS_DIR": str(self.keys),
            "BLINDPASS_ADMIN_SOCKET_PATH": str(self.admin_socket),
            "BLINDPASS_AUTHORITY_URL_FILE": str(r.dir / "authority-url"),
            "BLINDPASS_CONTROLLER_TENANT_ID": r.tenant,
            "BLINDPASS_CONTROLLER_OWNER_ID": r.owner,
        }
        if os.environ.get("RUST_LOG"):
            # Opt-in (P07-I04, S07): a success path with debug logging, scanned like any other run.
            values["RUST_LOG"] = os.environ["RUST_LOG"]
        return values

    def command(self, *args, check=True, timeout=120):
        if self.r.backend == "postgres" and (args[:1] == ("restore",) or args[:2] in (("backup", "create"), ("backup", "verify"))):
            return self.r.toolkit_command(self, args, check=check, timeout=max(timeout, 600))
        return run([str(BIN / "blindpass-controller"), *args], env=self.env(), check=check, timeout=timeout)

    def start(self):
        out = os.open(self.log, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        self.process = subprocess.Popen([str(BIN / "blindpass-controller"), "serve"], env=self.env(),
                                        stdout=out, stderr=subprocess.STDOUT, start_new_session=True)
        os.close(out)

    def stop(self):
        if self.process and self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
            try:
                self.process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        self.process = None

    def alive(self):
        return self.process is not None and self.process.poll() is None


class TlsApi:
    """Minimal HTTPS client: connects to the loopback listener, verifies the name."""

    def __init__(self, cafile, hostname=HOSTNAME):
        self.context = ssl.create_default_context(cafile=str(cafile))
        self.hostname = hostname
        self.cookies = {}
        self.csrf = None

    def request(self, method, path, body=None, headers=None, session=True):
        with socket.create_connection(("127.0.0.1", PORT), timeout=10) as raw:
            with self.context.wrap_socket(raw, server_hostname=self.hostname) as tls:
                values = {"Host": f"{HOSTNAME}:{PORT}", "Origin": ORIGIN, "Accept": "application/json",
                          "Connection": "close"}
                if session and self.cookies:
                    values["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
                if session and self.csrf:
                    values["X-CSRF-Token"] = self.csrf
                values.update(headers or {})
                payload = b""
                if body is not None:
                    payload = json.dumps(body).encode()
                    values["Content-Type"] = "application/json"
                values["Content-Length"] = str(len(payload))
                head = f"{method} {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in values.items()) + "\r\n"
                tls.sendall(head.encode() + payload)
                response = http.client.HTTPResponse(tls)
                response.begin()
                data = response.read()
                for header in response.msg.get_all("Set-Cookie") or []:
                    jar = http.cookies.SimpleCookie(header)
                    for key, morsel in jar.items():
                        self.cookies[key] = morsel.value
                try:
                    parsed = json.loads(data) if data else None
                except ValueError:
                    parsed = None
                return response.status, parsed

    def login(self, username, password):
        token = secrets.token_urlsafe(32)[:43]
        status, body = self.request("POST", "/api/v3/admin/session/login",
                                    {"username": username, "password": password},
                                    {"Cookie": f"bp_csrf={token}", "X-CSRF-Token": token}, session=False)
        if status != 200:
            code = body.get("error") if isinstance(body, dict) and isinstance(body.get("error"), str) else "no error code"
            raise Failure(f"operator login refused (status {status}, {code[:40]})")
        self.csrf = body["csrf_token"]
        return body


class GuestVM:
    """One disposable QEMU guest with its own overlay, ssh key and forwarded port."""

    def __init__(self, rehearsal, tag, ssh_port):
        self.r = rehearsal
        self.tag = tag
        self.ssh_port = ssh_port
        self.dir = rehearsal.dir / f"vm-{tag}"
        self.ssh_key = self.dir / "ssh-key"
        self.qemu_pid = None

    def ssh_options(self):
        return ["-i", str(self.ssh_key), "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=3", "-p", str(self.ssh_port)]

    def guest(self, *command, data=None, check=True, timeout=180):
        try:
            return run(["ssh", *self.ssh_options(), f"{GUEST_USER}@127.0.0.1", " ".join(map(shlex_quote, command))],
                       data=data, check=check, timeout=timeout)
        except Failure:
            # Guest command names only (never their stdin).
            raise Failure("guest command failed: " + " ".join(map(str, command))[:100]) from None

    def guest_helper(self, *command, data=None, check=True, timeout=180):
        return self.guest("sudo", "/usr/local/sbin/blindpass-p03-guest", *command, data=data, check=check, timeout=timeout)

    def boot(self):
        r = self.r
        self.dir.mkdir(mode=0o700)
        image = Path(os.environ.get("BLINDPASS_FLEET_GUEST_IMAGE", IMAGE_DEFAULT))
        expected = os.environ.get("BLINDPASS_FLEET_GUEST_IMAGE_SHA256", IMAGE_SHA_DEFAULT)
        if hashlib.sha256(image.read_bytes()).hexdigest() != expected:
            raise Failure("pinned guest image hash does not match")
        run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(self.ssh_key)])
        env = dict(os.environ, BLINDPASS_FLEET_GUEST_IMAGE=str(image), BLINDPASS_FLEET_GUEST_IMAGE_SHA256=expected,
                   BLINDPASS_FLEET_SSH_KEY=str(self.ssh_key), BLINDPASS_FLEET_GUEST_USER=GUEST_USER)
        image_dir = self.dir / "image"
        run([str(ROOT / "tests/fleet/provision-guest.sh"), "--output-dir", str(image_dir)], env=env)
        pidfile = self.dir / "qemu.pid"
        disk_gb = os.environ.get("BLINDPASS_P06_NODE_DISK_GB")
        if disk_gb:  # the managed-application task needs room for the browser, Grafana and the Node runtime
            run(["qemu-img", "resize", f"{image_dir}/guest-overlay.qcow2", f"{int(disk_gb)}G"])
        run(["qemu-system-x86_64", "-name", f"blindpass-p06-relay-{self.tag}", "-enable-kvm", "-cpu", "host",
             "-m", str(int(os.environ.get("BLINDPASS_P06_NODE_MEMORY_MB", "1536"))), "-smp", "2",
             "-drive", f"file={image_dir}/guest-overlay.qcow2,if=virtio,format=qcow2",
             "-drive", f"file={image_dir}/seed.iso,if=virtio,media=cdrom,readonly=on,format=raw",
             "-netdev", f"user,id=net0,hostfwd=tcp:127.0.0.1:{self.ssh_port}-:22", "-device", "virtio-net-pci,netdev=net0",
             "-display", "none", "-monitor", "none", "-serial", f"file:{self.dir}/serial.log",
             "-pidfile", str(pidfile), "-daemonize"])
        self.qemu_pid = int(pidfile.read_text())
        for _ in range(90):
            if run(["ssh", *self.ssh_options(), f"{GUEST_USER}@127.0.0.1", "true"], check=False).returncode == 0:
                break
            time.sleep(2)
        else:
            raise Failure("guest did not become reachable")
        self.guest("mkdir", "-m", "0700", "-p", "/tmp/p03")
        files = [BIN / "blindpass-broker", BIN / "blindpass-node", BIN / "blindpass-workload-client",
                 ROOT / "deploy/native/blindpass-broker.service", ROOT / "deploy/native/blindpass-node.service",
                 ROOT / "deploy/native/blindpass-node.sysusers", ROOT / "deploy/native/blindpass-workload.sysusers",
                 ROOT / "tests/fleet/p03-guest.sh", r.dir / "controller.crt"]
        run(["scp", *[("-P" if o == "-p" else o) for o in self.ssh_options()], *map(str, files),
             f"{GUEST_USER}@127.0.0.1:/tmp/p03/"])
        self.guest("sudo", "install", "-m", "0755", "/tmp/p03/p03-guest.sh", "/usr/local/sbin/blindpass-p03-guest")
        self.guest_helper("prepare", ORIGIN, timeout=300)

    def stop(self):
        if self.qemu_pid:
            try:
                os.kill(self.qemu_pid, signal.SIGTERM)
            except ProcessLookupError:
                pass


class Rehearsal:
    def __init__(self, args):
        self.args = args
        self.backend = getattr(args, "backend", None) or os.environ.get("BLINDPASS_P06_BACKEND", "sqlite")
        if self.backend not in ("sqlite", "postgres"):
            raise Failure("unknown controller backend")
        self.dir = Path(tempfile.mkdtemp(prefix="blindpass-p06-relay."))
        self.dir.chmod(0o700)
        self.authority = Authority()
        self.pg = PgStore(self) if self.backend == "postgres" else None
        self.tenant = "p06rr_tenant_" + secrets.token_hex(4)
        self.owner = "p06rr_owner_" + secrets.token_hex(4)
        self.controllers = []
        self.vm = GuestVM(self, "a", SSH_PORT)
        self.vms = [self.vm]
        self.api = None

    # ---- guest plumbing (guest A by default) ------------------------------
    def ssh_options(self):
        return self.vm.ssh_options()

    def guest(self, *command, data=None, check=True, timeout=180):
        return self.vm.guest(*command, data=data, check=check, timeout=timeout)

    def guest_helper(self, *command, data=None, check=True, timeout=180):
        return self.vm.guest_helper(*command, data=data, check=check, timeout=timeout)

    def boot_guest(self):
        self.vm.boot()

    def add_vm(self, tag, ssh_port):
        vm = GuestVM(self, tag, ssh_port)
        self.vms.append(vm)
        vm.boot()
        return vm

    # ---- PostgreSQL backend: the pinned toolkit lives in the controller image ----
    def toolkit_command(self, controller, args, check=True, timeout=600):
        """`backup create|verify` and `restore` need pg_dump/pg_restore/initdb (ADR 0011), which the
        host lacks. Run the product CLI from the toolkit image against the same files and database:
        the run directory is mounted at the same path and handed to the image's unprivileged uid for
        the duration of the call, then returned to the runner."""
        image = os.environ.get("BLINDPASS_P06_TOOLKIT_IMAGE", "blindpass-p06-controller:pkgrec")
        directory = str(self.dir)

        def chown(owner):
            run(["docker", "run", "--rm", "--user", "0", "--network", "none", "--entrypoint", "find",
                 "--mount", f"type=bind,src={directory},dst={directory}", image, directory,
                 "-path", f"{directory}/vm-*", "-prune", "-o", "-exec", "chown", owner, "{}", "+"], timeout=120)

        chown("10001:10001")
        try:
            command = ["docker", "run", "--rm", "--network", "host", "--user", "10001:10001", "--cap-drop", "ALL",
                       "--security-opt", "no-new-privileges", "--tmpfs", "/dev/shm:rw,size=1g,mode=1777",
                       "--mount", f"type=bind,src={directory},dst={directory}"]
            # The image defaults to a proxied, /data-backed controller; the harness controller is
            # direct-TLS and PostgreSQL-backed, so override both image defaults explicitly.
            values = {**controller.env(), "BLINDPASS_PROXY_REQUIRED": "0", "BLINDPASS_DATA_DIR": ""}
            for key, value in values.items():
                if key != "PATH":
                    command += ["-e", f"{key}={value}"]
            command += ["--entrypoint", "/usr/local/bin/blindpass-controller", image, *args]
            return run(command, check=check, timeout=timeout)
        finally:
            chown(f"{os.getuid()}:{os.getgid()}")

    # ---- controller-store reads (SQLite file or PostgreSQL schema) ---------
    def db_rows(self, controller, sql, params=()):
        if controller.database:
            return self.pg.rows(controller.database, sql, params)
        import sqlite3
        connection = sqlite3.connect(f"file:{controller.data / 'controller.db'}?mode=ro", uri=True)
        try:
            return connection.execute(sql, params).fetchall()
        finally:
            connection.close()

    # ---- host controller -------------------------------------------------
    def make_certificate(self, name="controller", subject=HOSTNAME):
        run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-quiet",
             "-keyout", str(self.dir / f"{name}.key"), "-out", str(self.dir / f"{name}.crt"),
             "-subj", f"/CN={subject}", "-addext", f"subjectAltName=DNS:{subject}"])
        (self.dir / f"{name}.key").chmod(0o600)
        (self.dir / f"{name}.crt").chmod(0o600)

    def prepare_controller_state(self, name):
        keys = self.dir / f"{name}-keys"
        data = self.dir / f"{name}-data"
        keys.mkdir(mode=0o700)
        if self.backend == "sqlite":
            data.mkdir(mode=0o700)
        else:
            data = None
        return keys, data

    def wait_ready(self, controller, expect=200, timeout=30):
        api = TlsApi(self.dir / f"{controller.certificate}.crt")
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if not controller.alive():
                raise Failure(f"{controller.name} exited early")
            try:
                status, _ = api.request("GET", "/readyz", session=False)
                if status == expect:
                    return
            except (OSError, ssl.SSLError, http.client.HTTPException):
                pass
            time.sleep(0.3)
        raise Failure(f"{controller.name} readiness {expect} not reached")

    def cleanup(self):
        for controller in self.controllers:
            controller.stop()
        for vm in self.vms:
            vm.stop()
        if os.environ.get("BLINDPASS_P06_KEEP_ARTIFACTS") != "1":
            if self.pg:
                self.pg.drop()
            self.authority.drop()
        if os.environ.get("BLINDPASS_P06_KEEP_ARTIFACTS") == "1":
            print(f"P06-RR kept artifacts in {self.dir}", file=sys.stderr)
        else:
            shutil.rmtree(self.dir, ignore_errors=True)


def shlex_quote(value):
    import shlex
    return shlex.quote(str(value))


STAGES = ["source", "enroll", "grant", "restore", "faults", "rebase", "relay"]
# The PostgreSQL rehearsal repeats the restore/relay path; the fault and rebase stages stay SQLite-only.
PG_STAGES = ["source", "enroll", "grant", "restore", "relay"]


def source_stage(r):
    r.make_certificate()
    r.api = TlsApi(r.dir / "controller.crt")
    r.authority.create()
    private_write(r.dir / "authority-url", r.authority.url())
    keys, data = r.prepare_controller_state("source")
    database = None
    if r.pg:
        r.pg.create_role()
        database = r.pg.create_database("source", schema=True)
        r.pg.url_file(database)
    r.source = Controller(r, "source", keys, data, database=database)
    r.controllers.append(r.source)
    run([str(BIN / "blindpass"), "keys", "init", "--directory", str(keys)])
    r.issuer = run([str(BIN / "blindpass"), "keys", "issuer-id", "--directory", str(keys)]).stdout.decode().strip()
    if not re.fullmatch(r"ed25519-[A-Za-z0-9_-]{43}", r.issuer):
        raise Failure("issuer id is malformed")
    variables = {"tenant": r.tenant, "owner": r.owner, "issuer": r.issuer}
    r.variables = variables
    r.authority.script("authority-register.sql", **variables)
    r.source.command("migrate")
    r.authority.script("authority-activate.sql", **variables)
    r.source.start()
    r.wait_ready(r.source)
    bootstrap = run([str(BIN / "blindpass"), "admin", "bootstrap", "--socket", str(r.source.admin_socket)]).stdout
    temporary = json.loads(bootstrap)["temporary_password"]
    r.canaries = [temporary]
    r.password = "P06-DUMMY-" + secrets.token_hex(12)
    r.canaries.append(r.password)
    r.api.login("admin", temporary)
    status, _ = r.api.request("POST", "/api/v3/admin/session/change-password",
                              {"current_password": temporary, "new_password": r.password})
    if status != 204:
        raise Failure("operator password change refused")
    r.api = TlsApi(r.dir / "controller.crt")
    body = r.api.login("admin", r.password)
    if body.get("must_change_password"):
        raise Failure("operator still must change password")
    passed("S1", "production controller (authority-backed, built-in TLS) serving; operator session established")


def enroll_stage(r):
    r.boot_guest()
    status, capabilities = r.api.request("GET", "/api/v3/capabilities", session=False)
    pub = capabilities["issuer_pub"]
    padded = pub + "=" * (-len(pub) % 4)
    import base64
    fingerprint = hashlib.sha256(base64.urlsafe_b64decode(padded)).hexdigest()
    status, enrollment = r.api.request("POST", "/api/v3/enrollments", {"name": "p06-relay"})
    if status not in (200, 201):
        raise Failure("enrollment create refused")
    r.node_id = enrollment["node_id"]
    r.canaries.append(enrollment["token"])
    output = r.guest_helper("enroll", ORIGIN, fingerprint, data=enrollment["token"].encode()).stdout.decode()
    found = re.search(r"fingerprint=([a-f0-9]{64}) status=submitted", output)
    if not found:
        raise Failure("node enrollment did not print its fingerprint")
    status, current = r.api.request("GET", f"/api/v3/enrollments/{enrollment['id']}")
    if status != 200 or current["fingerprint"] != found.group(1):
        raise Failure("controller and node fingerprints differ")
    try:
        status, body = r.api.request("POST", f"/api/v3/enrollments/{enrollment['id']}/approve",
                                     {"expected_fingerprint": found.group(1), "expected_version": current["version"]},
                                     {"If-Match": f'"{current["version"]}"'})
    except http.client.RemoteDisconnected:
        status, body = None, None
    if status != 200:
        phase = r.authority.scalar("SELECT phase||':'||epoch||':'||revision FROM blindpass_authority.recovery_authority")
        raise Failure(f"enrollment approval refused: status={status} body={body} authority={phase}")
    r.guest_helper("start-node")
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        status, node = r.api.request("GET", f"/api/v3/nodes/{r.node_id}")
        if status == 200 and node.get("status") == "online":
            break
        time.sleep(1)
    else:
        raise Failure("node did not come online")
    trusted = r.authority.scalar(f"SELECT count(*) FROM blindpass_authority.broker_trust WHERE node_id='{r.node_id}' AND state='active'")
    if trusted != "1":
        raise Failure("authority holds no active broker trust for the enrolled node")
    passed("S2", "real broker+node in a QEMU guest enrolled over verified HTTPS; node online; authority holds its broker trust")


def grant_stage(r):
    """One real consumed grant, so the broker's report carries a record the controller must map."""
    import base64
    suffix = secrets.token_hex(4)
    approver_password = session_password = "P06-DUMMY-" + secrets.token_hex(12)
    r.canaries.append(approver_password)
    status, approver = r.api.request("POST", "/api/v3/admin/operators",
                                     {"username": f"p06-approver-{suffix}", "display_name": "P06 approver",
                                      "role": "operator", "password": approver_password})
    if status not in (200, 201):
        raise Failure("approver operator was not created")
    approver_api = TlsApi(r.dir / "controller.crt")
    session = approver_api.login(f"p06-approver-{suffix}", approver_password)
    if session.get("must_change_password"):
        approver_password = "P06-DUMMY-" + secrets.token_hex(12)
        r.canaries.append(approver_password)
        status, _ = approver_api.request("POST", "/api/v3/admin/session/change-password",
                                         {"current_password": session_password, "new_password": approver_password})
        if status != 204:
            raise Failure("approver password change refused")
        approver_api = TlsApi(r.dir / "controller.crt")
        approver_api.login(f"p06-approver-{suffix}", approver_password)
    # The policy comes first: a workload registration binds the policy version current when it is created.
    status, policy = r.api.request("GET", "/api/v3/policies")
    status, _ = r.api.request("PUT", "/api/v3/policies", {
        "expected_version": policy["version"],
        "rules": [{"id": "p06rr-approve-noop-file", "action": "noop.marker", "mode": "file", "decision": "pending_approval",
                   "approval_required": True, "approver_ids": [approver["id"]], "max_ttl_seconds": 120}]},
        {"If-Match": f'"{policy["version"]}"'})
    if status != 200:
        raise Failure("policy was not updated")
    unit = f"blindpass-p03-p06rr-{suffix}.service"
    account = r.guest_helper("workload-account").stdout.decode().strip()
    if not re.fullmatch(r"uid:[1-9][0-9]*", account):
        raise Failure("guest returned a malformed workload account")
    status, workload = r.api.request("POST", "/api/v3/workloads", {
        "node_id": r.node_id, "name": f"p03-p06rr-{suffix}", "unit": unit, "account": account,
        "consumption_mode": "file", "local_ceiling_seconds": 120})
    if status not in (200, 201):
        raise Failure("workload was not registered")
    payload = base64.urlsafe_b64encode(json.dumps({"action": "noop.marker", "mode": "file", "purpose": "P06 relay rehearsal",
                                                   "resource_id": "P06-CANARY-RR", "ttl_seconds": 60},
                                                  separators=(",", ":")).encode()).decode().rstrip("=")
    r.guest_helper("--unit", unit, "configure-workload", r.node_id, workload["id"], payload)
    r.guest_helper("--unit", unit, "start-workload")
    request = r.guest_helper("--unit", unit, "wait-request").stdout.decode()
    found = re.search(r"event_key=([A-Za-z0-9_-]+)", request), re.search(r"invocation=([a-f0-9]{32})", request)
    if not all(found):
        raise Failure("workload request evidence is malformed")
    event_key, invocation = found[0].group(1), found[1].group(1)
    for _ in range(180):
        status, operation = r.api.request("POST", "/api/v3/operations", {
            "workload_id": workload["id"], "action": "noop.marker", "mode": "file", "purpose": "P06 relay rehearsal",
            "resource_id": "P06-CANARY-RR", "invocation_id": invocation, "ttl_seconds": 60, "broker_event_key": event_key},
            {"Idempotency-Key": "p06rr" + secrets.token_hex(16)})
        if status in (200, 201):
            break
        if status != 409:
            raise Failure("operation request refused")
        time.sleep(0.25)
    else:
        raise Failure("broker event was not accepted within the evidence window")
    status, approval = approver_api.request("GET", f"/api/v3/approvals/{operation['approval_id']}")
    status, _ = approver_api.request("POST", f"/api/v3/approvals/{operation['approval_id']}/approve", {
        "expected_status": "pending", "expected_version": approval["version"], "operation_ids": approval["operation_ids"]},
        {"Idempotency-Key": "p06rr" + secrets.token_hex(16), "If-Match": f'"{approval["version"]}"'})
    if status != 200:
        raise Failure("approval was refused")
    status, granted = r.api.request("GET", f"/api/v3/operations/{operation['id']}")
    if granted.get("status") != "granted" or not granted.get("grant_id"):
        raise Failure("operation was not granted")
    deadline = time.monotonic() + 30
    while True:  # the workload client is one-shot: deliver the grant file only after the broker applied the grant
        acked = any(json.loads(row[0]).get("kind") == "grant" and json.loads(row[0]).get("body", {}).get("id") == granted["grant_id"]
                    for row in r.db_rows(r.source, "SELECT envelope_json FROM node_inbox WHERE node_id=? AND acked_at IS NOT NULL", (r.node_id,)))
        if acked:
            if os.environ.get("BLINDPASS_P06_DEBUG") == "1":
                print("grant acknowledged at", time.strftime("%H:%M:%S", time.gmtime()), file=sys.stderr)
            break
        if time.monotonic() > deadline:
            raise Failure("broker did not acknowledge the grant")
        time.sleep(0.2)
    r.guest_helper("--unit", unit, "provide-grant", data=(granted["grant_id"] + "\n").encode())
    try:
        r.guest_helper("--unit", unit, "verify-workload", granted["grant_id"], operation["id"])
    except Failure:
        if os.environ.get("BLINDPASS_P06_DEBUG") == "1":
            for service in ("blindpass-node", "blindpass-broker"):
                text = r.guest("sudo", "journalctl", "-u", service, "-n", "300", "-o", "short-precise", "--no-pager",
                               check=False).stdout.decode(errors="replace")
                print("\n".join(l for l in text.splitlines() if "identity peer" not in l)[-3000:], file=sys.stderr)
            print(r.guest("sudo", "cat", "/var/lib/blindpass/broker/pending-node-events.jsonl", check=False).stdout.decode(errors="replace")[-1200:], file=sys.stderr)
            print("\n".join(l[:230] for l in r.source.log.read_text().splitlines() if '"200 OK"' not in l)[-3000:], file=sys.stderr)
        raise
    r.guest_helper("--unit", unit, "wait-outbox-empty")
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        status, done = r.api.request("GET", f"/api/v3/operations/{operation['id']}")
        if done.get("status") == "completed":
            break
        time.sleep(0.5)
    else:
        raise Failure("operation did not complete")
    r.grant_id = granted["grant_id"]
    r.operation_id = operation["id"]
    passed("S2b", "one real grant issued, approved by a second operator and consumed by a workload in the guest; controller operation completed")


def fence_and_stop(r, controller):
    r.authority.script("authority-fence.sql", **r.variables)
    controller.stop()


def provision_custody(r):
    """ADR 0013 role credentials: signing credential plus recipient certificate seal, the
    recipient key plus the signer certificate open. One test host holds all four files."""
    r.signing, r.signing_cert = r.dir / "backup-signing.pem", r.dir / "backup-signing-certificate.pem"
    r.recipient, r.recipient_cert = r.dir / "backup-recipient.pem", r.dir / "backup-recipient-certificate.pem"
    r.source.command("backup", "key-init", "--role", "signing", "--output", str(r.signing),
                     "--certificate-output", str(r.signing_cert))
    r.source.command("backup", "key-init", "--role", "recipient", "--output", str(r.recipient),
                     "--certificate-output", str(r.recipient_cert))


def seal_args(r):
    return ["--signing-credential-file", str(r.signing), "--recipient-certificate-file", str(r.recipient_cert)]


def open_args(r):
    return ["--recipient-key-file", str(r.recipient), "--signing-certificate-file", str(r.signing_cert)]


def reserve_and_restore(r, name):
    """Operator steps between a fenced record and a serving recovering controller."""
    revision = r.authority.scalar(f"SELECT revision FROM blindpass_authority.recovery_authority WHERE tenant_id='{r.tenant}'")
    reserved = r.authority.scalar(
        f"SELECT epoch||':'||phase FROM blindpass_authority.reserve_recovery('{r.tenant}','{r.issuer}','{r.owner}',{revision},1)")
    if not reserved.endswith(":recovering"):
        raise Failure("authority did not reserve recovery")
    epoch = int(reserved.split(":")[0])
    destination = r.dir / name
    database, target = None, []
    if r.pg:
        database = r.pg.create_database(name, schema=False)  # an empty target: pg_restore creates the schema
        target = ["--database-url-file", str(r.pg.url_file(database))]
    receipt = r.source.command("restore", "--archive", str(r.archive), *open_args(r), *target,
                               "--destination", str(destination), "--authority-url-file", str(r.dir / "authority-url"),
                               "--tenant-id", r.tenant, "--owner-id", r.owner, "--recovery-id", f"p06rr_{name}",
                               timeout=300).stdout.decode()
    receipt = json.loads(receipt.strip().splitlines()[-1])
    if receipt.get("phase") != "recovery_required" or receipt.get("activation_permitted") is not False:
        raise Failure("restore receipt is not fenced")
    controller = Controller(r, name, destination / "keys", None if r.pg else destination / "data", database=database)
    r.controllers.append(controller)
    controller.start()
    r.wait_ready(controller, expect=503)
    for path in ("/api/v3/capabilities", "/api/auth/me", "/"):
        status, _ = r.api.request("GET", path, session=False)
        if status != 503:
            raise Failure("ordinary route reopened on the recovering controller")
    r.restored = controller
    r.destination = destination
    return epoch


def restore_stage(r):
    provision_custody(r)
    backups = r.dir / "backups"
    backups.mkdir(mode=0o700)
    r.source.command("backup", "create", "--output", str(backups), *seal_args(r), timeout=300)
    archives = sorted(backups.rglob("*.bpbackup"))
    if len(archives) != 1:
        raise Failure("backup create did not publish exactly one archive")
    r.archive = archives[0]
    fence_and_stop(r, r.source)
    epoch = reserve_and_restore(r, "restored")
    passed("S3", f"authenticated backup restored under a recovering authority record (epoch {epoch}); controller serving fenced 503")


GUEST_CONTROL = r"""
import json, socket, ssl, sys, time, urllib.request

SOCKET = "/run/blindpass/control.sock"


def control(payload, wait=5.0):
    sock = socket.socket(socket.AF_UNIX)
    sock.settimeout(wait)
    sock.connect(SOCKET)
    out = b""
    try:
        sock.sendall(payload)
        sock.shutdown(socket.SHUT_WR)
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            out += chunk
    except (ConnectionResetError, BrokenPipeError, socket.timeout):
        # The broker closing on a bad frame is a refusal, not a result.
        pass
    sock.close()
    return out


def framed(response, tag):
    head, _, body = response.partition(b"\n")
    assert head.startswith(tag.encode() + b" "), head[:40]
    assert int(head.split()[1]) == len(body)
    return body


def refused(response):
    return response[:3] == b"ERR" or response == b""


mode = sys.argv[1]
if mode == "expire":
    challenge = json.loads(framed(control(b"RECOVERY_CHALLENGE\n"), "RECOVERY_CHALLENGE"))
    request = json.dumps({"version": 1, "node_id": challenge["node_id"],
                          "node_key_version": challenge["node_key_version"],
                          "broker_challenge": challenge["broker_challenge"]}, separators=(",", ":"), sort_keys=True).encode()
    http = urllib.request.Request("https://p03-controller:8443/api/recovery/request", data=request,
                                  headers={"Content-Type": "application/json"}, method="POST")
    signed = urllib.request.urlopen(http, timeout=10, context=ssl.create_default_context()).read()
    time.sleep(float(sys.argv[2]))
    reply = control(b"RECOVERY_REPORT %d\n" % len(signed) + signed)
    print(json.dumps({"controller_signed_request": True, "broker_refused": refused(reply),
                      "broker_returned_page": reply.startswith(b"RECOVERY_REPORT ")}))
elif mode == "malformed":
    cases = {
        "huge_length": b"RECOVERY_REPORT 99999999\n{}",
        "short_body": b"RECOVERY_REPORT 40\n{}",
        "not_json": b"RECOVERY_REPORT 12\nnot json here",
        "leading_zero": b"RECOVERY_REPORT 012\n" + b"x" * 12,
        "oversized_body": b"RECOVERY_REPORT 70000\n" + b"x" * 70000,
        "unknown_command": b"RECOVERY_EXPORT_EVERYTHING\n",
        "forged_request": b"RECOVERY_REPORT 2\n{}",
    }
    print(json.dumps({name: refused(control(payload)) for name, payload in cases.items()}))
"""


def snapshot(r):
    """Durable recovery state that a failed relay must leave unchanged."""
    reports = r.db_rows(r.restored, "SELECT node_id,state FROM controller_recovery_reports ORDER BY node_id")
    nodes = r.db_rows(r.restored, "SELECT node_id,state FROM controller_recovery_nodes ORDER BY node_id")
    challenges = r.authority.scalar("SELECT coalesce(string_agg(node_id||':'||state||':'||next_page||':'||consumed,','),'') FROM blindpass_authority.recovery_challenges")
    ledger = r.authority.scalar("SELECT phase||':'||epoch||':'||revision FROM blindpass_authority.recovery_authority")
    return {"reports": reports, "nodes": nodes, "challenges": challenges, "ledger": ledger}


def sqlite_rows(r, sql, params=()):
    return r.db_rows(r.restored, sql, params)


def relay_command(r, controller=ORIGIN, timeout=60, vm=None):
    return (vm or r.vm).guest("sudo", "-u", "blindpass-node", "/usr/libexec/blindpass-node", "recovery-relay",
                   "--controller", controller, check=False, timeout=timeout)


def relay_fails_closed(r, label, controller=ORIGIN, timeout=60):
    before = snapshot(r)
    result = relay_command(r, controller, timeout)
    if result.returncode == 0 or b"recovery_relay state=" in result.stdout:
        raise Failure(f"{label}: relay did not fail closed")
    message = result.stderr.decode()
    if "blindpass-node:" not in message or any(word in message for word in ("PRIVATE", "token", "Bearer")):
        raise Failure(f"{label}: relay error is not a fixed, secret-free message")
    if snapshot(r) != before:
        raise Failure(f"{label}: a failed relay changed durable recovery state")
    return message.strip().splitlines()[-1][:120]


def stop_and_start_restored(r, certificate="controller"):
    r.restored.stop()
    r.restored.certificate = certificate
    r.restored.start()


def faults_stage(r):
    baseline = snapshot(r)
    if baseline["challenges"] != "" or baseline["reports"]:
        raise Failure("fault stage must start before any report is collected")
    # RR04-a: a name the certificate does not cover.
    r.guest("sudo", "sh", "-c", "echo '10.0.2.2 p06-other' >> /etc/hosts")
    curl = r.guest("sh", "-c", "curl --silent --show-error https://p06-other:8443/readyz >/dev/null 2>&1; echo $?").stdout.decode().strip()
    if curl != "60":
        raise Failure("control: the guest did not reject the mismatched name as a certificate failure")
    message = relay_fails_closed(r, "tls-name", "https://p06-other:8443")
    passed("F1", f"relay refuses a certificate that does not cover the requested name ({message!r}); durable state unchanged")
    # RR04-b: same name, certificate the guest does not trust; then a controller restart.
    r.make_certificate("untrusted")
    stop_and_start_restored(r, "untrusted")
    r.wait_ready(r.restored, expect=503)
    curl = r.guest("sh", "-c", "curl --silent --show-error https://p03-controller:8443/readyz >/dev/null 2>&1; echo $?").stdout.decode().strip()
    if curl != "60":
        raise Failure("control: the guest did not reject the untrusted certificate as a certificate failure")
    message = relay_fails_closed(r, "tls-untrusted")
    stop_and_start_restored(r, "controller")
    r.wait_ready(r.restored, expect=503)
    passed("F2", f"relay refuses an untrusted certificate for the right name ({message!r}); durable state unchanged; restored controller restarted under the recovering record")
    # RR04-c: slow controller (stopped process): bounded, no state change.
    os.kill(r.restored.process.pid, signal.SIGSTOP)
    try:
        started = time.monotonic()
        message = relay_fails_closed(r, "slow-controller", timeout=90)
        elapsed = time.monotonic() - started
    finally:
        os.kill(r.restored.process.pid, signal.SIGCONT)
    if elapsed > 40:
        raise Failure("relay exceeded its bounded deadline against a stalled controller")
    r.wait_ready(r.restored, expect=503)
    passed("F3", f"stalled controller: relay gave up in {elapsed:.1f}s ({message!r}); durable state unchanged")
    # RR04-d: expired broker nonce with a real controller-signed request. The control for
    # these frames is L1, which sends the identical exchange without a delay.
    out = r.guest("sudo", "-u", "blindpass-node", "python3", "-", "expire", "35", data=GUEST_CONTROL.encode(), timeout=120)
    outcome = json.loads(out.stdout.decode().strip().splitlines()[-1])
    if not (outcome["controller_signed_request"] and outcome["broker_refused"] and not outcome["broker_returned_page"]):
        raise Failure("broker accepted a controller request after its nonce expired")
    state = snapshot(r)
    if state["reports"] or "collecting" not in state["challenges"]:
        raise Failure("expired-nonce attempt left an unexpected durable state")
    passed("F4", f"real broker refused a real controller-signed request after its 30s nonce expired; protected challenge stays collecting (authority: {state['challenges']})")
    # RR04-e: malformed, oversized, partial and unknown frames straight at the broker.
    out = r.guest("sudo", "-u", "blindpass-node", "sh", "-c", "python3 - malformed 2>&1", data=GUEST_CONTROL.encode(), check=False, timeout=120)
    results = json.loads(out.stdout.decode().strip().splitlines()[-1])
    if not all(results.values()):
        raise Failure(f"broker accepted a malformed control frame: {[k for k, v in results.items() if not v]}")
    r.guest("systemctl", "is-active", "--quiet", "blindpass-broker.service")
    r.guest("sudo", "-u", "blindpass-node", "/usr/libexec/blindpass-node", "status")
    if snapshot(r) != state:
        raise Failure("malformed frames changed durable recovery state")
    passed("F5", f"{len(results)} malformed/oversized/partial/unknown frames refused by the real broker; service active; state unchanged")
    # RR04-f: broker restart (protected identity survives, transient nonce is gone).
    r.guest("sudo", "systemctl", "restart", "blindpass-broker.service")
    time.sleep(3)
    r.guest("sudo", "systemctl", "is-active", "--quiet", "blindpass-broker.service")
    passed("F6", "broker restarted; protected identity intact")


def rebase_stage(r):
    """A page the broker exported but the controller never received (lost response)."""
    out = r.guest("sudo", "-u", "blindpass-node", "python3", "-", "expire", "0", data=GUEST_CONTROL.encode(), timeout=120)
    fresh = json.loads(out.stdout.decode().strip().splitlines()[-1])
    if not (fresh["controller_signed_request"] and fresh["broker_returned_page"] and not fresh["broker_refused"]):
        raise Failure("control: the real broker did not return a page for a fresh controller-signed request")
    before = snapshot(r)
    result = relay_command(r)
    text = result.stdout.decode().strip()
    if result.returncode != 0 or text != "recovery_relay state=rebase_required pages=1 activation_permitted=false":
        raise Failure(f"expected rebase_required after a lost page, got exit={result.returncode} stdout={text!r}")
    state = snapshot(r)
    if state["reports"] or ":rebase_required:" not in state["challenges"] or state["challenges"].endswith(":true"):
        raise Failure("rebase outcome left an unexpected durable state")
    if not state["ledger"].startswith("recovering:") or any(row[1] != "quarantined" for row in state["nodes"]):
        raise Failure("rebase outcome changed authority phase or node quarantine")
    again = relay_command(r).stdout.decode().strip()
    if "state=rebase_required" not in again:
        raise Failure("a repeated relay did not stay rebase_required")
    passed("L1", f"after a page the broker exported but the controller never received, collecting again reports rebase_required (authority: {state['challenges']}); no report recorded, nodes stay quarantined, ledger {state['ledger']}")
    # A fresh, higher reservation and a new restore are the only way forward.
    fence_and_stop(r, r.restored)
    epoch = reserve_and_restore(r, "restored_b")
    if epoch <= int(before["ledger"].split(":")[1]):
        raise Failure("the new reservation is not higher")
    passed("L2", f"fenced, reserved a higher epoch ({epoch}) and restored the same archive into a new destination; controller serving fenced 503")


def relay_stage(r):
    result = relay_command(r)
    out = result.stdout.decode().strip()
    if result.returncode != 0 or out != "recovery_relay state=covered pages=1 activation_permitted=false":
        raise Failure(f"relay did not complete: exit={result.returncode} stdout={out!r} stderr={result.stderr.decode()[-200:]!r}")
    state = snapshot(r)
    if len(state["reports"]) != 1 or state["reports"][0][1] != "quarantined":
        raise Failure("controller did not record exactly one quarantined node report")
    if "covered" not in state["challenges"] or not state["ledger"].startswith("recovering:"):
        raise Failure("authority challenge or ledger state is wrong after the relay")
    if any(row[1] != "quarantined" for row in state["nodes"]):
        raise Failure("a node left quarantine without activation")
    mapped = sqlite_rows(r, "SELECT grant_id,operation_id,mapping FROM controller_recovery_intents")
    if mapped != [(r.grant_id, r.operation_id, "matched")]:
        raise Failure(f"the consumed grant was not mapped exactly: {mapped}")
    uncertain = sqlite_rows(r, "SELECT state FROM controller_recovery_operations WHERE operation_id=?", (r.operation_id,))
    if uncertain != [("uncertain",)]:
        raise Failure("the consumed operation was not left uncertain by recovery")
    for path in ("/api/v3/capabilities", "/api/auth/me", "/api/v3/nodes", "/"):
        status, _ = r.api.request("GET", path, session=False)
        if status != 503:
            raise Failure("ordinary route reopened after the relay")
    status, body = r.api.request("GET", "/readyz", session=False)
    if status != 503:
        raise Failure("recovering controller became ready")
    passed("R1", f"{out} (recovery epoch {state['ledger'].split(':')[1]}); one quarantined node report recorded; the consumed grant mapped exactly (matched) to its now-uncertain operation; authority challenge covered; ledger {state['ledger']}; ordinary routes 503")
    # A repeat is idempotent and still cannot activate.
    again = relay_command(r)
    text = again.stdout.decode().strip()
    if again.returncode != 0 or "state=covered" not in text or "activation_permitted=false" not in text:
        raise Failure("repeat relay was not an idempotent covered status")
    if snapshot(r) != state:
        raise Failure("repeat relay changed durable state")
    passed("R2", f"repeat relay idempotent ({text})")
    scan_logs(r)


def controller_log_expectation(controller):
    """(minimum bytes, required content) for a controller's log. A controller that served has plenty to
    show. A stale one (fenced, retired or superseded source) only ever logs its refusal to start, one
    short line that must still be that refusal, so a truncated or wrong capture cannot pass."""
    if controller.name.startswith("stale"):
        return 32, [b'"startup_failed"']
    return 256, []


def scan_logs(r):
    secrets_to_find = [*r.canaries, r.authority.owner_password, r.authority.runtime_password]
    if len(r.canaries) < 4 or any(len(value) < 12 for value in secrets_to_find):
        raise Failure("the log scan has no canaries to look for")
    journal = r.guest("sudo", "journalctl", "-u", "blindpass-broker.service", "-u", "blindpass-node.service",
                      "--no-pager", "-o", "cat", timeout=60).stdout.decode()
    # Fail closed: an empty, missing or truncated capture is a failure, and every scan is first shown
    # to see a planted token (P07-I04, finding F2).
    try:
        for index, controller in enumerate(r.controllers):
            minimum, require = controller_log_expectation(controller)
            canary_log_scan.assert_log_clean(f"P06-R3 controller {index} log", canary_log_scan.read_log(controller.log),
                                             secrets_to_find, markers=["PRIVATE KEY"], min_bytes=minimum, require=require)
        canary_log_scan.assert_log_clean("P06-R3 guest broker and node journal", journal, secrets_to_find,
                                         markers=["PRIVATE KEY"], min_bytes=32)
    except canary_log_scan.LogScanError as error:
        raise Failure(str(error)) from None
    passed("R3", "controller and guest broker/node logs contain no operator or approver password, bootstrap password, enrollment token, authority password or PEM private key")


def unsupported(reason):
    print(f"P06-RR-UNSUPPORTED {reason}", file=sys.stderr)
    return 78


def preflight(backend="sqlite"):
    if os.geteuid() == 0:
        return unsupported("run as the runner owner, not through sudo")
    for tool in ("docker", "qemu-system-x86_64", "qemu-img", "ssh", "scp", "ssh-keygen", "openssl", "cloud-localds"):
        if shutil.which(tool) is None:
            return unsupported(f"{tool} is unavailable in PATH")
    if not (os.access("/dev/kvm", os.R_OK) and os.access("/dev/kvm", os.W_OK)):
        return unsupported("/dev/kvm is unavailable or inaccessible")
    for binary in ("blindpass-controller", "blindpass", "blindpass-broker", "blindpass-node", "blindpass-workload-client"):
        if not (BIN / binary).is_file():
            return unsupported(f"{binary} is not built; run: cargo build --release -p blindpass-controller -p blindpass-cli -p blindpass-broker -p blindpass-node")
    image = Path(os.environ.get("BLINDPASS_FLEET_GUEST_IMAGE", IMAGE_DEFAULT))
    if not image.is_file():
        return unsupported("pinned guest image is missing")
    if backend == "postgres":
        image = os.environ.get("BLINDPASS_P06_TOOLKIT_IMAGE", "blindpass-p06-controller:pkgrec")
        if run(["docker", "image", "inspect", image], check=False).returncode != 0:
            return unsupported(f"toolkit image {image} is missing (the host has no pinned PGDG toolkit)")
    probe = run(["docker", "exec", PG_CONTAINER, "pg_isready", "-U", "blindpass"], check=False)
    if probe.returncode != 0:
        return unsupported(f"PostgreSQL fixture container {PG_CONTAINER} is not ready")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--until", choices=STAGES, default=STAGES[-1])
    parser.add_argument("--backend", choices=("sqlite", "postgres"), default=os.environ.get("BLINDPASS_P06_BACKEND", "sqlite"))
    args = parser.parse_args()
    blocked = preflight(args.backend)
    if blocked:
        return blocked
    r = Rehearsal(args)
    stages = PG_STAGES if r.backend == "postgres" else STAGES
    try:
        for stage in stages:
            globals()[f"{stage}_stage"](r)
            if stage == args.until:
                break
        return 0
    except (Failure, OSError, ssl.SSLError, http.client.HTTPException, KeyError, ValueError) as error:
        print(f"P06-RR FAIL {type(error).__name__}: {error}", file=sys.stderr)
        for controller in r.controllers:
            if controller.log.exists():
                print(f"--- {controller.name} log tail", file=sys.stderr)
                print(controller.log.read_text()[-1500:], file=sys.stderr)
        return 1
    finally:
        r.cleanup()


if __name__ == "__main__":
    sys.exit(main())
