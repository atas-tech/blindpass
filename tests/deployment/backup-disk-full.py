#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""P06-B06: actual ENOSPC in a private mount namespace; no host mount changes."""
import argparse
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time


def checked(argv, *, env=None, timeout=20):
    started = time.monotonic()
    result = subprocess.run(argv, env=env, capture_output=True, timeout=timeout)
    if time.monotonic() - started >= timeout:
        raise RuntimeError("observed command deadline exceeded")
    return result


def exhausted_phase(arguments, env, output, phase):
    """Observe actual tool output growth before accepting a phase failure."""
    member={"capture":"database.sqlite", "encryption":"encrypted.der", "verification":"verified.tar"}[phase]
    minimum=16384 if phase=="capture" else 1024*1024
    started=time.monotonic(); observed=False
    child=subprocess.Popen(arguments,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    try:
        while child.poll() is None:
            for path in output.rglob(member):
                try: observed=observed or path.stat().st_size>minimum
                except FileNotFoundError: pass  # Ordinary job cleanup can race observation.
            if time.monotonic()-started>=20:
                raise RuntimeError("disk-full phase exceeded deadline")
            time.sleep(0.001)
        stdout,stderr=child.communicate(timeout=max(0.001,20-(time.monotonic()-started)))
        if time.monotonic()-started>=20 or not observed:
            raise RuntimeError("actual disk-full phase progress was not observed")
        return subprocess.CompletedProcess(arguments,child.returncode,stdout,stderr)
    finally:
        if child.poll() is None:
            child.kill()
        child.wait()


def namespace(root, controller, phase):
    # The outer driver maps only its non-root UID; refuse ordinary host root.
    uid_map = Path("/proc/self/uid_map").read_text().split()
    if os.geteuid() != 0 or uid_map[0] != "0" or uid_map[1] == "0" or uid_map[2] != "1":
        raise RuntimeError("disposable mapped user namespace required")
    output = root / "output"
    # Encryption first retains the complete snapshot and canonical archive;
    # verification first retains the authenticated envelope before decryption.
    # These quotas exhaust the filesystem at the named actual tool phase.
    quota={"capture":"1m", "encryption":"20m", "verification":"12m"}[phase]
    mount = checked([
        "/usr/bin/mount", "-t", "tmpfs", "-o", "size="+quota+",mode=0700,nosuid,nodev,noexec",
        "none", str(output),
    ])
    if mount.returncode:
        raise RuntimeError("private tiny filesystem mount failed")
    try:
        env = {
            "BLINDPASS_KEYS_DIR": str(root / "keys"),
            "BLINDPASS_DATA_DIR": str(root / "data"),
            "BLINDPASS_PUBLIC_URL": "https://controller.p06.invalid",
            "BLINDPASS_UI_BASE_URL": "https://controller.p06.invalid",
        }
        if phase=="verification":
            arguments=[str(controller),"backup","verify","--archive",str(root/"complete"/"archive.bpbackup"),
                       "--work-directory",str(output),"--recovery-key-file",str(root/"recovery.pem")]
        else:
            arguments=[str(controller),"backup","create","--output",str(output),
                       "--recovery-key-file",str(root/"recovery.pem")]
        result = exhausted_phase(arguments,env,output,phase)
        if result.returncode == 0:
            raise RuntimeError("backup phase succeeded despite insufficient filesystem space")
        # Require the actual phase failure, rather than a configuration/tool failure
        # that never exercises ENOSPC. No arbitrary stderr is printed.
        expected=b"SQLite snapshot capture or validation failed" if phase=="capture" else b"backup cryptographic operation failed"
        if expected not in result.stderr:
            raise RuntimeError("did not reach the expected disk-full phase failure")
        if list(output.iterdir()):
            raise RuntimeError("failed phase retained partial staging or published a backup")
        with sqlite3.connect(root / "data" / "controller.db") as source:
            length = source.execute("SELECT length(dummy) FROM disk_full_payload WHERE id=1").fetchone()[0]
            integrity = source.execute("PRAGMA integrity_check").fetchone()[0]
        if length != 8 * 1024 * 1024 or integrity != "ok":
            raise RuntimeError("failed phase changed or damaged source data")
        print(json.dumps({"scenario": "P06-B06", "phase":phase, "disk_full": "passed", "source_intact": True, "partial_publication": False}))
    finally:
        if checked(["/usr/bin/umount", str(output)]).returncode:
            raise RuntimeError("private filesystem teardown failed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--controller", type=Path, default=Path("target/debug/blindpass-controller"))
    parser.add_argument("--phase", choices=["capture","encryption","verification","all"], default="all")
    parser.add_argument("--namespace-fixture", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    controller = args.controller.resolve(strict=True)
    if args.namespace_fixture:
        namespace(args.namespace_fixture.resolve(strict=True), controller, args.phase)
        return
    if os.geteuid() == 0:
        raise RuntimeError("run the outer test as a non-root user")
    with tempfile.TemporaryDirectory(prefix="blindpass-p06-enospc-") as temporary:
        root = Path(temporary)
        for name in ["keys", "data", "output", "complete"]:
            (root / name).mkdir(mode=0o700)
        for name in ["root-secret", "agent-jwt-secret", "issuer-key"]:
            with (root / "keys" / name).open("xb") as key:
                os.chmod(key.name, 0o600)
                key.write(os.urandom(32))
        env = {
            "BLINDPASS_KEYS_DIR": str(root / "keys"), "BLINDPASS_DATA_DIR": str(root / "data"),
            "BLINDPASS_PUBLIC_URL": "https://controller.p06.invalid",
            "BLINDPASS_UI_BASE_URL": "https://controller.p06.invalid",
        }
        if checked([str(controller), "migrate"], env=env).returncode:
            raise RuntimeError("explicit fixture migration failed")
        with sqlite3.connect(root / "data" / "controller.db") as source:
            source.execute("CREATE TABLE disk_full_payload (id INTEGER PRIMARY KEY, dummy BLOB NOT NULL)")
            source.execute("INSERT INTO disk_full_payload VALUES (1, zeroblob(8388608))")
        if checked([str(controller), "backup", "key-init", "--output", str(root / "recovery.pem")]).returncode:
            raise RuntimeError("explicit fixture recovery key creation failed")
        if args.phase in ["all","verification"]:
            result=checked([str(controller),"backup","create","--output",str(root/"complete"),
                            "--recovery-key-file",str(root/"recovery.pem")],env=env)
            if result.returncode or json.loads(result.stdout).get("verified") is not True:
                raise RuntimeError("complete verification fixture creation failed")
            (root/"complete"/json.loads(result.stdout)["backup"]).rename(root/"complete"/"archive.bpbackup")
        for phase in ["capture","encryption","verification"] if args.phase=="all" else [args.phase]:
            result = checked([
                "/usr/bin/unshare", "--user", "--map-root-user", "--mount", "--propagation", "private",
                sys.executable, str(Path(__file__).resolve()), "--controller", str(controller),
                "--namespace-fixture", str(root), "--phase", phase,
            ], timeout=40)
            if result.returncode:
                raise RuntimeError("isolated "+phase+" disk-full gate failed; no private diagnostics emitted")
            print(result.stdout.decode().strip(),flush=True)


if __name__ == "__main__":
    main()
