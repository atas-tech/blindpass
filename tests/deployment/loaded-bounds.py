#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Run a deployment harness while the host is saturated.

CPU burners (default 2x the logical CPUs, nice 0) and a bounded disk writer run
for the whole child run. The child keeps its own bounds (compose-up.py enforces
15 s controller readiness and Docker health), so a pass means the bound held
under this load; the load shape is printed with the child's own PASS lines.
Usage: loaded-bounds.py [--factor N] [--disk-mib N] -- <command...>
"""
import argparse, os, signal, subprocess, sys, tempfile, time


def burner():
    while True:
        pass


def disk_writer(directory, mib):
    block = os.urandom(1 << 20)
    path = os.path.join(directory, "load.bin")
    while True:
        with open(path, "wb") as handle:
            for _ in range(mib):
                handle.write(block)
            handle.flush()
            os.fsync(handle.fileno())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--factor", type=float, default=2.0)
    parser.add_argument("--disk-mib", type=int, default=256)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("no command")
    cpus = os.cpu_count() or 1
    count = max(1, int(cpus * args.factor))
    children = []
    with tempfile.TemporaryDirectory(prefix="bp-load-") as directory:
        try:
            for _ in range(count):
                pid = os.fork()
                if pid == 0:
                    signal.signal(signal.SIGTERM, signal.SIG_DFL)
                    burner()
                children.append(pid)
            pid = os.fork()
            if pid == 0:
                signal.signal(signal.SIGTERM, signal.SIG_DFL)
                disk_writer(directory, args.disk_mib)
            children.append(pid)
            time.sleep(3)
            load = os.getloadavg()[0]
            print(f"LOAD cpus={cpus} burners={count} disk_mib={args.disk_mib} load1={load:.1f}", flush=True)
            result = subprocess.run(command).returncode
            print(f"LOAD end load1={os.getloadavg()[0]:.1f} exit={result}", flush=True)
            return result
        finally:
            for pid in children:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            for pid in children:
                try:
                    os.waitpid(pid, 0)
                except ChildProcessError:
                    pass


if __name__ == "__main__":
    sys.exit(main())
