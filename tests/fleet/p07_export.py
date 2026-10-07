#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""P07-I04: opt-in evidence export for the shell fleet harnesses (standard library only).

A thin command line over tests/deployment/canary_log_scan.py. When the environment variable P07_RUN
names a directory, a harness can hand it log files, journals and state dumps (`file`) and the
generated secrets it created (`bytes-canary`, `text-canary`, `json-canary`, `secret-lines`) so that
scripts/tests/canary-scan.sh can look again offline. Without P07_RUN every command does nothing and
exits 0, so a default harness run is unchanged.

Fail-closed rules: a missing, unreadable or empty input to `file`, and a canary command that finds
no value the offline scanner can use, exit 1. Nothing here ever prints a value, only counts.
Exit status: 0 done (or no P07_RUN), 1 could not export or register, 2 usage.
"""
import base64
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'deployment'))
import canary_log_scan as scan  # noqa: E402

USAGE = (
    'usage: p07_export.py file KIND LABEL PATH\n'
    '       p07_export.py bytes-canary PATH        (raw secret bytes: hex, base64, base64url)\n'
    '       p07_export.py text-canary PATH         (one single-line secret)\n'
    '       p07_export.py json-canary PATH [--skip SUBSTRING ...]   (every string leaf)\n'
    '       p07_export.py secret-lines PATH        (values after a leading "secret ")\n'
)


class Failure(Exception):
    pass


def fail(message):
    raise Failure(message)


def read(path):
    try:
        return scan.read_log(path)
    except scan.LogScanError as error:
        raise Failure(str(error)) from None


def register(values, label):
    values = [bytes(value) for value in values]
    usable = [value for value in values if scan._usable_offline(value)]
    if not usable:
        fail(f'{label}: no value the offline scanner can use (each needs {scan.OFFLINE_MIN_BYTES}+ bytes, '
             f'{scan.OFFLINE_MIN_DISTINCT}+ distinct, one line)')
    counts = scan.register_canaries(usable)
    print(f'{label}: {len(usable)} usable, {counts["registered"]} newly registered, '
          f'{len(values) - len(usable)} unusable')


def command_file(args):
    if len(args) != 3:
        raise SystemExit(usage())
    kind, label, path = args
    data = read(path)
    if not data.strip():
        fail(f'{label}: the file is empty; a scan of nothing proves nothing')
    target = scan.export(label, data, kind=kind)
    print(f'{label}: exported {len(data)} bytes to {kind}/{target.name}')


def command_bytes_canary(args):
    if len(args) != 1:
        raise SystemExit(usage())
    secret = read(args[0])
    if not secret:
        fail('bytes-canary: the file is empty')
    values = [secret.hex().encode(), base64.b64encode(secret), base64.urlsafe_b64encode(secret).rstrip(b'=')]
    values.append(secret)  # the raw bytes too; register() drops it when it is not a single usable line
    register(values, 'bytes-canary')


def command_text_canary(args):
    if len(args) != 1:
        raise SystemExit(usage())
    text = read(args[0]).rstrip(b'\r\n')
    register([text], 'text-canary')


def leaves(value, path=()):
    if isinstance(value, dict):
        for key, child in value.items():
            yield from leaves(child, path + (str(key),))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from leaves(child, path + (str(index),))
    elif isinstance(value, str):
        yield path, value


def command_json_canary(args):
    if not args:
        raise SystemExit(usage())
    path, rest = args[0], args[1:]
    skips = []
    while rest:
        if rest[0] != '--skip' or len(rest) < 2:
            raise SystemExit(usage())
        skips.append(rest[1].lower())
        rest = rest[2:]
    try:
        document = json.loads(read(path))
    except ValueError:
        fail('json-canary: the file is not valid JSON')
    values, skipped = [], 0
    for key_path, value in leaves(document):
        if any(skip in '.'.join(key_path).lower() for skip in skips):
            skipped += 1
            continue
        values.append(value.encode())
    register(values, 'json-canary')
    if skipped:
        print(f'json-canary: {skipped} leaf value(s) skipped by --skip (documented exceptions)')


def command_secret_lines(args):
    if len(args) != 1:
        raise SystemExit(usage())
    values = []
    for line in read(args[0]).splitlines():
        if line.startswith(b'secret '):
            values.append(line[len(b'secret '):].strip())
    register(values, 'secret-lines')


COMMANDS = {
    'file': command_file,
    'bytes-canary': command_bytes_canary,
    'text-canary': command_text_canary,
    'json-canary': command_json_canary,
    'secret-lines': command_secret_lines,
}


def usage():
    sys.stderr.write(USAGE)
    return 2


def main(argv):
    if not argv or argv[0] not in COMMANDS:
        return usage()
    if not os.environ.get('P07_RUN'):
        return 0
    try:
        COMMANDS[argv[0]](argv[1:])
    except Failure as error:
        sys.stderr.write(f'p07_export: {error}\n')
        return 1
    except scan.LogScanError as error:
        sys.stderr.write(f'p07_export: {error}\n')
        return 1
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main(sys.argv[1:]))
    except SystemExit as stop:
        sys.exit(stop.code if isinstance(stop.code, int) else 2)
