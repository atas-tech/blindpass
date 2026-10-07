#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""P06-BS01/B10: actual SQLite member boundary, complete verification and refusal."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import time


def command(arguments, env=None, expected=None):
    started = time.monotonic()
    result = subprocess.run(arguments, env=env, stdin=subprocess.DEVNULL,
                            capture_output=True, timeout=120)
    elapsed = time.monotonic() - started
    if elapsed >= 120:
        raise RuntimeError('backup size command exceeded deadline')
    if expected is None:
        if result.returncode:
            raise RuntimeError('backup size command failed; private diagnostics withheld')
    elif result.returncode == 0 or expected.encode() not in result.stderr:
        raise RuntimeError('backup size refusal did not report the required limit')
    return result, elapsed


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as source:
        while chunk := source.read(1024 * 1024):
            value.update(chunk)
    return value.digest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--controller', type=Path, default=Path('target/debug/blindpass-controller'))
    args = parser.parse_args()
    controller = args.controller.resolve(strict=True)
    cap = 512 * 1024 * 1024
    member_budget = cap - 65536 - 8192 - 3 * 32
    with tempfile.TemporaryDirectory(prefix='blindpass-p06-size-limit-') as temporary:
        root = Path(temporary)
        keys, data, output, verify = [root / name for name in ['keys', 'data', 'output', 'verify']]
        for directory in [keys, data, output, verify]:
            directory.mkdir(mode=0o700)
        for name in ['root-secret', 'agent-jwt-secret', 'issuer-key']:
            path = keys / name
            with path.open('xb') as file:
                path.chmod(0o600)
                file.write(os.urandom(32))
        key_hashes = {path.name: digest(path) for path in keys.iterdir()}
        env = {'BLINDPASS_KEYS_DIR': str(keys), 'BLINDPASS_DATA_DIR': str(data),
               'BLINDPASS_PUBLIC_URL': 'https://controller.p06.invalid',
               'BLINDPASS_UI_BASE_URL': 'https://controller.p06.invalid'}
        command([str(controller), 'migrate'], env)
        recovery = root / 'recovery.pem'
        command([str(controller), 'backup', 'key-init', '--output', str(recovery)])
        database = data / 'controller.db'
        with sqlite3.connect(database) as db:
            db.execute('CREATE TABLE size_boundary_payload (dummy BLOB NOT NULL)')
            db.commit()
            page = db.execute('PRAGMA page_size').fetchone()[0]
            target = member_budget // page * page
            identity = db.execute('SELECT tenant_id, issuer_epoch, schema_version FROM controller_meta WHERE id=1').fetchone()
            payload = 500 * 1024 * 1024
            # Overflow pages store page_size-4 payload bytes. Adjust from real
            # compact file sizes, then insist on the exact target, not an estimate.
            for _ in range(6):
                db.execute('DELETE FROM size_boundary_payload')
                db.execute('INSERT INTO size_boundary_payload VALUES (zeroblob(?))', (payload,))
                db.commit()
                db.execute('VACUUM')
                actual = database.stat().st_size
                if actual == target:
                    break
                payload += (target - actual) // page * (page - 4)
            else:
                raise RuntimeError('could not construct the exact SQLite size boundary')
            if db.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                raise RuntimeError('size boundary fixture integrity failed')
        result, create_seconds = command([str(controller), 'backup', 'create', '--output', str(output),
                                          '--recovery-key-file', str(recovery)], env)
        value = json.loads(result.stdout)
        if value.get('verified') is not True:
            raise RuntimeError('size boundary was published without full verification')
        archive = output / value['backup']
        original_hash = digest(archive)
        archive_bytes = archive.stat().st_size
        result, verify_seconds = command([str(controller), 'backup', 'verify', '--archive', str(archive),
                                          '--work-directory', str(verify), '--recovery-key-file', str(recovery)])
        value = json.loads(result.stdout)
        if value.get('verified') is not True or list(verify.iterdir()):
            raise RuntimeError('size boundary verification or cleanup failed')
        with sqlite3.connect(database) as db:
            db.execute('UPDATE size_boundary_payload SET dummy = zeroblob(?)', (payload + page - 4,))
            db.commit()
            db.execute('VACUUM')
        oversized_bytes = database.stat().st_size
        if oversized_bytes != target + page or oversized_bytes <= member_budget:
            raise RuntimeError('oversized fixture did not cross the member limit by one page')
        _, refusal_seconds = command([str(controller), 'backup', 'create', '--output', str(output),
                                      '--recovery-key-file', str(recovery)], env, 'backup exceeds limit')
        if list(output.iterdir()) != [archive] or digest(archive) != original_hash:
            raise RuntimeError('oversized backup published output, left residue or changed the old archive')
        if {path.name: digest(path) for path in keys.iterdir()} != key_hashes:
            raise RuntimeError('size boundary commands changed controller keys')
        with sqlite3.connect(database) as db:
            if db.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                raise RuntimeError('oversized source integrity changed')
            if db.execute('SELECT tenant_id, issuer_epoch, schema_version FROM controller_meta WHERE id=1').fetchone() != identity:
                raise RuntimeError('size boundary commands changed controller identity')
            if db.execute('SELECT length(dummy) FROM size_boundary_payload').fetchone()[0] != payload + page - 4:
                raise RuntimeError('size boundary commands changed source payload')
        command([str(controller), 'backup', 'verify', '--archive', str(archive), '--work-directory', str(verify),
                 '--recovery-key-file', str(recovery)])
        print(json.dumps({'scenario': 'P06-BS01/B10', 'bundle_cap_bytes': cap, 'member_budget_bytes': member_budget,
                          'database_bytes': target, 'payload_bytes': payload, 'archive_bytes': archive_bytes,
                          'oversized_database_bytes': oversized_bytes, 'page_bytes': page,
                          'create_seconds': round(create_seconds, 3), 'verify_seconds': round(verify_seconds, 3),
                          'refusal_seconds': round(refusal_seconds, 3), 'full_verification': True,
                          'old_archive_and_source_intact': True, 'private_fixtures_removed_on_exit': True}), flush=True)


if __name__ == '__main__':
    main()
