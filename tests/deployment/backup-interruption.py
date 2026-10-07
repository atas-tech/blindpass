#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""P06-B06: SIGKILL during actual encryption/decryption; observe and reap children."""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import signal
import sqlite3
import stat
import subprocess
import tempfile
import time


def checked(arguments, env=None):
    started=time.monotonic()
    result=subprocess.run(arguments,env=env,stdin=subprocess.DEVNULL,capture_output=True,timeout=60)
    if result.returncode or time.monotonic()-started>=60:
        raise RuntimeError('backup fixture command failed; private diagnostics withheld')
    return result


def file_hash(path):
    digest=hashlib.sha256()
    with path.open('rb') as source:
        while chunk:=source.read(1024*1024): digest.update(chunk)
    return digest.digest()


def tool_children(pid, flag):
    found=[]
    for task in Path('/proc/'+str(pid)+'/task').glob('*'):
        try: children=(task/'children').read_text().split()
        except FileNotFoundError: continue
        for value in children:
            try: arguments=Path('/proc/'+value+'/cmdline').read_bytes().split(b'\0')
            except FileNotFoundError: continue
            if arguments and arguments[0]==b'/usr/bin/openssl' and flag.encode() in arguments:
                found.append(int(value))
    return found


def killed_phase(controller, env, root, phase, recovery, archive=None):
    work=root/phase; work.mkdir(mode=0o700)
    if phase=='encryption':
        arguments=[str(controller),'backup','create','--output',str(work),'--recovery-key-file',str(recovery)]
        member='encrypted.der'; flag='-encrypt'
    else:
        arguments=[str(controller),'backup','verify','--archive',str(archive),
                   '--work-directory',str(work),'--recovery-key-file',str(recovery)]
        member='verified.tar'; flag='-decrypt'
    child=subprocess.Popen(arguments,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    started=time.monotonic(); observed=False; descendants=[]
    try:
        while child.poll() is None and time.monotonic()-started<30:
            for path in work.rglob(member):
                try: growing=path.stat().st_size>1024*1024
                except FileNotFoundError: continue
                if growing:
                    descendants=tool_children(child.pid,flag)
                    observed=bool(descendants)
                    if observed: break
            if observed: break
            time.sleep(0.001)
    finally:
        if child.poll() is None: child.kill()
        result=child.wait(timeout=5)
    # The test is a private child subreaper, so adopted OpenSSL children are
    # actually reaped here; a zombie does not count as teardown success.
    statuses={}; deadline=time.monotonic()+5
    while len(statuses)<len(descendants) and time.monotonic()<deadline:
        for pid in descendants:
            if pid in statuses: continue
            waited,status=os.waitpid(pid,os.WNOHANG)
            if waited: statuses[pid]=status
        if len(statuses)<len(descendants): time.sleep(0.005)
    if len(statuses)<len(descendants):
        for pid in descendants:
            if pid not in statuses:
                os.kill(pid,signal.SIGKILL); os.waitpid(pid,0)
        raise RuntimeError('parent-death termination deadline exceeded')
    if not observed or result!=-signal.SIGKILL:
        raise RuntimeError('actual crypto tool progress was not interrupted')
    if not all(os.WIFSIGNALED(status) and os.WTERMSIG(status)==signal.SIGKILL for status in statuses.values()):
        raise RuntimeError('crypto child was not killed after parent death')
    entries=list(work.iterdir())
    if not entries or any(not p.name.startswith('.backup-') for p in entries):
        raise RuntimeError('interrupted phase published output or left no observable residue')
    for path in work.rglob('*'):
        metadata=path.lstat()
        mode=0o700 if stat.S_ISDIR(metadata.st_mode) else 0o600
        if (not stat.S_ISDIR(metadata.st_mode) and not stat.S_ISREG(metadata.st_mode)) or stat.S_IMODE(metadata.st_mode)!=mode or metadata.st_uid!=os.geteuid():
            raise RuntimeError('interrupted plaintext custody is unsafe')
    output=checked([str(controller),'backup','cleanup','--work-directory',str(work)])
    if json.loads(output.stdout)['removed_staging_directories']<1 or list(work.iterdir()):
        raise RuntimeError('explicit interrupted-stage cleanup failed')
    print(json.dumps({'scenario':'P06-B06','phase':phase,'sigkill':'passed',
                      'actual_tool_progress':True,'child_killed_and_reaped':True,'partial_publication':False}),flush=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--controller',type=Path,default=Path('target/debug/blindpass-controller'))
    args=parser.parse_args(); controller=args.controller.resolve(strict=True)
    libc=ctypes.CDLL(None,use_errno=True)
    libc.prctl.argtypes=[ctypes.c_int,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong]
    libc.prctl.restype=ctypes.c_int
    if libc.prctl(36,1,0,0,0):  # PR_SET_CHILD_SUBREAPER; this test process only.
        raise RuntimeError('private test child subreaper unavailable')
    with tempfile.TemporaryDirectory(prefix='blindpass-p06-crypto-kill-') as temporary:
        root=Path(temporary); keys=root/'keys'; data=root/'data'; complete=root/'complete'
        for path in [keys,data,complete]: path.mkdir(mode=0o700)
        for name in ['root-secret','agent-jwt-secret','issuer-key']:
            path=keys/name
            with path.open('xb') as output:
                path.chmod(0o600); output.write(os.urandom(32))
        before=hashlib.sha256(b''.join(p.read_bytes() for p in sorted(keys.iterdir()))).digest()
        env={'BLINDPASS_KEYS_DIR':str(keys),'BLINDPASS_DATA_DIR':str(data),
             'BLINDPASS_PUBLIC_URL':'https://controller.p06.invalid','BLINDPASS_UI_BASE_URL':'https://controller.p06.invalid'}
        checked([str(controller),'migrate'],env)
        size=192*1024*1024
        with sqlite3.connect(data/'controller.db') as database:
            database.execute('CREATE TABLE interrupted_crypto_payload (dummy BLOB NOT NULL)')
            database.execute('INSERT INTO interrupted_crypto_payload VALUES(zeroblob(?))',(size,))
            identity=database.execute('SELECT tenant_id,issuer_epoch,schema_version FROM controller_meta WHERE id=1').fetchone()
        recovery=root/'recovery.pem'
        checked([str(controller),'backup','key-init','--output',str(recovery)])
        killed_phase(controller,env,root,'encryption',recovery)
        started=time.monotonic()
        result=checked([str(controller),'backup','create','--output',str(complete),'--recovery-key-file',str(recovery)],env)
        elapsed=time.monotonic()-started
        value=json.loads(result.stdout)
        if value.get('verified') is not True: raise RuntimeError('complete fixture verification missing')
        print(json.dumps({'scenario':'P06-B10','fixture_bytes':size,'complete_backup_verified':True,
                          'backup_seconds':round(elapsed,3)}),flush=True)
        archive=complete/value['backup']; original=file_hash(archive)
        killed_phase(controller,env,root,'verification',recovery,archive)
        if file_hash(archive)!=original:
            raise RuntimeError('verification interruption changed the original archive')
        if hashlib.sha256(b''.join(p.read_bytes() for p in sorted(keys.iterdir()))).digest()!=before:
            raise RuntimeError('interruption changed controller keys')
        with sqlite3.connect(data/'controller.db') as database:
            if database.execute('SELECT length(dummy) FROM interrupted_crypto_payload').fetchone()[0]!=size or database.execute('PRAGMA integrity_check').fetchone()[0]!='ok':
                raise RuntimeError('interruption changed the source database')
            if database.execute('SELECT tenant_id,issuer_epoch,schema_version FROM controller_meta WHERE id=1').fetchone()!=identity:
                raise RuntimeError('interruption changed source identity')
        print('PASS P06-B06 source/keys/complete archive intact; private fixtures removed on exit',flush=True)


if __name__=='__main__': main()
