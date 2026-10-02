#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -euo pipefail
release_output=${1:-dist/release}
# Only archives are hashed, never an arbitrary working directory or credential.
python3 - "$release_output" <<'PY'
from pathlib import Path
import hashlib, os, re, sys, tempfile
root = Path(sys.argv[1])
archives = sorted(root.glob('blindpass-*-linux-*.tar.zst'))
if not archives:
    raise SystemExit('checksums: no completed release archives')
if (root / 'SHA256SUMS').exists() or (root / 'SHA256SUMS').is_symlink():
    raise SystemExit('checksums: refusing to replace existing inventory')
entries = []
for archive in archives:
    if archive.is_symlink() or not archive.is_file() or not re.fullmatch(r'blindpass-(controller|node)-[a-zA-Z0-9.-]+-linux-(x86_64|aarch64)\.tar\.zst', archive.name):
        raise SystemExit('checksums: unsafe artifact')
    digest = hashlib.sha256()
    with archive.open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(block)
    entries.append(f'{digest.hexdigest()}  {archive.name}\n')
fd, temporary = tempfile.mkstemp(prefix='.checksums-', suffix='.tmp', dir=root)
try:
    with os.fdopen(fd, 'w') as destination:
        destination.writelines(entries); destination.flush(); os.fsync(destination.fileno())
    os.link(temporary, root / 'SHA256SUMS')
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(directory)
    finally: os.close(directory)
finally:
    Path(temporary).unlink(missing_ok=True)
PY
