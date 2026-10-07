# SPDX-License-Identifier: AGPL-3.0-only
"""Fail-closed log assertions for the P06 harnesses (P07-I04, finding F2). Standard library only.

The harnesses used to run `secret in text` against whatever a log capture returned and pass when
nothing matched, so an empty, truncated or unreadable capture passed. `assert_log_clean` fails
instead when it could not look: an empty or tiny log, a log without the content it must hold, no
canaries, or a finder that cannot find a value it was asked to find (positive control). A failure
never contains a canary, a marker, or any log text, only the label, counts and SHA-256 prefixes.

When the environment variable P07_RUN names a directory, every scanned log is also exported there
(mode 0600) and the usable canaries are appended to `canaries.txt`, so that
`scripts/tests/canary-scan.sh --canaries $P07_RUN/canaries.txt ... $P07_RUN` can look again offline.
Without P07_RUN nothing is written. The helper has no dependency, so a harness that is copied into a
guest can carry it next to itself.
"""
import hashlib
import os
from pathlib import Path
import re
import secrets

MIN_BYTES = 64
MIN_CANARY_BYTES = 8          # in-harness floor; the offline scanner wants 12 and 8 distinct bytes
OFFLINE_MIN_BYTES = 12
OFFLINE_MIN_DISTINCT = 8


class LogScanError(AssertionError):
    """The scan could not look, or it found something. The message is safe to print."""


def _bytes(value):
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, str):
        return value.encode('utf-8')
    raise LogScanError('a scan value is neither text nor bytes')


def _prefix(value):
    return hashlib.sha256(value).hexdigest()[:8]


def _hits(data, values):
    """Indexes of the values that occur in data. The one finder every check and control uses."""
    return [index for index, value in enumerate(values) if value in data]


def read_log(path):
    """Read a log file, failing closed on a missing, unreadable or non-regular path."""
    path = Path(path)
    try:
        if not path.is_file():
            raise LogScanError(f'log {path.name} is not a readable file')
        return path.read_bytes()
    except OSError:
        raise LogScanError(f'log {path.name} could not be read') from None


def run_dir():
    """The export directory named by P07_RUN, created private, or None."""
    value = os.environ.get('P07_RUN')
    if not value:
        return None
    path = Path(value)
    if not path.is_absolute():
        raise LogScanError('P07_RUN must be an absolute path')
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    return path


def _safe_name(label):
    name = re.sub(r'[^A-Za-z0-9._-]+', '_', str(label)).lstrip('._-')
    return (name or 'unnamed')[:96]


def export(label, data, kind='logs', suffix='.log'):
    """Write data under $P07_RUN/<kind>/ (mode 0600, never overwriting). A no-op without P07_RUN."""
    root = run_dir()
    if root is None:
        return None
    directory = root / _safe_name(kind)
    directory.mkdir(mode=0o700, exist_ok=True)
    base = _safe_name(label)
    for attempt in range(1000):
        target = directory / (base + ('' if attempt == 0 else f'-{attempt}') + suffix)
        try:
            descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            continue
        with os.fdopen(descriptor, 'wb') as handle:
            handle.write(_bytes(data))
        return target
    raise LogScanError('too many exports with the same label')


def _usable_offline(value):
    return (len(value) >= OFFLINE_MIN_BYTES and len(set(value)) >= OFFLINE_MIN_DISTINCT
            and b'\n' not in value and b'\r' not in value)


def register_canaries(values):
    """Append the canaries the offline scanner can use to $P07_RUN/canaries.txt (one per line,
    mode 0600, no duplicates). Returns counts only. A no-op without P07_RUN."""
    root = run_dir()
    if root is None:
        return {'registered': 0, 'skipped': 0}
    target = root / 'canaries.txt'
    descriptor = os.open(target, os.O_RDWR | os.O_CREAT | os.O_APPEND, 0o600)
    registered = skipped = 0
    with os.fdopen(descriptor, 'r+b') as handle:
        handle.seek(0)
        known = set(handle.read().splitlines())
        for value in map(_bytes, values):
            if not _usable_offline(value):
                skipped += 1
            elif value not in known:
                handle.write(value + b'\n')
                known.add(value)
                registered += 1
    return {'registered': registered, 'skipped': skipped}


def assert_log_clean(label, log, canaries, *, markers=(), require=(), min_bytes=MIN_BYTES, allow_empty=None):
    """Fail unless the log was really looked at and holds no canary and no marker.

    canaries  secret values that must not appear (passwords, tokens, dummy constants). May be empty
              when markers are given.
    markers   patterns that must not appear and are not canaries (for example b'PRIVATE KEY-----').
    require   content a genuine capture must hold (a unit or service name), so a truncated or
              wrong capture cannot pass.
    allow_empty  a stated reason why a capture that really was taken may be empty by design (for
              example the shipped nginx edge sets `access_log off` and `error_log /dev/null`). The
              caller must have asserted that property itself; only an empty capture is excused, a
              missing capture, missing `require` content, a failed control or a leak still fail.
    Returns counts for the PASS line. Raises LogScanError (an AssertionError) otherwise.
    """
    if log is None:
        raise LogScanError(f'{label}: no log was captured')
    data = _bytes(log)
    canary_values = [_bytes(value) for value in canaries]
    marker_values = [_bytes(value) for value in markers]
    expected = [_bytes(value) for value in require]
    # Keep the evidence even when the scan fails, so a leak can be investigated offline. An allowed empty
    # capture is recorded as a note with its reason: the offline scanner rejects empty logs on purpose.
    if isinstance(allow_empty, str) and allow_empty.strip() and not data.strip():
        export(label + '-empty-by-design', f'{label}: the capture is empty by design: {allow_empty.strip()}\n', kind='notes', suffix='.txt')
    else:
        export(label, data)
    register_canaries(canary_values)
    reason = allow_empty.strip() if isinstance(allow_empty, str) else ''
    if reason:
        min_bytes = 0
    if len(data.strip()) < max(0 if reason else 1, min_bytes):
        raise LogScanError(f'{label}: the captured log is empty or too short ({len(data)} bytes, at least {min_bytes} '
                           'required): a scan of nothing proves nothing')
    if not (canary_values or marker_values) or any(len(value) < MIN_CANARY_BYTES for value in canary_values + marker_values):
        raise LogScanError(f'{label}: the scan has no usable canaries (each value needs at least {MIN_CANARY_BYTES} bytes)')
    missing = [index for index, value in enumerate(expected) if value not in data]
    if missing:
        raise LogScanError(f'{label}: the log lacks expected content ({len(missing)} of {len(expected)} required '
                           'markers absent): the capture is truncated or from the wrong source')
    values = canary_values + marker_values
    # Positive control, through the same finder as the real scan: a random token planted in a copy
    # of this very log must be found and must not be there already; every value must be findable
    # in a buffer that holds it.
    token = b'P07-CONTROL-' + secrets.token_hex(12).encode()
    if _hits(data, [token]) or _hits(data + b'\n' + token, [token]) != [0]:
        raise LogScanError(f'{label}: the scan control failed (the finder cannot see a planted token)')
    if _hits(b'\0pad\n' + b'\npad\0'.join(values) + b'\npad', values) != list(range(len(values))):
        raise LogScanError(f'{label}: the scan control failed (the finder cannot see a value it was given)')
    found = _hits(data, values)
    if found:
        names = ', '.join(_prefix(values[index]) for index in found)
        raise LogScanError(f'{label}: {len(found)} forbidden value(s) in the log (sha256 prefix {names})')
    stats = {'bytes': len(data), 'canaries': len(canary_values), 'markers': len(marker_values),
             'required': len(expected), 'control': 'ok'}
    if reason and not data.strip():
        stats['empty_by_design'] = reason
    return stats
