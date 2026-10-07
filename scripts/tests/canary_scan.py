#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Fail-closed exposure scanner for archives, container images, backups, dumps, transcripts and logs.

P07-I04 / pilot S06-S07. The earlier VM scanners could pass because they saw nothing (an empty
journal, a skipped artifact, an unreadable archive). This one treats "could not look" as a failure:

  exit 0  every requested artifact class was found, fully read and is clean (allowlisted hits are
          still reported with their reason)
  exit 1  at least one canary, key material, secret-shaped value or unsafe artifact was found
  exit 2  configuration error (bad canary list, bad allowlist, no canaries, bad usage)
  exit 3  the scan is incomplete: unreadable, truncated, corrupt, unsupported, over a limit, empty,
          or a requested class had no artifact. An incomplete scan is never a pass.

Nothing printed or written ever contains a canary, an encoding of one, key material or a matched
secret: hits carry a SHA-256 prefix, a location (with canary-bearing names redacted) and a count.
"""
import argparse
import base64
import bz2
import collections
import fnmatch
import hashlib
import html
import io
import json
import lzma
import math
import os
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.parse
import zipfile
import zlib

VERSION = 1
CHUNK = 1024 * 1024
HEAD = 8192
MIN_CANARY_BYTES = 12
MIN_DISTINCT_BYTES = 8
MIN_REASON = 10
SMALL_JSON_LIMIT = 4 * 1024 * 1024
TAIL_SHAPES = 4096
HIT_CAP = 200

EXIT_PASS, EXIT_HITS, EXIT_CONFIG, EXIT_INCOMPLETE = 0, 1, 2, 3


class ConfigError(Exception):
    pass


class Incomplete(Exception):
    """The scan of one artifact (or member) could not be completed."""

    def __init__(self, reason, detail=''):
        super().__init__(reason)
        self.reason = reason
        self.detail = detail


class StreamError(Incomplete):
    """A sticky failure of an enclosing stream: nothing after it in that stream can be trusted."""


# ----------------------------------------------------------------------------------------------------------
# Canary patterns
# ----------------------------------------------------------------------------------------------------------

class Pattern:
    __slots__ = ('cid', 'kind', 'labels', 'data', 'pid')

    def __init__(self, pid, cid, kind, labels, data):
        self.pid, self.cid, self.kind, self.labels, self.data = pid, cid, kind, labels, data


def canary_id(value):
    return hashlib.sha256(value).hexdigest()[:8]


def base64_cores(data, urlsafe):
    """Substrings of the base64 text of `data` that do not depend on the bytes around it."""
    encode = base64.urlsafe_b64encode if urlsafe else base64.b64encode
    cores = []
    for lead_zero_bytes, lead_chars in ((0, 0), (1, 2), (2, 3)):
        encoded = encode(b'\0' * lead_zero_bytes + data).rstrip(b'=')
        length = lead_zero_bytes + len(data)
        end = len(encoded) - (0 if length % 3 == 0 else 1)
        cores.append(encoded[lead_chars:end])
    return cores


def variants(value):
    """{label: set(bytes)} for one canary (bytes) and its text form when it is valid UTF-8."""
    try:
        text = value.decode('utf-8')
    except UnicodeDecodeError:
        text = None
    out = collections.OrderedDict()

    def add(label, data):
        if isinstance(data, str):
            data = data.encode('utf-8')
        if len(data) >= 8:
            out.setdefault(label, set()).add(data)

    add('raw', value)
    if text is not None:
        add('utf-16le', text.encode('utf-16-le'))
        add('utf-16be', text.encode('utf-16-be'))
    add('hex', value.hex())
    add('hex-upper', value.hex().upper())
    for core in base64_cores(value, False):
        add('base64', core)
    for core in base64_cores(value, True):
        add('base64url', core)
    if text is not None:
        add('url', urllib.parse.quote(text, safe=''))
        add('url', urllib.parse.quote_plus(text))
        add('json', json.dumps(text, ensure_ascii=True)[1:-1])
        add('json', json.dumps(text, ensure_ascii=False)[1:-1])
        add('json', json.dumps(text, ensure_ascii=True)[1:-1].replace('/', '\\/'))
        add('json-unicode', ''.join('\\u%04x' % ord(ch) for ch in text))
        add('json-unicode', ''.join('\\u%04X' % ord(ch) for ch in text))
        add('html', html.escape(text, quote=True))
    add('url-all', ''.join('%%%02X' % byte for byte in value))
    add('url-all', ''.join('%%%02x' % byte for byte in value))
    add('bytes-debug', ', '.join(str(byte) for byte in value))
    add('hex-escape', ''.join('\\x%02x' % byte for byte in value))
    add('hex-escape', ''.join('\\x%02X' % byte for byte in value))
    return out


def build_patterns(canaries):
    """canaries: list of (kind, bytes). Equal byte strings share one Pattern with all their labels."""
    by_bytes = collections.OrderedDict()
    for kind, value in canaries:
        cid = canary_id(value)
        for label, datas in variants(value).items():
            for data in sorted(datas):
                key = (cid, data)
                entry = by_bytes.setdefault(key, (cid, kind, []))
                if label not in entry[2]:
                    entry[2].append(label)
    return [Pattern(index, cid, kind, labels, data) for index, ((_, data), (cid, kind, labels)) in enumerate(by_bytes.items())]


class Compiled:
    """Pattern groups shared by every Matcher of one scanner (building them per file would be slow)."""

    PREFIX = 6

    def __init__(self, patterns):
        self.patterns = patterns
        self.groups = collections.OrderedDict()
        for pattern in patterns:
            self.groups.setdefault(pattern.data[:self.PREFIX], []).append(pattern)
        self.group_max = {prefix: max(len(p.data) for p in group) for prefix, group in self.groups.items()}
        self.overlap = (max(len(p.data) for p in patterns) - 1) if patterns else 0


class Matcher:
    """Streaming multi-pattern search. Matches that straddle chunk boundaries are found."""

    def __init__(self, compiled):
        self.compiled = compiled
        self.tail = b''
        self.base = 0
        self.found = {}

    def feed(self, chunk):
        compiled = self.compiled
        if not chunk or not compiled.patterns:
            return
        data = self.tail + chunk
        fresh = len(self.tail)
        for prefix, group in compiled.groups.items():
            begin = max(0, fresh - compiled.group_max[prefix] + 1)
            while True:
                at = data.find(prefix, begin)
                if at < 0:
                    break
                for pattern in group:
                    if data.startswith(pattern.data, at) and at + len(pattern.data) > fresh:
                        entry = self.found.setdefault(pattern.pid, [0, self.base + at])
                        entry[0] += 1
                begin = at + 1
        keep = min(len(data), compiled.overlap)
        self.tail = data[len(data) - keep:] if keep else b''
        self.base += len(data) - len(self.tail)

    def skip_zeros(self, count):
        """Advance over `count` zero bytes. The caller has already fed enough leading zeros for any match that
        ends in them; the zero tail kept here lets a pattern that starts with NULs (UTF-16BE, raw keys) match."""
        keep = min(self.compiled.overlap, count)
        self.base += len(self.tail) + count - keep
        self.tail = b'\0' * keep


# ----------------------------------------------------------------------------------------------------------
# Secret-shaped material
# ----------------------------------------------------------------------------------------------------------

UUID = rb'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
# (name, literal that must occur in the lower-cased chunk before the regex is tried, regex). The literal keeps
# the scan fast on binaries; regexes start with a literal so the regex engine can skip ahead as well.
SHAPES = [
    # A header alone is only the string literal inside OpenSSL/Node/Go binaries; require the base64 body to follow.
    ('pem', b'-----begin ', re.compile(rb'-----BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----[ \t]*\r?\n'
                                     rb'(?:[A-Za-z][A-Za-z0-9-]*: [^\r\n]*\r?\n)*[ \t]*\r?\n?[A-Za-z0-9+/]{40,}')),
    ('age-secret-key', b'age-secret-key-1', re.compile(rb'AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}')),
    ('jwt', b'eyj', re.compile(rb'eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,}')),
    ('bearer-token', b'bearer', re.compile(rb'(?i:bearer)[ \t]+(?=[A-Za-z0-9._~+/=-]*\d)[A-Za-z0-9._~+/=-]{24,}')),
    ('agent-api-key', b'ak_', re.compile(rb'ak_' + UUID + rb'_[A-Za-z0-9_-]{20,}')),
    ('enrollment-token', b'en_', re.compile(rb'en_' + UUID + rb'_[A-Za-z0-9_-]{43}')),
    ('signed-link', b'sig=', re.compile(rb'[?&](?:metadata_sig|submit_sig|sig)=[A-Za-z0-9_%.\-]{40,}')),
    ('bootstrap-token', b'bootstrap-token', re.compile(rb'(?i:x-blindpass-bootstrap-token)["\':=\s]+[A-Za-z0-9_-]{32,}')),
]
BOUNDARY_CHECKED = {'jwt', 'bearer-token', 'agent-api-key', 'enrollment-token'}
WORD = frozenset(b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_')


def shape_name(base, match):
    if base != 'pem':
        return base
    kind = (match.group(1) or b'').decode().strip().lower()
    return f'pem-{kind}-private-key' if kind else 'pem-private-key'


class ShapeScanner:
    def __init__(self):
        self.tail = b''
        self.base = 0
        self.found = {}

    def feed(self, chunk):
        data = self.tail + chunk
        fresh = len(self.tail)
        low = data.lower()
        for base, literal, regex in SHAPES:
            if literal not in low:
                continue
            for match in regex.finditer(data):
                if match.end() <= fresh:
                    continue
                if base in BOUNDARY_CHECKED and match.start() > 0 and data[match.start() - 1] in WORD:
                    continue
                name = shape_name(base, match)
                entry = self.found.setdefault(name, [0, self.base + match.start(), hashlib.sha256(match.group(0)).hexdigest()[:8]])
                entry[0] += 1
        keep = min(len(data), TAIL_SHAPES)
        self.tail = data[len(data) - keep:]
        self.base += len(data) - len(self.tail)

    def skip_zeros(self, count):
        """No secret shape contains a NUL, so zeros end every candidate match."""
        self.base += len(self.tail) + count
        self.tail = b''


SECRET_ENV_NAME = re.compile(r'(?i)(^|_)(pass(word|wd)?|secret|token|api_?key|private_?key|credentials?)(_|$)')
SECRET_ENV_SKIP = re.compile(r'(?i)_(file|path|dir|url|name|id|ttl|len|length|min|max)$')
ENV_ASSIGNMENT = re.compile(r'(?<![A-Za-z0-9_])([A-Za-z_][A-Za-z0-9_]*)=("[^"]*"|\'[^\']*\'|[^\s]+)')


def secret_assignment(name, value):
    """True for NAME=VALUE where NAME says it is a secret and VALUE is a literal, not a file or secret reference."""
    value = value.strip('"\'')
    return bool(value) and bool(SECRET_ENV_NAME.search(name)) and not SECRET_ENV_SKIP.search(name) \
        and not value.startswith(('/run/secrets/', '$', '<'))

FORBIDDEN_EXACT = {
    'root-secret', 'agent-jwt-secret', 'issuer-key', 'controller-backup-signing-credential', 'recovery-credential',
    'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519', '.git-credentials', '.netrc', '.pgpass',
}
ENV_SAMPLE = {'.env.example', '.env.sample', '.env.template', '.env.dist'}
BACKUP_STAGING = re.compile(r'^\.backup-[0-9a-f]{32}$')


def forbidden_rule(name):
    """The rule id a path component violates, or None."""
    lowered = name.lower()
    if name in FORBIDDEN_EXACT:
        return name
    if name == '.env' or (name.startswith('.env.') and lowered not in ENV_SAMPLE):
        return '.env'
    if BACKUP_STAGING.match(name):
        return '.backup-staging'
    if fnmatch.fnmatch(lowered, 'authority-password*'):
        return 'authority-password'
    if 'certificate' not in lowered and (fnmatch.fnmatch(lowered, '*recovery-key*') or fnmatch.fnmatch(lowered, '*recipient-key*')):
        return 'recovery-key'
    if fnmatch.fnmatch(lowered, 'age-identity*') or fnmatch.fnmatch(lowered, '*.age-identity'):
        return 'age-identity'
    if any(fnmatch.fnmatch(lowered, pattern) for pattern in ('*.key', '*-key.pem', '*private*.pem', '*.p12', '*.pfx', '*.jks')):
        return 'private-key-file'
    return None


# ----------------------------------------------------------------------------------------------------------
# Magic / classification
# ----------------------------------------------------------------------------------------------------------

UNSUPPORTED = [
    (b'7z\xbc\xaf\x27\x1c', '7z'), (b'Rar!\x1a\x07', 'rar'), (b'070701', 'cpio'), (b'070702', 'cpio'), (b'070707', 'cpio'),
    (b'\xed\xab\xee\xdb', 'rpm'), (b'hsqs', 'squashfs'), (b'sqsh', 'squashfs'), (b'QFI\xfb', 'qcow2'), (b'KDMV', 'vmdk'),
    (b'\x04\x22\x4d\x18', 'lz4'), (b'LZIP', 'lzip'), (b'\x89LZO\x00', 'lzop'), (b'\x1f\x9d', 'compress'), (b'MSCF', 'cab'),
    (b'<<< Oracle VM VirtualBox Disk Image >>>', 'vdi'),
]
CMS_OID = bytes.fromhex('06092a864886f70d010702')
CORE_NAMES = ('core', 'core.*', '*.core', '*.dmp', '*.mdmp', '*.crash', '*.coredump*', 'vgcore.*')


def tar_header(head):
    if len(head) < 512 or head[0] == 0:
        return False
    field = head[148:156].strip(b'\0 ')
    try:
        recorded = int(field, 8)
    except ValueError:
        return False
    computed = sum(head[:148]) + 8 * 32 + sum(head[156:512])
    return computed == recorded


def sniff(head):
    if not head:
        return 'empty'
    if head[:3] == b'\x1f\x8b\x08':
        return 'gz'
    if head[:3] == b'BZh' and len(head) > 3 and 0x31 <= head[3] <= 0x39:
        return 'bz2'
    if head[:6] == b'\xfd7zXZ\x00':
        return 'xz'
    if head[:4] == b'\x28\xb5\x2f\xfd' or (len(head) >= 4 and 0x50 <= head[0] <= 0x5f and head[1:4] == b'\x2a\x4d\x18'):
        return 'zst'
    if head[:4] in (b'PK\x03\x04', b'PK\x05\x06'):
        return 'zip'
    if head[:8] == b'!<arch>\n':
        return 'ar'
    if tar_header(head):
        return 'tar'
    if head[:4] == b'\x7fELF' and len(head) >= 18:
        etype = int.from_bytes(head[16:18], 'big' if head[5] == 2 else 'little')
        if etype == 4:
            return 'elf-core'
    if head[0] == 0x30 and CMS_OID in head[:16]:
        return 'cms'
    for magic, name in UNSUPPORTED:
        if head.startswith(magic):
            return 'unsupported:' + name
    return 'other'


def classify(name, kind, extra_globs):
    base = os.path.basename(name or '').lower()
    for cls, glob in extra_globs:
        if fnmatch.fnmatch(base, glob.lower()):
            return cls
    if kind == 'cms' or base.endswith(('.bpbackup', '.cms', '.p7m')):
        return 'backup'
    if kind == 'elf-core' or any(fnmatch.fnmatch(base, glob) for glob in CORE_NAMES):
        return 'dump'
    if base.endswith(('.jsonl', '.ndjson')) or 'transcript' in base or 'stream-json' in base:
        return 'transcript'
    if base.endswith(('.log', '.out', '.err', '.journal')) or 'journal' in base or '.log.' in base:
        return 'log'
    return None


# ----------------------------------------------------------------------------------------------------------
# Stream plumbing
# ----------------------------------------------------------------------------------------------------------

class Budget:
    def __init__(self, limit):
        self.limit = limit
        self.used = 0

    def charge(self, count):
        self.used += count
        if self.used > self.limit:
            raise StreamError('byte_limit_exceeded', f'more than {self.limit} bytes read')


class PeekReader:
    def __init__(self, raw):
        self.raw = raw
        self.buf = b''
        self.eof = False

    def peek(self, count):
        while len(self.buf) < count and not self.eof:
            chunk = self.raw.read(count - len(self.buf))
            if not chunk:
                self.eof = True
                break
            self.buf += chunk
        return self.buf[:count]

    def read(self, count=-1):
        if count is None or count < 0:
            count = CHUNK
        if self.buf:
            data, self.buf = self.buf[:count], self.buf[count:]
            return data
        return self.raw.read(count)


class Counting:
    """Charges every byte read from a source stream to the run-wide budget."""

    def __init__(self, raw, budget):
        self.raw, self.budget = raw, budget

    def read(self, count=-1):
        data = self.raw.read(count if count and count > 0 else CHUNK)
        self.budget.charge(len(data))
        return data


MAGICS = {'gz': (b'\x1f\x8b',), 'bz2': (b'BZh',), 'xz': (b'\xfd7zXZ\x00',), 'zst': (b'\x28\xb5\x2f\xfd',)}


def zstd_backend():
    mode = os.environ.get('CANARY_SCAN_ZSTD', 'auto')
    if mode == 'none':
        return 'none'
    if mode in ('auto', 'module'):
        try:
            import compression.zstd  # noqa: F401
            return 'module'
        except ImportError:
            if mode == 'module':
                return 'none'
    if shutil.which('zstd'):
        return 'cli'
    return 'none'


class ZstdCli:
    """Decompress through the zstd binary; a non-zero exit (truncation, corruption) is an error."""

    def __init__(self, raw):
        self.raw = raw
        self.proc = subprocess.Popen(['zstd', '-dc', '--no-progress', '-q'], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.DEVNULL)
        self.feeder = threading.Thread(target=self._feed, daemon=True)
        self.feeder.start()
        self.done = False

    def _feed(self):
        try:
            while True:
                block = self.raw.read(CHUNK)
                if not block:
                    break
                self.proc.stdin.write(block)
        except (OSError, Incomplete, ValueError):
            pass
        finally:
            try:
                self.proc.stdin.close()
            except OSError:
                pass

    def read(self, count):
        data = self.proc.stdout.read(count)
        if not data and not self.done:
            self.done = True
            self.feeder.join(timeout=30)
            if self.proc.wait(timeout=30) != 0:
                raise StreamError('stream_corrupt', 'zstd stream is truncated or corrupt')
        return data


class Decompressor:
    """Incremental, strict decompressor: truncation, corruption and trailing garbage are errors."""

    def __init__(self, raw, kind, scanner):
        self.raw, self.kind, self.scanner = raw, kind, scanner
        self.budget = scanner.budget
        self.out = b''
        self.done = False
        self.error = None
        self.inbuf = b''
        self.raw_eof = False
        self.cli = None
        if kind == 'zst':
            backend = scanner.zstd
            if backend == 'none':
                self.error = StreamError('codec_unavailable', 'no zstd decoder')
            elif backend == 'cli':
                self.cli = ZstdCli(raw)
        if not self.error and not self.cli:
            self.dec = self._new()

    def _new(self):
        if self.kind == 'gz':
            return zlib.decompressobj(16 + zlib.MAX_WBITS)
        if self.kind == 'bz2':
            return bz2.BZ2Decompressor()
        if self.kind == 'xz':
            return lzma.LZMADecompressor()
        from compression import zstd
        return zstd.ZstdDecompressor()

    def _raw(self):
        if self.inbuf:
            block, self.inbuf = self.inbuf, b''
            return block
        if self.raw_eof:
            return b''
        block = self.raw.read(CHUNK)
        if not block:
            self.raw_eof = True
        return block

    def read(self, count=-1):
        if self.error:
            raise self.error
        if count is None or count < 0:
            count = CHUNK
        try:
            if self.cli:
                data = self.cli.read(count)
                self.budget.charge(len(data))
                return data
            while len(self.out) < count and not self.done:
                self._step()
        except StreamError as error:
            self.error = error
            raise
        except Incomplete:
            raise
        except Exception as error:  # zlib, bz2, lzma and zstd each raise their own error type for damaged input
            self.error = StreamError('stream_corrupt', type(error).__name__)
            raise self.error
        data, self.out = self.out[:count], self.out[count:]
        self.budget.charge(len(data))
        return data

    def _step(self):
        dec = self.dec
        if dec.eof:
            return self._after_member()
        if self.kind == 'gz':
            block = dec.unconsumed_tail or self._raw()
        else:
            block = self._raw() if dec.needs_input else b''
        if not block and (self.kind == 'gz' or dec.needs_input):
            raise StreamError('stream_truncated', f'{self.kind} stream ends before its end marker')
        self.out += dec.decompress(block, CHUNK)

    def _after_member(self):
        unused = self.dec.unused_data
        rest = unused + self._raw_until(max(0, 6 - len(unused)))
        self.inbuf = b''
        magic = MAGICS[self.kind]
        if not rest and self.raw_eof:
            self.done = True
        elif any(rest.startswith(m) for m in magic) or (self.kind == 'zst' and self._zst_magic(rest)):
            self.dec = self._new()
            self.inbuf = rest
        elif not rest.strip(b'\0') and self.kind in ('gz', 'xz'):
            while True:
                block = self.raw.read(CHUNK)
                if not block:
                    break
                if block.strip(b'\0'):
                    raise StreamError('trailing_data_after_stream', 'non-zero bytes after the end of the stream')
            self.raw_eof = True
            self.done = True
        else:
            raise StreamError('trailing_data_after_stream', 'unrecognised bytes after the end of the stream')

    @staticmethod
    def _zst_magic(rest):
        return rest[:4] == b'\x28\xb5\x2f\xfd' or (len(rest) >= 4 and 0x50 <= rest[0] <= 0x5f and rest[1:4] == b'\x2a\x4d\x18')

    def _raw_until(self, count):
        data = b''
        while len(data) < count and not self.raw_eof:
            block = self.raw.read(count - len(data))
            if not block:
                self.raw_eof = True
                break
            data += block
        return data


class TapReader:
    """Remembers the tail of a stream so the block where tarfile stopped can be inspected afterwards."""

    KEEP = 2 * CHUNK + 4096

    def __init__(self, inner):
        self.inner = inner
        self.ring = bytearray()
        self.total = 0

    def read(self, count=-1):
        data = self.inner.read(count)
        self.total += len(data)
        self.ring += data
        if len(self.ring) > 2 * self.KEEP:
            del self.ring[:len(self.ring) - self.KEEP]
        return data

    def block_at(self, position, size):
        start = position - (self.total - len(self.ring))
        if start < 0 or start + size > len(self.ring):
            return None
        return bytes(self.ring[start:start + size])


class MemberReader:
    """A size-checked view of an archive member that optionally hashes and captures what it reads."""

    def __init__(self, inner, size, hashed=False, capture=0):
        self.inner, self.size = inner, size
        self.count = 0
        self.hasher = hashlib.sha256() if hashed else None
        self.capture_limit = capture if capture and size is not None and size <= capture else 0
        self.captured = bytearray() if self.capture_limit else None

    def read(self, count=-1):
        data = self.inner.read(count if count and count > 0 else CHUNK)
        self.count += len(data)
        if self.hasher:
            self.hasher.update(data)
        if self.captured is not None:
            self.captured += data
        return data

    def finish(self):
        if self.size is not None and self.count != self.size:
            raise Incomplete('member_truncated', f'read {self.count} of {self.size} bytes')

    @property
    def digest(self):
        return self.hasher.hexdigest() if self.hasher else None


class Artifact:
    def __init__(self, path, loc):
        self.path, self.loc = path, loc
        self.kind = None
        self.files = 0
        self.entries = 0
        self.bytes = 0
        self.max_depth = 0
        self.formats = set()
        self.hits = []
        self.hits_truncated = 0
        self.findings = []
        self.patterns = []
        self.incomplete = []
        self.classes = collections.Counter()

    def add_incomplete(self, reason, location, detail=''):
        self.incomplete.append({'reason': reason, 'location': location, 'detail': detail})

    def to_json(self):
        return {
            'path': self.loc, 'kind': self.kind, 'files': self.files, 'entries': self.entries, 'bytes': self.bytes,
            'max_depth': self.max_depth, 'formats': sorted(self.formats), 'classes': dict(self.classes),
            'hits': self.hits, 'hits_truncated': self.hits_truncated, 'findings': self.findings,
            'patterns': self.patterns, 'incomplete': self.incomplete,
        }


class JsonJoin:
    """Concatenates JSON string values per key name and overall, so a secret split over stream deltas is reassembled."""

    MAX_KEYS = 256

    def __init__(self, compiled):
        self.compiled = compiled
        self.by_key = {}
        self.everything = Matcher(compiled)

    def _matcher(self, key):
        matcher = self.by_key.get(key)
        if matcher is None:
            if len(self.by_key) >= self.MAX_KEYS:
                return self.everything
            matcher = self.by_key[key] = Matcher(self.compiled)
        return matcher

    def feed_record(self, node, key=''):
        if isinstance(node, str):
            data = node.encode('utf-8', 'replace')
            self._matcher(key).feed(data)
            self.everything.feed(data)
        elif isinstance(node, dict):
            for name, item in node.items():
                self.feed_record(item, str(name))
        elif isinstance(node, list):
            for item in node:
                self.feed_record(item, key)

    @property
    def found(self):
        merged = {}
        for matcher in (self.everything, *self.by_key.values()):
            for pid, (count, offset) in matcher.found.items():
                entry = merged.setdefault(pid, [0, offset])
                entry[0] += count
                entry[1] = min(entry[1], offset)
        return merged


class ImageScope:
    """Collects what an image export (docker save tar/directory, OCI layout) says it contains."""

    def __init__(self):
        self.names = {}
        self.blobs = {}
        self.json = {}

    def note(self, name, size, digest, captured):
        self.names[name] = size
        if digest is not None:
            self.blobs[name] = digest
        if captured is not None:
            self.json[name] = bytes(captured)

    def recognised(self):
        if 'oci-layout' in self.names and 'index.json' in self.names:
            return True
        manifest = self._load('manifest.json')
        return isinstance(manifest, list) and bool(manifest) and all(isinstance(item, dict) and 'Layers' in item for item in manifest)

    def _load(self, name):
        data = self.json.get(name)
        if data is None:
            return None
        try:
            return json.loads(data)
        except ValueError:
            return None


# ----------------------------------------------------------------------------------------------------------
# The scanner
# ----------------------------------------------------------------------------------------------------------

class Scanner:
    def __init__(self, canaries, *, allowlist=(), max_depth=10, max_bytes=1024 ** 4, max_entries=5_000_000,
                 shapes=True, class_globs=(), excludes=(), scratch=None):
        self.canary_sources = canaries
        self.patterns = build_patterns(canaries)
        self.compiled = Compiled(self.patterns)
        self.allowlist = list(allowlist)
        self.used_allow = set()
        self.max_depth, self.max_entries = max_depth, max_entries
        self.budget = Budget(max_bytes)
        self.shapes = shapes
        self.class_globs = list(class_globs)
        self.excludes = list(excludes)
        self.excluded = []
        self.scratch = scratch
        self.zstd = zstd_backend()
        self.artifacts = []
        self.global_incomplete = []
        self.totals = collections.Counter()
        self.redactions = sorted({p.data for p in self.patterns}, key=len, reverse=True)
        self.by_pid = {p.pid: p for p in self.patterns}
        self.databases = []
        self.backup_leaves = []
        self.leaf_sha = None
        self.hash_leaves = any(entry.get('sha256') for entry in self.allowlist)

    # -- output hygiene -----------------------------------------------------------------------------------------
    def safe(self, text):
        data = text.encode('utf-8', 'surrogateescape')
        for pattern in self.redactions:
            if pattern in data:
                data = data.replace(pattern, b'<canary>')
        text = data.decode('utf-8', 'replace')
        return ''.join(ch if ch.isprintable() else '?' for ch in text)[:400]

    # -- allowlist ----------------------------------------------------------------------------------------------
    def allowed(self, kind, ident, location):
        for index, entry in enumerate(self.allowlist):
            if entry['kind'] == kind and entry['id'] in ('*', ident) and fnmatch.fnmatch(location, entry['path']):
                if entry.get('sha256') and entry['sha256'].lower() != self.leaf_sha:
                    continue
                self.used_allow.add(index)
                return entry['reason']
        return None

    # -- recording ----------------------------------------------------------------------------------------------
    def record_hit(self, art, pattern, location, offset, count, encoding):
        safe_location = self.safe(location)
        reason = self.allowed('canary', pattern.cid, safe_location)
        if len(art.hits) >= HIT_CAP:
            art.hits_truncated += 1
            return
        art.hits.append({'canary': pattern.cid, 'source': pattern.kind, 'encoding': encoding, 'location': safe_location,
                         'offset': offset, 'count': count, 'allowlisted': reason is not None, 'reason': reason})

    def record_finding(self, art, kind, ident, location, detail=''):
        safe_location = self.safe(location)
        reason = self.allowed(kind, ident, safe_location)
        art.findings.append({'kind': kind, 'id': ident, 'location': safe_location, 'detail': detail,
                             'allowlisted': reason is not None, 'reason': reason})

    def record_pattern(self, art, name, location, offset, count, prefix):
        safe_location = self.safe(location)
        reason = self.allowed('pattern', name, safe_location)
        art.patterns.append({'pattern': name, 'location': safe_location, 'offset': offset, 'count': count,
                             'sha256_prefix': prefix, 'allowlisted': reason is not None, 'reason': reason})

    def check_name(self, art, location, component, seen):
        rule = forbidden_rule(component)
        if rule is None:
            return
        key = (rule, location)
        if key in seen:
            return
        seen.add(key)
        self.record_finding(art, 'forbidden-name', rule, location)

    def check_path(self, art, container, name, seen):
        """Check every component of an archive member path; `container` is where the archive itself lives."""
        parts = [part for part in name.replace('\\', '/').split('/') if part not in ('', '.', '..')]
        for index, part in enumerate(parts):
            self.check_name(art, f'{container}!{"/".join(parts[:index + 1])}', part, seen)

    # -- entry points -------------------------------------------------------------------------------------------
    def excluded_by(self, rel, path):
        for glob in self.excludes:
            if fnmatch.fnmatch(rel, glob) or fnmatch.fnmatch(path, glob):
                return glob
        return None

    def scan_target(self, root):
        if not os.path.lexists(root):
            self.global_incomplete.append({'reason': 'path_missing', 'location': self.safe(root), 'detail': ''})
            return
        base = os.path.basename(root.rstrip('/')) or root
        if os.path.isdir(root) and not os.path.islink(root):
            self.walk(root, root, base)
        else:
            self.scan_path(root, base, root)

    def walk(self, root, directory, label):
        try:
            entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
        except OSError as error:
            art = Artifact(directory, self.safe(os.path.relpath(directory, root)))
            art.add_incomplete('unreadable', art.loc, type(error).__name__)
            self.artifacts.append(art)
            return
        for entry in entries:
            rel = os.path.relpath(entry.path, root)
            glob = self.excluded_by(rel, entry.path)
            if glob:
                self.excluded.append({'path': self.safe(rel), 'glob': glob})
                continue
            if entry.is_dir(follow_symlinks=False):
                rule = forbidden_rule(entry.name)
                if rule:
                    art = Artifact(entry.path, self.safe(rel))
                    art.kind = 'directory'
                    self.record_finding(art, 'forbidden-name', rule, rel)
                    self.artifacts.append(art)
                if os.path.isfile(os.path.join(entry.path, 'oci-layout')) and os.path.isfile(os.path.join(entry.path, 'index.json')):
                    self.scan_oci_directory(entry.path, rel)
                else:
                    self.walk(root, entry.path, label)
            else:
                self.scan_path(entry.path, rel, root)

    def scan_oci_directory(self, directory, rel):
        scope = ImageScope()
        art = Artifact(directory, self.safe(rel))
        art.kind = 'image-directory'
        self.artifacts.append(art)
        self.walk_image_dir(directory, directory, rel, scope, art)
        self.finish_image(scope, art, rel)

    def walk_image_dir(self, top, directory, rel, scope, image_art):
        for entry in sorted(os.scandir(directory), key=lambda item: item.name):
            sub = os.path.relpath(entry.path, top)
            if entry.is_dir(follow_symlinks=False):
                self.walk_image_dir(top, entry.path, rel, scope, image_art)
                continue
            self.scan_path(entry.path, f'{rel}/{sub}', top, scope=scope, member_name=sub.replace(os.sep, '/'))

    def scan_path(self, path, loc, root, scope=None, member_name=None):
        art = Artifact(path, self.safe(loc))
        self.artifacts.append(art)
        seen = set()
        try:
            info = os.lstat(path)
            self.check_name(art, loc, os.path.basename(path), seen)
            self.scan_text(art, loc.encode('utf-8', 'surrogateescape'), loc)
            if stat.S_ISLNK(info.st_mode):
                art.kind = 'symlink'
                art.files += 1
                art.entries += 1
                self.totals['files'] += 1
                self.scan_text(art, os.readlink(path).encode('utf-8', 'surrogateescape'), loc + '->')
                return
            if not stat.S_ISREG(info.st_mode):
                art.kind = 'special'
                art.add_incomplete('special_file', art.loc, stat.filemode(info.st_mode))
                return
            art.kind = 'file'
            with open(path, 'rb') as handle:
                source = PeekReader(Counting(handle, self.budget))
                member = None
                if scope is not None and member_name is not None:
                    member = MemberReader(source, info.st_size, hashed=member_name.startswith('blobs/sha256/'),
                                          capture=SMALL_JSON_LIMIT if member_name.endswith('.json') or member_name.startswith('blobs/sha256/') else 0)
                    source = PeekReader(member)
                self.scan_stream(source, loc, 0, art, os.path.basename(path), top=True, seen=seen)
                if member is not None:
                    member.finish()
                    scope.note(member_name, info.st_size, member.digest, member.captured)
        except StreamError as error:
            art.add_incomplete(error.reason, art.loc, error.detail)
        except Incomplete as error:
            art.add_incomplete(error.reason, art.loc, error.detail)
        except PermissionError:
            art.add_incomplete('unreadable', art.loc, 'permission denied')
        except OSError as error:
            art.add_incomplete('unreadable', art.loc, type(error).__name__)
        except Exception as error:  # fail closed on anything unexpected
            art.add_incomplete('scanner_error', art.loc, type(error).__name__)

    def scan_docker_image(self, ref):
        directory = tempfile.mkdtemp(prefix='canary-scan-image-', dir=self.scratch)
        export = os.path.join(directory, 'image.tar')
        try:
            try:
                done = subprocess.run(['docker', 'save', '-o', export, ref], capture_output=True, timeout=1800)
            except (OSError, subprocess.SubprocessError) as error:
                self.global_incomplete.append({'reason': 'docker_save_failed', 'location': self.safe(ref), 'detail': type(error).__name__})
                return
            if done.returncode != 0 or not os.path.isfile(export):
                self.global_incomplete.append({'reason': 'docker_save_failed', 'location': self.safe(ref), 'detail': f'exit {done.returncode}'})
                return
            self.scan_path(export, f'docker:{ref}', directory)
        finally:
            shutil.rmtree(directory, ignore_errors=True)

    # -- stream scanning ----------------------------------------------------------------------------------------
    def scan_text(self, art, data, location):
        matcher = Matcher(self.compiled)
        matcher.feed(data)
        self.collect(art, matcher, location, None)
        art.bytes += len(data)
        self.totals['bytes_scanned'] += len(data)

    def collect(self, art, matcher, location, suffix, exclude=()):
        for pid, (count, offset) in matcher.found.items():
            if pid in exclude:
                continue
            pattern = self.by_pid[pid]
            if suffix == 'json-joined':
                encoding = 'json-joined'
            elif suffix:
                encoding = '|'.join(label + suffix for label in pattern.labels)
            else:
                encoding = '|'.join(pattern.labels)
            self.record_hit(art, pattern, location, offset, count, encoding)

    def scan_stream(self, stream, loc, depth, art, name, top=False, seen=None, scope=None):
        if depth > self.max_depth:
            raise Incomplete('depth_limit_exceeded', f'deeper than {self.max_depth}')
        art.max_depth = max(art.max_depth, depth)
        head = stream.peek(HEAD)
        kind = sniff(head)
        art.formats.add(kind.split(':')[0])
        if seen is None:
            seen = set()
        if kind.startswith('unsupported:'):
            raise Incomplete('unsupported_container', kind.split(':', 1)[1])
        if kind in ('gz', 'bz2', 'xz', 'zst'):
            self.totals['archives'] += 1
            self.scan_text(art, head[:512], loc + '!header')
            inner = Decompressor(stream, kind, self)
            inner_name = name[:name.rfind('.')] if name and '.' in name else name
            child = PeekReader(inner)
            self.scan_stream(child, f'{loc}!{kind}', depth + 1, art, inner_name, seen=seen)
            self.drain(child, art, loc, kind)
        elif kind == 'tar':
            self.totals['archives'] += 1
            self.scan_tar(stream, loc, depth, art, seen)
        elif kind == 'zip':
            self.totals['archives'] += 1
            self.scan_zip(stream, loc, depth, art, seen)
        elif kind == 'ar':
            self.totals['archives'] += 1
            self.scan_ar(stream, loc, depth, art, seen)
        else:
            self.scan_leaf(stream, loc, kind, head, name, depth, art, top)

    def drain(self, child, art, loc, kind):
        """Read the rest of a decompressed stream so truncation and CRC errors surface, and scan what is left."""
        extra = bytearray()
        total = 0
        while True:
            block = child.read(CHUNK)
            if not block:
                break
            total += len(block)
            if block.strip(b'\0'):
                extra += block
        if extra:
            self.scan_text(art, bytes(extra), f'{loc}!{kind}!trailing')
            raise Incomplete('trailing_data', 'non-zero bytes after the end of an archive')

    def count_entry(self, art):
        art.entries += 1
        if art.entries > self.max_entries:
            raise StreamError('entry_limit_exceeded', f'more than {self.max_entries} entries')

    def scan_tar(self, stream, loc, depth, art, seen):
        tap = TapReader(stream)
        scope = ImageScope()
        try:
            archive = tarfile.open(fileobj=tap, mode='r|', bufsize=CHUNK, errorlevel=2)
        except (tarfile.TarError, OSError, EOFError, ValueError) as error:
            raise StreamError('archive_corrupt', type(error).__name__)
        try:
            for member in archive:
                self.count_entry(art)
                name = member.name
                member_loc = f'{loc}!{name}'
                self.check_path(art, loc, name, seen)
                for text in (name, member.linkname, member.uname, member.gname, *member.pax_headers.values()):
                    if text:
                        self.scan_text(art, text.encode('utf-8', 'surrogateescape'), member_loc)
                if member.isreg():
                    handle = archive.extractfile(member)
                    names = name.removeprefix('./')
                    wants_hash = names.startswith('blobs/sha256/') or names.endswith('layer.tar')
                    capture = SMALL_JSON_LIMIT if names.endswith('.json') or names.startswith('blobs/sha256/') else 0
                    reader = MemberReader(handle, member.size, hashed=wants_hash, capture=capture)
                    try:
                        self.scan_stream(PeekReader(reader), member_loc, depth + 1, art, os.path.basename(name), seen=seen)
                    except StreamError:
                        raise
                    except Incomplete as error:
                        art.add_incomplete(error.reason, self.safe(member_loc), error.detail)
                    self.skip_rest(reader)
                    try:
                        reader.finish()
                    except Incomplete as error:
                        art.add_incomplete(error.reason, self.safe(member_loc), error.detail)
                    scope.note(names, member.size, reader.digest, reader.captured)
                elif member.issym() or member.islnk():
                    scope.names[name.removeprefix('./')] = 0
                else:
                    scope.names[name.removeprefix('./')] = 0
        except StreamError:
            raise
        except (tarfile.TarError, OSError, EOFError, ValueError, zlib.error, lzma.LZMAError) as error:
            raise StreamError('archive_corrupt', type(error).__name__)
        # tarfile ends silently at an empty, truncated or invalid header; only a full all-zero block is an end marker.
        if tap.block_at(archive.offset, tarfile.BLOCKSIZE) != b'\0' * tarfile.BLOCKSIZE:
            raise StreamError('tar_end_marker_missing', 'the archive does not end with a tar end-of-archive block')
        left = getattr(archive.fileobj, 'buf', None)
        if left is None:
            raise StreamError('tar_reader_changed', 'cannot inspect read-ahead')
        if left.strip(b'\0'):
            self.scan_text(art, bytes(left), f'{loc}!trailing')
            raise Incomplete('trailing_data', 'non-zero bytes after the end of the tar archive')
        trailing = bytearray()
        while True:
            block = stream.read(CHUNK)
            if not block:
                break
            if block.strip(b'\0'):
                trailing += block
        if trailing:
            self.scan_text(art, bytes(trailing), f'{loc}!trailing')
            raise Incomplete('trailing_data', 'non-zero bytes after the end of the tar archive')
        if scope.recognised():
            self.finish_image(scope, art, loc)

    @staticmethod
    def skip_rest(reader):
        while reader.read(CHUNK):
            pass

    def scan_zip(self, stream, loc, depth, art, seen):
        try:
            self._scan_zip(stream, loc, depth, art, seen)
        except Incomplete:
            raise
        except Exception as error:  # a damaged central directory can raise nearly anything
            raise StreamError('archive_corrupt', type(error).__name__)

    def _scan_zip(self, stream, loc, depth, art, seen):
        spool = tempfile.SpooledTemporaryFile(max_size=64 * 1024 * 1024, dir=self.scratch)
        try:
            while True:
                block = stream.read(CHUNK)
                if not block:
                    break
                spool.write(block)
            spool.seek(0)
            try:
                archive = zipfile.ZipFile(spool)
            except (zipfile.BadZipFile, OSError, ValueError) as error:
                raise StreamError('archive_corrupt', type(error).__name__)
            if archive.comment:
                self.scan_text(art, archive.comment, f'{loc}!comment')
            for info in archive.infolist():
                self.count_entry(art)
                member_loc = f'{loc}!{info.filename}'
                self.check_path(art, loc, info.filename, seen)
                self.scan_text(art, info.filename.encode('utf-8', 'surrogateescape'), member_loc)
                if info.comment:
                    self.scan_text(art, info.comment, member_loc)
                if info.flag_bits & 0x1:
                    raise StreamError('encrypted_member', 'password-protected zip member')
                if info.is_dir():
                    continue
                try:
                    with archive.open(info) as handle:
                        reader = MemberReader(Counting(handle, self.budget), info.file_size)
                        self.scan_stream(PeekReader(reader), member_loc, depth + 1, art, os.path.basename(info.filename), seen=seen)
                        self.skip_rest(reader)
                        reader.finish()
                except StreamError:
                    raise
                except Incomplete as error:
                    art.add_incomplete(error.reason, self.safe(member_loc), error.detail)
                except (zipfile.BadZipFile, NotImplementedError, RuntimeError, zlib.error, OSError, EOFError) as error:
                    raise StreamError('archive_corrupt', type(error).__name__)
        finally:
            spool.close()

    def scan_ar(self, stream, loc, depth, art, seen):
        try:
            self._scan_ar(stream, loc, depth, art, seen)
        except Incomplete:
            raise
        except Exception as error:
            raise StreamError('archive_corrupt', type(error).__name__)

    def _scan_ar(self, stream, loc, depth, art, seen):
        magic = stream.read(8)
        if magic != b'!<arch>\n':
            raise StreamError('archive_corrupt', 'bad ar magic')
        while True:
            header = self.read_exact(stream, 60, allow_empty=True)
            if header is None:
                break
            if header[58:60] != b'`\n':
                raise StreamError('archive_corrupt', 'bad ar member header')
            self.count_entry(art)
            name = header[:16].decode('utf-8', 'replace').strip()
            try:
                size = int(header[48:58].decode().strip())
            except ValueError:
                raise StreamError('archive_corrupt', 'bad ar member size')
            member_loc = f'{loc}!{name}'
            self.scan_text(art, header[:16], member_loc)
            reader = MemberReader(stream, size)
            try:
                self.scan_stream(PeekReader(_Limited(reader, size)), member_loc, depth + 1, art, name.rstrip('/'), seen=seen)
            except StreamError:
                raise
            except Incomplete as error:
                art.add_incomplete(error.reason, self.safe(member_loc), error.detail)
            remaining = size - reader.count
            while remaining > 0:
                block = stream.read(min(remaining, CHUNK))
                if not block:
                    raise StreamError('archive_corrupt', 'truncated ar member')
                remaining -= len(block)
            if size % 2:
                self.read_exact(stream, 1)

    @staticmethod
    def read_exact(stream, count, allow_empty=False):
        data = b''
        while len(data) < count:
            block = stream.read(count - len(data))
            if not block:
                if allow_empty and not data:
                    return None
                raise StreamError('archive_corrupt', 'truncated archive')
            data += block
        return data

    # -- leaves -------------------------------------------------------------------------------------------------
    def scan_leaf(self, stream, loc, kind, head, name, depth, art, top):
        cls = classify(name, kind, self.class_globs)
        art.files += 1
        self.totals['files'] += 1
        text_like = b'\0' not in head[:4096]
        lowered = (name or '').lower()
        jsonl = lowered.endswith(('.jsonl', '.ndjson'))
        matcher = Matcher(self.compiled)
        leaf_hash = hashlib.sha256() if self.hash_leaves else None
        shapes = ShapeScanner() if self.shapes else None
        wrapped = Matcher(self.compiled) if text_like and self.patterns else None
        joined = JsonJoin(self.compiled) if jsonl else None
        line = bytearray()
        parsed_lines = 0
        counts = collections.Counter()
        sampled = 0
        total = 0
        db_magic = None
        if head.startswith(b'SQLite format 3\0'):
            db_magic = 'sqlite'
        elif head.startswith(b'PGDMP'):
            db_magic = 'pgdump'
        while True:
            chunk = stream.read(CHUNK)
            if not chunk:
                break
            total += len(chunk)
            if leaf_hash is not None:
                leaf_hash.update(chunk)
            lead = self.compiled.overlap + 1
            if len(chunk) >= 4 * lead + 4096 and chunk.count(0) == len(chunk):
                # A core dump is mostly untouched pages. No pattern is made of zeros alone, so an all-zero chunk can
                # only complete or start a match at its edges: feed the leading bytes, skip the rest.
                matcher.feed(chunk[:lead])
                matcher.skip_zeros(len(chunk) - lead)
                if shapes is not None:
                    shapes.skip_zeros(len(chunk))
                if wrapped is not None:
                    wrapped.feed(chunk[:lead].translate(None, b'\r\n\t '))
                    wrapped.skip_zeros(len(chunk) - lead)
                self.totals['zero_bytes_skipped'] += len(chunk) - lead
                if cls == 'backup':
                    counts.update(chunk[:65536])
                    sampled += min(len(chunk), 65536)
                continue
            matcher.feed(chunk)
            if shapes is not None:
                shapes.feed(chunk)
            if wrapped is not None:
                wrapped.feed(chunk.translate(None, b'\r\n\t '))
            if cls == 'backup' and sampled < 16 * CHUNK:
                window = chunk[4096:4096 + 65536] if total == len(chunk) else chunk[:65536]
                counts.update(window)
                sampled += len(window)
            if joined is not None:
                line += chunk
                while True:
                    cut = line.find(b'\n')
                    if cut < 0:
                        break
                    parsed_lines += self.join_json(bytes(line[:cut]), joined)
                    del line[:cut + 1]
                if len(line) > 256 * 1024 * 1024:
                    raise Incomplete('line_too_long', 'JSON line over 256 MiB')
        if joined is not None and line:
            parsed_lines += self.join_json(bytes(line), joined)
        art.bytes += total
        self.totals['bytes_scanned'] += total
        if cls:
            art.classes[cls] += 1
            self.totals[{'backup': 'backups', 'dump': 'dumps', 'transcript': 'transcripts', 'log': 'logs'}[cls]] += 1
        self.leaf_sha = leaf_hash.hexdigest() if leaf_hash is not None else None
        self.collect(art, matcher, loc, None)
        if wrapped is not None:
            self.collect(art, wrapped, loc, '+wrapped', exclude=set(matcher.found))
        if joined is not None:
            self.collect(art, joined, loc, 'json-joined', exclude=set(matcher.found))
        if shapes is not None:
            for pattern_name, (count, offset, prefix) in shapes.found.items():
                self.record_pattern(art, pattern_name, loc, offset, count, prefix)
        if total == 0 and top and cls in ('backup', 'dump', 'transcript', 'log'):
            art.add_incomplete('empty_artifact', art.loc, f'empty {cls}')
        if jsonl and total and parsed_lines == 0:
            art.add_incomplete('transcript_not_json', art.loc, 'no line parsed as JSON')
        self.leaf_sha = None
        if db_magic:
            self.databases.append((art, loc, db_magic))
        if cls == 'backup':
            self.check_backup(art, loc, name, head, total, counts, sampled)

    @staticmethod
    def join_json(line, joined):
        line = line.strip()
        if not line:
            return 0
        try:
            value = json.loads(line)
        except ValueError:
            return 0
        joined.feed_record(value)
        return 1

    def check_backup(self, art, loc, name, head, total, counts, sampled):
        self.backup_leaves.append(loc)
        base = (name or '').lower()
        required = base.endswith(('.bpbackup', '.cms', '.p7m'))
        if not (head[:1] == b'\x30' and CMS_OID in head[:16]):
            if required:
                self.record_finding(art, 'backup-not-cms', 'cms', loc, 'backup file is not a CMS envelope')
            return
        marker = head[1]
        if marker < 0x80:
            length, header = marker, 2
        elif marker == 0x80 or (marker & 0x7f) > 4:
            raise Incomplete('backup_envelope_length_mismatch', 'indefinite or oversized DER length')
        else:
            width = marker & 0x7f
            length, header = int.from_bytes(head[2:2 + width], 'big'), 2 + width
        if header + length != total:
            raise Incomplete('backup_envelope_length_mismatch', f'DER says {header + length} bytes, file has {total}')
        if sampled < 8192:
            raise Incomplete('backup_too_small', f'only {sampled} bytes after the envelope header')
        entropy = -sum((c / sampled) * math.log2(c / sampled) for c in counts.values())
        floor = 7.9 if sampled >= 32768 else 7.8
        if entropy < floor:
            self.record_finding(art, 'backup-not-ciphertext', 'entropy', loc, f'entropy {entropy:.2f} bits/byte is below {floor}')

    # -- images -------------------------------------------------------------------------------------------------
    def finish_image(self, scope, art, loc):
        if not scope.recognised():
            return
        self.totals['images'] += 1
        layers = set()
        missing = []
        for name, digest in scope.blobs.items():
            if name.startswith('blobs/sha256/') and name.split('/')[-1] != digest:
                art.add_incomplete('image_blob_digest_mismatch', self.safe(f'{loc}!{name}'), 'content does not match its digest name')
        manifest = scope._load('manifest.json')
        if isinstance(manifest, list) and manifest and all(isinstance(item, dict) for item in manifest):
            for item in manifest:
                for ref in [item.get('Config')] + list(item.get('Layers') or []):
                    if ref and ref.removeprefix('./') not in scope.names:
                        missing.append(ref)
                for ref in item.get('Layers') or []:
                    layers.add(ref)
                config = scope._load((item.get('Config') or '').removeprefix('./'))
                self.check_image_config(config, art, loc)
        if 'oci-layout' in scope.names and 'index.json' in scope.names:
            self.walk_oci_index(scope, art, loc, layers, missing)
        for ref in missing:
            art.add_incomplete('image_layer_missing', self.safe(f'{loc}!{ref}'), 'referenced content is not in the export')
        self.totals['image_layers'] += len(layers)

    def walk_oci_index(self, scope, art, loc, layers, missing):
        pending = [scope._load('index.json')]
        seen = set()
        while pending:
            node = pending.pop()
            if not isinstance(node, dict):
                continue
            for descriptor in node.get('manifests') or []:
                digest = (descriptor.get('digest') or '').split(':')[-1]
                blob = f'blobs/sha256/{digest}'
                if blob in seen:
                    continue
                seen.add(blob)
                if blob not in scope.names:
                    missing.append(blob)
                    continue
                child = scope._load(blob)
                if isinstance(child, dict) and 'manifests' in child:
                    pending.append(child)
                elif isinstance(child, dict):
                    config_digest = ((child.get('config') or {}).get('digest') or '').split(':')[-1]
                    if config_digest:
                        config_blob = f'blobs/sha256/{config_digest}'
                        if config_blob not in scope.names:
                            missing.append(config_blob)
                        else:
                            self.check_image_config(scope._load(config_blob), art, loc)
                    for layer in child.get('layers') or []:
                        layer_blob = 'blobs/sha256/' + (layer.get('digest') or '').split(':')[-1]
                        layers.add(layer_blob)
                        if layer_blob not in scope.names:
                            missing.append(layer_blob)

    def check_image_config(self, config, art, loc):
        if not isinstance(config, dict):
            return
        inner = config.get('config') or {}
        for entry in inner.get('Env') or []:
            name, _, value = str(entry).partition('=')
            if secret_assignment(name, value):
                digest = hashlib.sha256(value.encode()).hexdigest()[:8]
                self.record_finding(art, 'image-env-secret', name, f'{loc}!config.Env', f'value sha256 prefix {digest}')
        for item in config.get('history') or []:
            created = str(item.get('created_by') or '')
            for match in ENV_ASSIGNMENT.finditer(created):
                if secret_assignment(match.group(1), match.group(2)):
                    digest = hashlib.sha256(match.group(2).strip('"\'').encode()).hexdigest()[:8]
                    self.record_finding(art, 'image-history-secret', match.group(1), f'{loc}!config.history', f'value sha256 prefix {digest}')

    @staticmethod
    def parent(location):
        if '/' in location:
            return location.rsplit('/', 1)[0]
        return location.rsplit('!', 1)[0] if '!' in location else ''

    def finalize_backup_neighbours(self):
        """A plaintext database in a backup's directory, or in a staging directory directly below it, is residue."""
        backup_dirs = {self.parent(location) for location in self.backup_leaves}
        for art, loc, kind in self.databases:
            here = self.parent(loc)
            if here in backup_dirs or self.parent(here) in backup_dirs:
                self.record_finding(art, 'plaintext-database-next-to-backup', kind, loc, 'a plaintext database sits beside an encrypted backup')


class _Limited:
    def __init__(self, inner, size):
        self.inner, self.left = inner, size

    def read(self, count=-1):
        if self.left <= 0:
            return b''
        data = self.inner.read(min(count if count and count > 0 else CHUNK, self.left))
        self.left -= len(data)
        return data


# ----------------------------------------------------------------------------------------------------------
# Positive controls
# ----------------------------------------------------------------------------------------------------------

def _gzip(data):
    import gzip
    return gzip.compress(data)


def _zstd(data):
    try:
        from compression import zstd
        return zstd.compress(data)
    except ImportError:
        return subprocess.run(['zstd', '-q', '-c'], input=data, capture_output=True, check=True).stdout


def _tar(token):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w') as archive:
        info = tarfile.TarInfo('control.txt')
        data = b'aa ' + token
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def _zip(token):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('control.txt', b'zz ' + token)
    return buffer.getvalue()


def _ar(token):
    body = b'ar ' + token
    header = b'control.txt/    ' + b'0           0     0     100644  ' + str(len(body)).encode().ljust(10) + b'`\n'
    return b'!<arch>\n' + header + body + (b'\n' if len(body) % 2 else b'')


def _jsonl(token):
    half = len(token) // 2
    return (json.dumps({'type': 'delta', 'text': token[:half].decode()}) + '\n'
            + json.dumps({'type': 'delta', 'text': token[half:].decode()}) + '\n').encode()


def _wrapped(token):
    return token[:9] + b'\r\n' + token[9:] + b'\n'


CONTROL_BUILDERS = {
    'tar': ('tar', _tar), 'gz': ('gz', lambda t: _gzip(b'xx ' + t)), 'bz2': ('bz2', lambda t: bz2.compress(b'xx ' + t)),
    'xz': ('xz', lambda t: lzma.compress(b'xx ' + t)), 'zip': ('zip', _zip), 'ar': ('ar', _ar),
    'jsonl': ('jsonl', _jsonl), 'wrapped': ('log', _wrapped), 'tar.gz': ('tgz', lambda t: _gzip(_tar(t))),
    'zst': ('zst', lambda t: _zstd(b'yy ' + t)),
}


def run_controls(scanner_kwargs, scratch):
    """Exercise the real pipeline on generated artifacts before trusting it with real ones.

    Each control is a container or encoding the scanner claims to support. The scanner must find a planted
    token in it and must not report a same-length different token planted in a twin.
    """
    token = ('P07-SCAN-CONTROL-' + secrets.token_hex(12)).encode()
    other = ('P07-SCAN-CONTROL-' + secrets.token_hex(12)).encode()
    directory = tempfile.mkdtemp(prefix='canary-scan-control-', dir=scratch)
    results = {'ok': True, 'detected': [], 'unavailable': [], 'failed': [], 'zstd_backend': zstd_backend()}
    try:
        for label, (suffix, build) in CONTROL_BUILDERS.items():
            if label == 'zst' and results['zstd_backend'] == 'none':
                results['unavailable'].append('zst')
                continue
            paths = {}
            for which, value in (('planted', token), ('twin', other)):
                path = os.path.join(directory, f'control-{label}-{which}.{suffix}')
                with open(path, 'wb') as handle:
                    handle.write(build(value))
                paths[which] = path
            outcome = {}
            for which, path in paths.items():
                probe = Scanner([('control', token)], **scanner_kwargs)
                probe.scan_path(path, path, directory)
                outcome[which] = probe.artifacts
            found = any(art.hits for art in outcome['planted']) and not any(art.incomplete for art in outcome['planted'])
            quiet = not any(art.hits for art in outcome['twin']) and not any(art.incomplete for art in outcome['twin'])
            (results['detected'] if found and quiet else results['failed']).append(label)
        results['ok'] = not results['failed']
    finally:
        shutil.rmtree(directory, ignore_errors=True)
    return results


# ----------------------------------------------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------------------------------------------

def check_canary(value, source):
    if len(value) < MIN_CANARY_BYTES or len(set(value)) < MIN_DISTINCT_BYTES:
        raise ConfigError(f'{source}: a canary must be at least {MIN_CANARY_BYTES} bytes with at least {MIN_DISTINCT_BYTES} distinct bytes')


def load_canaries(path):
    try:
        raw = open(path, 'rb').read()
    except OSError as error:
        raise ConfigError(f'cannot read the canary list: {type(error).__name__}')
    values = []
    stripped = raw.lstrip()
    if stripped.startswith(b'['):
        try:
            decoded = json.loads(raw.decode('utf-8'))
        except ValueError:
            raise ConfigError('the canary list looks like JSON but is not valid JSON')
        if not isinstance(decoded, list) or not all(isinstance(item, str) for item in decoded):
            raise ConfigError('a JSON canary list must be an array of strings')
        values = [item.encode('utf-8') for item in decoded]
    else:
        for line in raw.split(b'\n'):
            line = line.rstrip(b'\r')
            if line:
                values.append(line)
    if not values:
        raise ConfigError('the canary list is empty: a scan with nothing to look for proves nothing')
    for value in values:
        check_canary(value, 'canary list')
    return [('canary', value) for value in dict.fromkeys(values)]


def load_key_material(path):
    try:
        raw = open(path, 'rb').read()
    except OSError as error:
        raise ConfigError(f'cannot read key material: {type(error).__name__}')
    if len(raw) > 64 * 1024:
        raise ConfigError('key material files are limited to 64 KiB')
    if raw.lstrip().startswith(b'-----BEGIN'):
        body = [line.strip() for line in raw.splitlines() if line.strip() and not line.startswith(b'-----')]
        body = [line for line in body if len(line) >= 32]
        if not body:
            raise ConfigError('key material PEM has no usable body lines')
        picks = [body[0], body[len(body) // 2], body[-1]]
        return [('key', pick) for pick in dict.fromkeys(picks)]
    value = raw.rstrip(b'\n') if raw.endswith(b'\n') and b'\0' not in raw else raw
    if len(value) < 16 or len(set(value)) < MIN_DISTINCT_BYTES:
        raise ConfigError('key material must be at least 16 bytes with at least 8 distinct bytes')
    return [('key', value)]


def load_allowlist(path):
    try:
        entries = json.loads(open(path, encoding='utf-8').read())
    except (OSError, ValueError) as error:
        raise ConfigError(f'cannot read the allowlist: {type(error).__name__}')
    if not isinstance(entries, list):
        raise ConfigError('the allowlist must be a JSON array')
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict) or not all(isinstance(entry.get(key), str) for key in ('kind', 'id', 'path', 'reason')):
            raise ConfigError(f'allowlist entry {index} needs string kind, id, path and reason')
        if len(entry['reason'].strip()) < MIN_REASON:
            raise ConfigError(f'allowlist entry {index} needs a reason of at least {MIN_REASON} characters')
        if not entry['kind'] or not entry['id'] or not entry['path']:
            raise ConfigError(f'allowlist entry {index} has an empty kind, id or path')
        if 'sha256' in entry and not (isinstance(entry['sha256'], str) and re.fullmatch(r'[0-9a-fA-F]{64}', entry['sha256'])):
            raise ConfigError(f'allowlist entry {index} has a malformed sha256 (64 hex characters of the exact file content)')
    return entries


def generate_canaries(path, count):
    if count < 1 or count > 100:
        raise ConfigError('--count must be between 1 and 100')
    punctuation = '!#$%&()*+,-./:;<=>?@[]^_{|}~'
    alnum = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    values = []
    for index in range(count):
        kind = index % 4
        if kind == 0:
            body = secrets.token_hex(16)
        elif kind == 1:
            body = ''.join(secrets.choice(alnum + '+/=') for _ in range(24))
        elif kind == 2:
            body = ''.join(secrets.choice(alnum + punctuation + '"\\\'') for _ in range(24))
        else:
            body = ''.join(secrets.choice(alnum + 'éüñ') for _ in range(20))
        values.append('P07-CANARY-' + body)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as error:
        raise ConfigError(f'cannot create the canary file (it must not exist): {type(error).__name__}')
    with os.fdopen(descriptor, 'w', encoding='utf-8') as handle:
        handle.write('\n'.join(values) + '\n')


# ----------------------------------------------------------------------------------------------------------
# Command line
# ----------------------------------------------------------------------------------------------------------

def parser():
    ap = argparse.ArgumentParser(
        prog='canary-scan.sh',
        description='Fail-closed exposure scanner (P07-I04). Every byte of every PATH is looked at, archives and '
                    'images are unpacked, and anything that cannot be read, decoded or completed fails the run.',
        epilog='Exit codes: 0 clean, 1 exposure found, 2 configuration error, 3 incomplete scan. '
               'Requesting a class (--backups, --dumps, ...) fails the run when no such artifact is found.')
    ap.add_argument('paths', nargs='*', metavar='PATH', help='files or directories to scan (symlinks are never followed)')
    ap.add_argument('--canaries', metavar='FILE', help='canary list: one value per line, or a JSON array of strings')
    ap.add_argument('--generate-canaries', metavar='FILE', help='write fresh dummy canaries (mode 0600, refuses to overwrite) and exit')
    ap.add_argument('--count', type=int, default=8, help='number of canaries for --generate-canaries (default 8)')
    ap.add_argument('--key-material', action='append', default=[], metavar='FILE', help='file whose contents are secret key bytes (or a PEM key); searched in every encoding, never printed')
    for flag, text in (('archives', 'tar/zip/ar and gz/bz2/xz/zst containers, nested'), ('images', 'docker-save or OCI image exports'),
                       ('backups', 'P06 CMS backup envelopes'), ('dumps', 'core and crash dumps'),
                       ('transcripts', 'client transcripts (JSONL or text)'), ('logs', 'logs, journals and captured process listings')):
        ap.add_argument(f'--{flag}', action='store_true', help=f'require and check {text}')
    ap.add_argument('--docker-image', action='append', default=[], metavar='REF', help='docker save an existing local image, scan the export, delete it')
    ap.add_argument('--allowlist', metavar='FILE', help='JSON array of {kind,id,path,reason[,sha256]}; the optional sha256 pins the exact file content; an allowlisted hit is reported, never dropped')
    ap.add_argument('--strict-allowlist', action='store_true', help='treat unused allowlist entries as an incomplete scan')
    ap.add_argument('--exclude', action='append', default=[], metavar='GLOB', help='skip matching paths; every exclusion is listed in the report')
    ap.add_argument('--class-glob', action='append', default=[], metavar='CLASS=GLOB', help='classify extra file names (class: log, transcript, dump, backup)')
    ap.add_argument('--no-pattern-scan', action='store_true', help='skip the secret-shape scan (PEM, age, JWT, bearer, product tokens, signed links)')
    ap.add_argument('--report', metavar='FILE', help='write the JSON report here')
    ap.add_argument('--max-depth', type=int, default=10, help='archive nesting limit (default 10)')
    ap.add_argument('--max-bytes', type=int, default=1024 ** 4, help='bytes read from sources and decompressors per run (default 1 TiB; a Chromium core is 32 GiB)')
    ap.add_argument('--max-entries', type=int, default=5_000_000, help='archive entries per artifact (default 5000000)')
    return ap


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if args.generate_canaries:
            generate_canaries(args.generate_canaries, args.count)
            print(f'wrote {args.count} canaries to {args.generate_canaries} (mode 0600); values are not printed')
            return EXIT_PASS
        if not args.canaries and not args.key_material:
            raise ConfigError('--canaries FILE is required: a scan with nothing to look for proves nothing')
        sources = load_canaries(args.canaries) if args.canaries else []
        for path in args.key_material:
            sources += load_key_material(path)
        allowlist = load_allowlist(args.allowlist) if args.allowlist else []
        if not args.paths and not args.docker_image:
            raise ConfigError('give at least one PATH or --docker-image')
        class_globs = []
        for item in args.class_glob:
            cls, _, glob = item.partition('=')
            if cls not in ('log', 'transcript', 'dump', 'backup') or not glob:
                raise ConfigError('--class-glob must look like log=GLOB')
            class_globs.append((cls, glob))
    except ConfigError as error:
        print(f'canary-scan: {error}', file=sys.stderr)
        return EXIT_CONFIG

    def interrupted(number, frame):
        # SystemExit unwinds through the `finally` blocks, so an image export in scratch is removed, and the exit
        # code is "incomplete": a terminated scan is never a pass.
        print(f'canary-scan: interrupted by signal {number}; the scan is incomplete', file=sys.stderr)
        raise SystemExit(EXIT_INCOMPLETE)
    for number in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
        signal.signal(number, interrupted)

    scratch = os.environ.get('TMPDIR') or None
    kwargs = dict(allowlist=allowlist, max_depth=args.max_depth, max_bytes=args.max_bytes, max_entries=args.max_entries,
                  shapes=not args.no_pattern_scan, class_globs=class_globs, excludes=args.exclude, scratch=scratch)
    started = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    control_kwargs = dict(kwargs, allowlist=[], excludes=[], class_globs=class_globs, shapes=False, max_bytes=1 << 30)
    controls = run_controls(control_kwargs, scratch)
    scanner = Scanner(sources, **kwargs)
    if not controls['ok']:
        scanner.global_incomplete.append({'reason': 'scanner_control_failed', 'location': ','.join(controls['failed']), 'detail': 'the scanner did not find a planted control'})
    else:
        for ref in args.docker_image:
            scanner.scan_docker_image(ref)
        for path in args.paths:
            scanner.scan_target(path)
        scanner.finalize_backup_neighbours()

    requested = [name for name in ('archives', 'images', 'backups', 'dumps', 'transcripts', 'logs') if getattr(args, name)]
    needed = {'archives': ('archives', 'no_archive_found'), 'images': ('images', 'no_image_found'), 'backups': ('backups', 'no_backup_found'),
              'dumps': ('dumps', 'no_dump_found'), 'transcripts': ('transcripts', 'no_transcript_found'), 'logs': ('logs', 'no_log_found')}
    for name in requested:
        key, reason = needed[name]
        if scanner.totals[key] == 0:
            scanner.global_incomplete.append({'reason': reason, 'location': name, 'detail': f'--{name} was requested and no such artifact was scanned'})
    if scanner.totals['files'] == 0:
        scanner.global_incomplete.append({'reason': 'nothing_scanned', 'location': '', 'detail': 'zero files were scanned'})
    unused = [dict(entry, index=index) for index, entry in enumerate(allowlist) if index not in scanner.used_allow]
    if unused and args.strict_allowlist:
        scanner.global_incomplete.append({'reason': 'allowlist_unused', 'location': '', 'detail': f'{len(unused)} allowlist entries matched nothing'})

    hits = [h for art in scanner.artifacts for h in art.hits]
    findings = [f for art in scanner.artifacts for f in art.findings]
    patterns = [p for art in scanner.artifacts for p in art.patterns]
    exposed = [item for item in hits + findings + patterns if not item['allowlisted']]
    incomplete = bool(scanner.global_incomplete) or any(art.incomplete for art in scanner.artifacts)
    code = EXIT_HITS if exposed else EXIT_INCOMPLETE if incomplete else EXIT_PASS
    totals = dict(scanner.totals)
    for key in ('files', 'bytes_scanned', 'zero_bytes_skipped', 'archives', 'images', 'image_layers', 'backups', 'dumps', 'transcripts', 'logs'):
        totals.setdefault(key, 0)
    totals.update(entries=sum(art.entries for art in scanner.artifacts), hits=len(hits), allowlisted_hits=sum(1 for h in hits if h['allowlisted']),
                  findings=len(findings), allowlisted_findings=sum(1 for f in findings if f['allowlisted']), patterns=len(patterns),
                  allowlisted_patterns=sum(1 for item in patterns if item['allowlisted']),
                  exposed=len(exposed), incomplete=sum(len(art.incomplete) for art in scanner.artifacts) + len(scanner.global_incomplete))
    report = {
        'tool': 'canary-scan', 'version': VERSION, 'started': started, 'finished': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'python': sys.version.split()[0],
        'canaries': {'count': len(sources), 'ids': [{'id': canary_id(value), 'source': kind} for kind, value in sources]},
        'controls': controls, 'requested': requested, 'artifacts': [art.to_json() for art in scanner.artifacts],
        'excluded': scanner.excluded, 'incomplete': scanner.global_incomplete,
        'allowlist': {'entries': len(allowlist), 'used': sorted(scanner.used_allow), 'unused': [{'index': u['index'], 'kind': u['kind'], 'id': u['id'], 'path': u['path']} for u in unused]},
        'totals': totals, 'result': 'PASS' if code == EXIT_PASS else 'FAIL_EXPOSED' if code == EXIT_HITS else 'FAIL_INCOMPLETE',
    }
    if args.report:
        with open(args.report, 'w', encoding='utf-8') as handle:
            json.dump(report, handle, indent=1, sort_keys=True)
    print_summary(report, scanner, code)
    return code


def print_summary(report, scanner, code):
    totals = report['totals']
    print(f"canary-scan {report['result']}: {totals['files']} files, {totals['entries']} entries, {totals['bytes_scanned']} bytes scanned; "
          f"{totals['exposed']} exposed, {totals['allowlisted_hits'] + totals['allowlisted_findings'] + totals['allowlisted_patterns']} allowlisted, {totals['incomplete']} incomplete")
    print(f"  controls: {'ok' if report['controls']['ok'] else 'FAILED'} ({', '.join(report['controls']['detected'])}; zstd backend {report['controls']['zstd_backend']})")
    classes = ', '.join(f'{key}={totals[key]}' for key in ('archives', 'images', 'image_layers', 'backups', 'dumps', 'transcripts', 'logs') if totals.get(key))
    if classes:
        print(f'  classes: {classes}')
    for art in report['artifacts']:
        for hit in art['hits']:
            state = f"allowlisted ({hit['reason']})" if hit['allowlisted'] else 'EXPOSED'
            print(f"  hit {state}: canary {hit['canary']} as {hit['encoding']} x{hit['count']} at {hit['location']} offset {hit['offset']}")
        for finding in art['findings']:
            state = f"allowlisted ({finding['reason']})" if finding['allowlisted'] else 'EXPOSED'
            print(f"  finding {state}: {finding['kind']} [{finding['id']}] at {finding['location']} {finding['detail']}")
        for item in art['patterns']:
            state = f"allowlisted ({item['reason']})" if item['allowlisted'] else 'EXPOSED'
            print(f"  shape {state}: {item['pattern']} sha256:{item['sha256_prefix']} x{item['count']} at {item['location']} offset {item['offset']}")
        for item in art['incomplete']:
            print(f"  incomplete: {item['reason']} at {item['location']} {item['detail']}")
    for item in report['incomplete']:
        print(f"  incomplete: {item['reason']} {item['location']} {item['detail']}")
    for entry in report['allowlist']['unused']:
        print(f"  unused allowlist entry: {entry['kind']} {entry['id']} {entry['path']}")
    for item in report['excluded']:
        print(f"  excluded: {item['path']} ({item['glob']})")


if __name__ == '__main__':
    sys.exit(main())
