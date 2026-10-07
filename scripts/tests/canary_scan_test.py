#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Self-tests for scripts/tests/canary-scan.sh (P07-I04, pilot S06/S07).

The scanner is a security gate, so these tests concentrate on the failure that
the earlier VM scanners had: passing because it saw nothing. Every container and
encoding type has a planted positive that must be found, every unreadable,
truncated, empty or unsupported input must fail closed, and no run may ever
print a canary, an encoding of one or a matched secret.

Run: python3 -m unittest scripts/tests/canary_scan_test.py
"""
import base64
import bz2
import gzip
import hashlib
import io
import json
import lzma
import os
import random
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
import urllib.parse
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCAN = HERE / 'canary-scan.sh'

PLAIN = 'P07-TEST-CANARY-0123456789abcdef0123456789abcdef'
SYMBOL = 'P07-TEST-CANARY-s+/=&"\\%<>\'\u00e9\u00fc-zzzz'
CANARIES = [PLAIN, SYMBOL]


def zstd_compress(data):
    try:
        from compression import zstd
        return zstd.compress(data)
    except ImportError:
        return subprocess.run(['zstd', '-q', '-c'], input=data, capture_output=True, check=True).stdout


def encodings(canary):
    """Independent renderings of one canary, keyed by the label the scanner must report."""
    raw = canary.encode()
    out = {
        'raw': raw,
        'utf-16le': canary.encode('utf-16-le'),
        'utf-16be': canary.encode('utf-16-be'),
        'hex': raw.hex().encode(),
        'hex-upper': raw.hex().upper().encode(),
        'url': urllib.parse.quote(canary, safe='').encode(),
        'url-all': ''.join('%%%02X' % b for b in raw).encode(),
        'json': json.dumps(canary, ensure_ascii=True)[1:-1].encode(),
        'json-unicode': ''.join('\\u%04x' % ord(ch) for ch in canary).encode(),
        'bytes-debug': ('[' + ', '.join(str(b) for b in raw) + ']').encode(),
        'hex-escape': ''.join('\\x%02x' % b for b in raw).encode(),
    }
    return out


def embedded_base64(canary, alignment, urlsafe):
    """A larger base64 stream that carries the canary at byte offset `alignment` modulo 3."""
    payload = b'\x01\x02\x03'[:alignment] + canary.encode() + b'\x7f\x80\x90'
    encode = base64.urlsafe_b64encode if urlsafe else base64.b64encode
    return encode(os.urandom(6) + payload + os.urandom(5))


def tar_bytes(members, fmt=tarfile.PAX_FORMAT, end_marker=True):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w', format=fmt) as archive:
        for member in members:
            info = tarfile.TarInfo(member['name'])
            kind = member.get('type', 'file')
            data = member.get('data', b'')
            if kind == 'symlink':
                info.type = tarfile.SYMTYPE
                info.linkname = member['linkname']
                archive.addfile(info)
            elif kind == 'dir':
                info.type = tarfile.DIRTYPE
                archive.addfile(info)
            else:
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
    data = buffer.getvalue()
    return data if end_marker else data.rstrip(b'\0')


def zip_bytes(members, comment=b''):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as archive:
        for name, data in members.items():
            archive.writestr(name, data)
        archive.comment = comment
    return buffer.getvalue()


def cms_envelope(size=40000, random_body=True):
    """A DER CMS SignedData-shaped envelope: definite length, signedData OID, random body."""
    oid = bytes.fromhex('06092a864886f70d010702')
    body = oid + (os.urandom(size) if random_body else b'A' * size)
    return b'\x30\x83' + len(body).to_bytes(3, 'big') + body


def elf_core(payload):
    header = b'\x7fELF\x02\x01\x01\x00' + b'\0' * 8 + struct.pack('<H', 4) + b'\0' * 46
    return header + b'\0' * 4096 + payload + b'\0' * 4096


def sha(data):
    return hashlib.sha256(data).hexdigest()


def docker_layout(layers, env=None, history=None, rename=None, drop_layer=None):
    """A docker-save export: manifest.json, config, and one layer.tar per entry in `layers`."""
    members = []
    layer_names = []
    for index, layer in enumerate(layers):
        name = f'layer{index:02d}/layer.tar'
        layer_names.append(name)
        if drop_layer != index:
            members.append({'name': name, 'data': layer})
    config = {'architecture': 'amd64', 'os': 'linux', 'config': {'Env': env or ['PATH=/usr/bin'], 'Cmd': ['/bin/sh']},
              'history': [{'created_by': item} for item in (history or ['/bin/sh -c #(nop) CMD'])],
              'rootfs': {'type': 'layers', 'diff_ids': [f'sha256:{sha(layer)}' for layer in layers]}}
    config_data = json.dumps(config).encode()
    config_name = f'{sha(config_data)}.json'
    manifest = [{'Config': config_name, 'RepoTags': ['example/test:latest'], 'Layers': layer_names}]
    members.append({'name': config_name, 'data': config_data})
    members.append({'name': 'manifest.json', 'data': json.dumps(manifest).encode()})
    return tar_bytes(members)


def oci_layout(layers, compress=True, tamper=None, drop_layer=None, env=None):
    blobs = {}
    descriptors = []
    for index, layer in enumerate(layers):
        data = gzip.compress(layer) if compress else layer
        digest = sha(data)
        blobs[digest] = data
        descriptors.append({'mediaType': 'application/vnd.oci.image.layer.v1.tar+gzip', 'digest': f'sha256:{digest}', 'size': len(data)})
    config = json.dumps({'architecture': 'amd64', 'os': 'linux', 'config': {'Env': env or ['PATH=/usr/bin']},
                         'rootfs': {'type': 'layers', 'diff_ids': [f'sha256:{sha(layer)}' for layer in layers]}}).encode()
    config_digest = sha(config)
    blobs[config_digest] = config
    manifest = json.dumps({'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.manifest.v1+json',
                           'config': {'mediaType': 'application/vnd.oci.image.config.v1+json', 'digest': f'sha256:{config_digest}', 'size': len(config)},
                           'layers': descriptors}).encode()
    manifest_digest = sha(manifest)
    blobs[manifest_digest] = manifest
    index = json.dumps({'schemaVersion': 2, 'manifests': [{'mediaType': 'application/vnd.oci.image.manifest.v1+json',
                                                          'digest': f'sha256:{manifest_digest}', 'size': len(manifest)}]}).encode()
    if drop_layer is not None:
        del blobs[descriptors[drop_layer]['digest'].split(':')[1]]
    members = [{'name': 'oci-layout', 'data': b'{"imageLayoutVersion":"1.0.0"}'}, {'name': 'index.json', 'data': index}]
    for digest, data in blobs.items():
        if tamper is not None and digest == descriptors[tamper]['digest'].split(':')[1]:
            data = data[:-1] + bytes([data[-1] ^ 1])
        members.append({'name': f'blobs/sha256/{digest}', 'data': data})
    return tar_bytes(members)


class ScanTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='canary-scan-test-'))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.root = self.tmp / 'artifacts'
        self.root.mkdir()
        self.canary_file = self.tmp / 'canaries.txt'
        self.canary_file.write_text('\n'.join(CANARIES) + '\n', encoding='utf-8')
        self.canary_file.chmod(0o600)

    # -- helpers -----------------------------------------------------------------------------------------
    def put(self, name, data, base=None):
        path = (base or self.root) / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data if isinstance(data, bytes) else data.encode())
        return path

    def scan(self, *flags, target=None, canaries=True, env=None, expect=None):
        report = self.tmp / 'report.json'
        if report.exists():
            report.unlink()
        command = [str(SCAN)]
        if canaries:
            command += ['--canaries', str(self.canary_file)]
        command += ['--report', str(report), *flags, str(target or self.root)]
        environment = {**os.environ, **(env or {})}
        done = subprocess.run(command, capture_output=True, env=environment, timeout=300)
        out = done.stdout.decode(errors='replace')
        err = done.stderr.decode(errors='replace')
        data = json.loads(report.read_text()) if report.exists() else None
        self.assert_no_secret_output(out + err + (report.read_text() if report.exists() else ''))
        if expect is not None:
            self.assertEqual(done.returncode, expect, f'exit {done.returncode}\n{out}\n{err}')
        return done.returncode, out + err, data

    def assert_no_secret_output(self, text):
        for canary in CANARIES:
            for label, variant in encodings(canary).items():
                if label.startswith('utf-16'):
                    continue
                self.assertNotIn(variant.decode('utf-8', 'ignore'), text, f'output leaked a {label} canary')
            for alignment in range(3):
                for urlsafe in (False, True):
                    stream = base64.urlsafe_b64encode(canary.encode()) if urlsafe else base64.b64encode(canary.encode())
                    self.assertNotIn(stream[8:-8].decode(), text)

    def hits(self, data):
        return [hit for artifact in data['artifacts'] for hit in artifact.get('hits', [])]

    def assert_hit(self, *flags, expect_label=None, target=None):
        code, text, data = self.scan(*flags, target=target)
        self.assertEqual(code, 1, text)
        hits = self.hits(data)
        self.assertTrue(hits, text)
        if expect_label:
            self.assertIn(expect_label, {label for hit in hits for label in hit['encoding'].split('|')}, text)
        return data

    def assert_clean(self, *flags, target=None):
        code, text, data = self.scan(*flags, target=target)
        self.assertEqual(code, 0, text)
        self.assertEqual(self.hits(data), [])
        self.assertGreater(data['totals']['bytes_scanned'], 0)
        return data

    def assert_incomplete(self, *flags, target=None, reason=None, env=None):
        code, text, data = self.scan(*flags, target=target, env=env)
        self.assertEqual(code, 3, text)
        if reason:
            reasons = {item['reason'] for artifact in data['artifacts'] for item in artifact.get('incomplete', [])}
            reasons |= {item['reason'] for item in data.get('incomplete', [])}
            self.assertIn(reason, reasons, text)
        return data

    # -- plain positives and clean controls ---------------------------------------------------------------
    def test_help_and_wrapper_are_executable(self):
        done = subprocess.run([str(SCAN), '--help'], capture_output=True)
        self.assertEqual(done.returncode, 0)
        self.assertIn(b'--archives', done.stdout)
        self.assertTrue(os.access(SCAN, os.X_OK))

    def test_clean_tree_passes_and_counts_what_it_scanned(self):
        self.put('a.log', 'nothing to see here\n' * 100)
        self.put('b/c.bin', os.urandom(5000))
        data = self.assert_clean()
        self.assertEqual(data['totals']['files'], 2)
        self.assertEqual(data['controls']['ok'], True)
        self.assertEqual(data['result'], 'PASS')

    def test_every_encoding_of_every_canary_is_detected_in_a_plain_file(self):
        for canary in CANARIES:
            for label, variant in encodings(canary).items():
                with self.subTest(canary=canary[:20], encoding=label):
                    for child in self.root.iterdir():
                        child.unlink()
                    self.put('x.bin', b'prefix-junk ' + variant + b' suffix-junk')
                    self.assert_hit(expect_label=label)

    def test_base64_and_base64url_at_every_alignment(self):
        for canary in CANARIES:
            for urlsafe in (False, True):
                for alignment in range(3):
                    with self.subTest(canary=canary[:20], urlsafe=urlsafe, alignment=alignment):
                        for child in self.root.iterdir():
                            child.unlink()
                        self.put('x.txt', b'Authorization: ' + embedded_base64(canary, alignment, urlsafe) + b'\n')
                        self.assert_hit(expect_label='base64url' if urlsafe else 'base64')

    def test_canary_across_the_read_chunk_boundary(self):
        chunk = 1024 * 1024
        for offset in (chunk - 1, chunk - 7, chunk - len(PLAIN) // 2, chunk + 3):
            with self.subTest(offset=offset):
                for child in self.root.iterdir():
                    child.unlink()
                body = bytearray(b'.' * (2 * chunk))
                body[offset:offset + len(PLAIN)] = PLAIN.encode()
                self.put('big.bin', bytes(body))
                self.assert_hit()

    def test_sparse_zero_regions_are_skipped_fast_without_missing_canaries_next_to_them(self):
        chunk = 1024 * 1024
        first = 8192          # the scanner's first read is the 8 KiB it peeked at to identify the file
        be = PLAIN.encode('utf-16-be')
        le = PLAIN.encode('utf-16-le')

        def dump(*pieces):
            """An ELF core header followed by zeros with `bytes` placed at absolute file offsets."""
            size = max(offset + len(data) for offset, data in pieces) + 3 * chunk
            body = bytearray(size)
            body[:64] = elf_core(b'')[:64]
            for offset, data in pieces:
                body[offset:offset + len(data)] = data
            return bytes(body)

        key_start = b'\0' * 4 + bytes(range(1, 29))      # raw key bytes that begin with NULs
        key_end = bytes(range(1, 29)) + b'\0' * 4        # ... and that end with NULs
        cases = {
            # the key's leading NULs are the last bytes of an all-zero chunk; its other bytes start the next chunk
            'key-starts-with-zeros': (dump((first + 2 * chunk - 4, key_start)), key_start),
            # the key's trailing NULs are the first bytes of an all-zero chunk
            'key-ends-with-zeros': (dump((first + chunk - 28, key_end)), key_end),
            'be-after-zeros': (dump((first + 2 * chunk - 1, be)), None),
            'le-before-zeros': (dump((first + chunk - (len(le) - 1), le[:-1])), None),
            'plain-between-zero-chunks': (dump((first + 3 * chunk + 100, PLAIN.encode())), None),
            'plain-inside-the-first-read': (dump((100, PLAIN.encode())), None),
        }
        for name, (blob, key) in cases.items():
            with self.subTest(case=name):
                for child in self.root.iterdir():
                    child.unlink()
                self.put('core.1', blob)
                flags = ['--dumps']
                self.canary_file.write_text('\n'.join(CANARIES) + '\n', encoding='utf-8')
                if key is not None:
                    key_file = self.tmp / 'key-material'
                    key_file.write_bytes(key)
                    flags += ['--key-material', str(key_file)]
                    self.canary_file.write_text('P07-TEST-CANARY-never-present-in-this-file\n')
                data = self.assert_hit(*flags)
                self.assertGreater(data['totals']['zero_bytes_skipped'], chunk)

    def test_a_large_all_zero_dump_is_scanned_and_counted_quickly(self):
        self.put('core.2', elf_core(b'') [:20] + b'\0' * (256 * 1024 * 1024))
        data = self.assert_clean('--dumps')
        self.assertGreater(data['totals']['bytes_scanned'], 256 * 1024 * 1024)
        # all-zero regions cannot hold a canary: they are counted as scanned but skipped, not searched byte by byte
        self.assertGreaterEqual(data['totals']['zero_bytes_skipped'], 255 * 1024 * 1024)

    def test_canary_wrapped_over_lines_in_text(self):
        wrapped = PLAIN[:20] + '\n' + PLAIN[20:30] + '\r\n' + PLAIN[30:]
        self.put('wrapped.log', 'start\n' + wrapped + '\nend\n')
        self.assert_hit('--logs', expect_label='raw+wrapped')

    def test_canary_split_across_tar_blocks_is_found_inside_the_member(self):
        body = b'.' * 509 + PLAIN.encode() + b'.' * 600
        self.put('x.tar', tar_bytes([{'name': 'f', 'data': body}]))
        self.assert_hit('--archives')

    # -- containers -----------------------------------------------------------------------------------------
    def container_cases(self, payload):
        tar = tar_bytes([{'name': 'dir/file.txt', 'data': b'x' * 10}, {'name': 'dir/secret.txt', 'data': payload}])
        return {
            'tar': tar,
            'tar.gz': gzip.compress(tar),
            'tar.bz2': bz2.compress(tar),
            'tar.xz': lzma.compress(tar),
            'tar.zst': zstd_compress(tar),
            'zip': zip_bytes({'a/b.txt': payload}),
            'gz': gzip.compress(payload),
            'bz2': bz2.compress(payload),
            'xz': lzma.compress(payload),
            'zst': zstd_compress(payload),
            'concatenated-gz': gzip.compress(b'clean first member') + gzip.compress(payload),
            'concatenated-bz2': bz2.compress(b'clean first stream') + bz2.compress(payload),
        }

    def test_planted_canary_found_in_every_container_type(self):
        for name, blob in self.container_cases(b'before ' + PLAIN.encode() + b' after').items():
            with self.subTest(container=name):
                for child in self.root.iterdir():
                    child.unlink()
                self.put(f'artifact.{name}', blob)
                self.assert_hit('--archives')

    def test_clean_containers_pass_and_are_counted(self):
        for name, blob in self.container_cases(b'nothing secret in here').items():
            with self.subTest(container=name):
                for child in self.root.iterdir():
                    child.unlink()
                self.put(f'artifact.{name}', blob)
                data = self.assert_clean('--archives')
                self.assertGreaterEqual(data['totals']['bytes_scanned'], len(b'nothing secret in here'))

    def test_nested_archives_are_unpacked_to_the_depth_limit(self):
        inner = tar_bytes([{'name': 'deep.txt', 'data': PLAIN.encode()}])
        layer = zip_bytes({'inner.tar.gz': gzip.compress(inner)})
        self.put('outer.tar.zst', zstd_compress(tar_bytes([{'name': 'mid.zip', 'data': layer}])))
        data = self.assert_hit('--archives')
        self.assertGreaterEqual(data['artifacts'][0]['max_depth'], 4)
        self.assertTrue(any('deep.txt' in hit['location'] for hit in self.hits(data)))

    def test_depth_limit_fails_closed_instead_of_skipping(self):
        blob = PLAIN.encode()
        for _ in range(5):
            blob = gzip.compress(blob)
        self.put('deep.gz', blob)
        self.assert_hit('--archives')
        self.assert_incomplete('--archives', '--max-depth', '3', reason='depth_limit_exceeded')

    def test_byte_and_entry_limits_fail_closed(self):
        self.put('bomb.gz', gzip.compress(b'\0' * (8 * 1024 * 1024)))
        self.assert_incomplete('--archives', '--max-bytes', str(1024 * 1024), reason='byte_limit_exceeded')
        for child in self.root.iterdir():
            child.unlink()
        self.put('many.tar', tar_bytes([{'name': f'f{i}', 'data': b'x'} for i in range(50)]))
        self.assert_incomplete('--archives', '--max-entries', '10', reason='entry_limit_exceeded')

    def test_member_names_link_targets_pax_and_zip_comments_are_scanned(self):
        cases = {
            'name.tar': tar_bytes([{'name': f'dir/{PLAIN}.txt', 'data': b'x'}]),
            'link.tar': tar_bytes([{'name': 'l', 'type': 'symlink', 'linkname': f'/run/{PLAIN}'}]),
            'zipname.zip': zip_bytes({f'{PLAIN}.txt': b'x'}),
            'zipcomment.zip': zip_bytes({'a': b'x'}, comment=PLAIN.encode()),
        }
        for name, blob in cases.items():
            with self.subTest(case=name):
                for child in self.root.iterdir():
                    child.unlink()
                self.put(name, blob)
                self.assert_hit('--archives')

    def test_a_name_containing_a_canary_is_redacted_in_every_output(self):
        self.put(f'{PLAIN}.txt', b'content')
        code, text, data = self.scan()
        self.assertEqual(code, 1, text)
        self.assertNotIn(PLAIN, json.dumps(data))
        self.assertNotIn(PLAIN, text)

    def test_ar_archives_and_deb_like_members_are_unpacked(self):
        member = gzip.compress(tar_bytes([{'name': 'x', 'data': PLAIN.encode()}]))
        header = b'debian-binary   ' + b'0           0     0     100644  4         `\n2.0\n'
        control = b'data.tar.gz'.ljust(16) + b'0           0     0     100644  %-10d`\n' % len(member) + member + (b'\n' if len(member) % 2 else b'')
        self.put('pkg.deb', b'!<arch>\n' + header + control)
        self.assert_hit('--archives')

    # -- container images --------------------------------------------------------------------------------
    def layer(self, files, whiteouts=()):
        members = [{'name': name, 'data': data} for name, data in files.items()]
        members += [{'name': name, 'data': b''} for name in whiteouts]
        return tar_bytes(members)

    def test_docker_save_layout_clean_scans_every_layer(self):
        layers = [self.layer({'etc/os-release': b'ID=test\n'}), self.layer({'app/run': b'#!/bin/sh\n'})]
        self.put('image.tar', docker_layout(layers))
        data = self.assert_clean('--images')
        self.assertEqual(data['totals']['images'], 1)
        self.assertEqual(data['totals']['image_layers'], 2)

    def test_docker_save_layout_finds_canary_in_deleted_lower_layer_config_env_and_history(self):
        lower = self.layer({'app/secret.txt': PLAIN.encode()})
        upper = self.layer({}, whiteouts=['app/.wh.secret.txt'])
        cases = {
            'deleted-layer': docker_layout([lower, upper]),
            'env': docker_layout([self.layer({'a': b'x'})], env=[f'API_VALUE={PLAIN}']),
            'history': docker_layout([self.layer({'a': b'x'})], history=[f'RUN echo {PLAIN} > /x']),
            'name': docker_layout([self.layer({f'{PLAIN}/x': b'x'})]),
        }
        for name, blob in cases.items():
            with self.subTest(case=name):
                for child in self.root.iterdir():
                    child.unlink()
                self.put('image.tar', blob)
                self.assert_hit('--images')

    def test_secret_named_env_in_image_config_is_a_finding_without_printing_the_value(self):
        value = 'hunter2-' + os.urandom(6).hex()
        self.put('image.tar', docker_layout([self.layer({'a': b'x'})], env=[f'DB_PASSWORD={value}']))
        code, text, data = self.scan('--images')
        self.assertEqual(code, 1, text)
        self.assertNotIn(value, text + json.dumps(data))
        self.assertIn('image-env-secret', {finding['kind'] for artifact in data['artifacts'] for finding in artifact['findings']})

    def test_secret_assignments_in_image_history_are_findings_but_ordinary_env_is_not(self):
        value = 'hunter2-' + os.urandom(6).hex()
        ordinary = ['ENV BLINDPASS_LISTEN=0.0.0.0:3200 BLINDPASS_KEYS_DIR=/keys PASSENGER_COUNT=12345678 TOKEN_TTL=3600',
                    'ARG DB_PASSWORD_FILE=/run/secrets/db', 'ENV API_TOKEN=$FROM_BUILD_SECRET']
        self.put('clean.tar', docker_layout([self.layer({'a': b'x'})], history=ordinary))
        self.assert_clean('--images')
        for child in self.root.iterdir():
            child.unlink()
        self.put('leaky.tar', docker_layout([self.layer({'a': b'x'})], history=[f'ARG DB_PASSWORD={value}']))
        code, text, data = self.scan('--images')
        self.assertEqual(code, 1, text)
        self.assertNotIn(value, text + json.dumps(data))
        self.assertIn('image-history-secret', {finding['kind'] for artifact in data['artifacts'] for finding in artifact['findings']})

    def test_file_reference_env_names_are_not_findings(self):
        self.put('image.tar', docker_layout([self.layer({'a': b'x'})], env=['DB_PASSWORD_FILE=/run/secrets/db', 'TOKEN=']))
        self.assert_clean('--images')

    def test_oci_layout_scans_gzip_layers_and_verifies_blob_digests(self):
        clean = oci_layout([self.layer({'a': b'x'}), self.layer({'b': b'y'})])
        self.put('oci.tar', clean)
        data = self.assert_clean('--images')
        self.assertEqual(data['totals']['image_layers'], 2)
        for child in self.root.iterdir():
            child.unlink()
        self.put('oci.tar', oci_layout([self.layer({'a': PLAIN.encode()})]))
        self.assert_hit('--images')

    def test_oci_layout_on_disk_directory(self):
        blob = oci_layout([self.layer({'a': PLAIN.encode()})])
        target = self.root / 'ocidir'
        with tarfile.open(fileobj=io.BytesIO(blob)) as archive:
            archive.extractall(target, filter='data')
        self.assert_hit('--images')

    def test_image_with_a_missing_layer_blob_fails_closed(self):
        self.put('oci.tar', oci_layout([self.layer({'a': b'x'}), self.layer({'b': b'y'})], drop_layer=1))
        self.assert_incomplete('--images', reason='image_layer_missing')
        for child in self.root.iterdir():
            child.unlink()
        self.put('docker.tar', docker_layout([self.layer({'a': b'x'}), self.layer({'b': b'y'})], drop_layer=0))
        self.assert_incomplete('--images', reason='image_layer_missing')

    def test_image_blob_digest_mismatch_fails_closed(self):
        self.put('oci.tar', oci_layout([self.layer({'a': b'x'})], compress=False, tamper=0))
        self.assert_incomplete('--images', reason='image_blob_digest_mismatch')

    def test_images_flag_without_an_image_fails_closed(self):
        self.put('plain.tar', tar_bytes([{'name': 'a', 'data': b'x'}]))
        self.assert_incomplete('--images', reason='no_image_found')

    def test_docker_image_option_saves_scans_and_removes_the_export(self):
        shim = self.tmp / 'bin'
        shim.mkdir()
        fixture = self.tmp / 'fixture.tar'
        fixture.write_bytes(docker_layout([self.layer({'a': PLAIN.encode()})]))
        script = shim / 'docker'
        script.write_text(f'#!/bin/sh\nif [ "$1" = save ]; then cp {fixture} "$3"; exit 0; fi\nexit 9\n')
        script.chmod(0o755)
        env = {'PATH': f'{shim}:{os.environ["PATH"]}'}
        empty = self.tmp / 'empty-root'
        empty.mkdir()
        code, text, data = self.scan('--images', '--docker-image', 'example/test:latest', target=empty, env=env)
        self.assertEqual(code, 1, text)
        self.assertTrue(self.hits(data))
        script.write_text('#!/bin/sh\nexit 1\n')
        code, text, data = self.scan('--images', '--docker-image', 'example/test:latest', target=empty, env=env)
        self.assertEqual(code, 3, text)

    def test_terminated_docker_image_export_is_removed_and_the_run_is_incomplete(self):
        shim = self.tmp / 'bin'
        shim.mkdir()
        scratch = self.tmp / 'scratch'
        scratch.mkdir()
        pidfile = self.tmp / 'docker.pid'
        (shim / 'docker').write_text(f'#!/bin/sh\necho $$ > {pidfile}\nhead -c 65536 /dev/zero > "$3"\nexec sleep 120\n')
        (shim / 'docker').chmod(0o755)
        empty = self.tmp / 'empty-root'
        empty.mkdir()
        command = [str(SCAN), '--canaries', str(self.canary_file), '--images', '--docker-image', 'example/test:latest', str(empty)]
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                env={**os.environ, 'PATH': f'{shim}:{os.environ["PATH"]}', 'TMPDIR': str(scratch)})
        try:
            deadline = time.monotonic() + 90
            while time.monotonic() < deadline and not any(scratch.glob('canary-scan-image-*/image.tar')):
                time.sleep(0.1)
            self.assertTrue(any(scratch.glob('canary-scan-image-*/image.tar')), 'the export never started')
            proc.terminate()
            out, _ = proc.communicate(timeout=30)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate()
        self.assertEqual(proc.returncode, 3, out.decode(errors='replace'))
        self.assertEqual(list(scratch.iterdir()), [], 'the interrupted export was left behind')
        pid = int(pidfile.read_text())
        time.sleep(0.5)
        self.assertFalse(os.path.exists(f'/proc/{pid}'), 'the docker child outlived the scanner')

    # -- backups ----------------------------------------------------------------------------------------------
    def test_encrypted_looking_cms_envelope_passes_the_backup_checks(self):
        self.put('controller-backup-abc.bpbackup', cms_envelope())
        data = self.assert_clean('--backups')
        self.assertEqual(data['totals']['backups'], 1)

    def test_backup_with_plaintext_database_inside_fails(self):
        envelope = cms_envelope(random_body=False)
        self.put('controller-backup-abc.bpbackup', envelope)
        code, text, data = self.scan('--backups')
        self.assertEqual(code, 1, text)
        self.assertIn('backup-not-ciphertext', {f['kind'] for a in data['artifacts'] for f in a['findings']})

    def test_backup_that_is_not_a_cms_envelope_fails(self):
        self.put('controller-backup-abc.bpbackup', b'SQLite format 3\0' + os.urandom(40000))
        code, text, data = self.scan('--backups')
        self.assertEqual(code, 1, text)
        self.assertIn('backup-not-cms', {f['kind'] for a in data['artifacts'] for f in a['findings']})

    def test_truncated_backup_envelope_fails_closed(self):
        self.put('controller-backup-abc.bpbackup', cms_envelope()[:-100])
        self.assert_incomplete('--backups', reason='backup_envelope_length_mismatch')

    def test_canary_or_key_material_inside_a_backup_is_a_hit(self):
        key = os.urandom(32)
        key_file = self.tmp / 'root-secret'
        key_file.write_bytes(key)
        key_file.chmod(0o600)
        body = bytes.fromhex('06092a864886f70d010702') + os.urandom(20000) + key + os.urandom(20000)
        self.put('controller-backup-abc.bpbackup', b'\x30\x83' + len(body).to_bytes(3, 'big') + body)
        code, text, data = self.scan('--backups', '--key-material', str(key_file))
        self.assertEqual(code, 1, text)
        self.assertTrue(self.hits(data))
        self.assertNotIn(key.hex(), text + json.dumps(data))

    def test_key_files_next_to_a_backup_are_findings_and_can_be_allowlisted_with_a_reason(self):
        self.put('controller-backup-abc.bpbackup', cms_envelope())
        self.put('keys/root-secret', os.urandom(32))
        self.put('keys/controller-backup-signing-credential', b'x' * 64)
        self.put('.backup-' + '0123456789abcdef' * 2 + '/database.sqlite', b'SQLite format 3\0' + b'\0' * 2000)
        code, text, data = self.scan('--backups')
        self.assertEqual(code, 1, text)
        kinds = {f['kind'] for a in data['artifacts'] for f in a['findings']}
        self.assertIn('forbidden-name', kinds)
        self.assertIn('plaintext-database-next-to-backup', kinds)
        allow = self.tmp / 'allow.json'
        allow.write_text(json.dumps([
            {'kind': 'forbidden-name', 'id': 'root-secret', 'path': '*keys/root-secret',
             'reason': 'fixture key directory is a separate custody location for this test'},
            {'kind': 'forbidden-name', 'id': 'controller-backup-signing-credential', 'path': '*keys/*',
             'reason': 'signing credential stays on the backup host by design (ADR 0013)'},
            {'kind': 'forbidden-name', 'id': '.backup-staging', 'path': '*.backup-*',
             'reason': 'staging residue is the subject of the cleanup test, not an accident'},
            {'kind': 'plaintext-database-next-to-backup', 'id': '*', 'path': '*database.sqlite',
             'reason': 'same staging residue'},
        ]))
        code, text, data = self.scan('--backups', '--allowlist', str(allow))
        self.assertEqual(code, 0, text)
        allowed = [f for a in data['artifacts'] for f in a['findings'] if f.get('allowlisted')]
        self.assertGreaterEqual(len(allowed), 3)
        self.assertTrue(all(f['reason'] for f in allowed))

    def test_the_live_database_in_the_parent_directory_is_not_residue(self):
        self.put('data/backups/controller-backup-abc.bpbackup', cms_envelope())
        self.put('data/controller.db', b'SQLite format 3\0' + b'\0' * 4000)
        self.assert_clean('--backups')

    def test_backups_flag_without_a_backup_fails_closed(self):
        self.put('a.txt', 'hello')
        self.assert_incomplete('--backups', reason='no_backup_found')

    # -- dumps, transcripts and logs ---------------------------------------------------------------------------
    def test_core_dump_is_scanned_and_found_even_when_compressed(self):
        self.put('core.123', elf_core(b'heap ' + PLAIN.encode() + b' heap'))
        self.assert_hit('--dumps')
        for child in self.root.iterdir():
            child.unlink()
        self.put('core.456.zst', zstd_compress(elf_core(b'heap ' + base64.b64encode(PLAIN.encode()) + b' heap')))
        self.assert_hit('--dumps')

    def test_clean_core_dump_counts_as_a_dump(self):
        self.put('core.123', elf_core(b'no secrets here'))
        data = self.assert_clean('--dumps')
        self.assertEqual(data['totals']['dumps'], 1)

    def test_dumps_flag_without_a_dump_fails_closed(self):
        self.put('a.log', 'x' * 100)
        self.assert_incomplete('--dumps', reason='no_dump_found')

    def test_transcript_with_json_escapes_and_secret_split_over_stream_deltas(self):
        half = len(PLAIN) // 2
        lines = [json.dumps({'type': 'delta', 'text': PLAIN[:half]}), json.dumps({'type': 'delta', 'text': PLAIN[half:]})]
        self.put('session.jsonl', '\n'.join(lines) + '\n')
        self.assert_hit('--transcripts', expect_label='json-joined')
        for child in self.root.iterdir():
            child.unlink()
        self.put('session2.jsonl', json.dumps({'text': SYMBOL}, ensure_ascii=True) + '\n')
        self.assert_hit('--transcripts')

    def test_clean_transcript_passes_and_is_counted(self):
        self.put('session.jsonl', json.dumps({'text': 'hello'}) + '\n' + json.dumps({'text': 'world'}) + '\n')
        data = self.assert_clean('--transcripts')
        self.assertEqual(data['totals']['transcripts'], 1)

    def test_transcript_with_no_parsable_json_lines_fails_closed(self):
        self.put('session.jsonl', 'this is not json\nneither is this\n')
        self.assert_incomplete('--transcripts', reason='transcript_not_json')

    def test_empty_log_or_transcript_or_dump_fails_closed(self):
        self.put('journal.log', b'')
        self.assert_incomplete('--logs', reason='empty_artifact')
        for child in self.root.iterdir():
            child.unlink()
        self.put('session.jsonl', b'')
        self.assert_incomplete('--transcripts', reason='empty_artifact')

    def test_logs_flag_without_a_log_fails_closed(self):
        self.put('a.bin', os.urandom(100))
        self.assert_incomplete('--logs', reason='no_log_found')

    # -- fail closed: unreadable, truncated, corrupt, unsupported -------------------------------------------------
    def test_missing_path_empty_directory_and_zero_files_fail_closed(self):
        self.assert_incomplete(target=self.tmp / 'does-not-exist', reason='path_missing')
        empty = self.tmp / 'empty'
        empty.mkdir()
        self.assert_incomplete(target=empty, reason='nothing_scanned')

    def test_unreadable_file_fails_closed(self):
        path = self.put('secret.log', 'x' * 50)
        path.chmod(0)
        self.addCleanup(path.chmod, 0o600)
        if os.access(path, os.R_OK):
            self.skipTest('running as a user that bypasses file modes')
        self.assert_incomplete(reason='unreadable')

    def test_truncated_archives_fail_closed(self):
        tar = tar_bytes([{'name': 'a', 'data': b'x' * 5000}, {'name': 'b', 'data': b'y' * 3000}])
        cases = {
            'trunc-mid-member.tar': tar[:700],
            'trunc-header.tar': tar[:5200],
            'no-end-marker.tar': tar_bytes([{'name': 'a', 'data': b'x' * 5000}], end_marker=False),
            # cut exactly after a complete member: tarfile ends silently, only the end-of-archive block tells
            'cut-at-boundary.tar': tar_bytes([{'name': 'a', 'data': b'x' * 512}, {'name': 'b', 'data': b'y' * 512}])[:1024],
            'invalid-header-midway.tar': tar_bytes([{'name': 'a', 'data': b'x' * 512}, {'name': 'b', 'data': b'y' * 512}])[:1024] + b'\x01' * 512 + b'\0' * 1024,
            'trunc.tar.gz': gzip.compress(tar)[:-20],
            'trunc.tar.bz2': bz2.compress(tar)[:-20],
            'trunc.tar.xz': lzma.compress(tar)[:-20],
            'trunc.tar.zst': zstd_compress(tar)[:-20],
            'trunc.zip': zip_bytes({'a': b'x' * 5000})[:-30],
        }
        for name, blob in cases.items():
            with self.subTest(case=name):
                for child in self.root.iterdir():
                    child.unlink()
                self.put(name, blob)
                code, text, data = self.scan('--archives')
                self.assertEqual(code, 3, text)

    def test_corrupt_streams_and_trailing_garbage_fail_closed(self):
        good_gz = gzip.compress(b'hello ' * 100)
        cases = {
            'bad-crc.gz': good_gz[:-8] + b'\0\0\0\0' + good_gz[-4:],
            'garbage-after.gz': good_gz + b'GARBAGE-AFTER-STREAM',
            'garbage-after.bz2': bz2.compress(b'hello ' * 100) + b'GARBAGE-AFTER-STREAM',
            'garbage-after.xz': lzma.compress(b'hello ' * 100) + b'GARBAGE-AFTER-STREAM',
            'bit-flip.bz2': bytearray(bz2.compress(b'hello ' * 1000)),
        }
        cases['bit-flip.bz2'][40] ^= 0xFF
        cases['bit-flip.bz2'] = bytes(cases['bit-flip.bz2'])
        for name, blob in cases.items():
            with self.subTest(case=name):
                for child in self.root.iterdir():
                    child.unlink()
                self.put(name, blob)
                code, text, data = self.scan('--archives')
                self.assertEqual(code, 3, text)

    def test_damaged_inputs_never_raise_an_unexpected_exception(self):
        """Seeded mutation fuzz: every outcome is a hit, a clean pass or a named incomplete reason, never `scanner_error`."""
        sys.path.insert(0, str(HERE))
        import canary_scan
        rng = random.Random(7)
        canary = PLAIN.encode()
        tar = tar_bytes([{'name': 'a', 'data': b'x' * 3000}, {'name': 'dir/b', 'data': canary + b'tail' * 100}])
        samples = {
            'tar': tar, 'tgz': gzip.compress(tar), 'tbz2': bz2.compress(tar), 'txz': lzma.compress(tar), 'tzst': zstd_compress(tar),
            'zip': zip_bytes({'a': b'x' * 2000, 'b': canary}),
            'docker': docker_layout([tar_bytes([{'name': 'f', 'data': b'hi'}])]),
            'oci': oci_layout([tar_bytes([{'name': 'f', 'data': b'hi'}])]),
        }
        for name, blob in samples.items():
            for index in range(60):
                data = bytearray(blob)
                mode = rng.choice(['flip', 'truncate', 'insert', 'zero'])
                if mode == 'flip':
                    for _ in range(rng.randint(1, 5)):
                        data[rng.randrange(len(data))] ^= rng.randrange(1, 256)
                elif mode == 'truncate':
                    data = data[:rng.randrange(1, len(data))]
                elif mode == 'insert':
                    at = rng.randrange(len(data))
                    data[at:at] = os.urandom(rng.randint(1, 40))
                else:
                    at = rng.randrange(len(data))
                    data[at:at + 32] = b'\0' * 32
                path = self.tmp / f'fuzz-{name}-{index}.bin'
                path.write_bytes(bytes(data))
                scanner = canary_scan.Scanner([('canary', canary)])
                scanner.scan_path(str(path), path.name, str(self.tmp))
                reasons = {item['reason'] for item in scanner.artifacts[0].incomplete}
                self.assertNotIn('scanner_error', reasons, f'{name} {mode} {index}: {[i["detail"] for i in scanner.artifacts[0].incomplete]}')
                path.unlink()

    def test_recognised_but_unsupported_containers_fail_closed(self):
        magics = {
            'x.7z': b'7z\xbc\xaf\x27\x1c' + os.urandom(200),
            'x.rar': b'Rar!\x1a\x07\x00' + os.urandom(200),
            'x.qcow2': b'QFI\xfb' + os.urandom(200),
            'x.squashfs': b'hsqs' + os.urandom(200),
            'x.cpio': b'070701' + os.urandom(200),
            'x.rpm': b'\xed\xab\xee\xdb' + os.urandom(200),
            'x.vmdk': b'KDMV' + os.urandom(200),
            'x.lz4': b'\x04\x22\x4d\x18' + os.urandom(200),
        }
        for name, blob in magics.items():
            with self.subTest(case=name):
                for child in self.root.iterdir():
                    child.unlink()
                self.put(name, blob)
                self.assert_incomplete(reason='unsupported_container')

    def test_encrypted_zip_member_fails_closed(self):
        blob = bytearray(zip_bytes({'a': b'x' * 100}))
        local = blob.find(b'PK\x03\x04')
        blob[local + 6] |= 1
        central = blob.find(b'PK\x01\x02')
        blob[central + 8] |= 1
        self.put('enc.zip', bytes(blob))
        self.assert_incomplete('--archives', reason='encrypted_member')

    def test_zstd_codec_unavailable_fails_closed_and_cli_fallback_works(self):
        self.put('x.zst', zstd_compress(b'filler ' + PLAIN.encode()))
        self.assert_incomplete('--archives', env={'CANARY_SCAN_ZSTD': 'none'}, reason='codec_unavailable')
        code, text, data = self.scan('--archives', env={'CANARY_SCAN_ZSTD': 'cli'})
        self.assertEqual(code, 1, text)
        self.assertIn('cli', json.dumps(data['controls']))

    def test_special_files_and_symlinks(self):
        outside = self.tmp / 'outside'
        outside.mkdir()
        self.put('leak.txt', PLAIN, base=outside)
        os.symlink(outside, self.root / 'link-to-dir')
        os.symlink(f'/run/{PLAIN}', self.root / 'link-with-canary')
        self.put('plain.txt', 'ok')
        code, text, data = self.scan()
        self.assertEqual(code, 1, text)
        locations = ' '.join(hit['location'] for hit in self.hits(data))
        self.assertNotIn('leak.txt', locations, 'symlinked directories must not be followed')
        (self.root / 'link-with-canary').unlink()
        os.mkfifo(self.root / 'pipe')
        code, text, data = self.scan()
        self.assertEqual(code, 3, text)
        self.assertIn('special_file', {item['reason'] for art in data['artifacts'] for item in art['incomplete']})

    def test_excludes_are_reported_and_never_silent(self):
        self.put('keep.log', 'clean content here')
        self.put('skip.log', PLAIN)
        code, text, data = self.scan('--exclude', '*skip.log')
        self.assertEqual(code, 0, text)
        self.assertEqual([item['path'].endswith('skip.log') for item in data['excluded']], [True])

    # -- canary list and allowlist handling --------------------------------------------------------------------------
    def test_bad_canary_lists_are_refused(self):
        self.put('a.txt', 'x' * 30)
        for text in ('', '\n\n', 'short\n', 'aaaaaaaaaaaaaaaaaaaa\n', 'P07-TEST-CANARY-ok-ok-ok\nshort\n'):
            with self.subTest(text=text):
                self.canary_file.write_text(text)
                code, out, _ = self.scan()
                self.assertEqual(code, 2, out)
        code, out, _ = self.scan(canaries=False)
        self.assertEqual(code, 2, out)
        code, out, _ = self.scan('--canaries', str(self.tmp / 'missing'), canaries=False)
        self.assertEqual(code, 2, out)

    def test_json_canary_list_and_generated_list_are_accepted(self):
        self.canary_file.write_text(json.dumps(CANARIES))
        self.put('a.txt', PLAIN)
        self.assert_hit()
        generated = self.tmp / 'generated.txt'
        done = subprocess.run([str(SCAN), '--generate-canaries', str(generated), '--count', '6'], capture_output=True)
        self.assertEqual(done.returncode, 0, done.stderr)
        values = generated.read_text().splitlines()
        self.assertEqual(len(values), 6)
        self.assertEqual(len(set(values)), 6)
        self.assertTrue(all(len(v) >= 24 for v in values))
        self.assertEqual(stat.S_IMODE(generated.stat().st_mode), 0o600)
        self.assertNotIn(values[0], done.stdout.decode() + done.stderr.decode())
        self.canary_file.write_text(generated.read_text())
        self.put('b.txt', values[3])
        code, text, data = self.scan()
        self.assertEqual(code, 1, text)
        done = subprocess.run([str(SCAN), '--generate-canaries', str(generated)], capture_output=True)
        self.assertNotEqual(done.returncode, 0, 'must not overwrite an existing canary file')

    def test_allowlisted_hit_is_reported_with_its_reason_and_passes(self):
        self.put('consumer/process.core.txt', PLAIN)
        digest = hashlib.sha256(PLAIN.encode()).hexdigest()[:8]
        allow = self.tmp / 'allow.json'
        allow.write_text(json.dumps([{'kind': 'canary', 'id': digest, 'path': '*consumer/*',
                                      'reason': 'consumer process holds the delivered secret by design (session access)'}]))
        code, text, data = self.scan('--allowlist', str(allow))
        self.assertEqual(code, 0, text)
        hits = self.hits(data)
        self.assertEqual(len(hits), 1)
        self.assertTrue(hits[0]['allowlisted'])
        self.assertIn('session access', hits[0]['reason'])
        self.assertEqual(data['totals']['allowlisted_hits'], 1)
        self.put('elsewhere/leak.txt', PLAIN)
        code, text, data = self.scan('--allowlist', str(allow))
        self.assertEqual(code, 1, 'a hit outside the allowlisted path must still fail')

    def test_allowlist_can_pin_the_exact_file_content(self):
        content = b'junk ' + self.shapes()['age-secret-key'] + b' junk'
        self.put('lib/vendor.so', content)
        entry = {'kind': 'pattern', 'id': 'age-secret-key', 'path': '*vendor.so', 'reason': 'vendor self-test vector, file pinned by digest',
                 'sha256': hashlib.sha256(content).hexdigest()}
        allow = self.tmp / 'allow.json'
        allow.write_text(json.dumps([entry]))
        code, text, data = self.scan('--allowlist', str(allow))
        self.assertEqual(code, 0, text)
        self.assertEqual(data['totals']['patterns'], 1)
        self.put('lib/vendor.so', content + b' changed')
        code, text, data = self.scan('--allowlist', str(allow))
        self.assertEqual(code, 1, 'a changed file must no longer match its digest-pinned allowance')
        allow.write_text(json.dumps([dict(entry, sha256='zz')]))
        code, text, _ = self.scan('--allowlist', str(allow))
        self.assertEqual(code, 2, text)

    def test_allowlist_entries_need_a_reason_and_unused_ones_are_reported(self):
        self.put('a.txt', 'x' * 40)
        allow = self.tmp / 'allow.json'
        allow.write_text(json.dumps([{'kind': 'canary', 'id': 'deadbeef', 'path': '*', 'reason': ''}]))
        code, text, _ = self.scan('--allowlist', str(allow))
        self.assertEqual(code, 2, text)
        allow.write_text(json.dumps([{'kind': 'canary', 'id': 'deadbeef', 'path': '*', 'reason': 'stale entry from an earlier run of this test'}]))
        code, text, data = self.scan('--allowlist', str(allow))
        self.assertEqual(code, 0, text)
        self.assertEqual(len(data['allowlist']['unused']), 1)
        code, text, data = self.scan('--allowlist', str(allow), '--strict-allowlist')
        self.assertEqual(code, 3, text)

    # -- secret-shaped material ---------------------------------------------------------------------------------------
    def shapes(self):
        base32 = 'QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L'
        uuid = '0123abcd-4567-89ab-cdef-0123456789ab'
        b64 = base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip('=')
        pem_body = base64.b64encode(os.urandom(48)).decode()
        jwt = 'eyJ' + base64.urlsafe_b64encode(os.urandom(18)).decode().rstrip('=') + '.eyJ' + \
              base64.urlsafe_b64encode(os.urandom(18)).decode().rstrip('=') + '.' + b64
        return {
            'pem-private-key': ('-----BEGIN ' + 'PRIVATE KEY-----\n' + pem_body + '\n-----END ' + 'PRIVATE KEY-----\n').encode(),
            'pem-rsa-private-key': ('-----BEGIN RSA ' + 'PRIVATE KEY-----\r\nProc-Type: 4,ENCRYPTED\r\nDEK-Info: AES-128-CBC,00\r\n\r\n' + pem_body + '\n').encode(),
            'age-secret-key': ('AGE-SECRET-KEY-1' + ''.join(base32[(i * 7) % 32] for i in range(58))).encode(),
            'jwt': jwt.encode(),
            'bearer-token': ('Authorization: Bearer ' + 'abcd1234' + b64).encode(),
            'agent-api-key': f'ak_{uuid}_{b64}'.encode(),
            'enrollment-token': f'en_{uuid}_{b64[:43]}'.encode(),
            'signed-link': f'https://x.example/?id={uuid}&metadata_sig={b64}{b64}&submit_sig={b64}{b64}'.encode(),
        }

    def test_secret_shapes_are_reported_by_name_and_hash_prefix_only(self):
        for name, blob in self.shapes().items():
            with self.subTest(shape=name):
                for child in self.root.iterdir():
                    child.unlink()
                self.put('layer.bin', b'junk ' + blob + b' junk')
                code, text, data = self.scan()
                self.assertEqual(code, 1, text)
                patterns = {p['pattern'] for a in data['artifacts'] for p in a.get('patterns', [])}
                self.assertIn(name, patterns)
                matched = hashlib.sha256(blob if name.startswith('pem') else blob).hexdigest()
                self.assertNotIn(blob.decode(), text + json.dumps(data))
                self.assertTrue(all(len(p['sha256_prefix']) == 8 for a in data['artifacts'] for p in a.get('patterns', [])))

    def test_bare_pem_header_literals_in_binaries_are_not_secret_shapes(self):
        literals = b''.join(('-----BEGIN ' + kind + 'PRIVATE KEY-----\x00').encode() for kind in ('', 'RSA ', 'EC ', 'ENCRYPTED '))
        self.put('node-like.bin', os.urandom(300) + literals + os.urandom(300))
        self.put('doc.md', 'A PEM file starts with `-----BEGIN ' + 'PRIVATE KEY-----` on its own line.\n')
        self.assert_clean()

    def test_documentation_placeholders_are_not_secret_shapes(self):
        self.put('doc.md', 'Send `Authorization: Bearer <token>` and `Bearer $TOKEN`.\nopenssl genpkey writes a PEM key.\nen_US.UTF-8 ak_ placeholder\n')
        self.assert_clean()

    def test_shape_scan_can_be_switched_off(self):
        self.put('x.bin', self.shapes()['jwt'])
        self.assert_clean('--no-pattern-scan')

    def test_secret_shapes_inside_nested_containers_are_found(self):
        self.put('x.tar.gz', gzip.compress(tar_bytes([{'name': 'k', 'data': self.shapes()['age-secret-key']}])))
        code, text, data = self.scan('--archives')
        self.assertEqual(code, 1, text)

    def test_key_material_file_is_found_in_every_encoding_but_never_printed(self):
        key = os.urandom(32)
        key_file = self.tmp / 'issuer-key'
        key_file.write_bytes(key)
        for label, blob in {'raw': key, 'hex': key.hex().encode(), 'b64': base64.b64encode(key), 'b64url': base64.urlsafe_b64encode(key)}.items():
            with self.subTest(encoding=label):
                for child in self.root.iterdir():
                    child.unlink()
                self.put('x.bin', b'....' + blob + b'....')
                code, text, data = self.scan('--key-material', str(key_file))
                self.assertEqual(code, 1, text)
                self.assertNotIn(key.hex(), text + json.dumps(data))

    # -- controls ---------------------------------------------------------------------------------------------------
    def test_positive_controls_run_before_the_real_scan(self):
        self.put('a.txt', 'x' * 30)
        _, _, data = self.scan()
        controls = data['controls']
        self.assertTrue(controls['ok'])
        for codec in ('tar', 'gz', 'bz2', 'xz', 'zip', 'zst', 'ar', 'jsonl', 'wrapped'):
            self.assertIn(codec, controls['detected'], codec)

    def test_report_identifies_canaries_by_hash_prefix_only(self):
        self.put('a.txt', PLAIN)
        _, _, data = self.scan()
        ids = [item['id'] for item in data['canaries']['ids']]
        self.assertIn(hashlib.sha256(PLAIN.encode()).hexdigest()[:8], ids)
        self.assertEqual(data['canaries']['count'], 2)


if __name__ == '__main__':
    unittest.main()
