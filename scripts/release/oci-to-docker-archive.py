#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Derive a `docker load` archive from the candidate OCI archive, byte for byte on the image content.

A stock Docker (overlay2 image store) refuses a plain OCI archive ("does not contain a manifest.json").
This copies the one linux image's config and layer blobs unchanged into a layout that also carries
the `manifest.json` Docker reads, so `docker load --input` works without extra tools. The multi-
platform index and the BuildKit attestation manifests are not carried: the registry identity stays
the index digest in `controller-image.digest`, and the SBOM assets come from the OCI archive. The
image ID Docker reports after loading is the config digest, printed here as `image_id`.

Every descriptor is checked against its content (size and sha256) first. The output is deterministic
(sorted members, zero mtime and ownership) and is never written over an existing file.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import tarfile
import tempfile

TAG = re.compile(r'(?:[a-z0-9][a-z0-9.-]*(?::[0-9]+)?/)*[a-z0-9][a-z0-9._-]*:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}')
IMAGE_MANIFEST = 'application/vnd.oci.image.manifest.v1+json'
IMAGE_INDEX = 'application/vnd.oci.image.index.v1+json'


class ConversionError(Exception):
    pass


def read_archive(path):
    members = {}
    try:
        with tarfile.open(path) as archive:
            for member in archive:
                name = PurePosixPath(member.name)
                if name.is_absolute() or '..' in name.parts or member.issym() or member.islnk():
                    raise ConversionError('unsafe OCI archive member')
                normal = str(name).removeprefix('./')
                if normal in members:
                    raise ConversionError('duplicate OCI archive member')
                if member.isfile():
                    members[normal] = archive.extractfile(member).read()
    except (OSError, tarfile.TarError) as error:
        raise ConversionError('OCI archive cannot be read') from error
    return members


def blob(members, entry):
    algorithm, _, digest = entry.get('digest', '').partition(':')
    if algorithm != 'sha256' or not re.fullmatch(r'[0-9a-f]{64}', digest):
        raise ConversionError('descriptor digest is not sha256')
    raw = members.get(f'blobs/sha256/{digest}')
    if raw is None or len(raw) != entry.get('size') or hashlib.sha256(raw).hexdigest() != digest:
        raise ConversionError('OCI content digest or size mismatch')
    return digest, raw


def select_image(members):
    try:
        top = json.loads(members['index.json'])['manifests']
        if len(top) != 1 or top[0].get('mediaType') != IMAGE_INDEX:
            raise ConversionError('expected exactly one top-level image index')
        _, index_raw = blob(members, top[0])
        children = json.loads(index_raw)['manifests']
    except (KeyError, ValueError, TypeError) as error:
        raise ConversionError('OCI index is malformed') from error
    images = [child for child in children
              if child.get('mediaType') == IMAGE_MANIFEST
              and 'vnd.docker.reference.type' not in (child.get('annotations') or {})
              and child.get('platform') == {'architecture': 'amd64', 'os': 'linux'}]
    if len(images) != 1:
        raise ConversionError('expected exactly one linux/amd64 image manifest')
    return images[0]


def deterministic_tar(files):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w', format=tarfile.PAX_FORMAT) as archive:
        for name in sorted(files):
            data = files[name]
            info = tarfile.TarInfo(name)
            info.size = len(data); info.mode = 0o644; info.mtime = 0
            info.uid = info.gid = 0; info.uname = info.gname = 'root'
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def convert(archive, tag):
    if not TAG.fullmatch(tag) or '@' in tag:
        raise ConversionError('tag must be a lowercase repository name with an explicit tag')
    members = read_archive(archive)
    image = select_image(members)
    image_digest, image_raw = blob(members, image)
    manifest = json.loads(image_raw)
    config_digest, config_raw = blob(members, manifest['config'])
    files = {f'blobs/sha256/{image_digest}': image_raw, f'blobs/sha256/{config_digest}': config_raw}
    layers = []
    for layer in manifest['layers']:
        digest, raw = blob(members, layer)
        files[f'blobs/sha256/{digest}'] = raw
        layers.append(f'blobs/sha256/{digest}')
    if not layers:
        raise ConversionError('image has no layers')
    files['manifest.json'] = (json.dumps([{'Config': f'blobs/sha256/{config_digest}', 'RepoTags': [tag],
                                           'Layers': layers}], separators=(',', ':')) + '\n').encode()
    files['oci-layout'] = b'{"imageLayoutVersion":"1.0.0"}\n'
    files['index.json'] = (json.dumps({'schemaVersion': 2, 'manifests': [{
        'mediaType': IMAGE_MANIFEST, 'digest': f'sha256:{image_digest}', 'size': len(image_raw),
        'annotations': {'io.containerd.image.name': tag, 'org.opencontainers.image.ref.name': tag.rsplit(':', 1)[1]}}]},
        separators=(',', ':')) + '\n').encode()
    return deterministic_tar(files), config_digest


def publish(data, destination):
    """No-replace publication after fsync, like the release archives."""
    if destination.exists() or destination.is_symlink():
        raise ConversionError('output exists; choose a new name')
    descriptor, temporary = tempfile.mkstemp(prefix='.docker-archive-', suffix='.tmp', dir=destination.parent)
    try:
        with os.fdopen(descriptor, 'wb') as output:
            output.write(data); output.flush(); os.fsync(output.fileno())
        os.link(temporary, destination)
    except OSError as error:
        raise ConversionError('output cannot be written') from error
    finally:
        Path(temporary).unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--tag', required=True)
    options = parser.parse_args()
    data, config_digest = convert(options.archive, options.tag)
    publish(data, options.output)
    print(f'wrote {options.output.name} sha256={hashlib.sha256(data).hexdigest()}')
    print(f'image_id sha256:{config_digest}')


if __name__ == '__main__':
    try:
        main()
    except ConversionError as error:
        print(f'oci-to-docker-archive: {error}', file=__import__('sys').stderr)
        raise SystemExit(1)
