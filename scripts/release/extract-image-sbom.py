#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Read the controller image digest and SPDX inventories out of the candidate OCI archive.

The archive is the exact candidate that is later pushed, so the digest recorded here is the
digest the registry must report after publication. Every descriptor is checked against its
content (size and sha256) before it is trusted, each attestation must bind to the linux image
manifest it names, and the three build-stage inventories must all be present. The full layer and
package cross-checks stay in tests/deployment/controller-sbom.py (P06-O10), which the release
workflow runs as a separate gate.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import tarfile
import tempfile

REQUIRED_DOCUMENTS = {'sbom', 'sbom-ui', 'sbom-binaries'}
REPOSITORY = re.compile(r'ghcr\.io/[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._/-]*')


class ArchiveError(Exception):
    pass


def read_archive(path):
    members = {}
    try:
        with tarfile.open(path) as archive:
            for member in archive:
                name = PurePosixPath(member.name)
                if name.is_absolute() or '..' in name.parts or member.issym() or member.islnk():
                    raise ArchiveError('unsafe OCI archive member')
                normal = str(name).removeprefix('./')
                if normal in members:
                    raise ArchiveError('duplicate OCI archive member')
                if member.isfile():
                    members[normal] = archive.extractfile(member).read()
    except (OSError, tarfile.TarError) as error:
        raise ArchiveError('OCI archive cannot be read') from error
    return members


def descriptor_bytes(members, entry):
    algorithm, _, digest = entry.get('digest', '').partition(':')
    if algorithm != 'sha256' or not re.fullmatch(r'[0-9a-f]{64}', digest):
        raise ArchiveError('descriptor digest is not sha256')
    raw = members.get(f'blobs/sha256/{digest}')
    if raw is None or len(raw) != entry.get('size') or hashlib.sha256(raw).hexdigest() != digest:
        raise ArchiveError('OCI content digest or size mismatch')
    return raw


def extract(path):
    members = read_archive(path)
    try:
        top = json.loads(members['index.json'])['manifests']
    except (KeyError, ValueError, TypeError) as error:
        raise ArchiveError('OCI index.json missing or invalid') from error
    if len(top) != 1:
        raise ArchiveError('expected exactly one top-level image entry')
    root = top[0]
    index = json.loads(descriptor_bytes(members, root))
    if 'manifests' not in index:
        raise ArchiveError('top-level entry is not an image index with attestations')
    images, attestations = {}, []
    for entry in index['manifests']:
        manifest = json.loads(descriptor_bytes(members, entry))
        if entry.get('annotations', {}).get('vnd.docker.reference.type') == 'attestation-manifest':
            attestations.append((entry, manifest))
        elif entry.get('platform', {}).get('os') == 'linux':
            descriptor_bytes(members, manifest['config'])
            for layer in manifest['layers']:
                descriptor_bytes(members, layer)
            images[entry['digest']] = manifest
    if not images:
        raise ArchiveError('no linux image manifest in the archive')
    documents = {}
    for entry, manifest in attestations:
        bound = entry['annotations'].get('vnd.docker.reference.digest')
        if bound not in images:
            raise ArchiveError('attestation does not belong to a linux image in this archive')
        for layer in manifest['layers']:
            statement = json.loads(descriptor_bytes(members, layer))
            if statement.get('predicateType') != 'https://spdx.dev/Document':
                continue
            if not any(subject.get('digest', {}).get('sha256') == bound.split(':', 1)[1] for subject in statement.get('subject', [])):
                raise ArchiveError('attestation subject is not the image it is bound to')
            name = statement['predicate'].get('name')
            if name in documents:
                raise ArchiveError('duplicate SPDX inventory name')
            documents[name] = statement['predicate']
    if set(documents) != REQUIRED_DOCUMENTS:
        raise ArchiveError('SPDX inventories missing or unexpected: ' + ', '.join(sorted(set(documents) ^ REQUIRED_DOCUMENTS)))
    return root['digest'], documents


def publish(destination, content):
    if destination.exists() or destination.is_symlink():
        raise ArchiveError(f'refusing to replace an existing file: {destination.name}')
    descriptor, temporary = tempfile.mkstemp(prefix='.sbom-', suffix='.tmp', dir=destination.parent)
    try:
        with os.fdopen(descriptor, 'w') as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o644)
        os.link(temporary, destination)
    finally:
        Path(temporary).unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--sbom-out', type=Path, required=True)
    parser.add_argument('--digest-out', type=Path, required=True)
    parser.add_argument('--repository', required=True, help='image repository, e.g. ghcr.io/atas-tech/blindpass-controller')
    options = parser.parse_args()
    if not REPOSITORY.fullmatch(options.repository):
        parser.error('repository must be a lowercase ghcr.io repository name with no tag or digest')
    try:
        for destination in (options.sbom_out, options.digest_out):
            if destination.exists() or destination.is_symlink():
                raise ArchiveError(f'refusing to replace an existing file: {destination.name}')
        digest, documents = extract(options.archive)
        bundle = {'format': 'blindpass-oci-spdx-bundle-v1', 'image_index_digest': digest, 'documents': dict(sorted(documents.items()))}
        publish(options.sbom_out, json.dumps(bundle, sort_keys=True, separators=(',', ':')) + '\n')
        publish(options.digest_out, f'{options.repository}@{digest}\n')
    except (ArchiveError, OSError, ValueError, KeyError, TypeError) as error:
        print(f'extract-image-sbom: {error if isinstance(error, ArchiveError) else "archive content is invalid"}', file=__import__('sys').stderr)
        raise SystemExit(1)
    print(f'extract-image-sbom: {digest}, {len(documents)} SPDX inventories')


if __name__ == '__main__':
    main()
