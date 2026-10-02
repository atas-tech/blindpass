#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""P06-O10: verify the actual OCI descriptor graph and attached SPDX content."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import tarfile
import tomllib

ROOT = Path(__file__).resolve().parents[2]


def verify(path, config_digest=None):
    with tarfile.open(path) as archive:
        members={}
        for member in archive:
            name=PurePosixPath(member.name)
            assert not name.is_absolute() and '..' not in name.parts
            assert not member.issym() and not member.islnk()
            assert member.name not in members, 'duplicate OCI member'
            if member.isfile(): members[member.name]=archive.extractfile(member).read()
        root=json.loads(members['index.json'])
        records=[]
        def descriptor(value):
            algorithm,digest=value['digest'].split(':',1)
            assert algorithm=='sha256'
            raw=members['blobs/sha256/'+digest]
            assert len(raw)==value['size'] and hashlib.sha256(raw).hexdigest()==digest, 'OCI content digest mismatch'
            return raw
        def walk(index):
            for entry in index['manifests']:
                value=json.loads(descriptor(entry))
                if 'manifests' in value: walk(value)
                else:
                    descriptor(value['config'])
                    for layer in value['layers']: descriptor(layer)
                    records.append((entry,value))
        walk(root)
        images={entry['digest'] for entry,_ in records if entry.get('platform',{}).get('os')=='linux'}
        assert images, 'no runtime image manifest'
        if config_digest:
            assert any(manifest['config']['digest']==config_digest for entry,manifest in records if entry['digest'] in images), 'tested local image config differs from OCI artifact'
        inventories=[]
        for entry,manifest in records:
            annotations=entry.get('annotations',{})
            if annotations.get('vnd.docker.reference.type')!='attestation-manifest': continue
            bound=annotations['vnd.docker.reference.digest']
            assert bound in images, 'unbound attestation'
            for layer in manifest['layers']:
                statement=json.loads(descriptor(layer))
                assert any(subject.get('digest',{}).get('sha256')==bound.split(':')[1] for subject in statement['subject']), 'wrong attestation subject'
                if statement['predicateType']=='https://spdx.dev/Document':
                    assert statement['predicate']['spdxVersion']=='SPDX-2.3'
                    inventories.append(statement['predicate'])
        assert inventories, 'attached SPDX SBOM missing'
        names=set()
        versions=set()
        def packages(value):
            if isinstance(value,dict):
                for package in value.get('packages',[]):
                    names.add(package['name'])
                    versions.add((package['name'],package.get('versionInfo')))
                for nested in value.values(): packages(nested)
            elif isinstance(value,list):
                for nested in value: packages(nested)
        for inventory in inventories: packages(inventory)
        for expected in ['libssl3','tokio-rustls','serde_json','react','@hpke/core']:
            assert expected in names, 'required runtime/build package missing: '+expected
        cargo=tomllib.loads((ROOT/'Cargo.lock').read_text())['package']
        for package in cargo:
            if 'source' in package:
                assert (package['name'],package['version']) in versions, 'locked Cargo package missing: '+package['name']
        npm=json.loads((ROOT/'package-lock.json').read_text())['packages']
        for path,package in npm.items():
            if 'node_modules/' not in path or package.get('link') or package.get('optional'): continue
            name=path.rsplit('node_modules/',1)[1]
            assert (name,package['version']) in versions, 'required locked npm package missing: '+name
        print(f'PASS P06-O10 bound OCI/SPDX attestation: {len(images)} runtime manifest(s), {len(inventories)} inventory document(s), {len(names)} unique package names')


if __name__=='__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('--archive',required=True)
    parser.add_argument('--config-digest')
    args=parser.parse_args()
    verify(args.archive,args.config_digest)
