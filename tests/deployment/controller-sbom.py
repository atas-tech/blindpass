#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""P06-O10: verify the actual OCI descriptor graph and attached SPDX content."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import tarfile
import tomllib

ROOT = Path(__file__).resolve().parents[2]


def verify(path, config_digest=None, runtime_packages=None):
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
        for entry,manifest in records:
            if entry['digest'] not in images:continue
            config=json.loads(descriptor(manifest['config']))
            rootfs=config.get('rootfs',{})
            assert rootfs.get('type')=='layers', 'runtime image rootfs type invalid'
            diff_ids=rootfs.get('diff_ids')
            assert isinstance(diff_ids,list) and len(diff_ids)==len(manifest['layers']), 'runtime layer/config count mismatch'
            for layer,expected in zip(manifest['layers'],diff_ids,strict=True):
                raw=descriptor(layer);media=layer['mediaType']
                if media in ['application/vnd.oci.image.layer.v1.tar+gzip','application/vnd.docker.image.rootfs.diff.tar.gzip']:
                    source=gzip.GzipFile(fileobj=io.BytesIO(raw))
                else:
                    assert media in ['application/vnd.oci.image.layer.v1.tar','application/vnd.docker.image.rootfs.diff.tar'], 'unsupported runtime layer encoding'
                    source=io.BytesIO(raw)
                digest=hashlib.sha256()
                with source:
                    while chunk:=source.read(1024*1024):digest.update(chunk)
                assert 'sha256:'+digest.hexdigest()==expected, 'runtime layer differs from tested image rootfs hash'
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
        by_name={}
        for inventory in inventories:
            name=inventory.get('name')
            assert name not in by_name, 'duplicate SPDX inventory name'
            by_name[name]=inventory
        assert set(by_name)=={'sbom','sbom-ui','sbom-binaries'}, 'runtime or configured build-stage SPDX inventory missing'
        if runtime_packages:
            rows=[line.split('\t') for line in Path(runtime_packages).read_text().splitlines()]
            assert rows and all(len(row)==2 and all(row) for row in rows), 'invalid installed-package inventory'
            installed={tuple(row) for row in rows}
            assert len(installed)==len(rows), 'duplicate installed-package inventory entry'
            observed={(package['name'],package.get('versionInfo'))
                      for package in by_name['sbom'].get('packages',[])
                      if any(reference.get('referenceType')=='purl' and
                             reference.get('referenceLocator','').startswith('pkg:deb/debian/')
                             for reference in package.get('externalRefs',[]))}
            assert observed==installed, 'runtime SPDX differs from exact tested image installed packages'
        names=set()
        stage_versions={}
        def packages(value,versions):
            if isinstance(value,dict):
                for package in value.get('packages',[]):
                    names.add(package['name'])
                    versions.add((package['name'],package.get('versionInfo')))
                for nested in value.values(): packages(nested,versions)
            elif isinstance(value,list):
                for nested in value: packages(nested,versions)
        for name,inventory in by_name.items():
            stage_versions[name]=set()
            packages(inventory,stage_versions[name])
        assert any(name=='libssl3' for name,_ in stage_versions['sbom']), 'runtime OpenSSL package missing'
        for expected in ['libssl3','tokio-rustls','serde_json','react','@hpke/core']:
            assert expected in names, 'required runtime/build package missing: '+expected
        cargo=tomllib.loads((ROOT/'Cargo.lock').read_text())['package']
        for package in cargo:
            if 'source' in package:
                assert (package['name'],package['version']) in stage_versions['sbom-binaries'], 'locked Cargo package missing from Rust build inventory: '+package['name']
        npm=json.loads((ROOT/'package-lock.json').read_text())['packages']
        for path,package in npm.items():
            if 'node_modules/' not in path or package.get('link') or package.get('optional'): continue
            name=path.rsplit('node_modules/',1)[1]
            assert (name,package['version']) in stage_versions['sbom-ui'], 'required locked npm package missing from UI build inventory: '+name
        print(f'PASS P06-O10 bound OCI/SPDX attestation: {len(images)} runtime manifest(s), {len(inventories)} inventory document(s), {len(names)} unique package names')
        if runtime_packages:print(f'PASS P06-SB01 exact runtime Debian package/version inventory: {len(installed)} packages')


if __name__=='__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('--archive',required=True)
    parser.add_argument('--config-digest')
    parser.add_argument('--runtime-packages',type=Path,help='Tab-separated package/version list queried from the exact tested image')
    args=parser.parse_args()
    verify(args.archive,args.config_digest,args.runtime_packages)
