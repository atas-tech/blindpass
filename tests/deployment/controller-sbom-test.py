#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""P06-SB01–SB04: inventory separation and OCI integrity regressions."""
import contextlib
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import tomllib
import unittest

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('controller_sbom',ROOT/'tests/deployment/controller-sbom.py')
sbom=importlib.util.module_from_spec(spec);spec.loader.exec_module(sbom)


def package(name,version,debian=False):
    value={'name':name,'versionInfo':version}
    if debian:
        value['externalRefs']=[{'referenceCategory':'PACKAGE-MANAGER','referenceType':'purl',
                               'referenceLocator':'pkg:deb/debian/'+name+'@'+version+'?arch=amd64'}]
    return value


def fixture(path, *, missing_runtime=False, duplicate_name=False, wrong_runtime=False, corrupt=False, swapped_builds=False, wrong_diff=False):
    # Real lock entries make build-package coverage complete even in the
    # intentionally missing/wrong runtime cases. Parser fixtures are synthetic.
    cargo=[package(p['name'],p['version']) for p in tomllib.loads((ROOT/'Cargo.lock').read_text())['package'] if 'source' in p]
    npm=[]
    for name,p in json.loads((ROOT/'package-lock.json').read_text())['packages'].items():
        if 'node_modules/' in name and not p.get('link') and not p.get('optional'):
            npm.append(package(name.rsplit('node_modules/',1)[1],p['version']))
    os_packages=[package('libssl3','3.0.22-1~deb12u1',True),package('coreutils','9.1-1',True)]
    runtime=[package('libssl3','3.0.20-1~deb12u2' if wrong_runtime else '3.0.22-1~deb12u1',True),os_packages[1]]
    documents=[('sbom-binaries',cargo+os_packages),('sbom-ui',npm)]
    if swapped_builds:documents=[('sbom-binaries',npm),('sbom-ui',cargo+os_packages)]
    if not missing_runtime: documents.insert(0,('sbom-ui' if duplicate_name else 'sbom',runtime))
    blobs={}
    def blob(raw,media):
        digest=hashlib.sha256(raw).hexdigest()
        blobs['blobs/sha256/'+digest]=raw
        return {'mediaType':media,'digest':'sha256:'+digest,'size':len(raw)}
    def descriptor(value,media):return blob(json.dumps(value,separators=(',',':')).encode(),media)
    stream=io.BytesIO()
    with tarfile.open(fileobj=stream,mode='w') as layer:
        raw=b'P06-SYNTHETIC-LAYER';entry=tarfile.TarInfo('dummy.txt');entry.size=len(raw)
        layer.addfile(entry,io.BytesIO(raw))
    plain=stream.getvalue();diff='sha256:'+('f'*64 if wrong_diff else hashlib.sha256(plain).hexdigest())
    layer=blob(gzip.compress(plain,mtime=0),'application/vnd.oci.image.layer.v1.tar+gzip')
    config=descriptor({'architecture':'amd64','os':'linux','config':{},'rootfs':{'type':'layers','diff_ids':[diff]}},'application/vnd.oci.image.config.v1+json')
    image=descriptor({'schemaVersion':2,'config':config,'layers':[layer]},'application/vnd.oci.image.manifest.v1+json')
    image['platform']={'architecture':'amd64','os':'linux'}
    statements=[]
    for name,packages in documents:
        value={'_type':'https://in-toto.io/Statement/v0.1',
               'subject':[{'name':'p06-synthetic','digest':{'sha256':image['digest'].split(':')[1]}}],
               'predicateType':'https://spdx.dev/Document',
               'predicate':{'spdxVersion':'SPDX-2.3','name':name,'packages':packages}}
        statements.append(descriptor(value,'application/vnd.in-toto+json'))
    attestation=descriptor({'schemaVersion':2,'config':config,'layers':statements},'application/vnd.oci.image.manifest.v1+json')
    attestation['platform']={'architecture':'unknown','os':'unknown'}
    attestation['annotations']={'vnd.docker.reference.type':'attestation-manifest','vnd.docker.reference.digest':image['digest']}
    index={'schemaVersion':2,'manifests':[image,attestation]}
    if corrupt:blobs['blobs/sha256/'+statements[0]['digest'].split(':')[1]]+=b' '
    blobs['index.json']=json.dumps(index).encode()
    blobs['oci-layout']=b'{"imageLayoutVersion":"1.0.0"}'
    with tarfile.open(path,'w') as archive:
        for name,raw in blobs.items():
            info=tarfile.TarInfo(name);info.size=len(raw)
            archive.addfile(info,io.BytesIO(raw))
    return config['digest']


class Verification(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(prefix='blindpass-p06-sbom-parser-')
        self.root=Path(self.temporary.name);self.archive=self.root/'candidate.tar'
        self.runtime=self.root/'runtime.tsv'
        self.runtime.write_text('libssl3\t3.0.22-1~deb12u1\ncoreutils\t9.1-1\n')
    def tearDown(self):self.temporary.cleanup()
    def check(self,digest, runtime=False):
        with contextlib.redirect_stdout(io.StringIO()):
            if runtime:return sbom.verify(self.archive,digest,self.runtime)
            return sbom.verify(self.archive,digest)

    def test_sb01_complete_separate_inventories_and_runtime_os_versions_accept(self):
        digest=fixture(self.archive);self.check(digest,runtime=True)

    def test_sb02_build_union_cannot_replace_runtime_document(self):
        digest=fixture(self.archive,missing_runtime=True)
        with self.assertRaises(AssertionError):self.check(digest)

    def test_sb02_duplicate_inventory_name_cannot_replace_configured_stage(self):
        digest=fixture(self.archive,duplicate_name=True)
        with self.assertRaises(AssertionError):self.check(digest)

    def test_sb03_build_package_cannot_replace_wrong_runtime_os_version(self):
        digest=fixture(self.archive,wrong_runtime=True)
        with self.assertRaises(AssertionError):self.check(digest,runtime=True)

    def test_sb02_correct_names_cannot_hide_swapped_build_inventory_contents(self):
        digest=fixture(self.archive,swapped_builds=True)
        with self.assertRaises(AssertionError):self.check(digest)

    def test_sb04_corrupted_blob_refuses(self):
        digest=fixture(self.archive,corrupt=True)
        with self.assertRaises(AssertionError):self.check(digest)

    def test_sb04_wrong_tested_image_refuses(self):
        fixture(self.archive)
        with self.assertRaises(AssertionError):self.check('sha256:'+'f'*64)

    def test_sb04_valid_descriptor_hash_cannot_hide_wrong_uncompressed_layer_hash(self):
        digest=fixture(self.archive,wrong_diff=True)
        with self.assertRaises(AssertionError):self.check(digest)


if __name__=='__main__':unittest.main()
