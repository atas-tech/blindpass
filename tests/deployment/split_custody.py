# SPDX-License-Identifier: AGPL-3.0-only
"""Split backup custody fixtures for the container harnesses (ADR 0013, P06-D29).

`custody` is what a backup host holds (signing credential, signer certificate and the
recipient's certificate). `offline` is what the operator holds elsewhere (recipient
private credential and the signer's certificate). Credentials are generated inside the
pinned image as UID 10001; dummy material only.
"""
from pathlib import Path

CUSTODY_FILES = ('signing.pem', 'signing-certificate.pem', 'recipient-certificate.pem')
OFFLINE_FILES = ('recipient.pem', 'recipient-certificate.pem', 'signing-certificate.pem')
# Arguments of an operator command that opens an archive with the offline material
# mounted at /offline.
OFFLINE_OPEN = ['--recipient-key-file', '/offline/recipient.pem',
                '--signing-certificate-file', '/offline/signing-certificate.pem']


def own(docker, helper, *paths):
    for path in paths:
        docker('run', '--rm', '--user', '0', '--mount', f'type=bind,src={path},dst=/d',
               '--entrypoint', '/bin/sh', helper, '-ec', 'chown -R 10001:10001 /d')


def provision(docker, image, helper, custody, offline):
    """Create both role credentials and place only public material on the backup host."""
    custody, offline = Path(custody), Path(offline)
    own(docker, helper, custody, offline)
    mounts = ['--mount', f'type=bind,src={custody},dst=/recovery',
              '--mount', f'type=bind,src={offline},dst=/offline']

    def key_init(*arguments):
        docker('run', '--rm', '--network', 'none', '--user', '10001:10001', '--ulimit', 'core=0',
               *mounts, '--entrypoint', '/usr/local/bin/blindpass', image, 'backup', 'key-init', *arguments)
    key_init('--role', 'signing', '--output', '/recovery/signing.pem',
             '--certificate-output', '/recovery/signing-certificate.pem')
    key_init('--role', 'recipient', '--output', '/offline/recipient.pem',
             '--certificate-output', '/offline/recipient-certificate.pem')
    docker('run', '--rm', '--user', '10001:10001', '--network', 'none', *mounts, '--entrypoint', '/bin/sh', helper, '-ec',
           'umask 077; cp /offline/recipient-certificate.pem /recovery/recipient-certificate.pem; '
           'cp /recovery/signing-certificate.pem /offline/signing-certificate.pem')


def assert_host_holds_no_decrypt_key(docker, helper, custody):
    """The backup host's directory must never contain the recipient private key."""
    listing = docker('run', '--rm', '--user', '10001:10001', '--network', 'none',
                     '--mount', f'type=bind,src={custody},dst=/d,readonly', '--entrypoint', '/bin/sh', helper, '-ec',
                     'for f in /d/*; do printf "%s %s\\n" "$(basename "$f")" "$(grep -c "PRIVATE KEY" "$f")"; done').stdout.decode()
    # Counts of `PRIVATE KEY` armor lines: one key has a BEGIN and an END line.
    keys = {name: int(count) for name, count in (line.split() for line in listing.splitlines())}
    assert set(keys) == set(CUSTODY_FILES), keys
    assert keys['signing.pem'] == 2 and keys['signing-certificate.pem'] == 0 and keys['recipient-certificate.pem'] == 0, keys
