#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Fixed native backup custody check. Metadata only; no credential plaintext read."""
import os
import stat
import sys


def check():
    if os.geteuid() != 0 or len(sys.argv) != 1:
        raise ValueError('unsupported invocation')
    flags = os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    parent = os.open('/', flags)
    try:
        info = os.fstat(parent)
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
            raise ValueError('unsafe parent')
        for component in ['etc', 'blindpass']:
            child = os.open(component, flags, dir_fd=parent)
            os.close(parent)
            parent = child
            info = os.fstat(parent)
            if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
                raise ValueError('unsafe parent')
        for name, minimum, maximum in [
            ('controller-backup-signing-credential', 1, 16384),
            ('controller-backup-recipient-certificate', 1, 16384),
            ('controller-backup-enabled', 0, 128),
        ]:
            descriptor = os.open(name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            try:
                info = os.fstat(descriptor)
                if not (stat.S_ISREG(info.st_mode) and info.st_uid == 0
                        and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600
                        and minimum <= info.st_size <= maximum):
                    raise ValueError('unsafe custody')
            finally:
                os.close(descriptor)
    finally:
        os.close(parent)


if __name__ == '__main__':
    try:
        check()
    except (OSError, ValueError):
        print('blindpass backup credential check: unsafe backup custody', file=sys.stderr)
        sys.exit(1)
    print('{"ok":true}')
