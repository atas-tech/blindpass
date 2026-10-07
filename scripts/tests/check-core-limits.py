#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Static check that every shipped service disables core dumps (pilot S07, P07-I04).

A crash dump of the broker, controller, restore job or database holds process memory: plaintext
credentials, decrypted backup bundles, session keys. systemd units must set LimitCORE=0 in [Service];
Compose services must set ulimits.core to 0 (an anchor or `<<` merge counts). Anything that cannot be
parsed, or no input at all, fails the run. Exceptions need a written reason and are always printed.

Exit: 0 clean, 1 service without a core limit, 2 bad exceptions file, 3 nothing found or unparsable.
Usage: check-core-limits.py [--exceptions FILE] PATH...
"""
import argparse
import fnmatch
import json
import os
import re
import sys

try:
    import yaml
except ImportError:  # fail closed rather than silently skip Compose files
    yaml = None


def unit_files(paths):
    for root in paths:
        if os.path.isfile(root):
            yield root
            continue
        for directory, _, names in os.walk(root):
            for name in sorted(names):
                yield os.path.join(directory, name)


def service_section(text):
    section, current = [], None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith('[') and stripped.endswith(']'):
            current = stripped
            continue
        if current == '[Service]':
            section.append(stripped)
    return section


def core_zero(value):
    if value == 0 or value == '0':
        return True
    return isinstance(value, dict) and value.get('soft') in (0, '0') and value.get('hard') in (0, '0')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('paths', nargs='+')
    parser.add_argument('--exceptions', help='JSON array of {path, service, reason}; path is a glob, service a name or *')
    args = parser.parse_args(argv)
    exceptions = []
    if args.exceptions:
        try:
            exceptions = json.load(open(args.exceptions))
            for entry in exceptions:
                if len(str(entry['reason']).strip()) < 10 or not entry['path'] or not entry['service']:
                    raise ValueError('reason of at least 10 characters, path and service are required')
        except (OSError, ValueError, KeyError, TypeError) as error:
            print(f'check-core-limits: bad exceptions file: {error}', file=sys.stderr)
            return 2
    units = composes = 0
    violations, excepted, incomplete = [], [], []

    def judge(path, service, ok):
        if ok:
            return
        for entry in exceptions:
            if fnmatch.fnmatch(path, entry['path']) and entry['service'] in ('*', service):
                excepted.append((path, service, entry['reason']))
                return
        violations.append((path, service))

    for path in unit_files(args.paths):
        if path.endswith('.service'):
            units += 1
            try:
                text = open(path, encoding='utf-8').read()
            except OSError as error:
                incomplete.append((path, type(error).__name__))
                continue
            ok = any(re.fullmatch(r'LimitCORE\s*=\s*0', line) for line in service_section(text))
            judge(path, '[Service]', ok)
        elif re.search(r'(^|/)(docker-)?compose[^/]*\.ya?ml$', path):
            if yaml is None:
                incomplete.append((path, 'PyYAML is not installed'))
                continue
            composes += 1
            try:
                document = yaml.safe_load(open(path, encoding='utf-8'))
                services = document.get('services') or {}
            except (OSError, yaml.YAMLError, AttributeError) as error:
                incomplete.append((path, type(error).__name__))
                continue
            for name, service in services.items():
                ulimits = (service or {}).get('ulimits') or {}
                judge(path, name, core_zero(ulimits.get('core')))
    print(f'check-core-limits: {units} units and {composes} Compose files checked')
    for path, service in violations:
        print(f'  VIOLATION {path}: {service} does not disable core dumps')
    for path, service, reason in excepted:
        print(f'  excepted {path}: {service} ({reason})')
    for path, why in incomplete:
        print(f'  INCOMPLETE {path}: {why}')
    if incomplete or units + composes == 0:
        if units + composes == 0:
            print('  INCOMPLETE: no systemd unit or Compose file found')
        return 3
    return 1 if violations else 0


if __name__ == '__main__':
    sys.exit(main())
