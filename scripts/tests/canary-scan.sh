#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Fail-closed exposure scanner (P07-I04, pilot S06/S07). See canary_scan.py or --help.
# Exit: 0 clean, 1 exposure found, 2 configuration error, 3 incomplete scan (never a pass).
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd) || exit 2
exec python3 "$here/canary_scan.py" "$@"
