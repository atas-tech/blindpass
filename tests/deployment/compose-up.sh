#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
set -eu
exec python3 "$(dirname "$0")/compose-up.py" "$@"
