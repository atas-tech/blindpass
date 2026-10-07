#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# P07-D9: build docs/release/vX.Y.Z/evidence.md from recorded scenario results.
#   scripts/release/collect-evidence.sh X.Y.Z [--commit SHA] [--required FILE] [--results DIR] [--output FILE]
set -euo pipefail
release_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
exec python3 "$release_root/scripts/release/collect-evidence.py" "$@"
