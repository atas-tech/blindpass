#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -euo pipefail
release_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
exec python3 "$release_root/scripts/release/release-artifacts.py" "$@"
