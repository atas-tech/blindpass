#!/usr/bin/env bash
# Retirement inventory generator (P08.4). Usage: inventory.sh [--root DIR] [--dispositions FILE] [--check [--accepted]]
set -euo pipefail
exec node "$(dirname -- "${BASH_SOURCE[0]}")/inventory.mjs" "$@"
