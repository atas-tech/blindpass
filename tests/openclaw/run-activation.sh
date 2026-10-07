#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Runs the P09 real-runtime scenarios (A01-A03, P09-I01..I03, P09-E01/E02) inside a throwaway guest.
#
#   tests/openclaw/run-activation.sh --release 2026.8.35 [--scenario 'a01*'] [--evidence FILE]
#
# The guest holds the real OpenClaw gateway, sops and age plus the plugin tree under test. Nothing
# from the scenarios runs on the host. Exit 78 with a P09-UNSUPPORTED record means an infrastructure
# prerequisite is missing, which is not a pass.
set -Eeuo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd "$here/../.." && pwd)
# shellcheck source=tools.lock
source "$here/tools.lock"

release=
pattern='*'
evidence=
while (($# > 0)); do
    case "$1" in
        --release) release=${2:?--release needs a value}; shift 2 ;;
        --scenario) pattern=${2:?--scenario needs a glob}; shift 2 ;;
        --evidence) evidence=${2:?--evidence needs a file}; shift 2 ;;
        -h|--help) sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
done
[[ "$release" == "$OPENCLAW_RELEASE" ]] || {
    printf 'P09-UNSUPPORTED only OpenClaw %s is reviewed (got %q)\n' "$OPENCLAW_RELEASE" "$release" >&2
    exit 78
}

export BLINDPASS_OPENCLAW_VM_DIR=
vm="$here/vm.sh"
[[ -e "${XDG_DATA_HOME:-$HOME/.local/share}/blindpass/vm-images/openclaw-$OPENCLAW_RELEASE-base.qcow2" ]] || "$vm" prepare
unset BLINDPASS_OPENCLAW_VM_DIR

log=$(mktemp "${TMPDIR:-/tmp}/blindpass-p09-run.XXXXXXXX")
cleanup() {
    "$vm" down >/dev/null 2>&1 || true
    if [[ -n "$evidence" ]]; then
        install -m 0644 "$log" "$evidence"
    fi
    rm -f -- "$log"
}
trap cleanup EXIT

{
    printf 'P09-HOST-ENV runner_owner=%s qemu=%s kvm=%s release=%s date=%s\n' \
        "${BLINDPASS_FLEET_RUNNER_OWNER:-unset}" "$(qemu-system-x86_64 --version | head -n 1)" \
        "$(stat -c '%A:%a' /dev/kvm)" "$release" "$(date -u +%FT%TZ)"
    printf 'P09-HOST-REPO commit=%s dirty=%s\n' "$(git -C "$repo" rev-parse --short HEAD)" \
        "$(git -C "$repo" status --porcelain | wc -l)"
} | tee -a "$log"

"$vm" up | tee -a "$log"

stage=$(mktemp -d "${TMPDIR:-/tmp}/blindpass-p09-stage.XXXXXXXX")
trap 'rm -rf -- "$stage"; cleanup' EXIT
tar -C "$repo" --exclude=node_modules --exclude=dist --exclude=test-results \
    -cf "$stage/tree.tar" packages/openclaw-plugin tests/openclaw/scenarios tests/openclaw/guest tests/openclaw/tools.lock
"$vm" scp "$stage/tree.tar" /tmp/
"$vm" ssh 'rm -rf ~/repo && mkdir -p ~/repo && tar -C ~/repo -xf /tmp/tree.tar && rm -f /tmp/tree.tar'

"$vm" ssh 'cat /opt/openclaw/TOOLS.txt; uname -r; systemd-detect-virt' | sed 's/^/P09-GUEST-ENV /' | tee -a "$log"

status=0
"$vm" ssh "cd ~/repo && export PATH=/opt/openclaw/node_modules/.bin:\$PATH && \
    P09_RELEASE=$release node --test --test-reporter=spec --test-concurrency=1 --test-timeout=600000 \
    tests/openclaw/scenarios/$pattern.test.mjs" 2>&1 | tee -a "$log" || status=${PIPESTATUS[0]}
printf 'P09-RUN-EXIT %s\n' "$status" | tee -a "$log"
exit "$status"
