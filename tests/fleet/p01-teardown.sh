#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -Eeuo pipefail

mode=${1:-}
case "$mode" in
    failure|cancel) ;;
    *)
        printf 'usage: p01-teardown.sh failure|cancel\n' >&2
        exit 2
        ;;
esac

log_file=$(mktemp "${TMPDIR:-/tmp}/blindpass-p01-teardown.XXXXXX")
run_dir=
runner_pid=
cleanup() {
    if [[ -n "$runner_pid" ]] && kill -0 "$runner_pid" 2>/dev/null; then
        kill -TERM "$runner_pid" 2>/dev/null || true
        wait "$runner_pid" 2>/dev/null || true
    fi
    rm -f -- "$log_file"
    if [[ -n "$run_dir" ]]; then
        rm -rf -- "$run_dir"
    fi
}
trap cleanup EXIT

if [[ "$mode" == failure ]]; then
    set +e
    BLINDPASS_FLEET_INJECT_FAILURE=1 BLINDPASS_FLEET_KEEP_ARTIFACTS=1 \
        ./tests/fleet/p01-vm.sh >"$log_file" 2>&1
    result=$?
    set -e
    [[ "$result" == 42 ]] || {
        cat "$log_file" >&2
        printf 'expected injected guest failure exit 42, got %s\n' "$result" >&2
        exit 1
    }
else
    BLINDPASS_FLEET_CANCEL_AFTER_BOOT_SECONDS=300 BLINDPASS_FLEET_KEEP_ARTIFACTS=1 \
        ./tests/fleet/p01-vm.sh >"$log_file" 2>&1 &
    runner_pid=$!
    cancel_log=
    marker_seen=no
    for _attempt in {1..180}; do
        overlay=$(sed -n 's/^P01-PROVISIONED overlay=\([^ ]*\) seed=.*/\1/p' "$log_file" | tail -n 1)
        if [[ "$overlay" == */image/guest-overlay.qcow2 ]]; then
            candidate=${overlay%/image/guest-overlay.qcow2}/guest-result.log
            if [[ -f "$candidate" ]] && grep -q 'P01-CANCEL-WINDOW' "$candidate"; then
                cancel_log=$candidate
                marker_seen=yes
            fi
        fi
        if [[ "$marker_seen" == yes ]]; then
            break
        fi
        if ! kill -0 "$runner_pid" 2>/dev/null; then
            break
        fi
        sleep 1
    done
    [[ "$marker_seen" == yes && -n "$cancel_log" ]] || {
        cat "$log_file" >&2
        kill "$runner_pid" 2>/dev/null || true
        wait "$runner_pid" 2>/dev/null || true
        printf 'runner did not reach the cancellation window\n' >&2
        exit 1
    }
    kill -TERM "$runner_pid"
    set +e
    wait "$runner_pid"
    result=$?
    set -e
    runner_pid=
    run_dir=${cancel_log%/guest-result.log}
    [[ "$result" != 0 ]] || {
        cat "$log_file" >&2
        printf 'cancelled runner unexpectedly succeeded\n' >&2
        exit 1
    }
fi

if [[ -z "$run_dir" ]]; then
    run_dir=$(awk '/P01-ARTIFACTS-RETAINED / { print $2; exit }' "$log_file")
fi
[[ -n "$run_dir" && -d "$run_dir" ]] || {
    cat "$log_file" >&2
    printf 'runner did not retain an evidence directory\n' >&2
    exit 1
}
if [[ -f "$run_dir/serial.log" ]] && grep -Fq -- '-----BEGIN SSH HOST KEY KEYS-----' "$run_dir/serial.log"; then
    cat "$log_file" >&2
    printf 'ephemeral SSH host private keys survived serial-log redaction\n' >&2
    exit 1
fi
[[ ! -e "$run_dir/image" ]] || {
    cat "$log_file" >&2
    printf 'guest disk artifacts survived %s teardown\n' "$mode" >&2
    exit 1
}
if pgrep -f '[q]emu-system-x86_64.*-name blindpass-p01' >/dev/null 2>&1; then
    cat "$log_file" >&2
    printf 'QEMU process survived %s teardown\n' "$mode" >&2
    exit 1
fi
printf 'P01-I07 %s teardown: PASS\n' "$mode"
