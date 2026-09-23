#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -Eeuo pipefail

unsupported() {
    printf 'P01-UNSUPPORTED %s\n' "$1" >&2
    exit 78
}

command -v qemu-system-x86_64 >/dev/null 2>&1 || unsupported 'qemu-system-x86_64 is unavailable'
command -v qemu-img >/dev/null 2>&1 || unsupported 'qemu-img is unavailable'
command -v ssh >/dev/null 2>&1 || unsupported 'ssh is unavailable'
command -v scp >/dev/null 2>&1 || unsupported 'scp is unavailable'
[[ -e /dev/kvm && -r /dev/kvm && -w /dev/kvm ]] || unsupported '/dev/kvm is unavailable or inaccessible'
[[ -n "${BLINDPASS_FLEET_RUNNER_OWNER:-}" ]] || unsupported 'BLINDPASS_FLEET_RUNNER_OWNER is unset'
[[ -n "${BLINDPASS_FLEET_SSH_KEY:-}" && -r "$BLINDPASS_FLEET_SSH_KEY" ]] || \
    unsupported 'BLINDPASS_FLEET_SSH_KEY is missing or unreadable'

printf 'P01-HOST-ENV runner_owner=%s qemu=%s qemu_img=%s kvm=%s cloud_localds=%s\n' \
    "$BLINDPASS_FLEET_RUNNER_OWNER" \
    "$(qemu-system-x86_64 --version | head -n 1)" \
    "$(qemu-img --version | head -n 1)" \
    "$(stat -c '%A:%a' /dev/kvm)" \
    "$(command -v cloud-localds)"

guest_user=${BLINDPASS_FLEET_GUEST_USER:-blindpass}
ssh_port=${BLINDPASS_FLEET_SSH_PORT:-22222}
keep_artifacts=${BLINDPASS_FLEET_KEEP_ARTIFACTS:-0}
inject_failure=${BLINDPASS_FLEET_INJECT_FAILURE:-0}
cancel_after_boot=${BLINDPASS_FLEET_CANCEL_AFTER_BOOT_SECONDS:-}
[[ "$inject_failure" == 0 || "$inject_failure" == 1 ]] || {
    printf 'BLINDPASS_FLEET_INJECT_FAILURE must be 0 or 1\n' >&2
    exit 2
}
if [[ -n "$cancel_after_boot" && ! "$cancel_after_boot" =~ ^[0-9]+$ ]]; then
    printf 'BLINDPASS_FLEET_CANCEL_AFTER_BOOT_SECONDS must be an integer\n' >&2
    exit 2
fi
run_dir=$(mktemp -d "${TMPDIR:-/tmp}/blindpass-p01.XXXXXXXX")
qemu_pidfile=$run_dir/qemu.pid
serial_log=$run_dir/serial.log
cleanup_done=0
guest_ssh_pid=

cleanup() {
    [[ "$cleanup_done" == 0 ]] || return
    cleanup_done=1
    if [[ -n "$guest_ssh_pid" ]]; then
        kill "$guest_ssh_pid" 2>/dev/null || true
        wait "$guest_ssh_pid" 2>/dev/null || true
    fi
    if [[ -f "$qemu_pidfile" ]]; then
        qemu_pid=$(<"$qemu_pidfile")
        kill "$qemu_pid" 2>/dev/null || true
        for _attempt in {1..20}; do
            kill -0 "$qemu_pid" 2>/dev/null || break
            sleep 0.1
        done
        kill -KILL "$qemu_pid" 2>/dev/null || true
    fi
    if [[ "$keep_artifacts" == 1 ]]; then
        # Retain only sanitized text evidence. Guest disks and seed media are
        # disposable state, even when logs are kept for CI review.
        rm -rf -- "$run_dir/image"
        printf 'P01-ARTIFACTS-RETAINED %s\n' "$run_dir" >&2
    else
        rm -rf -- "$run_dir"
    fi
}
on_signal() {
    cleanup
    trap - EXIT INT TERM
    exit 143
}
trap cleanup EXIT
trap on_signal INT TERM

"$(dirname "$0")/provision-guest.sh" --output-dir "$run_dir/image"
cargo build --release --workspace --locked

qemu-system-x86_64 \
    -name blindpass-p01,debug-threads=on \
    -enable-kvm -cpu host -m 2048 -smp 2 \
    -drive "file=$run_dir/image/guest-overlay.qcow2,if=virtio,format=qcow2" \
    -drive "file=$run_dir/image/seed.iso,if=virtio,media=cdrom,readonly=on,format=raw" \
    -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:$ssh_port-:22" \
    -device virtio-net-pci,netdev=net0 \
    -display none -monitor none -serial "file:$serial_log" \
    -pidfile "$qemu_pidfile" -daemonize

ssh_options=(-i "$BLINDPASS_FLEET_SSH_KEY" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=3 -p "$ssh_port")
scp_options=(-i "$BLINDPASS_FLEET_SSH_KEY" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=3 -P "$ssh_port")
guest_target="$guest_user@127.0.0.1"
for _attempt in {1..90}; do
    if ssh "${ssh_options[@]}" "$guest_target" true 2>/dev/null; then
        break
    fi
    sleep 2
done
ssh "${ssh_options[@]}" "$guest_target" true >/dev/null 2>&1 || {
    printf 'guest did not become reachable; serial log: %s\n' "$serial_log" >&2
    exit 1
}

scp "${scp_options[@]}" \
    target/release/blindpass-broker \
    target/release/blindpass-backup-probe \
    target/release/blindpass-consumer \
    target/release/blindpass-custody-probe \
    target/release/blindpass-crash-probe \
    target/release/blindpass-credential-loader \
    target/release/blindpass-transport-probe \
    target/release/blindpass-workload-client \
    tests/fleet/p01-guest.sh \
    "$guest_target:/tmp/"
scp "${scp_options[@]}" deploy/native/*.service "$guest_target:/tmp/"
guest_environment=(env)
[[ "$inject_failure" == 1 ]] && guest_environment+=(BLINDPASS_P01_INJECT_FAILURE=1)
[[ -n "$cancel_after_boot" ]] && guest_environment+=(BLINDPASS_P01_CANCEL_AFTER_BOOT_SECONDS="$cancel_after_boot")
ssh "${ssh_options[@]}" "$guest_target" \
    "sudo install -m 0755 /tmp/p01-guest.sh /usr/local/sbin/blindpass-p01-guest && sudo ${guest_environment[*]} /usr/local/sbin/blindpass-p01-guest" \
    >"$run_dir/guest-result.log" 2>&1 &
guest_ssh_pid=$!
set +e
wait "$guest_ssh_pid"
guest_result=$?
set -e
guest_ssh_pid=
cat "$run_dir/guest-result.log"

if [[ "$guest_result" != 0 ]]; then
    exit "$guest_result"
fi

printf 'P01-VM-COMPLETE runner_owner=%s serial_log=%s\n' "$BLINDPASS_FLEET_RUNNER_OWNER" "$serial_log"
