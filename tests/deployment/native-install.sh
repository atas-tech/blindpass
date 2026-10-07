#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Real disposable KVM lifecycle; never invokes the installer on the host.
set -Eeuo pipefail
repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
os_profile=
archive=
power_loss=false
tool_faults=false
credential_faults=false
recovery=false
faults=false
rollback=false
while (($#)); do
    case "$1" in
        --os) os_profile=$2; shift 2 ;;
        --archive) archive=$2; shift 2 ;;
        --power-loss) power_loss=true; shift ;;
        --tool-faults) tool_faults=true; shift ;;
        --credential-faults) credential_faults=true; shift ;;
        --recovery) recovery=true; shift ;;
        --faults) faults=true; shift ;;
        --rollback) rollback=true; shift ;;
        *) printf '%s\n' 'usage: native-install.sh --os debian-12|ubuntu-24.04 --archive FILE [--power-loss|--tool-faults|--credential-faults|--recovery|--faults|--rollback]' >&2; exit 2 ;;
    esac
done
[[ "$os_profile" == debian-12 || "$os_profile" == ubuntu-24.04 ]] && [[ -f "$archive" ]] || exit 2
[[ "$power_loss" != true || "$tool_faults" != true ]] || exit 2
[[ "$credential_faults" != true || ( "$power_loss" != true && "$tool_faults" != true ) ]] || exit 2
[[ "$recovery" != true || ( "$power_loss" != true && "$tool_faults" != true && "$credential_faults" != true ) ]] || exit 2
[[ "$faults" != true || ( "$power_loss" != true && "$tool_faults" != true && "$credential_faults" != true && "$recovery" != true ) ]] || exit 2
[[ "$rollback" != true || ( "$power_loss" != true && "$tool_faults" != true && "$credential_faults" != true && "$recovery" != true && "$faults" != true ) ]] || exit 2
[[ "$(id -u)" != 0 && -r /dev/kvm && -w /dev/kvm ]] || { printf 'P06-NATIVE unsupported KVM/runner\n'; exit 78; }
for program in qemu-system-x86_64 qemu-img cloud-localds ssh scp ssh-keygen; do command -v "$program" >/dev/null || exit 78; done
[[ -n "${BLINDPASS_FLEET_GUEST_IMAGE:-}" && -n "${BLINDPASS_FLEET_GUEST_IMAGE_SHA256:-}" ]] || exit 78
umask 077
run_dir=$(mktemp -d "${BLINDPASS_NATIVE_RUN_ROOT:-/tmp}/blindpass-p06-native.XXXXXXXX")
ssh_port=${BLINDPASS_FLEET_SSH_PORT:-22262}
[[ "$ssh_port" =~ ^[0-9]+$ && "$ssh_port" -ge 1024 && "$ssh_port" -le 65535 ]] || exit 2
ssh_guest="p06runner@127.0.0.1"
ssh_options=(-i "$run_dir/key" -p "$ssh_port" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=3)
cleanup() {
    if [[ -f "$run_dir/qemu.pid" ]]; then
        qemu_pid=$(<"$run_dir/qemu.pid")
        kill "$qemu_pid" 2>/dev/null || true
        for _ in {1..30}; do kill -0 "$qemu_pid" 2>/dev/null || break; sleep .1; done
        kill -KILL "$qemu_pid" 2>/dev/null || true
    fi
    # Serial/cloud-init may contain ephemeral SSH host keys; never retain it.
    rm -rf -- "$run_dir"
    printf 'P06-NATIVE teardown complete\n'
}
on_exit() {
    exit_status=$?
    if [[ "$exit_status" != 0 ]]; then
        # Installer refusals are fixed strings; never echo arbitrary guest logs.
        ssh "${ssh_options[@]}" "$ssh_guest" 'sudo python3 -c '\''from pathlib import Path; p=Path("/root/p06-native/private-diagnostics.txt"); print("\n".join(line for line in (p.read_text() if p.exists() else "").splitlines() if line.startswith("blindpass install: "))) '\''' 2>/dev/null || true
        # BackupError uses fixed static strings. Keep unrelated child/parser
        # output and private diagnostics inside the disposable guest.
        ssh "${ssh_options[@]}" "$ssh_guest" 'sudo python3 -c '\''from pathlib import Path; p=Path("/root/p06-native/private-diagnostics.txt"); prefixes=("blindpass-controller: backup", "blindpass-controller: SQLite", "blindpass-controller: unsafe backup", "blindpass-controller: recovery", "blindpass-controller: controller key", "blindpass-controller: invalid backup options"); print("\n".join(line for line in (p.read_text() if p.exists() else "").splitlines() if line.startswith(prefixes))) '\''' 2>/dev/null || true
        ssh "${ssh_options[@]}" "$ssh_guest" 'sudo systemctl show blindpass-controller-backup.service --property=Result --property=ExecMainStatus; sudo journalctl -u blindpass-controller-backup.service -o cat --no-pager | sed -n '\''/^blindpass-controller: backup/p; /^blindpass-controller: SQLite/p; /^blindpass-controller: unsafe backup/p; /^blindpass-controller: recovery/p; /^blindpass-controller: controller key/p; /Failed to set up/p'\''' 2>/dev/null || true
        ssh "${ssh_options[@]}" "$ssh_guest" 'sudo systemctl show blindpass-controller-backup-credential-check.service --property=Result --property=ExecMainStatus; sudo journalctl -u blindpass-controller-backup-credential-check.service -o cat --no-pager | sed -n '\''/^blindpass backup credential check: unsafe backup custody$/p; /Failed to set up/p'\''' 2>/dev/null || true
        [[ -f "$run_dir/qemu.err" ]] && printf 'P06-NATIVE qemu_stderr: %s\n' "$(tr '\n' ' ' < "$run_dir/qemu.err" | cut -c1-400)"
        # Kernel resource/I-O fault lines and guest memory, no process arguments.
        ssh "${ssh_options[@]}" "$ssh_guest" 'free -m | sed -n 2p; sudo dmesg 2>/dev/null | grep -i -E "out of memory|oom-kill|killed process|i/o error|ext4-fs|no space|blk_update|virtio_blk|vda" | cut -c1-200 | head -14' 2>/dev/null || true
        # Capacity only (no file contents): free space and directory sizes of the state tree.
        ssh "${ssh_options[@]}" "$ssh_guest" 'df -h /var/lib/blindpass | tail -1; sudo du -sh /var/lib/blindpass/controller/* /var/lib/blindpass/controller/.[!.]* 2>/dev/null | sed "s/\.backup-[0-9a-f]*/.backup-<id>/"' 2>/dev/null || true
        # The upgrade unit's own static refusal strings and exit status only.
        ssh "${ssh_options[@]}" "$ssh_guest" 'sudo systemctl show blindpass-controller-upgrade.service --property=Result --property=ExecMainStatus; sudo journalctl -u blindpass-controller-upgrade.service -o cat --no-pager | sed -n '\''/^blindpass-controller: /p; /^blindpass: /p; /status=/p; /Failed to set up/p; /No space/p'\''' 2>/dev/null || true
        ssh "${ssh_options[@]}" "$ssh_guest" 'sudo systemctl show blindpass-controller-initialize.service --property=Result --property=ExecMainStatus; sudo journalctl -u blindpass-controller-initialize.service -o cat --no-pager | sed -n '\''/^[Bb]lindpass/p; /status=/p; /Failed to set up/p; /^thread .*panicked/p; /^OS can/p; /^P06-CREDENTIAL:/p; /^d[r-]/p; /^l[r-]/p; /^-[r-]/p'\''' 2>/dev/null || true
    fi
    cleanup
    exit "$exit_status"
}
trap on_exit EXIT
trap 'exit 143' INT TERM
ssh-keygen -q -t ed25519 -N '' -f "$run_dir/key"
BLINDPASS_FLEET_SSH_KEY="$run_dir/key" BLINDPASS_FLEET_GUEST_USER=p06runner \
    "$repo_root/tests/fleet/provision-guest.sh" --output-dir "$run_dir/image" >/dev/null
if [[ "$power_loss" == true || "$recovery" == true || "$rollback" == true ]]; then
    # Source, WAL and several private crypto/verification copies must fit.
    # Grow only this disposable overlay; cloud-init grows its root filesystem.
    overlay_size=$(qemu-img info --output=json "$run_dir/image/guest-overlay.qcow2" | python3 -c 'import json,sys; print(json.load(sys.stdin)["virtual-size"])')
    if [[ "$overlay_size" -lt 8589934592 ]]; then
        qemu-img resize "$run_dir/image/guest-overlay.qcow2" 8G >/dev/null
    fi
fi
start_qemu() {
qemu-system-x86_64 -enable-kvm -cpu host -m 2048 -smp 2 -display none \
    -drive "file=$run_dir/image/guest-overlay.qcow2,if=virtio,format=qcow2" \
    -drive "file=$run_dir/image/seed.iso,media=cdrom,readonly=on" \
    -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:$ssh_port-:22" -device virtio-net-pci,netdev=net0 \
    -serial "file:$run_dir/serial.log" -daemonize -pidfile "$run_dir/qemu.pid" 2>>"$run_dir/qemu.err"
}
start_qemu
wait_ssh() {
    for _ in {1..120}; do
        if ssh "${ssh_options[@]}" "$ssh_guest" true 2>/dev/null; then return; fi
        sleep 1
    done
    printf 'P06-NATIVE guest SSH deadline exceeded\n' >&2; return 1
}
wait_ssh
# SSH may restart once during cloud-init after the first successful probe.
# Retry this read-only wait only on transport/timeout failures, never on a
# terminal cloud-init error or any installer action.
cloud_deadline=$((SECONDS+180))
while true; do
    cloud_remaining=$((cloud_deadline-SECONDS))
    [[ "$cloud_remaining" -gt 0 ]] || { printf 'P06-NATIVE cloud-init observation deadline exceeded\n' >&2; exit 1; }
    cloud_wait=30
    [[ "$cloud_remaining" -ge "$cloud_wait" ]] || cloud_wait=$cloud_remaining
    if timeout "${cloud_wait}s" ssh "${ssh_options[@]}" "$ssh_guest" 'sudo cloud-init status --wait >/dev/null 2>&1'; then
        [[ "$SECONDS" -lt "$cloud_deadline" ]] || { printf 'P06-NATIVE cloud-init observation deadline exceeded\n' >&2; exit 1; }
        break
    else cloud_status=$?; fi
    [[ "$cloud_status" == 255 || "$cloud_status" == 124 ]] || exit "$cloud_status"
    [[ "$SECONDS" -lt "$cloud_deadline" ]] || { printf 'P06-NATIVE cloud-init observation deadline exceeded\n' >&2; exit 1; }
    sleep 1
done
actual_os=$(ssh "${ssh_options[@]}" "$ssh_guest" '. /etc/os-release; printf "%s-%s" "$ID" "$VERSION_ID"')
[[ "$actual_os" == "$os_profile" ]] || { printf 'P06-NATIVE pinned OS mismatch\n'; exit 1; }
printf 'P06-NATIVE profile=%s artifact_sha256=%s\n' "$os_profile" "$(sha256sum "$archive" | cut -d' ' -f1)"
# Host image is pinned; OS tools (including a disposable PostgreSQL that stands in
# for the independent recovery authority) are installed only in the guest.
ssh "${ssh_options[@]}" "$ssh_guest" 'sudo timeout 300s sh -c "apt-get -o Acquire::Retries=1 -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20 update >/dev/null 2>&1 && DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=1 -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20 install -y python3 openssl ca-certificates zstd curl util-linux postgresql postgresql-client >/dev/null 2>&1"'
scp -q -i "$run_dir/key" -P "$ssh_port" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
    "$archive" "$repo_root/tests/deployment/native-guest.py" "$repo_root/tests/deployment/canary_log_scan.py" "$repo_root/tests/deployment/native_rollback.py" "$ssh_guest:/tmp/"
printf 'P06-NATIVE guest_test_sha256=%s\n' "$(sha256sum "$repo_root/tests/deployment/native-guest.py" | cut -d' ' -f1)"
ssh "${ssh_options[@]}" "$ssh_guest" 'sudo sh -c '\''install -d -m 0700 /root/p06-native && tar --zstd -xf /tmp/blindpass-controller-*.tar.zst -C /root/p06-native && mv /root/p06-native/blindpass-controller-* /root/p06-native/bundle && cp /tmp/native-guest.py /tmp/canary_log_scan.py /tmp/native_rollback.py /root/p06-native/ && chmod 0700 /root/p06-native/native-guest.py'\'''
ssh "${ssh_options[@]}" "$ssh_guest" 'sudo python3 /root/p06-native/native-guest.py before-reboot'
boot_id=$(ssh "${ssh_options[@]}" "$ssh_guest" 'cat /proc/sys/kernel/random/boot_id')
ssh "${ssh_options[@]}" "$ssh_guest" 'sudo systemctl reboot' || true
for _ in {1..120}; do
    current_boot=$(ssh "${ssh_options[@]}" "$ssh_guest" 'cat /proc/sys/kernel/random/boot_id' 2>/dev/null || true)
    if [[ -n "$current_boot" && "$current_boot" != "$boot_id" ]]; then break; fi
    sleep 1
done
[[ -n "$current_boot" && "$current_boot" != "$boot_id" ]] || { printf 'P06-NATIVE reboot deadline exceeded\n'; exit 1; }
wait_ssh
if [[ "$power_loss" == true ]]; then
    ssh "${ssh_options[@]}" "$ssh_guest" 'sudo python3 /root/p06-native/native-guest.py after-reboot-power-loss'
    ssh "${ssh_options[@]}" "$ssh_guest" 'sudo python3 /root/p06-native/native-guest.py power-loss-prepare'
    qemu_pid=$(<"$run_dir/qemu.pid")
    [[ "$qemu_pid" =~ ^[0-9]+$ ]] || exit 1
    kill -KILL "$qemu_pid"
    # This exact QEMU process owns only this run's disposable overlay. Check
    # exit before reopening its disk; no graceful guest shutdown is requested.
    process_state=
    for _ in {1..50}; do
        if ! kill -0 "$qemu_pid" 2>/dev/null; then break; fi
        process_state=$(awk '{print $3}' "/proc/$qemu_pid/stat" 2>/dev/null || true)
        [[ "$process_state" == Z ]] && break
        sleep .1
    done
    [[ ! -e "/proc/$qemu_pid/stat" || "$process_state" == Z ]] || { printf 'P06-NB05 QEMU termination deadline exceeded\n' >&2; exit 1; }
    rm -- "$run_dir/qemu.pid"
    printf 'P06-NB05 scoped_QEMU_SIGKILL=True guest_shutdown=False\n'
    # Process exit can precede release of a pending block-I/O file reference.
    # Wait read-only for the overlay lock; do not retry a VM start mutation.
    lock_deadline=$((SECONDS+10))
    until qemu-img info "$run_dir/image/guest-overlay.qcow2" >/dev/null 2>&1; do
        [[ "$SECONDS" -lt "$lock_deadline" ]] || { printf 'P06-NB05 disk-lock release deadline exceeded\n' >&2; exit 1; }
        sleep .1
    done
    # Disk-image state after the hard kill, reported (not repaired) so a host-level image fault is never mistaken for an application fault.
    printf 'P06-NB05 qcow2_check: %s\n' "$(qemu-img check "$run_dir/image/guest-overlay.qcow2" 2>&1 | tr '\n' ' ' | cut -c1-300)"
    start_qemu
    wait_ssh
    ssh "${ssh_options[@]}" "$ssh_guest" 'sudo python3 /root/p06-native/native-guest.py power-loss-recover'
else
    if [[ "$rollback" == true ]]; then
        ssh "${ssh_options[@]}" "$ssh_guest" 'sudo python3 /root/p06-native/native-guest.py after-reboot-rollback'
    elif [[ "$faults" == true ]]; then
        ssh "${ssh_options[@]}" "$ssh_guest" 'sudo python3 /root/p06-native/native-guest.py after-reboot-faults'
    elif [[ "$recovery" == true ]]; then
        ssh "${ssh_options[@]}" "$ssh_guest" 'sudo python3 /root/p06-native/native-guest.py after-reboot-recovery'
    elif [[ "$credential_faults" == true ]]; then
        ssh "${ssh_options[@]}" "$ssh_guest" 'sudo python3 /root/p06-native/native-guest.py after-reboot-credential-faults'
    elif [[ "$tool_faults" == true ]]; then
        ssh "${ssh_options[@]}" "$ssh_guest" 'sudo python3 /root/p06-native/native-guest.py after-reboot-tool-faults'
    else
        ssh "${ssh_options[@]}" "$ssh_guest" 'sudo python3 /root/p06-native/native-guest.py after-reboot'
    fi
fi
ssh "${ssh_options[@]}" "$ssh_guest" 'printf "P06-NATIVE kernel=%s systemd=%s\n" "$(uname -r)" "$(systemd --version | head -n1)"'
printf 'P06-NATIVE %s PASS\n' "$os_profile"
