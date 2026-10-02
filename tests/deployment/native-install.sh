#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Real disposable KVM lifecycle; never invokes the installer on the host.
set -Eeuo pipefail
repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
os_profile=
archive=
while (($#)); do
    case "$1" in
        --os) os_profile=$2; shift 2 ;;
        --archive) archive=$2; shift 2 ;;
        *) printf '%s\n' 'usage: native-install.sh --os debian-12|ubuntu-24.04 --archive FILE' >&2; exit 2 ;;
    esac
done
[[ "$os_profile" == debian-12 || "$os_profile" == ubuntu-24.04 ]] && [[ -f "$archive" ]] || exit 2
[[ "$(id -u)" != 0 && -r /dev/kvm && -w /dev/kvm ]] || { printf 'P06-NATIVE unsupported KVM/runner\n'; exit 78; }
for program in qemu-system-x86_64 qemu-img cloud-localds ssh scp ssh-keygen; do command -v "$program" >/dev/null || exit 78; done
[[ -n "${BLINDPASS_FLEET_GUEST_IMAGE:-}" && -n "${BLINDPASS_FLEET_GUEST_IMAGE_SHA256:-}" ]] || exit 78
umask 077
run_dir=$(mktemp -d /tmp/blindpass-p06-native.XXXXXXXX)
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
qemu-system-x86_64 -enable-kvm -cpu host -m 2048 -smp 2 -display none \
    -drive "file=$run_dir/image/guest-overlay.qcow2,if=virtio,format=qcow2" \
    -drive "file=$run_dir/image/seed.iso,media=cdrom,readonly=on" \
    -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:$ssh_port-:22" -device virtio-net-pci,netdev=net0 \
    -serial "file:$run_dir/serial.log" -daemonize -pidfile "$run_dir/qemu.pid"
wait_ssh() {
    for _ in {1..120}; do
        if ssh "${ssh_options[@]}" "$ssh_guest" true 2>/dev/null; then return; fi
        sleep 1
    done
    printf 'P06-NATIVE guest SSH deadline exceeded\n' >&2; return 1
}
wait_ssh
ssh "${ssh_options[@]}" "$ssh_guest" 'sudo cloud-init status --wait >/dev/null 2>&1'
actual_os=$(ssh "${ssh_options[@]}" "$ssh_guest" '. /etc/os-release; printf "%s-%s" "$ID" "$VERSION_ID"')
[[ "$actual_os" == "$os_profile" ]] || { printf 'P06-NATIVE pinned OS mismatch\n'; exit 1; }
printf 'P06-NATIVE profile=%s artifact_sha256=%s\n' "$os_profile" "$(sha256sum "$archive" | cut -d' ' -f1)"
# Host image is pinned; OS tools are installed only in the disposable guest.
ssh "${ssh_options[@]}" "$ssh_guest" 'sudo timeout 300s sh -c "apt-get -o Acquire::Retries=1 -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20 update >/dev/null 2>&1 && DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=1 -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20 install -y python3 openssl ca-certificates zstd curl util-linux >/dev/null 2>&1"'
scp -q -i "$run_dir/key" -P "$ssh_port" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
    "$archive" "$repo_root/tests/deployment/native-guest.py" "$ssh_guest:/tmp/"
printf 'P06-NATIVE guest_test_sha256=%s\n' "$(sha256sum "$repo_root/tests/deployment/native-guest.py" | cut -d' ' -f1)"
ssh "${ssh_options[@]}" "$ssh_guest" 'sudo sh -c '\''install -d -m 0700 /root/p06-native && tar --zstd -xf /tmp/blindpass-controller-*.tar.zst -C /root/p06-native && mv /root/p06-native/blindpass-controller-* /root/p06-native/bundle && cp /tmp/native-guest.py /root/p06-native/native-guest.py && chmod 0700 /root/p06-native/native-guest.py'\'''
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
ssh "${ssh_options[@]}" "$ssh_guest" 'sudo python3 /root/p06-native/native-guest.py after-reboot'
ssh "${ssh_options[@]}" "$ssh_guest" 'printf "P06-NATIVE kernel=%s systemd=%s\n" "$(uname -r)" "$(systemd --version | head -n1)"'
printf 'P06-NATIVE %s PASS\n' "$os_profile"
