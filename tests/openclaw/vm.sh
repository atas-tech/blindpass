#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Disposable QEMU/KVM guest for the P09 OpenClaw migration scenarios.
#
#   vm.sh prepare    build the cached base image (Node, sops, age, OpenClaw)
#   vm.sh up         boot a fresh throwaway overlay of the base image
#   vm.sh ssh [cmd]  run a command (or shell) in the guest
#   vm.sh scp SRC... DEST   copy host files into the guest (DEST is a guest path)
#   vm.sh down       stop the guest and delete every run artifact
#
# State lives in $BLINDPASS_OPENCLAW_VM_DIR (default: a fresh mktemp dir recorded in
# $XDG_RUNTIME_DIR/blindpass-openclaw-vm.dir). The guest holds only generated dummy
# credentials; the SSH key is created per run and never leaves the run directory.
set -Eeuo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=tools.lock
source "$here/tools.lock"

unsupported() {
    printf 'P09-UNSUPPORTED %s\n' "$1" >&2
    exit 78
}

guest_user=${BLINDPASS_FLEET_GUEST_USER:-blindpass}
image_store=${XDG_DATA_HOME:-$HOME/.local/share}/blindpass/vm-images
tool_cache=${XDG_CACHE_HOME:-$HOME/.cache}/blindpass/openclaw-tools
raw_image=${BLINDPASS_FLEET_GUEST_IMAGE:-$image_store/noble-server-cloudimg-amd64.img}
raw_sha=${BLINDPASS_FLEET_GUEST_IMAGE_SHA256:-}
base_image=$image_store/openclaw-$OPENCLAW_RELEASE-base.qcow2
pointer=${XDG_RUNTIME_DIR:-/tmp}/blindpass-openclaw-vm.dir
guest_disk=${BLINDPASS_OPENCLAW_GUEST_DISK:-14G}
guest_mem=${BLINDPASS_OPENCLAW_GUEST_MEM_MB:-4096}

state_dir() {
    if [[ -n "${BLINDPASS_OPENCLAW_VM_DIR:-}" ]]; then
        printf '%s\n' "$BLINDPASS_OPENCLAW_VM_DIR"
    elif [[ -r "$pointer" ]]; then
        cat "$pointer"
    else
        return 1
    fi
}

preflight() {
    [[ "$(id -u)" != 0 ]] || unsupported 'run as the runner owner, not through sudo'
    for tool in qemu-system-x86_64 qemu-img ssh scp ssh-keygen cloud-localds sha256sum; do
        command -v "$tool" >/dev/null 2>&1 || unsupported "$tool is unavailable"
    done
    [[ -r /dev/kvm && -w /dev/kvm ]] || unsupported '/dev/kvm is unavailable or inaccessible'
    [[ -r "$raw_image" ]] || unsupported "guest image is missing: $raw_image"
    [[ -n "$raw_sha" ]] || {
        [[ -r "$raw_image.sha256" ]] && raw_sha=$(awk '{print $1}' "$raw_image.sha256")
    }
    [[ -n "$raw_sha" ]] || unsupported 'BLINDPASS_FLEET_GUEST_IMAGE_SHA256 is unset and no .sha256 sidecar exists'
    [[ -n "${BLINDPASS_FLEET_RUNNER_OWNER:-}" ]] || unsupported 'BLINDPASS_FLEET_RUNNER_OWNER is unset'
}

free_port() {
    local port
    for port in $(seq 22290 22340); do
        if ! (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
            printf '%s\n' "$port"
            return 0
        fi
    done
    return 1
}

load_state() {
    local dir
    dir=$(state_dir) || { printf 'no guest is running (vm.sh up first)\n' >&2; exit 2; }
    # shellcheck disable=SC1091
    source "$dir/state.env"
    ssh_options=(-i "$dir/id_ed25519" -o BatchMode=yes -o StrictHostKeyChecking=no
        -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=5 -p "$ssh_port")
    scp_options=(-i "$dir/id_ed25519" -o BatchMode=yes -o StrictHostKeyChecking=no
        -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=5 -P "$ssh_port")
}

boot() { # boot <backing image> <backing sha or ''>
    local backing=$1 dir port
    dir=$(mktemp -d "${TMPDIR:-/tmp}/blindpass-p09.XXXXXXXX")
    chmod 0700 "$dir"
    printf '%s\n' "$dir" >"$pointer"
    ssh-keygen -q -t ed25519 -N '' -C 'blindpass-p09-disposable' -f "$dir/id_ed25519"
    port=$(free_port) || unsupported 'no free local SSH port in 22290-22340'

    if [[ "$backing" == "$raw_image" ]]; then
        [[ "$(sha256sum "$raw_image" | awk '{print $1}')" == "$raw_sha" ]] || \
            unsupported 'guest image hash mismatch'
    fi
    qemu-img create -q -f qcow2 -F qcow2 -b "$backing" "$dir/guest-overlay.qcow2"
    qemu-img resize -q "$dir/guest-overlay.qcow2" "$guest_disk"
    umask 077
    printf '#cloud-config\nusers:\n  - default\n  - name: %s\n    groups: [sudo]\n    shell: /bin/bash\n    sudo: ["ALL=(ALL) NOPASSWD:ALL"]\n    lock_passwd: true\n    ssh_authorized_keys:\n      - %s\nssh_pwauth: false\npackage_update: false\n' \
        "$guest_user" "$(<"$dir/id_ed25519.pub")" >"$dir/user-data"
    printf 'instance-id: blindpass-p09-%s\nlocal-hostname: blindpass-p09\n' "$(basename "$dir")" >"$dir/meta-data"
    cloud-localds "$dir/seed.iso" "$dir/user-data" "$dir/meta-data"
    printf 'ssh_port=%s\nqemu_pidfile=%s\n' "$port" "$dir/qemu.pid" >"$dir/state.env"

    qemu-system-x86_64 -name 'blindpass-p09' -enable-kvm -cpu host -m "$guest_mem" -smp 4 \
        -drive "file=$dir/guest-overlay.qcow2,if=virtio,format=qcow2" \
        -drive "file=$dir/seed.iso,if=virtio,media=cdrom,readonly=on,format=raw" \
        -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:$port-:22" -device virtio-net-pci,netdev=net0 \
        -display none -monitor none -serial "file:$dir/serial.log" \
        -pidfile "$dir/qemu.pid" -daemonize

    load_state
    local attempt
    for attempt in $(seq 1 90); do
        ssh "${ssh_options[@]}" "$guest_user@127.0.0.1" true 2>/dev/null && return 0
        sleep 2
    done
    printf 'guest did not become reachable; serial log kept in %s\n' "$dir" >&2
    exit 1
}

guest_run() {
    ssh "${ssh_options[@]}" "$guest_user@127.0.0.1" "$@"
}

stop_guest() { # stop_guest <graceful 0|1>
    local dir pid attempt
    dir=$(state_dir) || return 0
    [[ -d "$dir" ]] || return 0
    if [[ -f "$dir/qemu.pid" ]]; then
        pid=$(<"$dir/qemu.pid")
        if [[ "$1" == 1 ]]; then
            load_state
            guest_run 'sudo systemctl poweroff' 2>/dev/null || true
            for attempt in $(seq 1 60); do
                kill -0 "$pid" 2>/dev/null || break
                sleep 1
            done
        fi
        kill "$pid" 2>/dev/null || true
        for attempt in $(seq 1 20); do
            kill -0 "$pid" 2>/dev/null || break
            sleep 0.1
        done
        kill -KILL "$pid" 2>/dev/null || true
    fi
}

fetch_tools() {
    install -d -m 0700 "$tool_cache"
    local file expected
    for pair in "$SOPS_ASSET:$SOPS_SHA256" "$AGE_ASSET:$AGE_SHA256"; do
        file=${pair%%:*}
        expected=${pair##*:}
        if [[ ! -r "$tool_cache/$file" ]]; then
            case "$file" in
                sops-*) gh release download "$SOPS_VERSION" -R getsops/sops -p "$file" -D "$tool_cache" ;;
                age-*) gh release download "$AGE_VERSION" -R FiloSottile/age -p "$file" -D "$tool_cache" ;;
            esac
        fi
        [[ "$(sha256sum "$tool_cache/$file" | awk '{print $1}')" == "$expected" ]] || \
            unsupported "hash mismatch for $file; delete $tool_cache/$file and retry"
    done
}

node_tarball() {
    local node_bin node_root out
    node_bin=$(readlink -f "$(command -v node)")
    node_root=$(dirname "$(dirname "$node_bin")")
    [[ -d "$node_root/lib/node_modules/npm" && -x "$node_root/bin/node" ]] || \
        unsupported "host node at $node_root is not an official-layout distribution"
    out=$tool_cache/node-$(node --version)-host.tar.gz
    [[ -r "$out" ]] || tar -C "$node_root" -czf "$out" bin lib include share
    printf '%s\n' "$out"
}

cmd=${1:-}
shift || true
case "$cmd" in
    prepare)
        preflight
        fetch_tools
        node_archive=$(node_tarball)
        [[ ! -e "$base_image" ]] || { printf 'base image already present: %s\n' "$base_image"; exit 0; }
        trap 'stop_guest 0; dir=$(state_dir 2>/dev/null) && rm -rf -- "$dir"; rm -f -- "$pointer"' EXIT
        boot "$raw_image" "$raw_sha"
        load_state
        ssh_target="$guest_user@127.0.0.1"
        guest_run 'cloud-init status --wait >/dev/null 2>&1 || true'
        scp "${scp_options[@]}" "$node_archive" "$tool_cache/$SOPS_ASSET" "$tool_cache/$AGE_ASSET" \
            "$here/guest/setup.sh" "$here/tools.lock" "$ssh_target:/tmp/"
        guest_run "sudo bash /tmp/setup.sh '$(basename "$node_archive")' '$SOPS_ASSET' '$AGE_ASSET' '$SOPS_SHA256' '$AGE_SHA256' '$OPENCLAW_RELEASE'"
        guest_run 'test -x /opt/openclaw/node_modules/.bin/openclaw && node --version >/dev/null' || \
            unsupported 'guest setup did not produce a working OpenClaw install'
        stop_guest 1
        dir=$(state_dir)
        qemu-img convert -O qcow2 "$dir/guest-overlay.qcow2" "$base_image.partial"
        mv -- "$base_image.partial" "$base_image"
        printf 'P09-BASE-IMAGE %s\n' "$base_image"
        ;;
    up)
        preflight
        [[ -e "$base_image" ]] || unsupported "no base image; run: $0 prepare"
        boot "$base_image" ''
        guest_run 'cloud-init status --wait >/dev/null 2>&1 || true'
        printf 'P09-VM-UP dir=%s ssh_port=%s\n' "$(state_dir)" "$ssh_port"
        ;;
    ssh)
        load_state
        guest_run "$@"
        ;;
    scp)
        load_state
        dest=${*: -1}
        scp -r "${scp_options[@]}" "${@:1:$#-1}" "$guest_user@127.0.0.1:$dest"
        ;;
    pull)
        load_state
        scp -r "${scp_options[@]}" "$guest_user@127.0.0.1:$1" "$2"
        ;;
    down)
        stop_guest 0
        if dir=$(state_dir 2>/dev/null) && [[ -d "$dir" ]]; then
            rm -rf -- "$dir"
        fi
        rm -f -- "$pointer"
        printf 'P09-VM-DOWN\n'
        ;;
    *)
        sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//' >&2
        exit 2
        ;;
esac
