#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -Eeuo pipefail

usage() {
    printf '%s\n' 'usage: provision-guest.sh --output-dir DIR'
}

unsupported() {
    printf 'P01-UNSUPPORTED %s\n' "$1" >&2
    exit 78
}

output_dir=
while (($# > 0)); do
    case "$1" in
        --output-dir)
            (($# >= 2)) || { usage >&2; exit 2; }
            output_dir=$2
            shift 2
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            usage >&2
            exit 2
            ;;
    esac
done

[[ -n "$output_dir" ]] || { usage >&2; exit 2; }
base_image=${BLINDPASS_FLEET_GUEST_IMAGE:-}
expected_sha=${BLINDPASS_FLEET_GUEST_IMAGE_SHA256:-}
ssh_key=${BLINDPASS_FLEET_SSH_KEY:-}
guest_user=${BLINDPASS_FLEET_GUEST_USER:-blindpass}

[[ -n "$base_image" ]] || unsupported 'BLINDPASS_FLEET_GUEST_IMAGE is unset'
[[ -n "$expected_sha" ]] || unsupported 'BLINDPASS_FLEET_GUEST_IMAGE_SHA256 is unset'
[[ -n "$ssh_key" && -r "$ssh_key" ]] || unsupported 'BLINDPASS_FLEET_SSH_KEY is missing or unreadable'
[[ -r "$base_image" ]] || unsupported 'pinned guest image is missing or unreadable'
command -v qemu-img >/dev/null 2>&1 || unsupported 'qemu-img is unavailable'
command -v cloud-localds >/dev/null 2>&1 || unsupported 'cloud-localds is unavailable'
command -v sha256sum >/dev/null 2>&1 || unsupported 'sha256sum is unavailable'

mkdir -p "$output_dir"
overlay=$output_dir/guest-overlay.qcow2
seed=$output_dir/seed.iso
user_data=$output_dir/user-data
meta_data=$output_dir/meta-data
[[ ! -e "$overlay" && ! -e "$seed" ]] || {
    printf 'refusing to overwrite existing VM artifacts in %s\n' "$output_dir" >&2
    exit 2
}

actual_sha=$(sha256sum "$base_image" | awk '{print $1}')
[[ "$actual_sha" == "$expected_sha" ]] || {
    printf 'P01-UNSUPPORTED guest image hash mismatch (expected %s, got %s)\n' \
        "$expected_sha" "$actual_sha" >&2
    exit 78
}

qemu-img create -q -f qcow2 -F qcow2 -b "$base_image" "$overlay"
public_key_file="${ssh_key}.pub"
if [[ -r "$public_key_file" ]]; then
    public_key=$(<"$public_key_file")
else
    command -v ssh-keygen >/dev/null 2>&1 || unsupported 'ssh-keygen is unavailable and the SSH public-key sidecar is missing'
    public_key=$(ssh-keygen -y -f "$ssh_key") || unsupported 'could not derive the SSH public key'
fi
[[ "$public_key" == ssh-* ]] || unsupported 'SSH public key is missing or malformed'
umask 077
printf '#cloud-config\nusers:\n  - default\n  - name: %s\n    groups: [sudo]\n    shell: /bin/bash\n    sudo: ["ALL=(ALL) NOPASSWD:ALL"]\n    lock_passwd: true\n    ssh_authorized_keys:\n      - %s\nssh_pwauth: false\npackage_update: false\nruncmd:\n  - [ sh, -c, "install -d -m 0755 /var/lib/blindpass-p01" ]\n' \
    "$guest_user" "$public_key" >"$user_data"
printf 'instance-id: blindpass-p01-%s\nlocal-hostname: blindpass-p01\n' \
    "$(basename "$output_dir")" >"$meta_data"
cloud-localds "$seed" "$user_data" "$meta_data"
printf 'P01-PROVISIONED overlay=%s seed=%s image_sha256=%s\n' \
    "$overlay" "$seed" "$actual_sha"
