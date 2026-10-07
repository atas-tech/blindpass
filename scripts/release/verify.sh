#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# P07-D2: verify a signed release inventory before trusting any artifact in it.
#
#   scripts/release/verify.sh --fingerprint SHA256:... [--revoked FILE] [--check-dir DIR] \
#       SHA256SUMS SHA256SUMS.sig docs/release/RELEASE_KEY.pub
#
# Trust comes from two independent facts: the signature verifies under the key in
# RELEASE_KEY.pub, and that key's fingerprint equals the one you obtained from a
# channel other than this repository checkout (release notes, the maintainer, a
# second copy of the key). The fingerprint is therefore required, from --fingerprint
# or BLINDPASS_RELEASE_KEY_FINGERPRINT; there is no "trust what is in the tree" mode.
#
# The signer identity and namespace are pinned here, not read from the key file, and
# the key file may hold exactly one bare Ed25519 public key (no options, no
# cert-authority, no second key), so it cannot widen the allowed-signers entry.
# A REVOKED_KEYS file beside the public key (one public key per line), or --revoked
# FILE, rejects signatures from those keys. With --check-dir DIR every listed file in
# DIR must match its checksum and DIR must hold no other files besides the inventory
# and its signature.
set -euo pipefail
umask 077

IDENTITY='blindpass-release'
NAMESPACE='blindpass-release-v1'

fail() { printf 'verify: %s\n' "$1" >&2; exit 1; }
usage() {
  printf 'usage: verify.sh --fingerprint SHA256:... [--revoked FILE] [--check-dir DIR] SHA256SUMS SHA256SUMS.sig RELEASE_KEY.pub\n' >&2
  exit 2
}

fingerprint=${BLINDPASS_RELEASE_KEY_FINGERPRINT:-}
revoked=''
check_dir=''
while (($#)); do
  case "$1" in
    --fingerprint) (($# >= 2)) || usage; fingerprint=$2; shift 2 ;;
    --revoked) (($# >= 2)) || usage; revoked=$2; shift 2 ;;
    --check-dir) (($# >= 2)) || usage; check_dir=$2; shift 2 ;;
    -h|--help) usage ;;
    --) shift; break ;;
    -*) usage ;;
    *) break ;;
  esac
done
(($# == 3)) || usage
sums=$1
signature=$2
pubkey=$3

[[ -n "$fingerprint" ]] || fail 'an independently obtained key fingerprint is required (--fingerprint SHA256:... or BLINDPASS_RELEASE_KEY_FINGERPRINT)'
[[ "$fingerprint" =~ ^SHA256:[A-Za-z0-9+/]{43}$ ]] || fail 'fingerprint must look like SHA256:<43 base64 characters>'

[[ -f "$sums" && ! -L "$sums" ]] || fail 'SHA256SUMS is missing or not a regular file'
[[ -s "$sums" ]] || fail 'SHA256SUMS is empty'
[[ -f "$signature" && ! -L "$signature" && -s "$signature" ]] || fail 'signature file is missing, empty or not a regular file'
[[ -f "$pubkey" && ! -L "$pubkey" && -s "$pubkey" ]] || fail 'release public key file is missing or empty (docs/release/RELEASE_KEY.pub is an owner-provided file)'

# Exactly one line: "ssh-ed25519 <base64>" with an optional free-text comment.
if (($(grep -c '' "$pubkey") != 1)) || ! grep -Eq '^ssh-ed25519 [A-Za-z0-9+/]{68}( [^[:cntrl:]]*)?$' "$pubkey"; then
  fail 'release public key file must hold exactly one bare ssh-ed25519 public key'
fi
key_line=$(cut -d' ' -f1,2 "$pubkey")

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
printf '%s\n' "$key_line" >"$tmp/key.pub"
actual=$(ssh-keygen -lf "$tmp/key.pub" 2>/dev/null | cut -d' ' -f2) || fail 'release public key is not a valid SSH public key'
[[ "$actual" == "$fingerprint" ]] || fail "release key fingerprint does not match the independently supplied one (file has $actual)"

printf '%s namespaces="%s" %s\n' "$IDENTITY" "$NAMESPACE" "$key_line" >"$tmp/allowed_signers"

revoke_args=()
if [[ -n "$revoked" ]]; then
  [[ -f "$revoked" && ! -L "$revoked" ]] || fail 'revocation list is missing or not a regular file'
else
  beside="$(dirname "$pubkey")/REVOKED_KEYS"
  [[ -e "$beside" || -L "$beside" ]] && revoked=$beside
fi
if [[ -n "$revoked" ]]; then
  [[ -f "$revoked" && ! -L "$revoked" && -r "$revoked" ]] || fail 'revocation list is unreadable or not a regular file'
  cp "$revoked" "$tmp/revoked"
  revoke_args=(-r "$tmp/revoked")
fi

if ! ssh-keygen -Y verify -f "$tmp/allowed_signers" -I "$IDENTITY" -n "$NAMESPACE" -s "$signature" "${revoke_args[@]}" \
    <"$sums" >"$tmp/verify.out" 2>&1; then
  fail 'signature verification FAILED (tampered inventory, wrong key, wrong namespace or revoked key)'
fi
printf 'verify: signature OK (identity %s, namespace %s, key %s)\n' "$IDENTITY" "$NAMESPACE" "$fingerprint"

[[ -n "$check_dir" ]] || exit 0
[[ -d "$check_dir" && ! -L "$check_dir" ]] || fail 'check directory is missing or a symlink'

listed="$tmp/listed"
: >"$listed"
count=0
while IFS= read -r line || [[ -n "$line" ]]; do
  [[ "$line" =~ ^[0-9a-f]{64}\ \ ([^[:cntrl:]]+)$ ]] || fail "unsafe or malformed inventory line"
  name=${BASH_REMATCH[1]}
  [[ "$name" != */* && "$name" != .* && "$name" != 'SHA256SUMS' && "$name" != 'SHA256SUMS.sig' ]] || fail "unsafe inventory path: $name"
  grep -qxF -- "$name" "$listed" && fail "duplicate inventory entry: $name"
  printf '%s\n' "$name" >>"$listed"
  count=$((count + 1))
done <"$sums"
((count > 0)) || fail 'inventory lists no files'

for entry in "$check_dir"/* "$check_dir"/.[!.]*; do
  [[ -e "$entry" || -L "$entry" ]] || continue
  base=$(basename "$entry")
  [[ "$base" == 'SHA256SUMS' || "$base" == 'SHA256SUMS.sig' ]] && continue
  [[ -f "$entry" && ! -L "$entry" ]] || fail "check directory holds a non-regular entry: $base"
  grep -qxF -- "$base" "$listed" || fail "file not listed in the signed inventory: $base"
done

if ! (cd "$check_dir" && sha256sum --check --strict "$sums" >"$tmp/check.out" 2>&1); then
  fail 'checksum check FAILED (a listed file is missing or differs from the signed inventory)'
fi
printf 'verify: %d file(s) match the signed inventory\n' "$count"
