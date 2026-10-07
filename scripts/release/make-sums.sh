#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# P07-D2: write the SHA256SUMS inventory for a staged release candidate.
#
#   scripts/release/make-sums.sh CANDIDATE_DIR VERSION
#
# CANDIDATE_DIR must hold exactly the intended assets for VERSION (X.Y.Z): every
# regular file must match the allow-list below and every required asset must be
# present. Anything else (a stray log, key, symlink, other version, subdirectory,
# an earlier SHA256SUMS or signature) fails and no inventory is written. This
# complements scripts/release/checksums.sh, which covers only the two controller/
# node archive families and stays the P06 archive-level check.
set -euo pipefail
umask 022

fail() { printf 'make-sums: %s\n' "$1" >&2; exit 1; }
(($# == 2)) || { printf 'usage: make-sums.sh CANDIDATE_DIR VERSION\n' >&2; exit 2; }
dir=$1
version=$2
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?$ ]] || fail 'version must look like X.Y.Z (no leading v, no path characters)'
[[ -d "$dir" && ! -L "$dir" ]] || fail 'candidate directory is missing or a symlink'

# Required: one regular file for each of these exact names.
required=(
  "blindpass-controller-$version-linux-x86_64.tar.zst"
  "blindpass-node-$version-linux-x86_64.tar.zst"
  "blindpass-approval-app-$version-linux-x86_64.tar.zst"
  "blindpass-mcp-server-$version.tgz"
  "blindpass-controller-image-$version-linux-amd64.oci.tar"
  "blindpass-controller-image-$version-linux-amd64.docker.tar"
  'controller-image.digest'
  "LICENSES-$version.md"
  'PKGBUILD'
  "blindpass-controller-image-$version.spdx.json"
  "blindpass-mcp-server-$version.cdx.json"
)
# Optional: the aarch64 pair, only together.
optional=(
  "blindpass-controller-$version-linux-aarch64.tar.zst"
  "blindpass-node-$version-linux-aarch64.tar.zst"
)

[[ ! -e "$dir/SHA256SUMS" && ! -L "$dir/SHA256SUMS" ]] || fail 'refusing to replace an existing SHA256SUMS'
[[ ! -e "$dir/SHA256SUMS.sig" && ! -L "$dir/SHA256SUMS.sig" ]] || fail 'a signature already exists; start from an unsigned candidate'

allowed=$(printf '%s\n' "${required[@]}" "${optional[@]}")
names=()
shopt -s nullglob dotglob
for entry in "$dir"/*; do
  base=${entry##*/}
  [[ -f "$entry" && ! -L "$entry" ]] || fail "not a regular file: $base"
  grep -qxF -- "$base" <<<"$allowed" || fail "unexpected file in candidate: $base"
  names+=("$base")
done
shopt -u nullglob dotglob

have() { printf '%s\n' "${names[@]}" | grep -qxF -- "$1"; }
for name in "${required[@]}"; do
  have "$name" || fail "required asset missing: $name"
done
a=0; b=0
have "${optional[0]}" && a=1
have "${optional[1]}" && b=1
((a == b)) || fail 'aarch64 needs both the controller and the node archive'

tmp=$(mktemp "$dir/.SHA256SUMS.XXXXXX")
trap 'rm -f "$tmp"' EXIT
(cd "$dir" && printf '%s\n' "${names[@]}" | LC_ALL=C sort | xargs -d '\n' sha256sum --) >"$tmp"
[[ -s "$tmp" ]] || fail 'empty inventory'
# link(2) refuses to replace, like checksums.sh.
ln "$tmp" "$dir/SHA256SUMS" || fail 'refusing to replace an existing SHA256SUMS'
printf 'make-sums: %d asset(s) listed in %s/SHA256SUMS\n' "${#names[@]}" "$dir"
