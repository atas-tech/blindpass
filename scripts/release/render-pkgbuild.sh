#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Render desktop/packaging/arch/PKGBUILD for one release archive.
#
#   scripts/release/render-pkgbuild.sh TEMPLATE VERSION ARCHIVE_SHA256 > PKGBUILD
#
# Fails unless the template still holds the placeholder (so a rendered file is never
# re-rendered with a different hash) and the inputs have the exact expected shape.
set -euo pipefail
fail() { printf 'render-pkgbuild: %s\n' "$1" >&2; exit 1; }
(($# == 3)) || { printf 'usage: render-pkgbuild.sh TEMPLATE VERSION ARCHIVE_SHA256\n' >&2; exit 2; }
template=$1; version=$2; sha=$3
[[ -f "$template" && ! -L "$template" ]] || fail 'template is missing or a symlink'
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail 'version must be X.Y.Z (a pre-release needs a reviewed pkgver mapping)'
[[ "$sha" =~ ^[0-9a-f]{64}$ ]] || fail 'archive sha256 must be 64 lowercase hex characters'
[[ "$sha" != "$(printf '0%.0s' {1..64})" ]] || fail 'refusing an all-zero checksum'
grep -qx "sha256sums=('REPLACED-BY-THE-RELEASE-WORKFLOW')" "$template" || fail 'template does not hold the checksum placeholder'
grep -qx 'pkgver=0.0.0' "$template" || fail 'template does not hold the pkgver placeholder'
sed -e "s/^pkgver=0\.0\.0\$/pkgver=$version/" \
    -e "s/^sha256sums=('REPLACED-BY-THE-RELEASE-WORKFLOW')\$/sha256sums=('$sha')/" "$template"
