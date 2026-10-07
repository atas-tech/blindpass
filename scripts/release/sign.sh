#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# P07-D2: sign a release inventory (SHA256SUMS) with the maintainer release key.
#
#   scripts/release/sign.sh --key PRIVATE_KEY_FILE SHA256SUMS
#
# Writes SHA256SUMS.sig next to the inventory with `ssh-keygen -Y sign` in the
# fixed namespace below, then proves the result with scripts/release/verify.sh
# against the key's own public half. The private key is read by ssh-keygen only:
# this script never prints, copies or logs it. CI writes the key to a 0600 file
# in a runner temporary directory, signs, and deletes it (see release.yml).
set -euo pipefail
umask 077

NAMESPACE='blindpass-release-v1'
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

fail() { printf 'sign: %s\n' "$1" >&2; exit 1; }
usage() { printf 'usage: sign.sh --key PRIVATE_KEY_FILE SHA256SUMS\n' >&2; exit 2; }

key=''
while (($#)); do
  case "$1" in
    --key) (($# >= 2)) || usage; key=$2; shift 2 ;;
    -h|--help) usage ;;
    --) shift; break ;;
    -*) usage ;;
    *) break ;;
  esac
done
(($# == 1)) && [[ -n "$key" ]] || usage
sums=$1
signature="$sums.sig"

[[ -f "$sums" && ! -L "$sums" ]] || fail 'SHA256SUMS must be an existing regular file (not a symlink)'
[[ -s "$sums" ]] || fail 'refusing to sign an empty inventory'
[[ -f "$key" && ! -L "$key" ]] || fail 'signing key must be an existing regular file (not a symlink)'
[[ ! -e "$signature" && ! -L "$signature" ]] || fail "refusing to replace an existing signature: $signature"

mode=$(stat -c '%a' "$key")
((8#$mode & 8#077)) && fail "signing key permissions are $mode; require 600 or stricter"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
public="$tmp/signer.pub"
# ssh-keygen -y derives the public half; a passphrase-protected key would prompt, so
# keep stdin closed and fail instead of hanging a CI job.
ssh-keygen -y -f "$key" </dev/null >"$public" 2>/dev/null || fail 'cannot read the signing key (wrong format or passphrase-protected)'
[[ "$(cut -d' ' -f1 "$public")" == 'ssh-ed25519' ]] || fail 'the release key must be an Ed25519 key'
fingerprint=$(ssh-keygen -lf "$public" | cut -d' ' -f2)

ssh-keygen -Y sign -q -f "$key" -n "$NAMESPACE" "$sums" </dev/null 2>/dev/null || fail 'signing failed'
[[ -s "$signature" ]] || fail 'signing produced no signature'

# Never leave a signature that does not verify against the key that made it.
if ! "$here/verify.sh" --fingerprint "$fingerprint" "$sums" "$signature" "$public" >/dev/null; then
  rm -f "$signature"
  fail 'self-verification failed; signature removed'
fi
printf 'sign: wrote %s (namespace %s, key %s)\n' "$signature" "$NAMESPACE" "$fingerprint"
