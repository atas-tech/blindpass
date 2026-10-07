#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# P07.6: the technical half of the go/no-go gate, run by the publish jobs before anything leaves
# the candidate stage. The other half is the environment approval a named reviewer gives after
# recording the dated go/no-go decision; this script never decides "go".
#
#   scripts/release/check-publish-gate.sh X.Y.Z [--repo DIR]
#
# Requires docs/release/vX.Y.Z/evidence.md in the checked-out tag to be exactly what
# collect-evidence.sh regenerates from the committed results (so it was not hand-edited), to
# report "ELIGIBLE FOR REVIEW", and to name a tested source commit that is an ancestor of the tag
# whose only later changes are under docs/release/vX.Y.Z/ (so the evidence is for this code).
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
fail() { printf 'check-publish-gate: %s\n' "$1" >&2; exit 1; }

(($# >= 1)) || { printf 'usage: check-publish-gate.sh X.Y.Z [--repo DIR]\n' >&2; exit 2; }
version=$1; shift
repo=$(cd "$here/../.." && pwd)
while (($#)); do
  case "$1" in
    --repo) (($# >= 2)) || exit 2; repo=$(cd "$2" && pwd); shift 2 ;;
    *) exit 2 ;;
  esac
done
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail 'version must be X.Y.Z (no leading v)'

release="docs/release/v$version"
evidence="$repo/$release/evidence.md"
[[ -f "$evidence" && ! -L "$evidence" ]] || fail "$release/evidence.md is missing: generate it with scripts/release/collect-evidence.sh and commit it with its results"
[[ -d "$repo/$release/results" ]] || fail "$release/results is missing"
grep -qx '\*\*Release gate: ELIGIBLE FOR REVIEW\*\*' "$evidence" || fail "$release/evidence.md does not report ELIGIBLE FOR REVIEW"

source_commit=$(sed -n 's/^\*\*Source commit:\*\* `\([0-9a-f]\{40\}\)`$/\1/p' "$evidence")
[[ -n "$source_commit" && $(printf '%s\n' "$source_commit" | wc -l) -eq 1 ]] || fail 'evidence.md names no single 40-hex source commit'
git -C "$repo" cat-file -e "$source_commit^{commit}" 2>/dev/null || fail 'the tested source commit is not in this repository'
git -C "$repo" merge-base --is-ancestor "$source_commit" HEAD || fail 'the tested source commit is not an ancestor of the commit being released'
outside=$(git -C "$repo" diff --name-only "$source_commit" HEAD | grep -v "^$release/" || true)
[[ -z "$outside" ]] || fail "files outside docs/release/v$version changed after the tested commit (the evidence is not for this code): $(printf '%s' "$outside" | head -n 3 | tr '\n' ' ')"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
if ! "$here/collect-evidence.sh" "$version" --commit "$source_commit" --required "$repo/docs/release/required-scenarios.json" \
    --results "$repo/$release/results" --output "$tmp/evidence.md" >/dev/null 2>"$tmp/collect.err"; then
  fail "the committed results do not regenerate an eligible matrix: $(head -n 1 "$tmp/collect.err")"
fi
cmp -s "$tmp/evidence.md" "$evidence" || fail "evidence.md differs from what the committed results regenerate (hand-edited or stale)"
printf 'check-publish-gate: publication gate OK for v%s (tested %s)\n' "$version" "$source_commit"
