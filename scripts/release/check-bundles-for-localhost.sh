#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# P07-D6 / P07-I03: fail a release when a built bundle can reach a development
# origin or ships a permissive Content-Security-Policy.
#
#   check-bundles-for-localhost.sh DIR [DIR...]   scan built bundles
#   check-bundles-for-localhost.sh --self-test    prove the checker on planted cases
#
# Fail-closed: a missing or unreadable directory, or a scan that reads no
# files at all, is a failure (exit 2), never a pass. Findings exit 1.
#
# Findings
#   loopback    an http(s)/ws(s) literal naming localhost, 127.0.0.1, [::1] or
#               0.0.0.0 with a port or path: an API default or a dev server.
#   csp-scheme  a CSP source list with a bare scheme (http: https: ws: wss:) or
#               "*": the F-9/F-11 shape that admits any destination.
#   csp-unsafe  'unsafe-eval' anywhere, or 'unsafe-inline' in default-src or
#               script-src.
#
# Reviewed false-positive classes (counted, never findings)
#   placeholder bare "http://localhost" with no port or path in a script: the
#               base URL react-router and similar libraries hand to the URL
#               parser to resolve relative paths. It is never fetched.
#   namespace   http://www.w3.org/..., XML/SVG namespace identifiers, which are
#               not network targets.
# A host that merely starts with a loopback name (localhost.example.com) is a
# different host and is not matched.
set -euo pipefail

# A loopback name must end at a name boundary, so localhost.example.com and
# localhost-proxy.example are other hosts and do not match.
readonly LOOPBACK='(?:https?|wss?)://(?:localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0)(?![A-Za-z0-9._-])[^"'"'"' )<>]{0,40}'

usage() {
  echo "usage: $0 DIR [DIR...] | --self-test" >&2
  exit 2
}

# Decode the entities an HTML attribute uses so a CSP in a meta tag is read as
# written.
decode() {
  sed -e "s/&#39;/'/g" -e 's/&quot;/"/g' -e 's/&amp;/\&/g' -e 's/&#x27;/'"'"'/g' "$1"
}

# Every CSP-looking value in one file, one per line.
csp_values() {
  decode "$1" | grep -oEi "(default|script|style|img|font|connect|frame|object|worker|media|child|manifest)-src[^;\"<>]*" || true
}

scan_directory() {
  local directory="$1" files=0 findings=0 placeholders=0 namespaces=0 file
  if [[ ! -d "$directory" || ! -r "$directory" ]]; then
    echo "check-bundles: $directory is missing or unreadable" >&2
    return 2
  fi
  while IFS= read -r -d '' file; do
    files=$((files + 1))
    local text
    text="$(decode "$file")"
    local line
    # Every loopback literal is a finding except the exact bare
    # http(s)://localhost placeholder, which is counted so a change in its
    # number is visible.
    while IFS= read -r line; do
      [[ -z "$line" ]] && continue
      if [[ "$line" == "http://localhost" || "$line" == "https://localhost" ]]; then
        placeholders=$((placeholders + 1))
        continue
      fi
      echo "FINDING loopback: $file: ${line:0:160}"
      findings=$((findings + 1))
    done < <(printf '%s\n' "$text" | grep -oP "$LOOPBACK" || true)
    namespaces=$((namespaces + $(printf '%s\n' "$text" | grep -oE 'https?://www\.w3\.org/[^"'"'"' )<>]*' | grep -c . || true)))
    # CSP source lists.
    while IFS= read -r line; do
      [[ -z "$line" ]] && continue
      local directive="${line%% *}"
      if grep -qE "(^|[[:space:]])((https?|wss?):|\*)([[:space:]]|\$)" <<<"$line"; then
        echo "FINDING csp-scheme: $file: ${line:0:160}"
        findings=$((findings + 1))
      fi
      if grep -qi "unsafe-eval" <<<"$line" ||
        { [[ "$directive" =~ ^(default|script)-src$ ]] && grep -qi "unsafe-inline" <<<"$line"; }; then
        echo "FINDING csp-unsafe: $file: ${line:0:160}"
        findings=$((findings + 1))
      fi
    done < <(csp_values "$file")
  done < <(find "$directory" -type f \( -name '*.js' -o -name '*.mjs' -o -name '*.cjs' -o -name '*.html' \
    -o -name '*.css' -o -name '*.json' -o -name '*.conf' -o -name '*.template' -o -name '*.txt' \
    -o -name '*.webmanifest' -o -name '*.svg' \) -print0)
  echo "scanned $directory: files=$files findings=$findings placeholder_localhost=$placeholders xml_namespaces=$namespaces"
  if ((files == 0)); then
    echo "check-bundles: $directory holds no scannable files; refusing to pass an empty scan" >&2
    return 2
  fi
  ((findings == 0)) || return 1
}

check() {
  local status=0 directory result
  for directory in "$@"; do
    scan_directory "$directory" || {
      result=$?
      ((result > status)) && status=$result
    }
  done
  return "$status"
}

self_test() {
  local root failures=0
  root="$(mktemp -d)"
  expect() {
    local name="$1" want="$2" got=0
    shift 2
    "$@" >"$root/out.txt" 2>&1 || got=$?
    if [[ "$got" != "$want" ]]; then
      echo "SELF-TEST FAIL $name: exit $got, wanted $want" >&2
      sed 's/^/    /' "$root/out.txt" >&2
      failures=$((failures + 1))
    else
      echo "self-test ok: $name (exit $got)"
    fi
  }
  plant() { mkdir -p "$root/$1"; printf '%s\n' "$2" >"$root/$1/$3"; }

  # Clean bundle: namespaces and the reviewed placeholder only.
  plant clean 'const u=new URL("http://localhost");const ns="http://www.w3.org/2000/svg";const x="http://www.w3.org/1999/xlink";' app.js
  plant clean '<meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; script-src &#39;self&#39;; connect-src &#39;self&#39; https://api.example; img-src &#39;self&#39; data:">' index.html
  expect clean-bundle-passes 0 check "$root/clean"

  # Planted positives, one per file.
  local index=0 literal
  for literal in 'http://127.0.0.1:3100' 'ws://localhost:5173/ws' 'http://localhost:8080/api' \
    'https://localhost:8443' 'http://[::1]:3100' 'http://0.0.0.0:3100' 'http://localhost/api'; do
    index=$((index + 1))
    plant "loopback$index" "fetch(\"$literal/x\")" app.js
    expect "loopback-literal-$index" 1 check "$root/loopback$index"
  done
  plant csp-http '<meta content="default-src &#39;none&#39;; connect-src &#39;self&#39; http: https: ws: wss:">' index.html
  expect csp-bare-schemes 1 check "$root/csp-http"
  plant csp-star "add_header Content-Security-Policy \"default-src 'none'; connect-src *\";" site.conf
  expect csp-wildcard 1 check "$root/csp-star"
  plant csp-eval "<meta content=\"script-src 'self' 'unsafe-eval'\">" index.html
  expect csp-unsafe-eval 1 check "$root/csp-eval"
  plant csp-inline "<meta content=\"script-src 'self' 'unsafe-inline'\">" index.html
  expect csp-unsafe-inline-script 1 check "$root/csp-inline"
  plant csp-style "<meta content=\"style-src 'self' 'unsafe-inline'; default-src 'none'; script-src 'self'\">" index.html
  expect csp-unsafe-inline-style-is-not-this-checks-concern 0 check "$root/csp-style"
  plant bare-ip 'const base="http://127.0.0.1";' app.js
  expect bare-loopback-ip-is-a-finding 1 check "$root/bare-ip"
  plant bare-ws 'new WebSocket("ws://localhost")' app.js
  expect bare-websocket-is-a-finding 1 check "$root/bare-ws"
  plant lookalike 'fetch("http://localhost.example.com/api");fetch("https://localhost-proxy.example:8443")' app.js
  expect lookalike-host-is-not-loopback 0 check "$root/lookalike"

  # Fail closed.
  expect missing-directory 2 check "$root/does-not-exist"
  mkdir "$root/empty"
  expect empty-directory 2 check "$root/empty"
  mkdir "$root/binary-only"
  printf '\0\1\2' >"$root/binary-only/blob.bin"
  expect no-scannable-files 2 check "$root/binary-only"
  expect no-arguments 2 bash -c "'$0' >/dev/null 2>&1"
  plant mixed 'ok' good.js
  expect one-bad-directory-fails-the-run 1 check "$root/clean" "$root/loopback1" "$root/mixed"
  expect missing-beats-findings 2 check "$root/loopback1" "$root/does-not-exist"

  rm -rf "$root"
  if ((failures > 0)); then
    echo "check-bundles: $failures self-test case(s) failed" >&2
    return 1
  fi
  echo "check-bundles: self-test passed"
}

main() {
  [[ $# -ge 1 ]] || usage
  if [[ "$1" == "--self-test" ]]; then
    self_test
    return
  fi
  check "$@"
}

# The sourced self-test needs `check` in scope when run through bash -c.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
