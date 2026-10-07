#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
set -eu
umask 077
case "${1:-serve}" in
    serve)
        shift "$(( $# > 0 ? 1 : 0 ))"
        [ "$#" = 0 ] || { printf '%s\n' 'blindpass: serve takes no container arguments' >&2; exit 2; }
        # Existing state only. P06 slice 7 adds reviewed locked upgrade migration.
        /usr/local/bin/blindpass-controller check-config >/dev/null
        exec /usr/local/bin/blindpass-controller serve
        ;;
    keys|migrate|admin|backup) exec /usr/local/bin/blindpass "$@" ;;
    healthcheck|check-config|--version|--build-info|--help|-h|-V)
        exec /usr/local/bin/blindpass-controller "$@" ;;
    *) printf '%s\n' 'blindpass: unsupported container command' >&2; exit 2 ;;
esac
