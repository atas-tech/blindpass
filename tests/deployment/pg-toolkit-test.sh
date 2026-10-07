#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# ADR 0011 PostgreSQL toolkit integration tests in the pinned-toolkit test image,
# as UID 10001 with a private socket-only source cluster. Requires Docker.
set -eu
root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"
docker build --file deploy/controller/Dockerfile --target pgtest --tag blindpass-p06-pgtest:local .
exec docker run --rm --user 10001:10001 --cap-drop ALL --security-opt no-new-privileges blindpass-p06-pgtest:local "$@"
