#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -Eeuo pipefail
[[ $(id -u) == 0 ]]
journal_dir=/var/lib/blindpass/broker/sessions
probe=/usr/lib/blindpass/login/blindpass-session-journal-probe
writer_pid=
mounted=0
isolated=0
cleanup() {
  if [[ -n $writer_pid ]]; then kill -KILL "$writer_pid" 2>/dev/null || true; wait "$writer_pid" 2>/dev/null || true; fi
  if [[ $mounted == 1 ]]; then umount "$journal_dir"; fi
  if [[ $isolated == 1 ]]; then umount "$journal_dir"; fi
}
trap cleanup EXIT
install -d -m 0700 "$journal_dir"
# Preserve the earlier real helper proof journal. Persistence-only fixtures
# run on a fresh mount and do not overwrite those operation records.
mount -t tmpfs -o size=1m,mode=0700 tmpfs "$journal_dir"
isolated=1
[[ ! -e $journal_dir/state.json ]]
"$probe" seed-hold >/tmp/p05-journal-writer.log &
writer_pid=$!
for _attempt in {1..100}; do
  if rg_ready=$(cat /tmp/p05-journal-writer.log) && [[ $rg_ready == 'P05-JOURNAL-VM durable_login_intent=ready' ]]; then break; fi
  sleep 0.02
done
[[ $(cat /tmp/p05-journal-writer.log) == 'P05-JOURNAL-VM durable_login_intent=ready' ]]
kill -KILL "$writer_pid"
wait "$writer_pid" 2>/dev/null || true
writer_pid=
"$probe" recover
[[ $(stat -c '%a:%U:%h' "$journal_dir/state.json") == 600:root:1 ]]
mount -t tmpfs -o size=64k,mode=0700 tmpfs "$journal_dir"
mounted=1
"$probe" diskfull
[[ $(stat -c '%a:%U:%h' "$journal_dir/state.json") == 600:root:1 ]]
umount "$journal_dir"
mounted=0
umount "$journal_dir"
isolated=0
printf 'P05-JOURNAL-VM directory=0700:root state=0600:root:1 scope=persistence-only\n'
