#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -Eeuo pipefail
[[ $(id -u) == 0 ]]
probe=/usr/lib/blindpass/login/blindpass-custody-clock-probe
run_dir=$(mktemp -d /run/p05-custody-clock.XXXXXXXX)
writer_pid=
cleanup() {
  if [[ -n $writer_pid ]]; then kill -KILL "$writer_pid" 2>/dev/null || true; wait "$writer_pid" 2>/dev/null || true; fi
  rm -rf -- "$run_dir"
}
trap cleanup EXIT
printf '\n' | timeout 30s "$probe" live >"$run_dir/live.log"
[[ $(tail -1 "$run_dir/live.log") =~ ^P05-CUSTODY-CLOCK\ mode=live\ boottime_elapsed_ms=[0-9]+\ runnable_elapsed_ms=[0-9]+\ one_use=true\ source_output=none$ ]]
mkfifo -m 0600 "$run_dir/input"
timeout 30s "$probe" expired <"$run_dir/input" >"$run_dir/expired.log" &
writer_pid=$!
exec 3>"$run_dir/input"
for _attempt in {1..100}; do
  [[ $(head -1 "$run_dir/expired.log") == 'P05-CUSTODY-CLOCK key_ready=true' ]] && break
  sleep 0.02
done
[[ $(head -1 "$run_dir/expired.log") == 'P05-CUSTODY-CLOCK key_ready=true' ]]
rtcwake --mode mem --seconds 6 >"$run_dir/rtcwake.log" 2>&1
printf '\n' >&3
exec 3>&-
wait "$writer_pid"
writer_pid=
[[ $(tail -1 "$run_dir/expired.log") =~ ^P05-CUSTODY-CLOCK\ mode=expired\ boottime_elapsed_ms=[0-9]+\ runnable_elapsed_ms=[0-9]+\ one_use=true\ source_output=none$ ]]
cat "$run_dir/live.log" "$run_dir/expired.log"
printf 'P05-CUSTODY-VM actual_rtc_suspend_seconds=6 key_ttl_ms=3000 expired_key=denied live_control=opened replay=denied scope=recipient_key_custody\n'
