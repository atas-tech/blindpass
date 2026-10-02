#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -Eeuo pipefail
[[ $(id -u) != 0 ]]
[[ -r /dev/kvm && -w /dev/kvm ]]
[[ -n ${BLINDPASS_FLEET_RUNNER_OWNER:-} ]]
[[ -r ${BLINDPASS_FLEET_SSH_KEY:-} ]]
artifact_root=${BLINDPASS_P05_HELPER_ARTIFACT_ROOT:-$PWD/test-results}
install -d -m 0700 "$artifact_root"
run_dir=$(mktemp -d "$artifact_root/blindpass-p05-helper-vm.XXXXXXXX")
cleanup() {
  if [[ -f $run_dir/qemu.pid ]]; then
    qemu_pid=$(<"$run_dir/qemu.pid")
    kill "$qemu_pid" 2>/dev/null || true
    for _attempt in {1..30}; do kill -0 "$qemu_pid" 2>/dev/null || break; sleep 0.1; done
    kill -KILL "$qemu_pid" 2>/dev/null || true
  fi
  rm -rf -- "$run_dir"
}
trap cleanup EXIT
trap 'exit 143' INT TERM
fleet_browser=${BLINDPASS_P05_FLEET_BROWSER:-0}
[[ $fleet_browser == 0 || $fleet_browser == 1 ]]
browser_app=${BLINDPASS_P05_BROWSER_APP:-fixture}
[[ $browser_app == fixture || $browser_app == grafana-managed && $fleet_browser == 1 ]]
ai_client=${BLINDPASS_P05_AI_CLIENT:-}
[[ -z $ai_client || $ai_client == claude || $ai_client == codex ]]
[[ -z $ai_client || $browser_app == grafana-managed && $fleet_browser == 1 ]]
if [[ $browser_app == grafana-managed ]]; then
  [[ -n ${P05_GRAFANA_HOME:-} && -f $P05_GRAFANA_HOME/bin/grafana ]]
  [[ -f $P05_GRAFANA_HOME/LICENSE && -f $P05_GRAFANA_HOME/NOTICE.md ]]
  tar -cf "$run_dir/grafana-runtime.tar" -C "$P05_GRAFANA_HOME" bin conf public LICENSE NOTICE.md
  printf 'P05-MANAGED-RUNTIME-BUNDLE sha256=%s\n' "$(sha256sum "$run_dir/grafana-runtime.tar" | awk '{print $1}')"
fi
./tests/fleet/provision-guest.sh --output-dir "$run_dir/image"
qemu-img resize "$run_dir/image/guest-overlay.qcow2" 8G >/dev/null
cargo build --release --locked -p blindpass-broker --bin blindpass-broker --bin blindpass-private-helper-probe --bin blindpass-session-journal-probe --bin blindpass-browser-proxy-probe --bin blindpass-runtime-identity-probe --bin blindpass-browser-supervisor-probe --bin blindpass-provision --bin blindpass-custody-clock-probe
install -m 0755 target/release/blindpass-provision "$run_dir/blindpass-provision"
install -m 0755 target/release/blindpass-custody-clock-probe "$run_dir/blindpass-custody-clock-probe"
install -m 0755 target/release/blindpass-broker "$run_dir/blindpass-broker"
install -m 0755 target/release/blindpass-private-helper-probe "$run_dir/blindpass-private-helper-probe"
install -m 0755 target/release/blindpass-session-journal-probe "$run_dir/blindpass-session-journal-probe"
install -m 0755 target/release/blindpass-browser-proxy-probe "$run_dir/blindpass-browser-proxy-probe"
install -m 0755 target/release/blindpass-runtime-identity-probe "$run_dir/blindpass-runtime-identity-probe"
install -m 0755 target/release/blindpass-browser-supervisor-probe "$run_dir/blindpass-browser-supervisor-probe"
if [[ $fleet_browser == 1 ]]; then
  cargo build --release --locked -p blindpass-controller -p blindpass-node
  install -m 0755 target/release/blindpass-controller "$run_dir/blindpass-controller"
  install -m 0755 target/release/blindpass-node "$run_dir/blindpass-node"
fi
node_bin=$(node -p 'process.execPath')
node_version=${BLINDPASS_P05_NODE_VERSION:-26.10.0}
[[ $node_version == 26.10.0 || $node_version == 24.21.0 ]]
[[ $(node --version) == v$node_version ]]
node_root=$(dirname "$(dirname "$node_bin")")
[[ -f $node_root/LICENSE ]]
[[ $(node -p 'require("playwright/package.json").version') == 1.58.2 ]]
browser_cache=$(dirname "$(dirname "$(node --input-type=module -e 'import {chromium} from "playwright"; console.log(chromium.executablePath())')")")
browser_cache=$(dirname "$browser_cache")
# Stream directly from verified installed files instead of duplicating binaries.
tar -czf "$run_dir/private-helper-runtime.tar.gz" \
  --transform='s,^helpers/login/,,' \
  --transform='s,^packages/openclaw-plugin/dist/,mcp/,' \
  --transform='s,^bin/,runtime/bin/,' \
  --transform='s,^\./LICENSE$,runtime/LICENSE,' \
  --transform='s,^chromium_headless_shell-1208,browsers/chromium_headless_shell-1208,' \
  -C "$PWD" helpers/login/src helpers/login/LICENSE packages/openclaw-plugin/dist/mcp-server.mjs packages/openclaw-plugin/dist/LICENSE packages/openclaw-plugin/dist/THIRD_PARTY_NOTICES.md packages/openclaw-plugin/dist/licenses node_modules/playwright node_modules/playwright-core node_modules/@playwright/mcp \
  -C "$node_root" bin/node ./LICENSE \
  -C "$browser_cache" chromium_headless_shell-1208
tar -xOzf "$run_dir/private-helper-runtime.tar.gz" runtime/LICENSE | cmp - "$node_root/LICENSE"
printf 'P05-HELPER-RUNTIME-BUNDLE sha256=%s\n' "$(sha256sum "$run_dir/private-helper-runtime.tar.gz" | awk '{print $1}')"
ssh_port=${BLINDPASS_P05_HELPER_SSH_PORT:-22227}
qemu-system-x86_64 -name blindpass-p05-helper -enable-kvm -cpu host -m 2048 -smp 2 \
  -drive "file=$run_dir/image/guest-overlay.qcow2,if=virtio,format=qcow2,cache=none,aio=threads" \
  -drive "file=$run_dir/image/seed.iso,if=virtio,media=cdrom,readonly=on,format=raw" \
  -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:$ssh_port-:22" -device virtio-net-pci,netdev=net0 \
  -display none -monitor none -serial "file:$run_dir/serial.log" -pidfile "$run_dir/qemu.pid" -daemonize
ssh_options=(-i "$BLINDPASS_FLEET_SSH_KEY" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=3 -p "$ssh_port")
scp_options=(-i "$BLINDPASS_FLEET_SSH_KEY" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=3 -P "$ssh_port")
guest_target=${BLINDPASS_FLEET_GUEST_USER:-blindpass}@127.0.0.1
for _attempt in {1..90}; do ssh "${ssh_options[@]}" "$guest_target" true 2>/dev/null && break; sleep 2; done
scp "${scp_options[@]}" "$run_dir/private-helper-runtime.tar.gz" "$run_dir/blindpass-broker" "$run_dir/blindpass-provision" "$run_dir/blindpass-custody-clock-probe" "$run_dir/blindpass-private-helper-probe" "$run_dir/blindpass-session-journal-probe" "$run_dir/blindpass-browser-proxy-probe" "$run_dir/blindpass-runtime-identity-probe" "$run_dir/blindpass-browser-supervisor-probe" tests/browser-handoff/private-helper-guest.sh deploy/native/blindpass-login* deploy/native/blindpass-browser* deploy/native/blindpass-session-revoker* deploy/native/blindpass-runtime-manager* deploy/native/blindpass-broker.service deploy/examples/browser-runtime.conf "$guest_target:/tmp/" >/dev/null
scp -r "${scp_options[@]}" tests/browser-handoff "$guest_target:/tmp/" >/dev/null
if [[ $fleet_browser == 1 ]]; then
  scp "${scp_options[@]}" "$run_dir/blindpass-controller" "$run_dir/blindpass-node" "$guest_target:/tmp/" >/dev/null
fi
if [[ $browser_app == grafana-managed ]]; then
  scp "${scp_options[@]}" "$run_dir/grafana-runtime.tar" "$guest_target:/tmp/" >/dev/null
fi
diagnostic_hold=${BLINDPASS_P05_DIAGNOSTIC_HOLD_SECONDS:-0}
[[ $diagnostic_hold =~ ^[0-9]{1,3}$ && $diagnostic_hold -le 240 ]]
if [[ -n $ai_client ]]; then
  export BLINDPASS_P05_HELPER_SSH_PORT=$ssh_port
  ssh "${ssh_options[@]}" "$guest_target" "sudo env BLINDPASS_P05_FLEET_BROWSER=$fleet_browser BLINDPASS_P05_BROWSER_APP=$browser_app BLINDPASS_P05_AI_CLIENT=$ai_client BLINDPASS_P05_DIAGNOSTIC_HOLD_SECONDS=$diagnostic_hold bash /tmp/private-helper-guest.sh" >"$run_dir/guest.log" 2>&1 &
  guest_pid=$!
  client_code=0
  BLINDPASS_P05_GUEST_PID=$guest_pid python tests/browser-handoff/ai-client-task.py "$ai_client" || client_code=$?
  guest_code=0
  wait "$guest_pid" || guest_code=$?
  cat "$run_dir/guest.log"
  [[ $client_code == 0 && $guest_code == 0 ]]
else
  ssh "${ssh_options[@]}" "$guest_target" "sudo env BLINDPASS_P05_FLEET_BROWSER=$fleet_browser BLINDPASS_P05_BROWSER_APP=$browser_app BLINDPASS_P05_DIAGNOSTIC_HOLD_SECONDS=$diagnostic_hold bash /tmp/private-helper-guest.sh"
fi
printf 'P05-HELPER-VM-COMPLETE runner_owner=%s\n' "$BLINDPASS_FLEET_RUNNER_OWNER"
