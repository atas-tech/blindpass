#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -Eeuo pipefail
[[ $(id -u) == 0 ]]
cleanup() {
  result=$?
  if [[ $result != 0 && -f /tmp/p05-helper-apt.log ]]; then tail -8 /tmp/p05-helper-apt.log; fi
  if [[ $result != 0 ]]; then
    journalctl -k --no-pager -o cat | grep -E 'apparmor=.*DENIED.*(userns_create|chrome)' | tail -3 || true
    # Numeric counters distinguish resource termination without reflecting
    # command lines, environment, process dumps or application log bodies.
    oom_events=$(journalctl -k --no-pager -o cat | grep -Ec 'Out of memory:|oom-kill:' || true)
    printf 'P05-GUEST-RESOURCES oom_kernel_events=%s\n' "$oom_events"
  fi
  systemctl stop blindpass-login-helper.socket >/dev/null 2>&1 || true
  systemctl stop 'blindpass-login-helper@*.service' >/dev/null 2>&1 || true
  systemctl stop blindpass-runtime-manager.socket 'blindpass-runtime-manager@*.service' blindpass-broker.service p05-fleet-node.service >/dev/null 2>&1 || true
  systemctl stop blindpass-browser.socket >/dev/null 2>&1 || true
  systemctl stop 'blindpass-browser@*.service' >/dev/null 2>&1 || true
  systemctl stop blindpass-browser-supervisor.socket blindpass-session-revoker.socket p05-native-supervisor.socket >/dev/null 2>&1 || true
  systemctl stop 'blindpass-session-revoker@*.service' >/dev/null 2>&1 || true
  systemctl stop 'blindpass-browser-supervisor@*.service' 'p05-native-supervisor@*.service' >/dev/null 2>&1 || true
}
trap cleanup EXIT
install -d -m 0755 /usr/lib/blindpass/login
tar --no-same-owner -xzf /tmp/private-helper-runtime.tar.gz -C /usr/lib/blindpass/login
install -m 0755 /tmp/blindpass-private-helper-probe /usr/lib/blindpass/login/
install -m 0755 /tmp/blindpass-session-journal-probe /usr/lib/blindpass/login/
install -m 0755 /tmp/blindpass-browser-proxy-probe /usr/lib/blindpass/login/
install -m 0755 /tmp/blindpass-runtime-identity-probe /usr/lib/blindpass/login/
install -m 0755 /tmp/blindpass-browser-supervisor-probe /usr/lib/blindpass/login/
install -m 0755 /tmp/blindpass-provision /usr/lib/blindpass/login/
install -m 0755 /tmp/blindpass-custody-clock-probe /usr/lib/blindpass/login/
install -m 0755 /tmp/blindpass-broker /usr/lib/blindpass/login/
# The shipped root broker unit and the shipped browser-runtime drop-in run unchanged in the guest. Only the
# binary location (the unit's /usr/libexec path) and, in the coordinator/fleet guests, one generated
# p05-guest.conf drop-in (shipped-broker-unit.mjs) differ from production.
install -d -m 0755 /usr/libexec /etc/systemd/system/blindpass-broker.service.d
install -m 0755 /tmp/blindpass-broker /usr/libexec/blindpass-broker
install -m 0644 /tmp/blindpass-broker.service /etc/systemd/system/blindpass-broker.service
install -m 0644 /tmp/browser-runtime.conf /etc/systemd/system/blindpass-broker.service.d/browser.conf
install -m 0644 /tmp/blindpass-login.sysusers /usr/lib/sysusers.d/
systemd-sysusers /usr/lib/sysusers.d/blindpass-login.sysusers >/dev/null 2>&1
install -m 0644 /tmp/blindpass-login-helper.socket /tmp/blindpass-login-helper@.service /etc/systemd/system/
install -m 0644 /tmp/blindpass-runtime-manager.socket /tmp/blindpass-runtime-manager@.service /etc/systemd/system/
install -m 0644 /tmp/blindpass-session-revoker.socket /tmp/blindpass-session-revoker@.service /etc/systemd/system/
install -m 0644 /tmp/blindpass-browser.socket /tmp/blindpass-browser@.service /tmp/blindpass-browser-supervisor.socket /tmp/blindpass-browser-supervisor@.service /etc/systemd/system/
install -m 0644 /tmp/blindpass-browser-supervisor.tmpfiles /usr/lib/tmpfiles.d/blindpass-browser-supervisor.conf
systemd-tmpfiles --create /usr/lib/tmpfiles.d/blindpass-browser-supervisor.conf
# Signed distribution packages provide the browser's shared-library prerequisites.
apt-get -o Acquire::Languages=none update -qq >/tmp/p05-helper-apt.log 2>&1
apt-get install -y -qq libatomic1 libnss3 libatk1.0-0t64 libatk-bridge2.0-0t64 libcups2t64 libdrm2 libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 libxrandr2 libgbm1 libasound2t64 >/tmp/p05-helper-apt.log 2>&1
install -m 0644 /tmp/blindpass-login-chromium.apparmor /etc/apparmor.d/blindpass-login-chromium
apparmor_parser -r /etc/apparmor.d/blindpass-login-chromium
[[ $(sysctl -n kernel.apparmor_restrict_unprivileged_userns) == 1 ]]
systemctl daemon-reload
bash /tmp/browser-handoff/browser-catalog-guest.sh
/usr/lib/blindpass/login/runtime/bin/node /tmp/browser-handoff/broker-mcp-guest.mjs
/usr/lib/blindpass/login/runtime/bin/node /tmp/browser-handoff/browser-owner-guest.mjs
install -m 0644 /tmp/browser-handoff/private-helper-preflight.mjs /usr/lib/blindpass/login/private-helper-preflight.mjs
systemd-run --wait --pipe --collect --unit=p05-helper-preflight \
  -p User=blindpass-login -p Group=blindpass-login -p NoNewPrivileges=yes \
  -p PrivateTmp=yes -p PrivateDevices=yes -p ProtectSystem=strict -p ProtectHome=yes \
  -p LimitCORE=0 -p KillMode=control-group -p RuntimeMaxSec=15s \
  -E HOME=/nonexistent -E PLAYWRIGHT_BROWSERS_PATH=/usr/lib/blindpass/login/browsers \
  /usr/lib/blindpass/login/runtime/bin/node /usr/lib/blindpass/login/private-helper-preflight.mjs
systemctl start blindpass-login-helper.socket
install -d -m 0700 /var/lib/blindpass/broker/sessions
[[ $(stat -c '%a:%U' /run/blindpass-private) == 700:root ]]
[[ $(stat -c '%a:%U' /run/blindpass-private/login.sock) == 600:root ]]
/usr/lib/blindpass/login/runtime/bin/node /tmp/browser-handoff/helper-identity-guest.mjs
systemctl start blindpass-browser.socket blindpass-browser-supervisor.socket blindpass-session-revoker.socket blindpass-runtime-manager.socket
if [[ ${BLINDPASS_P05_FLEET_BROWSER:-0} == 1 ]]; then
  install -m 0755 /tmp/blindpass-controller /tmp/blindpass-node /usr/lib/blindpass/login/
  if [[ ${BLINDPASS_P05_BROWSER_APP:-fixture} == grafana-managed ]]; then
    install -d -m 0755 /usr/lib/blindpass/grafana
    tar --no-same-owner -xf /tmp/grafana-runtime.tar -C /usr/lib/blindpass/grafana
    rm /tmp/grafana-runtime.tar
  fi
  /usr/lib/blindpass/login/runtime/bin/node /tmp/browser-handoff/fleet-browser-guest.mjs
else
  /usr/lib/blindpass/login/runtime/bin/node /tmp/browser-handoff/coordinator-guest.mjs
fi
/usr/lib/blindpass/login/runtime/bin/node /tmp/browser-handoff/private-helper-guest.mjs
bash /tmp/browser-handoff/supervisor-client-guest.sh
systemctl start blindpass-browser.socket blindpass-browser-supervisor.socket blindpass-session-revoker.socket p05-native-supervisor.socket
/usr/lib/blindpass/login/runtime/bin/node /tmp/browser-handoff/session-revoker-guest.mjs
/usr/lib/blindpass/login/runtime/bin/node /tmp/browser-handoff/isolated-browser-guest.mjs
bash /tmp/browser-handoff/session-journal-guest.sh
bash /tmp/browser-handoff/custody-clock-guest.sh
sleep 2
# End-of-run leak check over `list-units --all`. Every instance must be inactive/dead, except a `failed` unit:
# the guests kill or time out helpers and supervisors on purpose, and such a unit ends in `failed`. A failed unit
# is acceptable only when its control group holds no process (a leak is a live process); it is still reported
# with its Result so the failure is recorded, never hidden. Any other state (active, activating, deactivating,
# reloading, or inactive with a failed sub-state) is a leak. A failing `systemctl` is never read as clean.
# Names, states and results are not secret.
assert_units_stopped() {
  local pattern=$1 listing unit load active sub _rest leaked=0 result cgroup procs cgroup_root=${BLINDPASS_CGROUP_ROOT:-/sys/fs/cgroup}
  listing=$(systemctl list-units "$pattern" --all --plain --no-legend --full) || return 2
  while read -r unit load active sub _rest; do
    [[ -n $unit ]] || continue
    if [[ $active == inactive && $sub == dead ]]; then continue; fi
    if [[ $active == failed && $sub == failed ]]; then
      result=$(systemctl show --property=Result --value "$unit") || return 2
      cgroup=$(systemctl show --property=ControlGroup --value "$unit") || return 2
      procs=
      if [[ -n $cgroup && -r $cgroup_root$cgroup/cgroup.procs ]]; then procs=$(<"$cgroup_root$cgroup/cgroup.procs"); fi
      printf 'P05-UNIT-FAILED pattern=%s unit=%s result=%s control_group=%s\n' "$pattern" "$unit" "${result:-unknown}" "${cgroup:-none}" >&2
      if [[ -n $procs ]]; then
        printf 'P05-UNIT-LEAK pattern=%s unit=%s load=%s active=%s sub=%s processes=%s\n' "$pattern" "$unit" "$load" "$active" "$sub" "$(wc -l <<<"$procs")" >&2
        leaked=1
      fi
      continue
    fi
    printf 'P05-UNIT-LEAK pattern=%s unit=%s load=%s active=%s sub=%s\n' "$pattern" "$unit" "$load" "$active" "$sub" >&2
    leaked=1
  done <<<"$listing"
  [[ $leaked == 0 ]]
}
# Positive controls: the listing works, and the checker rejects a unit that is certainly not inactive/dead.
[[ -n $(systemctl list-units 'blindpass-*.socket' --all --plain --no-legend --full) ]]
if assert_units_stopped 'blindpass-login-helper.socket' 2>/dev/null; then
  printf 'P05-LEAK-CHECK-CONTROL the checker accepted a listening socket\n' >&2
  exit 1
fi
leak_patterns=('blindpass-login-helper@*.service' 'blindpass-browser@*.service' 'blindpass-runtime-manager@*.service'
  'blindpass-browser-supervisor@*.service' 'blindpass-session-revoker@*.service' 'p05-native-supervisor@*.service'
  'blindpass-broker.service' 'p05-fleet-node.service' 'p05-browser-agent.service')
leaks=0
for leak_pattern in "${leak_patterns[@]}"; do assert_units_stopped "$leak_pattern" || leaks=1; done
[[ $leaks == 0 ]]
printf 'P05-HELPER-VM runtime=%s systemd=%s kernel=%s active_helper_units=0\n' "$(/usr/lib/blindpass/login/runtime/bin/node --version)" "$(systemd --version | head -1)" "$(uname -r)"
