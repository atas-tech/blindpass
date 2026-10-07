#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Node guest only: the P05 managed-application and stock AI-client task, run against the packaged native
# controller in the other guest. It installs the same shipped broker/browser units and runtime bundle as
# tests/browser-handoff/private-helper-guest.sh, skips that script's helper/probe verification stages (they are
# P05 evidence, not needed to run the task), and starts fleet-browser-guest.mjs with the remote-controller
# fixture. tests/fleet/p06-native-node-vm.py --scenario ai-task copies the inputs to /tmp and drives it.
set -Eeuo pipefail
[[ $(id -u) == 0 ]]
cleanup() {
  result=$?
  if [[ $result != 0 && -f /tmp/p05-helper-apt.log ]]; then tail -8 /tmp/p05-helper-apt.log; fi
  systemctl stop blindpass-login-helper.socket 'blindpass-login-helper@*.service' >/dev/null 2>&1 || true
  systemctl stop blindpass-runtime-manager.socket 'blindpass-runtime-manager@*.service' blindpass-broker.service p05-fleet-node.service >/dev/null 2>&1 || true
  systemctl stop blindpass-browser.socket 'blindpass-browser@*.service' blindpass-browser-supervisor.socket blindpass-session-revoker.socket >/dev/null 2>&1 || true
  systemctl stop 'blindpass-session-revoker@*.service' 'blindpass-browser-supervisor@*.service' >/dev/null 2>&1 || true
  rm -f /root/p06-remote-controller.json
}
trap cleanup EXIT
# The shared node-guest preparation enabled the plain broker and node units; the managed-application flow
# starts its own broker and node and needs a fresh /etc/blindpass and broker state directory.
systemctl disable --now blindpass-node.service blindpass-broker.service >/dev/null 2>&1 || true
systemctl reset-failed blindpass-node.service blindpass-broker.service >/dev/null 2>&1 || true
rm -rf /etc/blindpass /var/lib/blindpass/broker
install -d -m 0755 /usr/lib/blindpass/login
tar --no-same-owner -xzf /tmp/private-helper-runtime.tar.gz -C /usr/lib/blindpass/login
install -m 0755 /tmp/blindpass-node /tmp/blindpass-provision /tmp/blindpass-broker /usr/lib/blindpass/login/
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
apt-get -o Acquire::Languages=none update -qq >/tmp/p05-helper-apt.log 2>&1
apt-get install -y -qq libatomic1 libnss3 libatk1.0-0t64 libatk-bridge2.0-0t64 libcups2t64 libdrm2 libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 libxrandr2 libgbm1 libasound2t64 >/tmp/p05-helper-apt.log 2>&1
install -m 0644 /tmp/blindpass-login-chromium.apparmor /etc/apparmor.d/blindpass-login-chromium
apparmor_parser -r /etc/apparmor.d/blindpass-login-chromium
[[ $(sysctl -n kernel.apparmor_restrict_unprivileged_userns) == 1 ]]
systemctl daemon-reload
systemctl start blindpass-login-helper.socket
install -d -m 0700 /var/lib/blindpass/broker/sessions
systemctl start blindpass-browser.socket blindpass-browser-supervisor.socket blindpass-session-revoker.socket blindpass-runtime-manager.socket
install -d -m 0755 /usr/lib/blindpass/grafana
tar --no-same-owner -xf /tmp/grafana-runtime.tar -C /usr/lib/blindpass/grafana
rm /tmp/grafana-runtime.tar
export BLINDPASS_P06_REMOTE_CONTROLLER=1 BLINDPASS_P05_FLEET_BROWSER=1 BLINDPASS_P05_BROWSER_APP=grafana-managed
/usr/lib/blindpass/login/runtime/bin/node /tmp/browser-handoff/fleet-browser-guest.mjs
printf 'P06-AI-GUEST complete runtime=%s systemd=%s\n' "$(/usr/lib/blindpass/login/runtime/bin/node --version)" "$(systemd --version | head -1)"
