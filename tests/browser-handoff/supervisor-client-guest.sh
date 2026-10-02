#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Disposable component driver; no changes to the production broker sandbox.
set -Eeuo pipefail
[[ $(id -u) == 0 ]]
cat > /etc/systemd/system/p05-native-supervisor.socket <<'UNIT'
[Socket]
ListenStream=/run/p05-native-supervisor/client.sock
SocketUser=root
SocketGroup=root
SocketMode=0600
DirectoryMode=0700
Accept=yes
RemoveOnStop=yes
UNIT
cat > /etc/systemd/system/p05-native-supervisor@.service <<'UNIT'
[Service]
Type=exec
User=root
Group=root
ExecStart=/usr/lib/blindpass/login/blindpass-browser-supervisor-probe --socket
StandardInput=socket
StandardOutput=null
StandardError=null
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
MemoryDenyWriteExecute=yes
RestrictAddressFamilies=AF_UNIX
CapabilityBoundingSet=CAP_CHOWN
ProtectControlGroups=yes
RuntimeMaxSec=10min
TimeoutStopSec=5s
KillMode=control-group
LimitCORE=0
UNIT
systemctl daemon-reload
systemd-analyze verify /etc/systemd/system/p05-native-supervisor.socket /etc/systemd/system/p05-native-supervisor@.service /etc/systemd/system/blindpass-browser-supervisor.socket /etc/systemd/system/blindpass-browser-supervisor@.service /etc/systemd/system/blindpass-session-revoker.socket /etc/systemd/system/blindpass-session-revoker@.service
