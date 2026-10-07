#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Runs as root inside the throwaway P09 guest only. Installs the pinned toolchain
# and OpenClaw. Never run this on a host.
set -Eeuo pipefail

node_archive=$1 sops_asset=$2 age_asset=$3 sops_sha=$4 age_sha=$5 openclaw_release=$6
user=blindpass

[[ "$(systemd-detect-virt)" != none ]] || { echo 'refusing to run outside a VM' >&2; exit 1; }

cd /tmp
[[ "$(sha256sum "$sops_asset" | awk '{print $1}')" == "$sops_sha" ]] || { echo 'sops hash mismatch' >&2; exit 1; }
[[ "$(sha256sum "$age_asset" | awk '{print $1}')" == "$age_sha" ]] || { echo 'age hash mismatch' >&2; exit 1; }

# The host Node build links libatomic, which the cloud image does not ship.
DEBIAN_FRONTEND=noninteractive apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq libatomic1
tar -xzf "$node_archive" -C /usr/local
/usr/local/bin/node --version >/dev/null
install -m 0755 "$sops_asset" /usr/local/bin/sops
tar -xzf "$age_asset" -C /tmp age/age age/age-keygen
install -m 0755 /tmp/age/age /usr/local/bin/age
install -m 0755 /tmp/age/age-keygen /usr/local/bin/age-keygen
rm -rf /tmp/age

install -d -o "$user" -g "$user" -m 0755 /opt/openclaw
sudo -u "$user" env HOME="/home/$user" npm_config_fund=false npm_config_audit=false \
    npm_config_update_notifier=false bash -c "
        set -Eeuo pipefail
        cd /opt/openclaw
        npm init -y >/dev/null
        npm install --save-exact 'openclaw@$openclaw_release' 2>&1 | tail -25
    "
{
    echo "node $(/usr/local/bin/node --version)"
    echo "npm $(/usr/local/bin/npm --version)"
    echo "sops $(sops --version 2>&1 | head -1)"
    echo "age $(age --version)"
    echo "age-keygen $(age-keygen --version)"
    echo "openclaw $(sudo -u "$user" /opt/openclaw/node_modules/.bin/openclaw --version 2>&1 | head -1)"
} | tee /opt/openclaw/TOOLS.txt

[[ -x /opt/openclaw/node_modules/.bin/openclaw ]] || { echo 'openclaw binary missing after install' >&2; exit 1; }
sudo -u "$user" /opt/openclaw/node_modules/.bin/openclaw --version >/dev/null
echo 'P09-GUEST-SETUP-OK'
