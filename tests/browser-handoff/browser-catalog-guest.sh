#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Disposable guest only: exercise the production binary's fixed catalog loader.
set -Eeuo pipefail
[[ $(id -u) == 0 ]]
[[ ! -e /etc/blindpass ]]
[[ ! -e /run/p05-browser-catalog ]]
cleanup() {
  systemctl stop p05-catalog-broker.service >/dev/null 2>&1 || true
  rm -rf -- /run/p05-browser-catalog /etc/blindpass
}
trap cleanup EXIT
install -d -m 0700 /run/p05-browser-catalog /etc/blindpass
catalog=/etc/blindpass/browser-resources.json
cat > "$catalog" <<'JSON'
{"version":1,"resources":[{"resource_id":"report-primary","workload_ids":["workload-a"],"credential_unit":"blindpass-login-helper@.service","credential_name":"primary-password","configuration":{"kind":"fixture","origin":"https://fixture.example.invalid","account":"primary","sessionMaxMs":300000}}]}
JSON
chmod 0600 "$catalog"
args=(--browser-resources
  --loader-socket /run/p05-browser-catalog/loader.sock
  --workload-socket /run/p05-browser-catalog/workload.sock
  --provision-socket /run/p05-browser-catalog/provision.sock
  --control-socket /run/p05-browser-catalog/control.sock
  --key-directory /run/p05-browser-catalog/keys
  --map blindpass-login-helper@.service=primary-password)
systemd-run --quiet --collect --unit=p05-catalog-broker \
  -p Type=notify -p NotifyAccess=main -p RuntimeMaxSec=15s -p TimeoutStopSec=5s \
  -p NoNewPrivileges=yes -p LimitCORE=0 -p RestrictAddressFamilies=AF_UNIX \
  /usr/lib/blindpass/login/blindpass-broker "${args[@]}"
[[ $(systemctl show -p ActiveState --value p05-catalog-broker.service) == active ]]
[[ -S /run/p05-browser-catalog/workload.sock ]]
systemctl stop p05-catalog-broker.service
rm -f /run/p05-browser-catalog/*.sock
expect_denial() {
  set +e
  /usr/lib/blindpass/login/blindpass-broker "${args[@]}" \
    >/run/p05-browser-catalog/stdout 2>/run/p05-browser-catalog/stderr
  code=$?
  set -e
  [[ $code == 1 ]]
  [[ ! -s /run/p05-browser-catalog/stdout ]]
  [[ $(< /run/p05-browser-catalog/stderr) == 'blindpass-broker: configuration:browser_catalog_unavailable' ]]
  [[ ! -S /run/p05-browser-catalog/workload.sock ]]
}
chmod 0644 "$catalog"
expect_denial
chmod 0600 "$catalog"
mv "$catalog" /etc/blindpass/actual.json
ln -s actual.json "$catalog"
expect_denial
rm "$catalog"
mv /etc/blindpass/actual.json "$catalog"
chmod 0777 /etc/blindpass
expect_denial
chmod 0700 /etc/blindpass
printf '{"version":1,"resources":[],"password":"P05-CONFIG-DUMMY-CANARY"}\n' > "$catalog"
expect_denial
printf 'P05-CATALOG-VM production_startup=ready unsafe_file=denied symlink=denied writable_parent=denied malformed=denied normal_canary=absent grant_consumed=none\n'
