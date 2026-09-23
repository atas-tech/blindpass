#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -Eeuo pipefail

[[ "$(id -u)" == 0 ]] || { printf 'P01-FAIL guest harness requires root\n' >&2; exit 1; }
[[ "$(ps -p 1 -o comm=)" == systemd ]] || {
    printf 'P01-UNSUPPORTED guest PID 1 is not systemd\n' >&2
    exit 78
}
command -v systemctl >/dev/null 2>&1 || { printf 'P01-UNSUPPORTED systemctl missing\n' >&2; exit 78; }

guest_os=$(. /etc/os-release && printf '%s-%s' "$ID" "$VERSION_ID")
guest_systemd=$(systemd --version | awk 'NR == 1 { print $2 }')
printf 'P01-GUEST-ENV os=%s kernel=%s systemd=%s pid1=%s\n' \
    "$guest_os" "$(uname -r)" "$guest_systemd" "$(ps -p 1 -o comm=)"

install -d -m 0755 /usr/libexec /etc/blindpass /etc/systemd/system
install -m 0755 /tmp/blindpass-broker /usr/libexec/blindpass-broker
install -m 0755 /tmp/blindpass-consumer /usr/libexec/blindpass-consumer
install -m 0755 /tmp/blindpass-credential-loader /usr/libexec/blindpass-credential-loader
install -m 0755 /tmp/blindpass-workload-client /usr/libexec/blindpass-workload-client
install -m 0755 /tmp/blindpass-transport-probe /usr/libexec/blindpass-transport-probe
install -m 0644 /tmp/blindpass-broker.service /etc/systemd/system/blindpass-broker.service
install -m 0644 /tmp/blindpass-consumer.service /etc/systemd/system/blindpass-consumer.service
install -m 0644 /tmp/blindpass-consumer-native.service /etc/systemd/system/blindpass-consumer-native.service
install -m 0644 /tmp/blindpass-workload.service /etc/systemd/system/blindpass-workload.service

getent group blindpass-workload >/dev/null || groupadd --system blindpass-workload
id blindpass-agent >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin --gid blindpass-workload blindpass-agent
usermod --append --groups blindpass-workload blindpass-agent

umask 077
printf '%s' 'P01-INITIAL-CANARY' >/etc/blindpass/api-key
chmod 0600 /etc/blindpass/api-key
install -d -m 0700 /run/blindpass-consumer
# The workload is started first solely to capture its invocation ID. The
# broker normally owns this RuntimeDirectory; pre-create it for the same
# systemd namespace policy while the broker is still stopped.
install -d -m 0751 /run/blindpass

systemctl daemon-reload
systemctl start --no-block blindpass-workload.service
invocation=
for _attempt in {1..30}; do
    invocation=$(systemctl show --property=InvocationID --value blindpass-workload.service)
    [[ -n "$invocation" ]] && break
    systemctl is-failed --quiet blindpass-workload.service && break
    sleep 1
done
[[ -n "$invocation" ]] || {
    printf 'P01-FAIL workload invocation unavailable before broker registration\n' >&2
    systemctl status blindpass-workload.service --no-pager -l >&2 || true
    journalctl -u blindpass-workload.service --no-pager -n 40 >&2 || true
    exit 1
}
systemctl is-failed --quiet blindpass-workload.service && {
    printf 'P01-FAIL workload unit failed before broker registration\n' >&2
    systemctl status blindpass-workload.service --no-pager -l >&2 || true
    journalctl -u blindpass-workload.service --no-pager -n 40 >&2 || true
    exit 1
}
workload_uid=$(id -u blindpass-agent)
[[ -n "$workload_uid" ]] || { printf 'P01-FAIL workload uid unavailable\n' >&2; exit 1; }

install -d -m 0755 /etc/systemd/system/blindpass-broker.service.d
write_workload_registration() {
    printf '[Service]\nExecStart=\nExecStart=/usr/libexec/blindpass-broker --loader-socket /run/blindpass/loader.sock --workload-socket /run/blindpass/workload.sock --map blindpass-consumer.service=api-key --credential api-key=/etc/blindpass/api-key --workload node-a:workload-a:blindpass-workload.service:%s:%s\n' \
        "$workload_uid" "$invocation" \
        >/etc/systemd/system/blindpass-broker.service.d/p01-workload.conf
}
write_workload_registration
systemctl daemon-reload
if ! systemctl start blindpass-broker.service; then
    printf 'P01-FAIL broker start command failed\n' >&2
    systemctl status blindpass-broker.service --no-pager -l >&2 || true
    journalctl -u blindpass-broker.service --no-pager -n 80 >&2 || true
    exit 1
fi
systemctl is-active --quiet blindpass-broker.service || { printf 'P01-FAIL broker did not activate\n' >&2; exit 1; }
printf 'P01-SOCKET-POLICY directory=%s loader=%s workload=%s\n' \
    "$(stat -c '%a:%u:%g' /run/blindpass)" \
    "$(stat -c '%a:%u:%g' /run/blindpass/loader.sock)" \
    "$(stat -c '%a:%u:%g' /run/blindpass/workload.sock)"
for _attempt in {1..30}; do
    journalctl -u blindpass-workload.service --no-pager -n 20 | grep -q 'WORKLOAD_READY' && break
    sleep 1
done
journalctl -u blindpass-workload.service --no-pager -n 20 | grep -q 'WORKLOAD_READY' || {
    printf 'P01-FAIL registered workload was not authorized\n' >&2
    printf 'P01-DIAG workload_uid=%s invocation=%s\n' "$workload_uid" "$invocation" >&2
    id blindpass-agent >&2 || true
    systemctl show blindpass-workload.service --property=InvocationID,SubState,MainPID --no-pager >&2 || true
    stat -c 'P01-DIAG %n mode=%a uid=%u gid=%g' /run/blindpass /run/blindpass/workload.sock 2>&1 || true
    systemctl status blindpass-workload.service --no-pager -l >&2 || true
    journalctl -u blindpass-workload.service --no-pager -n 60 >&2 || true
    journalctl -u blindpass-broker.service --no-pager -n 60 >&2 || true
    exit 1
}
printf 'P01-I02 registered non-root workload: PASS\n'

cat >/etc/systemd/system/blindpass-loader-nonroot.service <<'UNIT'
[Unit]
Description=BlindPass P01 non-root loader probe
After=blindpass-broker.service
[Service]
Type=oneshot
User=blindpass-agent
Group=blindpass-workload
ExecStart=/usr/libexec/blindpass-credential-loader --socket /run/blindpass/loader.sock --unit blindpass-consumer.service --credential api-key --output /run/blindpass-nonroot.key
UNIT
systemctl daemon-reload
if systemctl start blindpass-loader-nonroot.service >/dev/null 2>&1; then
    printf 'P01-FAIL non-root loader reached the root-only socket\n' >&2
    exit 1
fi
printf 'P01-I02 non-root loader denied by socket boundary: PASS\n'

cat >/etc/systemd/system/blindpass-stall.service <<'UNIT'
[Unit]
Description=BlindPass P01 stalled loader probe
After=blindpass-broker.service
[Service]
Type=oneshot
User=root
Group=root
ExecStart=/usr/libexec/blindpass-transport-probe --socket /run/blindpass/loader.sock --hold-ms 8000
UNIT
systemctl daemon-reload
if ! systemctl start blindpass-stall.service >/dev/null 2>&1; then
    printf 'P01-FAIL broker stalled-frame probe did not complete\n' >&2
    journalctl -u blindpass-stall.service --no-pager -n 40 >&2 || true
    journalctl -u blindpass-broker.service --no-pager -n 80 >&2 || true
    exit 1
fi
stall_probe=$(journalctl -u blindpass-stall.service --no-pager -o cat -n 20 | grep 'STALL_DENIED' | tail -n 1)
[[ "$stall_probe" == STALL_DENIED\ * ]] || {
    printf 'P01-FAIL broker did not enforce its bounded stalled-frame response\n' >&2
    exit 1
}
printf 'P01-I04 stalled loader frame within broker deadline: PASS (%s)\n' "$stall_probe"

systemctl start blindpass-consumer.service
systemctl is-active --quiet blindpass-consumer.service || { printf 'P01-FAIL consumer did not activate\n' >&2; exit 1; }
printf 'P01-E01 initial native consumer: PASS\n'
systemctl restart blindpass-consumer.service
systemctl is-active --quiet blindpass-consumer.service || {
    printf 'P01-FAIL consumer restart could not re-resolve loader identity\n' >&2
    exit 1
}
printf 'P01-I01 loader restart re-resolved current invocation: PASS\n'

old_invocation=$invocation
systemctl stop blindpass-workload.service >/dev/null 2>&1 || true
systemctl reset-failed blindpass-workload.service >/dev/null 2>&1 || true
systemctl start --no-block blindpass-workload.service
replacement_invocation=
for _attempt in {1..30}; do
    replacement_invocation=$(systemctl show --property=InvocationID --value blindpass-workload.service)
    if [[ -n "$replacement_invocation" && "$replacement_invocation" != "$old_invocation" ]]; then
        break
    fi
    sleep 0.2
done
[[ -n "$replacement_invocation" && "$replacement_invocation" != "$old_invocation" ]] || {
    printf 'P01-FAIL workload restart did not receive a new invocation\n' >&2
    exit 1
}
stale_workload_denied=no
for _attempt in {1..30}; do
    if journalctl -u blindpass-broker.service --no-pager -n 80 | grep -q 'unknown_registration'; then
        stale_workload_denied=yes
        break
    fi
    sleep 0.2
done
systemctl stop blindpass-workload.service >/dev/null 2>&1 || true
systemctl reset-failed blindpass-workload.service >/dev/null 2>&1 || true
[[ "$stale_workload_denied" == yes ]] || {
    printf 'P01-FAIL replacement workload invocation was accepted\n' >&2
    exit 1
}
install -d -m 0755 /etc/systemd/system/blindpass-workload.service.d
cat >/etc/systemd/system/blindpass-workload.service.d/p01-delay.conf <<'UNIT'
[Service]
ExecStart=
ExecStart=/usr/libexec/blindpass-workload-client --socket /run/blindpass/workload.sock --node node-a --workload workload-a --unit blindpass-workload.service --operation health --startup-delay-ms 5000 --hold-seconds 3600
UNIT
systemctl daemon-reload
systemctl reset-failed blindpass-workload.service >/dev/null 2>&1 || true
workload_started_at=$(date --iso-8601=seconds)
systemctl start --no-block blindpass-workload.service
re_registered_invocation=
for _attempt in {1..30}; do
    re_registered_invocation=$(systemctl show --property=InvocationID --value blindpass-workload.service)
    if [[ -n "$re_registered_invocation" && "$re_registered_invocation" != "$replacement_invocation" ]]; then
        break
    fi
    sleep 0.2
done
[[ -n "$re_registered_invocation" && "$re_registered_invocation" != "$replacement_invocation" ]] || {
    printf 'P01-FAIL delayed replacement workload did not receive a fresh invocation\n' >&2
    exit 1
}
invocation=$re_registered_invocation
write_workload_registration
systemctl daemon-reload
systemctl restart blindpass-broker.service
workload_recovered=no
for _attempt in {1..30}; do
    current_invocation=$(systemctl show --property=InvocationID --value blindpass-workload.service)
    if systemctl is-active --quiet blindpass-workload.service \
        && [[ "$current_invocation" == "$re_registered_invocation" ]] \
        && journalctl -u blindpass-workload.service --since "$workload_started_at" --no-pager \
            | grep -q 'WORKLOAD_READY'; then
        workload_recovered=yes
        break
    fi
    sleep 0.2
done
rm -f /etc/systemd/system/blindpass-workload.service.d/p01-delay.conf
systemctl daemon-reload
[[ "$workload_recovered" == yes ]] || {
    printf 'P01-FAIL replacement workload did not recover after re-registration\n' >&2
    systemctl status blindpass-workload.service --no-pager -l >&2 || true
    journalctl -u blindpass-workload.service --no-pager -n 60 >&2 || true
    journalctl -u blindpass-broker.service --no-pager -n 60 >&2 || true
    exit 1
}
printf 'P01-I01 stale workload invocation denied and re-registration required: PASS\n'

command -v systemd-creds >/dev/null 2>&1 || {
    printf 'P01-UNSUPPORTED systemd-creds is unavailable for the mandatory native credential comparison\n' >&2
    exit 78
}
systemd-creds setup >/dev/null 2>&1 || {
    printf 'P01-UNSUPPORTED systemd host credential key setup failed\n' >&2
    exit 78
}
native_credential=/etc/blindpass/api-key.cred
native_credential_next=/etc/blindpass/api-key.cred.next
systemd-creds --with-key=host --name=api-key encrypt /etc/blindpass/api-key "$native_credential_next" >/dev/null
install -m 0600 "$native_credential_next" "$native_credential"
rm -f "$native_credential_next"
systemctl daemon-reload
systemctl start blindpass-consumer-native.service
systemctl is-active --quiet blindpass-consumer-native.service || {
    printf 'P01-FAIL native encrypted credential consumer did not activate\n' >&2
    exit 1
}
printf 'P01-E02 native encrypted credstore initial delivery: PASS (host-key profile)\n'
systemctl stop blindpass-consumer-native.service
printf '%s' 'P01-ROTATED-CANARY' >/etc/blindpass/api-key
chmod 0600 /etc/blindpass/api-key
systemd-creds --with-key=host --name=api-key encrypt /etc/blindpass/api-key "$native_credential_next" >/dev/null
install -m 0600 "$native_credential_next" "$native_credential"
rm -f "$native_credential_next"
systemctl start blindpass-consumer-native.service
systemctl is-active --quiet blindpass-consumer-native.service || {
    printf 'P01-FAIL native encrypted credential rotation did not activate\n' >&2
    exit 1
}
printf 'P01-E02 native encrypted credstore controlled rotation: PASS\n'

cat >/etc/systemd/system/blindpass-unauthorized.service <<'UNIT'
[Unit]
Description=BlindPass P01 forged unit probe
After=blindpass-broker.service
[Service]
Type=oneshot
User=root
ExecStart=/usr/libexec/blindpass-credential-loader --socket /run/blindpass/loader.sock --unit blindpass-consumer.service --credential api-key --output /run/blindpass-unauthorized.key
UNIT
systemctl daemon-reload
if systemctl start blindpass-unauthorized.service >/dev/null 2>&1; then
    printf 'P01-FAIL forged unit routing was accepted\n' >&2
    exit 1
fi
printf 'P01-I02 mismatched loader routing: PASS\n'

cat >/etc/systemd/system/blindpass-unregistered.service <<'UNIT'
[Unit]
Description=BlindPass P01 unregistered workload probe
After=blindpass-broker.service
[Service]
Type=oneshot
User=blindpass-agent
Group=blindpass-workload
ExecStart=/usr/libexec/blindpass-workload-client --socket /run/blindpass/workload.sock --node node-a --workload unregistered --unit blindpass-unregistered.service --operation health
UNIT
systemctl daemon-reload
if systemctl start blindpass-unregistered.service >/dev/null 2>&1; then
    printf 'P01-FAIL unregistered workload was accepted\n' >&2
    exit 1
fi
printf 'P01-I02 unregistered workload: PASS\n'

install -d -m 0700 /run/blindpass-faults
for case_name in empty partial malformed oversized; do
    case "$case_name" in
        empty) : > "/run/blindpass-faults/$case_name" ;;
        partial) printf '%s' 'P01' > "/run/blindpass-faults/$case_name" ;;
        malformed) printf '\377' > "/run/blindpass-faults/$case_name" ;;
        oversized) dd if=/dev/zero of="/run/blindpass-faults/$case_name" bs=65537 count=1 status=none ;;
    esac
    chmod 0600 "/run/blindpass-faults/$case_name"
    if /usr/libexec/blindpass-consumer --credential-file "/run/blindpass-faults/$case_name" --prefix P01- >/dev/null 2>&1; then
        printf 'P01-FAIL consumer accepted %s material\n' "$case_name" >&2
        exit 1
    fi
done
printf 'P01-I04 empty/partial/malformed/oversized consumer material: PASS\n'

for canary in P01-INITIAL-CANARY; do
    if ps axww -o args= | awk -v needle="$canary" \
        '$0 !~ /awk/ && index($0, needle) { found = 1 } END { exit found ? 0 : 1 }'; then
        printf 'P01-FAIL %s appeared in a process argument\n' "$canary" >&2
        exit 1
    fi
    if journalctl --no-pager -u blindpass-broker.service -u blindpass-consumer.service \
        -u blindpass-workload.service -u blindpass-loader-nonroot.service \
        | grep -F -- "$canary" >/dev/null 2>&1; then
        printf 'P01-FAIL %s appeared in a service journal\n' "$canary" >&2
        exit 1
    fi
done
printf 'P01-I06 initial canary absent from process arguments and service journals: PASS\n'

systemctl stop blindpass-consumer.service
printf '%s' 'P01-ROTATED-CANARY' >/etc/blindpass/api-key
chmod 0600 /etc/blindpass/api-key
systemctl restart blindpass-broker.service
systemctl start blindpass-consumer.service
printf 'P01-E01 controlled restart rotation: PASS\n'
if ps axww -o args= | awk -v needle='P01-ROTATED-CANARY' \
    '$0 !~ /awk/ && index($0, needle) { found = 1 } END { exit found ? 0 : 1 }' \
    || journalctl --no-pager -u blindpass-broker.service -u blindpass-consumer.service \
        -u blindpass-workload.service | grep -F -- 'P01-ROTATED-CANARY' >/dev/null 2>&1; then
    printf 'P01-FAIL rotated canary appeared in process arguments or service journals\n' >&2
    exit 1
fi
printf 'P01-I06 rotated canary absent from process arguments and service journals: PASS\n'

systemctl stop blindpass-consumer.service blindpass-broker.service >/dev/null 2>&1 || true
cat >/etc/systemd/system/blindpass-broker.service.d/p01-api-removed.conf <<'UNIT'
[Service]
InaccessiblePaths=/run/dbus/system_bus_socket
UNIT
systemctl daemon-reload
systemctl start blindpass-broker.service
rm -f /run/blindpass-consumer/api-key
if systemctl start blindpass-consumer.service >/dev/null 2>&1; then
    printf 'P01-FAIL broker delivered after system-bus API removal\n' >&2
    exit 1
fi
[[ ! -e /run/blindpass-consumer/api-key ]] || {
    printf 'P01-FAIL consumer material remained after system-bus API removal\n' >&2
    exit 1
}
printf 'P01-I03 system-bus API removal failed closed: PASS\n'
rm -f /etc/systemd/system/blindpass-broker.service.d/p01-api-removed.conf
systemctl daemon-reload
systemctl restart blindpass-broker.service
systemctl reset-failed blindpass-consumer.service >/dev/null 2>&1 || true

printf 'P01-I05 HPKE restart/absent-key VM path: NOT_CLAIMED (portable vector covered separately)\n'
printf 'P01-RETAINED-PROTECTED-MATERIAL /etc/blindpass/api-key /etc/blindpass/api-key.cred\n'

systemctl stop blindpass-stall.service blindpass-loader-nonroot.service blindpass-unregistered.service blindpass-unauthorized.service blindpass-consumer.service blindpass-consumer-native.service blindpass-workload.service blindpass-broker.service >/dev/null 2>&1 || true
rm -f /run/blindpass/loader.sock /run/blindpass/workload.sock
[[ ! -e /run/blindpass/loader.sock && ! -e /run/blindpass/workload.sock ]] || {
    printf 'P01-FAIL broker sockets remained after cleanup\n' >&2
    exit 1
}
[[ -f /etc/blindpass/api-key && "$(stat -c '%a:%u' /etc/blindpass/api-key)" == 600:0 ]] || {
    printf 'P01-FAIL protected material was not retained with root-only mode\n' >&2
    exit 1
}
[[ -f /etc/blindpass/api-key.cred && "$(stat -c '%a:%u' /etc/blindpass/api-key.cred)" == 600:0 ]] || {
    printf 'P01-FAIL encrypted native credential was not retained with root-only mode\n' >&2
    exit 1
}
rm -f /run/blindpass-unauthorized.key /run/blindpass-nonroot.key
rm -rf -- /run/blindpass-faults /run/blindpass-consumer
rm -f /etc/systemd/system/blindpass-broker.service \
    /etc/systemd/system/blindpass-consumer.service \
    /etc/systemd/system/blindpass-consumer-native.service \
    /etc/systemd/system/blindpass-workload.service \
    /etc/systemd/system/blindpass-stall.service \
    /etc/systemd/system/blindpass-loader-nonroot.service \
    /etc/systemd/system/blindpass-unauthorized.service \
    /etc/systemd/system/blindpass-unregistered.service
rm -rf -- /etc/systemd/system/blindpass-broker.service.d
rm -rf -- /etc/systemd/system/blindpass-workload.service.d
rm -f /usr/libexec/blindpass-broker /usr/libexec/blindpass-consumer \
    /usr/libexec/blindpass-credential-loader /usr/libexec/blindpass-workload-client \
    /usr/libexec/blindpass-transport-probe
systemctl daemon-reload
[[ ! -e /etc/systemd/system/blindpass-broker.service && ! -e /run/blindpass/loader.sock ]] || {
    printf 'P01-FAIL broker installation remained after uninstall\n' >&2
    exit 1
}
printf 'P01-GUEST-CLEANUP sockets_removed=yes units_removed=yes protected_material_retained=yes\n'
