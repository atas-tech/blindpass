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

assert_canary_absent() {
    local canary=$1
    if ps axww -o args= | awk -v needle="$canary" \
        '$0 !~ /awk/ && index($0, needle) { found = 1 } END { exit found ? 0 : 1 }'; then
        printf 'P01-FAIL %s appeared in a process argument\n' "$canary" >&2
        exit 1
    fi
    if journalctl --no-pager -u blindpass-broker.service -u blindpass-consumer.service \
        -u blindpass-backup.service -u blindpass-workload.service -u blindpass-loader-nonroot.service \
        -u blindpass-loader-race.service \
        | grep -F -- "$canary" >/dev/null 2>&1; then
        printf 'P01-FAIL %s appeared in a service journal\n' "$canary" >&2
        exit 1
    fi
    while IFS= read -r -d '' artifact; do
        [[ "$artifact" == /tmp/p01-guest.sh ]] && continue
        if grep -aF -- "$canary" "$artifact" >/dev/null 2>&1; then
            printf 'P01-FAIL %s appeared in runtime artifact %s\n' "$canary" "$artifact" >&2
            exit 1
        fi
    done < <(
        find /tmp /var/tmp /var/crash /run/blindpass-consumer /run/blindpass-backup \
            /run/blindpass-loader-race /run/blindpass-faults /run/blindpass-custody-probe \
            -xdev -type f -size -1M -print0 2>/dev/null
    )
}

install -d -m 0755 /usr/libexec /etc/blindpass /etc/systemd/system
install -m 0755 /tmp/blindpass-broker /usr/libexec/blindpass-broker
install -m 0755 /tmp/blindpass-backup-probe /usr/libexec/blindpass-backup-probe
install -m 0755 /tmp/blindpass-consumer /usr/libexec/blindpass-consumer
install -m 0755 /tmp/blindpass-custody-probe /usr/libexec/blindpass-custody-probe
install -m 0755 /tmp/blindpass-credential-loader /usr/libexec/blindpass-credential-loader
install -m 0755 /tmp/blindpass-workload-client /usr/libexec/blindpass-workload-client
install -m 0755 /tmp/blindpass-transport-probe /usr/libexec/blindpass-transport-probe
install -m 0644 /tmp/blindpass-broker.service /etc/systemd/system/blindpass-broker.service
install -m 0644 /tmp/blindpass-backup.service /etc/systemd/system/blindpass-backup.service
install -m 0644 /tmp/blindpass-consumer.service /etc/systemd/system/blindpass-consumer.service
install -m 0644 /tmp/blindpass-consumer-native.service /etc/systemd/system/blindpass-consumer-native.service
install -m 0644 /tmp/blindpass-workload.service /etc/systemd/system/blindpass-workload.service

if [[ "${BLINDPASS_P01_INJECT_FAILURE:-0}" == 1 ]]; then
    printf 'P01-INJECTED-FAILURE guest test failure for teardown validation\n' >&2
    exit 42
fi
if [[ -n "${BLINDPASS_P01_CANCEL_AFTER_BOOT_SECONDS:-}" ]]; then
    printf 'P01-CANCEL-WINDOW seconds=%s\n' "$BLINDPASS_P01_CANCEL_AFTER_BOOT_SECONDS"
    sleep "$BLINDPASS_P01_CANCEL_AFTER_BOOT_SECONDS"
fi

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
    local registration_uid=${1:-$workload_uid}
    local registration_invocation=${2:-$invocation}
    local registration_unit=${3:-blindpass-workload.service}
    local registration_workload=${4:-workload-a}
    printf '[Service]\nExecStart=\nExecStart=/usr/libexec/blindpass-broker --loader-socket /run/blindpass/loader.sock --workload-socket /run/blindpass/workload.sock --map blindpass-consumer.service=api-key --map blindpass-backup.service=api-key --map blindpass-loader-race.service=api-key --credential api-key=/etc/blindpass/api-key --workload node-a:%s:%s:%s:%s\n' \
        "$registration_workload" "$registration_unit" "$registration_uid" "$registration_invocation" \
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

install -d -m 0700 /run/blindpass-custody-probe
if ! /usr/libexec/blindpass-custody-probe --workdir /run/blindpass-custody-probe; then
    printf 'P01-FAIL custody lifecycle probe failed\n' >&2
    exit 1
fi

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

user_manager_uid=$(id -u blindpass)
user_manager_runtime=/run/user/$user_manager_uid
user_manager_ready=no
if command -v runuser >/dev/null 2>&1 && command -v systemd-run >/dev/null 2>&1 \
    && systemctl start "user-runtime-dir@$user_manager_uid.service" >/dev/null 2>&1 \
    && systemctl start "user@$user_manager_uid.service" >/dev/null 2>&1; then
    install -d -o blindpass -g blindpass -m 0700 "$user_manager_runtime"
    user_manager_ready=yes
fi
if [[ "$user_manager_ready" == yes ]]; then
    rm -f "$user_manager_runtime/p01-user-manager.key"
    if runuser -u blindpass -- env \
        XDG_RUNTIME_DIR="$user_manager_runtime" \
        DBUS_SESSION_BUS_ADDRESS="unix:path=$user_manager_runtime/bus" \
        systemd-run --user --wait --collect --unit=blindpass-p01-user-loader \
        /usr/libexec/blindpass-credential-loader \
        --socket /run/blindpass/loader.sock --unit blindpass-consumer.service \
        --credential api-key --output "$user_manager_runtime/p01-user-manager.key" \
        >/run/blindpass-user-manager.log 2>&1; then
        printf 'P01-FAIL user-manager loader reached the root-only socket\n' >&2
        exit 1
    fi
    [[ ! -e "$user_manager_runtime/p01-user-manager.key" ]] || {
        printf 'P01-FAIL user-manager loader left credential material\n' >&2
        exit 1
    }
    printf 'P01-I02 user-manager loader denied by socket boundary: PASS\n'
else
    printf 'P01-I02 user-manager profile: NOT_CLAIMED (user manager unavailable)\n'
fi

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

install -d -m 0700 /run/blindpass-loader-race
cat >/etc/systemd/system/blindpass-loader-race.service <<'UNIT'
[Unit]
Description=BlindPass P01 root loader restart race probe
After=blindpass-broker.service
[Service]
Type=oneshot
User=root
Group=root
ExecStart=/usr/libexec/blindpass-credential-loader --socket /run/blindpass/loader.sock --unit blindpass-loader-race.service --credential api-key --output /run/blindpass-loader-race/api-key --pre-request-delay-ms 1000
LimitCORE=0
UNIT
systemctl daemon-reload
for loader_race_round in 1 2; do
    rm -f /run/blindpass-loader-race/api-key /run/blindpass-loader-race/api-key.tmp
    systemctl reset-failed blindpass-loader-race.service >/dev/null 2>&1 || true
    systemctl start --no-block blindpass-loader-race.service
    loader_old_pid=
    loader_old_invocation=
    for _attempt in {1..30}; do
        loader_old_pid=$(systemctl show --property=MainPID --value blindpass-loader-race.service)
        loader_old_invocation=$(systemctl show --property=InvocationID --value blindpass-loader-race.service)
        if [[ "$loader_old_pid" != 0 && -n "$loader_old_invocation" ]]; then
            break
        fi
        sleep 0.2
    done
    [[ "$loader_old_pid" != 0 && -n "$loader_old_invocation" ]] || {
        printf 'P01-FAIL root loader race did not start (round=%s)\n' "$loader_race_round" >&2
        exit 1
    }
    sleep 0.2
    systemctl restart --no-block blindpass-loader-race.service
    loader_new_pid=
    loader_new_invocation=
    for _attempt in {1..30}; do
        loader_new_pid=$(systemctl show --property=MainPID --value blindpass-loader-race.service)
        loader_new_invocation=$(systemctl show --property=InvocationID --value blindpass-loader-race.service)
        if [[ "$loader_new_pid" != 0 && "$loader_new_pid" != "$loader_old_pid" \
            && "$loader_new_invocation" != "$loader_old_invocation" ]]; then
            break
        fi
        sleep 0.2
    done
    [[ "$loader_new_pid" != 0 && "$loader_new_pid" != "$loader_old_pid" \
        && "$loader_new_invocation" != "$loader_old_invocation" ]] || {
        printf 'P01-FAIL root loader race did not receive a replacement invocation (round=%s)\n' "$loader_race_round" >&2
        exit 1
    }
    for _attempt in {1..40}; do
        [[ -f /run/blindpass-loader-race/api-key ]] && break
        sleep 0.2
    done
    [[ -f /run/blindpass-loader-race/api-key ]] || {
        printf 'P01-FAIL replacement root loader did not deliver a credential (round=%s)\n' "$loader_race_round" >&2
        systemctl status blindpass-loader-race.service --no-pager -l >&2 || true
        exit 1
    }
    /usr/libexec/blindpass-consumer --credential-file /run/blindpass-loader-race/api-key --prefix P01- || {
        printf 'P01-FAIL replacement root loader delivered invalid material (round=%s)\n' "$loader_race_round" >&2
        exit 1
    }
    printf 'P01-I01 root loader pidfd-to-invocation restart race: PASS (round=%s old_pid=%s new_pid=%s)\n' \
        "$loader_race_round" "$loader_old_pid" "$loader_new_pid"
done
systemctl stop blindpass-loader-race.service >/dev/null 2>&1 || true
rm -f /etc/systemd/system/blindpass-loader-race.service
systemctl daemon-reload

systemctl reset-failed blindpass-backup.service >/dev/null 2>&1 || true
systemctl start blindpass-backup.service
systemctl is-active --quiet blindpass-backup.service || {
    printf 'P01-FAIL disposable backup consumer did not activate\n' >&2
    exit 1
}
backup_restore=$(/usr/libexec/blindpass-backup-probe \
    --credential-file /run/blindpass-backup/api-key \
    --artifact /run/blindpass-backup/artifact --mode restore)
[[ "$backup_restore" == BACKUP_RESTORED ]] || {
    printf 'P01-FAIL disposable backup restore did not validate\n' >&2
    exit 1
}
[[ "$(stat -c '%a:%u' /run/blindpass-backup/artifact)" == 600:0 ]] || {
    printf 'P01-FAIL disposable backup artifact permissions were not root-only\n' >&2
    exit 1
}
printf 'P01-E01 credential-consuming backup write/restore: PASS\n'

for delivery_fault in empty partial malformed oversized corrupt; do
    cat >/etc/systemd/system/blindpass-broker.service.d/p01-delivery-fault.conf <<UNIT
[Service]
Environment=BLINDPASS_P01_TEST_MODE=1
Environment=BLINDPASS_P01_DELIVERY_FAULT=$delivery_fault
UNIT
    systemctl daemon-reload
    systemctl stop blindpass-consumer.service >/dev/null 2>&1 || true
    systemctl reset-failed blindpass-consumer.service >/dev/null 2>&1 || true
    rm -f /run/blindpass-consumer/api-key /run/blindpass-consumer/api-key.tmp
    systemctl reset-failed blindpass-broker.service >/dev/null 2>&1 || true
    if ! systemctl restart blindpass-broker.service; then
        printf 'P01-FAIL broker did not restart for delivery fault %s\n' "$delivery_fault" >&2
        systemctl status blindpass-broker.service --no-pager -l >&2 || true
        journalctl -u blindpass-broker.service --no-pager -n 80 >&2 || true
        exit 1
    fi
    if systemctl start blindpass-consumer.service >/dev/null 2>&1; then
        printf 'P01-FAIL consumer accepted broker delivery fault %s\n' "$delivery_fault" >&2
        exit 1
    fi
    [[ ! -e /run/blindpass-consumer/api-key.tmp ]] || {
        printf 'P01-FAIL broker delivery fault %s left a temporary credential\n' "$delivery_fault" >&2
        exit 1
    }
    rm -f /run/blindpass-consumer/api-key
    systemctl reset-failed blindpass-consumer.service >/dev/null 2>&1 || true
done
rm -f /etc/systemd/system/blindpass-broker.service.d/p01-delivery-fault.conf
systemctl daemon-reload
systemctl reset-failed blindpass-broker.service >/dev/null 2>&1 || true
systemctl restart blindpass-broker.service
printf 'P01-I04 broker empty/partial/malformed/oversized/corrupt delivery: PASS\n'

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
systemctl reset-failed blindpass-broker.service >/dev/null 2>&1 || true
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

install -d -m 0755 /etc/systemd/system/blindpass-workload.service.d
for race_round in 1 2 3; do
    cat >/etc/systemd/system/blindpass-workload.service.d/p01-race.conf <<'UNIT'
[Service]
ExecStart=
ExecStart=/usr/libexec/blindpass-workload-client --socket /run/blindpass/workload.sock --node node-a --workload workload-a --unit blindpass-workload.service --operation health --pre-request-delay-ms 5000 --hold-seconds 3600
UNIT
    systemctl daemon-reload
    systemctl stop blindpass-workload.service >/dev/null 2>&1 || true
    systemctl reset-failed blindpass-workload.service >/dev/null 2>&1 || true
    race_started_at=$(date --iso-8601=seconds)
    systemctl start --no-block blindpass-workload.service
    race_old_invocation=
    race_old_pid=
    for _attempt in {1..30}; do
        race_old_invocation=$(systemctl show --property=InvocationID --value blindpass-workload.service)
        race_old_pid=$(systemctl show --property=MainPID --value blindpass-workload.service)
        if [[ -n "$race_old_invocation" && "$race_old_pid" != 0 ]]; then
            break
        fi
        sleep 0.2
    done
    [[ -n "$race_old_invocation" && "$race_old_pid" != 0 ]] || {
        printf 'P01-FAIL race workload did not start (round=%s)\n' "$race_round" >&2
        exit 1
    }
    sleep 1
    systemctl restart blindpass-workload.service
    race_new_invocation=
    race_new_pid=
    for _attempt in {1..30}; do
        race_new_invocation=$(systemctl show --property=InvocationID --value blindpass-workload.service)
        race_new_pid=$(systemctl show --property=MainPID --value blindpass-workload.service)
        if [[ -n "$race_new_invocation" && "$race_new_invocation" != "$race_old_invocation" \
            && "$race_new_pid" != 0 && "$race_new_pid" != "$race_old_pid" ]]; then
            break
        fi
        sleep 0.2
    done
    [[ -n "$race_new_invocation" && "$race_new_invocation" != "$race_old_invocation" \
        && "$race_new_pid" != 0 && "$race_new_pid" != "$race_old_pid" ]] || {
        printf 'P01-FAIL workload race did not receive a replacement invocation (round=%s)\n' "$race_round" >&2
        exit 1
    }
    invocation=$race_new_invocation
    write_workload_registration
    systemctl daemon-reload
    systemctl reset-failed blindpass-broker.service >/dev/null 2>&1 || true
    systemctl restart blindpass-broker.service
    race_recovered=no
    for _attempt in {1..40}; do
        if systemctl is-active --quiet blindpass-workload.service \
            && [[ "$(systemctl show --property=InvocationID --value blindpass-workload.service)" == "$race_new_invocation" ]] \
            && journalctl -u blindpass-workload.service --since "$race_started_at" --no-pager \
                | grep -q 'WORKLOAD_READY'; then
            race_recovered=yes
            break
        fi
        sleep 0.2
    done
    [[ "$race_recovered" == yes ]] || {
        printf 'P01-FAIL replacement workload did not recover after pidfd race (round=%s)\n' "$race_round" >&2
        journalctl -u blindpass-workload.service --no-pager -n 60 >&2 || true
        journalctl -u blindpass-broker.service --no-pager -n 60 >&2 || true
        exit 1
    }
    printf 'P01-I01 pidfd-to-invocation restart race: PASS (round=%s old_pid=%s new_pid=%s)\n' \
        "$race_round" "$race_old_pid" "$race_new_pid"
done
rm -f /etc/systemd/system/blindpass-workload.service.d/p01-race.conf
systemctl daemon-reload

cat >/etc/systemd/system/blindpass-dynamic.service <<'UNIT'
[Unit]
Description=BlindPass P01 DynamicUser workload probe
After=blindpass-broker.service
[Service]
Type=simple
DynamicUser=yes
SupplementaryGroups=blindpass-workload
ExecStart=/usr/libexec/blindpass-workload-client --socket /run/blindpass/workload.sock --node node-a --workload dynamic-a --unit blindpass-dynamic.service --operation health --startup-delay-ms 5000 --hold-seconds 3600
Restart=on-failure
RestartSec=1s
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadOnlyPaths=/run/blindpass
RestrictAddressFamilies=AF_UNIX
LockPersonality=yes
MemoryDenyWriteExecute=yes
LimitCORE=0
ProtectKernelTunables=yes
ProtectControlGroups=yes
ProtectKernelModules=yes
RestrictSUIDSGID=yes
SystemCallArchitectures=native
UNIT
systemctl daemon-reload
systemctl stop blindpass-workload.service >/dev/null 2>&1 || true
systemctl reset-failed blindpass-workload.service >/dev/null 2>&1 || true
systemctl start --no-block blindpass-dynamic.service
dynamic_invocation=
dynamic_pid=
dynamic_uid=
for _attempt in {1..30}; do
    dynamic_invocation=$(systemctl show --property=InvocationID --value blindpass-dynamic.service)
    dynamic_pid=$(systemctl show --property=MainPID --value blindpass-dynamic.service)
    if [[ -n "$dynamic_invocation" && "$dynamic_pid" != 0 && -r "/proc/$dynamic_pid/status" ]]; then
        dynamic_uid=$(stat -c '%u' "/proc/$dynamic_pid")
        if [[ "$dynamic_uid" != 0 ]]; then
            break
        fi
    fi
    sleep 0.2
done
[[ -n "$dynamic_invocation" && "$dynamic_pid" != 0 && "$dynamic_uid" != 0 ]] || {
    printf 'P01-FAIL DynamicUser workload identity was unavailable\n' >&2
    systemctl status blindpass-dynamic.service --no-pager -l >&2 || true
    exit 1
}
write_workload_registration "$dynamic_uid" "$dynamic_invocation" \
    blindpass-dynamic.service dynamic-a
systemctl daemon-reload
systemctl reset-failed blindpass-broker.service >/dev/null 2>&1 || true
systemctl restart blindpass-broker.service
dynamic_ready=no
for _attempt in {1..40}; do
    if systemctl is-active --quiet blindpass-dynamic.service \
        && [[ "$(systemctl show --property=InvocationID --value blindpass-dynamic.service)" == "$dynamic_invocation" ]] \
        && journalctl -u blindpass-dynamic.service --no-pager -n 30 | grep -q 'WORKLOAD_READY'; then
        dynamic_ready=yes
        break
    fi
    sleep 0.2
done
[[ "$dynamic_ready" == yes ]] || {
    printf 'P01-FAIL DynamicUser workload was not authorized\n' >&2
    systemctl status blindpass-dynamic.service --no-pager -l >&2 || true
    journalctl -u blindpass-dynamic.service --no-pager -n 60 >&2 || true
    exit 1
}
printf 'P01-I02 DynamicUser workload identity and registration: PASS (uid=%s)\n' "$dynamic_uid"
systemctl stop blindpass-dynamic.service >/dev/null 2>&1 || true
systemctl reset-failed blindpass-dynamic.service >/dev/null 2>&1 || true
rm -f /etc/systemd/system/blindpass-dynamic.service
systemctl daemon-reload

systemctl reset-failed blindpass-workload.service >/dev/null 2>&1 || true
systemctl start --no-block blindpass-workload.service
invocation=
for _attempt in {1..30}; do
    invocation=$(systemctl show --property=InvocationID --value blindpass-workload.service)
    [[ -n "$invocation" ]] && break
    sleep 0.2
done
[[ -n "$invocation" ]] || {
    printf 'P01-FAIL fixed workload did not restart after DynamicUser profile\n' >&2
    exit 1
}
write_workload_registration
systemctl daemon-reload
systemctl reset-failed blindpass-broker.service >/dev/null 2>&1 || true
systemctl restart blindpass-broker.service
for _attempt in {1..40}; do
    if journalctl -u blindpass-workload.service --no-pager -n 30 | grep -q 'WORKLOAD_READY'; then
        break
    fi
    sleep 0.2
done
journalctl -u blindpass-workload.service --no-pager -n 30 | grep -q 'WORKLOAD_READY' || {
    printf 'P01-FAIL fixed workload did not recover after DynamicUser profile\n' >&2
    exit 1
}
printf 'P01-I02 fixed-account workload restored after DynamicUser profile: PASS\n'

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

tpm_probe_status=0
tpm_capability=$(systemd-analyze has-tpm2 2>&1) || tpm_probe_status=$?
tpm_capability_one_line=$(printf '%s' "$tpm_capability" | tr '\n' ' ' | tr -cs '[:alnum:]_.+-' '_')
if [[ "$tpm_capability" == *'Unknown command verb'* ]]; then
    printf 'P01-I06 TPM-CAPABILITY unsupported-command=%s\n' "$tpm_capability_one_line"
    tpm_probe_available=no
else
    printf 'P01-I06 TPM-CAPABILITY status=%s result=%s\n' "$tpm_probe_status" "$tpm_capability_one_line"
    tpm_probe_available=yes
fi
tpm_credential=/etc/blindpass/api-key.tpm2.cred
tpm_plaintext=/run/blindpass-consumer/api-key.tpm2
rm -f "$tpm_credential" "$tpm_plaintext"
if [[ "$tpm_probe_available" == yes && "$tpm_probe_status" == 0 ]]; then
    if systemd-creds --no-ask-password --with-key=tpm2 --name=api-key \
        encrypt /etc/blindpass/api-key "$tpm_credential" >/dev/null 2>&1 \
        && systemd-creds --no-ask-password --with-key=tpm2 \
            decrypt "$tpm_credential" "$tpm_plaintext" >/dev/null 2>&1 \
        && cmp -s /etc/blindpass/api-key "$tpm_plaintext"; then
        printf 'P01-I06 TPM-required custody profile: PASS\n'
    else
        printf 'P01-I06 TPM-required custody profile: NOT_CLAIMED (capability probe succeeded but encryption/recovery failed)\n'
    fi
elif [[ "$tpm_probe_available" == yes ]]; then
    if systemd-creds --no-ask-password --with-key=tpm2 --name=api-key \
        encrypt /etc/blindpass/api-key "$tpm_credential" >/dev/null 2>&1; then
        printf 'P01-FAIL TPM-required profile silently accepted without TPM\n' >&2
        exit 1
    fi
    printf 'P01-I06 TPM-required custody profile: UNSUPPORTED (TPM absent; no host-key fallback)\n'
else
    printf 'P01-I06 TPM-required custody profile: NOT_CLAIMED (systemd TPM capability probe unavailable)\n'
fi
rm -f "$tpm_credential" "$tpm_plaintext"

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

assert_canary_absent 'P01-INITIAL-CANARY'
printf 'P01-I06 initial canary absent from args/journals/runtime artifacts: PASS\n'

systemctl stop blindpass-backup.service blindpass-consumer.service
printf '%s' 'P01-ROTATED-CANARY' >/etc/blindpass/api-key
chmod 0600 /etc/blindpass/api-key
systemctl reset-failed blindpass-broker.service >/dev/null 2>&1 || true
systemctl restart blindpass-broker.service
systemctl start blindpass-consumer.service
printf 'P01-E01 controlled restart rotation: PASS\n'
systemctl reset-failed blindpass-backup.service >/dev/null 2>&1 || true
systemctl start blindpass-backup.service
backup_restore=$(/usr/libexec/blindpass-backup-probe \
    --credential-file /run/blindpass-backup/api-key \
    --artifact /run/blindpass-backup/artifact --mode restore)
[[ "$backup_restore" == BACKUP_RESTORED ]] || {
    printf 'P01-FAIL rotated disposable backup restore did not validate\n' >&2
    exit 1
}
printf 'P01-E01 rotated credential-consuming backup write/restore: PASS\n'
assert_canary_absent 'P01-ROTATED-CANARY'
printf 'P01-I06 rotated canary absent from args/journals/runtime artifacts: PASS\n'

systemctl stop blindpass-consumer.service blindpass-broker.service >/dev/null 2>&1 || true
cat >/etc/systemd/system/blindpass-broker.service.d/p01-api-removed.conf <<'UNIT'
[Service]
InaccessiblePaths=/run/dbus/system_bus_socket
UNIT
systemctl daemon-reload
systemctl reset-failed blindpass-broker.service >/dev/null 2>&1 || true
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
systemctl reset-failed blindpass-broker.service >/dev/null 2>&1 || true
systemctl restart blindpass-broker.service
systemctl reset-failed blindpass-consumer.service >/dev/null 2>&1 || true

printf 'P01-I05 HPKE restart/absent-key VM path: PASS (ephemeral custody probe)\n'
printf 'P01-RETAINED-PROTECTED-MATERIAL /etc/blindpass/api-key /etc/blindpass/api-key.cred\n'

systemctl stop blindpass-stall.service blindpass-loader-nonroot.service blindpass-loader-race.service blindpass-unregistered.service blindpass-unauthorized.service blindpass-dynamic.service blindpass-consumer.service blindpass-consumer-native.service blindpass-backup.service blindpass-workload.service blindpass-broker.service >/dev/null 2>&1 || true
if [[ "$user_manager_ready" == yes ]]; then
    rm -f /run/blindpass-user-manager.log "$user_manager_runtime/p01-user-manager.key"
    systemctl stop "user@$user_manager_uid.service" "user-runtime-dir@$user_manager_uid.service" >/dev/null 2>&1 || true
fi
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
rm -rf -- /run/blindpass-faults /run/blindpass-consumer /run/blindpass-backup /run/blindpass-loader-race /run/blindpass-custody-probe
rm -f /etc/systemd/system/blindpass-broker.service \
    /etc/systemd/system/blindpass-backup.service \
    /etc/systemd/system/blindpass-consumer.service \
    /etc/systemd/system/blindpass-consumer-native.service \
    /etc/systemd/system/blindpass-workload.service \
    /etc/systemd/system/blindpass-stall.service \
    /etc/systemd/system/blindpass-loader-nonroot.service \
    /etc/systemd/system/blindpass-loader-race.service \
    /etc/systemd/system/blindpass-dynamic.service \
    /etc/systemd/system/blindpass-unauthorized.service \
    /etc/systemd/system/blindpass-unregistered.service
rm -rf -- /etc/systemd/system/blindpass-broker.service.d
rm -rf -- /etc/systemd/system/blindpass-workload.service.d
rm -f /usr/libexec/blindpass-broker /usr/libexec/blindpass-consumer \
    /usr/libexec/blindpass-backup-probe \
    /usr/libexec/blindpass-custody-probe \
    /usr/libexec/blindpass-credential-loader /usr/libexec/blindpass-workload-client \
    /usr/libexec/blindpass-transport-probe
systemctl daemon-reload
[[ ! -e /etc/systemd/system/blindpass-broker.service && ! -e /run/blindpass/loader.sock ]] || {
    printf 'P01-FAIL broker installation remained after uninstall\n' >&2
    exit 1
}
printf 'P01-GUEST-CLEANUP sockets_removed=yes units_removed=yes protected_material_retained=yes\n'
