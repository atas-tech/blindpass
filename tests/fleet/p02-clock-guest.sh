#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -Eeuo pipefail

fail() {
    printf 'P02-I09-FAIL %s\n' "$1" >&2
    exit 1
}

unsupported() {
    printf 'P02-I09-UNSUPPORTED %s\n' "$1" >&2
    exit 78
}

[[ "$(id -u)" == 0 ]] || fail 'guest probe requires root'
[[ "$(ps -p 1 -o comm=)" == systemd ]] || unsupported 'guest PID 1 is not systemd'
[[ -x /tmp/blindpass-controller ]] || fail 'controller binary is missing'
for command in curl date awk systemctl; do
    command -v "$command" >/dev/null 2>&1 || unsupported "$command is unavailable"
done

started_wall=$(date +%s)
started_boottime=$(awk '{print $1}' /proc/uptime)
controller_pid=
workspace=/run/blindpass-p02-clock

controller_stop() {
    [[ -n "$controller_pid" ]] || return 0
    kill -TERM "$controller_pid" 2>/dev/null || true
    for _attempt in {1..50}; do
        kill -0 "$controller_pid" 2>/dev/null || break
        sleep 0.1
    done
    kill -KILL "$controller_pid" 2>/dev/null || true
    wait "$controller_pid" 2>/dev/null || true
    controller_pid=
}

restore_guest_clock() {
    local restore_wall
    restore_wall=$(awk -v wall="$started_wall" -v boot="$started_boottime" \
        'NR == 1 { printf "%.0f", wall + $1 - boot }' /proc/uptime)
    date --set="@$restore_wall" >/dev/null 2>&1 || true
}

cleanup() {
    controller_stop
    restore_guest_clock
    rm -rf "$workspace"
}
trap cleanup EXIT

# This image is disposable. Disable guest time sync so it cannot undo the
# deliberate test step while the controller is observing it.
timedatectl set-ntp false >/dev/null 2>&1 || true
systemctl stop systemd-timesyncd.service chrony.service >/dev/null 2>&1 || true
if ! apt-get update -qq >/tmp/p02-clock-apt.log 2>&1 \
    || ! DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl postgresql postgresql-client \
        >>/tmp/p02-clock-apt.log 2>&1; then
    unsupported 'could not install PostgreSQL and curl in the disposable guest'
fi
systemctl start postgresql.service >/dev/null 2>&1 || unsupported 'PostgreSQL did not start'

db_password=$(od -An -N18 -tx1 /dev/urandom | tr -d ' \n')
if ! printf "CREATE ROLE blindpass LOGIN PASSWORD '%s';\nCREATE DATABASE blindpass OWNER blindpass;\n" \
    "$db_password" | runuser -u postgres -- psql -v ON_ERROR_STOP=1 >/dev/null 2>&1; then
    fail 'could not create the disposable PostgreSQL fixture'
fi

umask 077
mkdir -p "$workspace" /etc/blindpass-p02
dd if=/dev/urandom of=/etc/blindpass-p02/root.secret bs=32 count=1 status=none
dd if=/dev/urandom of=/etc/blindpass-p02/agent.secret bs=32 count=1 status=none
chmod 0600 /etc/blindpass-p02/*.secret

export BLINDPASS_TEST_MODE=1
export BLINDPASS_LISTEN=127.0.0.1:38081
export BLINDPASS_PUBLIC_URL=http://127.0.0.1:38081
export BLINDPASS_UI_BASE_URL=http://127.0.0.1:38080
export BLINDPASS_ROOT_SECRET_FILE=/etc/blindpass-p02/root.secret
export BLINDPASS_AGENT_JWT_SECRET_FILE=/etc/blindpass-p02/agent.secret
export BLINDPASS_ADMIN_SOCKET_PATH="$workspace/admin.sock"
export BLINDPASS_CLOCK_TOLERANCE_MS=2000

wait_ready() {
    local expected=$1
    local status=000
    for _attempt in {1..40}; do
        status=$(curl --connect-timeout 1 --max-time 1 -sS -o /dev/null \
            -w '%{http_code}' http://127.0.0.1:38081/readyz 2>/dev/null || true)
        [[ "$status" == "$expected" ]] && return 0
        sleep 0.1
    done
    printf 'P02-I09-FAIL readiness expected=%s observed=%s\n' "$expected" "$status" >&2
    return 1
}

start_controller() {
    /tmp/blindpass-controller serve >"$workspace/controller.log" 2>&1 &
    controller_pid=$!
}

assert_fenced_restart_stays_unready() {
    start_controller
    wait_ready 503 || fail 'readiness accepted the persisted clock fence after restart'
    controller_stop
}

run_backend() {
    local backend=$1
    local original_wall target_wall database_url
    database_url=$2
    export BLINDPASS_DATABASE_URL="$database_url"
    /tmp/blindpass-controller migrate >"$workspace/migrate.log" 2>&1 \
        || fail "$backend migration failed"

    start_controller
    wait_ready 200 || fail "$backend did not become ready before the clock step"
    sleep 1.2
    original_wall=$(date +%s)
    target_wall=$((original_wall - 10))
    date --set="@$target_wall" >/dev/null || fail "$backend guest clock step failed"
    wait_ready 503 || fail "$backend running clock regression was not fenced"
    printf 'P02-I09-VM backend=%s running_backward_step=PASS tolerance_ms=2000\n' "$backend"

    controller_stop
    restore_guest_clock
    assert_fenced_restart_stays_unready
    printf 'P02-I09-VM backend=%s persisted_restart_readiness_fence=PASS\n' "$backend"

    /tmp/blindpass-controller reconcile-clock >"$workspace/reconcile.log" 2>&1 \
        || fail "$backend clock reconciliation failed"
    start_controller
    wait_ready 200 || fail "$backend readiness did not recover after reconciliation"

    target_wall=$(($(date +%s) + 10))
    date --set="@$target_wall" >/dev/null || fail "$backend forward clock step failed"
    wait_ready 200 || fail "$backend forward clock step fenced the controller"
    printf 'P02-I09-VM backend=%s forward_step_remains_ready=PASS\n' "$backend"
    controller_stop
    restore_guest_clock
    /tmp/blindpass-controller reconcile-clock >"$workspace/reconcile.log" 2>&1 \
        || fail "$backend cleanup reconciliation failed"
}

run_backend sqlite "sqlite://$workspace/sqlite.db?mode=rwc"
run_backend postgres "postgresql://blindpass:${db_password}@127.0.0.1:5432/blindpass"

printf 'P02-I09-VM-COMPLETE sqlite=PASS postgres=PASS guest_clock_restored=YES\n'
