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

assert_same_boot_rollback_refuses_start() {
    local original_wall target_wall process_state exit_status
    controller_stop
    # Let CLOCK_BOOTTIME advance longer than the backward wall-clock step.
    # The anchor is refreshed by the one-second monitor before shutdown.
    sleep 8
    original_wall=$(date +%s)
    target_wall=$((original_wall - 5))
    date --set="@$target_wall" >/dev/null || fail 'same-boot stopped clock step failed'
    start_controller

    for _attempt in {1..40}; do
        process_state=$(awk '{print $3}' "/proc/$controller_pid/stat" 2>/dev/null || true)
        [[ -z "$process_state" || "$process_state" == Z ]] && break
        sleep 0.1
    done
    process_state=$(awk '{print $3}' "/proc/$controller_pid/stat" 2>/dev/null || true)
    if [[ -n "$process_state" && "$process_state" != Z ]]; then
        controller_stop
        fail 'same-boot backward step did not refuse controller startup'
    fi
    set +e
    wait "$controller_pid"
    exit_status=$?
    set -e
    controller_pid=
    [[ "$exit_status" != 0 ]] || fail 'same-boot backward step exited successfully'
    printf 'P02-I09-VM backend=%s stopped_same_boot_backward_step=PASS rollback_seconds=5 downtime_seconds=8\n' "$backend"
    restore_guest_clock
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

    assert_same_boot_rollback_refuses_start
    /tmp/blindpass-controller reconcile-clock >"$workspace/reconcile.log" 2>&1 \
        || fail "$backend same-boot startup fence reconciliation failed"
    start_controller
    wait_ready 200 || fail "$backend readiness did not recover after same-boot reconciliation"
    controller_stop
    restore_guest_clock
    /tmp/blindpass-controller reconcile-clock >"$workspace/reconcile.log" 2>&1 \
        || fail "$backend cleanup reconciliation failed"
}

run_backend sqlite "sqlite://$workspace/sqlite.db?mode=rwc"
run_backend postgres "postgresql://blindpass:${db_password}@127.0.0.1:5432/blindpass"

reboot_id=$(tr -d '-' </proc/sys/kernel/random/boot_id)
request_id="p02-reboot-request-${reboot_id}"
exchange_id="p02-reboot-exchange-${reboot_id}"
approval_id="p02-reboot-approval-${reboot_id}"
operator_id="p02-reboot-operator-${reboot_id}"
session_id="p02-reboot-session-${reboot_id}"
window_id="p02-reboot-rate-window-${reboot_id}"
idem_key="p02-reboot-idempotency-${reboot_id}"
reboot_tenant=$(PGPASSWORD="$db_password" psql -h 127.0.0.1 -U blindpass -d blindpass \
    -X -qAt -v ON_ERROR_STOP=1 -c 'SELECT tenant_id FROM controller_meta WHERE id = 1')
created_at=$(date +%s%3N)
expires_at=$((created_at + 600000))
PGPASSWORD="$db_password" psql -h 127.0.0.1 -U blindpass -d blindpass \
    -X -q -v ON_ERROR_STOP=1 <<SQL
INSERT INTO secret_requests
    (id, tenant_id, requester_agent_id, public_key, description, confirmation_code, status, created_at, expires_at)
VALUES
    ('$request_id', '$reboot_tenant', 'reboot-fixture-agent', 'dummy-key', 'reboot purge fixture', 'dummy-code', 'pending', $created_at, $expires_at);
INSERT INTO exchanges
    (id, tenant_id, requester_agent_id, requester_public_key, secret_name, purpose, fulfiller_hint, policy_decision_json, policy_hash, status, created_at, expires_at)
VALUES
    ('$exchange_id', '$reboot_tenant', 'reboot-fixture-agent', 'dummy-key', 'reboot.secret', 'reboot purge fixture', 'fixture-fulfiller', '{"decision":"allow"}', 'dummy-policy-hash', 'pending', $created_at, $expires_at);
INSERT INTO approvals
    (reference, tenant_id, requester_agent_id, secret_name, purpose, fulfiller_hint, reason, approver_ids_json, approver_rings_json, status, created_at, expires_at)
VALUES
    ('$approval_id', '$reboot_tenant', 'reboot-fixture-agent', 'reboot.secret', 'reboot purge fixture', 'fixture-fulfiller', 'fixture', '[]', '[]', 'pending', $created_at, $expires_at);
INSERT INTO bootstrap_tokens (token_hash, expires_at) VALUES ('dummy-reboot-bootstrap-hash', $expires_at);
INSERT INTO rate_windows (key, window_start, count, expires_at) VALUES ('$window_id', $created_at, 1, $expires_at);
INSERT INTO idempotency_keys
    (tenant_id, actor_id, operation, key_hash, request_hash, response_json, created_at, expires_at)
VALUES
    ('$reboot_tenant', 'reboot-fixture-operator', 'fixture', '$idem_key', 'dummy-request-hash', '{}', $created_at, $expires_at);
INSERT INTO operators (id, username, display_name, password_hash, role, created_at)
VALUES ('$operator_id', 'p02-reboot-fixture', 'P02 reboot fixture', 'dummy-password-hash', 'admin', $created_at);
INSERT INTO operator_sessions
    (id, operator_id, refresh_hash, csrf_secret, kind, created_at, expires_at, family_id, last_seen_at)
VALUES
    ('$session_id', '$operator_id', 'dummy-reboot-refresh-hash', 'dummy-reboot-csrf', 'browser', $created_at, $expires_at, 'p02-reboot-session-family', $created_at);
SQL

reboot_state=/var/lib/blindpass-p02-clock-reboot
mkdir -p "$reboot_state"
chmod 0700 "$reboot_state"
install -m 0755 /tmp/blindpass-controller "$reboot_state/blindpass-controller"
printf '%s' "$db_password" >"$reboot_state/postgres-password"
chmod 0600 "$reboot_state/postgres-password"
cat >"$reboot_state/resume-after-reboot.sh" <<'RESUME'
#!/usr/bin/env bash
set -Eeuo pipefail

state=/var/lib/blindpass-p02-clock-reboot
password=$(<"$state/postgres-password")
boot_before=$(<"$state/boot-before")
request_id=$(<"$state/request-id")
exchange_id=$(<"$state/exchange-id")
approval_id=$(<"$state/approval-id")
operator_id=$(<"$state/operator-id")
session_id=$(<"$state/session-id")
window_id=$(<"$state/window-id")
idem_key=$(<"$state/idempotency-key")
boot_after=$(tr -d '-' </proc/sys/kernel/random/boot_id)
[[ "$boot_before" != "$boot_after" ]] || exit 1

export BLINDPASS_TEST_MODE=1
export BLINDPASS_LISTEN=127.0.0.1:38081
export BLINDPASS_PUBLIC_URL=http://127.0.0.1:38081
export BLINDPASS_UI_BASE_URL=http://127.0.0.1:38080
export BLINDPASS_DATABASE_URL="postgresql://blindpass:${password}@127.0.0.1:5432/blindpass"
export BLINDPASS_ROOT_SECRET_FILE=/etc/blindpass-p02/root.secret
export BLINDPASS_AGENT_JWT_SECRET_FILE=/etc/blindpass-p02/agent.secret
export BLINDPASS_ADMIN_SOCKET_PATH=/run/blindpass-p02-clock-reboot/admin.sock
export BLINDPASS_CLOCK_TOLERANCE_MS=2000
mkdir -p /run/blindpass-p02-clock-reboot

"$state/blindpass-controller" serve >"$state/controller.log" 2>&1 &
controller_pid=$!
cleanup_controller() {
    kill -TERM "$controller_pid" 2>/dev/null || true
    wait "$controller_pid" 2>/dev/null || true
}
trap cleanup_controller EXIT

status=000
for _attempt in {1..60}; do
    status=$(curl --connect-timeout 1 --max-time 1 -sS -o /dev/null \
        -w '%{http_code}' http://127.0.0.1:38081/readyz 2>/dev/null || true)
    [[ "$status" == 503 ]] && break
    [[ "$status" == 200 ]] && exit 1
    sleep 0.25
done
[[ "$status" == 503 ]] || exit 1

pg() {
    PGPASSWORD="$password" psql -h 127.0.0.1 -U blindpass -d blindpass \
        -X -qAt -v ON_ERROR_STOP=1 "$@"
}
for table in secret_requests exchanges approvals bootstrap_tokens rate_windows idempotency_keys; do
    count=$(pg -c "SELECT COUNT(*) FROM $table")
    [[ "$count" == 0 ]] || exit 1
done
session_count=$(pg -c "SELECT COUNT(*) FROM operator_sessions WHERE id = '$session_id' AND operator_id = '$operator_id' AND revoked_at IS NULL")
[[ "$session_count" == 1 ]] || exit 1
fence_events=$(pg -c "SELECT COUNT(*) FROM audit_events WHERE action = 'clock_restart_fence'")
[[ "$fence_events" == 1 ]] || exit 1
printf 'P02-I09-REBOOT-PASS boot_id_changed=yes transient_state_purged=yes operator_session_preserved=yes fence_events=1\n' >"$state/result"
chmod 0600 "$state/result"
RESUME
chmod 0700 "$reboot_state/resume-after-reboot.sh"
printf '%s\n' "$reboot_id" >"$reboot_state/boot-before"
printf '%s\n' "$request_id" >"$reboot_state/request-id"
printf '%s\n' "$exchange_id" >"$reboot_state/exchange-id"
printf '%s\n' "$approval_id" >"$reboot_state/approval-id"
printf '%s\n' "$operator_id" >"$reboot_state/operator-id"
printf '%s\n' "$session_id" >"$reboot_state/session-id"
printf '%s\n' "$window_id" >"$reboot_state/window-id"
printf '%s\n' "$idem_key" >"$reboot_state/idempotency-key"
chmod 0600 "$reboot_state"/{boot-before,request-id,exchange-id,approval-id,operator-id,session-id,window-id,idempotency-key}
cat >/etc/systemd/system/blindpass-p02-clock-reboot.service <<'UNIT'
[Unit]
Description=BlindPass P02 reboot clock-fence probe
After=network.target postgresql.service
Wants=postgresql.service

[Service]
Type=oneshot
ExecStart=/var/lib/blindpass-p02-clock-reboot/resume-after-reboot.sh
TimeoutStartSec=45

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable blindpass-p02-clock-reboot.service >/dev/null
printf 'P02-I09-VM guest_reboot_scheduled=yes transient_state=seeded operator_session=seeded\n'
sync
systemctl reboot

printf 'P02-I09-VM-COMPLETE sqlite=PASS postgres=PASS guest_clock_restored=YES\n'
