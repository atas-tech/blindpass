#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -Eeuo pipefail
umask 077

unsupported() {
    printf 'P03-UNSUPPORTED %s\n' "$1" >&2
    exit 78
}

[[ $(id -u) != 0 ]] || unsupported 'run the host harness as the runner owner, not through sudo'
for tool in cargo node npm python3 qemu-system-x86_64 qemu-img ssh scp ssh-keygen openssl curl sha256sum; do
    command -v "$tool" >/dev/null 2>&1 || unsupported "$tool is unavailable in the runner-owner PATH"
done
[[ -e /dev/kvm && -r /dev/kvm && -w /dev/kvm ]] || unsupported '/dev/kvm is unavailable or inaccessible'
[[ -n "${BLINDPASS_FLEET_RUNNER_OWNER:-}" ]] || unsupported 'BLINDPASS_FLEET_RUNNER_OWNER is unset'

backend_selection=both
while (($# > 0)); do
    case "$1" in
        --backend)
            (($# >= 2)) || { printf 'usage: %s [--backend sqlite|postgres|both]\n' "$0" >&2; exit 2; }
            backend_selection=$2
            shift 2
            ;;
        --help|-h)
            printf 'usage: %s [--backend sqlite|postgres|both]\n' "$0"
            exit 0
            ;;
        *)
            printf 'usage: %s [--backend sqlite|postgres|both]\n' "$0" >&2
            exit 2
            ;;
    esac
done
[[ "$backend_selection" =~ ^(sqlite|postgres|both)$ ]] || {
    printf 'backend must be sqlite, postgres or both\n' >&2
    exit 2
}

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
guest_user=${BLINDPASS_FLEET_GUEST_USER:-blindpass}
guest_image=${BLINDPASS_FLEET_GUEST_IMAGE:-"${XDG_DATA_HOME:-$HOME/.local/share}/blindpass/vm-images/noble-server-cloudimg-amd64.img"}
guest_image_sha=${BLINDPASS_FLEET_GUEST_IMAGE_SHA256:-612b2c0cc1bc413a6cb8c38fd611794caf0f2b436c50013d8b3794db12ad7354}
pg_parent_url=${P03_TEST_POSTGRES_URL:-postgres://blindpass:localdev@127.0.0.1:5433/blindpass}
ssh_port_a=${BLINDPASS_P03_SSH_PORT_A:-22222}
ssh_port_b=${BLINDPASS_P03_SSH_PORT_B:-22223}
declare -A guest_ports
guest_ports=([a]=$ssh_port_a [b]=$ssh_port_b)

[[ -r "$guest_image" ]] || unsupported 'pinned guest image is missing or unreadable'
[[ "$guest_image_sha" =~ ^[a-f0-9]{64}$ ]] || unsupported 'BLINDPASS_FLEET_GUEST_IMAGE_SHA256 is malformed'
actual_image_sha=$(sha256sum "$guest_image" | awk '{print $1}')
[[ "$actual_image_sha" == "$guest_image_sha" ]] || unsupported 'pinned guest image hash does not match'
[[ "$ssh_port_a" =~ ^[0-9]+$ && "$ssh_port_b" =~ ^[0-9]+$ ]] || {
    printf 'BLINDPASS_P03_SSH_PORT_A and BLINDPASS_P03_SSH_PORT_B must be integer ports\n' >&2
    exit 2
}
[[ "$ssh_port_a" != "$ssh_port_b" ]] || { printf 'P03 guest SSH ports must be distinct\n' >&2; exit 2; }

run_dir=$(mktemp -d "${TMPDIR:-/tmp}/blindpass-p03.XXXXXXXX")
chmod 0700 "$run_dir"
ssh_key=$run_dir/ephemeral-ssh-key
proxy_pid=
controller_pid=
postgres_state_file=
postgres_url_file=
cleanup_done=0
declare -a qemu_pidfiles=()

stop_pid() {
    local pid=${1:-}
    [[ "$pid" =~ ^[0-9]+$ ]] || return 0
    kill -TERM "$pid" 2>/dev/null || true
    for _attempt in {1..30}; do
        kill -0 "$pid" 2>/dev/null || return 0
        sleep 0.1
    done
    kill -KILL "$pid" 2>/dev/null || true
}

cleanup() {
    [[ "$cleanup_done" == 0 ]] || return
    cleanup_done=1
    stop_pid "$controller_pid"
    stop_pid "$proxy_pid"
    [[ -n "$controller_pid" ]] && wait "$controller_pid" 2>/dev/null || true
    [[ -n "$proxy_pid" ]] && wait "$proxy_pid" 2>/dev/null || true
    for pidfile in "${qemu_pidfiles[@]}"; do
        [[ -s "$pidfile" ]] || continue
        qemu_pid=$(<"$pidfile")
        stop_pid "$qemu_pid"
    done
    if [[ -n "$postgres_state_file" && -f "$postgres_state_file" \
        && -n "$postgres_url_file" && -f "$postgres_url_file" ]]; then
        P03_TEST_POSTGRES_URL="$pg_parent_url" node "$repo_root/tests/fleet/p03-postgres.mjs" \
            drop "$postgres_state_file" "$postgres_url_file" >/dev/null 2>&1 || true
    fi
    if [[ "${BLINDPASS_P03_KEEP_FAILED_ARTIFACTS:-0}" == 1 && "${run_status:-0}" != 0 ]]; then
        printf 'P03-FAILED-ARTIFACTS path=%s\n' "$run_dir" >&2
    else
        rm -rf -- "$run_dir"
    fi
}
trap 'run_status=$?; cleanup' EXIT
trap 'exit 143' INT TERM

ssh-keygen -q -t ed25519 -N '' -f "$ssh_key"
export BLINDPASS_FLEET_SSH_KEY="$ssh_key"
export BLINDPASS_FLEET_GUEST_IMAGE="$guest_image"
export BLINDPASS_FLEET_GUEST_IMAGE_SHA256="$guest_image_sha"
export BLINDPASS_FLEET_GUEST_USER="$guest_user"

printf 'P03-HOST-ENV runner_owner=%s qemu=%s kvm=%s image_sha256=%s\n' \
    "$BLINDPASS_FLEET_RUNNER_OWNER" \
    "$(qemu-system-x86_64 --version | head -n 1)" \
    "$(stat -c '%A:%a' /dev/kvm)" "$actual_image_sha"
cargo build --release -p blindpass-controller -p blindpass-broker -p blindpass-node --locked

openssl req -x509 -newkey rsa:2048 -nodes -days 2 -quiet \
    -keyout "$run_dir/controller.key" -out "$run_dir/controller.crt" \
    -subj '/CN=p03-controller' -addext 'subjectAltName=DNS:p03-controller'
chmod 0600 "$run_dir/controller.key"
chmod 0644 "$run_dir/controller.crt"

ssh_options=(-i "$ssh_key" -o BatchMode=yes -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null -o ConnectTimeout=3)
scp_options=(-i "$ssh_key" -o BatchMode=yes -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null -o ConnectTimeout=3)

guest_ssh() {
    local guest=$1
    shift
    ssh "${ssh_options[@]}" -p "${guest_ports[$guest]}" \
        "$guest_user@127.0.0.1" "$@"
}

guest_call() {
    local guest=$1
    shift
    guest_ssh "$guest" sudo /usr/local/sbin/blindpass-p03-guest "$@"
}

guest_scp() {
    local guest=$1
    shift
    scp "${scp_options[@]}" -P "${guest_ports[$guest]}" "$@" \
        "$guest_user@127.0.0.1:/tmp/p03/"
}

start_guest() {
    local guest=$1
    local backend=$2
    local image_dir=$run_dir/$backend/$guest/image
    mkdir -p "$image_dir"
    "$repo_root/tests/fleet/provision-guest.sh" --output-dir "$image_dir"
    local port=${guest_ports[$guest]}
    local pidfile=$run_dir/$backend/$guest/qemu.pid
    local serial_log=$run_dir/$backend/$guest/serial.log
    qemu-system-x86_64 \
        -name "blindpass-p03-$backend-$guest,debug-threads=on" \
        -enable-kvm -cpu host -m 1536 -smp 2 \
        -global PIIX4_PM.disable_s3=0 \
        -drive "file=$image_dir/guest-overlay.qcow2,if=virtio,format=qcow2" \
        -drive "file=$image_dir/seed.iso,if=virtio,media=cdrom,readonly=on,format=raw" \
        -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:$port-:22" \
        -device virtio-net-pci,netdev=net0 \
        -display none -monitor none -serial "file:$serial_log" \
        -pidfile "$pidfile" -daemonize
    qemu_pidfiles+=("$pidfile")
    local target="$guest_user@127.0.0.1"
    for _attempt in {1..90}; do
        if ssh "${ssh_options[@]}" -p "$port" "$target" true 2>/dev/null; then
            break
        fi
        sleep 2
    done
    ssh "${ssh_options[@]}" -p "$port" "$target" true >/dev/null 2>&1 || {
        printf 'P03-FAIL guest %s did not become reachable\n' "$guest" >&2
        return 1
    }
    ssh "${ssh_options[@]}" -p "$port" "$target" mkdir -m 0700 -p /tmp/p03
    guest_scp "$guest" \
        "$repo_root/target/release/blindpass-broker" \
        "$repo_root/target/release/blindpass-node" \
        "$repo_root/target/release/blindpass-workload-client" \
        "$repo_root/deploy/native/blindpass-broker.service" \
        "$repo_root/deploy/native/blindpass-node.service" \
        "$repo_root/deploy/native/blindpass-node.sysusers" \
        "$repo_root/deploy/native/blindpass-workload.sysusers" \
        "$repo_root/tests/fleet/p03-guest.sh" \
        "$run_dir/controller.crt"
    guest_ssh "$guest" sudo install -m 0755 /tmp/p03/p03-guest.sh /usr/local/sbin/blindpass-p03-guest
    guest_call "$guest" prepare https://p03-controller:8443
    printf 'P03-GUEST-READY backend=%s guest=%s ssh_port=%s\n' "$backend" "$guest" "$port"
}

start_proxy_process() {
    local log_file=$1
    shift
    stop_pid "$proxy_pid"
    [[ -n "$proxy_pid" ]] && wait "$proxy_pid" 2>/dev/null || true
    python3 "$repo_root/tests/fleet/p03-tls-proxy.py" \
        --certificate "$run_dir/controller.crt" \
        --private-key "$run_dir/controller.key" \
        "$@" >"$log_file" 2>&1 &
    proxy_pid=$!
    for _attempt in {1..30}; do
        kill -0 "$proxy_pid" 2>/dev/null || break
        if curl --silent --show-error --fail --max-time 1 \
            --resolve p03-controller:8443:127.0.0.1 \
            --cacert "$run_dir/controller.crt" \
            https://p03-controller:8443/readyz >/dev/null 2>&1; then
            printf 'P03-TLS-PROXY-READY\n'
            return 0
        fi
        sleep 0.1
    done
    printf 'P03-FAIL TLS proxy did not become ready\n' >&2
    return 1
}

start_proxy() {
    local marker=$1
    start_proxy_process "$(dirname "$marker")/tls-proxy.log" \
        --drop-first-events-response --drop-marker "$marker" --drop-hold-seconds 3
}

start_protocol_mismatch_proxy() {
    local marker=$1
    start_proxy_process "$(dirname "$marker")/tls-proxy-mismatch.log" \
        --force-protocol-mismatch --mismatch-marker "$marker"
}

start_delayed_grant_proxy() {
    local marker=$1
    local delay_seconds=${2:-4}
    start_proxy_process "$(dirname "$marker")/tls-proxy-grant-delay.log" \
        --delay-first-grant-response --grant-marker "$marker" \
        --grant-delay-seconds "$delay_seconds"
}

start_reconnect_storm_proxy() {
    local marker=$1
    local failures=${2:-3}
    start_proxy_process "$(dirname "$marker")/tls-proxy-reconnect-storm.log" \
        --fail-first-node-polls "$failures" --poll-failure-marker "$marker"
}

start_time_reply_replay_proxy() {
    local marker=$1
    start_proxy_process "$(dirname "$marker")/tls-proxy-time-replay.log" \
        --replay-time-reply-on-reconnect --time-reply-marker "$marker"
}

start_clear_proxy() {
    local log_file=$1
    start_proxy_process "$log_file"
}

stop_proxy() {
    stop_pid "$proxy_pid"
    [[ -n "$proxy_pid" ]] && wait "$proxy_pid" 2>/dev/null || true
    proxy_pid=
}

admin() {
    env \
        "P03_CONTROLLER_URL=http://127.0.0.1:3200" \
        "P03_UI_ORIGIN=http://127.0.0.1:5175" \
        "P03_ADMIN_SEED_FILE=$admin_seed_file" \
        node "$repo_root/tests/fleet/p03-admin.mjs" "$@"
}

grant_acknowledged() {
    local node_id=$1 grant_id=$2
    if [[ "$current_backend" == sqlite ]]; then
        python3 - "$backend_dir/controller.sqlite" "$node_id" "$grant_id" <<'PY'
import json
import sqlite3
import sys

database, node_id, grant_id = sys.argv[1:]
connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
try:
    rows = connection.execute(
        "SELECT envelope_json FROM node_inbox WHERE node_id = ? AND acked_at IS NOT NULL",
        (node_id,),
    )
    acknowledged = any(
        (lambda envelope: envelope.get("kind") == "grant"
         and envelope.get("body", {}).get("id") == grant_id)(json.loads(row[0]))
        for row in rows
    )
    print(str(acknowledged).lower())
finally:
    connection.close()
PY
    else
        node "$repo_root/tests/fleet/p03-postgres.mjs" grant-acknowledged \
            "$database_url_file" "$node_id" "$grant_id"
    fi
}

wait_for_grant_acknowledgement() {
    local node_id=$1 grant_id=$2
    for _attempt in {1..60}; do
        [[ $(grant_acknowledged "$node_id" "$grant_id") == true ]] && return 0
        sleep 0.1
    done
    printf 'P03-FAIL broker did not acknowledge grant application before its lifetime elapsed\n' >&2
    return 1
}

json_field() {
    node -e 'const value = JSON.parse(process.argv[1]); console.log(value[process.argv[2]] ?? "");' "$1" "$2"
}

create_enrollment() {
    local guest=$1
    local name=$2
    local token_file=$run_dir/$current_backend/enrollment-$guest.token
    local enrollment
    enrollment=$(admin create-enrollment "$name" "$token_file")
    enrollment_id=$(json_field "$enrollment" id)
    node_id=$(json_field "$enrollment" node_id)
    [[ "$enrollment_id" =~ ^en_[A-Za-z0-9_-]+$ && "$node_id" =~ ^nd_[A-Za-z0-9_-]+$ ]] || {
        printf 'P03-FAIL controller returned malformed enrollment identifiers\n' >&2
        return 1
    }
    guest_ssh "$guest" sudo /usr/local/sbin/blindpass-p03-guest enroll \
        https://p03-controller:8443 "$issuer_fingerprint" <"$token_file" >&2
    rm -f -- "$token_file"
    admin approve-enrollment "$enrollment_id" >/dev/null
    printf '%s\n' "$node_id"
}

setup_workload() {
    local guest=$1
    local node_id=$2
    local label=$3
    local payload=$4
    local workload_json
    local account
    account=$(guest_call "$guest" workload-account)
    [[ "$account" =~ ^uid:[0-9]+$ ]] || {
        printf 'P03-FAIL guest returned a malformed workload account binding\n' >&2
        return 1
    }
    workload_json=$(admin create-workload "$node_id" "$label" "$account")
    local workload_id
    workload_id=$(json_field "$workload_json" id)
    [[ "$workload_id" =~ ^wl_[A-Za-z0-9_-]+$ ]] || {
        printf 'P03-FAIL controller returned a malformed workload identifier\n' >&2
        return 1
    }
    guest_call "$guest" configure-workload "$node_id" "$workload_id" "$payload" >&2
    printf '%s\n' "$workload_id"
}

issue_operation() {
    local workload_id=$1
    local resource_id=$2
    local request_record=$3
    local purpose=$4
    local ttl_seconds=${5:-60}
    local event_key invocation_id
    event_key=$(sed -n 's/.*event_key=\([A-Za-z0-9_-]*\).*/\1/p' <<<"$request_record")
    invocation_id=$(sed -n 's/.*invocation=\([a-f0-9]*\).*/\1/p' <<<"$request_record")
    [[ "$event_key" =~ ^[A-Za-z0-9_-]{16,128}$ && "$invocation_id" =~ ^[a-f0-9]{32}$ ]] || {
        printf 'P03-FAIL guest returned malformed invocation evidence\n' >&2
        return 1
    }
    local operation_json
    operation_json=$(admin operation "$workload_id" "$event_key" "$invocation_id" "$resource_id" "$purpose" "$ttl_seconds")
    ISSUED_INVOCATION_ID=$invocation_id
    ISSUED_OPERATION_ID=$(json_field "$operation_json" operation_id)
    ISSUED_GRANT_ID=$(json_field "$operation_json" grant_id)
    [[ "$ISSUED_OPERATION_ID" =~ ^op_[A-Za-z0-9_-]+$ && "$ISSUED_GRANT_ID" =~ ^gr_[A-Za-z0-9_-]+$ ]] || {
        printf 'P03-FAIL controller returned malformed operation identifiers\n' >&2
        return 1
    }
}

complete_operation() {
    local guest=$1
    local node_id=$2
    local workload_id=$3
    local resource_id=$4
    local request_record=$5
    local purpose=$6
    issue_operation "$workload_id" "$resource_id" "$request_record" "$purpose"
    guest_call "$guest" restart-node
    local operation_id=$ISSUED_OPERATION_ID
    local grant_id=$ISSUED_GRANT_ID
    printf '%s\n' "$grant_id" | guest_call "$guest" provide-grant
    guest_call "$guest" verify-workload "$grant_id" "$operation_id"
    guest_call "$guest" wait-outbox-empty
    local status_json status
    status_json=$(admin operation-status "$operation_id")
    status=$(json_field "$status_json" status)
    [[ "$status" == completed ]] || {
        printf 'P03-FAIL operation %s ended in %s\n' "$operation_id" "$status" >&2
        return 1
    }
    admin audit-check "$node_id" "$operation_id" "$workload_id" \
        "$ISSUED_INVOCATION_ID" "$grant_id"
    COMPLETED_OPERATION_ID=$operation_id
    COMPLETED_GRANT_ID=$grant_id
}

run_backend() {
    current_backend=$1
    local backend_dir=$run_dir/$current_backend
    mkdir -m 0700 -p "$backend_dir"
    local database_url_file=$backend_dir/database.url
    local postgres_state=$backend_dir/postgres.state
    if [[ "$current_backend" == sqlite ]]; then
        printf 'sqlite:%s/controller.sqlite?mode=rwc\n' "$backend_dir" >"$database_url_file"
        chmod 0600 "$database_url_file"
    else
        postgres_state_file=$postgres_state
        postgres_url_file=$database_url_file
        P03_TEST_POSTGRES_URL="$pg_parent_url" node "$repo_root/tests/fleet/p03-postgres.mjs" \
            create "$postgres_state" "$database_url_file"
    fi

    local root_secret=$backend_dir/root.secret
    local agent_secret=$backend_dir/agent.secret
    local issuer_secret=$backend_dir/issuer.secret
    dd if=/dev/urandom of="$root_secret" bs=32 count=1 status=none
    dd if=/dev/urandom of="$agent_secret" bs=32 count=1 status=none
    dd if=/dev/urandom of="$issuer_secret" bs=32 count=1 status=none
    chmod 0600 "$root_secret" "$agent_secret" "$issuer_secret"
    local admin_socket=$backend_dir/admin.sock
    local -a controller_env=(
        BLINDPASS_TEST_MODE=1
        BLINDPASS_LISTEN=127.0.0.1:3200
        BLINDPASS_PUBLIC_URL=https://p03-controller:8443
        BLINDPASS_UI_BASE_URL=http://127.0.0.1:5175
        BLINDPASS_DATABASE_URL_FILE="$database_url_file"
        BLINDPASS_ROOT_SECRET_FILE="$root_secret"
        BLINDPASS_AGENT_JWT_SECRET_FILE="$agent_secret"
        BLINDPASS_ISSUER_KEY_FILE="$issuer_secret"
        BLINDPASS_ADMIN_SOCKET_PATH="$admin_socket"
    )
    env "${controller_env[@]}" "$repo_root/target/release/blindpass-controller" migrate
    printf '{"agents":["p03-synthetic-fixture"],"local_admin":true}\n' >"$backend_dir/seed.fixture.json"
    env "${controller_env[@]}" "$repo_root/target/release/blindpass-controller" \
        seed --fixture "$backend_dir/seed.fixture.json" >"$backend_dir/admin-seed.json"
    chmod 0600 "$backend_dir/admin-seed.json" "$backend_dir/seed.fixture.json"
    admin_seed_file=$backend_dir/admin-seed.json

    env "${controller_env[@]}" "$repo_root/target/release/blindpass-controller" serve \
        >"$backend_dir/controller.log" 2>&1 &
    controller_pid=$!
    local ready=0
    for _attempt in {1..100}; do
        if curl --silent --show-error --fail --max-time 1 \
            http://127.0.0.1:3200/readyz >/dev/null 2>&1; then
            ready=1
            break
        fi
        kill -0 "$controller_pid" 2>/dev/null || break
        sleep 0.2
    done
    [[ "$ready" == 1 ]] || {
        printf 'P03-FAIL controller did not become ready for %s\n' "$current_backend" >&2
        return 1
    }
    issuer_fingerprint=$(admin issuer-fingerprint | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>process.stdout.write(JSON.parse(s)));')
    [[ "$issuer_fingerprint" =~ ^[a-f0-9]{64}$ ]] || {
        printf 'P03-FAIL controller returned a malformed issuer fingerprint\n' >&2
        return 1
    }
    admin policy >/dev/null

    start_guest a "$current_backend"
    start_guest b "$current_backend"
    local drop_marker=$backend_dir/first-events-response-dropped
    start_proxy "$drop_marker"

    local request_json payload_a payload_b node_a node_b workload_a workload_b request_record
    node_a=$(create_enrollment a "p03-$current_backend-node-a")
    workload_a=
    payload_a=$(node -e 'process.stdout.write(Buffer.from(JSON.stringify({action:"noop.marker",mode:"file",purpose:"P03 partition replay",resource_id:"P03-CANARY-A",ttl_seconds:60})).toString("base64url"))')
    workload_a=$(setup_workload a "$node_a" "$current_backend-a" "$payload_a")
    guest_call a start-node
    sleep 2

    stop_proxy
    guest_call a start-workload
    request_record=$(guest_call a wait-request)
    local event_key
    event_key=$(sed -n 's/.*event_key=\([A-Za-z0-9_-]*\).*/\1/p' <<<"$request_record")
    [[ "$event_key" =~ ^[A-Za-z0-9_-]{16,128}$ ]] || {
        printf 'P03-FAIL partitioned workload request did not produce a broker event key\n' >&2
        return 1
    }
    guest_call a restart-channel
    guest_call a assert-broker-event "$event_key"
    start_proxy "$drop_marker"
    for _attempt in {1..800}; do
        [[ -f "$drop_marker" ]] && break
        kill -0 "$proxy_pid" 2>/dev/null || break
        sleep 0.1
    done
    [[ -f "$drop_marker" ]] || {
        printf 'P03-FAIL TLS proxy did not record the simulated lost application response\n' >&2
        return 1
    }
    guest_call a assert-node-outbox-nonempty
    guest_call a restart-node
    guest_call a wait-outbox-empty
    guest_call a stop-workload
    guest_call a start-workload
    request_record=$(guest_call a wait-request)
    complete_operation a "$node_a" "$workload_a" P03-CANARY-A "$request_record" 'P03 partition replay'
    printf 'P03-SCENARIO backend=%s scenario=P03-I06-partition-restart-replay status=passed\n' "$current_backend"

    local mismatch_marker=$backend_dir/protocol-mismatch-seen
    guest_call a stop-node
    start_protocol_mismatch_proxy "$mismatch_marker"
    guest_call a start-node-async
    guest_call a assert-node-protocol-mismatch
    [[ -s "$mismatch_marker" ]] || {
        printf 'P03-FAIL TLS proxy did not serve the incompatible-protocol response\n' >&2
        return 1
    }
    start_clear_proxy "$backend_dir/tls-proxy-recovery.log"
    guest_call a restart-channel
    local channel_recovered=false mismatch_node_status mismatch_last_seen
    for _attempt in {1..60}; do
        mismatch_node_status=$(admin node-status "$node_a")
        mismatch_last_seen=$(json_field "$mismatch_node_status" last_seen_at)
        if [[ "$mismatch_last_seen" =~ ^[0-9]+$ ]] \
            && (( $(node -e 'process.stdout.write(String(Date.now()))') - mismatch_last_seen < 5000 )); then
            channel_recovered=true
            break
        fi
        sleep 0.2
    done
    [[ "$channel_recovered" == true ]] || {
        printf 'P03-FAIL node did not recover after the controller protocol mismatch was cleared\n' >&2
        return 1
    }
    guest_call a assert-node-channel-active
    printf 'P03-SCENARIO backend=%s scenario=P03-I06-protocol-mismatch incompatible_exit=78 restart_loop=false recovery=passed status=passed\n' \
        "$current_backend"

    local reconnect_failure_marker=$backend_dir/transient-poll-failures
    guest_call a stop-node
    start_reconnect_storm_proxy "$reconnect_failure_marker" 3
    guest_call a start-node
    local reconnect_failure_count=0
    for _attempt in {1..300}; do
        if [[ -f "$reconnect_failure_marker" ]]; then
            reconnect_failure_count=$(wc -l <"$reconnect_failure_marker")
            ((reconnect_failure_count >= 3)) && break
        fi
        kill -0 "$proxy_pid" 2>/dev/null || break
        sleep 0.1
    done
    [[ "$reconnect_failure_count" == 3 ]] || {
        printf 'P03-FAIL TLS proxy did not inject three transient node-poll failures\n' >&2
        return 1
    }
    local reconnect_backoff_ms
    reconnect_backoff_ms=$(python3 - "$reconnect_failure_marker" <<'PY'
import sys
from pathlib import Path

rows = [line.split() for line in Path(sys.argv[1]).read_text().splitlines()]
if [row[0] for row in rows] != ["1", "2", "3"]:
    raise SystemExit("transient poll failure sequence is malformed")
times = [int(row[1]) for row in rows]
delays = [right - left for left, right in zip(times, times[1:])]
if not (700 <= delays[0] <= 2_000 and 1_400 <= delays[1] <= 3_500):
    raise SystemExit(f"node retry backoff fell outside bounded windows: {delays}")
print(f"{delays[0]},{delays[1]}")
PY
    ) || {
        printf 'P03-FAIL transient node retry intervals were not exponential and bounded\n' >&2
        return 1
    }
    local channel_recovered=false reconnect_node_status reconnect_last_poll
    for _attempt in {1..100}; do
        reconnect_node_status=$(admin node-status "$node_a")
        reconnect_last_poll=$(json_field "$reconnect_node_status" last_poll_at)
        if [[ "$reconnect_last_poll" =~ ^[0-9]+$ ]] \
            && (( $(node -e 'process.stdout.write(String(Date.now()))') - reconnect_last_poll < 5000 )); then
            channel_recovered=true
            break
        fi
        sleep 0.2
    done
    [[ "$channel_recovered" == true ]] || {
        printf 'P03-FAIL node did not poll successfully after transient reconnect failures\n' >&2
        return 1
    }
    guest_call a assert-node-channel-stable
    [[ $(wc -l <"$reconnect_failure_marker") == 3 ]] || {
        printf 'P03-FAIL transient poll fault count changed after recovery\n' >&2
        return 1
    }
    printf 'P03-SCENARIO backend=%s scenario=P03-I06-reconnect-storm failures=3 backoff_ms=%s service_restarts=0 recovery=passed status=passed\n' \
        "$current_backend" "$reconnect_backoff_ms"

    local time_reply_replay_marker=$backend_dir/time-reply-replay
    guest_call a stop-node
    start_time_reply_replay_proxy "$time_reply_replay_marker"
    guest_call a start-node
    local time_reply_captured=false
    for _attempt in {1..150}; do
        if grep -Fq 'captured ' "$time_reply_replay_marker" 2>/dev/null; then
            time_reply_captured=true
            break
        fi
        kill -0 "$proxy_pid" 2>/dev/null || break
        sleep 0.2
    done
    [[ "$time_reply_captured" == true ]] || {
        printf 'P03-FAIL TLS proxy did not capture a signed broker-time reply\n' >&2
        return 1
    }
    guest_call a restart-channel
    local time_reply_replayed=false
    for _attempt in {1..150}; do
        if grep -Fq 'replayed ' "$time_reply_replay_marker" 2>/dev/null; then
            time_reply_replayed=true
            break
        fi
        kill -0 "$proxy_pid" 2>/dev/null || break
        sleep 0.2
    done
    [[ "$time_reply_replayed" == true && $(wc -l <"$time_reply_replay_marker") == 2 ]] || {
        printf 'P03-FAIL TLS proxy did not replay exactly one captured signed time reply after broker restart\n' >&2
        return 1
    }
    local replay_timestamp replay_node_status replay_last_poll time_reply_recovered=false
    replay_timestamp=$(awk '$1 == "replayed" {print $2}' "$time_reply_replay_marker")
    [[ "$replay_timestamp" =~ ^[0-9]+$ ]] || {
        printf 'P03-FAIL time-reply replay marker timestamp is malformed\n' >&2
        return 1
    }
    guest_call a assert-time-reply-replay-rejected
    for _attempt in {1..100}; do
        replay_node_status=$(admin node-status "$node_a")
        replay_last_poll=$(json_field "$replay_node_status" last_poll_at)
        if [[ "$replay_last_poll" =~ ^[0-9]+$ ]] \
            && (( replay_last_poll > replay_timestamp )) \
            && (( $(node -e 'process.stdout.write(String(Date.now()))') - replay_last_poll < 5000 )); then
            time_reply_recovered=true
            break
        fi
        sleep 0.2
    done
    [[ "$time_reply_recovered" == true ]] || {
        printf 'P03-FAIL node did not recover with fresh signed controller time after replay rejection\n' >&2
        return 1
    }
    guest_call a assert-node-channel-stable
    printf 'P03-SCENARIO backend=%s scenario=P03-I06-time-challenge-replay broker_restart=true rejected=true fresh_time_recovered=true node_restarts=0 status=passed\n' \
        "$current_backend"
    start_clear_proxy "$backend_dir/tls-proxy-after-time-replay.log"

    local rotation_metadata rotation_result rotation_pending rotation_version
    rotation_metadata=$(guest_call a rotate-prepare)
    rotation_result=$(admin rotate-node-key "$node_a" "$rotation_metadata")
    rotation_pending=$(json_field "$rotation_result" rotation_pending)
    [[ "$rotation_pending" == true ]] || {
        printf 'P03-FAIL controller did not stage the broker-prepared key rotation\n' >&2
        return 1
    }
    local rotation_complete=false rotation_status
    for _attempt in {1..240}; do
        rotation_status=$(admin node-status "$node_a")
        rotation_pending=$(json_field "$rotation_status" rotation_pending)
        rotation_version=$(json_field "$rotation_status" key_version)
        if [[ "$rotation_pending" == false && "$rotation_version" == 2 ]]; then
            rotation_complete=true
            break
        fi
        sleep 0.5
    done
    [[ "$rotation_complete" == true ]] || {
        printf 'P03-FAIL broker did not apply and acknowledge node key rotation\n' >&2
        return 1
    }
    printf 'P03-SCENARIO backend=%s scenario=P03-I01-in-place-key-rotation key_version=%s status=passed\n' \
        "$current_backend" "$rotation_version"

    local suspend_payload suspend_workload suspend_request suspend_operation suspend_grant
    suspend_payload=$(node -e 'process.stdout.write(Buffer.from(JSON.stringify({action:"noop.marker",mode:"file",purpose:"P03 suspend-aware grant expiry",resource_id:"P03-CANARY-SUSPENDED",ttl_seconds:20})).toString("base64url"))')
    suspend_workload=$(setup_workload a "$node_a" "$current_backend-a-suspend" "$suspend_payload")
    guest_call a start-workload
    suspend_request=$(guest_call a wait-request)
    issue_operation "$suspend_workload" P03-CANARY-SUSPENDED "$suspend_request" \
        'P03 suspend-aware grant expiry' 20
    suspend_operation=$ISSUED_OPERATION_ID
    suspend_grant=$ISSUED_GRANT_ID
    wait_for_grant_acknowledgement "$node_a" "$suspend_grant"
    local suspend_grant_json suspend_expires_at suspend_now suspend_remaining_ms
    suspend_grant_json=$(admin grant-status "$suspend_grant")
    suspend_expires_at=$(json_field "$suspend_grant_json" expires_at)
    suspend_now=$(node -e 'process.stdout.write(String(Date.now()))')
    [[ "$suspend_expires_at" =~ ^[0-9]+$ ]] || {
        printf 'P03-FAIL controller returned a malformed suspend-test grant expiry\n' >&2
        return 1
    }
    suspend_remaining_ms=$((suspend_expires_at - suspend_now))
    ((suspend_remaining_ms > 5000)) || {
        printf 'P03-FAIL suspend-test grant was not live at broker acknowledgement (%s ms remained)\n' \
            "$suspend_remaining_ms" >&2
        return 1
    }
    local suspend_seconds=25 suspend_output clock_restore_epoch
    suspend_output=$(guest_call a suspend-resume "$suspend_seconds")
    [[ "$suspend_output" =~ P03-GUEST-SUSPEND-RESUME\ boottime_elapsed_ms=([0-9]+) ]] || {
        printf 'P03-FAIL guest did not report a completed suspend/resume interval\n' >&2
        return 1
    }
    printf '%s\n' "$suspend_output"
    guest_call a roll-clock-back 7200
    printf '%s\n' "$suspend_grant" | guest_call a provide-grant
    guest_call a assert-expired-workload "$suspend_grant"
    clock_restore_epoch=$(node -e 'process.stdout.write(String(Math.floor(Date.now()/1000)))')
    guest_call a restore-clock "$clock_restore_epoch"
    printf 'P03-SCENARIO backend=%s scenario=P03-I06-suspend-clock-rollback ttl_seconds=20 suspend_seconds=%s grant_live_before_suspend_ms=%s operation_id=%s grant_denied=true marker_created=false status=passed\n' \
        "$current_backend" "$suspend_seconds" "$suspend_remaining_ms" "$suspend_operation"

    node_b=$(create_enrollment b "p03-$current_backend-node-b")
    payload_b=$(node -e 'process.stdout.write(Buffer.from(JSON.stringify({action:"noop.marker",mode:"file",purpose:"P03 second host",resource_id:"P03-CANARY-B",ttl_seconds:60})).toString("base64url"))')
    workload_b=$(setup_workload b "$node_b" "$current_backend-b" "$payload_b")
    guest_call b start-node
    sleep 2
    guest_call b start-workload
    request_record=$(guest_call b wait-request)
    complete_operation b "$node_b" "$workload_b" P03-CANARY-B "$request_record" 'P03 second host'

    local pending_payload pending_workload pending_request pending_operation pending_grant delayed_grant_marker
    pending_payload=$(node -e 'process.stdout.write(Buffer.from(JSON.stringify({action:"noop.marker",mode:"file",purpose:"P03 revoked undelivered grant",resource_id:"P03-CANARY-REVOKED",ttl_seconds:8})).toString("base64url"))')
    pending_workload=$(setup_workload a "$node_a" "$current_backend-a-revoked" "$pending_payload")
    sleep 2
    guest_call a start-workload
    pending_request=$(guest_call a wait-request)
    delayed_grant_marker=$backend_dir/expired-grant-response-held
    # Leave time for grant issuance and revocation to reach the controller
    # while the grant is live, then hold the node response past its deadline.
    start_delayed_grant_proxy "$delayed_grant_marker" 10
    issue_operation "$pending_workload" P03-CANARY-REVOKED "$pending_request" 'P03 revoked undelivered grant' 8
    pending_operation=$ISSUED_OPERATION_ID
    pending_grant=$ISSUED_GRANT_ID
    for _attempt in {1..300}; do
        [[ -f "$delayed_grant_marker" ]] && break
        kill -0 "$proxy_pid" 2>/dev/null || break
        sleep 0.1
    done
    [[ -f "$delayed_grant_marker" ]] || {
        printf 'P03-FAIL TLS proxy did not hold the delayed grant response\n' >&2
        return 1
    }
    printf 'P03-SCENARIO backend=%s scenario=P03-I06-delayed-expired-grant response_delay_seconds=10 ttl_seconds=8 status=observed\n' \
        "$current_backend"
    printf 'P03-PENDING-OPERATION operation_id=%s grant_id=%s\n' "$pending_operation" "$pending_grant"

    local revocation_started_ms revocation_finished_ms revocation_elapsed_ms
    revocation_started_ms=$(node -e 'process.stdout.write(String(Date.now()))')
    admin revoke-node "$node_a" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{const v=JSON.parse(s);if(v.status!=="revoked"||v.revocation_pending!==true)process.exit(1);});'
    local pending=true node_status_json
    for _attempt in {1..240}; do
        node_status_json=$(admin node-status "$node_a")
        pending=$(json_field "$node_status_json" revocation_pending)
        [[ "$pending" == false ]] && break
        sleep 0.5
    done
    [[ "$pending" == false ]] || {
        printf 'P03-FAIL node %s did not apply and acknowledge revocation\n' "$node_a" >&2
        return 1
    }
    guest_call a wait-outbox-empty
    admin grant-rejection-check "$node_a" "$pending_grant"
    revocation_finished_ms=$(node -e 'process.stdout.write(String(Date.now()))')
    revocation_elapsed_ms=$((revocation_finished_ms - revocation_started_ms))
    ((revocation_elapsed_ms <= 30000)) || {
        printf 'P03-FAIL connected node revocation exceeded 30 seconds (%s ms)\n' "$revocation_elapsed_ms" >&2
        return 1
    }
    local revoked_operation
    revoked_operation=$(admin operation-status "$pending_operation")
    [[ $(json_field "$revoked_operation" status) == revoked ]] || {
        printf 'P03-FAIL undelivered operation %s was not revoked with its node\n' "$pending_operation" >&2
        return 1
    }
    guest_call a verify-revoked-grant "$pending_grant"
    guest_call a stop-workload
    guest_call a restart-channel
    guest_call a start-workload
    guest_call a assert-revoked-workload "$pending_grant"
    printf 'P03-SCENARIO backend=%s scenario=P03-E01-two-host-authorization revocation_ms=%s status=passed\n' \
        "$current_backend" "$revocation_elapsed_ms"

    guest_call a archive-revoked-identity "$node_a"
    local recovered_node
    recovered_node=$(create_enrollment a "p03-$current_backend-node-a-recovered")
    [[ "$recovered_node" != "$node_a" ]] || {
        printf 'P03-FAIL recovery reused the revoked node identity\n' >&2
        return 1
    }
    local recovered_payload recovered_workload recovered_request
    recovered_payload=$(node -e 'process.stdout.write(Buffer.from(JSON.stringify({action:"noop.marker",mode:"file",purpose:"P03 recovered identity",resource_id:"P03-CANARY-RECOVERED",ttl_seconds:60})).toString("base64url"))')
    recovered_workload=$(setup_workload a "$recovered_node" "$current_backend-a-recovered" "$recovered_payload")
    guest_call a start-node
    sleep 2
    guest_call a start-workload
    recovered_request=$(guest_call a wait-request)
    complete_operation a "$recovered_node" "$recovered_workload" P03-CANARY-RECOVERED \
        "$recovered_request" 'P03 recovered identity'
    printf 'P03-SCENARIO backend=%s scenario=P03-E02-revoked-node-recovery status=passed\n' "$current_backend"

    stop_proxy
    stop_pid "$controller_pid"
    wait "$controller_pid" 2>/dev/null || true
    controller_pid=
    for pidfile in "${qemu_pidfiles[@]}"; do
        [[ "$pidfile" == "$backend_dir/"* ]] || continue
        qemu_pid=$(<"$pidfile")
        stop_pid "$qemu_pid"
    done
    qemu_pidfiles=()
    if [[ "$current_backend" == postgres ]]; then
        P03_TEST_POSTGRES_URL="$pg_parent_url" node "$repo_root/tests/fleet/p03-postgres.mjs" \
            drop "$postgres_state" "$database_url_file"
        postgres_state_file=
        postgres_url_file=
    fi
    printf 'P03-BACKEND-COMPLETE backend=%s\n' "$current_backend"
}

case "$backend_selection" in
    sqlite) run_backend sqlite ;;
    postgres) run_backend postgres ;;
    both)
        run_backend sqlite
        run_backend postgres
        ;;
esac
printf 'P03-VM-COMPLETE runner_owner=%s backends=%s guests=2 revocation=reconciled recovery=passed\n' \
    "$BLINDPASS_FLEET_RUNNER_OWNER" "$backend_selection"
