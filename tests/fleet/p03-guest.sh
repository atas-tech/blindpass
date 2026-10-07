#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -Eeuo pipefail

unit=blindpass-p03-workload.service
workload_group=blindpass-workload

fail() {
    printf 'P03-GUEST-FAIL %s\n' "$1" >&2
    exit 1
}

valid_id() {
    [[ "$1" =~ ^[A-Za-z0-9_-]{1,128}$ ]]
}

operation_marker_count() {
    local marker_directory=/run/blindpass/ops
    if [[ ! -e "$marker_directory" && ! -L "$marker_directory" ]]; then
        printf '0\n'
        return 0
    fi
    [[ -d "$marker_directory" && ! -L "$marker_directory" ]] || return 1
    find "$marker_directory" -maxdepth 1 -type f -name '*.marker' 2>/dev/null | wc -l
}

invocation_log() {
    local expected_invocation=$1
    journalctl -u "$unit" -o json --no-pager 2>/dev/null | python3 -c '
import json
import sys

expected = sys.argv[1]
rows = []
for line in sys.stdin:
    try:
        rows.append(json.loads(line))
    except ValueError:
        continue
start = next((index for index, row in enumerate(rows)
              if row.get("INVOCATION_ID") == expected
              or row.get("_SYSTEMD_INVOCATION_ID") == expected), None)
if start is None:
    sys.exit(1)
for row in rows[start:]:
    manager_id = row.get("INVOCATION_ID")
    if manager_id not in (None, expected) and str(row.get("MESSAGE", "")).startswith("Starting "):
        break
    message = row.get("MESSAGE")
    if isinstance(message, str):
        print(message)
' "$expected_invocation"
}

# Wait for the current workload invocation to fail and require the broker's
# exact consume-denial code. Any other failure, a marker, or a completion
# fails the check, so an unrelated socket or permission error cannot pass.
assert_consume_denied() {
    local grant_id=$1 expected_codes=$2 state result invocation current_log denial
    [[ "$grant_id" =~ ^gr_[A-Za-z0-9_-]{16,128}$ ]] || fail 'grant identifier is invalid'
    [[ "$expected_codes" =~ ^[a-z_]+(\|[a-z_]+)*$ ]] || fail 'expected denial codes are invalid'
    # A grant consumed earlier by its own workload already has its marker;
    # the denied attempt must not create one where none existed.
    local marker=/run/blindpass/ops/"$grant_id".marker marker_existed=false
    [[ -e "$marker" || -L "$marker" ]] && marker_existed=true
    for _attempt in {1..800}; do
        state=$(systemctl show --property=ActiveState --value "$unit" 2>/dev/null || true)
        result=$(systemctl show --property=Result --value "$unit" 2>/dev/null || true)
        invocation=$(systemctl show --property=InvocationID --value "$unit" 2>/dev/null || true)
        if [[ "$state" == failed && "$result" == exit-code && "$invocation" =~ ^[a-f0-9]{32}$ ]]; then
            current_log=$(invocation_log "$invocation" || true)
            if [[ "$marker_existed" == false && ( -e "$marker" || -L "$marker" ) ]]; then
                fail 'denied grant created a marker'
            fi
            if grep -Fq "OPERATION_COMPLETED $grant_id" <<<"$current_log"; then
                fail 'denied grant reported completion'
            fi
            # Permanent grant denials end the client at once; broker-level
            # denials such as node_revoked are retried and then reported.
            denial=$(sed -n -e 's/^blindpass-workload-client: consume denied: \([a-z_]*\)$/\1/p' \
                -e 's/^blindpass-workload-client: workload socket unavailable: ERR \([a-z_]*\)$/\1/p' \
                <<<"$current_log" | tail -n 1)
            [[ -n "$denial" ]] || fail "workload failed without a broker consume denial: $(tail -n 1 <<<"$current_log")"
            [[ "$denial" =~ ^($expected_codes)$ ]] || \
                fail "grant was denied for $denial, expected $expected_codes"
            printf 'P03-GUEST-CONSUME-DENIED grant_id=%s code=%s\n' "$grant_id" "$denial"
            return 0
        fi
        sleep 0.2
    done
    journalctl -u "$unit" -n 30 -o cat --no-pager >&2 || true
    fail 'workload did not fail closed when presenting the grant'
}

deliver_grant_file() {
    local grant_id=$1 temp_file
    install -d -o root -g root -m 0755 /run/blindpass/grants
    temp_file=$(mktemp /run/blindpass/grants/.grant.XXXXXXXX)
    chmod 0600 "$temp_file"
    printf '%s\n' "$grant_id" >"$temp_file"
    chown "root:$workload_group" "$temp_file"
    chmod 0640 "$temp_file"
    mv -f -- "$temp_file" "$grant_file"
}

[[ $(id -u) == 0 ]] || fail 'guest helper requires root'
if [[ "${1:-}" == --unit ]]; then
    [[ "${2:-}" =~ ^blindpass-p03-[a-z0-9-]{1,48}\.service$ ]] || fail 'workload unit name is invalid'
    unit=$2
    shift 2
fi
# Each workload unit has its own root-owned grant file so parallel workloads
# never read another unit's grant.
grant_file=/run/blindpass/grants/${unit%.service}
command=${1:-}
shift || true

case "$command" in
    workload-account)
        printf 'uid:%s\n' "$(id -u blindpass-agent)"
        ;;
    prepare)
        controller_url=${1:-}
        [[ "$controller_url" == 'https://p03-controller:8443' ]] || fail 'controller origin is invalid'
        if [[ ! -x /usr/bin/curl ]]; then
            apt-get update -qq >/tmp/p03-apt.log 2>&1 \
                && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl >>/tmp/p03-apt.log 2>&1 \
                || fail 'the stock curl transport could not be installed in the disposable guest'
            rm -f /tmp/p03-apt.log
        fi
        install -D -m 0755 /tmp/p03/blindpass-broker /usr/libexec/blindpass-broker
        install -D -m 0755 /tmp/p03/blindpass-node /usr/libexec/blindpass-node
        install -D -m 0755 /tmp/p03/blindpass-workload-client /usr/libexec/blindpass-workload-client
        install -D -m 0644 /tmp/p03/blindpass-broker.service /etc/systemd/system/blindpass-broker.service
        install -D -m 0644 /tmp/p03/blindpass-node.service /etc/systemd/system/blindpass-node.service
        install -D -m 0644 /tmp/p03/blindpass-node.sysusers /usr/lib/sysusers.d/blindpass-node.conf
        install -D -m 0644 /tmp/p03/blindpass-workload.sysusers /usr/lib/sysusers.d/blindpass-workload.conf
        install -D -m 0644 /tmp/p03/controller.crt /usr/local/share/ca-certificates/blindpass-p03-controller.crt
        update-ca-certificates >/dev/null
        systemd-sysusers
        install -d -m 0755 /etc/blindpass
        printf 'BLINDPASS_CONTROLLER_URL=%s\n' "$controller_url" >/etc/blindpass/node.env
        chmod 0600 /etc/blindpass/node.env
        grep -qE '^10\.0\.2\.2[[:space:]]+p03-controller([[:space:]]|$)' /etc/hosts || \
            printf '10.0.2.2 p03-controller\n' >>/etc/hosts
        systemctl daemon-reload
        systemctl enable --now blindpass-broker.service
        install -d -o root -g root -m 0755 /run/blindpass/grants
        /usr/libexec/blindpass-node status >/dev/null
        printf 'P03-GUEST-PREPARED\n'
        ;;
    enroll)
        controller_url=${1:-}
        fingerprint=${2:-}
        [[ "$controller_url" == 'https://p03-controller:8443' ]] || fail 'controller origin is invalid'
        [[ "$fingerprint" =~ ^[A-Fa-f0-9]{64}$ ]] || fail 'issuer fingerprint is invalid'
        /usr/libexec/blindpass-node enroll --controller "$controller_url" \
            --issuer-fingerprint "$fingerprint" --token-stdin
        ;;
    start-node)
        systemctl enable --now blindpass-node.service
        printf 'P03-GUEST-NODE-STARTED\n'
        ;;
    stop-node)
        systemctl stop blindpass-node.service
        printf 'P03-GUEST-NODE-STOPPED\n'
        ;;
    start-node-async)
        systemctl reset-failed blindpass-node.service >/dev/null 2>&1 || true
        systemctl start --no-block blindpass-node.service
        printf 'P03-GUEST-NODE-START-QUEUED\n'
        ;;
    assert-node-protocol-mismatch)
        for _attempt in {1..50}; do
            state=$(systemctl show --property=ActiveState --value blindpass-node.service 2>/dev/null || true)
            result=$(systemctl show --property=Result --value blindpass-node.service 2>/dev/null || true)
            exit_status=$(systemctl show --property=ExecMainStatus --value blindpass-node.service 2>/dev/null || true)
            if [[ "$state" == failed && "$result" == exit-code && "$exit_status" == 78 ]]; then
                break
            fi
            sleep 0.2
        done
        [[ "$state" == failed && "$result" == exit-code && "$exit_status" == 78 ]] || \
            fail 'protocol mismatch did not leave the node service in its explicit incompatible state'
        journalctl -u blindpass-node.service -o cat --no-pager 2>/dev/null |
            grep -Fq 'blindpass-node: controller requires an unsupported node protocol' || \
            fail 'node service did not report the incompatible controller protocol'
        sleep 2
        restarts=$(systemctl show --property=NRestarts --value blindpass-node.service 2>/dev/null || true)
        [[ "$restarts" == 0 ]] || fail 'node service restarted after a permanent protocol mismatch'
        printf 'P03-GUEST-NODE-PROTOCOL-MISMATCH-STOPPED exit_status=%s restarts=%s\n' \
            "$exit_status" "$restarts"
        ;;
    assert-node-channel-active)
        systemctl is-active --quiet blindpass-node.service || fail 'node channel service is not active'
        printf 'P03-GUEST-NODE-CHANNEL-ACTIVE\n'
        ;;
    assert-node-channel-stable)
        systemctl is-active --quiet blindpass-node.service || fail 'node channel service is not active'
        restarts=$(systemctl show --property=NRestarts --value blindpass-node.service 2>/dev/null || true)
        [[ "$restarts" == 0 ]] || fail 'transient channel failures restarted the node service'
        printf 'P03-GUEST-NODE-CHANNEL-STABLE restarts=%s\n' "$restarts"
        ;;
    assert-time-reply-replay-rejected)
        rejection_count=$(journalctl -u blindpass-broker.service -o cat --no-pager 2>/dev/null |
            grep -Fc 'controller document rejected: time reply does not match the pending broker challenge' || true)
        [[ "$rejection_count" == 1 ]] || fail 'broker did not reject exactly one stale signed time challenge'
        systemctl is-active --quiet blindpass-node.service || fail 'node channel did not recover after rejecting the replay'
        restarts=$(systemctl show --property=NRestarts --value blindpass-node.service 2>/dev/null || true)
        [[ "$restarts" == 0 ]] || fail 'stale time challenge restarted the node service'
        printf 'P03-GUEST-TIME-REPLY-REPLAY-REJECTED rejected=%s node_restarts=%s\n' \
            "$rejection_count" "$restarts"
        ;;
    suspend-resume)
        seconds=${1:-}
        [[ "$seconds" =~ ^[0-9]+$ ]] && ((seconds >= 5 && seconds <= 60)) || \
            fail 'suspend duration must be an integer from 5 to 60 seconds'
        command -v rtcwake >/dev/null 2>&1 || fail 'rtcwake is unavailable in the guest'
        before_boottime_ms=$(awk '{printf "%.0f", $1 * 1000}' /proc/uptime)
        if ! rtcwake --mode mem --seconds "$seconds" >/tmp/p03-rtcwake.log 2>&1; then
            cat /tmp/p03-rtcwake.log >&2 || true
            rm -f /tmp/p03-rtcwake.log
            fail 'guest could not suspend and wake from its RTC alarm'
        fi
        rm -f /tmp/p03-rtcwake.log
        after_boottime_ms=$(awk '{printf "%.0f", $1 * 1000}' /proc/uptime)
        elapsed_boottime_ms=$((after_boottime_ms - before_boottime_ms))
        ((elapsed_boottime_ms >= seconds * 1000 - 250)) || \
            fail 'CLOCK_BOOTTIME did not include the guest suspend interval'
        printf 'P03-GUEST-SUSPEND-RESUME boottime_elapsed_ms=%s\n' "$elapsed_boottime_ms"
        ;;
    roll-clock-back)
        seconds=${1:-}
        [[ "$seconds" =~ ^[0-9]+$ ]] && ((seconds >= 60 && seconds <= 86400)) || \
            fail 'clock rollback must be between 60 and 86400 seconds'
        timedatectl set-ntp false >/dev/null 2>&1 || true
        current_epoch=$(date +%s)
        target_epoch=$((current_epoch - seconds))
        date --set="@$target_epoch" >/dev/null || fail 'guest wall clock rollback failed'
        observed_epoch=$(date +%s)
        ((observed_epoch <= target_epoch + 2)) || fail 'guest wall clock did not remain behind the target'
        printf 'P03-GUEST-CLOCK-ROLLED-BACK seconds=%s current_epoch=%s\n' "$seconds" "$observed_epoch"
        ;;
    restore-clock)
        epoch=${1:-}
        [[ "$epoch" =~ ^[0-9]{9,12}$ ]] || fail 'clock restore epoch is invalid'
        date --set="@$epoch" >/dev/null || fail 'guest wall clock restore failed'
        printf 'P03-GUEST-CLOCK-RESTORED epoch=%s\n' "$epoch"
        ;;
    reboot-guest)
        systemctl --no-block reboot || fail 'guest reboot could not be queued'
        printf 'P03-GUEST-REBOOT-QUEUED\n'
        ;;
    rotate-prepare)
        /usr/libexec/blindpass-node rotate-prepare
        ;;
    configure-workload)
        node_id=${1:-}
        workload_id=${2:-}
        operation_payload=${3:-}
        valid_id "$node_id" || fail 'node identifier is invalid'
        valid_id "$workload_id" || fail 'workload identifier is invalid'
        [[ "$operation_payload" =~ ^[A-Za-z0-9_-]{1,1024}$ ]] || fail 'operation payload is invalid'
        install -d -o root -g root -m 0755 /run/blindpass/grants
        rm -f -- "$grant_file"
        cat >/etc/systemd/system/"$unit" <<EOF
[Unit]
Description=BlindPass P03 disposable workload
Requires=blindpass-broker.service
After=blindpass-broker.service

[Service]
Type=oneshot
User=blindpass-agent
Group=$workload_group
ExecStart=/usr/libexec/blindpass-workload-client --socket /run/blindpass/workload.sock --node $node_id --workload $workload_id --unit $unit --operation request:$operation_payload --grant-file $grant_file
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

[Install]
WantedBy=multi-user.target
EOF
        chmod 0644 /etc/systemd/system/"$unit"
        systemctl daemon-reload
        systemctl reset-failed "$unit" >/dev/null 2>&1 || true
        printf 'P03-GUEST-WORKLOAD-CONFIGURED\n'
        ;;
    configure-consumer)
        # A unit that presents a known grant ID directly, without first
        # making its own request. Used for copied-grant attempts.
        node_id=${1:-}
        workload_id=${2:-}
        grant_id=${3:-}
        valid_id "$node_id" || fail 'node identifier is invalid'
        valid_id "$workload_id" || fail 'workload identifier is invalid'
        [[ "$grant_id" =~ ^gr_[A-Za-z0-9_-]{16,128}$ ]] || fail 'grant identifier is invalid'
        cat >/etc/systemd/system/"$unit" <<UNIT
[Unit]
Description=BlindPass P03 copied-grant consumer
Requires=blindpass-broker.service
After=blindpass-broker.service

[Service]
Type=oneshot
User=blindpass-agent
Group=$workload_group
ExecStart=/usr/libexec/blindpass-workload-client --socket /run/blindpass/workload.sock --node $node_id --workload $workload_id --unit $unit --operation consume:$grant_id
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadOnlyPaths=/run/blindpass
RestrictAddressFamilies=AF_UNIX
UNIT
        chmod 0644 /etc/systemd/system/"$unit"
        systemctl daemon-reload
        systemctl reset-failed "$unit" >/dev/null 2>&1 || true
        printf 'P03-GUEST-CONSUMER-CONFIGURED\n'
        ;;
    run-outside-unit)
        # An ordinary process running as the workload account outside any
        # registered unit, claiming a registered unit and workload by name.
        node_id=${1:-}
        workload_id=${2:-}
        claimed_unit=${3:-}
        operation=${4:-}
        claimed_invocation=${5:-}
        valid_id "$node_id" || fail 'node identifier is invalid'
        valid_id "$workload_id" || fail 'workload identifier is invalid'
        [[ "$claimed_invocation" =~ ^[a-f0-9]{32}$ ]] || fail 'claimed invocation is invalid'
        [[ "$claimed_unit" =~ ^blindpass-p03-[a-z0-9-]{1,48}\.service$ ]] || fail 'claimed unit is invalid'
        [[ "$operation" =~ ^(request|consume):[A-Za-z0-9_-]{1,1024}$ ]] || fail 'operation is invalid'
        marker_count_before=$(operation_marker_count) || fail 'could not count operation markers'
        set +e
        output=$(timeout 90 runuser -u blindpass-agent -g "$workload_group" -- \
            /usr/libexec/blindpass-workload-client --socket /run/blindpass/workload.sock \
            --node "$node_id" --workload "$workload_id" --unit "$claimed_unit" \
            --invocation "$claimed_invocation" --operation "$operation" 2>&1)
        status=$?
        set -e
        [[ "$status" != 0 ]] || fail 'a process outside the registered unit was authorized'
        if grep -Eq '^OPERATION_(REQUEST|COMPLETED) ' <<<"$output"; then
            fail 'a process outside the registered unit reached the broker operation path'
        fi
        marker_count_after=$(operation_marker_count) || fail 'could not count operation markers'
        [[ "$marker_count_after" == "$marker_count_before" ]] || fail 'outside process created a marker'
        reason=$(sed -n 's/^blindpass-workload-client: //p' <<<"$output" | tail -n 1 | tr -c 'A-Za-z0-9_:. \n-' '_')
        printf 'P03-GUEST-OUTSIDE-UNIT-DENIED status=%s reason=%s\n' "$status" "$reason"
        ;;
    assert-request-denied)
        # The current invocation must fail before any broker request with the
        # broker's exact denial code.
        expected_code=${1:-}
        [[ "$expected_code" =~ ^[a-z_]+(\|[a-z_]+)*$ ]] || fail 'expected denial code is invalid'
        marker_count_before=$(operation_marker_count) || fail 'could not count operation markers'
        for _attempt in {1..800}; do
            state=$(systemctl show --property=ActiveState --value "$unit" 2>/dev/null || true)
            result=$(systemctl show --property=Result --value "$unit" 2>/dev/null || true)
            invocation=$(systemctl show --property=InvocationID --value "$unit" 2>/dev/null || true)
            if [[ "$state" == failed && "$result" == exit-code && "$invocation" =~ ^[a-f0-9]{32}$ ]]; then
                current_log=$(invocation_log "$invocation" || true)
                if grep -Eq '^OPERATION_(REQUEST|COMPLETED) ' <<<"$current_log"; then
                    fail 'a forged or unregistered workload reached the broker operation path'
                fi
                reason=$(sed -n 's/^blindpass-workload-client: //p' <<<"$current_log" | tail -n 1)
                [[ "$reason" =~ (^|[^a-z_])($expected_code)$ ]] || \
                    fail "workload was denied for '$reason', expected $expected_code"
                code=${BASH_REMATCH[2]}
                marker_count_after=$(operation_marker_count) || fail 'could not count operation markers'
                [[ "$marker_count_after" == "$marker_count_before" ]] || fail 'denied workload created a marker'
                printf 'P03-GUEST-REQUEST-DENIED code=%s\n' "$code"
                exit 0
            fi
            sleep 0.2
        done
        journalctl -u "$unit" -n 30 -o cat --no-pager >&2 || true
        fail 'forged or unregistered workload did not fail closed'
        ;;
    assert-operation-closed)
        # The waiting worker must end with the controller's typed closure,
        # not a grant or a timeout.
        expected_status=${1:-}
        [[ "$expected_status" =~ ^(rejected|expired|cancelled|denied)$ ]] || fail 'closure status is invalid'
        started_ms=$(date +%s%3N)
        for _attempt in {1..900}; do
            state=$(systemctl show --property=ActiveState --value "$unit" 2>/dev/null || true)
            result=$(systemctl show --property=Result --value "$unit" 2>/dev/null || true)
            invocation=$(systemctl show --property=InvocationID --value "$unit" 2>/dev/null || true)
            if [[ "$state" == failed && "$result" == exit-code && "$invocation" =~ ^[a-f0-9]{32}$ ]]; then
                current_log=$(invocation_log "$invocation" || true)
                if grep -Fq 'OPERATION_COMPLETED ' <<<"$current_log"; then
                    fail 'closed operation completed'
                fi
                grep -Eq "(^|[^a-z_])operation_${expected_status}\$" <<<"$current_log" || \
                    fail "worker did not report operation_${expected_status}: $(tail -n 1 <<<"$current_log")"
                printf 'P03-GUEST-OPERATION-CLOSED status=%s observed_after_ms=%s\n' \
                    "$expected_status" "$(( $(date +%s%3N) - started_ms ))"
                exit 0
            fi
            sleep 0.2
        done
        journalctl -u "$unit" -n 30 -o cat --no-pager >&2 || true
        fail "worker did not receive the operation_${expected_status} closure"
        ;;
    unprivileged-api-attempt)
        # The workload account sends a well-formed approval while naming an
        # operator in a header, so only authentication decides the result.
        # Print only the HTTP status code.
        approval_id=${1:-}
        operation_id=${2:-}
        operator_id=${3:-}
        [[ "$approval_id" =~ ^oa_[A-Za-z0-9_-]{8,128}$ ]] || fail 'approval identifier is invalid'
        valid_id "$operation_id" || fail 'operation identifier is invalid'
        valid_id "$operator_id" || fail 'operator identifier is invalid'
        body=$(printf '{"expected_status":"pending","expected_version":1,"operation_ids":["%s"]}' "$operation_id")
        code=$(runuser -u blindpass-agent -- curl --silent --output /dev/null --write-out '%{http_code}' \
            --max-time 10 -X POST \
            -H 'Content-Type: application/json' -H "X-Operator-Id: $operator_id" \
            -H 'Idempotency-Key: p03-unprivileged-approval-attempt' -H 'If-Match: "1"' \
            --data "$body" \
            "https://p03-controller:8443/api/v3/approvals/$approval_id/approve" || true)
        [[ "$code" =~ ^[0-9]{3}$ ]] || fail 'operator API attempt did not return an HTTP status'
        printf 'P03-GUEST-UNPRIVILEGED-API status=%s\n' "$code"
        ;;
    start-workload)
        previous_invocation=$(systemctl show --property=InvocationID --value "$unit" 2>/dev/null || true)
        journal_cursor=$(journalctl -u "$unit" -n 1 --show-cursor --no-pager 2>/dev/null |
            sed -n 's/^-- cursor: //p' | tail -n 1 || true)
        systemctl reset-failed "$unit" >/dev/null 2>&1 || true
        systemctl start --no-block "$unit"
        for _attempt in {1..300}; do
            invocation=$(systemctl show --property=InvocationID --value "$unit" 2>/dev/null || true)
            if [[ ! "$invocation" =~ ^[a-f0-9]{32}$ || "$invocation" == "$previous_invocation" ]] \
                && [[ -n "$journal_cursor" ]]; then
                invocation=$({ journalctl -u "$unit" --after-cursor "$journal_cursor" \
                    -o json --no-pager 2>/dev/null || true; } | python3 -c '
import json
import re
import sys

latest = ""
for line in sys.stdin:
    try:
        row = json.loads(line)
        candidate = row.get("_SYSTEMD_INVOCATION_ID") or row.get("INVOCATION_ID")
    except ValueError:
        continue
    if isinstance(candidate, str) and re.fullmatch(r"[a-f0-9]{32}", candidate):
        latest = candidate
print(latest)
')
            fi
            if [[ "$invocation" =~ ^[a-f0-9]{32}$ && "$invocation" != "$previous_invocation" ]]; then
                current_log=$(invocation_log "$invocation" || true)
                if [[ -n "$current_log" ]]; then
                    printf 'P03-GUEST-WORKLOAD-STARTED invocation=%s\n' "$invocation"
                    exit 0
                fi
            fi
            sleep 0.2
        done
        systemctl show --property=ActiveState --property=SubState --property=Result \
            --property=InvocationID "$unit" >&2 || true
        journalctl -u "$unit" -n 20 -o cat --no-pager 2>/dev/null |
            sed -E 's/^(OPERATION_(REQUEST|COMPLETED)) .*/\1 [redacted]/' >&2 || true
        fail 'systemd did not record a new workload invocation within 60 seconds'
        ;;
    wait-request)
        for _attempt in {1..300}; do
            invocation=$(systemctl show --property=InvocationID --value "$unit" 2>/dev/null || true)
            if [[ "$invocation" =~ ^[a-f0-9]{32}$ ]]; then
                event_key=$({ invocation_log "$invocation" 2>/dev/null || true; } |
                    awk '/^OPERATION_REQUEST / {print $2; exit}')
                if [[ "$event_key" =~ ^[A-Za-z0-9_-]{16,128}$ ]]; then
                    printf 'P03-REQUEST invocation=%s event_key=%s\n' "$invocation" "$event_key"
                    exit 0
                fi
            fi
            sleep 0.2
        done
        journalctl -u "$unit" -n 30 -o cat --no-pager >&2 || true
        journalctl -u blindpass-node.service -n 40 -o cat --no-pager >&2 || true
        journalctl -u blindpass-broker.service -n 40 -o cat --no-pager >&2 || true
        fail 'workload request did not reach the broker'
        ;;
    provide-grant)
        install -d -o root -g root -m 0755 /run/blindpass/grants
        temp_file=$(mktemp /run/blindpass/grants/.grant.XXXXXXXX)
        chmod 0600 "$temp_file"
        cat >"$temp_file"
        [[ $(stat -c '%s' "$temp_file") -le 140 ]] || {
            rm -f -- "$temp_file"
            fail 'grant identifier input is oversized'
        }
        grant_id=$(<"$temp_file")
        [[ "$grant_id" =~ ^gr_[A-Za-z0-9_-]{16,128}$ ]] || {
            rm -f -- "$temp_file"
            fail 'grant identifier is invalid'
        }
        chown "root:$workload_group" "$temp_file"
        chmod 0640 "$temp_file"
        mv -f -- "$temp_file" "$grant_file"
        printf 'P03-GUEST-GRANT-DELIVERED\n'
        ;;
    verify-workload)
        grant_id=${1:-}
        operation_id=${2:-}
        [[ "$grant_id" =~ ^gr_[A-Za-z0-9_-]{16,128}$ ]] || fail 'grant identifier is invalid'
        valid_id "$operation_id" || fail 'operation identifier is invalid'
        for _attempt in {1..300}; do
            if journalctl -u "$unit" -o cat --no-pager 2>/dev/null |
                grep -Fq "OPERATION_COMPLETED $grant_id"; then
                marker=/run/blindpass/ops/"$grant_id".marker
                [[ -f "$marker" && ! -L "$marker" && ! -s "$marker" ]] || fail 'dummy marker is missing or malformed'
                [[ $(stat -c '%a:%u' "$marker") == '444:0' ]] || fail 'dummy marker ownership or permissions are unsafe'
                [[ $(stat -c '%a:%u' /run/blindpass/ops) == '711:0' ]] \
                    || fail 'operation marker directory is listable or not root-owned'
                printf 'P03-GUEST-OPERATION-COMPLETED grant_id=%s operation_id=%s\n' "$grant_id" "$operation_id"
                exit 0
            fi
            sleep 0.2
        done
        journalctl -u "$unit" -n 30 -o cat --no-pager >&2 || true
        journalctl -u blindpass-node.service -n 40 -o cat --no-pager >&2 || true
        journalctl -u blindpass-broker.service -n 40 -o cat --no-pager >&2 || true
        queue=/var/lib/blindpass/broker/pending-node-events.jsonl
        if [[ -f "$queue" && ! -L "$queue" ]]; then
            printf 'P03-GUEST-PENDING-BROKER-EVENTS count=%s bytes=%s\n' \
                "$(wc -l <"$queue")" "$(stat -c '%s' "$queue")" >&2
        fi
        fail 'workload operation did not complete'
        ;;
    verify-revoked-grant)
        grant_id=${1:-}
        expected_codes=${2:-grant_revoked}
        [[ "$grant_id" =~ ^gr_[A-Za-z0-9_-]{16,128}$ ]] || fail 'grant identifier is invalid'
        deliver_grant_file "$grant_id"
        assert_consume_denied "$grant_id" "$expected_codes"
        ;;
    assert-grant-revocation-journal)
        grant_id=${1:-}
        [[ "$grant_id" =~ ^gr_[A-Za-z0-9_-]{16,128}$ ]] || fail 'grant identifier is invalid'
        journal=/var/lib/blindpass/broker/revoked-grants.jsonl
        for _attempt in {1..300}; do
            if [[ -f "$journal" && ! -L "$journal" ]]; then
                matches=$(grep -F -c '"grant_id":"'"$grant_id"'"' "$journal" || true)
                [[ "$matches" == 1 ]] && break
            fi
            sleep 0.2
        done
        [[ -f "$journal" && ! -L "$journal" ]] || fail 'grant revocation journal is missing or unsafe'
        [[ $(stat -c '%a:%u' "$journal") == '600:0' ]] || fail 'grant revocation journal is not private'
        matches=$(grep -F -c '"grant_id":"'"$grant_id"'"' "$journal" || true)
        [[ "$matches" == 1 ]] || fail 'grant revocation was not persisted exactly once'
        printf 'P03-GUEST-GRANT-REVOCATION-DURABLE records=%s\n' "$matches"
        ;;
    assert-rebooted-grant-denied)
        # After reboot the broker holds no accepted grants until fresh
        # reconciliation. An identity-mismatch denial would mean the old
        # grant survived and only the new invocation stopped it.
        assert_consume_denied "${1:-}" grant_unknown
        rm -f -- "$grant_file"
        printf 'P03-GUEST-REBOOTED-GRANT-DENIED\n'
        ;;
    assert-expired-workload)
        assert_consume_denied "${1:-}" grant_expired
        printf 'P03-GUEST-EXPIRED-GRANT-DENIED\n'
        ;;
    assert-consume-denied)
        assert_consume_denied "${1:-}" "${2:-}"
        ;;
    assert-consumed-once)
        grant_id=${1:-}
        [[ "$grant_id" =~ ^gr_[A-Za-z0-9_-]{16,128}$ ]] || fail 'grant identifier is invalid'
        journal=/var/lib/blindpass/broker/consumed.jsonl
        [[ -f "$journal" && ! -L "$journal" ]] || fail 'consumed grant journal is unavailable'
        [[ $(grep -F -c '"'"$grant_id"'"' "$journal") == 1 ]] \
            || fail 'grant was not consumed exactly once'
        printf 'P03-GUEST-CONSUMED-ONCE grant_id=%s\n' "$grant_id"
        ;;
    stop-workload)
        systemctl stop "$unit" >/dev/null 2>&1 || true
        printf 'P03-GUEST-WORKLOAD-STOPPED\n'
        ;;
    assert-revoked-workload)
        grant_id=${1:-}
        [[ "$grant_id" =~ ^gr_[A-Za-z0-9_-]{16,128}$ ]] || fail 'grant identifier is invalid'
        for _attempt in {1..800}; do
            state=$(systemctl show --property=ActiveState --value "$unit" 2>/dev/null || true)
            result=$(systemctl show --property=Result --value "$unit" 2>/dev/null || true)
            invocation=$(systemctl show --property=InvocationID --value "$unit" 2>/dev/null || true)
            if [[ "$state" == failed && "$result" == exit-code \
                && "$invocation" =~ ^[a-f0-9]{32}$ ]]; then
                current_log=$(invocation_log "$invocation" || true)
                if grep -Eq '^OPERATION_(REQUEST|COMPLETED) ' <<<"$current_log"; then
                    fail 'revoked node accepted a fresh workload request'
                fi
                grep -Eq '^blindpass-workload-client: (node identity is revoked|workload socket unavailable: ERR node_revoked)$' \
                    <<<"$current_log" || fail 'revoked workload did not report a node-revoked denial'
                marker=/run/blindpass/ops/"$grant_id".marker
                [[ ! -e "$marker" && ! -L "$marker" ]] || \
                    fail 'revoked workload created its grant marker'
                printf 'P03-GUEST-OLD-WORKLOAD-DENIED\n'
                exit 0
            fi
            sleep 0.2
        done
        fail 'revoked node did not fail the retried workload'
        ;;
    assert-policy-denied)
        policy_version=${1:-}
        expected_invocation=${2:-}
        expected_marker_count=${3:-}
        workload_error=''
        [[ "$policy_version" =~ ^[1-9][0-9]*$ ]] || fail 'policy version is invalid'
        [[ "$expected_invocation" =~ ^[a-f0-9]{32}$ ]] || fail 'workload invocation is invalid'
        [[ "$expected_marker_count" =~ ^[0-9]+$ ]] || fail 'expected marker count is invalid'
        policy_file=/var/lib/blindpass/broker/fleet-policy.json
        for _attempt in {1..300}; do
            if grep -Eq '"policy_version"[[:space:]]*:[[:space:]]*'"$policy_version"'([,}])' "$policy_file" 2>/dev/null \
                && grep -Fq '"allowed_actions":[]' "$policy_file"; then
                break
            fi
            sleep 0.2
        done
        grep -Eq '"policy_version"[[:space:]]*:[[:space:]]*'"$policy_version"'([,}])' "$policy_file" \
            || fail 'broker did not retain the current signed policy version'
        grep -Fq '"allowed_actions":[]' "$policy_file" \
            || fail 'broker policy still permits the replayed action'
        systemctl is-active --quiet blindpass-broker.service || fail 'broker service is not active'
        systemctl is-active --quiet blindpass-node.service || fail 'node service is not active'
        for _attempt in {1..100}; do
            state=$(systemctl show --property=ActiveState --value "$unit" 2>/dev/null || true)
            result=$(systemctl show --property=Result --value "$unit" 2>/dev/null || true)
            invocation=$(systemctl show --property=InvocationID --value "$unit" 2>/dev/null || true)
            if [[ "$invocation" =~ ^[a-f0-9]{32}$ && "$invocation" != "$expected_invocation" ]]; then
                fail 'workload invocation changed before the policy result was checked'
            fi
            if [[ "$invocation" == "$expected_invocation" && "$state" == failed \
                && "$result" == exit-code ]]; then
                current_log=$(invocation_log "$invocation" || true)
                if grep -Eq '^OPERATION_(REQUEST|COMPLETED) ' <<<"$current_log"; then
                    fail 'broker accepted an operation under the delayed stale policy'
                fi
                if grep -Fq 'blindpass-workload-client: operation request was denied by local policy' \
                    <<<"$current_log"; then
                    marker_count_after=$(operation_marker_count) || fail 'could not count operation markers'
                    [[ "$marker_count_after" == "$expected_marker_count" ]] \
                        || fail 'policy replay created a new operation marker'
                    printf 'P03-GUEST-STALE-POLICY-DENIED policy_version=%s denial=local_policy marker_created=false\n' \
                        "$policy_version"
                    exit 0
                fi
                workload_error=$(sed -n 's/^blindpass-workload-client: //p' <<<"$current_log" | tail -n 1)
                if [[ -n "$workload_error" ]]; then
                    fail "workload failed for a reason other than local policy denial: $workload_error"
                fi
            fi
            if [[ "$state" == active && "$invocation" == "$expected_invocation" ]]; then
                current_log=$(invocation_log "$invocation" || true)
                if grep -Eq '^OPERATION_(REQUEST|COMPLETED) ' <<<"$current_log"; then
                    fail 'broker accepted an operation under the delayed stale policy'
                fi
                workload_error=$(sed -n 's/^blindpass-workload-client: //p' <<<"$current_log" | tail -n 1)
                if [[ -n "$workload_error" ]]; then
                    fail "workload failed for a reason other than local policy denial: $workload_error"
                fi
            fi
            sleep 0.2
        done
        journalctl -u "$unit" -n 30 -o cat --no-pager >&2 || true
        [[ -n "$workload_error" ]] \
            || workload_error='the expected local policy denial was not recorded'
        fail "workload did not fail closed under the current policy: $workload_error"
        ;;
    wait-policy-version)
        policy_version=${1:-}
        [[ "$policy_version" =~ ^[1-9][0-9]*$ ]] || fail 'policy version is invalid'
        policy_file=/var/lib/blindpass/broker/fleet-policy.json
        for _attempt in {1..300}; do
            if grep -Eq '"policy_version"[[:space:]]*:[[:space:]]*'"$policy_version"'([,}])' "$policy_file" 2>/dev/null \
                && grep -Fq '"allowed_actions":[]' "$policy_file"; then
                printf 'P03-GUEST-POLICY-APPLIED version=%s allowed_actions=0\n' "$policy_version"
                exit 0
            fi
            sleep 0.2
        done
        fail 'broker did not apply the follow-up signed deny policy'
        ;;
    wait-policy-allows)
        policy_version=${1:-}
        [[ "$policy_version" =~ ^[1-9][0-9]*$ ]] || fail 'policy version is invalid'
        policy_file=/var/lib/blindpass/broker/fleet-policy.json
        for _attempt in {1..300}; do
            if grep -Eq '"policy_version"[[:space:]]*:[[:space:]]*'"$policy_version"'([,}])' "$policy_file" 2>/dev/null \
                && grep -Fq '"noop.marker"' "$policy_file"; then
                printf 'P03-GUEST-POLICY-APPLIED version=%s allows=noop.marker\n' "$policy_version"
                exit 0
            fi
            sleep 0.2
        done
        fail 'broker did not apply the signed allowing policy'
        ;;
    key-canaries)
        # Print encodings of this disposable guest's private node key material
        # so the host can prove none of it reached the controller.
        # Include every archived revoked identity: those keys went through
        # enrollment, rotation and revocation and must not leak either.
        identity=/var/lib/blindpass/broker/node-identity.state
        [[ -f "$identity" && ! -L "$identity" ]] || fail 'node identity state is unavailable'
        identities=("$identity")
        for archived in /var/lib/blindpass/revoked-identities/*/node-identity.state; do
            [[ -e "$archived" ]] || continue
            [[ -f "$archived" && ! -L "$archived" ]] || fail 'archived node identity is not a regular file'
            identities+=("$archived")
        done
        python3 - "${identities[@]}" <<'PY'
import base64
import sys

print(f"identities {len(sys.argv) - 1}")
for path in sys.argv[1:]:
    data = open(path, "rb").read()
    if len(data) < 72:
        raise SystemExit("node identity state is truncated")
    for secret in (data[8:40], data[40:72]):
        print(f"secret {base64.urlsafe_b64encode(secret).decode().rstrip('=')}")
        print(f"secret {base64.b64encode(secret).decode()}")
        print(f"secret {secret.hex()}")
        # SQLite dumps render BLOB values as uppercase hexadecimal.
        print(f"secret {secret.hex().upper()}")
PY
        ;;
    enable-crash-hook)
        # Test-mode drop-in for the disposable guest only; test mode alone
        # changes nothing until the root-owned flag file is armed.
        install -d -m 0755 /etc/systemd/system/blindpass-broker.service.d
        printf '[Service]\nEnvironment=BLINDPASS_P01_TEST_MODE=1\n' \
            >/etc/systemd/system/blindpass-broker.service.d/p03-crash-hook.conf
        systemctl daemon-reload
        systemctl restart blindpass-broker.service
        systemctl restart blindpass-node.service
        printf 'P03-GUEST-CRASH-HOOK-ENABLED\n'
        ;;
    arm-crash-hook)
        install -d -o root -g root -m 0700 /run/blindpass/test
        install -o root -g root -m 0600 /dev/null /run/blindpass/test/crash-after-consume-intent
        restarts=$(systemctl show --property=NRestarts --value blindpass-broker.service)
        printf 'P03-GUEST-CRASH-HOOK-ARMED broker_restarts=%s\n' "$restarts"
        ;;
    assert-crash-after-intent)
        grant_id=${1:-}
        restarts_before=${2:-}
        expected_operation=${3:-}
        expected_epoch=${4:-}
        [[ "$grant_id" =~ ^gr_[A-Za-z0-9_-]{16,128}$ ]] || fail 'grant identifier is invalid'
        [[ "$restarts_before" =~ ^[0-9]+$ ]] || fail 'broker restart count is invalid'
        [[ "$expected_operation" =~ ^op_[A-Za-z0-9_-]{1,125}$ ]] || fail 'operation identifier is invalid'
        [[ "$expected_epoch" =~ ^[1-9][0-9]*$ ]] || fail 'issuer epoch is invalid'
        for _attempt in {1..150}; do
            restarts=$(systemctl show --property=NRestarts --value blindpass-broker.service)
            if ((restarts > restarts_before)) && systemctl is-active --quiet blindpass-broker.service; then
                break
            fi
            sleep 0.2
        done
        [[ ! -e /run/blindpass/test/crash-after-consume-intent ]] || fail 'crash hook did not fire'
        ((restarts > restarts_before)) || fail 'broker did not abort and restart after the consume intent'
        systemctl is-active --quiet blindpass-broker.service || fail 'broker did not recover after the crash'
        # The workload unit Requires= the broker, so systemd stopped it when
        # the broker aborted and started a new invocation with the broker's
        # restart. Stop that invocation; it cannot hold the old grant binding.
        systemctl stop "$unit" >/dev/null 2>&1 || true
        journal=/var/lib/blindpass/broker/consumed.jsonl
        [[ $(grep -F -c '"'"$grant_id"'"' "$journal" 2>/dev/null || true) == 1 ]] \
            || fail 'consume intent was not durable exactly once'
        python3 - "$journal" "$grant_id" "$expected_operation" "$expected_epoch" <<'PY'
import hashlib
import json
import os
import stat
import sys

def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('duplicate journal field')
        value[key] = item
    return value

fd = os.open(sys.argv[1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
metadata = os.fstat(fd)
assert stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 0
assert stat.S_IMODE(metadata.st_mode) == 0o600 and metadata.st_nlink == 1
assert metadata.st_size <= 64 * 1024 * 1024
with os.fdopen(fd, encoding='utf-8') as source:
    rows = [json.loads(line, object_pairs_hook=unique_object) for line in source if line.strip()]
matches = [row for row in rows if row.get('grant_id') == sys.argv[2]]
assert len(matches) == 1
row = matches[0]
assert set(row) == {'grant_id', 'operation_id', 'issuer_epoch', 'expires_at_ms'}
assert row['operation_id'] == sys.argv[3]
assert type(row['issuer_epoch']) is int and row['issuer_epoch'] == int(sys.argv[4])
assert type(row['expires_at_ms']) is int and row['expires_at_ms'] > 0
with open('/usr/libexec/blindpass-broker', 'rb') as program:
    binary_hash = hashlib.file_digest(program, 'sha256').hexdigest()
print('P06-CJ06 bound_operation=true bound_epoch=true private_single_link=true broker_sha256=' + binary_hash)
PY
        marker=/run/blindpass/ops/"$grant_id".marker
        [[ ! -e "$marker" && ! -L "$marker" ]] || fail 'crash between intent and effect created a marker'
        printf 'P03-GUEST-CRASH-AFTER-INTENT broker_restarts=%s intent_records=1 marker_created=false\n' "$restarts"
        ;;
    disable-crash-hook)
        rm -f /etc/systemd/system/blindpass-broker.service.d/p03-crash-hook.conf \
            /run/blindpass/test/crash-after-consume-intent
        systemctl daemon-reload
        systemctl restart blindpass-broker.service
        systemctl restart blindpass-node.service
        printf 'P03-GUEST-CRASH-HOOK-DISABLED\n'
        ;;
    marker-count)
        operation_marker_count || fail 'could not count operation markers'
        ;;
    wait-outbox-empty)
        outbox=/var/lib/blindpass/node/outbox.jsonl
        broker_events=/var/lib/blindpass/broker/pending-node-events.jsonl
        for _attempt in {1..600}; do
            broker_event_count=0
            overflow_pending=false
            if [[ -s "$broker_events" ]]; then
                if broker_lines=$(wc -l 2>/dev/null <"$broker_events"); then
                    if ((broker_lines > 1)); then
                        broker_event_count=$((broker_lines - 1))
                    fi
                    if grep -Fq '"audit_overflow_pending":true' "$broker_events" 2>/dev/null; then
                        overflow_pending=true
                    fi
                fi
            fi
            if [[ ! -s "$outbox" && "$broker_event_count" == 0 && "$overflow_pending" == false ]]; then
                printf 'P03-GUEST-EVENT-QUEUES-DRAINED\n'
                exit 0
            fi
            sleep 0.2
        done
        printf 'P03-GUEST-QUEUE-STATE node_outbox_bytes=%s broker_event_count=%s overflow_pending=%s node_state=%s broker_state=%s\n' \
            "$(stat -c '%s' "$outbox" 2>/dev/null || echo 0)" \
            "$broker_event_count" "$overflow_pending" \
            "$(systemctl show --property=ActiveState --value blindpass-node.service 2>/dev/null || true)" \
            "$(systemctl show --property=ActiveState --value blindpass-broker.service 2>/dev/null || true)" >&2
        journalctl -u blindpass-node.service -n 80 -o cat --no-pager >&2 2>/dev/null || true
        journalctl -u blindpass-broker.service -n 80 -o cat --no-pager >&2 2>/dev/null || true
        fail 'broker or node event queue did not drain after application acknowledgement'
        ;;
    wait-outbox-nonempty)
        for _attempt in {1..300}; do
            if [[ -s /var/lib/blindpass/node/outbox.jsonl ]]; then
                printf 'P03-GUEST-OUTBOX-PERSISTED\n'
                exit 0
            fi
            sleep 0.2
        done
        fail 'node event outbox did not receive the broker event'
        ;;
    assert-broker-event)
        event_key=${1:-}
        [[ "$event_key" =~ ^[A-Za-z0-9_-]{16,128}$ ]] || fail 'broker event key is invalid'
        queue=/var/lib/blindpass/broker/pending-node-events.jsonl
        [[ -f "$queue" && ! -L "$queue" ]] || fail 'broker event queue is missing after restart'
        python3 - "$queue" "$event_key" <<'PY' || fail 'broker event was not persisted exactly once'
import json
import os
import stat
import sys

def unique_fields(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result

try:
    descriptor = os.open(sys.argv[1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as journal:
        metadata = os.fstat(journal.fileno())
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_nlink != 1
                or metadata.st_size > 72 * 1024 * 1024):
            raise ValueError("unsafe queue")
        rows = [json.loads(line, object_pairs_hook=unique_fields) for line in journal]
    if not rows or any(not isinstance(row, dict) for row in rows):
        raise ValueError("invalid queue")
    # Ownership/closure headers refer to the same key. Only an event's exact
    # top-level idempotency key proves a queued event, never a text match.
    events = rows[1:]
    if (type(rows[0].get("v")) is not int or rows[0]["v"] not in range(1, 6)
            or any(set(row) != {"idempotency_key", "kind", "body"}
                   or not isinstance(row["body"], dict)
                   or not isinstance(row["idempotency_key"], str)
                   or row["kind"] not in ("operation_request", "operation_result", "operation_cancel", "audit")
                   for row in events)):
        raise ValueError("invalid queue shape")
    matches = [row for row in events if row["idempotency_key"] == sys.argv[2]]
    if len(matches) != 1 or matches[0]["kind"] != "operation_request":
        raise ValueError("event count differs")
except (OSError, ValueError, KeyError, TypeError):
    sys.exit(1)
PY
        printf 'P03-GUEST-BROKER-EVENT-PERSISTED\n'
        ;;
    assert-node-outbox-nonempty)
        outbox=/var/lib/blindpass/node/outbox.jsonl
        [[ -f "$outbox" && ! -L "$outbox" && -s "$outbox" ]] || fail 'node event outbox is empty after the simulated lost response'
        node_uid=$(id -u blindpass-node)
        [[ $(stat -c '%a:%u' "$outbox") == "600:$node_uid" ]] || fail 'node event outbox ownership or permissions are unsafe'
        printf 'P03-GUEST-NODE-OUTBOX-PERSISTED\n'
        ;;
    restart-channel)
        systemctl stop blindpass-node.service blindpass-broker.service
        systemctl start blindpass-broker.service
        systemctl start blindpass-node.service
        printf 'P03-GUEST-CHANNEL-RESTARTED\n'
        ;;
    restart-node)
        systemctl restart blindpass-node.service
        printf 'P03-GUEST-NODE-RESTARTED\n'
        ;;
    assert-channel-after-boot)
        systemctl is-active --quiet blindpass-broker.service || fail 'broker service is not active after boot'
        systemctl is-active --quiet blindpass-node.service || fail 'node service is not active after boot'
        restarts=$(systemctl show --property=NRestarts --value blindpass-node.service 2>/dev/null || true)
        [[ "$restarts" == 0 ]] || fail 'node service entered a restart loop after boot'
        printf 'P03-GUEST-CHANNEL-ACTIVE-AFTER-BOOT restarts=%s\n' "$restarts"
        ;;
    archive-revoked-identity)
        node_id=${1:-}
        valid_id "$node_id" || fail 'node identifier is invalid'
        systemctl stop blindpass-node.service blindpass-broker.service
        archive=/var/lib/blindpass/revoked-identities
        install -d -o root -g root -m 0700 "$archive"
        [[ -d /var/lib/blindpass/broker && ! -L /var/lib/blindpass/broker ]] || fail 'broker identity directory is unavailable'
        [[ ! -e "$archive/$node_id" ]] || fail 'revoked identity archive already exists'
        mv /var/lib/blindpass/broker "$archive/$node_id"
        install -d -o root -g root -m 0700 /var/lib/blindpass/broker
        systemctl start blindpass-broker.service
        /usr/libexec/blindpass-node status >/dev/null
        printf 'P03-GUEST-OLD-IDENTITY-ARCHIVED node_id=%s\n' "$node_id"
        ;;
    *)
        fail 'unknown P03 guest command'
        ;;
esac
