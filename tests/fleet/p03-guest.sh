#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -Eeuo pipefail

unit=blindpass-p03-workload.service
grant_file=/run/blindpass/grants/current
workload_group=blindpass-workload

fail() {
    printf 'P03-GUEST-FAIL %s\n' "$1" >&2
    exit 1
}

valid_id() {
    [[ "$1" =~ ^[A-Za-z0-9_-]{1,128}$ ]]
}

[[ $(id -u) == 0 ]] || fail 'guest helper requires root'
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
    start-workload)
        systemctl reset-failed "$unit" >/dev/null 2>&1 || true
        systemctl start --no-block "$unit"
        printf 'P03-GUEST-WORKLOAD-STARTED\n'
        ;;
    wait-request)
        for _attempt in {1..300}; do
            invocation=$(systemctl show --property=InvocationID --value "$unit" 2>/dev/null || true)
            if [[ "$invocation" =~ ^[a-f0-9]{32}$ ]]; then
                event_key=$(journalctl -u "$unit" "_SYSTEMD_INVOCATION_ID=$invocation" -o cat --no-pager 2>/dev/null |
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
        temp_file=$(mktemp /run/blindpass/grants/.current.XXXXXXXX)
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
        [[ "$grant_id" =~ ^gr_[A-Za-z0-9_-]{16,128}$ ]] || fail 'grant identifier is invalid'
        install -d -o root -g root -m 0755 /run/blindpass/grants
        temp_file=$(mktemp /run/blindpass/grants/.current.XXXXXXXX)
        chmod 0600 "$temp_file"
        printf '%s\n' "$grant_id" >"$temp_file"
        chown "root:$workload_group" "$temp_file"
        chmod 0640 "$temp_file"
        mv -f -- "$temp_file" "$grant_file"
        for _attempt in {1..600}; do
            state=$(systemctl show --property=ActiveState --value "$unit" 2>/dev/null || true)
            result=$(systemctl show --property=Result --value "$unit" 2>/dev/null || true)
            if [[ "$state" == failed && "$result" == exit-code ]]; then
                marker=/run/blindpass/ops/"$grant_id".marker
                [[ ! -e "$marker" && ! -L "$marker" ]] || fail 'revoked grant created a marker'
                if journalctl -u "$unit" -o cat --no-pager 2>/dev/null |
                    grep -Fq "OPERATION_COMPLETED $grant_id"; then
                    fail 'revoked grant reported completion'
                fi
                printf 'P03-GUEST-REVOKED-GRANT-DENIED\n'
                exit 0
            fi
            sleep 0.2
        done
        fail 'revoked grant did not fail closed in the workload'
        ;;
    assert-expired-workload)
        grant_id=${1:-}
        [[ "$grant_id" =~ ^gr_[A-Za-z0-9_-]{16,128}$ ]] || fail 'grant identifier is invalid'
        for _attempt in {1..300}; do
            state=$(systemctl show --property=ActiveState --value "$unit" 2>/dev/null || true)
            result=$(systemctl show --property=Result --value "$unit" 2>/dev/null || true)
            if [[ "$state" == failed && "$result" == exit-code ]]; then
                marker=/run/blindpass/ops/"$grant_id".marker
                [[ ! -e "$marker" && ! -L "$marker" ]] || fail 'expired grant created a marker'
                if journalctl -u "$unit" -o cat --no-pager 2>/dev/null |
                    grep -Fq "OPERATION_COMPLETED $grant_id"; then
                    fail 'expired grant reported operation completion'
                fi
                printf 'P03-GUEST-EXPIRED-GRANT-DENIED\n'
                exit 0
            fi
            sleep 0.2
        done
        journalctl -u "$unit" -n 30 -o cat --no-pager >&2 || true
        fail 'expired grant did not fail closed in the workload'
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
                current_log=$(journalctl -u "$unit" "_SYSTEMD_INVOCATION_ID=$invocation" \
                    -o cat --no-pager 2>/dev/null || true)
                if grep -Eq '^OPERATION_(REQUEST|COMPLETED) ' <<<"$current_log"; then
                    fail 'revoked node accepted a fresh workload request'
                fi
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
        matches=$(grep -F -c "$event_key" "$queue" || true)
        [[ "$matches" == 1 ]] || fail 'broker event was not persisted exactly once'
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
