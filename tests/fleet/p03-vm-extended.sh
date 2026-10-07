# SPDX-License-Identifier: AGPL-3.0-only
# shellcheck shell=bash
#
# Additional P03 pilot scenarios for tests/fleet/p03-vm.sh. Sourced by the
# runner and called from run_backend, whose locals (backend_dir,
# controller_env, recovered_node, node_b, database_url_file) remain visible.

# Broker denial codes asserted below. They are stable broker protocol values;
# an unrelated failure never matches them.
P03_CODE_UNREGISTERED='unknown_registration'
P03_CODE_WORKLOAD_MISMATCH='workload_mismatch'
# A process outside any unit resolves to its session scope, which differs
# from the unit it claims and has no registration.
P03_CODE_OUTSIDE_UNIT='binding_mismatch:self_reported_unit_or_invocation_differs_from_OS_identity|unknown_registration'

now_ms() {
    node -e 'process.stdout.write(String(Date.now()))'
}

operation_payload() {
    local purpose=$1 resource=$2 ttl=$3
    node -e 'process.stdout.write(Buffer.from(JSON.stringify({action:"noop.marker",mode:"file",purpose:process.argv[1],resource_id:process.argv[2],ttl_seconds:Number(process.argv[3])})).toString("base64url"))' \
        "$purpose" "$resource" "$ttl"
}

wait_for_fresh_poll() {
    local node_id=$1 after_ms=$2 status last_poll
    for _attempt in {1..300}; do
        status=$(admin node-status "$node_id")
        last_poll=$(json_field "$status" last_poll_at)
        if [[ "$last_poll" =~ ^[0-9]+$ ]] && (( last_poll > after_ms )); then
            return 0
        fi
        sleep 0.2
    done
    printf 'P03-FAIL node %s did not poll after %s\n' "$node_id" "$after_ms" >&2
    return 1
}

request_event() {
    local guest=$1
    # Runs inside command substitutions, where errexit is not inherited.
    guest_call "$guest" start-workload >/dev/null || return 1
    guest_call "$guest" wait-request
}

start_controller() {
    env "${controller_env[@]}" "$repo_root/target/release/blindpass-controller" serve \
        >>"$backend_dir/controller.log" 2>&1 &
    controller_pid=$!
    for _attempt in {1..100}; do
        if curl --silent --show-error --fail --max-time 1 \
            http://127.0.0.1:3200/readyz >/dev/null 2>&1; then
            return 0
        fi
        kill -0 "$controller_pid" 2>/dev/null || break
        sleep 0.2
    done
    printf 'P03-FAIL controller did not become ready after restart\n' >&2
    return 1
}

# Pilot E05 and I10: decline, dismiss and expire approvals. The waiting worker
# receives the controller-signed closure; no grant, delivery or marker occurs.
# The requester and the workload account cannot approve.
scenario_e05_approval_closures() {
    local node_a=$1 kind request pending operation_id approval_id decision_json status expected_status
    for kind in rejected cancelled expired; do
        setup_workload a "$node_a" "$current_backend-e05-$kind" \
            "$(operation_payload "P03 E05 $kind" "P03-E05-${kind^^}" 60)"
        request=$(request_event a)
        pending=$(admin request-operation "$SETUP_WORKLOAD_ID" \
            "$(sed -n 's/.*event_key=\([A-Za-z0-9_-]*\).*/\1/p' <<<"$request")" \
            "$(sed -n 's/.*invocation=\([a-f0-9]*\).*/\1/p' <<<"$request")" \
            "P03-E05-${kind^^}" "P03 E05 $kind" 60)
        operation_id=$(json_field "$pending" operation_id)
        approval_id=$(json_field "$pending" approval_id)
        [[ "$approval_id" =~ ^oa_ ]] || { printf 'P03-FAIL E05 approval is malformed\n' >&2; return 1; }
        if [[ "$kind" == rejected ]]; then
            decision_json=$(admin decide "$approval_id" approve admin)
            [[ $(json_field "$decision_json" status) == 403 ]] || {
                printf 'P03-FAIL requester approved its own operation (%s)\n' "$decision_json" >&2
                return 1
            }
            status=$(guest_call a unprivileged-api-attempt "$approval_id" "$operation_id" "$APPROVER_ID")
            # The workload account holds no operator session or cookie, so the
            # operator API must refuse it as unauthenticated.
            [[ "$status" =~ status=401$ ]] || {
                printf 'P03-FAIL workload account reached the operator approval API (%s)\n' "$status" >&2
                return 1
            }
            [[ $(json_field "$(admin approval-status "$approval_id")" status) == pending ]] || {
                printf 'P03-FAIL unauthorized approval attempts changed the approval\n' >&2
                return 1
            }
            printf 'P03-SCENARIO backend=%s scenario=I10-unprivileged-approval requester=403 workload_api=%s status=passed\n' \
                "$current_backend" "${status##*=}"
            decision_json=$(admin decide "$approval_id" reject)
            [[ $(json_field "$decision_json" status) == 200 ]] || {
                printf 'P03-FAIL named approver could not reject (%s)\n' "$decision_json" >&2
                return 1
            }
        elif [[ "$kind" == cancelled ]]; then
            admin cancel-operation "$operation_id" >/dev/null
        fi
        guest_call a assert-operation-closed "$kind"
        status=$(admin operation-status "$operation_id")
        [[ $(json_field "$status" grant_id) == null || -z $(json_field "$status" grant_id) ]] || {
            printf 'P03-FAIL closed E05 operation %s received a grant\n' "$operation_id" >&2
            return 1
        }
        # A rejected or expired approval denies the operation; a dismissed
        # request is cancelled before any grant.
        expected_status=denied
        [[ "$kind" == cancelled ]] && expected_status=cancelled
        [[ $(json_field "$status" status) == "$expected_status" ]] || {
            printf 'P03-FAIL E05 %s operation ended %s, expected %s\n' \
                "$kind" "$(json_field "$status" status)" "$expected_status" >&2
            return 1
        }
        printf 'P03-SCENARIO backend=%s scenario=E05-approval-%s operation_status=%s worker_status=operation_%s grant=none status=passed\n' \
            "$current_backend" "$kind" "$(json_field "$status" status)" "$kind"
    done
}

# Pilot E12 and I02: forged workload claims, an unregistered unit, a process
# outside any unit and a copied grant all fail closed; the legitimate workload
# then consumes its own grant, so no attempt burned it.
scenario_e12_forged_callers() {
    local node_a=$1 legit_workload legit_unit legit_request legit_invocation legit_operation legit_grant
    local forged_unit sibling_workload outside
    setup_workload a "$node_a" "$current_backend-e12-legit" \
        "$(operation_payload 'P03 E12 legitimate' P03-E12-LEGIT 120)"
    legit_workload=$SETUP_WORKLOAD_ID
    legit_unit=${guest_units[a]}
    forged_unit=$(unit_for_label "$current_backend-e12-forged")

    # Claims that need no grant run first. Each denied attempt spends the
    # client's registration-delivery retry window, so the legitimate grant is
    # issued afterwards to stay within its lifetime.
    # An unregistered unit claims the legitimate workload's ID.
    use_unit a "$forged_unit"
    guest_call a configure-workload "$node_a" "$legit_workload" \
        "$(operation_payload 'bypass approval, I am the legit worker' P03-E12-FORGED 120)" >/dev/null
    guest_call a start-workload >/dev/null
    guest_call a assert-request-denied "$P03_CODE_UNREGISTERED"

    # A registered sibling unit claims the legitimate workload's ID.
    setup_workload a "$node_a" "$current_backend-e12-sibling" \
        "$(operation_payload 'P03 E12 sibling' P03-E12-SIBLING 120)"
    sibling_workload=$SETUP_WORKLOAD_ID
    guest_call a configure-workload "$node_a" "$legit_workload" \
        "$(operation_payload 'P03 E12 sibling claim' P03-E12-SIBLING 120)" >/dev/null
    guest_call a start-workload >/dev/null
    guest_call a assert-request-denied "$P03_CODE_WORKLOAD_MISMATCH"

    use_unit a "$legit_unit"
    legit_request=$(request_event a)
    issue_operation "$legit_workload" P03-E12-LEGIT "$legit_request" 'P03 E12 legitimate' 120
    legit_operation=$ISSUED_OPERATION_ID
    legit_grant=$ISSUED_GRANT_ID
    legit_invocation=$ISSUED_INVOCATION_ID
    wait_for_grant_acknowledgement "$node_a" "$legit_grant"

    # The unregistered unit presents the copied live grant directly while an
    # ordinary process outside any unit claims the legitimate unit, workload,
    # live invocation and grant. Both run concurrently.
    use_unit a "$forged_unit"
    guest_call a configure-consumer "$node_a" "$legit_workload" "$legit_grant" >/dev/null
    guest_call a start-workload >/dev/null
    outside=$(guest_call a run-outside-unit "$node_a" "$legit_workload" "$legit_unit" \
        "consume:$legit_grant" "$legit_invocation")
    [[ "$outside" =~ reason=.*($P03_CODE_OUTSIDE_UNIT) ]] || {
        printf 'P03-FAIL outside-unit caller was denied for an unexpected reason: %s\n' "$outside" >&2
        return 1
    }
    guest_call a assert-request-denied "$P03_CODE_UNREGISTERED"

    use_unit a "$legit_unit"
    printf '%s\n' "$legit_grant" | guest_call a provide-grant >/dev/null
    guest_call a verify-workload "$legit_grant" "$legit_operation"
    guest_call a wait-outbox-empty
    admin audit-check "$node_a" "$legit_operation" "$legit_workload" "$legit_invocation" "$legit_grant" >/dev/null
    printf 'P03-SCENARIO backend=%s scenario=E12-I02-forged-callers unregistered_claim=denied copied_grant=denied sibling_claim=denied outside_unit=denied legit_completed=true sibling_workload=%s status=passed\n' \
        "$current_backend" "$sibling_workload"
}

# Pilot E11: parallel requests from two nodes and four workloads. Each grant
# completes once under its own identity; a consumed grant presented by another
# workload is denied.
scenario_e11_parallel() {
    local node_a=$1 node_b=$2 guest label index
    local -a guests=(a a b b) nodes=("$node_a" "$node_a" "$node_b" "$node_b")
    local -a units=() workloads=() requests=() operations=() grants=() invocations=()
    for index in 0 1 2 3; do
        guest=${guests[$index]}
        label="$current_backend-e11-$guest$index"
        setup_workload "$guest" "${nodes[$index]}" "$label" \
            "$(operation_payload "P03 E11 $index" "P03-E11-$index" 120)"
        workloads[index]=$SETUP_WORKLOAD_ID
        units[index]=${guest_units[$guest]}
    done
    for index in 0 1 2 3; do
        use_unit "${guests[$index]}" "${units[$index]}"
        guest_call "${guests[$index]}" start-workload >/dev/null
    done
    for index in 0 1 2 3; do
        use_unit "${guests[$index]}" "${units[$index]}"
        requests[index]=$(guest_call "${guests[$index]}" wait-request)
    done
    for index in 0 1 2 3; do
        issue_operation "${workloads[$index]}" "P03-E11-$index" "${requests[$index]}" "P03 E11 $index" 120
        operations[index]=$ISSUED_OPERATION_ID
        grants[index]=$ISSUED_GRANT_ID
        invocations[index]=$ISSUED_INVOCATION_ID
    done
    for index in 0 1 2 3; do
        wait_for_grant_acknowledgement "${nodes[$index]}" "${grants[$index]}"
    done
    for index in 0 1 2 3; do
        use_unit "${guests[$index]}" "${units[$index]}"
        printf '%s\n' "${grants[$index]}" | guest_call "${guests[$index]}" provide-grant >/dev/null
    done
    for index in 0 1 2 3; do
        use_unit "${guests[$index]}" "${units[$index]}"
        guest_call "${guests[$index]}" verify-workload "${grants[$index]}" "${operations[$index]}" >/dev/null
    done
    guest_call a wait-outbox-empty >/dev/null
    guest_call b wait-outbox-empty >/dev/null
    for index in 0 1 2 3; do
        admin audit-check "${nodes[$index]}" "${operations[$index]}" "${workloads[$index]}" \
            "${invocations[$index]}" "${grants[$index]}" >/dev/null
        guest_call "${guests[$index]}" assert-consumed-once "${grants[$index]}" >/dev/null
    done
    # Workload 1 presents workload 0's consumed grant from its own unit.
    use_unit a "${units[1]}"
    guest_call a configure-consumer "$node_a" "${workloads[1]}" "${grants[0]}" >/dev/null
    guest_call a start-workload >/dev/null
    guest_call a assert-consume-denied "${grants[0]}" grant_consumed
    guest_call a assert-consumed-once "${grants[0]}" >/dev/null
    printf 'P03-SCENARIO backend=%s scenario=E11-parallel-two-nodes workloads=4 completed=4 cross_identity_reuse=denied status=passed\n' \
        "$current_backend"
}

# Pilot E07 and O01: the controller hangs, then restarts. The broker keeps
# requests locally, a held grant stops authorizing at expiry, the relay does
# not enter a restart loop, and work resumes after recovery.
scenario_e07_controller_outage() {
    local node_a=$1 held_workload held_unit held_request held_grant held_expiry
    local queued_workload queued_unit queued_request outage_started outage_ms resumed_ms
    # Register both workloads first; each signed registration must reach the
    # broker before the controller hangs (one poll delivers, the next acks).
    setup_workload a "$node_a" "$current_backend-e07-queued" \
        "$(operation_payload 'P03 E07 queued request' P03-E07-QUEUED 60)"
    queued_workload=$SETUP_WORKLOAD_ID
    queued_unit=${guest_units[a]}
    setup_workload a "$node_a" "$current_backend-e07-held" \
        "$(operation_payload 'P03 E07 held grant' P03-E07-HELD 30)"
    held_workload=$SETUP_WORKLOAD_ID
    held_unit=${guest_units[a]}
    wait_for_fresh_poll "$node_a" "$(now_ms)"
    wait_for_fresh_poll "$node_a" "$(now_ms)"
    held_request=$(request_event a)
    issue_operation "$held_workload" P03-E07-HELD "$held_request" 'P03 E07 held grant' 30
    held_grant=$ISSUED_GRANT_ID
    wait_for_grant_acknowledgement "$node_a" "$held_grant"
    held_expiry=$(json_field "$(admin grant-status "$held_grant")" expires_at)

    outage_started=$(now_ms)
    (( outage_started + 5000 < held_expiry )) || {
        printf 'P03-FAIL E07 held grant was not live when the controller outage began\n' >&2
        return 1
    }
    kill -STOP "$controller_pid"
    use_unit a "$queued_unit"
    queued_request=$(request_event a)
    use_unit a "$held_unit"
    while (( $(now_ms) < held_expiry + 5000 )); do sleep 1; done
    printf '%s\n' "$held_grant" | guest_call a provide-grant >/dev/null
    guest_call a assert-consume-denied "$held_grant" 'grant_expired|trusted_time_unavailable'
    guest_call a assert-node-channel-stable >/dev/null
    kill -CONT "$controller_pid"
    outage_ms=$(( $(now_ms) - outage_started ))
    resumed_ms=$(now_ms)
    wait_for_fresh_poll "$node_a" "$resumed_ms"

    # The request the broker observed during the outage is older than the
    # one-minute evidence window: it cannot be approved after recovery and
    # the worker must request again. No access widens across the outage.
    use_unit a "$queued_unit"
    local stale_attempt
    if stale_attempt=$(admin request-operation "$queued_workload" \
        "$(sed -n 's/.*event_key=\([A-Za-z0-9_-]*\).*/\1/p' <<<"$queued_request")" \
        "$(sed -n 's/.*invocation=\([a-f0-9]*\).*/\1/p' <<<"$queued_request")" \
        P03-E07-QUEUED 'P03 E07 queued request' 60 2>&1); then
        printf 'P03-FAIL a request observed during the outage was accepted after recovery\n' >&2
        return 1
    fi
    [[ "$stale_attempt" == *'409 broker_evidence_stale'* ]] || {
        printf 'P03-FAIL outage request was rejected for an unexpected reason: %s\n' "$stale_attempt" >&2
        return 1
    }
    guest_call a stop-workload >/dev/null
    local fresh_request
    fresh_request=$(request_event a)
    complete_operation a "$node_a" "$queued_workload" P03-E07-QUEUED "$fresh_request" 'P03 E07 queued request'
    printf 'P03-SCENARIO backend=%s scenario=E07-controller-hang outage_ms=%s grant_live_at_outage_ms=%s held_grant_after_expiry=denied outage_request=stale_rejected fresh_request_completed=true node_restarts=0 status=passed\n' \
        "$current_backend" "$outage_ms" "$(( held_expiry - outage_started ))"

    stop_pid "$controller_pid"
    wait "$controller_pid" 2>/dev/null || true
    start_controller
    resumed_ms=$(now_ms)
    wait_for_fresh_poll "$node_a" "$resumed_ms"
    guest_call a assert-node-channel-stable >/dev/null
    setup_workload a "$node_a" "$current_backend-o01-restart" \
        "$(operation_payload 'P03 O01 controller restart' P03-O01-RESTART 60)"
    local restart_request restart_workload=$SETUP_WORKLOAD_ID
    restart_request=$(request_event a)
    complete_operation a "$node_a" "$restart_workload" P03-O01-RESTART "$restart_request" 'P03 O01 controller restart'
    printf 'P03-SCENARIO backend=%s scenario=O01-controller-restart channel_recovered=true operation_completed=true status=passed\n' \
        "$current_backend"
}

# Pilot E01 exposure check: no private node key material reaches controller
# state or logs. A visible canary placed in an operation purpose is the
# positive control, so an empty or unreadable dump cannot pass.
scenario_e01_key_exposure() {
    local node_a=$1 canary_file=$backend_dir/key-canaries dump=$backend_dir/controller-state.txt
    local visible_canary="P03VISIBLE$(openssl rand -hex 12)"
    setup_workload a "$node_a" "$current_backend-e01-canary" \
        "$(operation_payload "P03 canary $visible_canary" P03-E01-CANARY 60)"
    local canary_request canary_workload=$SETUP_WORKLOAD_ID
    canary_request=$(request_event a)
    complete_operation a "$node_a" "$canary_workload" P03-E01-CANARY "$canary_request" "P03 canary $visible_canary"
    local identities_a identities_b patterns
    : >"$canary_file"
    chmod 0600 "$canary_file"
    guest_call a key-canaries >>"$canary_file"
    identities_a=$(awk '$1 == "identities" {print $2}' "$canary_file")
    guest_call b key-canaries >>"$canary_file"
    identities_b=$(awk '$1 == "identities" {n = $2} END {print n}' "$canary_file")
    # Guest a holds its live identity and the identity archived by E02.
    [[ "$identities_a" =~ ^[0-9]+$ && "$identities_b" =~ ^[0-9]+$ ]] \
        && ((identities_a >= 2 && identities_b >= 1)) || {
        printf 'P03-FAIL guest key canaries are missing an identity\n' >&2
        return 1
    }
    patterns=$(( (identities_a + identities_b) * 8 ))
    [[ $(grep -c '^secret ' "$canary_file") == "$patterns" ]] || {
        printf 'P03-FAIL guest key canaries are incomplete\n' >&2
        return 1
    }
    rm -f -- "$dump"
    if [[ "$current_backend" == sqlite ]]; then
        python3 - "$backend_dir/controller.sqlite" "$dump" <<'PY'
import os
import sqlite3
import sys

connection = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
fd = os.open(sys.argv[2], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as out:
    for line in connection.iterdump():
        out.write(line + "\n")
connection.close()
PY
    else
        node "$repo_root/tests/fleet/p03-postgres.mjs" dump-text "$database_url_file" "$dump"
    fi
    cat "$backend_dir/controller.log" >>"$dump"
    grep -Fq "$visible_canary" "$dump" || {
        printf 'P03-FAIL exposure scanner positive control was not found in controller state\n' >&2
        return 1
    }
    local exposed
    exposed=$(awk '$1 == "secret" {print $2}' "$canary_file" | grep -F -c -f - "$dump" || true)
    [[ "$exposed" == 0 ]] || {
        printf 'P03-FAIL private node key material appeared in controller state or logs\n' >&2
        return 1
    }
    if [[ -n "${P07_RUN:-}" ]]; then
        # Register the guest private-key encodings, keep the state dump for the offline scan, and put the
        # intentionally visible value on a SEPARATE control list: scanning the exported state with that list
        # must find it (the scanner reads these formats), scanning with the real list must not.
        p07 secret-lines "$canary_file"
        p07 file state "p03-$current_backend-controller-state" "$dump"
        local control_file=$backend_dir/p07-control.canary
        printf '%s\n' "$visible_canary" >"$control_file"
        chmod 0600 "$control_file"
        P07_RUN="$P07_RUN/control" p07 text-canary "$control_file"
        rm -f -- "$control_file"
    fi
    rm -f -- "$canary_file" "$dump"
    printf 'P03-SCENARIO backend=%s scenario=E01-no-private-key-at-controller identities=%s patterns=%s positive_control=found exposed=0 status=passed\n' \
        "$current_backend" "$((identities_a + identities_b))" "$patterns"
}

# P03-I05 and pilot I08: the broker aborts after the durable consume intent
# and before the marker effect. systemd restarts it, no marker appears, the
# intent stays recorded once, and the controller records an uncertain result.
# Same-invocation retry after the crash is covered by broker unit tests; here
# systemd stops the dependent workload when the broker aborts.
scenario_i05_crash_after_intent() {
    local node_a=$1 crash_request crash_workload crash_operation crash_grant armed restarts_before status crash_epoch
    guest_call a enable-crash-hook >/dev/null
    wait_for_fresh_poll "$node_a" "$(now_ms)"
    setup_workload a "$node_a" "$current_backend-i05-crash" \
        "$(operation_payload 'P03 I05 crash after intent' P03-I05-CRASH 30)"
    crash_workload=$SETUP_WORKLOAD_ID
    crash_request=$(request_event a)
    issue_operation "$crash_workload" P03-I05-CRASH "$crash_request" 'P03 I05 crash after intent' 30
    crash_operation=$ISSUED_OPERATION_ID
    crash_grant=$ISSUED_GRANT_ID
    wait_for_grant_acknowledgement "$node_a" "$crash_grant"
    armed=$(guest_call a arm-crash-hook)
    restarts_before=${armed##*broker_restarts=}
    printf '%s\n' "$crash_grant" | guest_call a provide-grant >/dev/null
    crash_epoch=$(json_field "$(curl --silent --show-error --fail --max-time 5 \
        http://127.0.0.1:3200/api/v3/capabilities)" issuer_epoch)
    [[ "$crash_epoch" =~ ^[1-9][0-9]*$ ]] || { printf 'P03-FAIL malformed current issuer epoch\n' >&2; return 1; }
    guest_call a assert-crash-after-intent "$crash_grant" "$restarts_before" "$crash_operation" "$crash_epoch"
    # Retrying the same grant from a new invocation after the broker restart
    # must be refused by the durable consume intent, with no marker.
    printf '%s\n' "$crash_grant" | guest_call a provide-grant >/dev/null
    guest_call a start-workload >/dev/null
    guest_call a assert-consume-denied "$crash_grant" grant_consumed >/dev/null
    guest_call a wait-outbox-empty >/dev/null
    # The operation is executing until the 30-second grant deadline passes
    # without a completed result; the 30-second expiry sweep then marks it
    # uncertain.
    for _attempt in {1..450}; do
        status=$(json_field "$(admin operation-status "$crash_operation")" status)
        [[ "$status" == uncertain ]] && break
        sleep 0.2
    done
    [[ "$status" == uncertain ]] || {
        printf 'P03-FAIL crash between intent and effect left operation %s as %s\n' "$crash_operation" "$status" >&2
        return 1
    }
    guest_call a disable-crash-hook >/dev/null
    wait_for_fresh_poll "$node_a" "$(now_ms)"
    printf 'P03-SCENARIO backend=%s scenario=P03-I05-crash-after-consume-intent broker_restarted=true intent_records=1 retry_denied=grant_consumed marker_created=false operation_status=uncertain status=passed\n' \
        "$current_backend"
}

run_extended_scenarios() {
    local node_a=$1 node_b=$2 policy_json policy_version
    APPROVER_ID=$(json_field "$(admin ensure-approver)" operator_id)
    policy_json=$(admin policy)
    policy_version=$(json_field "$policy_json" version)
    guest_call b start-node >/dev/null
    wait_for_node_online "$node_b"
    guest_call a wait-policy-allows "$policy_version" >/dev/null
    guest_call b wait-policy-allows "$policy_version" >/dev/null

    if want_scenario e05; then scenario_e05_approval_closures "$node_a"; fi
    if want_scenario e12; then scenario_e12_forged_callers "$node_a"; fi
    if want_scenario e11; then scenario_e11_parallel "$node_a" "$node_b"; fi
    if want_scenario i05; then scenario_i05_crash_after_intent "$node_a"; fi
    if want_scenario e07; then scenario_e07_controller_outage "$node_a"; fi
    if want_scenario e01; then scenario_e01_key_exposure "$node_a"; fi
}

# Debugging aid: BLINDPASS_P03_EXTENDED_SCENARIOS narrows the stage only in an
# extended-only run, which never counts as acceptance evidence. Callers use
# `if`, never `&&`, so errexit stays active inside each scenario.
want_scenario() {
    [[ "${BLINDPASS_P03_EXTENDED_ONLY:-0}" == 1 && -n "${BLINDPASS_P03_EXTENDED_SCENARIOS:-}" ]] || return 0
    [[ " $BLINDPASS_P03_EXTENDED_SCENARIOS " == *" $1 "* ]]
}
