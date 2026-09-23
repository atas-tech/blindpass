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
p01_started_at=$(date --iso-8601=seconds)
new_canary() {
    local label=$1
    printf 'P01-%s-%s' "$label" "$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
}
initial_canary=$(new_canary initial)
rotated_canary=$(new_canary rotated)
crash_canary=$(new_canary crash)
[[ "$initial_canary" != "$rotated_canary" ]] || {
    printf 'P01-FAIL generated rotation value matched the initial value\n' >&2
    exit 1
}
tpm_device=absent
if [[ -e /dev/tpmrm0 || -e /dev/tpm0 ]]; then
    tpm_device=present
fi
printf 'P01-GUEST-ENV os=%s kernel=%s systemd=%s pid1=%s tpm=%s\n' \
    "$guest_os" "$(uname -r)" "$guest_systemd" "$(ps -p 1 -o comm=)" "$tpm_device"

consumer_credential=/run/credentials/blindpass-consumer.service/api-key
backup_credential=/run/credentials/blindpass-backup.service/api-key
native_consumer_credential=/run/credentials/blindpass-consumer-native.service/api-key
native_backup_credential=/run/credentials/blindpass-backup-native.service/api-key

assert_canary_absent() {
    local expected_owner
    local mode
    local owner
    local mode_value
    local proc_cmdline
    local process_args
    for proc_cmdline in /proc/[0-9]*/cmdline; do
        [[ -r "$proc_cmdline" ]] || continue
        process_args=$(tr '\0' ' ' <"$proc_cmdline" 2>/dev/null || true)
        if [[ "$process_args" == *"$initial_canary"* || "$process_args" == *"$rotated_canary"* \
            || "$process_args" == *"$crash_canary"* ]]; then
            printf 'P01-FAIL a generated canary appeared in a process argument\n' >&2
            exit 1
        fi
    done
    if journalctl --since "$p01_started_at" --no-pager \
        | grep -F -f /run/blindpass-source/canary-patterns >/dev/null 2>&1; then
        printf 'P01-FAIL a generated canary appeared in the journal\n' >&2
        exit 1
    fi
    while IFS= read -r -d '' artifact; do
        [[ "$artifact" == /tmp/p01-guest.sh ]] && continue
        case "$artifact" in
            /run/credentials/blindpass-consumer.service/api-key|\
            /run/credentials/blindpass-consumer-native.service/api-key)
                expected_owner=$(id -u blindpass-consumer)
                ;;
            /run/credentials/blindpass-backup.service/api-key|\
            /run/credentials/blindpass-backup-native.service/api-key)
                expected_owner=$(id -u blindpass-backup)
                ;;
            /run/blindpass-loader-race/api-key)
                expected_owner=0
                ;;
            *) expected_owner= ;;
        esac
        if [[ -n "$expected_owner" ]]; then
            read -r mode owner < <(stat -c '%a %u' "$artifact")
            mode_value=$((8#$mode))
            [[ "$owner" == "$expected_owner" || "$owner" == 0 ]] \
                && (( (mode_value & 077) == 0 )) || {
                printf 'P01-FAIL credential file had unexpected owner or group/world access: %s\n' "$artifact" >&2
                exit 1
            }
            continue
        fi
        if grep -aF -f /run/blindpass-source/canary-patterns "$artifact" >/dev/null 2>&1; then
            printf 'P01-FAIL a generated canary appeared in runtime artifact %s\n' "$artifact" >&2
            exit 1
        fi
    done < <(
        find /tmp /var/tmp /var/crash /var/log /var/lib/systemd/coredump \
            /run/credentials /run/blindpass-consumer /run/blindpass-backup \
            /run/blindpass-backup-native \
            /run/blindpass-loader-race /run/blindpass-faults /run/blindpass-custody-probe \
            /run/blindpass-provision-probes /run/blindpass-crash-canary \
            /run/blindpass-unauthorized.key /run/blindpass-nonroot.key /run/blindpass-user-manager.log \
            -type f -size -1M -print0 2>/dev/null
    )
}

assert_broker_log_contains() {
    local expected=$1
    if ! journalctl -u blindpass-broker.service --since "$p01_started_at" --no-pager -o cat \
        | grep -F -- "$expected" >/dev/null; then
        printf 'P01-FAIL broker journal did not contain expected denial evidence: %s\n' "$expected" >&2
        journalctl -u blindpass-broker.service --since "$p01_started_at" --no-pager -o cat -n 100 >&2 || true
        exit 1
    fi
}

tpm_deb_dir=${BLINDPASS_P01_TPM_DEB_DIR:-}
if [[ -n "$tpm_deb_dir" ]]; then
    command -v dpkg >/dev/null 2>&1 || {
        printf 'P01-UNSUPPORTED dpkg is unavailable for the TPM runtime bundle\n' >&2
        exit 78
    }
    mapfile -t tpm_debs < <(find "$tpm_deb_dir" -maxdepth 1 -type f -name '*.deb' -print | sort)
    ((${#tpm_debs[@]} > 0)) || {
        printf 'P01-FAIL TPM runtime bundle has no .deb files\n' >&2
        exit 1
    }
    tpm_install_log=/run/blindpass-p01-tpm-install.log
    tpm_install_status=0
    dpkg --unpack "${tpm_debs[@]}" >"$tpm_install_log" 2>&1 || tpm_install_status=$?
    dpkg --configure -a >>"$tpm_install_log" 2>&1 || tpm_install_status=$?
    if [[ "$tpm_install_status" != 0 ]]; then
        printf 'P01-FAIL TPM runtime bundle could not be configured\n' >&2
        tail -n 40 "$tpm_install_log" >&2 || true
        exit 1
    fi
    printf 'P01-GUEST-TPM-PACKAGES installed=%s\n' \
        "$(dpkg-query -W -f='${db:Status-Abbrev} ${Package}=${Version}\n' 'libtss2*' tpm-udev 2>/dev/null \
            | awk '$1 == \"ii\" { print $2 }' | tr '\n' ' ' | sed 's/[[:space:]]*$//')"
fi

install -d -m 0755 /usr/libexec /etc/blindpass /etc/systemd/system
install -m 0755 /tmp/blindpass-broker /usr/libexec/blindpass-broker
install -m 0755 /tmp/blindpass-backup-probe /usr/libexec/blindpass-backup-probe
install -m 0755 /tmp/blindpass-consumer /usr/libexec/blindpass-consumer
install -m 0755 /tmp/blindpass-custody-probe /usr/libexec/blindpass-custody-probe
install -m 0755 /tmp/blindpass-crash-probe /usr/libexec/blindpass-crash-probe
install -m 0755 /tmp/blindpass-credential-loader /usr/libexec/blindpass-credential-loader
install -m 0755 /tmp/blindpass-provision /usr/libexec/blindpass-provision
install -m 0755 /tmp/blindpass-workload-client /usr/libexec/blindpass-workload-client
install -m 0755 /tmp/blindpass-transport-probe /usr/libexec/blindpass-transport-probe
install -m 0644 /tmp/blindpass-broker.service /etc/systemd/system/blindpass-broker.service
install -m 0644 /tmp/blindpass-backup.service /etc/systemd/system/blindpass-backup.service
install -m 0644 /tmp/blindpass-backup-native.service /etc/systemd/system/blindpass-backup-native.service
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

command -v systemd-sysusers >/dev/null 2>&1 || {
    printf 'P01-UNSUPPORTED systemd-sysusers is unavailable for the service-account setup\n' >&2
    exit 78
}
install -d -m 0755 /usr/lib/sysusers.d
install -m 0644 /tmp/blindpass-workload.sysusers /usr/lib/sysusers.d/blindpass-workload.conf
systemd-sysusers /usr/lib/sysusers.d/blindpass-workload.conf
for account in blindpass-agent blindpass-consumer blindpass-backup; do
    id "$account" >/dev/null 2>&1 || {
        printf 'P01-FAIL sysusers did not create %s\n' "$account" >&2
        exit 1
    }
done

umask 077
install -d -m 0700 /run/blindpass-source
printf '%s\n%s\n%s\n' "$initial_canary" "$rotated_canary" "$crash_canary" \
    >/run/blindpass-source/canary-patterns
chmod 0600 /run/blindpass-source/canary-patterns
printf '%s' "$initial_canary" >/run/blindpass-source/api-key
chmod 0600 /run/blindpass-source/api-key
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
workload_gid=$(getent group blindpass-workload | cut -d: -f3)
[[ -n "$workload_uid" ]] || { printf 'P01-FAIL workload uid unavailable\n' >&2; exit 1; }
[[ -n "$workload_gid" ]] || { printf 'P01-FAIL workload group id unavailable\n' >&2; exit 1; }

install -d -m 0755 /etc/systemd/system/blindpass-broker.service.d
write_workload_registration() {
    local registration_uid=${1:-$workload_uid}
    local registration_invocation=${2:-$invocation}
    local registration_unit=${3:-blindpass-workload.service}
    local registration_workload=${4:-workload-a}
    cat >/etc/systemd/system/blindpass-broker.service.d/p01-workload.conf <<UNIT
[Service]
ExecStart=
ExecStart=/usr/libexec/blindpass-broker --loader-socket /run/blindpass/loader.sock --workload-socket /run/blindpass/workload.sock --provision-socket /run/blindpass/provision.sock --workload-group blindpass-workload --map blindpass-consumer.service=api-key --map blindpass-backup.service=api-key --map blindpass-loader-race.service=api-key --workload node-a:$registration_workload:$registration_unit:$registration_uid:$registration_invocation
ExecStartPost=/bin/sh -c '/usr/libexec/blindpass-provision --unit blindpass-consumer.service --credential api-key < /run/blindpass-source/api-key'
ExecStartPost=/bin/sh -c '/usr/libexec/blindpass-provision --unit blindpass-backup.service --credential api-key < /run/blindpass-source/api-key'
ExecStartPost=/bin/sh -c '/usr/libexec/blindpass-provision --unit blindpass-loader-race.service --credential api-key < /run/blindpass-source/api-key'
UNIT
}
write_workload_registration
systemctl daemon-reload
if ! systemctl start blindpass-broker.service; then
    if journalctl -u blindpass-broker.service --no-pager -n 80 \
        | grep -Eq 'LIBSYSTEMD_[0-9]+|SO_PEERPIDFD unavailable|GetUnitByPIDFD unavailable'; then
        printf 'P01-UNSUPPORTED guest lacks the systemd pidfd API required by this broker profile\n' >&2
        journalctl -u blindpass-broker.service --no-pager -n 80 >&2 || true
        exit 78
    fi
    printf 'P01-FAIL broker start command failed\n' >&2
    systemctl status blindpass-broker.service --no-pager -l >&2 || true
    journalctl -u blindpass-broker.service --no-pager -n 80 >&2 || true
    exit 1
fi
systemctl is-active --quiet blindpass-broker.service || { printf 'P01-FAIL broker did not activate\n' >&2; exit 1; }
printf 'P01-SOCKET-POLICY directory=%s loader=%s workload=%s provision=%s\n' \
    "$(stat -c '%a:%u:%g' /run/blindpass)" \
    "$(stat -c '%a:%u:%g' /run/blindpass/loader.sock)" \
    "$(stat -c '%a:%u:%g' /run/blindpass/workload.sock)" \
    "$(stat -c '%a:%u:%g' /run/blindpass/provision.sock)"

if ((guest_systemd < 253)); then
    identity_probe_status=0
    /usr/libexec/blindpass-credential-loader --socket /run/blindpass/loader.sock \
        --unit blindpass-consumer.service --credential api-key \
        --output /run/blindpass-unsupported-credential \
        >/run/blindpass-unsupported-host.log 2>&1 || identity_probe_status=$?
    [[ "$identity_probe_status" != 0 ]] || {
        printf 'P01-FAIL older systemd host unexpectedly completed direct identity delivery\n' >&2
        exit 1
    }
    systemctl is-active --quiet blindpass-broker.service || {
        printf 'P01-FAIL older systemd host caused a broker startup/linker failure\n' >&2
        exit 1
    }
    if ! journalctl -u blindpass-broker.service --since "$p01_started_at" --no-pager -o cat \
        | grep -Eq 'unsupported_host:(SO_PEERPIDFD unavailable|systemd GetUnitByPIDFD unavailable)'; then
        printf 'P01-FAIL older systemd host did not report an explicit unsupported identity API\n' >&2
        journalctl -u blindpass-broker.service --since "$p01_started_at" --no-pager -o cat -n 80 >&2 || true
        exit 1
    fi
    [[ ! -e /run/blindpass-unsupported-credential ]] || {
        printf 'P01-FAIL unsupported host created a credential file\n' >&2
        exit 1
    }
    printf 'P01-UNSUPPORTED systemd %s lacks the P01 pidfd identity API; broker remained active and denied delivery\n' \
        "$guest_systemd" >&2
    exit 78
fi

install -d -m 0700 /run/blindpass-provision-probes
if runuser -u blindpass-consumer -- env BLINDPASS_P01_TEST_MODE=1 \
    /usr/libexec/blindpass-provision --unit blindpass-consumer.service --credential api-key \
    </run/blindpass-source/api-key >/run/blindpass-provision-probes/nonroot.log 2>&1; then
    printf 'P01-FAIL non-root provisioning reached the root-only socket\n' >&2
    exit 1
fi
printf 'P01-I05 non-root provisioning denied by socket mode: PASS\n'

if BLINDPASS_P01_TEST_MODE=1 /usr/libexec/blindpass-provision \
    --unit blindpass-unmapped.service --credential api-key \
    </run/blindpass-source/api-key >/run/blindpass-provision-probes/unmapped.log 2>&1; then
    printf 'P01-FAIL unmapped HPKE destination was provisioned\n' >&2
    exit 1
fi
assert_broker_log_contains 'identity:binding_mismatch:provision destination is not mapped'
printf 'P01-I05 unmapped provisioning destination denied: PASS\n'

for provision_fault in wrong-key tampered-ciphertext wrong-aad replay; do
    if ! BLINDPASS_P01_TEST_MODE=1 /usr/libexec/blindpass-provision \
        --unit blindpass-consumer.service --credential api-key --test-fault "$provision_fault" \
        </run/blindpass-source/api-key >"/run/blindpass-provision-probes/$provision_fault.log" 2>&1; then
        printf 'P01-FAIL live provisioning probe %s did not observe a broker denial\n' "$provision_fault" >&2
        cat "/run/blindpass-provision-probes/$provision_fault.log" >&2
        exit 1
    fi
    grep -F "P01-PROVISION-DENIED fault=$provision_fault response=ERR authentication_failed" \
        "/run/blindpass-provision-probes/$provision_fault.log" >/dev/null || {
        printf 'P01-FAIL live provisioning probe %s returned an unexpected denial\n' "$provision_fault" >&2
        cat "/run/blindpass-provision-probes/$provision_fault.log" >&2
        exit 1
    }
    assert_broker_log_contains 'crypto:authentication_failed'
done
printf 'P01-I05 live wrong-key, tampered, wrong-AAD and replay rejection: PASS\n'

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
identity_workload_trace=$(journalctl -u blindpass-broker.service --no-pager -o cat \
    | grep 'identity peer role=workload' \
    | grep 'unit=blindpass-workload.service' \
    | tail -n 1 || true)
[[ "$identity_workload_trace" =~ uid=$workload_uid\ gid=$workload_gid\ pidfd=true\ unit=blindpass-workload\.service\ invocation=[0-9a-f]{32} ]] || {
    printf 'P01-FAIL successful workload identity trace was not recorded\n' >&2
    printf 'P01-DIAG identity_workload_trace=%s\n' "$identity_workload_trace" >&2
    journalctl -u blindpass-broker.service --no-pager -o cat -n 80 >&2 || true
    exit 1
}
printf 'P01-I02 workload identity trace: PASS (%s)\n' "$identity_workload_trace"

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
[[ "$user_manager_ready" == yes ]] || {
    printf 'P01-UNSUPPORTED user-manager denial scenario could not start its user manager\n' >&2
    exit 78
}
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
    printf 'P01-FAIL user-manager scenario unexpectedly unavailable\n' >&2
    exit 1
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
stall_elapsed_ms=${stall_probe#*elapsed_ms=}
stall_elapsed_ms=${stall_elapsed_ms%% *}
[[ "$stall_elapsed_ms" =~ ^[0-9]+$ && "$stall_elapsed_ms" -le 2500 ]] || {
    printf 'P01-FAIL stalled-frame close took %s ms; expected at most 2000 ms plus 500 ms scheduling tolerance\n' \
        "$stall_elapsed_ms" >&2
    exit 1
}
printf 'P01-I04 stalled loader closed without payload: PASS (%s, max=2500ms)\n' "$stall_probe"

if ! systemctl start blindpass-consumer.service; then
    printf 'P01-DIAG initial consumer credential activation failed\n' >&2
    systemctl status blindpass-consumer.service --no-pager -l >&2 || true
    journalctl -u blindpass-consumer.service --since "$p01_started_at" --no-pager -o cat -n 80 >&2 || true
    journalctl -u blindpass-broker.service --since "$p01_started_at" --no-pager -o cat -n 120 >&2 || true
    exit 1
fi
systemctl is-active --quiet blindpass-consumer.service || { printf 'P01-FAIL consumer did not activate\n' >&2; exit 1; }
[[ "$(systemctl show --property=User --value blindpass-consumer.service)" == blindpass-consumer ]] || {
    printf 'P01-FAIL consumer unit did not use its dedicated account\n' >&2; exit 1;
}
[[ -s "$consumer_credential" ]] || {
    printf 'P01-FAIL systemd did not stage a non-empty consumer credential\n' >&2; exit 1;
}
cmp -s /run/blindpass-source/api-key "$consumer_credential" || {
    printf 'P01-FAIL staged consumer credential did not match the generated canary\n' >&2
    exit 1
}
printf 'P01-E01 systemd credential handoff to dedicated non-root consumer: PASS\n'
identity_loader_trace=$(journalctl -u blindpass-broker.service --since "$p01_started_at" --no-pager -o cat \
    | grep 'identity peer role=systemd-credential' \
    | grep 'unit=blindpass-consumer.service' \
    | grep 'credential=api-key' \
    | tail -n 1 || true)
consumer_invocation=$(systemctl show --property=InvocationID --value blindpass-consumer.service)
[[ -n "$consumer_invocation" && "$identity_loader_trace" == *"uid=0 gid=0 pidfd=true unit=blindpass-consumer.service invocation=$consumer_invocation credential=api-key"* ]] || {
    printf 'P01-FAIL successful loader identity trace was not recorded\n' >&2
    printf 'P01-DIAG identity_loader_trace=%s\n' "$identity_loader_trace" >&2
    journalctl -u blindpass-broker.service --no-pager -o cat -n 80 >&2 || true
    exit 1
}
printf 'P01-I02 loader identity trace: PASS (%s)\n' "$identity_loader_trace"
systemctl restart blindpass-consumer.service
systemctl is-active --quiet blindpass-consumer.service || {
    printf 'P01-FAIL systemd did not re-request the credential after consumer restart\n' >&2
    exit 1
}
printf 'P01-I01 systemd re-requested credential after consumer restart: PASS\n'

install -d -m 0700 /run/blindpass-loader-race
cat >/etc/systemd/system/blindpass-broker.service.d/p01-lookup-delay.conf <<'UNIT'
[Service]
Environment=BLINDPASS_P01_TEST_MODE=1
Environment=BLINDPASS_P01_IDENTITY_LOOKUP_DELAY_MS=900
UNIT
systemctl daemon-reload
systemctl reset-failed blindpass-broker.service >/dev/null 2>&1 || true
systemctl restart blindpass-broker.service
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
    loader_race_started_at=$(date --iso-8601=seconds)
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
    old_peer_denial=
    for _attempt in {1..30}; do
        old_peer_denial=$(journalctl -u blindpass-broker.service --since "$loader_race_started_at" --no-pager -o cat \
            | grep -F "loader request denied: os_identity:peer_exited unit=blindpass-loader-race.service invocation=$loader_old_invocation" \
            | tail -n 1 || true)
        [[ -n "$old_peer_denial" ]] && break
        sleep 0.1
    done
    [[ -n "$old_peer_denial" ]] || {
        printf 'P01-FAIL delayed pidfd lookup did not deny the pre-restart peer after it exited (round=%s)\n' \
            "$loader_race_round" >&2
        journalctl -u blindpass-broker.service --since "$p01_started_at" --no-pager -o cat -n 80 >&2 || true
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
    cmp -s /run/blindpass-source/api-key /run/blindpass-loader-race/api-key || {
        printf 'P01-FAIL replacement direct helper did not receive the generated canary (round=%s)\n' \
            "$loader_race_round" >&2
        exit 1
    }
    identity_loader_trace=$(journalctl -u blindpass-broker.service --since "$p01_started_at" --no-pager -o cat \
        | grep 'identity peer role=loader' \
        | grep "unit=blindpass-loader-race.service invocation=$loader_new_invocation" \
        | tail -n 1 || true)
    [[ "$identity_loader_trace" =~ uid=0\ gid=0\ pidfd=true\ unit=blindpass-loader-race\.service\ invocation=$loader_new_invocation ]] || {
        printf 'P01-FAIL direct helper identity did not match the replacement invocation (round=%s)\n' \
            "$loader_race_round" >&2
        journalctl -u blindpass-broker.service --since "$p01_started_at" --no-pager -o cat -n 80 >&2 || true
        exit 1
    }
    printf 'P01-I01 lookup-after-exit denied old peer and replacement delivered: PASS (round=%s old_pid=%s new_pid=%s)\n' \
        "$loader_race_round" "$loader_old_pid" "$loader_new_pid"
done
rm -f /etc/systemd/system/blindpass-broker.service.d/p01-lookup-delay.conf
systemctl daemon-reload
systemctl reset-failed blindpass-broker.service >/dev/null 2>&1 || true
systemctl restart blindpass-broker.service
systemctl stop blindpass-loader-race.service >/dev/null 2>&1 || true
rm -f /etc/systemd/system/blindpass-loader-race.service
systemctl daemon-reload

systemctl reset-failed blindpass-backup.service >/dev/null 2>&1 || true
systemctl start blindpass-backup.service
systemctl is-active --quiet blindpass-backup.service || {
    printf 'P01-FAIL disposable backup consumer did not activate\n' >&2
    exit 1
}
[[ "$(systemctl show --property=User --value blindpass-backup.service)" == blindpass-backup ]] || {
    printf 'P01-FAIL backup unit did not use its dedicated account\n' >&2
    exit 1
}
[[ -s "$backup_credential" ]] || {
    printf 'P01-FAIL systemd did not stage a non-empty backup credential\n' >&2
    exit 1
}
cmp -s /run/blindpass-source/api-key "$backup_credential" || {
    printf 'P01-FAIL staged backup credential did not match the generated canary\n' >&2
    exit 1
}
backup_restore=$(runuser -u blindpass-backup -- /usr/libexec/blindpass-backup-probe \
    --credential-file "$backup_credential" \
    --artifact /run/blindpass-backup/artifact --mode restore)
[[ "$backup_restore" == BACKUP_RESTORED ]] || {
    printf 'P01-FAIL disposable backup restore did not validate\n' >&2
    exit 1
}
backup_initial_artifact_hash=$(sha256sum /run/blindpass-backup/artifact | cut -d ' ' -f 1)
[[ "$(stat -c '%a:%u' /run/blindpass-backup/artifact)" == "600:$(id -u blindpass-backup)" ]] || {
    printf 'P01-FAIL disposable backup artifact permissions did not match backup account\n' >&2
    exit 1
}
printf 'P01-E01 credential-consuming backup write/restore: PASS (initial_artifact_sha256=%s)\n' \
    "$backup_initial_artifact_hash"

for delivery_fault in empty partial malformed oversized corrupt; do
    cat >/etc/systemd/system/blindpass-broker.service.d/p01-delivery-fault.conf <<UNIT
[Service]
Environment=BLINDPASS_P01_TEST_MODE=1
Environment=BLINDPASS_P01_DELIVERY_FAULT=$delivery_fault
UNIT
    systemctl daemon-reload
    systemctl stop blindpass-consumer.service >/dev/null 2>&1 || true
    systemctl reset-failed blindpass-consumer.service >/dev/null 2>&1 || true
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
    [[ ! -s "$consumer_credential" ]] || {
        printf 'P01-FAIL broker delivery fault %s left usable credential bytes\n' "$delivery_fault" >&2
        exit 1
    }
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
systemd-creds --with-key=host --name=api-key encrypt /run/blindpass-source/api-key "$native_credential_next" >/dev/null
install -m 0600 "$native_credential_next" "$native_credential"
rm -f "$native_credential_next"
systemctl daemon-reload
systemctl start blindpass-consumer-native.service
systemctl is-active --quiet blindpass-consumer-native.service || {
    printf 'P01-FAIL native encrypted credential consumer did not activate\n' >&2
    exit 1
}
systemctl start blindpass-backup-native.service
systemctl is-active --quiet blindpass-backup-native.service || {
    printf 'P01-FAIL native encrypted credential backup did not activate\n' >&2
    exit 1
}
cmp -s /run/blindpass-source/api-key "$native_consumer_credential" || {
    printf 'P01-FAIL native consumer did not receive the generated source value\n' >&2
    exit 1
}
cmp -s /run/blindpass-source/api-key "$native_backup_credential" || {
    printf 'P01-FAIL native backup did not receive the generated source value\n' >&2
    exit 1
}
[[ "$(systemctl show --property=User --value blindpass-consumer-native.service)" == blindpass-consumer \
    && "$(systemctl show --property=User --value blindpass-backup-native.service)" == blindpass-backup ]] || {
    printf 'P01-FAIL native comparison did not use the same dedicated service accounts\n' >&2
    exit 1
}
native_backup_restore=$(runuser -u blindpass-backup -- /usr/libexec/blindpass-backup-probe \
    --credential-file "$native_backup_credential" \
    --artifact /run/blindpass-backup-native/artifact --mode restore)
[[ "$native_backup_restore" == BACKUP_RESTORED ]] || {
    printf 'P01-FAIL initial native backup did not restore with its staged credential\n' >&2
    exit 1
}
native_initial_backup_hash=$(sha256sum /run/blindpass-backup-native/artifact | cut -d ' ' -f 1)
printf 'P01-E02 native host-key delivery and non-root backup: PASS (initial_artifact_sha256=%s)\n' \
    "$native_initial_backup_hash"
systemctl stop blindpass-consumer-native.service blindpass-backup-native.service
printf '%s' "$rotated_canary" >/run/blindpass-source/api-key
chmod 0600 /run/blindpass-source/api-key
systemd-creds --with-key=host --name=api-key encrypt /run/blindpass-source/api-key "$native_credential_next" >/dev/null
install -m 0600 "$native_credential_next" "$native_credential"
rm -f "$native_credential_next"
systemctl start blindpass-consumer-native.service
systemctl is-active --quiet blindpass-consumer-native.service || {
    printf 'P01-FAIL native encrypted credential rotation did not activate\n' >&2
    exit 1
}
systemctl start blindpass-backup-native.service
systemctl is-active --quiet blindpass-backup-native.service || {
    printf 'P01-FAIL native backup rotation did not activate\n' >&2
    exit 1
}
cmp -s /run/blindpass-source/api-key "$native_consumer_credential" || {
    printf 'P01-FAIL rotated native consumer did not receive the generated source value\n' >&2
    exit 1
}
cmp -s /run/blindpass-source/api-key "$native_backup_credential" || {
    printf 'P01-FAIL rotated native backup did not receive the generated source value\n' >&2
    exit 1
}
native_rotated_backup_hash=$(sha256sum /run/blindpass-backup-native/artifact | cut -d ' ' -f 1)
[[ "$native_rotated_backup_hash" != "$native_initial_backup_hash" ]] || {
    printf 'P01-FAIL native backup artifact did not change after credential rotation\n' >&2
    exit 1
}
native_backup_restore=$(runuser -u blindpass-backup -- /usr/libexec/blindpass-backup-probe \
    --credential-file "$native_backup_credential" \
    --artifact /run/blindpass-backup-native/artifact --mode restore)
[[ "$native_backup_restore" == BACKUP_RESTORED ]] || {
    printf 'P01-FAIL rotated native backup did not restore with its staged credential\n' >&2
    exit 1
}
printf 'P01-E02 native host-key rotation changed backup bytes and restored: PASS (rotated_artifact_sha256=%s)\n' \
    "$native_rotated_backup_hash"
native_host_key=/var/lib/systemd/credential.secret
native_recovery_plaintext=/run/blindpass-consumer/native-recovery
[[ -f "$native_host_key" ]] || {
    printf 'P01-FAIL native host-key profile did not create its protected key\n' >&2
    exit 1
}
mv "$native_host_key" "$native_host_key.p01-missing"
native_recovery_status=0
systemd-creds --no-ask-password --with-key=host decrypt \
    "$native_credential" "$native_recovery_plaintext" >/dev/null 2>&1 || native_recovery_status=$?
mv "$native_host_key.p01-missing" "$native_host_key"
rm -f "$native_recovery_plaintext"
[[ "$native_recovery_status" != 0 ]] || {
    printf 'P01-FAIL native encrypted credstore decrypted without its host key\n' >&2
    exit 1
}
printf 'P01-E02 native encrypted credstore missing-key recovery denial: PASS\n'

tpm_probe_status=0
tpm_capability=$(systemd-creds has-tpm2 2>&1) || tpm_probe_status=$?
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
tpm_encrypt_error=/run/blindpass-consumer/tpm2-encrypt.error
tpm_decrypt_error=/run/blindpass-consumer/tpm2-decrypt.error
install -d -m 0700 /run/blindpass-consumer
rm -f "$tpm_credential" "$tpm_plaintext"
: >"$tpm_encrypt_error"
: >"$tpm_decrypt_error"
tpm_encrypt_status=0
systemd-creds --with-key=tpm2 --name=api-key \
    encrypt /run/blindpass-source/api-key "$tpm_credential" >/dev/null 2>"$tpm_encrypt_error" \
    || tpm_encrypt_status=$?
tpm_decrypt_status=skipped
if [[ "$tpm_encrypt_status" == 0 ]]; then
    tpm_decrypt_status=0
    systemd-creds --with-key=tpm2 --name=api-key \
        decrypt "$tpm_credential" "$tpm_plaintext" >/dev/null 2>"$tpm_decrypt_error" \
        || tpm_decrypt_status=$?
fi
tpm_compare=no
if [[ "$tpm_encrypt_status" == 0 && "$tpm_decrypt_status" == 0 ]] &&
    cmp -s /run/blindpass-source/api-key "$tpm_plaintext"; then
    tpm_compare=yes
fi
if [[ "$tpm_encrypt_status" == 0 && "$tpm_decrypt_status" == 0 && "$tpm_compare" == yes ]]; then
    [[ "$tpm_device" == present ]] || {
        printf 'P01-FAIL TPM-required profile succeeded without a visible TPM device\n' >&2
        rm -f "$tpm_credential" "$tpm_plaintext"
        exit 1
    }
    printf 'P01-I06 TPM-required custody profile: PASS (device=%s probe_status=%s)\n' \
        "$tpm_device" "$tpm_probe_status"
elif [[ "$tpm_device" == present ]]; then
    tpm_encrypt_error_one_line=$(tr '\n' ' ' <"$tpm_encrypt_error" | tr -cs '[:alnum:]_.:/+-' '_' | cut -c1-240)
    tpm_decrypt_error_one_line=$(tr '\n' ' ' <"$tpm_decrypt_error" | tr -cs '[:alnum:]_.:/+-' '_' | cut -c1-240)
    printf 'P01-FAIL TPM device is present but explicit tpm2 encryption/recovery failed (encrypt_status=%s decrypt_status=%s compare=%s encrypt_error=%s decrypt_error=%s)\n' \
        "$tpm_encrypt_status" "$tpm_decrypt_status" "$tpm_compare" \
        "${tpm_encrypt_error_one_line:-none}" "${tpm_decrypt_error_one_line:-none}" >&2
    rm -f "$tpm_credential" "$tpm_plaintext"
    exit 1
else
    printf 'P01-I06 TPM-required custody profile: UNSUPPORTED (device absent; explicit tpm2 mode rejected; probe_status=%s available=%s)\n' \
        "$tpm_probe_status" "$tpm_probe_available"
fi
rm -f "$tpm_credential" "$tpm_plaintext" "$tpm_encrypt_error" "$tpm_decrypt_error"

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
assert_broker_log_contains 'identity:binding_mismatch:routing unit does not match authenticated unit'
printf 'P01-I02 mismatched loader routing: PASS\n'

cat >/etc/systemd/system/blindpass-unregistered.service <<'UNIT'
[Unit]
Description=BlindPass P01 unregistered workload probe
After=blindpass-broker.service
[Service]
Type=oneshot
User=blindpass-agent
Group=blindpass-workload
TimeoutStartSec=5s
ExecStart=/usr/libexec/blindpass-workload-client --socket /run/blindpass/workload.sock --node node-a --workload unregistered --unit blindpass-unregistered.service --operation health
UNIT
systemctl daemon-reload
if systemctl start blindpass-unregistered.service >/dev/null 2>&1; then
    printf 'P01-FAIL unregistered workload was accepted\n' >&2
    exit 1
fi
assert_broker_log_contains 'identity:unknown_registration'
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

cat >/etc/systemd/system/blindpass-crash.service <<'UNIT'
[Unit]
Description=BlindPass P01 core-artifact probe
[Service]
Type=oneshot
User=root
StandardInput=file:/run/blindpass-crash-canary
ExecStart=/usr/libexec/blindpass-crash-probe
LimitCORE=0
UNIT
systemctl daemon-reload
printf '%s' "$crash_canary" >/run/blindpass-crash-canary
chmod 0600 /run/blindpass-crash-canary
crash_started_at=$(date --iso-8601=seconds)
if systemctl start blindpass-crash.service >/dev/null 2>&1; then
    printf 'P01-FAIL crash probe unexpectedly exited successfully\n' >&2
    exit 1
fi
rm -f /run/blindpass-crash-canary
if command -v coredumpctl >/dev/null 2>&1; then
    crash_records=$(coredumpctl --no-pager --no-legend --since "$crash_started_at" 2>/dev/null \
        | grep -F -f /run/blindpass-source/canary-patterns || true)
    [[ -z "$crash_records" ]] || {
        printf 'P01-FAIL a generated canary appeared in coredump metadata\n' >&2
        exit 1
    }
fi
crash_artifact_count=0
while IFS= read -r -d '' crash_artifact; do
    crash_artifact_count=$((crash_artifact_count + 1))
    if grep -aF -f /run/blindpass-source/canary-patterns "$crash_artifact" >/dev/null 2>&1; then
        printf 'P01-FAIL crash canary appeared in artifact %s\n' "$crash_artifact" >&2
        exit 1
    fi
    rm -f -- "$crash_artifact"
done < <(find /var/crash /var/lib/systemd/coredump -type f \
    -newermt "$crash_started_at" -print0 2>/dev/null)
printf 'P01-I06 core-artifact canary review: PASS (reports_inspected=%s coredumpctl=%s)\n' \
    "$crash_artifact_count" "$(command -v coredumpctl >/dev/null 2>&1 && printf available || printf unavailable)"
assert_canary_absent

assert_canary_absent
printf 'P01-I06 initial canary absent from args/journals/runtime artifacts: PASS\n'

systemctl stop blindpass-backup.service blindpass-consumer.service
printf '%s' "$rotated_canary" >/run/blindpass-source/api-key
chmod 0600 /run/blindpass-source/api-key
systemctl reset-failed blindpass-broker.service >/dev/null 2>&1 || true
systemctl restart blindpass-broker.service
systemctl start blindpass-consumer.service
cmp -s /run/blindpass-source/api-key "$consumer_credential" || {
    printf 'P01-FAIL rotated broker consumer did not receive the generated value\n' >&2
    exit 1
}
printf 'P01-E01 controlled restart rotation: PASS\n'
systemctl reset-failed blindpass-backup.service >/dev/null 2>&1 || true
systemctl start blindpass-backup.service
backup_rotated_artifact_hash=$(sha256sum /run/blindpass-backup/artifact | cut -d ' ' -f 1)
[[ "$backup_rotated_artifact_hash" != "$backup_initial_artifact_hash" ]] || {
    printf 'P01-FAIL broker backup artifact did not change after credential rotation\n' >&2
    exit 1
}
cmp -s /run/blindpass-source/api-key "$backup_credential" || {
    printf 'P01-FAIL rotated broker backup did not receive the generated value\n' >&2
    exit 1
}
backup_restore=$(runuser -u blindpass-backup -- /usr/libexec/blindpass-backup-probe \
    --credential-file "$backup_credential" \
    --artifact /run/blindpass-backup/artifact --mode restore)
[[ "$backup_restore" == BACKUP_RESTORED ]] || {
    printf 'P01-FAIL rotated disposable backup restore did not validate\n' >&2
    exit 1
}
printf 'P01-E01 rotated credential changed backup bytes and restored: PASS (rotated_artifact_sha256=%s)\n' \
    "$backup_rotated_artifact_hash"
assert_canary_absent
printf 'P01-I06 rotated canary absent from args/journals/runtime artifacts: PASS\n'

systemctl stop blindpass-consumer.service blindpass-broker.service >/dev/null 2>&1 || true
cat >/etc/systemd/system/blindpass-broker.service.d/p01-api-removed.conf <<'UNIT'
[Service]
InaccessiblePaths=/run/dbus/system_bus_socket
UNIT
systemctl daemon-reload
systemctl reset-failed blindpass-broker.service >/dev/null 2>&1 || true
systemctl start blindpass-broker.service
systemctl is-active --quiet blindpass-broker.service || {
    printf 'P01-FAIL broker did not remain active with the system bus hidden\n' >&2
    exit 1
}
if systemctl start blindpass-consumer.service >/dev/null 2>&1; then
    printf 'P01-FAIL broker delivered after system-bus API removal\n' >&2
    exit 1
fi
systemctl is-active --quiet blindpass-broker.service || {
    printf 'P01-FAIL broker crashed instead of denying system-bus identity lookup\n' >&2
    exit 1
}
[[ ! -s "$consumer_credential" ]] || {
    printf 'P01-FAIL consumer material remained after system-bus API removal\n' >&2
    exit 1
}
assert_broker_log_contains 'unsupported_host:system bus unavailable'
printf 'P01-I03 system-bus API removal failed closed: PASS\n'
rm -f /etc/systemd/system/blindpass-broker.service.d/p01-api-removed.conf
systemctl daemon-reload
systemctl reset-failed blindpass-broker.service >/dev/null 2>&1 || true
if ! systemctl restart blindpass-broker.service; then
    printf 'P01-FAIL broker did not restart after restoring the system bus\n' >&2
    systemctl status blindpass-broker.service --no-pager -l >&2 || true
    journalctl -u blindpass-broker.service --since "$p01_started_at" --no-pager -o cat -n 120 >&2 || true
    exit 1
fi
systemctl reset-failed blindpass-consumer.service >/dev/null 2>&1 || true

cat >/etc/systemd/system/blindpass-broker.service.d/zz-p01-kernel-api-removed.conf <<'UNIT'
[Service]
SystemCallFilter=~getsockopt
SystemCallErrorNumber=ENOPROTOOPT
ExecStartPost=
UNIT
systemctl daemon-reload
systemctl reset-failed blindpass-broker.service >/dev/null 2>&1 || true
if ! systemctl restart blindpass-broker.service; then
    printf 'P01-FAIL broker did not restart under getsockopt denial\n' >&2
    systemctl status blindpass-broker.service --no-pager -l >&2 || true
    journalctl -u blindpass-broker.service --since "$p01_started_at" --no-pager -o cat -n 120 >&2 || true
    exit 1
fi
systemctl is-active --quiet blindpass-broker.service || {
    printf 'P01-FAIL broker did not become ready with peer-credential syscalls unavailable\n' >&2
    exit 1
}
if systemctl start blindpass-consumer.service >/dev/null 2>&1; then
    printf 'P01-FAIL broker delivered after getsockopt API removal\n' >&2
    exit 1
fi
systemctl is-active --quiet blindpass-broker.service || {
    printf 'P01-FAIL broker crashed instead of reporting unsupported peer identity\n' >&2
    exit 1
}
[[ ! -s "$consumer_credential" ]] || {
    printf 'P01-FAIL consumer material remained after getsockopt API removal\n' >&2
    exit 1
}
assert_broker_log_contains 'unsupported_host:SO_PEERCRED unavailable'
printf 'P01-I03 kernel socket-identity API removal failed closed: PASS\n'
rm -f /etc/systemd/system/blindpass-broker.service.d/zz-p01-kernel-api-removed.conf
systemctl daemon-reload
systemctl reset-failed blindpass-broker.service >/dev/null 2>&1 || true
systemctl restart blindpass-broker.service
systemctl reset-failed blindpass-consumer.service >/dev/null 2>&1 || true

cat >/etc/systemd/system/blindpass-broker.service.d/zz-p01-no-auto-provision.conf <<'UNIT'
[Service]
ExecStartPost=
UNIT
systemctl stop blindpass-consumer.service >/dev/null 2>&1 || true
systemctl daemon-reload
[[ -z "$(systemctl show --property=ExecStartPost --value blindpass-broker.service)" ]] || {
    printf 'P01-FAIL broker auto-provisioning remained enabled for the restart test\n' >&2
    exit 1
}
systemctl restart blindpass-broker.service
if systemctl start blindpass-consumer.service >/dev/null 2>&1; then
    printf 'P01-FAIL broker restart retained an ephemeral credential\n' >&2
    exit 1
fi
[[ ! -s "$consumer_credential" ]] || {
    printf 'P01-FAIL absent-key start left credential material\n' >&2
    exit 1
}
/usr/libexec/blindpass-provision --unit blindpass-consumer.service --credential api-key \
    </run/blindpass-source/api-key
systemctl reset-failed blindpass-consumer.service >/dev/null 2>&1 || true
systemctl start blindpass-consumer.service
printf 'P01-I05 live broker restart requires HPKE reprovisioning: PASS\n'
rm -f /etc/systemd/system/blindpass-broker.service.d/zz-p01-no-auto-provision.conf
systemctl daemon-reload

printf 'P01-I05 live broker HPKE provisioning and restart path: PASS\n'

cat >/etc/systemd/system/blindpass-broker.service.d/zz-p01-short-ttl.conf <<'UNIT'
[Service]
Environment=BLINDPASS_P01_TEST_MODE=1
Environment=BLINDPASS_P01_CUSTODY_KEY_TTL_MS=500
Environment=BLINDPASS_P01_CREDENTIAL_TTL_MS=2500
ExecStartPost=
UNIT
systemctl stop blindpass-consumer.service >/dev/null 2>&1 || true
systemctl daemon-reload
systemctl reset-failed blindpass-broker.service >/dev/null 2>&1 || true
systemctl restart blindpass-broker.service
if ! BLINDPASS_P01_TEST_MODE=1 /usr/libexec/blindpass-provision \
    --unit blindpass-consumer.service --credential api-key --test-fault expired-key \
    --test-delay-before-seal-ms 1200 </run/blindpass-source/api-key \
    >/run/blindpass-provision-probes/expired-key.log 2>&1; then
    printf 'P01-FAIL delayed live HPKE response did not report key expiry\n' >&2
    cat /run/blindpass-provision-probes/expired-key.log >&2
    exit 1
fi
grep -F 'P01-PROVISION-DENIED fault=expired-key response=ERR recipient_key_missing_or_expired' \
    /run/blindpass-provision-probes/expired-key.log >/dev/null || {
    printf 'P01-FAIL delayed live HPKE response had an unexpected expiry result\n' >&2
    cat /run/blindpass-provision-probes/expired-key.log >&2
    exit 1
}
assert_broker_log_contains 'crypto:recipient key missing or expired'
/usr/libexec/blindpass-provision --unit blindpass-consumer.service --credential api-key \
    </run/blindpass-source/api-key
systemctl reset-failed blindpass-consumer.service >/dev/null 2>&1 || true
systemctl start blindpass-consumer.service
cmp -s /run/blindpass-source/api-key "$consumer_credential" || {
    printf 'P01-FAIL short-TTL broker did not deliver the generated canary before expiry\n' >&2
    exit 1
}
systemctl stop blindpass-consumer.service
sleep 3
if systemctl start blindpass-consumer.service >/dev/null 2>&1; then
    printf 'P01-FAIL live credential remained usable after the configured expiry\n' >&2
    exit 1
fi
[[ ! -s "$consumer_credential" ]] || {
    printf 'P01-FAIL expired credential left usable bytes in the systemd credential directory\n' >&2
    exit 1
}
assert_broker_log_contains 'delivery:credential_missing'
printf 'P01-I05 live short-TTL HPKE key and credential expiry denial: PASS\n'
rm -f /etc/systemd/system/blindpass-broker.service.d/zz-p01-short-ttl.conf
systemctl daemon-reload
systemctl reset-failed blindpass-broker.service >/dev/null 2>&1 || true
systemctl restart blindpass-broker.service
systemctl reset-failed blindpass-consumer.service >/dev/null 2>&1 || true
systemctl start blindpass-consumer.service

printf 'P01-RETAINED-PROTECTED-MATERIAL /etc/blindpass/api-key.cred\n'

systemctl stop blindpass-stall.service blindpass-loader-nonroot.service blindpass-loader-race.service blindpass-unregistered.service blindpass-unauthorized.service blindpass-dynamic.service blindpass-crash.service blindpass-consumer.service blindpass-consumer-native.service blindpass-backup.service blindpass-backup-native.service blindpass-workload.service blindpass-broker.service >/dev/null 2>&1 || true
if [[ "$user_manager_ready" == yes ]]; then
    rm -f /run/blindpass-user-manager.log "$user_manager_runtime/p01-user-manager.key"
    systemctl stop "user@$user_manager_uid.service" "user-runtime-dir@$user_manager_uid.service" >/dev/null 2>&1 || true
fi
rm -f /run/blindpass/loader.sock /run/blindpass/workload.sock /run/blindpass/provision.sock
[[ ! -e /run/blindpass/loader.sock && ! -e /run/blindpass/workload.sock && ! -e /run/blindpass/provision.sock ]] || {
    printf 'P01-FAIL broker sockets remained after cleanup\n' >&2
    exit 1
}
[[ -f /run/blindpass-source/api-key && "$(stat -c '%a:%u' /run/blindpass-source/api-key)" == 600:0 ]] || {
    printf 'P01-FAIL protected material was not retained with root-only mode\n' >&2
    exit 1
}
[[ -f /etc/blindpass/api-key.cred && "$(stat -c '%a:%u' /etc/blindpass/api-key.cred)" == 600:0 ]] || {
    printf 'P01-FAIL encrypted native credential was not retained with root-only mode\n' >&2
    exit 1
}
rm -f /run/blindpass-unauthorized.key /run/blindpass-nonroot.key
rm -f /run/blindpass-crash-canary
rm -rf -- /run/blindpass-faults /run/blindpass-provision-probes /run/blindpass-consumer /run/blindpass-backup /run/blindpass-loader-race /run/blindpass-custody-probe
rm -rf -- /run/blindpass-backup-native /run/credentials/blindpass-consumer.service \
    /run/credentials/blindpass-backup.service /run/credentials/blindpass-consumer-native.service \
    /run/credentials/blindpass-backup-native.service
rm -f /usr/lib/sysusers.d/blindpass-workload.conf
rm -rf -- /run/blindpass-source
rm -f /etc/systemd/system/blindpass-broker.service \
    /etc/systemd/system/blindpass-backup.service \
    /etc/systemd/system/blindpass-backup-native.service \
    /etc/systemd/system/blindpass-consumer.service \
    /etc/systemd/system/blindpass-consumer-native.service \
    /etc/systemd/system/blindpass-workload.service \
    /etc/systemd/system/blindpass-stall.service \
    /etc/systemd/system/blindpass-loader-nonroot.service \
    /etc/systemd/system/blindpass-loader-race.service \
    /etc/systemd/system/blindpass-crash.service \
    /etc/systemd/system/blindpass-dynamic.service \
    /etc/systemd/system/blindpass-unauthorized.service \
    /etc/systemd/system/blindpass-unregistered.service
rm -rf -- /etc/systemd/system/blindpass-broker.service.d
rm -rf -- /etc/systemd/system/blindpass-workload.service.d
rm -f /usr/libexec/blindpass-broker /usr/libexec/blindpass-consumer \
    /usr/libexec/blindpass-backup-probe \
    /usr/libexec/blindpass-custody-probe \
    /usr/libexec/blindpass-crash-probe \
    /usr/libexec/blindpass-credential-loader /usr/libexec/blindpass-provision /usr/libexec/blindpass-workload-client \
    /usr/libexec/blindpass-transport-probe
systemctl daemon-reload
[[ ! -e /etc/systemd/system/blindpass-broker.service && ! -e /run/blindpass/loader.sock ]] || {
    printf 'P01-FAIL broker installation remained after uninstall\n' >&2
    exit 1
}
printf 'P01-GUEST-CLEANUP sockets_removed=yes units_removed=yes protected_material_retained=yes\n'
