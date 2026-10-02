#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Guest side of tests/fleet/p05-backup.sh (P05-I05 / P05-E02 native restic job).
#
# NEVER RUN. The real restic and rest-server binaries are blocked pending human
# review (docs/product/decisions/0007-p05-native-backup-dependency-review.md).
# This script has only been checked with `bash -n` and the offline scanner
# self-test below; no subcommand that executes restic or rest-server has run.
#
# It is installed and driven by the host script, one subcommand per call. Every
# secret is a generated dummy canary read from files under /run/p05-source; no
# secret is placed in argv, and failure output never prints credential bytes.
set -Eeuo pipefail
umask 077

readonly SOURCE_DIR=${P05_SOURCE_DIR:-/run/p05-source}
readonly DATA_DIR=/srv/example-backup-data
readonly UNIT=example-backup.service
readonly NATIVE_UNIT=example-backup-native.service
readonly CREDENTIAL=restic-password
readonly RESTIC=/usr/local/bin/restic
readonly ENV_FILE=/etc/blindpass/example-backup.env
readonly BACKUP_HOST=example-backup
readonly NATIVE_CRED=/etc/blindpass/restic-password.cred

LAST_LOG=
LAST_STATUS=0

fail() {
    printf 'P05-GUEST-FAIL %s\n' "$1" >&2
    exit 1
}

note() {
    printf 'P05-GUEST %s\n' "$1"
}

# Prints a journal excerpt with every known canary line removed, so a failure
# diagnostic can never reproduce a credential.
safe_tail() {
    local text=$1
    if [[ -s $SOURCE_DIR/canaries ]]; then
        grep -vaF -f "$SOURCE_DIR/canaries" <<<"$text" | tail -n 25 || true
    else
        tail -n 25 <<<"$text"
    fi
}

repository_url() {
    sed -n 's/^RESTIC_REPOSITORY=//p' "$ENV_FILE"
}

# Operator-side restic (outside any unit): reads the password from a file the
# harness owns, never from argv or the environment.
operator_restic() {
    local password_file=$1
    shift
    RESTIC_REPOSITORY=$(repository_url) RESTIC_PASSWORD_FILE=$password_file \
        RESTIC_CACHE_DIR=/root/.cache/restic "$RESTIC" "$@"
}

current_password_file() {
    printf '%s/pw-current\n' "$SOURCE_DIR"
}

snapshot_count() {
    operator_restic "$(current_password_file)" snapshots --json --host "$BACKUP_HOST" \
        | python3 -c 'import json, sys; print(len(json.load(sys.stdin) or []))'
}

journal_cursor() {
    journalctl --sync >/dev/null 2>&1 || true
    journalctl --no-pager -n 1 --show-cursor -o cat 2>/dev/null | sed -n 's/^-- cursor: //p'
}

journal_since() {
    local cursor=$1 unit=$2
    journalctl --sync >/dev/null 2>&1 || true
    if [[ -n $cursor ]]; then
        journalctl --no-pager -o cat --after-cursor "$cursor" -u "$unit" 2>/dev/null || true
    else
        journalctl --no-pager -o cat -u "$unit" 2>/dev/null || true
    fi
}

# Start a oneshot unit and capture its status and the journal of this run.
run_unit() {
    local unit=$1 cursor
    cursor=$(journal_cursor)
    LAST_STATUS=0
    systemctl start "$unit" >/dev/null 2>&1 || LAST_STATUS=$?
    LAST_LOG=$(journal_since "$cursor" "$unit")
}

assert_no_staged_credential() {
    local unit=$1
    [[ ! -e /run/credentials/$unit/$CREDENTIAL ]] \
        || fail "$unit left its staged credential behind"
}

# ---- scanner ---------------------------------------------------------------

# Roots that must never hold a canary after the units have finished. The
# harness-owned oracle directory is excluded by name; the scan itself proves it
# can see a planted control value before the real result is accepted.
scan_roots() {
    if [[ -n ${P05_SCAN_ROOTS:-} ]]; then
        tr ':' '\n' <<<"$P05_SCAN_ROOTS"
    else
        printf '%s\n' /run /var/log /var/cache/example-backup /var/lib/blindpass \
            /var/lib/systemd /etc/blindpass /tmp /var/tmp /root/.cache
    fi
}

# Number of regular files below the scan roots that contain any pattern. grep
# exits 2 for an unreadable or vanished file; the positive control, not the exit
# status, is what proves the scan can see content.
scan_files() {
    local patterns=$1 root
    local -a roots=()
    while IFS= read -r root; do
        [[ -d $root ]] && roots+=("$root")
    done < <(scan_roots)
    ((${#roots[@]} > 0)) || fail 'no scan root exists'
    { grep -rlaF -D skip -s --exclude-dir=p05-source -f "$patterns" "${roots[@]}" 2>/dev/null || true; } | wc -l
}

# Number of live processes whose argv or environment contains any pattern.
scan_proc() {
    local patterns=$1 hits=0 file
    for file in /proc/[0-9]*/cmdline /proc/[0-9]*/environ; do
        [[ -r $file ]] || continue
        if grep -qaF -f "$patterns" -- "$file" 2>/dev/null; then
            hits=$((hits + 1))
        fi
    done
    printf '%s\n' "$hits"
}

# Positive control first (a planted file and a live process argument must be
# found), then the real canaries must be absent everywhere.
scan_canaries() {
    local patterns=$SOURCE_DIR/canaries control control_dir control_patterns files_hits proc_hits
    local control_pid
    [[ -s $patterns ]] || fail 'canary patterns are missing'
    control=P05-SCAN-CONTROL-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
    control_dir=${P05_CONTROL_DIR:-/run/p05-scan-control}
    control_patterns=$(mktemp "${TMPDIR:-/tmp}/p05-scan-control-patterns.XXXXXXXX")
    install -d -m 0700 "$control_dir"
    printf '%s\n' "$control" >"$control_patterns"
    printf '%s' "$control" >"$control_dir/control-file"
    # Two commands in -c prevent bash from exec-ing sleep, which would drop the
    # control token from the process arguments.
    P05_SCAN_CONTROL=$control bash -c 'sleep 30; :' "$control" &
    control_pid=$!
    sleep 0.2
    files_hits=$(scan_files "$control_patterns")
    proc_hits=$(scan_proc "$control_patterns")
    kill "$control_pid" 2>/dev/null || true
    wait "$control_pid" 2>/dev/null || true
    rm -rf -- "$control_dir" "$control_patterns"
    ((files_hits >= 1)) || fail 'canary file scanner missed its positive control'
    ((proc_hits >= 1)) || fail 'canary process scanner missed its positive control'
    files_hits=$(scan_files "$patterns")
    proc_hits=$(scan_proc "$patterns")
    ((files_hits == 0)) || fail "a canary was found in $files_hits file(s) below the scan roots"
    ((proc_hits == 0)) || fail "a canary was found in $proc_hits process argument/environment(s)"
    note 'canary scan files=clean proc=clean control=detected'
}

# ---- server guest (host A) -------------------------------------------------

cmd_server_start() {
    local port=${1:?port required}
    [[ $port =~ ^[0-9]+$ ]] || fail 'port must be an integer'
    install -m 0755 /tmp/p05/rest-server /usr/local/bin/rest-server
    id p05-rest >/dev/null 2>&1 \
        || useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin p05-rest
    install -d -m 0700 -o p05-rest -g p05-rest /var/lib/p05-rest
    cat >/etc/systemd/system/p05-rest-server.service <<UNIT
[Unit]
Description=P05 disposable rest-server (no authentication, test only)
After=network-online.target
[Service]
User=p05-rest
ExecStart=/usr/local/bin/rest-server --path /var/lib/p05-rest --listen :$port --no-auth
Restart=no
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/p05-rest
PrivateTmp=yes
UNIT
    systemctl daemon-reload
    systemctl start p05-rest-server.service
    for _attempt in {1..30}; do
        systemctl is-active --quiet p05-rest-server.service && break
        sleep 1
    done
    systemctl is-active --quiet p05-rest-server.service || fail 'rest-server did not start'
    note "rest-server active port=$port version=$(/usr/local/bin/rest-server --version 2>&1 | head -n 1)"
}

# ---- consumer guest (host B) ----------------------------------------------

cmd_consumer_prepare() {
    local repository=${1:?repository URL required}
    [[ $repository == rest:http://* ]] || fail 'repository must be a rest:http:// URL'
    install -d -m 0755 /usr/libexec /usr/local/bin /etc/blindpass /etc/systemd/system \
        /usr/lib/sysusers.d
    install -m 0755 /tmp/p05/blindpass-broker /usr/libexec/blindpass-broker
    install -m 0755 /tmp/p05/blindpass-provision /usr/libexec/blindpass-provision
    install -m 0755 /tmp/p05/restic "$RESTIC"
    install -m 0644 /tmp/p05/blindpass-broker.service /etc/systemd/system/blindpass-broker.service
    install -m 0644 /tmp/p05/example-backup.service /etc/systemd/system/example-backup.service
    install -m 0644 /tmp/p05/example-backup.timer /etc/systemd/system/example-backup.timer
    install -d -m 0755 /etc/systemd/system/blindpass-broker.service.d
    install -m 0644 /tmp/p05/native-backup-broker.conf \
        /etc/systemd/system/blindpass-broker.service.d/native-backup.conf
    install -m 0644 /tmp/p05/blindpass-workload.sysusers /usr/lib/sysusers.d/blindpass-workload.conf
    install -m 0644 /tmp/p05/blindpass-node.sysusers /usr/lib/sysusers.d/blindpass-node.conf
    systemd-sysusers /usr/lib/sysusers.d/blindpass-workload.conf /usr/lib/sysusers.d/blindpass-node.conf
    id blindpass-backup >/dev/null 2>&1 || fail 'sysusers did not create blindpass-backup'
    printf 'RESTIC_REPOSITORY=%s\n' "$repository" >"$ENV_FILE"
    chmod 0644 "$ENV_FILE"
    systemctl daemon-reload
    systemd-analyze verify /etc/systemd/system/example-backup.service \
        /etc/systemd/system/example-backup.timer \
        || fail 'systemd-analyze verify rejected an example unit'
    note 'example units verified by systemd-analyze in the guest'
}

# Derives the credential variants and the source data set from the generated
# canaries the host copied to /tmp/p05, then removes the staging copies.
cmd_make_fixtures() {
    install -d -m 0700 "$SOURCE_DIR"
    local name
    for name in pw-initial pw-rotated canary-json-marker; do
        [[ -s /tmp/p05/$name ]] || fail "staged $name is missing"
        install -m 0600 /tmp/p05/"$name" "$SOURCE_DIR/$name"
    done
    # Exact bytes, no trailing newline: the profile rejects anything else.
    printf '{"v":1,"password":"%s","marker":"%s"}' "$(<"$SOURCE_DIR/pw-initial")" \
        "$(<"$SOURCE_DIR/canary-json-marker")" >"$SOURCE_DIR/pw-json"
    printf '%s\n' "$(<"$SOURCE_DIR/pw-initial")" >"$SOURCE_DIR/pw-newline"
    head -c 1025 /dev/zero | tr '\0' a >"$SOURCE_DIR/pw-oversized"
    printf '\xff\xfe%s' "$(<"$SOURCE_DIR/pw-initial")" >"$SOURCE_DIR/pw-badutf8"
    : >"$SOURCE_DIR/pw-empty"
    cp -- "$SOURCE_DIR/pw-initial" "$SOURCE_DIR/pw-current"
    # Every canary the scans must not find: both passwords and the JSON marker.
    { cat -- "$SOURCE_DIR/pw-initial"; printf '\n'; cat -- "$SOURCE_DIR/pw-rotated"; printf '\n'; \
        cat -- "$SOURCE_DIR/canary-json-marker"; printf '\n'; } >"$SOURCE_DIR/canaries"
    rm -f -- /tmp/p05/pw-initial /tmp/p05/pw-rotated /tmp/p05/canary-json-marker
    # The fixed source tree: random artifact bytes plus text and a nested file.
    install -d -m 0750 -o root -g blindpass-backup "$DATA_DIR" "$DATA_DIR/nested"
    head -c 2097152 /dev/urandom >"$DATA_DIR/artifact.bin"
    printf 'p05 example backup note %s\n' "$(date --iso-8601=seconds)" >"$DATA_DIR/note.txt"
    head -c 4096 /dev/urandom >"$DATA_DIR/nested/small.bin"
    chown -R root:blindpass-backup "$DATA_DIR"
    chmod -R u=rwX,g=rX,o= "$DATA_DIR"
    (cd "$DATA_DIR" && find . -type f -print0 | sort -z | xargs -0 sha256sum) \
        >"$SOURCE_DIR/data.sha256"
    note "fixtures ready files=$(wc -l <"$SOURCE_DIR/data.sha256")"
}

# The server guest never sees a password; it only receives the canary list so the
# same file and process scans can prove that.
cmd_install_canaries() {
    install -d -m 0700 "$SOURCE_DIR"
    [[ -s /tmp/p05/canaries ]] || fail 'staged canary list is missing'
    install -m 0600 /tmp/p05/canaries "$SOURCE_DIR/canaries"
    rm -f -- /tmp/p05/canaries
}

cmd_init_repository() {
    operator_restic "$SOURCE_DIR/pw-initial" init >/dev/null
    operator_restic "$SOURCE_DIR/pw-initial" cat config >/dev/null \
        || fail 'repository is not readable with the initial password'
    note 'repository initialised by the operator with the initial password'
}

cmd_broker_start() {
    systemctl daemon-reload
    systemctl restart blindpass-broker.service
    for _attempt in {1..30}; do
        systemctl is-active --quiet blindpass-broker.service && break
        sleep 1
    done
    systemctl is-active --quiet blindpass-broker.service || fail 'broker did not become active'
    for _attempt in {1..20}; do
        [[ -S /run/blindpass/provision.sock && -S /run/blindpass/loader.sock ]] && break
        sleep 0.5
    done
    journalctl --sync >/dev/null 2>&1 || true
    journalctl -u blindpass-broker.service --no-pager -o cat -n 50 \
        | grep -Fq "credential profile $CREDENTIAL=password-file" \
        || fail 'broker did not report the password-file profile'
    note "broker active pid=$(systemctl show -p MainPID --value blindpass-broker.service) profile=password-file"
}

provision_from() {
    local name=$1
    [[ $name =~ ^pw-[a-z0-9]+$ ]] || fail 'invalid credential fixture name'
    /usr/libexec/blindpass-provision --unit "$UNIT" --credential "$CREDENTIAL" \
        <"$SOURCE_DIR/$name"
}

# Real HPKE provisioning of a valid value.
cmd_provision() {
    local name=${1:?fixture name required}
    provision_from "$name" >/dev/null || fail "provisioning $name was refused"
    note "provisioned $name through the HPKE path"
}

# A value the profile must refuse: the broker answers with the fixed code, and the
# previously provisioned value keeps working (checked by the next backup step).
cmd_provision_reject() {
    local name=${1:?fixture name required} code=${2:?expected code required}
    local output status=0
    output=$(provision_from "$name" 2>&1) || status=$?
    ((status != 0)) || fail "provisioning $name was unexpectedly accepted"
    grep -Fq -- "$code" <<<"$output" || fail "provisioning $name failed for another reason: $(safe_tail "$output")"
    note "provisioning $name refused with $code"
}

cmd_set_current() {
    local name=${1:?fixture name required}
    cp -- "$SOURCE_DIR/$name" "$SOURCE_DIR/pw-current"
}

cmd_backup_ok() {
    local label=${1:?label required} before after
    before=$(snapshot_count)
    run_unit "$UNIT" success
    ((LAST_STATUS == 0)) || fail "$label: unit failed: $(safe_tail "$LAST_LOG")"
    [[ $(systemctl show -p Result --value "$UNIT") == success ]] || fail "$label: unit result is not success"
    after=$(snapshot_count)
    ((after == before + 1)) || fail "$label: expected exactly one new snapshot (before=$before after=$after)"
    assert_no_staged_credential "$UNIT"
    note "$label backup ok snapshots_before=$before snapshots_after=$after"
}

# kind: missing = systemd could not load the credential (no restic ran);
#       stale   = restic ran its repository check and refused the password.
cmd_backup_denied() {
    local label=${1:?label required} kind=${2:?kind required} before after pattern
    case $kind in
        missing) pattern='Failed at step CREDENTIALS|status=243/CREDENTIALS|Failed to set up credentials' ;;
        stale) pattern='wrong password|no key found' ;;
        *) fail 'unknown denial kind' ;;
    esac
    before=$(snapshot_count)
    run_unit "$UNIT" failure
    ((LAST_STATUS != 0)) || fail "$label: the unit unexpectedly succeeded"
    grep -Eiq -- "$pattern" <<<"$LAST_LOG" \
        || fail "$label: failed for an unexpected reason: $(safe_tail "$LAST_LOG")"
    after=$(snapshot_count)
    ((after == before)) || fail "$label: a snapshot was created"
    assert_no_staged_credential "$UNIT"
    note "$label denied kind=$kind snapshots=$after"
}

cmd_restore_compare() {
    local label=${1:?label required} target
    target=/run/p05-restore-$label
    rm -rf -- "$target"
    operator_restic "$(current_password_file)" restore latest --host "$BACKUP_HOST" --target "$target" >/dev/null
    diff -r -- "$DATA_DIR" "$target$DATA_DIR" || fail "$label: restored tree differs"
    (cd "$target$DATA_DIR" && find . -type f -print0 | sort -z | xargs -0 sha256sum) \
        | cmp -s - "$SOURCE_DIR/data.sha256" || fail "$label: restored checksums differ"
    rm -rf -- "$target"
    note "$label restore compare ok bytes_identical=true"
}

# A larger incompressible file so a throttled job lasts long enough to log the
# operator out while restic is still uploading.
cmd_add_slow_artifact() {
    head -c 3145728 /dev/urandom >"$DATA_DIR/slow.bin"
    chown root:blindpass-backup "$DATA_DIR/slow.bin"
    chmod 0640 "$DATA_DIR/slow.bin"
    (cd "$DATA_DIR" && find . -type f -print0 | sort -z | xargs -0 sha256sum) \
        >"$SOURCE_DIR/data.sha256"
}

# Rotation: the repository password is changed in place with `restic key passwd`
# (an existing repository, no re-init); the old password must stop working.
cmd_rotate_repository_password() {
    "$RESTIC" key passwd --help 2>&1 | grep -q -- '--new-password-file' \
        || fail 'the pinned restic has no key passwd --new-password-file'
    operator_restic "$SOURCE_DIR/pw-initial" key passwd --new-password-file "$SOURCE_DIR/pw-rotated" >/dev/null
    if operator_restic "$SOURCE_DIR/pw-initial" cat config >/dev/null 2>&1; then
        fail 'the old repository password still authenticates after key passwd'
    fi
    operator_restic "$SOURCE_DIR/pw-rotated" cat config >/dev/null \
        || fail 'the rotated repository password does not authenticate'
    cp -- "$SOURCE_DIR/pw-rotated" "$SOURCE_DIR/pw-current"
    note 'repository password rotated with key passwd; the old password is refused'
}

cmd_broker_restart() {
    systemctl restart blindpass-broker.service
    for _attempt in {1..30}; do
        [[ -S /run/blindpass/provision.sock && -S /run/blindpass/loader.sock ]] \
            && systemctl is-active --quiet blindpass-broker.service && break
        sleep 0.5
    done
    systemctl is-active --quiet blindpass-broker.service || fail 'broker did not restart'
    note 'broker restarted; in-memory credentials discarded'
}

# Logout while a throttled backup is running. The job belongs to the system
# manager, not to the operator's login session, so it must finish unharmed.
cmd_logout_during_job() {
    local key=/run/p05-operator-key pid_before status_after before after tries
    id p05-operator >/dev/null 2>&1 || useradd --create-home --shell /bin/bash p05-operator
    printf 'p05-operator ALL=(root) NOPASSWD: /usr/bin/systemctl start --no-block %s\n' "$UNIT" \
        >/etc/sudoers.d/p05-operator
    chmod 0440 /etc/sudoers.d/p05-operator
    visudo -cf /etc/sudoers.d/p05-operator >/dev/null || fail 'operator sudoers file is invalid'
    rm -f -- "$key" "$key.pub"
    ssh-keygen -q -t ed25519 -N '' -f "$key"
    install -d -m 0700 -o p05-operator -g p05-operator /home/p05-operator/.ssh
    install -m 0600 -o p05-operator -g p05-operator "$key.pub" /home/p05-operator/.ssh/authorized_keys
    install -d -m 0755 /etc/systemd/system/example-backup.service.d
    # Throttle only for this step so the job outlives the operator session.
    cat >/etc/systemd/system/example-backup.service.d/p05-throttle.conf <<'DROPIN'
[Service]
ExecStart=
ExecStart=/usr/local/bin/restic backup --limit-upload 256 --host example-backup --tag blindpass-p05 /srv/example-backup-data
DROPIN
    systemctl daemon-reload
    before=$(snapshot_count)
    ssh -i "$key" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        p05-operator@127.0.0.1 \
        "sudo -n /usr/bin/systemctl start --no-block $UNIT; exec sleep 600" >/dev/null 2>&1 &
    local ssh_pid=$!
    tries=0
    until loginctl list-sessions --no-legend | awk '$3 == "p05-operator" { found = 1 } END { exit !found }'; do
        tries=$((tries + 1))
        ((tries <= 30)) || { kill "$ssh_pid" 2>/dev/null || true; fail 'operator login session never appeared'; }
        sleep 1
    done
    pid_before=0
    tries=0
    while [[ $pid_before == 0 ]]; do
        pid_before=$(systemctl show -p MainPID --value "$UNIT")
        tries=$((tries + 1))
        ((tries <= 60)) || fail 'the backup process never started'
        [[ $pid_before == 0 ]] && sleep 0.5
    done
    [[ $(systemctl show -p ActiveState --value "$UNIT") == activating ]] \
        || fail 'the backup finished before the operator logged out; enlarge the artifact'
    loginctl terminate-user p05-operator
    kill "$ssh_pid" 2>/dev/null || true
    wait "$ssh_pid" 2>/dev/null || true
    tries=0
    while loginctl list-sessions --no-legend | awk '$3 == "p05-operator" { found = 1 } END { exit !found }'; do
        tries=$((tries + 1))
        ((tries <= 30)) || fail 'the operator session did not end'
        sleep 1
    done
    # The job must still be the same process, or already finished successfully.
    if [[ $(systemctl show -p ActiveState --value "$UNIT") == activating ]]; then
        [[ $(systemctl show -p MainPID --value "$UNIT") == "$pid_before" ]] \
            || fail 'the backup process changed after the operator logged out'
    fi
    for _attempt in {1..180}; do
        [[ $(systemctl show -p ActiveState --value "$UNIT") != activating ]] && break
        sleep 1
    done
    status_after=$(systemctl show -p Result --value "$UNIT")
    [[ $status_after == success ]] || fail "the backup did not succeed after logout (result=$status_after)"
    after=$(snapshot_count)
    ((after == before + 1)) || fail "expected exactly one snapshot from the throttled job (before=$before after=$after)"
    rm -f -- /etc/systemd/system/example-backup.service.d/p05-throttle.conf
    rmdir /etc/systemd/system/example-backup.service.d 2>/dev/null || true
    systemctl daemon-reload
    note "operator logout during job ok main_pid=$pid_before result=success snapshots_before=$before snapshots_after=$after"
}

# ---- native encrypted-credential comparison -------------------------------

cmd_native_prepare() {
    command -v systemd-creds >/dev/null 2>&1 || {
        printf 'P05-UNSUPPORTED systemd-creds is unavailable for the native comparison\n' >&2
        exit 78
    }
    systemd-creds setup >/dev/null 2>&1 || fail 'systemd-creds setup failed'
    sed \
        -e 's#^LoadCredential=restic-password:/run/blindpass/loader.sock$#LoadCredentialEncrypted=restic-password:/etc/blindpass/restic-password.cred#' \
        -e '/^Requires=blindpass-broker.service$/d' \
        -e 's#^After=blindpass-broker.service network-online.target$#After=network-online.target#' \
        -e 's#^Description=.*#Description=BlindPass example restic backup with a native encrypted credential (comparison)#' \
        /etc/systemd/system/example-backup.service >/etc/systemd/system/$NATIVE_UNIT
    grep -q '^LoadCredentialEncrypted=restic-password:' /etc/systemd/system/$NATIVE_UNIT \
        || fail 'native unit derivation did not select the encrypted credential'
    ! grep -q 'loader.sock' /etc/systemd/system/$NATIVE_UNIT || fail 'native unit still names the broker socket'
    systemctl daemon-reload
    note 'native comparison unit derived from example-backup.service'
}

cmd_native_encrypt() {
    local name=${1:?fixture name required}
    [[ $name =~ ^pw-[a-z0-9]+$ ]] || fail 'invalid credential fixture name'
    systemd-creds --with-key=host --name="$CREDENTIAL" encrypt "$SOURCE_DIR/$name" "$NATIVE_CRED" \
        || fail 'systemd-creds encrypt failed'
    chmod 0600 "$NATIVE_CRED"
    note "native credential encrypted from $name with the host key (no TPM claim)"
}

cmd_native_backup_ok() {
    local label=${1:?label required} before after
    before=$(snapshot_count)
    run_unit "$NATIVE_UNIT" success
    ((LAST_STATUS == 0)) || fail "$label: native unit failed: $(safe_tail "$LAST_LOG")"
    after=$(snapshot_count)
    ((after == before + 1)) || fail "$label: expected exactly one new snapshot"
    assert_no_staged_credential "$NATIVE_UNIT"
    note "$label native backup ok snapshots_before=$before snapshots_after=$after"
}

cmd_native_backup_denied() {
    local label=${1:?label required} before after
    before=$(snapshot_count)
    run_unit "$NATIVE_UNIT" failure
    ((LAST_STATUS != 0)) || fail "$label: the native unit unexpectedly succeeded"
    grep -Eiq -- 'wrong password|no key found' <<<"$LAST_LOG" \
        || fail "$label: failed for an unexpected reason: $(safe_tail "$LAST_LOG")"
    after=$(snapshot_count)
    ((after == before)) || fail "$label: a snapshot was created"
    note "$label native denied (stale encrypted credential) snapshots=$after"
}

# ---- evidence --------------------------------------------------------------

cmd_journal_control() {
    local token unit
    token=P05-JOURNAL-CONTROL-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
    unit=p05-journal-control-$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')
    P05_JOURNAL_CONTROL=$token systemd-run --quiet --wait --collect --unit="$unit" \
        -E P05_JOURNAL_CONTROL /usr/bin/printenv P05_JOURNAL_CONTROL >/dev/null \
        || fail 'journal control unit failed'
    printf '%s\n' "$token"
}

cmd_journal_dump() {
    journalctl --sync >/dev/null 2>&1 || true
    journalctl --no-pager -o cat -b
}

cmd_versions() {
    printf 'P05-VERSIONS os=%s kernel=%s systemd=%s pid1=%s\n' \
        "$(. /etc/os-release && printf '%s-%s' "$ID" "$VERSION_ID")" "$(uname -r)" \
        "$(systemd --version | awk 'NR == 1 { print $2 }')" "$(ps -p 1 -o comm=)"
    [[ ! -x $RESTIC ]] || printf 'P05-VERSIONS restic=%s\n' "$("$RESTIC" version | head -n 1)"
    [[ ! -x /usr/local/bin/rest-server ]] \
        || printf 'P05-VERSIONS rest-server=%s\n' "$(/usr/local/bin/rest-server --version 2>&1 | head -n 1)"
    [[ ! -x /usr/libexec/blindpass-broker ]] || printf 'P05-VERSIONS broker_sha256=%s\n' \
        "$(sha256sum /usr/libexec/blindpass-broker | awk '{print $1}')"
}

main() {
    [[ $(id -u) == 0 ]] || fail 'guest harness requires root'
    [[ $(ps -p 1 -o comm=) == systemd ]] || {
        printf 'P05-UNSUPPORTED guest PID 1 is not systemd\n' >&2
        exit 78
    }
    local command=${1:-}
    shift || true
    case $command in
        server-start) cmd_server_start "$@" ;;
        consumer-prepare) cmd_consumer_prepare "$@" ;;
        make-fixtures) cmd_make_fixtures ;;
        install-canaries) cmd_install_canaries ;;
        init-repository) cmd_init_repository ;;
        broker-start) cmd_broker_start ;;
        broker-restart) cmd_broker_restart ;;
        provision) cmd_provision "$@" ;;
        provision-reject) cmd_provision_reject "$@" ;;
        set-current) cmd_set_current "$@" ;;
        backup-ok) cmd_backup_ok "$@" ;;
        backup-denied) cmd_backup_denied "$@" ;;
        restore-compare) cmd_restore_compare "$@" ;;
        add-slow-artifact) cmd_add_slow_artifact ;;
        rotate-repository-password) cmd_rotate_repository_password ;;
        logout-during-job) cmd_logout_during_job ;;
        native-prepare) cmd_native_prepare ;;
        native-encrypt) cmd_native_encrypt "$@" ;;
        native-backup-ok) cmd_native_backup_ok "$@" ;;
        native-backup-denied) cmd_native_backup_denied "$@" ;;
        scan-canaries) scan_canaries ;;
        journal-control) cmd_journal_control ;;
        journal-dump) cmd_journal_dump ;;
        versions) cmd_versions ;;
        *) fail "unknown subcommand: $command" ;;
    esac
}

# Allow `source`-ing for the offline scanner self-test without running anything.
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    main "$@"
fi
