#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# P05-I05 / P05-E02 two-host native restic backup harness.
#
# NEVER RUN. This harness is gated on reviewed restic and rest-server artifacts
# that do not exist yet: both are blocked pending human review
# (docs/product/decisions/0007-p05-native-backup-dependency-review.md). It has been
# checked statically with `bash -n` only, plus the artifact-gate exit paths below,
# which execute no restic or rest-server code. No result of this script exists, and
# nothing in it may be cited as P05-I05 or P05-E02 evidence until it has run
# against artifacts that ADR 0007 records as approved.
#
# Required environment (all four, or the script exits 77 before doing anything):
#   RESTIC_BIN, RESTIC_SHA256            restic binary and its reviewed SHA-256
#   REST_SERVER_BIN, REST_SERVER_SHA256  rest-server binary and its reviewed SHA-256
# Infrastructure, as for p03-vm.sh: BLINDPASS_FLEET_RUNNER_OWNER, readable pinned
# BLINDPASS_FLEET_GUEST_IMAGE with BLINDPASS_FLEET_GUEST_IMAGE_SHA256, QEMU/KVM,
# cloud-localds, cargo, node, ssh/scp/ssh-keygen. Optional ports:
#   BLINDPASS_P05_SSH_PORT_A (default 22242)  guest A: rest-server
#   BLINDPASS_P05_SSH_PORT_B (default 22243)  guest B: broker + backup consumer
#   BLINDPASS_P05_REST_PORT  (default 18000)  host loopback forward to guest A
#
# Exit codes: 0 pass, 1 failure, 2 usage, 77 blocked (artifacts), 78 unsupported
# infrastructure. `--check-artifacts` verifies only the artifact gate and exits 0.
#
# Rotation procedure under test: the repository password of the existing
# repository is changed with `restic key passwd`, then the new bytes are
# provisioned to the broker (or re-encrypted for the native baseline). That is the
# simplest verifiable rotation: no re-init, the old password must stop working, and
# a stale credential must be refused by the unit's own repository check. A new
# repository would only prove that re-init works.
set -Eeuo pipefail
umask 077

blocked() {
    printf 'blocked: reviewed restic/rest-server artifacts not provided (ADR 0007)\n' >&2
    [[ -z ${1:-} ]] || printf 'P05-BLOCKED-DETAIL %s\n' "$1" >&2
    exit 77
}

unsupported() {
    printf 'P05-UNSUPPORTED %s\n' "$1" >&2
    exit 78
}

usage() {
    printf 'usage: %s [--check-artifacts]\n' "$0"
}

check_only=0
while (($# > 0)); do
    case "$1" in
        --check-artifacts) check_only=1; shift ;;
        --help|-h) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
done

# The artifact gate runs first so exit 77 is the same on every machine. It only
# hashes the files; neither binary is executed here.
verify_artifact() {
    local label=$1 path=${2:-} expected=${3:-} actual
    [[ -n $path && -n $expected ]] || blocked "$label path or SHA-256 is not set"
    [[ $expected =~ ^[a-f0-9]{64}$ ]] || blocked "$label SHA-256 is not 64 lowercase hex digits"
    [[ -f $path && -x $path ]] || blocked "$label is not an executable regular file"
    actual=$(sha256sum -- "$path" | awk '{print $1}')
    [[ $actual == "$expected" ]] || blocked "$label SHA-256 does not match the reviewed value"
}
verify_artifact restic "${RESTIC_BIN:-}" "${RESTIC_SHA256:-}"
verify_artifact rest-server "${REST_SERVER_BIN:-}" "${REST_SERVER_SHA256:-}"
if ((check_only == 1)); then
    printf 'P05-ARTIFACTS-VERIFIED restic_sha256=%s rest_server_sha256=%s (hashed only, not executed)\n' \
        "$RESTIC_SHA256" "$REST_SERVER_SHA256"
    exit 0
fi

[[ $(id -u) != 0 ]] || unsupported 'run the host harness as the runner owner, not through sudo'
for tool in cargo node python3 qemu-system-x86_64 qemu-img ssh scp ssh-keygen sha256sum od tr; do
    command -v "$tool" >/dev/null 2>&1 || unsupported "$tool is unavailable in the runner-owner PATH"
done
[[ -e /dev/kvm && -r /dev/kvm && -w /dev/kvm ]] || unsupported '/dev/kvm is unavailable or inaccessible'
[[ -n ${BLINDPASS_FLEET_RUNNER_OWNER:-} ]] || unsupported 'BLINDPASS_FLEET_RUNNER_OWNER is unset'

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
guest_user=${BLINDPASS_FLEET_GUEST_USER:-blindpass}
guest_image=${BLINDPASS_FLEET_GUEST_IMAGE:-"${XDG_DATA_HOME:-$HOME/.local/share}/blindpass/vm-images/noble-server-cloudimg-amd64.img"}
guest_image_sha=${BLINDPASS_FLEET_GUEST_IMAGE_SHA256:-612b2c0cc1bc413a6cb8c38fd611794caf0f2b436c50013d8b3794db12ad7354}
ssh_port_a=${BLINDPASS_P05_SSH_PORT_A:-22242}
ssh_port_b=${BLINDPASS_P05_SSH_PORT_B:-22243}
rest_port=${BLINDPASS_P05_REST_PORT:-18000}
rest_guest_port=8000
declare -A guest_ports
guest_ports=([a]=$ssh_port_a [b]=$ssh_port_b)

[[ -r $guest_image ]] || unsupported 'pinned guest image is missing or unreadable'
[[ $guest_image_sha =~ ^[a-f0-9]{64}$ ]] || unsupported 'BLINDPASS_FLEET_GUEST_IMAGE_SHA256 is malformed'
actual_image_sha=$(sha256sum "$guest_image" | awk '{print $1}')
[[ $actual_image_sha == "$guest_image_sha" ]] || unsupported 'pinned guest image hash does not match'
for port in "$ssh_port_a" "$ssh_port_b" "$rest_port"; do
    [[ $port =~ ^[0-9]+$ ]] || { printf 'ports must be integers\n' >&2; exit 2; }
done
[[ $ssh_port_a != "$ssh_port_b" && $ssh_port_a != "$rest_port" && $ssh_port_b != "$rest_port" ]] \
    || { printf 'P05 ports must be distinct\n' >&2; exit 2; }

run_dir=$(mktemp -d "${TMPDIR:-/tmp}/blindpass-p05.XXXXXXXX")
chmod 0700 "$run_dir"
stage_dir=$run_dir/stage
install -d -m 0700 "$stage_dir"
ssh_key=$run_dir/ephemeral-ssh-key
cleanup_done=0
declare -a qemu_pidfiles=()

stop_pid() {
    local pid=${1:-}
    [[ $pid =~ ^[0-9]+$ ]] || return 0
    kill -TERM "$pid" 2>/dev/null || true
    for _attempt in {1..30}; do
        kill -0 "$pid" 2>/dev/null || return 0
        sleep 0.1
    done
    kill -KILL "$pid" 2>/dev/null || true
}

cleanup() {
    [[ $cleanup_done == 0 ]] || return
    cleanup_done=1
    local pidfile qemu_pid
    for pidfile in "${qemu_pidfiles[@]}"; do
        [[ -s $pidfile ]] || continue
        qemu_pid=$(<"$pidfile")
        stop_pid "$qemu_pid"
    done
    if [[ ${BLINDPASS_P05_KEEP_FAILED_ARTIFACTS:-0} == 1 && ${run_status:-0} != 0 ]]; then
        # Generated canaries, passwords and artifact copies never survive.
        rm -rf -- "$stage_dir" "$run_dir"/restic "$run_dir"/rest-server
        printf 'P05-FAILED-ARTIFACTS path=%s\n' "$run_dir" >&2
    else
        rm -rf -- "$run_dir"
    fi
}
trap 'run_status=$?; cleanup' EXIT
trap 'exit 143' INT TERM

fail() {
    printf 'P05-FAIL %s\n' "$1" >&2
    exit 1
}

step() {
    printf 'P05-STEP %s\n' "$*"
}

# Copy the artifacts into the private run directory and hash the copies, so the
# bytes that reach the guests are the bytes the gate approved.
install -m 0755 "$RESTIC_BIN" "$run_dir/restic"
install -m 0755 "$REST_SERVER_BIN" "$run_dir/rest-server"
[[ $(sha256sum "$run_dir/restic" | awk '{print $1}') == "$RESTIC_SHA256" ]] \
    || fail 'the staged restic copy does not match the reviewed SHA-256'
[[ $(sha256sum "$run_dir/rest-server" | awk '{print $1}') == "$REST_SERVER_SHA256" ]] \
    || fail 'the staged rest-server copy does not match the reviewed SHA-256'

ssh-keygen -q -t ed25519 -N '' -f "$ssh_key"
export BLINDPASS_FLEET_SSH_KEY="$ssh_key"
export BLINDPASS_FLEET_GUEST_IMAGE="$guest_image"
export BLINDPASS_FLEET_GUEST_IMAGE_SHA256="$guest_image_sha"
export BLINDPASS_FLEET_GUEST_USER="$guest_user"

printf 'P05-HOST-ENV runner_owner=%s qemu=%s kvm=%s image_sha256=%s rustc=%s node=%s\n' \
    "$BLINDPASS_FLEET_RUNNER_OWNER" "$(qemu-system-x86_64 --version | head -n 1)" \
    "$(stat -c '%A:%a' /dev/kvm)" "$actual_image_sha" "$(rustc --version)" "$(node --version)"
printf 'P05-ARTIFACTS restic_sha256=%s rest_server_sha256=%s (reviewed values; see ADR 0007)\n' \
    "$RESTIC_SHA256" "$REST_SERVER_SHA256"

cargo build --release -p blindpass-broker --locked

ssh_options=(-i "$ssh_key" -o BatchMode=yes -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null -o ConnectTimeout=3)
scp_options=("${ssh_options[@]}")

guest_ssh() {
    local guest=$1
    shift
    ssh "${ssh_options[@]}" -p "${guest_ports[$guest]}" "$guest_user@127.0.0.1" "$@"
}

# Quote each argument: ssh joins them into one remote shell command.
guest_call() {
    local guest=$1 remote_command
    shift
    printf -v remote_command '%q ' sudo /usr/local/sbin/blindpass-p05-guest "$@"
    guest_ssh "$guest" "$remote_command"
}

guest_stage() {
    local guest=$1
    shift
    scp "${scp_options[@]}" -P "${guest_ports[$guest]}" "$@" "$guest_user@127.0.0.1:/tmp/p05/"
}

start_guest() {
    local guest=$1 extra_forward=${2:-}
    local image_dir=$run_dir/$guest/image pidfile=$run_dir/$guest/qemu.pid
    local serial_log=$run_dir/$guest/serial.log port=${guest_ports[$guest]} target
    mkdir -p "$image_dir"
    "$repo_root/tests/fleet/provision-guest.sh" --output-dir "$image_dir"
    qemu-system-x86_64 \
        -name "blindpass-p05-$guest,debug-threads=on" \
        -enable-kvm -cpu host -m 1536 -smp 2 \
        -drive "file=$image_dir/guest-overlay.qcow2,if=virtio,format=qcow2" \
        -drive "file=$image_dir/seed.iso,if=virtio,media=cdrom,readonly=on,format=raw" \
        -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:$port-:22${extra_forward}" \
        -device virtio-net-pci,netdev=net0 \
        -display none -monitor none -serial "file:$serial_log" \
        -pidfile "$pidfile" -daemonize
    qemu_pidfiles+=("$pidfile")
    target="$guest_user@127.0.0.1"
    for _attempt in {1..90}; do
        ssh "${ssh_options[@]}" -p "$port" "$target" true 2>/dev/null && break
        sleep 2
    done
    ssh "${ssh_options[@]}" -p "$port" "$target" true >/dev/null 2>&1 \
        || fail "guest $guest did not become reachable"
    ssh "${ssh_options[@]}" -p "$port" "$target" mkdir -m 0700 -p /tmp/p05
    guest_stage "$guest" "$repo_root/tests/fleet/p05-backup-guest.sh"
    guest_ssh "$guest" sudo install -m 0755 /tmp/p05/p05-backup-guest.sh /usr/local/sbin/blindpass-p05-guest
    printf 'P05-GUEST-READY guest=%s ssh_port=%s\n' "$guest" "$port"
}

new_canary() {
    printf 'P05-%s-%s' "$1" "$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
}

# Dummy canaries only. Password files hold the exact bytes, with no newline.
printf '%s' "$(new_canary RESTIC-PW-INITIAL)" >"$stage_dir/pw-initial"
printf '%s' "$(new_canary RESTIC-PW-ROTATED)" >"$stage_dir/pw-rotated"
printf '%s' "$(new_canary JSON-MARKER)" >"$stage_dir/canary-json-marker"
{
    cat -- "$stage_dir/pw-initial"; printf '\n'
    cat -- "$stage_dir/pw-rotated"; printf '\n'
    cat -- "$stage_dir/canary-json-marker"; printf '\n'
} >"$stage_dir/canaries"
[[ $(<"$stage_dir/pw-initial") != "$(<"$stage_dir/pw-rotated")" ]] || fail 'generated passwords collide'

# Host-side journal scan with positive controls: reuses the browser-handoff scanner
# semantics (non-empty source, injected control token detected, expected unit
# lifecycle lines present, canaries absent) on a journal fetched from the guest.
scan_journal() {
    local journal_file=$1
    shift
    P05_SCAN_MODULE="$repo_root/tests/browser-handoff/journal-canary-scan.mjs" \
        P05_SCAN_CANARIES="$stage_dir/canaries" P05_SCAN_JOURNAL="$journal_file" \
        P05_SCAN_UNITS="$*" node --input-type=module -e '
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
const { assertScannedClean } = await import(pathToFileURL(process.env.P05_SCAN_MODULE).href);
const canaries = readFileSync(process.env.P05_SCAN_CANARIES, "utf8").split("\n").filter(Boolean);
const output = readFileSync(process.env.P05_SCAN_JOURNAL);
const expectedUnits = process.env.P05_SCAN_UNITS.split(" ").filter(Boolean);
const result = assertScannedClean({ output, canaries, expectedUnits });
console.log(`P05-JOURNAL-SCAN PASS ${JSON.stringify(result)}`);
'
}

step 'boot guests'
start_guest a ",hostfwd=tcp:127.0.0.1:$rest_port-:$rest_guest_port"
start_guest b

step 'server (host A): disposable rest-server'
guest_stage a "$run_dir/rest-server"
guest_call a server-start "$rest_guest_port"
guest_stage a "$stage_dir/canaries"
guest_call a install-canaries

# 10.0.2.2 is the QEMU user-network alias for the runner; the rest-server is
# reached through the loopback forward to guest A.
repository_url="rest:http://10.0.2.2:$rest_port/p05repo"

step 'consumer (host B): broker, restic, example units, fixtures, repository'
guest_stage b \
    "$repo_root/target/release/blindpass-broker" \
    "$repo_root/target/release/blindpass-provision" \
    "$run_dir/restic" \
    "$repo_root/deploy/native/blindpass-broker.service" \
    "$repo_root/deploy/examples/example-backup.service" \
    "$repo_root/deploy/examples/example-backup.timer" \
    "$repo_root/deploy/examples/native-backup-broker.conf" \
    "$repo_root/deploy/native/blindpass-workload.sysusers" \
    "$repo_root/deploy/native/blindpass-node.sysusers" \
    "$stage_dir/pw-initial" "$stage_dir/pw-rotated" "$stage_dir/canary-json-marker"
guest_call b consumer-prepare "$repository_url"
guest_call b make-fixtures
guest_call b init-repository
guest_call b broker-start

step 'P05-E02 initial: provision over HPKE, ordinary unit without MCP, restore and compare'
guest_call b provision pw-initial
guest_call b backup-ok initial
guest_call b restore-compare initial

step 'P05-I05 password-file profile: rejected values leave the previous value in place'
guest_call b provision-reject pw-newline password_file_control_character
guest_call b provision-reject pw-oversized password_file_too_long
guest_call b provision-reject pw-badutf8 password_file_invalid_utf8
guest_call b provision-reject pw-empty 'credential is empty'
guest_call b backup-ok after-rejected-values

step 'P05-I05 a JSON envelope is never decoded: accepted as literal text, repository auth fails'
guest_call b provision pw-json
guest_call b backup-denied json-literal stale
guest_call b provision pw-initial
guest_call b backup-ok after-json-recovery

step 'P05-E02 native encrypted-credstore baseline (initial password)'
guest_call b native-prepare
guest_call b native-encrypt pw-initial
guest_call b native-backup-ok native-initial
guest_call b restore-compare native-initial

step 'P05-I05 missing credential: broker restart discards memory custody; unit fails closed'
guest_call b broker-restart
guest_call b backup-denied after-broker-restart missing
guest_call b native-backup-ok native-while-broker-empty
guest_call b provision pw-initial
guest_call b backup-ok recovered-after-reprovision

step 'P05-E02 operator logout does not disturb a running job'
guest_call b add-slow-artifact
guest_call b logout-during-job
guest_call b restore-compare after-logout

step 'P05-E02 / P05-I05 rotation: key passwd, stale denial, re-provision, restart, repeat'
guest_call b rotate-repository-password
guest_call b backup-denied stale-broker-credential stale
guest_call b native-backup-denied stale-native-credential
guest_call b provision pw-rotated
guest_call b backup-ok rotated
guest_call b backup-ok rotated-repeat
guest_call b restore-compare rotated
guest_call b native-encrypt pw-rotated
guest_call b native-backup-ok rotated-native
guest_call b restore-compare rotated-native

step 'exposure: file/process scans and journal scans with positive controls'
guest_call b scan-canaries
guest_call a scan-canaries
control_token=$(guest_call b journal-control)
[[ $control_token =~ ^P05-JOURNAL-CONTROL-[a-f0-9]{32}$ ]] || fail 'journal control token is malformed'
guest_call b journal-dump >"$run_dir/journal-b.txt"
grep -Fq -- "$control_token" "$run_dir/journal-b.txt" || fail 'the journal control unit output is missing from the dump'
scan_journal "$run_dir/journal-b.txt" blindpass-broker.service example-backup.service example-backup-native.service
guest_call a journal-dump >"$run_dir/journal-a.txt"
scan_journal "$run_dir/journal-a.txt" p05-rest-server.service

step 'versions'
guest_call a versions
guest_call b versions

printf 'P05-E02-RUN-COMPLETE runner_owner=%s (artifact approval is recorded in ADR 0007, not by this script)\n' \
    "$BLINDPASS_FLEET_RUNNER_OWNER"
