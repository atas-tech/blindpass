#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Guest-side helper for tests/fleet/p10-vm.py (P10 cross-workload fulfillment).
# It runs as root next to the P03 guest helper and only prepares disposable
# fixtures: the broker's fulfillment ceilings, a provisioned source credential
# and recipient units that read it through the root-only credential loader.
# Credentials arrive on stdin and never appear in argv, unit files or output.
set -Eeuo pipefail

issuer_unit=blindpass-p10-issuer.service
credential=api-key
client=/usr/local/lib/blindpass-p10-provider-client

fail() {
    printf 'P10-GUEST-FAIL %s\n' "$1" >&2
    exit 1
}

recipient_unit() {
    [[ "$1" =~ ^[a-z]{3,16}$ ]] || fail 'recipient label is invalid'
    printf 'blindpass-p10-recipient-%s.service\n' "$1"
}

[[ $(id -u) == 0 ]] || fail 'guest helper requires root'
command=${1:-}
shift || true

# The shipped broker unit with only the fulfillment mappings changed. The
# base arguments are the ones deploy/native/blindpass-broker.service carries.
write_broker_dropin() {
    local arguments=$1
    install -d -m 0755 /etc/systemd/system/blindpass-broker.service.d
    cat >/etc/systemd/system/blindpass-broker.service.d/p10.conf <<UNIT
[Service]
ExecStart=
ExecStart=/usr/libexec/blindpass-broker --loader-socket /run/blindpass/loader.sock --workload-socket /run/blindpass/workload.sock --provision-socket /run/blindpass/provision.sock --control-socket /run/blindpass/control.sock --key-directory /var/lib/blindpass/broker --workload-group blindpass-workload --node-group blindpass-node $arguments
UNIT
    systemctl daemon-reload
    systemctl restart blindpass-broker.service
    systemctl is-active --quiet blindpass-broker.service || fail 'broker did not start with the P10 mapping'
}

case "$command" in
    install-tools)
        install -m 0755 /tmp/p10/blindpass-provision /usr/libexec/blindpass-provision
        printf 'P10-GUEST-TOOLS-INSTALLED\n'
        ;;
    configure-issuer)
        write_broker_dropin "--map $issuer_unit=$credential --fulfillment-source $issuer_unit"
        printf 'P10-GUEST-ISSUER-CONFIGURED\n'
        ;;
    configure-recipients)
        port=${1:-}
        shift || true
        [[ "$port" =~ ^[0-9]{2,5}$ ]] || fail 'provider port is invalid'
        (($# >= 1)) || fail 'at least one recipient label is required'
        arguments=
        install -d -m 0755 /usr/local/lib
        cat >"$client" <<'PY'
import http.client
import os
import sys

# Presents the loaded credential to the dummy provider and prints the status
# only. The credential itself is never printed.
path = os.path.join(os.environ["CREDENTIALS_DIRECTORY"], "api-key")
with open(path, "rb") as handle:
    value = handle.read().decode().strip()
if not value:
    # A refused loader read reaches the unit as an empty credential: report it and stop.
    print("P10-PROVIDER credential=empty", flush=True)
    sys.exit(4)
connection = http.client.HTTPConnection("10.0.2.2", int(os.environ["P10_PROVIDER_PORT"]), timeout=5)
connection.request("GET", "/p10", headers={"Authorization": "Bearer " + value})
status = connection.getresponse().status
print("P10-PROVIDER status=%d" % status, flush=True)
sys.exit(0 if status == 200 else 3)
PY
        chmod 0644 "$client"
        for label in "$@"; do
            unit=$(recipient_unit "$label")
            arguments+=" --map $unit=$credential --fulfillment-destination $unit"
            cat >/etc/systemd/system/"$unit" <<UNIT
[Unit]
Description=BlindPass P10 recipient ($label) reading a fulfilled credential
Requires=blindpass-broker.service
After=blindpass-broker.service

[Service]
Type=oneshot
DynamicUser=yes
TimeoutStartSec=20s
LoadCredential=$credential:/run/blindpass/loader.sock
Environment=P10_PROVIDER_PORT=$port
ExecStart=/usr/bin/python3 $client
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
RestrictAddressFamilies=AF_UNIX AF_INET
LockPersonality=yes
LimitCORE=0
ProtectKernelTunables=yes
ProtectControlGroups=yes
ProtectKernelModules=yes
RestrictSUIDSGID=yes
SystemCallArchitectures=native
UNIT
            chmod 0644 /etc/systemd/system/"$unit"
        done
        write_broker_dropin "$arguments"
        printf 'P10-GUEST-RECIPIENTS-CONFIGURED count=%s\n' "$#"
        ;;
    provision-source)
        # The credential is read from stdin by blindpass-provision.
        /usr/libexec/blindpass-provision --unit "$issuer_unit" --credential "$credential"
        printf 'P10-GUEST-SOURCE-PROVISIONED\n'
        ;;
    run-recipient)
        unit=$(recipient_unit "${1:-}")
        systemctl reset-failed "$unit" >/dev/null 2>&1 || true
        before=$(date +%s)
        status=0
        timeout 40 systemctl start "$unit" >/dev/null 2>&1 || status=$?
        # The unit is oneshot: when it has exited, its journal holds the provider status
        # or the loader refusal. Only that last line and the unit result are reported.
        result=$(systemctl show --property=Result --value "$unit" 2>/dev/null || true)
        line=$(journalctl -u "$unit" --since "@$before" -o cat --no-pager 2>/dev/null | grep -E '^P10-PROVIDER ' | tail -n 1 || true)
        printf 'P10-GUEST-RECIPIENT-RESULT start_status=%s result=%s provider=%s\n' \
            "$status" "${result:-unknown}" "${line:-none}"
        ;;
    broker-reads)
        # How often the loader served the unit, from the broker's own journal.
        unit=$(recipient_unit "${1:-}")
        count=$(journalctl -u blindpass-broker.service -o cat --no-pager 2>/dev/null | grep -Fc "unit=$unit" || true)
        printf 'P10-GUEST-BROKER-MENTIONS unit=%s count=%s\n' "$unit" "$count"
        ;;
    restart-broker)
        systemctl restart blindpass-broker.service
        systemctl is-active --quiet blindpass-broker.service || fail 'broker did not restart'
        printf 'P10-GUEST-BROKER-RESTARTED\n'
        ;;
    scan-state|scan-control)
        # Looks for the credential (raw, base64, base64url, hex) in persistent and runtime
        # state, argv, environments and the journal. scan-control plants the same value in
        # a file first and requires the scan to find it, so a blind scan cannot pass.
        mode=$command
        # The script travels as an argument because stdin carries the credential.
        scan_script=$(cat <<'PY'
import base64
import binascii
import os
import subprocess
import sys

mode = sys.argv[1]
value = sys.stdin.read().strip().encode()
if len(value) < 16:
    print("P10-GUEST-FAIL scan value is too short", file=sys.stderr)
    sys.exit(1)
needles = {value, base64.b64encode(value), base64.urlsafe_b64encode(value).rstrip(b"="),
           binascii.hexlify(value), binascii.hexlify(value).upper()}
needles.update({base64.b64encode(value).rstrip(b"=")})
planted = "/var/lib/blindpass-p10-control.txt"
if mode == "scan-control":
    with open(planted, "wb") as handle:
        handle.write(b"control " + value + b"\n")
roots = ["/var/lib/blindpass", "/run/blindpass", "/etc/blindpass", "/etc/systemd/system",
         "/usr/local", "/tmp", "/var/tmp", "/root", "/home"]
if mode == "scan-control":
    roots.append("/var/lib")
hits = []
scanned = 0

def check(label, data):
    global scanned
    scanned += 1
    if any(needle in data for needle in needles):
        hits.append(label)

for root in roots:
    for directory, _, names in os.walk(root, followlinks=False):
        for name in names:
            path = os.path.join(directory, name)
            try:
                if os.path.islink(path) or not os.path.isfile(path) or os.path.getsize(path) > 64 * 1024 * 1024:
                    continue
                with open(path, "rb") as handle:
                    check(path, handle.read())
            except OSError:
                continue
for entry in os.listdir("/proc"):
    if not entry.isdigit():
        continue
    for leaf in ("cmdline", "environ"):
        try:
            with open(f"/proc/{entry}/{leaf}", "rb") as handle:
                check(f"/proc/<pid>/{leaf}", handle.read())
        except OSError:
            continue
journal = subprocess.run(["journalctl", "--no-pager", "-o", "cat"], capture_output=True, check=False).stdout
if len(journal) < 64:
    print("P10-GUEST-FAIL the journal capture is empty", file=sys.stderr)
    sys.exit(1)
check("journal", journal)
if mode == "scan-control":
    os.unlink(planted)
    if planted not in hits:
        print("P10-GUEST-FAIL the scan did not find a planted value", file=sys.stderr)
        sys.exit(1)
    print("P10-GUEST-SCAN-CONTROL found-planted=true")
    sys.exit(0)
if hits:
    print("P10-GUEST-FAIL credential found in: " + ", ".join(sorted(set(hits))), file=sys.stderr)
    sys.exit(1)
print(f"P10-GUEST-SCAN-CLEAN scanned={scanned} hits=0")
PY
)
        python3 -c "$scan_script" "$mode"
        ;;
    *)
        fail "unknown command ${command:-<none>}"
        ;;
esac
