# P06 stock AI-client task on the packaged native controller — 2026-10-06

**Status:** two-guest QEMU/KVM runs on the uncommitted tree above `8a595ad` (Ubuntu 24.04 controller guest running the packaged native controller from the rebuilt release archive, Ubuntu 24.04 node guest). **Claude Code passed; Codex could not run** because its workspace is out of credits. This is slice 9's stock AI-client workflow for the native profile. It is not P05 acceptance and not P06 acceptance (still false).

## What ran

`tests/fleet/p06-native-node-vm.py --scenario ai-task` (new). It brings up the packaged controller as in the other native scenarios, boots a fresh node guest (2 GiB, 8 GiB disk) and runs the P05 managed-application workflow in it **against that remote controller**: `tests/fleet/p06-ai-guest.sh` installs the shipped broker, browser and login-helper units, the Node 26.10 runtime, Playwright's Chromium and the verified Grafana 13.2.3 runtime bundle (the archive checked against the Grafana download page's SHA-256 in the P05 record, already extracted on this host; nothing new was downloaded) and starts `tests/browser-handoff/fleet-browser-guest.mjs` with `BLINDPASS_P06_REMOTE_CONTROLLER=1`. A new `startRemoteFleetController` (in `fleet-controller-fixture.mjs`) replaces the in-guest test-mode controller: it logs in to the packaged controller over verified HTTPS as the operator whose password the harness generated, with everything else (enrollment and approval, policy, workload registration, the node channel, HPKE provisioning, browser session grant, stock Playwright MCP tool, cancellation and journal scans) unchanged. The host then runs `tests/browser-handoff/ai-client-task.py claude`, which uses this host's signed-in client in place through a fixed SSH connector.

## Result

| Run | Outcome |
|---|---|
| No AI client (managed workflow only), 2 passing runs after the harness fixes below | `P05-MANAGED-FLEET-VM` printed: Grafana 13.2.3 external viewer, setup and operation logins counted, 403 on durable mutations, 401 on the recovery API, 401 for the copied session after cancel and after restart |
| **Claude Code 2.1.287** (final run) | `P05-AI-TASK client=claude actual_mcp_request=true actual_controller_approval=true actual_node=true hpke_source=true stock_report_reads=2 stock_reconnects=1 parsed_artifacts=12 copied_cookie_cancel=401 exact_runtime_removed=true root_transport_other_uid=denied source_session_canaries=absent setup_logins=1 operation_logins=1`; tool trace request, status, navigate, wait, snapshot, navigate, wait, snapshot, cancel; `resultShape` valid |
| **Codex CLI 0.160.0** | not run to completion: the client exits at once with `Your workspace is out of credits. Add credits to continue.` (reproduced with a plain `codex exec` without any MCP). No tool call reached the broker. |

Resume Codex once credits exist: `BLINDPASS_P05_AI_CLIENT=codex P05_GRAFANA_HOME=<verified grafana-13.2.3> BLINDPASS_P06_NODE_MEMORY_MB=2048 BLINDPASS_P06_NODE_DISK_GB=8 python3 tests/fleet/p06-native-node-vm.py --archive ... --bin-dir ... --scenario ai-task`.

## How it got there (all harness, no product code)

- The shared node-guest preparation enables the plain broker and node units and creates `/etc/blindpass`; the managed flow needs both fresh, so `p06-ai-guest.sh` disables them and removes the directory first.
- The new client version `2.1.287` wraps its final answer in a Markdown fence (earlier recorded runs used 2.1.286). Two Claude runs ran the whole task correctly (nine-call trace, cancel, 401) and then failed `verify-client-result` because the strict parser rejects a fenced answer (`resultShape: fenced` in the diagnostic added for this). The parser was **not** loosened. The prompt now says "plain text with no Markdown and no code fence" (`ai-client-task.py`), after which the answer was bare JSON and the run passed. The P05 parser tests (9) still pass.
- One Claude run passed the task but my new stage looked for the no-AI marker; fixed to require `P05-AI-TASK client=<name>`.
- Early no-AI runs showed two flakes. **Login observer race (diagnosed and fixed):** the driver waited for the login POST counter and then asserted the verified counter, but the observer increments the first synchronously and the second only after it has read the broker journal, so a slow read made `verifiedLoginCount` 0 and `reserved_records` 0 (seen once in six runs). The broker itself persists the helper binding before sending the source (`session_journal.rs::record_helper`), so this was a driver race, not a broker defect. `fleet-browser-guest.mjs` and `ai-task-guest.mjs` now wait for the verified counter (or an observer failure); `coordinator-guest.mjs` has no async observer and is unchanged. Two later full runs passed; one pass cannot prove a 1-in-6 flake gone, so the evidence is the diagnosis, not the reruns. **Transport:** `fleet_controller_transport_failed` from the port forward accepting one connection at a time; the remote fixture now keeps one connection alive and retries reads (never writes).
- Wide-output diagnostics (fixed status, route and error code only) were added for the remote controller; no credential, token or cookie is printed, and the stage fails if the operator password or a generated canary appears in the output.

## Limits

- Claude Code only; Codex blocked on credits. One passing Claude run in its final form, preceded by two runs that exposed the answer-format issue and one that exposed the harness marker bug.
- Native profile with SQLite store, one node, x86-64. The controller guest is the same host's guest, reached through a host port forward, not a separate machine on a real network.
- The Grafana distribution is a verified P05 artifact reused from `/tmp`, not a new dependency; its provenance is the P05 record, not re-checked here.
- The unfenced-JSON prompt change lives in the P05 runner and applies to both clients. It makes the task text slightly stricter; it does not change what the parser accepts.
- GUI provisioning, URL elicitation and the two-host backup workflow of P05 are untouched and remain open there.
- A loaded or fault-injected run of this scenario was not made.
