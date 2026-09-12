# Native Linux Fleet Pilot: E2E and Integration Test Plan

**Date:** 2026-09-12  
**Status:** Proposed; no scenarios in this document have been implemented or executed.  
**Design:** [Native Linux Fleet Research](../product/Native%20Linux%20Fleet%20Research%202026-09.md).

This plan accompanies the proposed milestone under the [repository phase testing rule](../../AGENTS.md). Scenario implementations are required alongside feature code. Existing repo tests do not establish the OS or fleet guarantees described here.

## Test environment and evidence

Use disposable Linux VMs with real systemd as the service manager, distinct service accounts, and real Unix sockets. One machine represents the Omarchy controller/operator host; a second runs a headless broker, isolated AI worker, and an ordinary service. Containers or mocked peer metadata alone are insufficient evidence for service-manager identity and isolation.

The controller itself must be tested both as a native service and inside a container. The VM requirement above applies to host brokers and their service consumers; it does not require the controller to run natively. Repeat the same fleet workflows with a separate controller host to verify that the Omarchy UI is not coupled to a local process.

## Controller deployment matrix

| Profile | Controller and backing services | Required coverage |
|---|---|---|
| D-NATIVE | Dedicated-account systemd service with native or externally managed database services; no container-runtime requirement | Common E2E/authorization/operations suites, native install/upgrade/recovery |
| D-CONTAINER | Non-root OCI application image under Docker Compose with declared volumes and bundled or externally managed backing services | Same common suites, image replacement, volume and key recovery, no privileged host integration |

Both profiles use the same controller version, policy fixtures, API schema, and enrollment/grant semantics. First run on the operator host, then exercise a separate controller host. Require an explicitly tested database topology for each profile; do not imply that every optional backing-service combination or OCI runtime is supported.

Containerized host brokers and arbitrary workload-container integrations are outside this matrix. Brokers remain native services in the initial pilot.

Use generated dummy credentials and a deterministic authenticated test API for automated cases. Add a low-privilege real-provider smoke test and a real backup job against a disposable destination. Record OS, kernel, systemd, adapter, broker, and controller versions. Omarchy 4.0.3 and systemd 261.2 are the inspected local baseline, not an established supported matrix.

Capture structured policy decisions, process exit results, service journal output, broker/controller audit events, transcripts, and permitted network observations. Evidence must contain test IDs and redacted metadata, not real credentials. Secret-leak assertions use a unique generated canary per test across broker-managed outputs, logs, artifacts, and model-visible traffic.

## End-to-end scenarios

| ID | Scenario | Required outcome |
|---|---|---|
| E01 | Enroll two nodes using distinct approved enrollment requests. | Each has its own node identity; enrollment replay, expired requests, and key substitution fail. |
| E02 | From a registered AI worker, request the pilot API operation; approve in the operator app and enter a new dummy credential encrypted for the correct host broker. | Operation succeeds; agent receives only the defined result; controller sees no plaintext; audit links operator, workload, node, action, and grant. |
| E03 | Repeat E02 with a second stock AI client through its adapter. | Same broker authorization and consumption semantics; no reliance on OpenClaw messaging. Mark unsupported clients explicitly rather than simulating support. |
| E04 | Provision a test backup credential to the headless node and start an ordinary systemd backup service. | Backup writes and restores a test artifact using its credential file; the service requires no MCP client. |
| E05 | Decline or dismiss an approval; allow another to expire. | No operation or delivery occurs. The worker receives a bounded, actionable status. |
| E06 | Revoke a connected workload's grant. | Subsequent broker operations are denied within the documented propagation bound; already issued service credentials are reported separately. |
| E07 | Disconnect or suspend the controller while a worker runs. | New grants fail closed; existing grants stop authorizing broker actions at expiry; no automatic widening of access. Already running credential-consuming services follow their declared lifecycle. |
| E08 | Rotate the backup credential. | A controlled restart acquires the new version; changing the stored source alone does not falsely report a refreshed running service. Restore remains functional. |
| E09 | Reboot a node with ephemeral custody and repeat with approved encrypted persistent custody. | Ephemeral secrets are unavailable; persistent custody follows its documented unlock/recovery policy. Missing material never produces a false success or plaintext fallback. |
| E10 | Lock or log out of Omarchy while requests are pending, then restart the shell. | Controller/brokers remain independent; no approval is inferred from UI absence, and requests remain bound to the same identities and expiry. |
| E11 | Run parallel requests from two nodes and several distinct workloads. | Results, handles, approvals, and credentials never cross identities; one-use grants execute at most once. |
| E12 | Try a normal process and an unregistered AI worker against the local broker. | Both fail closed despite supplying an authorized workload's name, PID, resource, or copied grant. |
| E13 | Revoke a node and attempt reconnect and reenrollment. | Old credentials cannot renew or regain access; reenrollment requires a new authorized identity flow. Controller displays outstanding provider-credential risk separately. |
| E14 | Remove the pilot from disposable hosts and restore saved service configuration. | Original service behavior returns, no orphaned privilege rules or sockets remain, and retained encrypted material is explicitly reported. |
| E15 | Repeat the core two-host pilot with native and container controllers, then with the controller on a separate host. | Same approval, operation, service-delivery, rejection, revocation, and disconnection behavior; Omarchy UI uses the authenticated API in every topology. |

## Identity and authorization integration

| ID | Scenario | Required outcome |
|---|---|---|
| I01 | Fabricate node IDs, workload IDs, PID fields, purpose text, and claimed unit names. | Authorization derives from authenticated enrollment and OS metadata; user-supplied identity assertions grant nothing. |
| I02 | Race process exit/PID reuse during local request validation. | Requests cannot become associated with a replacement process; failures release resources and deny execution. |
| I03 | Run two scripts with the same interpreter, or two units using the same executable. | Protected registration and execution context distinguish them; executable name alone is not authority. |
| I04 | Attempt access from a worker sharing the desktop UID. | Record the convenience profile's limits. The stronger profile must demonstrate separate-account/container isolation, including no operator desktop IPC or approval-code write access. |
| I05 | If SPIRE is selected, exercise real Unix and systemd attestors and credential renewal. | Correct registration is required; wrong unit/account/selectors fail. Test user-manager behavior separately before declaring support. |
| I06 | Present expired, wrong-audience, wrong-workspace, wrong-node, wrong-mode, and modified grants. | Each is rejected with no secret release; errors avoid disclosing inaccessible resource metadata. |
| I07 | Change policy or revoke approval between request and execution. | Execution enforces the current applicable decision and local authority ceiling. |
| I08 | Replay a one-use grant concurrently and retry after uncertain API outcomes. | Grant consumption is atomic; operation-specific idempotency rules prevent unsafe duplicate effects. |
| I09 | Simulate a signed controller decision exceeding the node's local ceiling. | Broker denies it. Test key-registration changes separately; ciphertext relay is not accepted as proof against controller compromise. |
| I10 | Attempt approval from an unprivileged workload over the operator API or local IPC. | Fleet identity/role checks and applicable local authorization are enforced; UI possession or a caller-supplied operator ID is insufficient. |

## Credential delivery and broker integration

| ID | Scenario | Required outcome |
|---|---|---|
| C01 | Real systemd credential loader connects to the broker socket. | Broker validates the loader context and registered unit-to-credential mapping, returning only the requested authorized value. |
| C02 | Ordinary process fabricates systemd-style abstract socket names. | Names are treated as untrusted routing hints until the peer is authenticated; no credential is returned. |
| C03 | Wrong unit requests another service's credential; test socket path replacement and symlink confusion. | Ownership and mapping checks prevent cross-service access. |
| C04 | Broker denies, crashes, stalls, or closes mid-delivery. | Service activation fails within a defined bound; it never starts successfully with empty or partial credentials. |
| C05 | Distinct service user tries to read another service's credential directory or source. | Access fails under the supported isolation profile; the test explicitly acknowledges host root as trusted. |
| C06 | Service activation/deactivation, restart, missing source, oversized value, and binary credential. | Lifecycle, limits, and bytes are handled correctly; no stale material is silently reused. |
| C07 | Brokered API request supplies an alternate host, redirect, header, path traversal, or unapproved action. | Adapter enforces its fixed origin and permitted operation; no credential is sent to an unintended destination. |
| C08 | Target API echoes authentication material or returns verbose errors; logging is set to debug. | Defined response validation prevents exposure through broker-managed results and logs. Test failure behavior, not just successful responses. |
| C09 | Attempt to reuse a handle from another session or after expiry. | Broker rejects it even when the raw handle is known. |
| C10 | Change the recipient key during enrollment/provisioning; replay ciphertext at another broker. | Destination binding is checked, the mismatch is visible, and decryption/delivery fails. |
| C11 | Enable encrypted persistence with TPM available, absent, or recovery unavailable. | Each configured mode behaves explicitly. No unnoticed downgrade or plaintext temporary file is accepted. |
| C12 | Deliberately malicious authorized credential-consuming test service prints its received credential. | Demonstrates that delivery mode is not model blindness or consumer containment; product wording must not claim otherwise. Use dummy material only. |
| C13 | Revoke a grant after a service has copied a static provider credential. | The test records that copied material remains valid until provider revocation/rotation; no false claim of remote erasure. |
| C14 | Child process, service journal, crash path, transcript, command arguments, and temporary artifacts are inspected with generated canaries. | No unintended leaks in brokered mode. Delivery-mode exposure is limited to the explicitly trusted consumer boundary. Disabling core dumps alone is not proof that plaintext never reaches persistent storage. |

## Fleet operations and desktop integration

| ID | Scenario | Required outcome |
|---|---|---|
| O01 | Network partition, reconnect storms, controller restart, and time skew. | Bounded backoff and queues; conservative expiry enforcement; no acceptance of expired grants through clock rollback. |
| O02 | Audit sink unavailable or disk full. | Documented bounded buffering or denial policy; no silent loss of security-relevant decisions or unbounded memory use. |
| O03 | Duplicate approval delivery or delayed revocation arrives after reconnection. | Idempotent handling and ordered policy/version reconciliation; no resurrection of revoked grants. |
| O04 | Shell plugin is restarted, disabled, or replaced. | Broker operation and key custody remain independent; plugin APIs reveal only the allowed metadata. |
| O05 | Very long purpose text, spoofed workload labels, markup, or terminal escapes appear in requests. | UI displays verified identity separately, renders untrusted text safely, and never executes it. |
| O06 | Broker/controller version mismatch or unsupported host capability. | Explicit compatibility error or documented limited profile; no silent removal of identity or isolation checks. |
| O07 | Node key rotation and documented recovery are exercised. | The intended node recovers under authorized procedure; old node credentials cannot continue indefinitely. |

## Controller packaging, persistence, and migration

| ID | Scenario | Required outcome |
|---|---|---|
| D01 | Clean native installation on a host without a container runtime. | Controller starts under its dedicated account with documented native/external backing services and passes readiness; no implicit Docker dependency. |
| D02 | Clean Compose installation using the release image. | Controller runs non-root without privileged mode, host PID namespace, service-manager sockets, or container-engine socket; only declared ports and persistent state are required. |
| D03 | Restart native service and replace the controller container with the same image. | Controller identity, trust configuration, enrolled nodes, policies, and durable audit state persist; signing keys are not regenerated. |
| D04 | Upgrade each package through a supported schema migration, then exercise the documented rollback or restore procedure. | Node/API compatibility follows the declared version policy; failed migrations do not report ready or corrupt usable backup state. |
| D05 | Back up each deployment and restore to a clean host with its protected signing/trust material. | Controller and node trust recover; expired/revoked grants remain invalid, audit continuity is preserved, and missing key material causes an explicit failure. |
| D06 | Migrate native to container and container to native using a stable endpoint and preserved identity. | Existing nodes reconnect without unnecessary reenrollment; policy and state remain consistent; source instance is stopped or fenced. |
| D07 | Attempt to start the restored controller while the original independently serves the fleet. | The supported procedure prevents concurrent independent writers/issuers; no high-availability behavior is inferred from a successful restore. |
| D08 | Missing volume, inaccessible database, wrong ownership, absent signing secret, or invalid configuration. | Readiness fails with sanitized diagnostics; no empty replacement fleet, default keys, or plaintext fallback is created silently. |
| D09 | Send termination signals during an approval or operation; interrupt controller-to-database and broker-to-controller connections. | Both packages follow the same graceful-shutdown, retry, grant, and uncertain-result semantics with bounded timeouts. |
| D10 | Inspect image layers, release archives, container inspection output, generated units, logs, and backup artifacts using dummy canaries. | No baked-in secrets or accidental credential disclosure; signing material is protected in runtime inputs and backups. |
| D11 | Omarchy logout, shell restart, and operator-host suspension with a remote controller. | Remote controller continues serving other nodes; UI reconnects safely. When the controller shares the suspended host, both packages show the documented outage behavior. |

## Release evidence and adoption gate

Run the existing workspace build and tests for implementation changes, then the relevant broker integration suites and disposable-VM E2E scenarios. Add regression cases alongside each behavior change; mocked OS calls alone cannot satisfy identity scenarios. Apply dependency-guard before any proposed dependency change.

Record results separately for D-NATIVE and D-CONTAINER and link native/container migration evidence in both directions. Neither package is considered supported until its common and package-specific scenarios pass. Containerized controller testing must not be used to claim host-broker isolation was tested inside a normal application container.

Each scenario needs its implementation location, environment, execution date, result, and evidence reference recorded when implemented. Unsupported scenarios remain explicit release blockers for the corresponding guarantee, rather than being marked passed by documentation review.

Before expanding beyond the pilot, collect setup and repeat-use evidence from three external operators, aiming for at least two repeat users. Record failure reasons, approval frequency, controller availability issues, and whether a simpler existing secret manager would have met the same need. These targets are proposed validation criteria, not current traction.
