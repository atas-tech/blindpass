# Linux Fleet Pilot and Roadmap Test Plan

**Consolidated:** 2026-09-22

**Status:** Proposed; no scenarios in this document have been implemented or executed.

**Design:** [Specification](../product/Specification.md) · [Roadmap](../product/Roadmap.md).

This single plan merges the native fleet and browser pilot scenarios, incorporates the round-two corrections, and covers roadmap milestones W0–W6. Fleet E/I/C/O/D identifiers retain their original meanings; browser identifiers gain a `B-` prefix to avoid collisions. Deferred browser IDs remain deferred, not passed. All scenarios, including new corrections below, require implementation and execution evidence.

This plan accompanies the proposed milestones under the [repository phase testing rule](../../AGENTS.md). Scenario implementations are required alongside feature code. Existing repo tests do not establish the OS or fleet guarantees described here.

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

Use generated dummy credentials and a deterministic authenticated staging fixture for automated cases. The proposed W1 operation is browser session handoff; its application prerequisites and B-series checks apply in addition to the common fleet tests. Add a low-privilege real-application smoke test and a real backup job against a disposable destination. A fixed API operation, if selected instead, requires its own response/destination assertions; it does not remove the native service gate. Record OS, kernel, systemd, adapter, broker, and controller versions. Omarchy 4.0.3 and systemd 261.2 are the inspected local baseline, not an established supported matrix.

Capture structured policy decisions, process exit results, service journal output, broker/controller audit events, transcripts, and permitted network observations. Evidence must contain test IDs and redacted metadata, not real credentials. Secret-leak assertions use a unique generated canary per test across broker-managed outputs, logs, artifacts, and model-visible traffic.

## Bounds and milestone gates

Before executing acceptance runs, record numeric request/startup timeouts, grant/session maximum lifetimes, connected revocation propagation, crash cleanup/revocation deadlines, retry/backoff limits, audit buffering, and the approval-frequency ceiling. Use the same declared values across deployment profiles. Undefined bounds are unresolved release requirements, not a passing result. Test elapsed behavior and provider/session invalidation separately from UI status.

| Milestone | Required suites |
|---|---|
| W0 | Identity/authorization and credential integration, including real system-scope C01–C02, C04, C15–C20; compare C16 baseline |
| W1 | Common E-series for the implemented topology, relevant I/C/O suites, browser first gate if selected, M01–M07, native backup/restore |
| W2 | E15 and all common suites in D-NATIVE and D-CONTAINER, D01–D11, migration in both directions |
| W5 | S01–S07 for active pilot paths; unresolved relevant exposure/authorization defects block release |
| W3 | R01–R04 plus all preceding pilot gates and declared support matrix |
| W4/W6 | A01–A03 / X01–X03 when activated; expand feature-specific cases alongside implementation |

I05 is conditional on selecting SPIRE and is not an initial dependency or pilot blocker when deferred. Containerized brokers, user-manager delivery, browser strong mode, generic login-UI testing, extensions, and CI are not supported by this pilot. Rejection/boundary tests for these exclusions remain required where listed.

## End-to-end scenarios

| ID | Scenario | Required outcome |
|---|---|---|
| E01 | Enroll two nodes using distinct approved enrollment requests. | Each has its own node identity; enrollment replay, expired requests, and key substitution fail. |
| E02 | From a registered AI worker, request the selected authenticated operation; approve in the operator app and enter a dummy credential encrypted for the verified broker key. | Work completes under the exact operation contract; for browser mode, run B-E01 and receive a context reference/safe status without raw cookies or password; controller sees no source plaintext; audit links operator, invocation, workload, node, action, and grant. |
| E03 | Repeat E02 with a second stock AI client through its adapter. | Same broker authorization and consumption semantics; no reliance on OpenClaw messaging. Mark unsupported clients explicitly rather than simulating support. |
| E04 | Provision a test backup credential to the headless node and start an ordinary systemd backup service. | Backup writes and restores a test artifact using its credential file; the service requires no MCP client. |
| E05 | Decline or dismiss an approval; allow another to expire. | No operation or delivery occurs. The worker receives a bounded, actionable status. |
| E06 | Revoke a connected workload's grant. | Subsequent broker operations are denied within the documented propagation bound; already issued service credentials are reported separately. |
| E07 | Disconnect or suspend the controller while a worker runs. | New grants fail closed; existing grants stop authorizing broker actions at expiry; no automatic widening of access. Already running credential-consuming services follow their declared lifecycle. |
| E08 | Rotate the backup credential using controlled restart, then the opted-in `RefreshOnReload=credentials` path on supported systemd/application versions. | Consumer demonstrably uses the new bytes and backup/restore works. A reload signal alone is not proof of refresh; unsupported refresh is explicit; no unrelated service restarts. |
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
| I02 | Race process exit/PID reuse during request validation, using real `SO_PEERPIDFD` and pidfd-based system-unit/invocation resolution. | No authority transfers to a replacement process. Raw PID or `/proc`-based authorization cannot satisfy this case; failures deny and release resources. |
| I03 | Run two scripts with the same interpreter, or two units using the same executable. | Protected registration and execution context distinguish them; executable name alone is not authority. |
| I04 | Attempt delivery from a user-manager unit or worker sharing the desktop UID; attempt cross-account access in the supported profile. | Excluded profiles cannot obtain credential-socket delivery; no isolation claim for shared-UID execution. Dedicated system-unit workers cannot access operator desktop IPC, approval code, broker custody, or private helper state. |
| I05 | Deferred unless SPIRE is selected: exercise real Unix/systemd attestors, renewal and process-exit races using the selected version. | Verify `systemd:id` and `systemd:fragment_path` selectors, wrong-account/unit rejection, and equivalent resistance to PID/invocation substitution. Do not assume the historically PID-based plugin meets the pidfd contract; user-manager units remain excluded. |
| I06 | Present expired, wrong-audience, wrong-workspace, wrong-node, wrong-mode, and modified grants. | Each is rejected with no secret release; errors avoid disclosing inaccessible resource metadata. |
| I07 | Change policy or revoke approval between request and execution. | Execution enforces the current applicable decision and local authority ceiling. |
| I08 | Replay a one-use grant concurrently and retry after uncertain API outcomes. | Grant consumption is atomic; operation-specific idempotency rules prevent unsafe duplicate effects. |
| I09 | Simulate a signed controller decision exceeding the node's local ceiling. | Broker denies it. Test key-registration changes separately; ciphertext relay is not accepted as proof against controller compromise. |
| I10 | Attempt approval from an unprivileged workload over the operator API or local IPC. | Fleet identity/role checks and applicable local authorization are enforced; UI possession or a caller-supplied operator ID is insufficient. |

## Credential delivery and broker integration

| ID | Scenario | Required outcome |
|---|---|---|
| C01 | Real system-scope credential loader connects to a root-owned mode-0600 broker socket before the service executes. | Verify UID 0, obtain `SO_PEERPIDFD`, resolve system unit and invocation through the chosen race-safe mechanism, then match the untrusted routing unit and administrator credential mapping. Release only the authorized value; do not assume peer PID is 1. |
| C02 | Reproduce the known forged-name request with an ordinary client bound to `\0deadbeefdeadbeef/unit/postgresql.service/db-password`; test mismatched routing names from reachable unauthorized contexts. | Filesystem/peer/identity checks reject it with no credential release. The September user-scope naive-server forgery is historical evidence, not a passing broker test; random socket prefixes convey no authority. |
| C03 | Wrong unit requests another service's credential; test socket path replacement and symlink confusion. | Ownership and mapping checks prevent cross-service access. |
| C04 | Broker denies, crashes, stalls, closes empty, or returns partial/malformed credential bytes. | Consumer startup validation rejects missing, empty, incomplete or unparseable material within the declared bound; no successful job runs. Test consumer validation explicitly because socket EOF can yield an empty credential file without systemd alone failing activation. |
| C05 | Distinct service user tries to read another service's credential directory or source. | Access fails under the supported isolation profile; the test explicitly acknowledges host root as trusted. |
| C06 | Service activation/deactivation, restart, missing source, oversized value, and binary credential. | Lifecycle, limits, and bytes are handled correctly; no stale material is silently reused. |
| C07 | Brokered API request supplies an alternate host, redirect, header, path traversal, or unapproved action. | Adapter enforces its fixed origin and permitted operation; no credential is sent to an unintended destination. |
| C08 | Target API echoes authentication material or returns verbose errors; logging is set to debug. | Defined response validation prevents exposure through broker-managed results and logs. Test failure behavior, not just successful responses. |
| C09 | Attempt to reuse a handle from another session or after expiry. | Broker rejects it even when the raw handle is known. |
| C10 | Change the recipient key during enrollment/provisioning; replay ciphertext at another broker. | Destination binding is checked, the mismatch is visible, and decryption/delivery fails. |
| C11 | Enable encrypted persistence with TPM available/absent and recovery material available/missing; attempt `--with-key=auto` host-key fallback. | Explicit capability detection and configured key mode prevent silent downgrade; a TPM-required profile fails when unavailable. A separately selected host-key-only profile is visible. No plaintext temporary file or false recovery success. |
| C12 | Deliberately malicious authorized credential-consuming test service prints its received credential. | Demonstrates that delivery mode is not model blindness or consumer containment; product wording must not claim otherwise. Use dummy material only. |
| C13 | Revoke a grant after a service has copied a static provider credential. | The test records that copied material remains valid until provider revocation/rotation; no false claim of remote erasure. |
| C14 | Child process, service journal, crash path, transcript, command arguments, and temporary artifacts are inspected with generated canaries. | No unintended leaks in brokered mode. Delivery-mode exposure is limited to the explicitly trusted consumer boundary. Disabling core dumps alone is not proof that plaintext never reaches persistent storage. |
| C15 | A real user-manager unit requests socket delivery using an authorized system-unit name and copied grant. | Reject outright. Same-UID metadata or a matching name cannot promote it into the supported system-unit profile. |
| C16 | Run an equivalent backup/restore job using a native `LoadCredentialEncrypted=` credstore baseline without the broker, alongside the approved broker flow. | Record setup, rotation/recovery effort, approval/audit benefit, and which workflow each operator would keep. No claim that delivery alone justifies the broker. |
| C17 | Repeat real system-unit identity and delivery under fixed service accounts and `DynamicUser=`. | Unit/invocation binding remains correct; unsupported DynamicUser behavior is explicit and cannot imply general support. Final consumer runs under its declared non-root account. |
| C18 | Exercise `LoadCredentialEncrypted=` socket behavior and selected encrypted custody on VMs with and without TPM support. | Verify actual protocol/bytes and protected key mode; unexpected behavior is unsupported, with no plaintext or weaker fallback. |
| C19 | Restart a unit and reuse its prior grant, handle, socket connection, or pending approval; race restart during unit-to-invocation resolution. | Invocation is re-established and stale authority rejected; no unit-name-only carryover or association with a new invocation. |
| C20 | Remove pidfd support or required systemd identity APIs; test socket access from another user and a compromised routing-name client. | Unsupported-host/permission failure is explicit and fail-closed; no raw-PID, user-manager, or same-UID compatibility fallback. |

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
| O08 | Measure approval prompts per operator per active day, dismissals and overrides under concurrent real workflows; exercise grouped approvals and scoped time-bounded grants. | Compare against the numerical ceiling declared before recruitment. Exceeding it fails the usability gate; grouping reduces prompts without expanding node/workload/action/account scope or duration silently. |

## Controller packaging, persistence, and migration

| ID | Scenario | Required outcome |
|---|---|---|
| D01 | Clean native installation on a host without a container runtime. | Controller starts under its dedicated account with documented native/external backing services and passes readiness; no implicit Docker dependency. |
| D02 | Clean Compose installation using the release image. | Controller runs non-root without privileged mode, host PID namespace, service-manager sockets, or container-engine socket; only declared ports and persistent state are required. |
| D03 | Restart native service and replace the controller container with the same image. | Controller identity, trust configuration, enrolled nodes, policies, and durable audit state persist; signing keys are not regenerated. |
| D04 | Upgrade each package through a supported schema migration, then exercise the documented rollback or restore procedure. | Node/API compatibility follows the declared version policy; failed migrations do not report ready or corrupt usable backup state. |
| D05 | Back up each deployment and restore to a clean host with its protected signing/trust material. | Controller and node trust recover; expired/revoked/consumed grants remain invalid, including revocations or consumption after a stale backup through the declared recovery reconciliation. Audit continuity is preserved and missing key material causes explicit failure. |
| D06 | Migrate native to container and container to native using a stable endpoint and preserved identity. | Existing nodes reconnect without unnecessary reenrollment; policy and state remain consistent; source instance is stopped or fenced. |
| D07 | Attempt to start the restored controller while the original independently serves the fleet. | The supported procedure prevents concurrent independent writers/issuers; no high-availability behavior is inferred from a successful restore. |
| D08 | Missing volume, inaccessible database, wrong ownership, absent signing secret, or invalid configuration. | Readiness fails with sanitized diagnostics; no empty replacement fleet, default keys, or plaintext fallback is created silently. |
| D09 | Send termination signals during an approval or operation; interrupt controller-to-database and broker-to-controller connections. | Both packages follow the same graceful-shutdown, retry, grant, and uncertain-result semantics with bounded timeouts. |
| D10 | Inspect image layers, release archives, container inspection output, generated units, logs, and backup artifacts using dummy canaries. | No baked-in secrets or accidental credential disclosure; signing material is protected in runtime inputs and backups. |
| D11 | Omarchy logout, shell restart, and operator-host suspension with a remote controller. | Remote controller continues serving other nodes; UI reconnects safely. When the controller shares the suspended host, both packages show the documented outage behavior. |

## Browser session handoff

### Browser harness and inherited gates

Implement these scenarios alongside feature code under the repository phase-testing rule. Use the [fleet harness above](#test-environment-and-evidence): disposable VMs with real systemd, the existing controller/broker contract, distinct service accounts, and the W1 stock-client matrix. Apply [the corrected loader authentication contract](../product/Specification.md#service-credential-loader-authentication), including its system-scope verification still outstanding.

The credential-loader connection requires uid 0, `SO_PEERPIDFD`, unit/invocation resolution, and the administrator's unit-to-credential mapping. The running agent is non-root in its own system unit and service account; its operation authentication inherits the fleet contract. Test rejection of forged routing metadata, user-manager peers, PID reuse, stale invocation identity, and missing/empty startup credentials through the fleet suite. Do not substitute mocked peer metadata or silently fall back to same-UID desktop execution.

Use one HTTPS staging fixture with cookie sessions, server-enforced maximum lifetime, revocation, and low-privilege accounts unable to change passwords/recovery details or mint durable credentials. Use one primary account and a second static account to test separation. The broker's login browser/process is inaccessible to the agent. No CI account pool or extension is required.

Use synthetic canary passwords and session cookies. Observe broker-managed logs, actual model-visible traffic, permitted screenshots, and exported artifacts. Keep harness-only evidence separate. Verify both successful authenticated work and absence of accidental disclosure; scans do not establish resistance to deliberate extraction. The agent's session cookies are intentionally available through its unrestricted browser API, but must not appear in the normal operation's model-facing result.

### Browser E2E scenarios

Original browser IDs are retained with the `B-` namespace so they cannot collide with fleet IDs. Deferred strong-mode and form-filling checks are not passed or removed requirements.

| ID | Scenario | Required result |
|---|---|---|
| B-E01 | Operator provisions and approves the account for a registered agent; broker logs in privately and imports session cookies into a fresh agent context | Agent completes the configured authenticated UI task; no source password or raw cookie in normal tool results; SPS sees ciphertext; audit binds workload and operation |
| B-E02 | Two static accounts use separate contexts on the same origin | Correct account/permissions in each; no cookie or result crossover; no reliance on tabs for isolation |
| B-E05 | Wrong password, timeout, disconnect, unsupported cookie handoff, or unexpected app error | Bounded safe status; no credential-bearing exception, screenshot, or raw error; partial login never reported as success; no fallback to agent-page filling |
| B-E06 | Agent supplies a different destination or attempts to replace the receiving context/workload | Only the administrator-configured origin and authenticated recipient accepted; unexpected login redirect rejected |
| B-E10 | Prompt injection requests another account or operation | Existing fleet policy/approval remains authoritative; caller cannot expand authorization through request fields |
| B-E11 | Successful and failed private login with available trace/video/HAR/console collectors | Private-login collectors suppressed before authentication; normal task artifacts contain no accidental canary password or cookie; cleanup/error paths included |
| B-E12 | Completion, cancellation, grant expiry, broker crash/restart, or agent unit restart | Further broker use denied; website session revoked within documented bound; copied cookie replay fails; revocation failure blocks account reuse |
| B-E13 | Application requires unsupported MFA, passkey, CAPTCHA, device binding, or durable refresh-token handoff | Explicit unsupported result or existing approved human handoff; no silent credential exposure fallback |
| B-E14 | Controlled compromised login fixture captures the password | Demonstrates recipient-site limitation; fixture excluded from approved pilot use; no secrecy-from-site claim |
| B-E15 | Agent attempts password/reset/recovery changes, authenticator enrollment, API-token minting, or durable app authorization using UI and direct endpoints | Application denies each for the pilot account; hiding UI is insufficient; reject onboarding if any path permits durable authority |
| B-E16 | Agent reads its own session cookie, then replays it before and after server-side expiry/revocation | Before expiry, session authority is expected; after expiry/revocation, replay fails. Record as mode-1 boundary evidence, not a non-extraction failure |
| B-E17 | Broker prepares the private session then crashes before or during handoff | No password/profile transfer; bounded cleanup of both contexts and server session; retry follows existing fleet uncertain-result semantics |

### Browser integration scenarios

| ID | Scenario | Required result |
|---|---|---|
| B-I01 | Existing fleet authorization plus browser-operation parameters | Unit/invocation, account mapping, approval, configured origin, receiving context, and deadline independently checked; no browser-specific grant issuer |
| B-I02 | Concurrent/duplicate requests or lost response | Existing atomic-use and retry rules prevent unintended duplicate session creation; uncertain state is reconciled or revoked |
| B-I03 | SPS recipient-key or account/operation metadata substitution | Reject unauthorized key or scope binding before release |
| B-I04 | Store expiry and owned plaintext copies | Host-broker lifecycle enforced; buffers disposed best-effort; no complete JS/browser-memory erasure claim |
| B-I05 | Plaintext exposure flag or model-visible resolver route | Operation refuses unsafe configuration; plaintext remains in broker's trusted consumer path |
| B-I10 | Nested credential-bearing errors and audit values | Only defined statuses/metadata serialized; no raw application error forwarding |
| B-I13 | Broker deadline versus website expiry/revocation | Enforce independently; server bounds session lifetime even if cookie expiry is modified; continuing activity cannot renew authority indefinitely |
| B-I14 | Cookie transfer with unrelated cookies, refresh material, invalid scope or wrong context binding | Import only approved app-session cookies with correct attributes into the fresh authorized context; never whole profiles/history or unrelated storage |
| B-I15 | Attempt agent-side access to broker login process, custody files, or debug endpoint | Fleet account/process separation prevents direct access; agent can still access its own handed-off session. This does not claim general strong-mode confinement |

### Deferred browser scenarios

These are outside the first gate. Implement and define their release evidence only when their corresponding feature is selected.

| IDs | Feature | Coverage retained |
|---|---|---|
| B-E03 | Account pool/scheduling | Worker/run/shard isolation, leases, mutation conflicts, crash recovery |
| B-E04, B-E07, B-E08, B-I09 | Login-UI-test mode | HTML/React/username-first input behavior; navigation/document races; hidden/duplicate/substituted fields; frame and broad origin-normalization cases. Exact configured-origin checks remain in B-E06/B-I01 for session handoff |
| B-E09, B-I11, B-I12 | Strong mode | Deny deliberate extraction through evaluation, prior listeners, network inspection, screenshots, storage, shell, profiles and alternate CDP; comprehensive egress including redirects/background traffic. Requires a constrained replacement for unrestricted agent browser tools |
| B-I06–B-I08 | Chrome extension | Native-host authorization, MV3 restart/replay, permissions; include headed and headless bundled Chromium compatibility |
| B-C01–B-C13 | CI/CD, deferred with Phase 5 federation | Earlier CI scenarios are deferred as a group: workload federation, untrusted PR refusal, parallel account leases, retries, artifacts, cancellation, rotation, audit and reruns. They are not W1 implementation or release obligations |

If a trusted DOM login recipe is needed inside the broker for the first application, test its actual selectors, origin checks, and failure behavior. That does not activate a generic form-filling feature or all deferred UI compatibility cases.

### Browser first gate

Require **B-E01, B-E02, B-E05, B-E06, B-E10–B-E17; B-I01–B-I05, B-I10, B-I13–B-I15**, plus the inherited fleet identity/isolation and W1 client requirements. **B-E09 and B-I11 are explicitly not first-gate requirements.** No CI or extension acceptance gate applies.

Require the application's disabled credential-management actions, server-side maximum session lifetime, and tested revocation before accepting a pilot account. A missing prerequisite blocks that application's participation rather than weakening the claim.

Record scenario implementation location, environment, version, date, result, and sanitized evidence. Run repository build/tests with implementation; documentation review does not establish a pass. Preserve the native fleet service job and deployment matrix. Claim mode-1 source-credential protection only; do not claim protection of the account from the actions its session authorizes.

## MCP and release integration

M-series scenarios implement W1's missing stock-client path; R-series implement W3 publication checks. All are proposed and unexecuted.

| ID | Scenario | Required result |
|---|---|---|
| M01 | Initialize and call tools over standard newline-delimited MCP stdio, including split/batched input, malformed messages, supported/unsupported protocol versions, and stdout diagnostics. | Supported initialization and calls succeed; framing and negotiation are version-correct; errors are bounded and stdout contains protocol messages only. |
| M02 | Exercise URL-mode capability present, absent, empty, form-only and version-mismatched; test the selected version's request state/correlation lifecycle. | URL delivery only when explicitly supported; sensitive inputs never requested through form mode; no reliance on removed completion notifications for the referenced 2026-07-28 contract. |
| M03 | Stock Claude Code completes approval, provisioning and the authenticated task; repeat in VS Code or Codex CLI using actual recorded versions. | Same broker identity/grant and operation contract; no OpenClaw or Telegram prerequisite. A custom protocol harness alone cannot establish compatibility. |
| M04 | Disable elicitation and chat transports; exercise explicit local-open and authenticated remote/operator-app fallback; decline, dismiss or expire input. | Reachable human input succeeds on intended host; deny/expiry never starts the operation. No default URL/confirmation-code output to MCP stderr or model results. |
| M05 | Scan actual supported-client transcripts, tool arguments/results, process logs and ordinary artifacts using canary links/codes/passwords/cookies. | No accidental exposure at default settings, including fallback and error paths. Verify human-only delivery rather than assuming every UI channel is private. Raw-link opt-ins are clearly outside default claims. |
| M06 | Cancel, time out, reconnect or replay elicitation requests and completion state; use another operator's link. | Operator/request/invocation binding, bounded status, safe cleanup and no grant expansion or duplicate consumption. Verify supported-client consent, URL display and no-prefetch handling. |
| M07 | Regression-test existing OpenClaw/runtime/CLI/Telegram routes after inserting elicitation and local/operator fallback. | Intended precedence and compatible behavior; no new plaintext model response or accidental switch to unsafe exposure flags. |
| R01 | Build release packages, inspect archives/image layers and perform clean native/Compose installs from documented instructions. | No secret/key/local-environment artifacts; explicit dependency/backing-service matrix; both quickstarts complete real pilot work. Confirm package-specific health, backup, restore, upgrade and uninstall instructions. |
| R02 | Install the intended npm release with `npx` on a clean host against a configured broker; inspect registry metadata and selected listings. | Entrypoint, runtime dependencies and configuration work outside the checkout; only intended packages lose `private`; advertised client capabilities match evidence. Registry/ClawHub presence cannot substitute for functional tests. |
| R03 | Compare endpoint defaults in manifests/core/docs and probe advertised public DNS, TLS, health/readiness at release time. | Consistent working endpoints. Deterministic builds do not depend on live DNS; separately recorded smoke checks establish deployment state. |
| R04 | Three external operators attempt setup and at least two repeat workflows without maintainer intervention during the 90-day window. | Record attempts, outcomes, chosen packaging, setup failures, O08 approval frequency, C16 alternative preference and willingness-to-pay interviews. Targets are not marked achieved without evidence. |

## Security and later milestones

S-series cases apply to active W5 pilot paths. A/X cases are deferred W4/W6 requirements; they do not expand the initial pilot. On activation, select the exact feature/consumer and extend these E2E and integration scenarios alongside implementation, per the repository phase-testing rule.

| ID | Milestone and scenario | Required result |
|---|---|---|
| S01 | W5: Generate and verify confirmation codes, rate-limit guessing, test collision/expiry/replay and confirm invalid codes cannot provision a request. | Cryptographic generator and declared adequate entropy; no accepted expired/replayed code or sensitive diagnostics. |
| S02 | W5: Exercise verification-token issuance, storage, expiry, use and replay for active authentication paths. | Only protected/hashed verifier state at rest, bounded expiry, intended one-time semantics, and safe errors. |
| S03 | W5: Perform operator login/refresh/logout through the real dashboard/API; inspect cookies, browser storage, source and documentation. | Actual token custody and expiration match the authoritative auth/security docs; resolve F-8 with evidence, not copied status text. |
| S04 | W5: Test production CSP/connect-src, baseline headers, allowed API/challenge calls, and forbidden exfiltration destinations in the selected deployment. | Intended app works under explicit production origins; no development localhost/wildcard schemes; HSTS enabled only with verified HTTPS readiness for its scope. |
| S05 | W5: Exercise password/account controls, distributed-IP guessing, lockout/recovery and slow/unavailable operator APIs. | Documented account-level protection alongside IP limits, usable recovery, bounded client timeouts and no accidental approval on failure. |
| S06 | W5: Inspect ignored/generated keys, tracked logs, release archives, logs and backup artifacts with dummy canaries. | Sensitive material excluded or protected as appropriate; no leaked canaries in shipped/default diagnostic artifacts. Confirm cipher documentation matches implemented HPKE primitives. |
| S07 | W5: Run complete successful/failed pilot paths with debug logging, child processes and simulated crash/artifact collection. | Mode-specific leakage and lifecycle assertions still hold; documented root/consumer/session limitations remain accurate. Frozen payment/guest findings retain explicit backlog status. |
| A01 | W4 deferred: Dry-run migration on a representative OpenClaw fixture/installation containing dummy plaintext credentials and unsupported references. | Masked findings and no file/key/config changes; unsupported cases explicit; no values in diagnostics. |
| A02 | W4 deferred: Import to encrypted store, rewrite SecretRefs, reload runtime and perform an authenticated operation; interrupt each migration stage and roll back. | Protected backups, recoverable/atomic updates, repeat-safe migration, actual post-reload consumption and restored original behavior on rollback. Removal of originals is a separate operator action. |
| A03 | W4 deferred: Provision after activation, omit or lose the age key, recover from backup, and exercise bootstrap backup warning. | Activation/reload semantics explicit; no false availability before reload or after key loss; tested documented recovery without plaintext fallback. |
| X01 | W6 deferred: Fulfill a named cross-workload request under allow/deny/approval policy with correctly bound issuer, recipient, resource and operation mode. | Only the approved recipient completes the chosen task; choose secret transfer, scoped credential or brokered action explicitly; audit establishes that contract. |
| X02 | W6 deferred: Substitute recipient keys/nodes/workspaces, replay ciphertext/grants, race one-use retrieval, and revoke or rotate during fulfillment. | Fail-closed binding and atomic lifecycle semantics; no treating ciphertext relocation as authorized re-encryption or granting an exchange record operation authority. |
| X03 | W6 deferred: Disconnect issuer/controller/recipient, lose a fulfillment reply, restore stale state and retry under expiry/tombstone/rotation lineage. | Bounded recoverable outcomes, no resurrected or duplicate authority, provider credential lifetime distinguished from grant/retrieval TTL. |

## Release evidence and adoption gate

Run the existing workspace build and tests for implementation changes, then the relevant broker integration suites and disposable-VM E2E scenarios. Add regression cases alongside each behavior change; mocked OS calls alone cannot satisfy identity scenarios. Apply dependency-guard before any proposed dependency change.

Record results separately for D-NATIVE and D-CONTAINER and link native/container migration evidence in both directions. Neither package is considered supported until its common and package-specific scenarios pass. Containerized controller testing must not be used to claim host-broker isolation was tested inside a normal application container.

Each scenario needs its implementation location, environment, execution date, result, and evidence reference recorded when implemented. Unsupported scenarios remain explicit release blockers for the corresponding guarantee, rather than being marked passed by documentation review.

Before expanding beyond the pilot, collect setup and repeat-use evidence from three external operators, aiming for at least two repeat users. Record failure reasons, approval frequency, controller availability issues, and whether a simpler existing secret manager would have met the same need. These targets are proposed validation criteria, not current traction.

## Execution record

Maintain one result row per scenario and deployment/client/profile combination when implemented. An absent row is unexecuted, never an implicit pass. Conditional/deferred cases must say why they do not apply; requirements for a claimed capability remain blockers until demonstrated.

| Scenario | Implementation location | Deployment/OS/client versions | Execution date | Result | Sanitized evidence |
|---|---|---|---|---|---|
| All proposed scenarios | Not implemented by this consolidation | Not executed | — | Proposed | No release evidence created by documentation review |

Existing workspace tests do not establish the new host or browser guarantees. Run `npm run build` and `npm test` with implementation changes, plus relevant Redis/PostgreSQL, actual-client, browser and real-VM suites. Do not satisfy system identity tests solely with mocked metadata or ordinary application containers.
