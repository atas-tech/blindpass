# P05 production coordinator execution — 2026-10-01

**Status: implementation in progress; P05 is not accepted.** The implementation
order exception preserves all original phase, stock client, inherited and release
gates. This supplements the [execution record](p05-workflows-and-clients-execution.md)
and the [paired acceptance plan](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/testing/phases/05-workflows-and-clients.md).

## Implemented changes

- The opt-in coordinator dispatches signed browser grants using the retained
  original kernel workload lease. Private authentication and runtime I/O run
  outside the state mutex. The Root runtime manager accepts fixed installed
  classes and checks invocation, UID, namespace, cgroup and private profile.
- Source custody checks runnable time and BOOTTIME. Prepared exchanges retain
  their original Source expiry and check it before each Source write. Missing
  or expired custody metadata denies new delivery. The website deadline remains
  independent after successful login.
- Confirmed closed browser records are retried after queue or storage failure.
  A successful scan marks the record for this process; ACK does not cause an
  endless loop. Restart intentionally replays canonical event keys, body and
  original close time. Failed reporting never restores workload authority or
  reverses cancellation. Recovery and delivery scheduling use BOOTTIME.

Registry plaintext is removed by custody purging after configured expiry;
new delivery checks fail closed at that deadline. Private prepared
frames may remain until their one-use exchange returns or its original grant
deadline, at most 120 seconds. The helper/Chromium and application have their
separate [memory limits](../../../helpers/login/README.md). The workload and
metadata manager do not consume Source. No forensic erasure is claimed.

## Earlier execution snapshots before correlation correction

| Check | Observed result | Limit |
|---|---|---|
| Approved host broker library | 214 passed | Includes two Source expiry cases, three closure scan cases and bounded manager partial-frame handling |
| Locked serial Rust workspace | 463 passed; four ignored | Desktop and PostgreSQL outage ignores remain open |
| Workspace all-target Clippy | Passed | Before final temporary poll diagnostics |
| Root build and npm workspace | Passed earlier in this implementation slice | MCP36, helper/channel55; 101 SPS service-gated skips remain |
| Actual fixture helper browsers | Host helper13 passed earlier in the slice | Component evidence |
| PostgreSQL component HTTP suites | Operations15, intents11, approvals7, channel3, lifecycle4 passed | Does not prove the integrated controller/node/runtime workflow |
| Signed-fixture production coordinator VM | Partial; overall gate fails at restart recovery | Uses a Root issuer fixture, not an actual controller/node or AI client |

The VM's assertions before the failed restart step reach actual HPKE provisioning,
private login, control/ACK availability while login is held, actual browser
identity, two stock reads and one reconnect, copied-cookie 200 before cancel and
401 after cancel, browser/profile removal, and a distinct final signed result
pair. The actual SIGKILL exit/status and restart are verified; only administrator
custody is re-provisioned. Restart account closure, copied-cookie denial and final
result assertions do not complete. The combined runner stops at that failure;
later helper/supervisor/journal regressions did not run in this slice. Earlier
dated component VM results remain separate.

Full Rust result log SHA256:
`084b9eb00069197e6ca5a648cc326a8ccee001f695ab60e9f0e0030ddb5536ca`.
The 463-case run precedes the final temporary numeric poll diagnostics. A fresh
complete gate for the current tree and exact latest release binary hashes are
still required. Test-first missing-field/method compilation failures are compile
failures, not behavioral red evidence.

## Recovery diagnostics and environment failures

The guest uses the pinned Ubuntu image, QEMU11.1.1, Node26.10.0 and the approved
private/stock browser profiles. Manager exchanges were observed completing in
roughly 75–104ms. The actual host stalled-frame test returns and closes after
eight seconds. Earlier driver recovery assertions failed, but their operation
selection was subsequently found incorrect, as described below. Kernel
samples include ext4 journal/data writeback and poll waits. Standalone dummy
fsync probes return in 5–9ms. These observations do not establish a single cause
for those earlier failures; unfinished accounts remain blocked or revoking.

The tracer was removed. Diagnostics read scheduling metadata and kernel function
names; no core dump or process-memory extraction was used. Direct I/O
(`cache=none,aio=threads`) preserves guest flushes. Optional failure holds are
capped at 240 seconds and do not constitute acceptance runs. A live read-only
sample observed zero block requests in flight and 2,000ms BOOTTIME progress over
two seconds. Kernel I/O-error counts were observed, but their device and relevance
were not established before the diagnostic guest ended.

The first workspace rerun failed CLI fixture copies with OS error122, quota
exceeded. A long private temporary path then failed five Unix socket tests with
`SUN_LEN` errors. A short alias to ignored private test storage gave the complete
passing rerun. Seven GB of generated Cargo incremental cache was removed;
unrelated shared temporary files were preserved.

Ordinary sandbox initialization subsequently failed while creating `/tmp/.git`
with quota exceeded. Automatic approval review then rejected the host evidence
recording command because workspace credits were exhausted; it explicitly made
no determination that the action was unsafe, and executed nothing. The privileged
guest handle was later missing, so no verified wait or new VM execution is claimed.
Ordinary execution and approved KVM checks subsequently recovered after the
owner reported restored credits. A further diagnostic run (24) reached recovery
but did not establish its outcome. Device classification found no `vda`/`vdb`
error matches; the seven other errors remain unclassified.

## Closure correlation and VM assertion corrections

A behavioral regression demonstrated that the delivery scan could withdraw a
different request's lease when two requests share a workload and recipe. Journal
schema 4 now stores the exact request event key and scans only its matching owner.
The existing full identity/recipe checks remain. Schemas 2/3 stay readable but
never fabricate missing correlation; confirmed cleanup can still be reported
without changing a guessed request. Older brokers cannot read schema 4; rollback
requires a matching protected journal backup. The host broker suite passes
216 cases, including the wrong-request regression and legacy schema-3 closure.

The VM driver also incorrectly read `operation_id` at the record's top level;
the protected schema places it inside `binding`. A previous closed record could
satisfy the restart wait before recovery ran. Earlier failures labelled
`recovery-account-close` therefore do not establish a 65-second recovery timeout
or a native runtime hang. The earlier kernel samples remain observations only.
The corrected driver selects the exact operation for activation and closure.
Three pure JS cases also cover helper record selection independently of journal
sort order. Actual run25 verifies cancellation and SIGKILL/restart recovery,
copied-cookie401 after each cleanup, two total logins with zero recovery relogin,
and distinct final signed results. Its combined runner later fails a helper
assertion selecting the last sorted record; that assertion now selects its exact
new record. Run26 fails earlier at helper metadata and does not repeat recovery.

A separate behavioral regression reproduces systemctl exit before stdout drain,
returning an empty manager reply. Waiting for pipe close fixes this race under
the existing output/deadline bounds; all12 manager cases pass. No single cause is
claimed for every earlier VM failure.

## Complete systemd regression run27

The clean run passes the full combined gate, including signed-fixture production
dispatch, cancellation and actual SIGKILL/restart cleanup, copied-cookie401,
zero recovery relogin and distinct final signed results. All later helper source
withholding, actual ENOSPC, detached journal, native sandbox/revocation,
supervisor/proxy/stock and journal SIGKILL/ENOSPC regressions execute and pass.
Original workload exit cancellation109ms; helper2-second override cleanup2144ms;
prepared supervisor EOF/SIGKILL cleanup70/60ms. The latter two supervisor cases
remain prepared-only, without imported source/session.

Runtime bundle SHA256:
`391200e3c0dc70a4972cf8a7e83d0eafd96dd6b66a53c0357830fc61ce718d00`.
Pinned image SHA256:
`612b2c0cc1bc413a6cb8c38fd611794caf0f2b436c50013d8b3794db12ad7354`.
This is actual broker/runtime evidence with a Root signed issuer fixture. It
does not pass P05-PC08's actual controller/node workflow or useful AI-client task.

## Host gates after coordinator correction

Root build and host npm pass: MCP36 and helper/channel60;101 SPS skips remain.
Actual host Chromium helper13 passes. Locked serial Rust workspace passes465
cases with4 inherited ignores; final all-target Clippy passes after a range-
pattern style correction. Syntax, formatting and whitespace checks pass.
The full Rust log SHA256 is
`9c961828630364bc3769f2a5050937320392cd2b4f8cca13cb73896957cea967`.
Seven tested binary hashes and execution log hashes are in
[structured evidence](p05-runtime-foundations.json). Owned VM/key directories
are zero after the full run.

## Recipient-key custody extension

Pending HPKE recipient keys now enforce independent runnable/BOOTTIME deadlines
with checked arithmetic. Clock failure retires all pending keys. Key lifetime
is checked immediately before and after cryptographic opening; late plaintext
is dropped instead of entering registry custody. Existing one-use behavior and
package/dependency boundaries are preserved. Keys are retired on custody purge
or attempted opening; no instantaneous memory erasure during suspend is claimed.

Three behavioral red cases reproduced retention after simulated suspend/clock
failure and an overflow panic. The corrected core suite passes53 cases. The latest locked workspace passes468
cases with4 inherited ignores; all-target Clippy passes. The actual Node26 guest
suspends for6 seconds: BOOTTIME advances6817ms and runnable time309ms while
the3-second key expires. Its live control opens once and replay is denied.
The complete combined systemd run passes; exact current binary inventory follows
the final Node24 run in structured evidence. The
bounded guest probe uses a generated dummy canary held only in trusted memory
and prints numeric timing/status, never plaintext or key material. It is a
recipient-key component and does not establish P04-D4 fleet provisioning or the
full Source/grant/website lifetime matrix.

## Node24 compatibility and declaration work

The official [Node24.21.0 release](https://nodejs.org/en/blog/release/v24.21.0)
was fetched into ignored temporary test storage and verified against the exact
official Linux amd64 archive SHA256:
`fd8e59d5a511510f6a298afb548f18c7d2b1be404d8b4a27d94fbe49f56cb2d6`.
No system-wide runtime installation was performed. Host build, workspace tests
(MCP36/helper-channel60/SPS101 skips) and actual helper13 pass under24.21.0.
The built MCP bytecode file is identical to the prior Node26 build.

An initial Node24 guest completed its scenarios, but editing the live Bash
runner caused offset corruption, an accidental second invocation and overall
exit70. That run is not counted as a complete gate. Cleanup completed. A frozen
script copy then passes the full Node24 systemd gate, including coordinator
restart, stock browser and actual recipient-key suspend: BOOTTIME6901ms versus
runnable101ms. Full Node upstream license text is verified in its runtime bundle.
Bundle SHA256:
`a54503c4334bb9bbd291adc0fb51ff193d513bb5df10f64b93842d8ecb72c1b1`.

Thirteen workspace manifests and matching lock metadata now declare
`^24.21.0 || ^26.10.0`. Non-engine lock metadata is byte-equivalent under
canonical JSON comparison; dependency versions/resolutions/integrities and
package boundaries were not changed. Existing reviewed dependency graphs apply.
Two behavioral red declaration/CI cases pass after the change. Regular CI and
the manual workspace/service job now contain both pinned profiles; remote CI
execution is not claimed. Final post-metadata local build and workspace gates pass on both pinned profiles.
Ordinary npm still skips101 service-gated SPS cases; remote CI has not run.
The frozen Node24 VM inventory records all eight exact release binaries in
[structured evidence](p05-runtime-foundations.json), with its log and runtime
bundle hashes and zero remaining owned VM/key/driver directories.

## Required continuation

Finish lost-response and unknown-runtime reconciliation, the managed application
and full lifetime matrix, P04-D4
provisioning, useful actual Claude/Codex tasks, independent suspend/clock and full
30-minute managed VM checks, owner/withdrawal retention, elicitation and ordered
fallback, native host-B backup/restore, slice commits, and all original
inherited/two-host/pilot acceptance. The proposed native binaries are
[blocked by dependency review](../../product/decisions/0007-p05-native-backup-dependency-review.md).


## Actual controller/node driver preparation

The opt-in `BLINDPASS_P05_FLEET_BROWSER=1` VM profile stages the actual
SQLite controller and unprivileged node relay. Enrollment/issuer pin, policy,
workload registration and browser approval use the real APIs; signed grant,
time, result and ACK delivery use the node channel. Source provisioning uses
the actual HPKE CLI. This remains a fixture website/operator profile and does
not execute useful stock AI clients or a second host.

Driver regressions cover empty204 responses, real UUID workload/manual
operation IDs, SHA-256 automatic-intent IDs, exact nested journal selection,
private subprocess/error bounds, provisional `executing` and authoritative
`revoked` cleanup metadata. The full Rust workspace passes468 with four
inherited ignores and current all-target Clippy passes. Current Node24 ordinary
workspace checks pass with MCP36/helper-channel73 and101 SPS skips.

Initial VM attempts failed in the driver before enrollment (empty successful
response), after workload creation (fixture-only ID assumption), and during a
held login (incorrect provisional-status expectation). The last failure shows
one actual POST with verified helper identity and no observer failure. Waiting
for `uncertain` instead of the controller's `executing` held the response until
the helper timed out. The reply-staging marker does not establish failed
journal reservation or zero authentication attempts. The corrected full VM
run passed as recorded below. Failed attempts establish no completed workflow.

## Actual controller/node execution — 2026-10-01

The frozen Node26.10.0 driver exits0 in the pinned Ubuntu24.04/KVM guest
(systemd255.4-1ubuntu8.17, kernel6.8.0-139-generic). The actual SQLite controller
accepts enrollment with checked issuer/node fingerprints, policy, workload and
human approval. The actual unprivileged node relays signed authority, time,
results and ACKs. The production broker invokes the separate private helper
after actual HPKE CLI provisioning and publishes a kernel-bound browser context.

Both login POSTs independently observe durable exact helper identity before
authentication. The held first login produces the expected provisional
`executing/result_uncertain` controller result while APIs remain responsive.
After releasing it, the stock browser tool reads the report twice and reconnects
once. Cancellation closes the exact journal record, removes the profile and
rejects a copied cookie with401; the controller retains `revoked` authority
with confirmed `browser_session_closed` metadata.

The second operation reaches ready before actual broker SIGKILL. After restart,
only the administrator credential is re-provisioned. Recovery closes the account
and exact browser identity/profile, rejects its copied cookie with401, returns
the original request response on replay and delivers confirmed closure through
the actual node channel. Total login count is2; recovery performs0 logins.
Generated Source, administrator and session canaries are absent from scanned
normal task output and service journals.

All later combined helper/runtime/persistence regressions pass. The2-second
helper override clears its verified cgroup in2140ms; prepared-only supervisor
EOF/SIGKILL cleanup measures40/60ms. Actual RTC suspend expires a3-second
recipient key with6202ms BOOTTIME and391ms runnable time. These are component
measurements, not the full production deadline matrix. Active helper units at
the end:0. The owned overlay/key/frozen-driver cleanup completes.

Log SHA256: `db80beb326c89e55a19852d5af2349be17e84a85e43d3db373355567b4ef779f`.
Runtime bundle SHA256:
`cb3fd2680375dc729d869a1327b03ea05c95c91770fde9a1d4186ccd8df353f8`.
The [structured record](p05-runtime-foundations.json) retains all10 exact release
binary hashes, source hashes and the pinned image hash. Final ordinary workspace
gates pass on Node24.21.0 and26.10.0: MCP36/helper-channel73, with101 SPS skips.
Full Rust passes468 with4 inherited ignores; current all-target Clippy passes.

This executes the fixture controller/node lifecycle portion of P05-PC08.
The operator is a disposable API fixture; provisioning is the local HPKE CLI.
Useful actual AI clients, selected managed Grafana integration, P04-D4 GUI,
native backup/restore, full clocks/deadlines and two-host/inherited acceptance
remain required. A second frozen actual controller/node run on Node24.21.0 also exits0 with all
combined regressions and the same two-login/no-recovery-login lifecycle. Its
helper override cleanup is2145ms; prepared-only supervisor EOF/SIGKILL60/60ms.
Recipient-key RTC measurements are6582ms BOOTTIME/100ms runnable. All owned
VM/key/frozen-driver directories are removed. An initial persistence log-file
creation race prints one missing-file diagnostic before the bounded readiness
loop succeeds; kill/recovery/ENOSPC assertions pass. Both dated exact inventories
are retained in the structured record.


## Managed application integration preparation

P05-PC12 adds the selected Grafana13.2.3 managed OAuth Viewer to the actual
controller/node driver. Account setup uses one separate trusted login under the
login UID, revokes it and counts it separately. Production operations retain
actual HPKE provisioning, installed reverse proof and journal gates. The fixed
Root0700/0600 Unix backend supplies the installed revoker without a test override.
Four profile/session/bootstrap/report-step cases pass; the stock flow explicitly
waits for the real managed report before snapshotting. OAuth observation has a
behavioral red/green and receives no Source/code/session arguments.

Node24/26 full workspace gates now pass with MCP36/helper-channel78 and101 SPS
skips. The added dummy process regression retains exit37 before cleanup, while
raw output and its canary are withheld. One overlapping Node24
run failed an existing DR-E08 approval heading wait; serial complete reruns pass,
and the failed log remains. This does not establish a load SLA.

Managed VM attempts1/3/4 fail in app setup; attempt2 reaches actual approval,
private login and ready browser but fails the stock-task assertion after one
independently verified login. Attempts3/4 fail readiness; attempt4 retains a live
app process before controlled cleanup and0 kernel OOM events. It does not retain
health status/version, so the cause remains unresolved. Setup now captures only
fixed startup flags, counters and exit/health metadata from a transient private
pipe; raw app logs never enter normal output. Attempt5 again fails readiness:
database/migrations/completion flags observed, HTTP listener absent, health0,
no error lines or kernel OOM; process alive before cleanup. These coarse flags
do not establish which subsystem prevented readiness. Attempt6 passes the
managed lifecycle with disposable application state on private Root `/run`;
the broker recovery journal remains on disk. The storage hypothesis is not a
confirmed cause. No useful AI-client pass is claimed.

The existing distribution includes full upstream LICENSE and NOTICE.md; the
[structured evidence](p05-runtime-foundations.json) records their hashes and all
failed attempts. No dependency version or package graph changes. A temporary
approval-service credits failure rejected one host check; after acknowledgement,
the same approved regression and later VMs executed. Existing dependency,
implementation-order and VM authorizations were retained.


## Actual managed controller/node lifecycle — Node26.10.0

Frozen P05-PC12 attempt6 exits0 on the pinned Ubuntu24.04/KVM image with
Grafana13.2.3. The actual SQLite controller, enrolled unprivileged node, production
broker, separate private helper and kernel-bound browser complete the same
approval/HPKE/identity lifecycle described above. One bootstrap external Viewer
login is counted separately and revoked; the two operation authentications each
independently observe durable exact helper identity. Stock report reads:2;
reconnects:1. Valid durable-account mutations return403; recovery API returns401.

Cancellation and actual broker SIGKILL/restart both close the exact browser
profile and reject the respective copied managed session with401. Recovery
performs0 logins. Confirmed closure traverses the real node channel. The fixed
Root0700/0600 administrator backend uses the installed revoker path. Source,
administrator and session canaries are absent from scanned normal output and
journals. All later helper/runtime/stock/persistence component regressions pass.

Helper2-second override cleanup:2115ms; original-process exit:84ms;
prepared-only supervisor EOF/SIGKILL:60/50ms. Actual6-second RTC suspend expires
the3-second recipient key with6379ms BOOTTIME/89ms runnable time. Active helper
units at end:0; the owned overlay directory is removed. These component bounds
do not establish the full production deadline or Source/grant/website matrix.

Log SHA256: `8a783680c43ab5ac6a97526d1c5e4d204938edf67df6bfb5020d870b51a828c2`.
Runtime bundle SHA256:
`4a38f663084399391e86728d6a321e3988c584587517602b243d2d31b111d5c9`.
Grafana bundle SHA256:
`e9847b602622a2f76434c888d1683f8bcaca0b1bc17f0838bd737e61a0a9a868`.
The structured record retains exact10 binaries, driver sources and image hash.

Application SQLite/config/identity state lives in Root0700 private `/run` for
this disposable profile. It remains live across broker SIGKILL; no application
or whole-guest reboot guarantee follows. Startup output is drained through a
trusted private Root pipe, with bounded transient line memory and fixed counters
only; buffers/partial line are cleared on close, without forensic erasure claims.
The broker's protected disk journal is still exercised for recovery.

At that snapshot the fresh pinned Node24 managed VM was running; its completed
result and later complete rerun are recorded below. Its first launch stopped before
guest execution at the host runtime-version guard; PATH selected Node26 while
Node24 was requested. That failed launch is retained and supplies no Node24
managed evidence. Useful Claude/Codex tasks, P04-D4 GUI provisioning, reviewed
native backup/restore, full lifetimes, two-host and inherited acceptance remain
required. P05 remains open.


## Node24 managed partial result and cleanup regression

The fresh correctly pinned Node24 VM completes the managed controller/node
lifecycle: stock2 reads/1 reconnect,2 independently verified operation logins,
0 recovery logins, copied managed sessions401 after cancel and broker SIGKILL,
durable mutations403/recovery401, confirmed real controller closure and canary
scans. It then fails the later `isolated-browser-guest` prepared-only
`supervisor-loss` component. The complete VM exits1; subsequent persistence and
RTC components do not execute. Exact failed substage was not retained, and no
cause is asserted. Kernel OOM events0; helper override cleanup2143ms. The owned
overlay is removed. Its dated log hash and runtime bundle are retained separately
in the structured record; it does not replace the complete Node26 pass.

P05-PC13 extracts the prior immediate profile assertion. A behavioral red with
three actual pure failures reproduces delayed profile removal after cgroup
emptiness. The corrected three cases pass, requiring both cgroup empty/absent
and profile absent within the same original five-second BOOTTIME bound,
including supervisor exit. Permission errors deny cleanup without reflecting
private paths. This is a test-driver observation correction; it does not prove
the cause of the earlier VM failure or establish new production cleanup.
At that snapshot the fresh frozen Node24 complete VM was running with fixed
mode/stage/code failure diagnostics; its completed pass is recorded below. Fresh full ordinary gates on Node24.21.0 and26.10.0 both pass81 helper/channel
cases and36 MCP cases, with101 SPS skips. Both final pinned workspace builds
pass. Rust source is unchanged since the468-pass/4-ignore and Clippy gates.
Current relative links:109 checked/0 missing across eight guides; Node/shell
syntax and `git diff --check` pass.


## Complete Node24 managed rerun and actual client readiness

Frozen managed Node24.21.0 attempt3 exits0. It repeats the actual controller/node/
Grafana lifecycle and all combined components, including the previously failing
prepared-only supervisor-loss assertions, actual persistence SIGKILL/ENOSPC and
recipient-key RTC. Helper2-second override cleanup2177ms; original-process exit
111ms; prepared-only supervisor EOF/SIGKILL70/60ms. Actual6-second RTC expires
the3-second key at6687ms BOOTTIME/116ms runnable. Active helper units0;
owned VM/key/frozen-driver directories remaining0. The earlier Node24 failure
is preserved, and this pass does not establish its exact cause.

The structured record retains its exact log, runtime/image,10 binaries and
source hashes separately from Node26. The selected managed lifecycle now has
complete VM execution on both pinned profiles. Application private `/run` state
remains live during broker SIGKILL; app/guest reboot, full clocks/deadlines and
phase acceptance are still unverified.

Actual installed Claude Code2.1.286 and Codex CLI0.159.3 also each execute one
MCP dummy-report tool and answer12 artifacts using existing host authentication.
This readiness exercise supplies no Source or application session and runs no
broker/website task. Claude uses modern per-request `2026-07-28` metadata with
explicit form/URL capability. Codex requests `2025-06-18` while declaring both;
the tested revision gate denies URL elicitation for that connection. No actual
URL elicitation, delivery/fallback or transcript secrecy is established.

The first Claude launch exits before MCP initialization; an explicit argument
delimiter after its variadic config option permits the actual call. Raw client
stdout/stderr are retained only transiently by the trusted scanner and withheld
from evidence; fixed metadata and byte counts are emitted. Session persistence
is disabled; private temporary files are removed. These controls make no
forensic erasure claim. The new metadata extractor passes4 test-first cases;
its initial missing-module failure is not a prior production behavioral bug.
A separate two-stub failure check reproduces the runner returning0 despite failed
clients; the final guard returns1. Current unchanged source-bound execution passes after that guard, with both
actual clients each calling the dummy tool once and answering12 artifacts.
The private temporary profile is removed. Latest full workspace gates pass85
helper/channel and36 MCP cases on each pinned Node version;101 SPS skips remain. Original P05-E01/M06/M07 authenticated-client tasks
remain required.

Final current workspace builds pass on both pinned profiles. Current Node/shell
syntax, Python runner compilation, JSON,109 relative links/0 missing and
`git diff --check` pass. Obsidian reading-view rendering and remote CI were not
run. The101 SPS skips and4 inherited Rust ignores remain unexecuted checks.

## Actual AI transport foundation — P05-PC14

The protocol-only MIT wrapper exports pass five actual host stdio cases:
legacy and modern legacy-registry startup plus legacy and modern bare embedding,
and the existing callback/schema case. The first host run passes the three
baseline cases and fails both new embedding cases before the exports exist.
The restricted run times out in all four stdio cases and cannot establish that
feature failure. The rebuilt bundle contains the new exports and retains its
existing license/package boundary check; no dependency graph changes.

Nineteen pure Root bridge, frame, stock-client, workload worker, private pipe and
task-observer cases pass. Two Python final-message parser cases pass. Initial
new-module failures are recorded as missing implementation, not prior production
bugs. Behavioral reds also exercise the missing startup/private-cancel fence
and missing final-transcript scanner. Private replies can settle while a normal
observer awaits control, avoiding a serialized-output deadlock. Stock stderr is
counted and discarded; invalid input and failures have fixed text.

The current Node26 build and subsequent full workspace gate exit0:104 helper/
channel cases and38 MCP cases pass;101 SPS service skips remain. The current
Node24 slice has not run yet. Source inspection and doubles do not establish the
authenticated client task. Original GUI, URL elicitation/fallback, full clock/
lifetime, native/two-host, inherited and acceptance gates remain required.

### P05-PC14 current AI progress and private temporary directory

The later generated-administrator fixture checks and fixed upstream-error
diagnostic bring the current workspace totals to107 helper/channel and38 MCP
cases on Node26.10.0 and24.21.0. Both host workspace runs pass;101 SPS service
skips remain. Four Python final-answer and bounded host-runner cases pass.
The Node26 build passes. The Node24 current build is still pending at this
checkpoint. Earlier104-case and unrun-Node24 statements above are historical.

The actual Claude2.1.286 dummy metadata probe identifies its ordinary handshake:
`server/discover`, `subscriptions/listen`, discovery again, tool list and call.
The bridge now permits the standard subscription method; its behavioral red
and green are recorded. This probe supplies no authenticated application task.

Claude VM7 performs real approval, one independently observed private-helper
login and durable exact browser-invocation readiness. It fails at the actual
stock `browser_navigate` callback. It does not read the report or complete
copy/reconnect/cancellation closure; its failure is preserved without a pass
claim. Earlier VM1/2 fail at Root transport setup; VM3–5 do not deliver a
login. VM6 reaches login/readiness but lacks VM7's exact tool diagnostic.

The installed pinned stock browser starts an additional Unix socket under
its temporary directory when binding an attached browser. The AI workload's
read-only system permits writes only in private home/output. The next change
creates a0700 private temporary directory inside its permitted home, sets
`TMPDIR` there and adds `UMask=0077`. Unix-only addressing, the read-only system
and existing writable-directory limits remain. This is a source-supported
candidate explanation; VM8 is running and has not verified the correction.

The diagnostic test first fails because no category is emitted, then passes
for read-only, permission, address-family, refused connection, timeout, unknown
upstream and transport errors. Generated Source/session/endpoint canaries stay
out of the fixed diagnostic and generic protocol error. Actual upstream error
text is never printed. The Root pipe accepts only exact whitelisted categories.

The restricted Node26 workspace run exits1 and includes a Node SIGABRT.
`coredumpctl` confirms `InternalCallbackScope::Close` and the asynchronous-ID
assertion in the broker-client test process; the approved host run passes.
The cause of that runtime assertion is not established. No core was extracted
or host configuration changed. It is separate from the failed browser callback.

At the next checkpoint, the current Node24 build also passes. VM8 still fails
at navigation after one independently verified login and browser readiness.
Its new private diagnostic reports a stock transport failure, rather than a
classified upstream tool error. It does not establish the temporary-directory
fix or any task/closure acceptance. The pinned stock server advertises and can
emit `notifications/tools/list_changed` during browser attachment; the adapter
previously rejected it. A meaningful first-red test reproduces that rejection;
the correction accepts the standard notification without adding advertised
browser tools. Additional tests confirm fixed decode/frame/notification/reply-ID
failure categories with generated private canaries withheld. VM9 is pending.

VM9 advances through actual first report snapshot, private copied-session200 and
stock reconnect. The second snapshot returns an upstream error; cancellation
and closure remain unverified. The exact cause of that error is not established.
The next test driver prompt explicitly requires sequential calls and describes
its intentional reconnect. The observer now requires a fresh completed
navigation and wait before each counted snapshot; a meaningful red reproduces
its previous acceptance of a repeated snapshot, and the correction passes.
Bounded diagnostic traces use only the six fixed tool names or `other`.
No source text, arguments or private values are included. The current full host
workspace gate passes on both Node profiles:110 helper/channel and38 MCP cases,
101 SPS skips. There are23 pure AI cases and four Python cases. VM10 is pending.

### Actual Claude authenticated task and combined VM pass — P05-PC14

VM10 exits0. Actual Claude Code2.1.286, Node26.10.0 and the pinned Ubuntu24.04/
systemd255 guest perform one broker operation with controller approval, actual
node dispatch and local HPKE Source provisioning. One operation login is
independently verified; two stock report snapshots across one reconnect each
follow fresh navigation/wait. The actual final client answer parses12 artifacts.
The private copied-session probe returns200 before cancellation and401 after;
the exact browser cgroup/profile is removed and controller closure confirmed.
The connected closure check measures28,790ms, including waiting for the final
client result, within its30s bound. Root transport denies the actual different
UID; normal MCP/client/journal Source/session canary checks pass. The host profile
is removed. The complete combined helper, reverse pidfd proof, supervisor,
stock-channel, journal SIGKILL/ENOSPC and RTC custody gates also finish0.

The runtime bundle is
`cffb6e5d5e9f26f4cfd9e30d0cb57bd8a4d803a86f1cdfe133fae70f404e6f8c`.
VM10's frozen source hashes and terminal log are preserved locally and hashed
in structured evidence. This establishes only the tested API operator/local
HPKE authenticated application workflow. It does not establish GUI provisioning,
URL elicitation/fallback, full lifetime/clock/native/two-host/inherited acceptance.
VM9's exact second-snapshot error remains unproven; the later sequential-prompt
pass does not retrospectively prove a concurrency cause.

The next actual Codex profile disables host shell, shell snapshots, subagents,
apps, remote plugins, hooks and web search through one-off flags/configuration,
following [official configuration documentation](https://learn.chatgpt.com/docs/config-file/config-basic).
The installed CLI reports shell_tool and the named integrations false; it still
reports unified_exec true despite an explicit disable request. The argument test
establishes requested configuration, not a complete adversarial tool-isolation
guarantee. A test-first missing-function red and three green Python host-runner
cases are recorded. Codex VM1 is pending; no second-client task pass is implied.

Codex VM1 finishes1 before actual AI task entry: its host readiness budget expires
at `guest-info`; the guest later fails the original-workload precheck at `exit`.
Catalog and packaged broker/MCP metadata checks finish, but no private helper
login or authenticated Codex task executes. The exact precheck cause is unknown.
The next diagnostic splits that exit stage into request/grant/consume/kill/
cancellation/deadline/unit steps, changing no bound or acceptance assertion.
Its syntax check passes; it has not run in a VM. No further rerun is claimed.
The owned disposable key, driver and VM-overlay counts are each0 after cleanup.

### Actual Codex authenticated task and combined VM pass — P05-PC14

Codex VM2 passes the original-workload precheck (110ms exit withdrawal) and
launches Codex, which exits1 before any MCP request/login. A local actual CLI
reproduces the failure: JSON environment-map syntax supplied through `-c` is
interpreted as a string, not a TOML map. Fixed dotted environment keys pass
Python TOML parsing and the actual native Codex configuration loader. No raw
client error text or private values are retained. Two setup-wait cases and one
configuration case bring Python checks to eight (six runner/two final parser).
The fixture readiness wait is now bounded600s for preparation only; the180s
client task and all broker/helper/grant/closure bounds are unchanged.

Codex VM3 exits0. Actual Codex CLI0.159.3 requests the broker operation, receives
real controller approval/node dispatch/local HPKE provisioning and performs one
independently verified private-helper login. Two real report reads follow fresh
navigation/wait across one stock reconnect. The final answer parses12 artifacts.
Copied session200 before cancellation becomes401 after; exact runtime/profile
removal and controller closure pass. Closure measures19,710ms including final
client-result observation. Root different-UID denial and normal Source/session
canary scans pass; host profile removal is verified. The complete combined
helper/reverse-pidfd/supervisor/stock/journal SIGKILL/ENOSPC/RTC custody gate also
finishes0. The runtime archive digest matches Claude VM10; source inputs and logs
are hashed in structured evidence. Owned key/driver/VM directories remaining0.

Both stock clients now have actual useful application-task evidence for the
selected Node26/systemd255 API operator/local HPKE profile. Node24 component/
lifecycle and workspace evidence remain separately scoped. Actual GUI
provisioning, capability-checked URL elicitation/fallback, full lifetimes/clocks,
native backup/restore, two-host/inherited/owner and release gates remain open.
The first original-workload precheck failure has not been assigned a cause;
its later110ms pass does not prove that it was a transient resource issue.

## Ordered delivery component — 2026-10-02

Both actual stock task results above remain selected API operator/local HPKE
evidence. The later [delivery component](p05-delivery-2026-10-02.md) adds14 pure
router and10 actual SDK stdio cases, with fixed order, exact capability/client
gate, safe uncertainty, deadline/retry/persistence and host/operator fences.
Both pinned Node builds/workspace gates pass62 MCP and110 helper/channel cases;
101 SPS skips remain. Eight Python cases pass. Production durable ledger,
GUI/real human delivery, reviewed stock-client UI privacy and original full
lifetime/native/two-host/inherited/owner gates remain open.
