# P05 workflow support matrix

**Updated:** 2026-10-02 (includes the 2026-10-02 delivery, signed-offer and offer-ingestion results). **Status:** Application prerequisites, runtime foundations and fixture/managed controller/node lifecycle execution;
P05 and W1 are not accepted. The
[phase plan](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/phases/05-workflows-and-clients.md)
owns the full scope. See the
[execution record](../testing/evidence/p05-workflows-and-clients-execution.md).
The [coordinator record](../testing/evidence/p05-coordinator-2026-10-01.md) adds
actual controller/node cancellation/restart cleanup and the complete combined
systemd regression run. The selected managed Grafana lifecycle and combined component gate now pass
on both pinned Node24.21.0 and26.10.0 profiles. Earlier failures remain recorded.
**Final tree (2026-10-02, later):** the component and managed lifecycle gates and the Codex task were rerun on Node 26.10.0 only; the Claude task passed 1 of 3 attempts; the Node 24.21.0 VM profile was not rerun. See the [completion review](../testing/evidence/p05-completion-review-2026-10-02.md).
Actual Claude and Codex selected API operator/local HPKE application tasks pass
on Node26. Full phase acceptance remains open.

**Stock-client scope.** Both stock-client passes (Claude Code 2.1.286 and Codex CLI
0.159.3) ran on 2026-10-01 on Node 26.10.0 only, with API-operator approval and
local HPKE provisioning. Both predate the PV05/PV06 signed-offer broker and
controller changes of 2026-10-02 and have not been rerun against them.
Neither run exercised URL elicitation. Claude Code 2.1.286 sends per-request
`2026-07-28` metadata without `initialize`; Codex CLI 0.159.3 initializes at
`2025-06-18`. The URL-elicitation gate requires `initialize` at `2025-11-25`, so
it always denies URL mode for both clients: the URL-capable variant of P05-E01 is
**unsupported** for Claude Code 2.1.286 and Codex CLI 0.159.3. The supported
human path is the authenticated operator console.

## Current evidence

| Integration/profile | Recorded version | Result and limits |
|---|---|---|
| Repository HTTPS fixture | Current source in [fixture-app](../../tests/browser-handoff/fixture-app) | 13 HTTP checks, two pure revocation checks and the earlier real Chromium UI check pass; account-wide recovery additionally fences pending login; application prerequisites only |
| Fixture JavaScript runtime | Node.js24.21.0/26.10.0 | Host build/workspace/helper and complete selected systemd coordinator/stock/suspend gates pass on both; declared range `^24.21.0 \|\| ^26.10.0`; remote CI and complete AI-client workflows remain open |
| Fixture UI runtime | Playwright 1.58.2, Chromium 145.0.7632.6 | Browser sandbox enabled, generated certificate key explicitly trusted; no broker/runtime-channel isolation proof |
| Fixture test TLS | OpenSSL 3.6.4 | Disposable CA; trusted HTTPS succeeds and untrusted HTTPS fails |
| Grafana OSS local-password Viewer | 13.2.3, official Linux amd64 archive | **Rejected:** UI email editable, own profile/email and password PUTs return 200; copied session returns 401 after administrator logout |
| Grafana OSS auth-proxy Viewer | 13.2.3, private Unix backend | **Rejected:** external metadata does not prevent valid profile/email mutation (200) |
| Grafana OSS managed Generic OAuth Viewer | 13.2.3, PKCE, no refresh tokens, private Unix backend, two isolated organizations | **Application prerequisites pass:** real report/profile UI, seven valid mutation denials (403), recovery disabled (401), copied-session revoke/expiry denial (401), live 5m maximum across five rotations; no integrated browser task claim |
| Disposable OAuth test issuer | Repository standard-library harness | Three config/HTTP/Chromium cases pass: fixed callback/client binding, PKCE, one-use code and immutable Viewer identity; not a production IdP |
| Forgejo read-only collaborator | Not selected/version not tested | Documentation research only; repository permission alone is not a demonstrated credential-management restriction |
| Claude Code stock client | 2.1.286 on 2026-10-01, per-request `2026-07-28` metadata (no `initialize`), Node26.10.0/systemd255 selected managed Grafana profile | Actual approved broker/node/local HPKE task passes: two report reads, stock reconnect, parsed12, copied-session401 after cancellation and exact runtime removal. API operator profile, before PV05/PV06; URL elicitation is denied by the revision gate (unsupported); GUI/fallback/full lifetime and release acceptance remain open |
| Codex CLI / VS Code stock client | Codex CLI 0.159.3 on 2026-10-01 (VM3 log 2026-10-01 22:51 +0700; the execution record writes it up under its 2026-10-02 heading), `initialize` at `2025-06-18`, Node26.10.0/systemd255 selected managed Grafana profile; VS Code not selected | Actual approved broker/node/local HPKE task passes: two report reads, stock reconnect, parsed12, copied-session401 after cancellation and exact runtime removal. Earlier preparation/configuration failures retained. API operator profile, before PV05/PV06. Caveat: the CLI reports `unified_exec` true despite an explicit disable request, so the requested tool-disable flags do not establish adversarial host tool isolation. URL elicitation is denied by the revision gate (unsupported); GUI/fallback/full lifetime and release acceptance remain open |
| URL elicitation / out-of-band fallback | Ordered router and2025-11-25 SDK adapter; production providers not enabled | Fourteen component/ten actual stdio cases pass: exact capabilities/client gate, ordered safe fallback, definite/uncertain failure, retry/deadline/persistence and host/operator fences. Modern continuation, durable production ledger, real provider/operator and reviewed stock-client UI/transcript evidence remain open. URL mode is unsupported for Claude Code 2.1.286 (modern per-request metadata) and Codex CLI 0.159.3 (`2025-06-18`): the gate always denies it and routing falls through to the next configured provider |
| Private login helper | Playwright 1.58.2 / Chromium 145.0.7632.6 / Node 26.10.0 | 11 library/fixture worker checks and managed Grafana worker check pass; actual Rust caller/separate-UID/root-only socket guest login/revoke passes; latest 2s override clears verified cgroup in 2,140ms with journal canaries absent; signed-fixture broker cancellation/restart lifecycle passes; full lifetime/AI-client acceptance pending |
| Actual stock browser tool Unix channel | `@playwright/mcp@0.0.83`, exact 1.64 alpha client library attached to Chromium 145.0.7632.6 | Both host prototype and actual DynamicUser/PrivateNetwork guest report/snapshot/reconnect pass; agent is separate UID, profile private, outside-loopback CDP and another UID denied; actual Rust kernel-pidfd/unit/invocation proxy denies another same-UID unit and restarted invocation before backend attachment; signed-fixture production coordinator passes; actual fixture controller/node passes; full lifetime and complete AI-client tasks pending |
| Official SDK transport, legacy wrapper and broker tools | Server/core 2.2.0, Zod 4.6.5 / Node 24.21.0 and 26.10.0 | 62 SDK/client cases passed on both Node profiles (2026-10-02 full build/workspace runs), including delivery component/stdio. After the 2026-10-02 review hardening the suite is 108 cases, run on Node 26.10.0 (and 25.0.0) only; Node 24.21.0 was not re-run for it. Legacy contracts, configured/staged/installed startup and notices pass. Earlier production-broker VM verifies signed version-2 request/cancel, ACK/restart retry and kernel denial; selected actual controller/node and both stock tasks pass separately (stock tasks on Node 26 only). Production human delivery, GUI and full client variants remain open |
| Actual controller/node fixture lifecycle | SQLite controller / unprivileged node / Node24.21.0 and26.10.0 / systemd255.4 | Enrollment/issuer pin, policy/approval, signed channel, local HPKE Source delivery, durable helper/browser identity, stock two reads/reconnect, cancellation and actual SIGKILL/restart closure pass; copied cookies401, two logins/zero recovery re-login. Fixture website and API operator; no AI-client, GUI provisioning, managed app or two-host acceptance |
| Actual managed controller/node lifecycle | Grafana13.2.3 / Node24.21.0 and26.10.0 / SQLite controller / unprivileged node | P05-PC12 passes: one separately revoked setup login, two operation logins/zero recovery logins, stock report/reconnect, durable mutations403/recovery401, copied sessions401 after cancellation and actual broker SIGKILL/restart. Private Root `/run` app state stays live; protected broker journal stays on disk. No app/guest reboot, AI-client or full lifetime acceptance |
| Native restic backup and restore | Not implemented | restic0.19.1/rest-server0.14.0 proposals [blocked by dependency review](decisions/0007-p05-native-backup-dependency-review.md); a fixed reviewed proposal and actual custody/backup/restore remain required |
| Fleet GUI provisioning contract | Browser-source binding v1 / Ed25519 signed-offer helpers / existing HPKE / Node24.21.0 and26.10.0 / sandboxed Chromium145.0.7632.6 / host libcrypto | Shared crypto checks and 16 actual browser/interoperability checks per profile pass. Broker offer minting/controller-signed one-use Source admission are implemented in the Unix listener; eleven broker/two core host cases pass with fixture grant/lease authority. Eleven controller HTTP cases pass on SQLite/PostgreSQL for administrator destination bindings and atomic public offer ingestion. Actual operator GUI/scoped submit, automatic publication, durable controller/node relay and real systemd/key/cancellation acceptance remain open; no P04-D4 claim. See [broker receiver evidence](../testing/evidence/p05-broker-provisioning-2026-10-02.md) and [controller offers](../testing/evidence/p05-controller-offers-2026-10-02.md) |
| Namespace worker identity before import | Linux 6.8 / systemd 255 / actual Rust listener and Node worker | Reverse kernel-pidfd proof matches exact unit/invocation/UID; same-UID wrong unit denied without consuming ticket; legitimate proof precedes import and held proof fails after exit. Root test metadata; signed-fixture coordinator proof/import passes; actual fixture controller/node passes; full managed lifetime acceptance pending |
| Root outside supervisor | Fixed Node 26.10.0 socket-activated Root service / native Rust client | Twelve JS and seven Rust cases pass; complete resource binding rejects mixed-source sessions before cookie IO. Actual VM Rust caller denies INET and RW-to-RX under the broker constraints while the capability-free supervisor supplies stock two reads/reconnect and protected explicit publication. Prepared-only EOF/SIGKILL cleanup measures 60/60ms; earlier synthetic-lease component scope; the separate signed-fixture coordinator run passes dispatch and imported-session restart recovery |
| Root administrator revocation | Fixed Node 26.10.0 Root service / native Rust client / managed Grafana 13.2.3 | Five JS, five native and four preparation/importer cases pass. Actual guest revoker has no capabilities; native caller preserves INET/RW-to-RX denial. Fixture preflight preserves the live session and session/account revoke returns copied-cookie 401. Actual managed external-account preflight and logout pass through the private host backend. Signed-fixture coordinator/account cleanup passes; actual fixture controller/node passes; full managed lifetime/AI-client workflow remains open |

The two Grafana rejections are specific to the local-password and auth-proxy
profiles. Only the executed managed Generic OAuth staging profile is selected.
The fixture is deterministic application test infrastructure, not the required
low-privilege real-application smoke or a stock-client browser task.

## Bounds

| Control | Current contract | Evidence |
|---|---|---|
| Fixture application session | Maximum 30 minutes, never renewed; shorter maxima permitted for tests | Shortened live expiry and simulated independent clock deadlines pass; 30-minute sustained fixture run not executed |
| Fixture administrator revoke | Immediate state invalidation before 204 response | Original browser and copied cookie denied after confirmation; no fleet propagation timing claim |
| Selected Grafana website session | Original 5m maximum despite active rotation | 297 reads, five rotations, last live 298,761 ms and rejection 299,765 ms; no VM clock/suspend evidence |
| Selected Grafana administrator revoke | Account-wide server logout, exclusive-account integration required | Original browser/copy 401 after confirmation; isolation account 200; no fleet propagation timing claim |
| OAuth issuer code / identity token | One-use code 30s; read-only identity token 10m; no refresh | PKCE/client/redirect/code-reuse tests pass; token-expiry soak not run |
| Fixture HTTPS request/header deadline | 5 seconds | Configured; stalled-connection timeout measurement not executed |
| Source custody, provisioning, grant, browser-operation deadline | Independent controls retained from P01/P03/P04/P05 plans | Component measurement only: actual 6-second RTC suspend expires a 3-second recipient key at 6,379-6,687 ms BOOTTIME (89-116 ms runnable); no integrated P05 deadline measurement |
| Helper 60s / operation 120s / connected revoke ≤30s / crash cleanup ≤60s | Proposed values in P05 | Partly measured, none accepted: the 60 s helper deadline is not run (guest uses a 2 s override; cleanup 2,115-2,146 ms, verified cgroup empty); connected cancellation closure is measured by the two stock tasks (rows below); actual broker SIGKILL/restart closes the exact browser and copied sessions return 401 without a recorded ≤60 s timing; prepared-only supervisor EOF/SIGKILL cleanup 40-70 ms; the 120 s operation bound is not measured |
| Native credential availability ≤5s | Proposed value in P05 | Not measured: the native service credential path is not implemented |
| Claude selected connected cancellation closure | ≤30s test bound | One actual application task verifies28,790ms including final client-result observation; no broad lifetime/clock/recovery guarantee |
| Codex selected connected cancellation closure | ≤30s test bound | One actual application task verifies19,710ms including final client-result observation; no broad lifetime/clock/recovery guarantee |

## Remaining acceptance

P05.1 application prerequisites pass for the fixture and the selected managed
Grafana staging profile. The runtime/context channel is selected and exercised by
the actual guest gates, and both actual stock clients (Claude Code 2.1.286, Codex
CLI 0.159.3) each completed one managed Grafana task on Node 26.10.0 with
API-operator approval and local HPKE provisioning. Still open: exact native-service
selection; P05.2-P05.7 full helper lifecycle acceptance, protected reconciliation
and revocation, GUI fleet provisioning, actual restic backup/restore/rotation,
integrated MCP workflow with production delivery routing, the stock-client
variants (GUI provisioning, fallback, full lifetimes, Node 24 AI tasks and a rerun
after PV05/PV06; URL-capable mode is unsupported for these two clients, see above)
and the full two-host/browser/pilot matrix.

Phase acceptance requires the original P01–P03 and P04 approval/provisioning gates.
Current P02/P03/P04 records leave acceptance/cutover and P04-D4 provisioning open.
The implementation-order exception below authorizes integrated work concurrently.

On 2026-09-30 the user explicitly authorized an implementation-order exception:
build the planned P05 integrations while closing those prerequisites. Acceptance
and release still require the original gates and complete scenario matrix.

Plaintext boundaries: fixture/issuer sign-in consumes generated passwords in
runtime memory and retains scrypt hashes. Selected Grafana receives only the
OAuth identity token and retains private disposable session/identity state.
The browser holds a copyable application session until server invalidation or
the original deadline. Native service credentials will be plaintext for the
trusted service consumer. Their lifecycle is not established by these fixture tests.


## Historical component snapshots

The following records describe earlier slices. Current controller/node fixture
and selected managed lifecycle results are in the table above and the dated
coordinator record; earlier statements that coordination remained pending are
retained as historical scope. They add no full phase or client acceptance.

The actual Rust private helper caller now passes in the pinned systemd guest.
The protected journal has fourteen local tests plus actual guest SIGKILL/ENOSPC
persistence recovery. Retry remains blocked_uncertain; these are trusted
transport/persistence foundations. The actual broker coordinator, verified
website/helper/browser reconciliation and production signed-grant channel remain
open, so this evidence adds no supported full-workflow profile.

Browser grant/source preparation and typed cookie validation now have 14
focused Rust checks. The protected journal is schema 3 and binds node/workload
IDs plus the administrator recipe fingerprint and exact proved helper identity
before source delivery. Legacy schema-2 unfinished records remain blocked and
cannot acquire a new helper. Production dispatch and the
cleanup coordinator remain pending. The namespace worker and private framed
tunnel have 11 pure checks. After two failed stock-tool attempts, the real guest
gate passes with a private writable agent working directory/home/cache: actual
separate dynamic UID/private namespace, outside CDP denial, protected profile,
stock report/reconnect, canary checks, copied-session revoke and verified cgroup/
profile cleanup. A later guest rerun replaces the UID-only proxy with the actual Rust component:
retained kernel pidfd, manager unit/invocation, same-UID other-unit denial despite
a claimed-unit header and restarted-invocation denial all pass before backend
attachment. Two stock reads and one reconnect run in the original invocation.
Seven proxy checks and two actual host agent-control checks pass. Production
signed-grant dispatch/coordinator and complete Claude/Codex tasks remain pending.


The root catalog and browser operation admission now have five file/parser and
six admission checks, with actual production startup/denials in the pinned VM.
Controller HTTP browser approval/grant cases pass on SQLite and PostgreSQL; core signatures and
actual broker Unix control correlation pass. Grants bind the original request
event and owner; native grant wire fields remain unchanged. The new status path
returns only opaque grant/operation IDs. Production asynchronous runtime
coordination and reconciliation, all stock AI tasks and inherited gates remain
open.


### Automatic controller browser intent

New Root browser events carry signed `request_version: 2`. Eleven actual HTTP
cases pass on each database: workload-requested approval, named human decision,
one signed grant under concurrent/repeated delivery, strict fields/identity/time,
atomic receipt/operation/approval/audit/closure rollback, failed-grant recovery,
policy-change closure, cancellation/expiry without renewal and missing-state
denial. Eleven original unversioned/manual browser cases remain passing. The
production broker VM verifies the new field in signed packaged-MCP events.
These are separate HTTP/VM components; production node/controller/broker browser
dispatch and verified website/helper/browser cleanup remain open.

### Durable operation ownership

The broker's version-5 snapshot retains workload/invocation, consumption mode,
cancellation delivery flags and verified closure after event ACK/restart. New
admission stops at 10,000 owners, or earlier when the 1 MiB durable header would
overflow (about 1,760 browser to 3,330 untyped owners); only provably terminal owners
are evicted (closure recorded, cancellation acknowledged, no runtime authority, journal
record or queued node event remains); write failure fences new authority until durable
retry. Versions 1/2 do not fabricate missing ownership;
version-3 owners remain untyped and cannot cancel. Version-4 typed browser owners
can cancel by event ID, but cannot establish missing resource/recipe binding.
Updated broker/relay/controller
are required; rollback needs matching state/database backups.

### Browser workload cancellation

Authenticated invocation owners can stop a browser request locally without
fresh controller time or queue space. Durable signed cancellation is relayed
when space returns; the controller checks original request evidence and commits
approval membership, grant revocation, signed closure, audit and event receipt
in one transaction. Consumed/expired grants are withdrawn too; consumer results
are preserved. Before-creation cancellation prevents later grant creation.
Native/untyped requests cannot use this path. Status and cancellation replies
are metadata, not verified website invalidation or runtime cleanup.

Eight broker cases, eleven controller HTTP cases on each database, typed core
checks and relay persistence/replay pass. Real VM identity/channel/journal checks
remain component evidence with a synthetic Root browser lease; no integrated
fleet cancellation/website cleanup or actual AI task is established. Integrated MCP workflow,
pruning and full production runtime acceptance remain open.


### Browser retry keys and cancellation before admission

Version-5 request records bind an optional opaque retry key to the original
invocation, request fields and full Root recipe/source mapping. Canonical retries
return the same event ID after lost reply/ACK/restart without renewing TTL or
creating another request. Changed fields, recipe or invocation are denied.
Every new browser request has original resource/recipe binding even without a
retry key. Older unbound owners cannot authorize fresh login.

Cancellation by retry key either uses existing signed cancellation or persists
a local withdrawal before admission. A late request cannot then obtain approval;
no controller event is fabricated without original evidence. Failed persistence
keeps the local stop and fences new authority. Withdrawal records share the
owner capacity and are never evicted. Twelve new broker and two
parser cases pass; actual Unix lost reply/reconnect is included with fixture
workload identity. Private-helper lost-reply recovery, signed runtime/website
cleanup, integrated MCP workflow and all original acceptance gates remain required.

### Original process authority component

P05-OW01–P05-OW06 now cover production admission retaining the actual original
workload pidfd, ACK preserving it, broker restart refusing reconstruction and a
same-UID/unit/invocation replacement failing to consume the old browser grant.
The real systemd guest measured signed cancellation 86ms after original child
exit while its parent remained active. No source was provisioned in this case;
it establishes original process authority, not a supported complete browser
workflow. The original coordinator, application, client and inherited acceptance
gates remain open.


## Asynchronous component scope — 2026-10-01

The detached helper API and immutable browser closure producer/consumer have
host, SQLite/PostgreSQL HTTP and actual systemd helper component evidence.
Consumed browser execution follows the website lifecycle independently of the
short grant deadline. Cleanup after cancellation preserves revoked authority.
The VM proves source withholding after journal permission withdrawal, rather
than complete runtime coordination. Stock Claude/Codex tasks, production browser
profile/current-authority/cleanup/recovery, full lifetime and inherited phase
acceptance remain open. No supported client/profile or phase acceptance is added.
