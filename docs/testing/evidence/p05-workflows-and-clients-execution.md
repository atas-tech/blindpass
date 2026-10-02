# P05 workflows and clients execution

**Date:** 2026-09-30. **Status:** P05.1 application prerequisites pass for the fixture
and selected managed-OAuth Grafana staging profile. Suitability preparation is implemented
in the working tree based on `1a37bbe`; this is not a completed slice or phase
acceptance. Existing uncommitted Rust remediation changes predate this work.
The full [implementation plan](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/phases/05-workflows-and-clients.md)
and [paired acceptance plan](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/testing/phases/05-workflows-and-clients.md)
retain their original scope and gates.

**Re-verified on the final tree — 2026-10-02 (later):** see the
[completion review](p05-completion-review-2026-10-02.md). On the current binaries the
component gate, the managed Grafana controller/node lifecycle gate and the Codex task pass
on Node 26.10.0; the Claude task passed on its third attempt (1 of 3: the other two did not
return a strict `{"artifacts":N}` answer). The Node 24.21.0 VM profile was not rerun. The
passes below that predate the review fixes are history, not current evidence. P05 is not
accepted; ADR 0007 (real restic) and several other gates stay open.

**Current execution — 2026-10-02:** both actual stock clients pass the selected
Node26 API operator/local HPKE managed Grafana task. The ordered delivery
component, SDK transport and provisioning crypto contract/interoperability
cases pass on both supported Node profiles. Shared
[signed-offer helpers](p05-signed-offer-2026-10-02.md) also pass native/browser
signature and sandboxed Chromium crypto checks; actual broker offer minting and
GUI/ciphertext relay integration remain open. The later
[broker receiver slice](p05-broker-provisioning-2026-10-02.md) implements offer
minting and signed Source admission with real keys/Unix framing in host fixture
tests; live operator/controller relay and systemd acceptance remain open.
GUI provisioning, real human delivery, native backup/restore and full
lifetime/two-host/inherited acceptance remain open. Dated entries below retain
their original scope; current [delivery evidence](p05-delivery-2026-10-02.md)
and [stock-task evidence](p05-coordinator-2026-10-01.md) record the later results.

## Executed scope

The dependency-free HTTPS fixture provides two generated test accounts, an
account-specific read-only report, fixed safe errors, restricted viewer APIs,
non-renewable server-side sessions and administrator revocation. Passwords are
salted scrypt hashes in server memory; bearer sessions are stored as digests.
No keys, cookies, source passwords, live URLs or captures are included here.
See [harness setup and plaintext lifetimes](../../../tests/browser-handoff/README.md).

Tests landed before `server.mjs`; the initial run failed because the implementation
module was absent. After implementation, restricted-sandbox HTTP binds failed
with `EPERM`; the actual passing run used permitted host loopback sockets.
Browser tests caught response-body retrieval after page navigation; the login
page now consumes its response before navigation and tests read non-bearer session
metadata from the authenticated context.

| Scenario/portion | Implementation | Profile/version | Command | Result |
|---|---|---|---|---|
| P05-I01 fixture: role restrictions, direct requests, TLS trust, account separation, no rolling lifetime and administrator revoke | [HTTP tests](../../../tests/browser-handoff/fixture-app/app.test.mjs) | Node 26.10.0 / OpenSSL 3.6.4, real HTTPS | `node --test --test-isolation=none tests/browser-handoff/fixture-app/app.test.mjs` | 12/12 pass, no skips |
| P05-I01 fixture UI: actual sign-in, report, absent credential UI, forbidden direct mutations and replay | [Browser test](../../../tests/browser-handoff/fixture-app/browser.test.mjs) | Playwright 1.58.2 / Chromium 145.0.7632.6, sandbox enabled | `node --test --test-isolation=none tests/browser-handoff/fixture-app/*.test.mjs` | 13/13 combined pass, no skips |
| B-I13 application-only prerequisite | HTTP suite above | Short live session; fake wall/monotonic clock cases | Same fixture command | Pass for shortened lifetime/activity/cookie-expiry tampering and fake independent clocks; not a VM suspend result or 30-minute soak |
| B-E16 application-only prerequisite | HTTP/browser suites above | Original and copied fixture session | Same fixture command | Live before revoke; HTTP 401 after revoke; no broker completion/cancel/expiry test |
| P05-I06 fixture error portion | HTTP suite above | Wrong credentials, malformed/oversized input | Same fixture command | Fixed statuses; no source password in response. Helper/capture/fallback exposure not implemented |
| P05-I01 real-app candidate | [Grafana probe](../../../tests/browser-handoff/grafana-suitability.mjs) | Grafana OSS 13.2.3, loopback HTTPS, local-password Viewer, configured 30m maximum | `node tests/browser-handoff/grafana-suitability.mjs "$P05_GRAFANA_HOME"` | Account restriction fails; candidate rejected. Rejection probe itself exits 0 |
| P05-I01 OAuth issuer prerequisite | [Issuer tests](../../../tests/browser-handoff/oauth-fixture.test.mjs) | Disposable HTTPS issuer, static Viewer accounts, PKCE S256, one-use 30s code, 10m identity token, no refresh | `npm run test:p05:oauth` | 3/3 pass; unsafe configuration/ambiguous fields rejected, client/redirect/PKCE/code reuse checks and native Chromium callback pass |
| P05-I01 selected real-app prerequisite; B-I13/B-E16 application portions | [Managed test](../../../tests/browser-handoff/managed-grafana.test.mjs) | Grafana OSS 13.2.3 Generic OAuth Viewer, private Unix backend, two organizations, 5m original maximum | `npm run test:p05:grafana` | 1/1 pass, no skips; actual report UI, managed profile fields, seven 403 mutations, recovery 401, revoke/copy replay, 297 active reads and five real rotations before original expiry |

The official Grafana archive SHA-256 was verified against its
[download page](https://grafana.com/grafana/download?edition=oss) before execution:
`6107ad27016296aac38e0d7ffa8753ab540b5541ad27e94790f771289d733235`.
Full archive extraction twice reached `EDQUOT`; both partial directories were
removed. The executed binary/config/public assets were extracted from that
verified archive without preinstalled extra plugins. The harness disables
plugin preinstallation and update reporting and uses only disposable private
SQLite state and generated passwords. It tears down its process, Chromium,
TLS keys and application state after the probe.

The actual profile UI permits editing email. Own profile/email and password
updates return 200 despite the verified Viewer role and non-admin account.
Administrator logout works and copied-cookie replay returns 401. The failed
account prerequisite prevents selecting this profile; its configured 30-minute
maximum was not validated by a sustained run. The
[sanitized observation summary](p05-grafana-13.2.3-suitability.json) contains no
live credentials. This is not a rejection of all possible Grafana configurations.

### Managed authentication follow-up

The private auth-proxy profile also fails: Grafana reports the user external,
but valid profile/email PUT still returns 200. See the
[negative observation](p05-grafana-13.2.3-auth-proxy-suitability.json).
The pinned application's external-user guard recognizes enabled OAuth providers
but not auth proxy, so the selected staging profile uses Generic OAuth instead.
The issuer consumes the source password; Grafana consumes its read-only identity
token. Public asserted identity/Authorization headers are stripped, and ordinary
API paths are forwarded without any role filter: the 403 results come from
Grafana. Backend administrative access is private fixture setup, not a proven
separate-UID helper boundary. Account-wide logout requires exclusive-account
use in the later broker integration.

Regression tests first reproduced duplicate authorization-field acceptance and
the native form's blocked cross-origin redirect. The issuer now rejects ambiguous
fields and its CSP permits only the fixed approved callback origin. A managed
profile adds its authentication source to the Email label; the test uses the
stable pinned field IDs and requires disabled name/email/username inputs. No
restriction assertion was relaxed to accept a writable profile.

The initial active-read loop stopped when Grafana required token rotation; a
401 there did not establish original-session expiry. The final test calls the
actual browser rotation API every 50 seconds, accepts returned cookie rotations
in memory, and measures the original five-minute maximum. It passed with
297 authenticated reads, five rotations, last authorized at 298,761 ms and
rejection at 299,765 ms. Original copied-cookie and altered-cookie-deadline replay
then return 401. Administrator logout separately invalidates the browser/copy,
while the other account stays authorized. Recovery send/reset routes return 401
for both anonymous and authenticated callers. See the
[final sanitized result](p05-grafana-13.2.3-managed-oauth-suitability.json).
This is a real application prerequisite, not an agent/broker task, production
IdP, VM clock test, or acceptance of P05-I01's full integration environment.

## Repository gates

| Command | Result / limit |
|---|---|
| `npm run build` | Pass |
| `npm test` | Pass after adding 12 fixture HTTP and two OAuth config/HTTP cases to the ordinary runner; SPS reports 80 passed and 101 skipped in 17 service-gated files |
| `npm run test:p05:fixture` | Pass, 13/13, no skips, including actual Chromium UI and copied-cookie replay |
| `npm run test:p05:oauth` | Pass, 3/3, no skips, including native OAuth form/callback Chromium regression |
| `npm run test:p05:grafana` | Pass, 1/1, no skips; live five-minute original session test and five token rotations |
| `cargo fmt --all -- --check` | Pass |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | Pass |
| `cargo test --workspace --locked` | Pass with host socket access; four ignored cases: three offscreen desktop-app E2E tests and PostgreSQL outage |
| `./tests/fleet/p01-vm.sh` | Pass on the pinned disposable Ubuntu 24.04 guest, kernel 6.8.0-139-generic/systemd 255, QEMU/KVM 11.1.1, no TPM; actual native loader/identity/HPKE/restart/expiry/rotation/canary checks; not P03/P05 acceptance |
| `git diff --check` | Pass in the repository and paired vault checkout; 61 changed-document relative file links checked with none missing; P05 JSON and new JavaScript syntax checks pass |

The fixture has no PostgreSQL/Redis integration requirement. Existing skipped
SPS/desktop/PostgreSQL cases were not enabled by this application-fixture change.
The P01 prerequisite rerun used the reviewed image SHA-256
`612b2c0cc1bc413a6cb8c38fd611794caf0f2b436c50013d8b3794db12ad7354`
and a freshly generated disposable SSH key. An approved unsandboxed check
confirmed readable/writable `/dev/kvm` and QEMU before execution. The runner
owner was `local-kvm-p05-prerequisite-20260930`; stalled delivery closed without
payload in 2,006 ms. Guest sockets/units, the overlay and generated key were
removed after the passing run. Host Rust 1.98.1/OpenSSL 3.6.4/systemd 261 and
guest systemd 255 are distinct profiles. TPM-required mode was explicitly
unsupported with no device; `coredumpctl` was unavailable in this guest. The
existing W0 narrow profile/exclusions remain in force. No P03/P05 VM workflow,
stock-client run or new phase acceptance is established by this prerequisite
rerun. Node 24 was not available/tested; no engine-range expansion was made.

## Incomplete requirements and next work

P05.1 application prerequisites now pass for the fixture and selected managed
Grafana staging profile. Runtime/context-channel feasibility and exact native
service selection remain open; slice 1 is not complete. Forgejo is only a
research lead. The rejected local-password/auth-proxy profiles remain unsupported.

P05.2–P05.7, P05-I02–I05, the remaining P05-I06 exposure paths, P05-E01–E03,
M01–M07, and the full inherited browser/fleet/native matrix remain unimplemented
or not run for P05. The support matrix does not declare stock-client, elicitation,
trusted runtime-channel, restic or two-host support. No benchmark or measured
fleet/helper/recovery bound is recorded.

The P05 plan explicitly allows suitability/fixture preparation before accepted
P01–P03 and P04 provisioning. Its integrated implementation gates remain open:
[P02](p02-controller-api-migration-rerun.md) has no acceptance/cutover record,
[P03](p03-fleet-authorization-execution.md) has remaining exit/review gates, and
[P04](p04-ui-ux-redesign-execution.md) explicitly lacks the D4 provisioning path.
Preparation has not waived or marked these requirements complete.

### Implementation-order authorization — 2026-09-30

After reviewing the passing application/P01 prerequisite evidence and the open
P02/P03/P04 records, the user explicitly authorized building the planned helper,
broker, provisioning, native service and MCP integration while closing the
prerequisites. This changes implementation order only. All original acceptance
scenarios, inherited/hosted evidence and release gates remain required; no phase
was accepted by this exception. Continue on the existing branch without pushing
or changing the scope of unexecuted checks.

The [MCP dependency proposal](../../product/decisions/0005-p05-mcp-dependency-review.md)
records current exact official packages and full Socket graphs. The all-in-one
SDK and deprecated server package are blocked. The smaller server 2.2.0 plus
Zod 4.6.5 proposal was approved by the user after dependency-guard review; no dependency,
lockfile, production schema or engine range changed. It does not waive the
inherited phase gates.

## Cleanup and rollback

Reverting this preparation removes the fixture/probe, ordinary-runner addition,
explicit test script and related evidence/support documentation. It does not
touch production schema, custody or operation behavior. Tests close their
servers/browsers and delete only task-created TLS/application state. Restoring
integrated broker/controller artifacts remains a later phase obligation.

## Private helper implementation entry — 2026-09-30

The user separately approved exact private `playwright@1.58.2` and stock
`@playwright/mcp@0.0.83` profiles in [decision 0006](../../product/decisions/0006-p05-browser-runtime-review.md).
The private manifest/lock now use exact 1.58.2. Lock review found only the new
workspace link and existing Playwright/core/fsevents becoming production-reachable;
no version/integrity changes or additional graph appeared. Both resolution and
installation used `--ignore-scripts`. Stock alpha runtime is not installed yet.

Test-first helper checks initially failed for the missing module; worker framing
checks initially failed for a missing worker. A real Chromium regression then
found Playwright routing allowed a redirected GET to an unapproved origin. No
password was submitted, but that violated the zero-request condition. Request-stage
Chromium Fetch filtering now blocks each redirect hop; the same actual browser
check passes with zero unapproved requests. Metadata fetch has a bounded abort
signal and an abandoned response waiter cannot emit an upstream rejection.
Worker IPC uses socket descriptors, not filesystem reads on nonblocking sockets;
malformed/oversized/trailing frames and debug/argv/descriptors are refused safely.

| Scenario portion | Actual command/profile | Result |
|---|---|---|
| B-I01–B-I03/P05-I06 library, fixture browser and separate worker | `npm run test:p05:helper`; Node 26.10.0, Playwright 1.58.2, sandboxed Chromium 145.0.7632.6, disposable HTTPS | 10/10 pass, no skips; private browser closed before library response; fresh context reads report; revoke denies original/copy; source password absent from protected worker response, stdout and stderr empty |
| Managed Grafana private worker, fresh context and server revoke | `npm run test:p05:helper:grafana` with verified Grafana OSS 13.2.3; same runtime | 1/1 pass in 5.2s; only two approved website cookies imported, actual report reads, valid profile mutation 403, server logout then website 401 |

The worker consumes password in private process/form memory; the protected broker
response contains cookies and revoke metadata, never the source password. JS
strings are not guaranteed erased. The workload browser intentionally receives
copyable website authority. Separate-UID systemd socket/unit templates have been
added, but actual guest execution, cgroup enforcement, OS network isolation,
broker import, protected reconciliation and stock-client integration are still
required. These passing worker tests do not establish the full parent scenarios.

## SDK and stock Unix-channel foundation — 2026-09-30

The exact approved SDK/core 2.2.0, Zod 4.6.5 and stock Playwright MCP 0.0.83
are now installed with lifecycle scripts disabled. Lock review found only their
reviewed graphs and local workspace links; the stock tool's exact 1.64 alpha
Playwright/core remain nested, separate from helper stable 1.58.2. Actual upstream
SDK/core Apache/MIT transition license files and Zod's MIT file are retained in
`packages/mcp-server/licenses/`.

Test-first SDK checks failed for the missing module, then actual subprocess tests
passed 6/6: four older initialize revisions (2024-11-05 through 2025-11-25), the
2026-07-28 per-request envelope without initialize, and invalid registry rejection.
Every revision lists and calls actual SDK tools; nested dummy exception material
is replaced by a fixed error and stderr stays empty. This is a factory/transport
foundation, with no built-in legacy/operation tools or production CLI yet.

`npm run test:p05:stock-channel` passes against actual `@playwright/mcp@0.0.83`
and its approved 1.64 alpha library, connected through a mode-0600 Unix CDP bridge
to sandboxed Chromium 145.0.7632.6. A separate worker performs fixture login;
approved cookies enter a fresh persistent workload context. The stock tool reads
the report twice across one reconnect. Navigation initially returned a snapshot
link; the task now invokes actual `browser_snapshot` rather than treating the
navigation summary as report evidence. Both returned results and two normal
stock artifacts exclude the source password, cookie canary and raw endpoint.
No alpha browser binary was downloaded; the explicit profile is alpha client
library attached to the named stable browser. CLI argv contains only a protected
config file path.

This probe establishes transport feasibility only. Its loopback CDP listener is
not namespace-isolated and its same-UID test proxy does not check systemd
invocations. The production broker proxy, namespace/egress design, real stock
Claude/Codex task, cross-UID/invocation denial and full parent scenarios remain
required. Installed host clients are Claude Code 2.1.285 and Codex CLI 0.159.1;
versions alone do not establish their task/elicitation support.

Root build and ordinary workspace tests passed after the package additions.
SPS still reports 80 passed/101 skipped across 17 skipped files; the explicit
browser/managed/VM gates remain separate. Rust format, Clippy and workspace tests passed; the four existing ignored Rust scenarios remain.


## Narrow helper systemd execution — 2026-09-30

Actual pinned Ubuntu 24.04/KVM guest execution passed the private login portion:
Node 26.10.0, kernel 6.8.0-139-generic, systemd 255 (255.4-1ubuntu8.17),
Playwright 1.58.2, Chromium 145.0.7632.6. Root-only socket permissions and
separate helper account are enforced by actual systemd. A second UID is denied,
returned approved cookie reads the report, fixture server revoke makes its copy
401, and no running helper units remain after success. The global Ubuntu userns
restriction remains enabled; an exact root-owned binary AppArmor permission
profile permits sandbox startup, following [Chromium's documented approach](https://chromium.googlesource.com/chromium/src/+/main/docs/security/apparmor-userns-restrictions.md).
The profile is not full AppArmor confinement.

Initial runs found host tmpfs quota exhaustion, insufficient guest disk space,
Node's missing libatomic library, private-tmp test staging isolation, Ubuntu's
userns restriction, and a strict fixture revoke payload mismatch. The disposable
harness now streams its bundle, uses ignored disk-backed test state and an 8 GiB
overlay, installs signed library prerequisites, and uses the exact installed
browser path. The pinned base image/hash is unchanged. Temporary SSH keys,
overlays and private staging data are removed on exit. A new deadline/journal
canary extension currently fails its manager-deadline check; it is being debugged.
Do not treat the successful login portion as deadline/cgroup/recovery acceptance.


The extended deadline test first returned `login_failed` after manager SIGTERM:
Playwright's signal handler can close Chromium and allow normal error handling
to finish. The worker now records interruption before importing Playwright and
returns only `uncertain`, without any session material, or no complete response
if the manager kills it. A direct worker signal regression passes. This preserves
the broker's obligation to persist uncertainty before sending a credential. The
VM test still requires an actual systemd timeout, the observed invocation/cgroup
identity, bounded cleanup and an empty cgroup; the latest rerun passes.
The fixed production worker authentication budget is 55s, manager runtime 60s
and stop grace 5s; the short override does not measure the full production bound.


Final short-deadline guest result: override 2,000 ms, observed cleanup 2,134 ms,
actual unit result `timeout`, observed invocation cgroup empty/removed, journal
password/cookie canaries absent, zero running helper units. The guest overlay
and generated SSH key were removed after the successful run. Library/fixture
helper suite now passes 11/11 including interruption handling. This is narrowly
P05-I03 helper-manager evidence; broker crash/restart, account reconciliation,
website recovery bounds and the full 60s production deadline remain unexecuted.


## Broker private helper transport foundation — 2026-09-30

New `crates/blindpass-broker/src/private_helper.rs` uses the fixed root-only
helper socket, requires its root-owned 0700 parent/0600 socket and root listener
peer, bounds connect/read/partial-write time and rejects oversized, partial,
trailing, duplicate/invalid UTF-8 or unknown-status envelopes. Only a protected
SecretBytes envelope can reach the later trusted importer. Debug/error output
contains no raw response or nested exception. Parsed local string copies and
partial buffers are cleared without a complete memory-erasure claim. The
importer must still validate cookie scope, original deadline and revoke binding.

Tests first failed for missing types/functions. Four actual Unix wire/kernel
checks now pass, including a stalled frame and saturated Unix listener backlog.
The connect deadline sets SO_SNDTIMEO before connect, as defined by the
[Linux socket interface](https://man7.org/linux/man-pages/man7/socket.7.html).
Broker Clippy and workspace format checks pass. Root build/npm and all Rust
workspace tests were rerun after the new module and pass; existing 101 SPS skips
and four Rust ignored scenarios remain. Managed Grafana helper was rerun after
the fixed worker budget/interruption change and passes.

The Rust transport is not yet called by the broker's operation handler or
exercised as a native caller in the guest. The preceding real guest test used
the Node driver. These four wire checks do not prove operation authorization,
workload/namespace isolation, trusted cookie import or protected reconciliation.


## Native helper caller and durable journal — 2026-09-30

The guest driver now invokes the actual Rust `request_private_login` transport
through a disposable native probe: private stdin and inherited socket fd 3,
bounded input/output, empty stdout/stderr, no credential arguments or raw errors.
Two subprocess tests first failed for the absent binary and now pass. Real
root-owned socket metadata and listener peer checks pass in the pinned guest;
login reads the report (200), another UID is denied, revoke rejects the copied
cookie (401), and the short manager timeout clears the observed invocation
cgroup. The successful journal-extended run measured 2,137ms for the 2,000ms
override. The runtime bundle SHA-256 is
`528584a0eafaef2edcdaac9d85fd9dab5a74176b454e428dd07f734323f64fd3`;
the pinned base image and private runtime versions are unchanged.

`session_journal.rs` implements a fixed root-only 0700 directory with a lifetime
exclusive lock and 0600 single-link snapshot files. Each mutation writes a new
private file, syncs it, atomically renames it through a pinned directory fd and
syncs the directory. Any persistence failure fences future transitions. Records
contain operation/idempotency/workload unit and invocation/resource/account,
state, original server deadline, protected nonbearer revocation handle and exact
browser unit/invocation. Passwords, cookies and browser endpoints are excluded.
The login handle must be durable before browser activation; the coordinator must
persist browser identity before cookie import. One unfinished operation blocks
its account and workload. Retry returns the existing status, never fresh login
authority. Opening after restart durably marks unfinished records
`blocked_uncertain`. No deadline-only release is implemented; the trusted
reconciler must confirm website revoke and termination of both private helper
and workload browser before closing. Closed replay records remain 24 hours,
pruned only with caller-verified signed controller time, with a persisted high
water mark. These APIs are trusted broker internals, not an authorization layer.

Ten tests pass after the expected missing-implementation failure: reservations
and replay, account/workload conflict, staged handle and substitution, operation
budget, restart fencing, incomplete cleanup, retention, unsafe metadata,
symlink/hardlink/FIFO/corrupt state rejection and injected persistence failure.
The actual guest probe additionally writes a login intent, is killed with
SIGKILL, reopens and proves the handle remains and retry is blocked. A disposable
64KiB tmpfs produces actual ENOSPC; activation fails, further transitions are
fenced, removing the filler permits recovery of the original intent without a
new login. Guest files remain 0700/0600 root-owned with one file link. This is
persistence evidence with synthetic timestamps and nonbearer metadata, not
actual broker crash/revoke recovery or independent application expiry evidence.

The Rust helper transport now uses the existing CLOCK_BOOTTIME reader with
250ms maximum socket wait windows and retry of timeout/interruption, rechecking
the deadline after successful reads including EOF. Six actual host tests pass,
including a 350ms helper response across wait windows and boot-time arithmetic.
This arithmetic is not a VM suspend/clock test. The default sandbox run stalled
under its socket/clock restrictions; the real host run was used for evidence.
On transaction failure the stream is shut down before returning uncertainty.
Private Playwright and systemd suspend/deadline behavior still need the full
production and suspend scenarios. No full broker/browser/client claim follows.


The final VM rerun against the CLOCK_BOOTTIME transport also passes: actual
Rust login/revoke plus SIGKILL and ENOSPC journal recovery; shortened cgroup
cleanup measured 2,147ms. Build, npm test, workspace formatting/Clippy and native
probe 2/2 pass. npm retains 101 skipped SPS tests. Two parallel Rust workspace
runs reached the existing CLI copied-executable ETXTBSY race (different fixture
cases); the full serial gate is being rerun. This known harness issue is recorded
in the inherited P02/P03 evidence; neither failed run counts as a passing gate.


Final serial Rust gate `cargo test --workspace -- --test-threads=1` passes,
including all six IPC and ten journal checks. Three Quickshell/offscreen and one
PostgreSQL outage case remain ignored. Both earlier parallel failures are
retained above; the serial result does not establish a fix for that CLI fixture
race. Shell syntax, guest JavaScript syntax, relative links (30 checked, none
missing) and repository diff whitespace checks pass. The authoritative paired
P05 plans record the new cases and precise persistence-only scope. The broker
coordinator, isolated channel and actual reconciler are still required before
browser workflow acceptance. No commit or push was made.

## Browser grant preparation and isolated worker — 2026-09-30

Fourteen focused Rust `browser_` checks pass: exact administrator recipe and
credential destination, approved workload/resource, grant and current policy/
registration/invocation binding, source availability, durable intent before
one-use consumption, fixed uncertain result/event staging, safe existing-key
replay, rechecking authority after private login and typed cookie/handle staging.
These use the existing accepted-grant fixture; the production workload dispatcher
does not yet route `browser.session` through this preparation API. The mutex
must be released before helper IO. Source plaintext stays in protected root
job memory until its one-use helper call, then that job copy is dropped. P01
custody has its own expiry. The private helper consumes the password; the
workload browser receives only the approved, intentionally extractable session.

The journal's schema 2 binds node/workload IDs and the administrator recipe
SHA-256 in addition to operation/key/unit/invocation/resource/account. Replay
rejects a changed node, workload or recipe. The decoder rejects schema 1;
unfinished development state must be reconciled with its matching runtime
before adopting this format. Ten journal cases and the preceding real guest
schema-2 SIGKILL/ENOSPC run pass; that run measured shortened helper cleanup at
2,138ms. This remains persistence evidence, not actual website crash recovery.

The new DynamicUser/PrivateNetwork browser template launches a fresh private
profile with sandboxing enabled. The worker publishes private `prepared`
metadata, then imports strictly approved cookies and opens CDP only after
successful import. The root coordinator must persist verified manager identity
before requesting import and recheck grant authority before publication. The
namespace CONNECT proxy accepts only the fixed application HTTPS authority;
bounded private frames forward opaque TLS records to a trusted outside
connector. CDP is a separate channel. Duplicate keys, malformed UTF-8, oversized
frames, excessive depth, arbitrary targets and early CDP are refused. Eleven
pure framing/state/stream tests pass after expected missing-implementation
failures; test doubles do not prove systemd or browser behavior.

The fixture adds separately authenticated account-wide revoke for lost login
replies. It deletes every selected-account session and invalidates password
verification already in flight; the other account remains usable. All 13 HTTPS
and two pure revocation checks pass. No fixture or Grafana account may be reused
until the real reconciler confirms website invalidation and helper/browser
termination. No claim about a Grafana pending-login race follows from the
fixture epoch test.

The first namespace guest attempt verified actual manager identity, a separate
dynamic UID, a different network namespace, host-loopback CDP denial and approved
cookie import. It failed during the first stock-tool task and does not pass the
channel gate. Sanitized diagnostics were added for a rerun. The test proxy is
UID-restricted; it does not implement production pidfd/unit/invocation exclusion.
Full Root broker dispatch/reconciliation, real Grafana namespace smoke,
provisioning/native backup, legacy/operation MCP tools, elicitation/fallback and
both complete stock AI tasks remain required.

The approval service initially prevented the full npm gate because workspace
credits were exhausted; no rejected command was executed. After the user's
approval to retry, the service recovered. Root build/npm, formatting and Clippy
pass. The serial Rust workspace gate also completed successfully; its existing
four ignored cases and 101 SPS skips remain. No commit or push was made.

The diagnostic guest rerun identified `EACCES` in the first stock browser tool
task. Supplying a private agent-owned working directory/home/cache resolves the
failure. The final pinned guest gate passes: DynamicUser differs from helper,
agent and root; actual manager invocation/PrivateNetwork and separate namespace
verified; guest host loopback cannot reach CDP; another UID cannot use the Unix
proxy; agent cannot read the 0700 browser profile. Approved cookie import into
fresh sandboxed Chromium precedes actual stock Playwright MCP report/snapshot
and reconnect (two reads, one reconnect). The managed output/home/cache and
normal journal scans exclude generated source/cookie canaries and raw endpoints.
Account-wide revoke denies the copied cookie (401); browser invocation cgroup
is empty/removed and profile is removed. Existing actual SIGKILL/ENOSPC probes
also pass. Short helper override cleanup is 2,131ms. Runtime bundle SHA-256 is
`08262cdb06e3deccb35d95b54b8777588c02532ed535432eb34499f63f8c7e3f`.
This establishes the real namespace/stock-tool feasibility profile, not a
production broker operation, same-UID invocation proxy or stock AI-client task.
Both earlier failures remain recorded; the implementation-order exception
waives no remaining inherited or complete-workflow gate.

Final npm rerun includes all 21 helper/channel/revocation pure/framing cases and
passes; native protected probe rerun passes 2/2. Relative link check covers 55
repository targets with none missing; JavaScript/shell syntax and
`git diff --check` pass. Disposable VM keys and overlays both count zero after
the successful run. The earlier 101 SPS skips and four Rust ignored checks
remain unexecuted. No commit or push was made; the P05 goal remains active.


## Invocation-checked browser proxy — 2026-09-30

The Rust component now retains the kernel peer pidfd and checks the actual
manager unit, invocation and UID. The root-owned per-workload Unix socket accepts
only `/current`; it rewrites discovery to the private root-selected DevTools
path. It rejects duplicate/ambiguous headers, supplied credentials, arbitrary
paths and routing claims. Boot-time deadlines, current authority and slot
generation are checked before backend attachment and during forwarding.
Sixteen connections, bounded headers/buffers, a two-second handshake and
50ms forwarding polls bound resource use. No raw endpoint enters status/error
output. The authority callback must enforce durable journal/runtime verification
and current signed policy/grant; production coordinator wiring remains pending.

Seven local proxy tests pass. The half-close test first demonstrated a dropped
relay tail; draining before half-close fixes it and the rerun passes. Two actual
host subprocess tests verify persistent agent stop with input EOF and fixed safe
invalid-command output. Restricted-sandbox subprocess IO was empty; that run
failed and is not counted. The approved host rerun passes.

The actual pinned systemd guest passes with this Rust proxy: retained kernel
pidfd, same-UID other-unit denial despite a claimed-unit header, and restarted
invocation denial all precede backend attachment. Two actual stock Playwright
MCP report reads and one reconnect run inside the original workload invocation.
Dynamic UID/namespace separation, sandbox, host-loopback CDP denial, other-UID
socket denial, profile privacy, copied-cookie account revoke (401), cgroup/profile
cleanup and canary scans pass. SIGKILL/ENOSPC journal probes also pass. The
shortened two-second helper cleanup measures 2,053ms. The guest uses a synthetic
root test-driver lease: it does not establish production signed-grant dispatch,
coordinator/reconciler, managed Grafana integration or a Claude/Codex task.

The first attempt waited on a persistent test agent after its stop command
without input EOF. The live process was observed; only that disposable VM was
stopped and the harness exited 255. Closing stdin on stop and bounding the agent
unit to 120 seconds fixes the driver. The subsequent full VM run exits zero;
no disposable SSH keys or overlays remain. Both attempts remain recorded.

Build, final npm test, formatting, Clippy and the full locked serial Rust suite
pass. Final helper/channel group: 23 passed, zero skipped. Existing SPS skips: 101;
existing ignored Rust cases: four (three desktop/offscreen and PostgreSQL outage).
The runtime bundle and all three release probe hashes are recorded in the
[runtime evidence](p05-runtime-foundations.json). No commit or push was made.


## Fixed resource admission and signed browser contracts — 2026-09-30

Five catalog cases and six admission cases pass, including real workload wire
framing. The fixed root file is bounded to 64 KiB/128 resources, opened through
retained directory descriptors, and rejects symlinks, writable ancestors, unsafe
owner/mode, hard links, nonregular files (including nonblocking FIFO), duplicates
and malformed configuration. Catalog installation validates every existing
source mapping before replacing it. Workload requests contain only approved
resource IDs; account/source destinations/recipes remain administrator data.

The catalog VM rerun exits zero: actual production broker READY with valid
configuration; unsafe file permissions, symlink, writable parent and malformed
configuration denied before workload sockets; fixed diagnostics contain no
generated dummy canary. The helper, invocation proxy/stock tool and SIGKILL/ENOSPC
gates also pass; shortened helper cleanup measures 2,136ms in that run. This
startup case consumes no grants and does not prove browser operation execution.

The first signed-contract test demonstrated that the existing core parser and
controller routes allowed only `noop.marker`. The implementation now accepts
only the exact browser action/mode pair, limits browser grants/requests to 120s
and adds the signed request-event correlation. Native grants omit the new field
and retain their existing canonical wire format. The browser profile requires
the updated typed contracts; no older-node/browser compatibility claim is made.

Three real controller HTTP cases pass on SQLite: broker-signed evidence, named
approval/self-denial, one idempotent signed grant, resource/mode/evidence/TTL
substitution denial and signature verification. The core crypto case signs and
verifies the browser body, denies missing/bad request keys, mode substitution
and deadline extension, and detects signature changes to request/resource/time.
Two broker correlation cases first fail, then pass after original owner and
closure checks and exact signed-grant status lookup are added. A separate actual
Unix control/signature case passes: signed registration/policy/grant, tamper
denial, correlation, one-use durable preparation, safe retry and private event
canary checks. Workload identities are fixtures in that case; kernel/systemd
identity is covered by the separate VM proxy gate.

The native/noop consumer returns `browser_runtime_unavailable` before consuming
a browser grant. This preserves its one-use authority for the asynchronous
coordinator. Runtime launch/import/publication and verified reconciliation remain
unintegrated, so these results do not complete P05. No commit or push was made.


The three controller HTTP cases also pass on PostgreSQL using isolated schemas
in the existing disposable test service. Named requester self-approval is
explicitly denied; the designated other approver succeeds. Database runtime
configuration stays private and is redacted from the saved test log.

The latest signed-contract release VM rerun also passes all helper, catalog
startup, namespace proxy/stock tool and persistence checks; shortened helper
cleanup measures 2,140ms. The exact staged release hashes are in the JSON record.
The later grant uniqueness regression fails closed before source preparation
and before status chooses a grant; it is tested separately in broker/Rust gates.
The guest startup probe consumes no grants and its namespace driver still uses
a synthetic root lease. Full signed runtime workflow acceptance remains open.


Final combined `cargo test -p blindpass-broker browser_`: 35 passed, zero skipped.
Final locked serial Rust workspace and workspace/all-target Clippy gates pass,
including the grant uniqueness guard. Explicit SQLite and PostgreSQL controller
runs each pass all three cases with named self-approval denial. Root build/npm
gates pass; npm retains 101 SPS skips and the full Rust gate four ignored cases.
Formatting, shell syntax, JSON, 97 relative links (none missing) and diff
whitespace checks pass. Temporary VM keys/overlays remaining: zero. These
component results preserve all full runtime, AI-client, native and inherited
acceptance requirements. No commit or push was made.


## Reverse worker pidfd proof before import — 2026-09-30

Socket activation identifies systemd's listener, so the actual namespace worker
now connects itself to a fixed Root-owned identity socket. A random 64-hex
challenge crosses protected IPC only; the Root book retains its SHA-256 hash,
limits pending proofs to 16 and enforces a 15s boot-time deadline. Exact unit,
invocation and non-root/non-workload/non-helper UID must match the actual kernel
pidfd peer. A wrong unit cannot burn the legitimate ticket. The verified token
retains that pidfd and is fenced when its listener shuts down. The coordinator
still must enforce the original operation deadline, current signed authority,
namespace configuration and durable journal identity before import/publication.

The worker state machine rejects import before proof and rejects malformed,
repeated or failed proof with browser/profile cleanup and safe `uncertain`
output. Its proof client selects only the fixed Root socket, checks 0750 Root
parent/0660 Root socket/group membership/single link and uses bounded framed IPC
and exact fixed acknowledgement. Browser workers alone receive the dedicated
`blindpass-runtime` group. Challenges never appear in normal output, argv or
environment. Rust byte buffers are wiped; Node clears input references, without
claiming deterministic V8 string or browser-session erasure. The source password
continues to be consumed only by the private login helper, never this worker.

The new import/proof regression first fails, then passes. Four Rust identity
cases and seven state/client cases pass, including actual Unix partial/trailing
and stalled-wire tests. Two full pinned VM runs pass: same-UID other-unit proof
denied, legitimate worker proof succeeds before cookie import, held pidfd fails
after worker exit, stock tool completes two report reads/one reconnect, existing
workload invocation denials, namespace/sandbox/profile/copy revoke checks and
SIGKILL/ENOSPC journal probes pass. Final run includes /run ancestor ownership
and single-link socket guards. Shortened helper cleanup is 2,133ms then 2,146ms.
Exact staged hashes and scope are in [runtime evidence](p05-runtime-foundations.json).
Expected runtime identity and the proxy lease are Root test-driver metadata;
production signed-grant coordination and actual website/helper/browser recovery
are not established by these component runs.

Root build, final approved-host npm gate (26 helper/channel/recovery cases),
final serial locked Rust workspace and workspace/all-target Clippy pass. Existing
101 SPS skips and four ignored Rust cases remain (three desktop/offscreen,
PostgreSQL outage). Restricted sandbox UnixStream::pair fails with EPERM and npm
stock subprocess tests terminate without a response; passing gates were rerun on
the approved host. These failed sandbox runs are not counted as passing evidence.
Temporary guest keys and overlays are removed. All original P05/inherited, full
numeric/clock/suspend, native, provisioning and stock AI-client gates remain open.
No commit or push was made.

Final Rust formatting, shell/Node syntax, runtime JSON, diff whitespace and 90
relative links across six updated repository pages pass; no missing targets.
Disposable key directories/VM overlays remaining: zero.


## Official SDK legacy wrapper and standalone distribution — 2026-09-30

The OpenClaw entrypoint now explicitly starts the approved SDK's newline stdio
transport. Its existing MIT legacy registrations are adapted into SDK schemas;
store remains opt-in. A trusted embedding `toolContext` replaces the old caller
JSON-RPC context. The SDK factory imports no plugin/helper/AGPL implementation,
so this wrapper creates no package cycle. Custom Content-Length/RPC handling is
removed; supported older initialize and modern per-request flows use the SDK.
This is a transport/programmatic API migration; `handleMcpRpcRequest` is removed,
`createMcpOptions` adapts callbacks and `createMcpServer` returns the SDK server.

Initial wrapper regression fails before the new adapter exists. All eleven
SDK/wrapper cases now pass, including actual split newline startup on older and
modern revisions. The plugin's 62 cases pass: existing secret/exchange/store/
resolver contracts, metadata-only managed responses and all three configured
Node startup profiles. Its in-process protocol tests use the SDK micro-transport;
actual stdio checks are separate. SDK schema rejection can occur before a legacy
handler; invalid persistence never starts collection. Safe static validation
text remains, while caught upstream failure text is normalized.

Two privacy regressions first fail, then pass: a generic returned error's text
and structured fields cannot reflect a dummy private canary; a real legacy list
handler catches an upstream error as normal `Failed ...` text, and the adapter
now labels/normalizes it before the SDK boundary. Thrown and marked returned
failures produce only this fixed sample:

```json
{"isError":true,"content":[{"type":"text","text":"Operation failed"}]}
```

The CLI suppresses legacy console notices before registration. Arbitrary trusted
callbacks that write raw streams remain outside that adapter guarantee. The
legacy MCP process consumes decrypted temporary buffers, wiped in handler
finally blocks. Named runtime-only copies have no automatic TTL and remain until
disposal/replacement/process exit; managed storage persists encrypted values.
This preserves the prior client contract and is separate from private browser
source-password consumption. V8 strings and browser sessions are not claimed to
be forensically erased.

The build bundles a standalone CLI with complete notices. Actual emitted
compiler inputs produce a version/hash inventory for 19 package versions,
including unchanged legacy modules; build checks reject AGPL workspace code or
missing/unsupported license text. Two notice-check cases pass. The installer
initially fails its new notice-retention assertions, then passes all five after
copying notices/licenses and validating them before install. All three audience
packaging cases pass, including actual staged npm newline startup and complete
inventory retention. Release metadata passes. No package versions, manifest or
lockfile graph changed in this migration; frozen payment behavior is not extended.

Final root build/npm, serial locked Rust workspace, workspace/all-target Clippy,
release metadata, packaging and install gates pass. Existing 101 SPS skips/four
ignored Rust cases remain. Restricted wrapper-test subprocess IO was empty;
passing actual transport evidence is from the approved host. Early test helpers
used the wrong SDK handler shape and JSON instead of SSE and are failed harness
runs, not passing evidence; corrected SDK micro-transport and actual stdio runs
pass. No VM rerun was needed for this JS-only migration; prior runtime component
VM scope is unchanged. Actual complete Claude/Codex tasks, operation tools,
elicitation/routing, signed coordinator/reconciliation, provisioning, backup and
all inherited/phase acceptance gates remain open. No commit or push was made.


## Durable operation ownership before MCP cancellation — 2026-09-30

P05-I02/I03 exposed a prerequisite: request ownership and closure status were
memory-only, so acknowledging the transport event and restarting made status
unknown and prevented original-request checks. The new host regression first
fails with `unknown` rather than the expected signed `closed rejected`. Its
restricted-sandbox attempt fails on Unix socket permission and is not evidence
of behavior.

Ownership is now written atomically with its request event in version-3 outbox
state. Verified closure status shares that snapshot; event ACK leaves both
records intact. New request admission stops at 10,000 owners without eviction;
unknown closures grant no authority and consume no local slot. Snapshot failures
fence request/grant authority. Failed request intent is withdrawn in memory;
the relay cannot publish it until withdrawal is durable. Verified closure remains
in force in memory across failure and is retried before releasing the fence.

The retained key-directory descriptor anchors final read/rename/unlink; directory
mode is 0700, state is owner-only 0600, regular and single-link. Reads are
nonblocking and bounded to 64 MiB, metadata header to 8 MiB, with strict version,
field/count/key/status and duplicate validation. Terminal directory ownership
and mode are checked; this is not a new complete ancestor-walk guarantee for the
administrator-selected key path. State contains ownership and safe status, not
source passwords, cookies, bearer links or browser endpoints. No session-secret
lifetime changes. Versions 1/2 remain readable without inventing missing owners;
version 3 is rejected by older brokers, so rollback needs a matching backup.

The broker suite passes all 138 cases. Five new cases cover pending ACK/restart,
closure write-failure/fence/retry, capacity without eviction, malformed record
parsing and private file safety; the existing signed closure case now asserts
closed status and another-invocation denial after ACK/restart. An initial full
run caught changed failure withdrawal behavior; intent rollback was restored
behind the fence. Two test fixture compile errors and lint corrections were
fixed before final gates. Workload identities in local Unix tests are fixtures;
the separate VM exercises actual kernel/systemd identity boundaries.

Final workspace and VM gate results are recorded after execution below. No
workload cancel event, MCP operation tool, lost-reply request idempotency, pruning
or verified website/helper/browser reconciler is established by this change.
The 24h confirmed-session journal retention is a separate existing mechanism;
operation metadata currently remains until capacity denial. Full P05, stock AI
clients, native/provisioning and inherited acceptance gates remain open. No
commit or push was made.


Final execution: `npm run build`, root `npm test`, locked serial Rust workspace,
workspace/all-target Clippy, Rust formatting and diff whitespace gates pass.
Root npm retains 101 SPS skips; Rust retains the three offscreen Quickshell and
one PostgreSQL outage ignored checks. Existing SDK/wrapper 11, plugin 62,
notice 2 and helper/channel/recovery 26 tests pass. The pinned systemd guest
rerun passes actual protected helper IPC, reverse worker pidfd proof before
import, wrong-unit/restarted-invocation denials, actual stock browser report
reads/reconnect, copied-session revoke, protected profile/cgroup cleanup,
SIGKILL/ENOSPC session-journal probes and catalog startup denials. Short helper
cleanup is 2,136ms. Its driver still supplies a synthetic Root browser lease;
it does not execute owner ACK/restart against the fleet controller. Exact staged
release hashes and scopes are in the JSON record. The initial VM wrapper lacked
an executable bit (exit 126); explicit bash invocation succeeds, without any
host-access denial. No new P03 two-guest or full stock AI task gate was run for
this prerequisite.


The final post-lint release build changes three artifact hashes, so a second
pinned VM run verifies the exact rebuilt artifacts and passes (2,135ms shortened
helper cleanup). Both staged hash sets are retained in the JSON evidence. Final
focused `operation_` source tests pass 13 library cases plus the workload-client
operation-request case. Final JSON/link checks cover 62 relative links with no
missing targets; URL-encoded spaces are decoded before checking. Disposable VM
keys/overlays remaining: zero. No new dependency or lockfile change was made for
this durable-state prerequisite.


## Invocation-owned browser cancellation — 2026-10-01

P05-I02/I03/I04 now have a browser-only cancellation component path. The initial
core regressions reject the missing event kind and malformed cancellation key;
initial broker cases return the ordinary echo response instead of cancelling,
and initial HTTP cases reject the new event kind. These expected failures are
followed by passing implemented tests. A signing fixture initially used an
invalid issuer key ID; the corrected case verifies actual Root broker signature
bytes through its Unix control channel. Workload resolution there uses fixtures.

Version-4 protected outbox state retains consumption mode and cancellation
requested/acknowledged flags with the existing owner/closure records. The actual
invocation owner can stop browser authority without fresh controller time or
outbox space. Failed persistence retains the local stop and fences new authority;
retry persists intent before publication. Queue recovery and ACK/restart are
idempotent. Native requests and untyped version-3 owners cannot cancel. Versions
1/2 cannot reconstruct forgotten owners; older brokers reject version 4, so
rollback requires matching state backup. Metadata still stops at 10,000 owners
without eviction or pruning. No source password, cookie, bearer link or browser
endpoint is added to state, events, responses or evidence; plaintext lifetimes
remain as documented for the helper and browser.

The controller checks signature and original browser request owner/evidence,
then serializes cancellation with operation creation and approval/grant issuance.
One transaction removes only the cancelled approval member, withdraws any grant
(including consumed or expired), retains prior consumer results, emits signed
revocation/closure and writes audit/event receipt. Cancellation before creation
prevents a later operation. Replaying exact evidence has no second effect. An
injected database-trigger failure proves rollback of operation, tombstone,
audit, receipt and signed delivery before successful retry on both databases.
No human approval is invented by this workload action.

Eight broker cancellation cases pass in the 146-case broker suite. Eleven
controller HTTP cases pass on SQLite and PostgreSQL (eight cancellation cases
plus the three prior admission cases); real signatures are verified. Three core
cancellation cases pass in the 49-case suite. The relay regression uncovered a
real replay issue: persisted canonical JSON reordered fields, and structural
comparison rejected identical signed bytes. After a separate expected-failure
run, canonical comparison now accepts that replay and rejects changed content.
All thirteen relay binary tests pass. The initial relay failure is not counted
as a passing run.

Final build, root npm, locked serial Rust workspace, all-target Clippy, Rust
format and diff checks pass. Root npm retains 101 SPS skips; Rust retains three
offscreen Quickshell and one PostgreSQL outage ignored cases. The pinned VM gate
passes actual protected helper IPC, catalog startup, worker pidfd proof before
import, same-UID wrong-unit/restarted-invocation denial, stock-tool two reads/one
reconnect, copied-session revoke, cgroup/profile cleanup and SIGKILL/ENOSPC
journal probes. Shortened helper cleanup measures 2,130ms; this is a 2s override,
not the complete production deadline. Exact staged hashes are in the JSON
record. The relay fix changes no staged VM binary. Disposable VM keys/overlays
remaining: zero; seven failed disposable cancellation fixtures were removed.

`requested`, `cancelling` and signed `closed cancelled` are metadata, not verified
website invalidation or helper/browser cleanup. The VM still uses a synthetic
Root browser lease and does not run integrated fleet cancellation. Lost-reply
request idempotency, original recipe binding, MCP tools, production runtime and
reconciliation, provisioning/native backup, actual Claude/Codex tasks and every
original/inherited gate remain required. No dependency change, commit, push or
phase acceptance follows from this cancellation component.


## Request retries and cancellation before reply — 2026-10-01

The paired P05 plan first adds retry, original recipe binding and pre-admission
cancellation scenarios under P05-I02/I03/I04/I06. Five new host regressions then
fail against the missing retry field/cancellation behavior. Three fixture compile
mistakes are corrected before that expected-failure run; compile failure is not
behavioral evidence. The implementation now accepts an optional opaque browser
`request_key`, preserving the five-field native wire payload.

Version-5 state binds the retry key to node/workload/unit/invocation, every
original request field and the full Root resource fingerprint. This fingerprint
now includes source destination, resource/workload allow-list and configuration,
so old journal fingerprints cannot silently match an updated recipe. Every new
browser request retains resource/recipe binding even without a retry key; older
unbound ownership cannot authorize fresh login. Versions 3/4 retain available
status metadata; v4 typed browser owners can cancel by event ID, but cannot
recover missing recipe/retry binding. Older brokers reject v5; matching state
backups are required for rollback. No pruning or capacity expansion is added.

Canonical identical retries return their original event ID after lost reply,
ACK and restored snapshot, without a new event or renewed TTL. Changed purpose,
TTL, resource, recipe/source mapping or invocation is denied. Already admitted
retry returns metadata even with stale controller time, a full outbox or a
persistence fence; new authority/admission remains fenced. The full suite caught
an admission-order regression: invalid new payloads bypassed the existing queue
pressure check. Original precedence was restored while retaining safe known
retry lookup. Two tests now explicitly distinguish missing catalog/unbound
legacy ownership from trusted original bindings.

`cancel-key` uses original signed cancellation for an admitted request. Before
admission it durably stores local withdrawal, blocks a late request and sends no
controller event without original evidence. Failed writes retain the stop in
memory, fence authority and permit durable retry. The initial implementation
incorrectly queued a pre-admission cancellation; the restart regression caught
it, and the corrected path skips such local withdrawals. They share the existing
10,000-owner bound. This does not prove browser website/runtime cleanup.

Twelve broker and two input-parser cases pass in the 160-case broker suite.
Coverage includes actual Unix lost reply/reconnect with fixture identity and one
persisted request, canonical reorder/ACK/restart, conflict/owner denial, full
queue/stale time/fence metadata, pre-cancel persistence/restart/write failure/
capacity, failed admission withdrawal, original unused-grant recipe denial
before source/journal use, and strict malformed/duplicate binding parsing.
Input tests cover a 512-byte UTF-8 purpose plus 128-byte retry key within the
1,536-byte encoded and 2,048-byte operation bounds. One additional protocol case
passes in the 50-case core suite. No request key or recipe details are added to
controller request bodies; source/password/session lifetimes are unchanged.

Final build/npm, locked serial Rust workspace, all-target Clippy and formatting
pass. Existing 101 SPS skips/four ignored Rust checks remain. Both pinned VM
component gates pass; final rebuilt artifacts include lint and owner-mode guards.
Shortened helper cleanup measures 2,050ms initially and 2,136ms finally, using a
2s override. Actual helper IPC, catalog denials, namespace/proxy/worker identity,
stock-tool two reads/one reconnect, copied-session revoke, cgroup/profile cleanup
and journal SIGKILL/ENOSPC checks remain passing. The Root browser lease is still
synthetic: no fleet retry/pre-cancel or production reconciliation is established
by that guest. Exact artifact hashes are retained in the JSON record. Eight
known failed disposable test directories were removed; VM keys/overlays remaining
are zero. No dependency, commit or push change was made for this component.

MCP operation tools/30s cancellation, private-helper lost-login reply recovery,
production signed runtime and verified website/helper/browser reconciliation,
pruning, provisioning/native backup, actual Claude/Codex tasks and every original
phase/inherited gate remain open. Full P05 is not accepted.

The existing eleven browser HTTP/controller cases also pass on SQLite in the
final workspace and on the disposable PostgreSQL backend after this change.
These regressions preserve signed request/grant/cancellation compatibility;
they are not production fleet retry or private-login recovery evidence.

## Broker operation tools and packaged Root transport — 2026-10-01

The paired P05-I04/M01/M02/P05-I06 plan first adds actual SDK tools, fixed trusted
identity/socket, bounded reply/cancellation and metadata-only scenarios. Initial
SDK tests fail because the operation tools are absent. Global deadline tests
also fail before the common callback bound; fixture/compile failures are not
counted as behavioral evidence. No dependency, manifest or lockfile is changed
for this component.

The MIT factory now registers `blindpass_request_operation`,
`blindpass_operation_status` and `blindpass_cancel_operation` with a trusted
broker client. The packaged wrapper opts in through `BLINDPASS_FLEET_MCP=1` and
administrator node/workload/unit metadata plus inherited `INVOCATION_ID`.
Caller JSON cannot replace those claims or select account/source/origin/socket/
browser options. The client checks fixed Root directory/socket owner/mode/link/
inode boundaries; Root independently verifies the real peer. Requests retain
the original bounded browser payload and explicit stable retry key. Results
have exact safe shapes and opaque IDs, with no source, URL, cookie or endpoint.

Every callback, including legacy adapters, has a cancellable 30s response bound.
Linux uses kernel uptime; the broker client fits its 29.9s total inside that
bound and reserves up to five seconds for independent withdrawal. Timeout,
reply loss, SDK cancellation and EOF withdraw a submitted request by its original
retry key. Failure to confirm withdrawal returns explicit uncertainty, with no
new request. Twelve ordinary calls and four reserved cancel slots bound
concurrency. One complete strict UTF-8/ASCII newline frame plus EOF is required;
oversized, partial, trailing, malformed or secret-bearing replies cannot escape.
Copied temporary response buffers are wiped; V8 strings have no forensic erasure
guarantee. Legacy plaintext/storage lifetimes remain as previously documented.
A bounded legacy response does not prove arbitrary callback I/O has stopped.

All 34 SDK/client cases pass: eleven original contracts, sixteen broker client
cases (including actual Unix framing/socket replacement/stall), three actual
old/modern SDK broker-tool cases, two cancellation/EOF cases and two common
deadline cases. Coverage includes bounded stalled withdrawal, pre-abort versus
definite denial, independent injected clock expiry, safe canary rejection,
concurrency reserve and no late submission after stalled path checks. These
are shortened/injected deadline regressions, not a real suspend measurement.
All 62 legacy plugin contracts, two emitted-license/boundary cases, three
packaging paths, five isolated install cases and release metadata pass.

Two pinned systemd VM runs execute the packaged wrapper against the production
Root broker under actual non-root workload identity. Both 2025-11-25 and
2026-07-28 make real request/retry/status/cancel calls. Root verifies broker
Ed25519 request/cancel signatures; an application ACK and broker restart precede
retry, which returns the original ID with no duplicate request. Another unit
using the same UID and claimed invocation is denied without publishing an event.
No source is provisioned and no controller runs in this portion. This adds real
production metadata transport evidence to the earlier component probes; it
does not make their synthetic Root browser lease a production signed grant.

The first runtime archive hash is
`885c1f30e70ae73df07bc0f62373b05842a7d0fb9ecb87b91ed0b58fc4c3780a`;
the final archive, including the common callback deadline, is
`cd0af390f480c0625f523f0e5c992e322e882bf40c674bf17c6343d249f73907`.
Final standalone MCP SHA-256 is
`0d28394377588163edeb3a0653244049adeb88b44cff8cb3984bd86d90436958`.
Full inventory hash/commands/Rust artifact hashes are in the JSON record.
Both runs retain all helper/catalog/namespace/proxy/worker/stock-tool/journal
checks, including two report reads, one reconnect, copied-session revocation,
cgroup/profile cleanup and actual SIGKILL/ENOSPC. Shortened helper cleanup is
2,133ms first and 2,160ms final with the existing 2s override; full 60s production
bound remains unmeasured.

Final build, host root npm, locked serial Rust workspace and host packaging pass.
Existing 101 SPS skips and four inherited Rust ignored checks remain. Restricted
npm/packaging/legacy subprocess runs failed; restricted Rust socket tests failed
and stalled, and that run was stopped. Approved host reruns pass and are the
recorded gates. No restricted run is counted as passing runtime evidence.
All-target Clippy, Rust format, shell/Node syntax, runtime JSON and diff whitespace
pass; 99 relative links across eight updated repository guides resolve. Disposable
VM keys and overlays remaining: zero.

Controller operation creation from verified intent, signed runtime dispatch,
private-helper identity before source delivery/lost-login reply recovery,
verified website/helper/browser reconciliation, retention/pruning, P04-D4,
native backup/restore, elicitation/fallback, Node 24, actual Claude/Codex tasks
and all original/inherited acceptance gates remain required. Request/grant/
cancellation results are metadata, not readiness or verified cleanup. No phase
acceptance, dependency change, commit or push follows from this component.

## Verified browser intent creates controller approval — 2026-10-01

The paired P05-I02/I03/I04 plan adds automatic execution intent before code.
One broker regression fails on the absent version; seven HTTP regressions fail
on missing creation, grant, denial, strict input and atomicity. A fixture compile
error was corrected before that behavioral run. Two later expected failures
expose missing signed policy-change closure and grant recovery without its
original receipt; both are corrected. DDL fixture drops now explicitly avoid
prepared statement caching, and future-time denial uses a stable margin beyond
the accepted boundary. Fixture errors do not count as behavioral failures.

Every new Root browser event carries signed `request_version: 2`. Native event
bytes and unversioned evidence retain their manual contract; old evidence is
never silently promoted to execution intent. The controller verifies the broker
signature before strict field parsing, node/workload/unit/account/invocation,
action/mode, observed time, current registration/policy and TTL checks. Unknown
versions, extra fields and invalid or stale bindings are safely discarded with
no operation/grant or raw body retained in normal audit. A human create call
cannot claim a versioned workload intent. Updated broker/controller are required
together; this adds no database migration or dependency change.

The requester is the verified workload (`workload:<id>`), not a synthetic human
operator. Approval detail identifies it and preserves per-operation evidence.
Only the existing named human approval route can decide; node auth cannot approve.
Receipt, operation, approval membership, safe audit and initial denial closure
commit in one transaction on both databases. Existing lock/registration/policy/
cancellation checks run inside that transaction. Grant issuance finishes before
ACK. A transient grant write failure leaves the original committed request
unACKed; exact replay resumes it with no new operation/approval/deadline. An allow
grant is also clamped to the original absolute request deadline in both its
builder and store validation. Missing original receipt or operation cannot
reconstruct fresh authority. Policy change during issuance signs denial closure
and records the denial audit atomically; closure write failure rolls back that
transition. Cancel or expiry prevents later recovery from creating new authority.

All eleven new HTTP cases pass on SQLite and PostgreSQL. Coverage includes
workload approval/named decision, outsider/node-auth denial, one signed grant
under concurrent/repeated event delivery, 15 malformed signed inputs, each
receipt/operation/approval/audit failure, grant failure/replay, signed initial
and recovery denial-closure rollback, policy change, failed-issuance cancellation,
request/cancel batch, expiry without renewal and damaged-state denial. All eleven
original unversioned/manual browser/cancellation cases still pass on each store;
original native and named self-approval contracts pass in the full workspace.
The full broker suite passes 161 cases; the new case checks the Root-only version
and absence of local retry key in the controller body.

The first final PostgreSQL run passes ten new cases but gets HTTP 408 in the
approval-creation case while the VM and full Rust gates also run. That failed
run is retained and not counted as passing; the cause is not proven. After both
other gates finish, the unchanged suite passes eleven new and eleven original
cases. This rerun is HTTP component evidence, not a broad load/concurrency SLA.
Final build, approved host root npm, full locked serial Rust workspace, all-target
Clippy and formatting pass. Existing 101 SPS skips/four inherited Rust ignored
checks remain. Syntax/link/diff and teardown checks are recorded in the JSON.
Final shell/Node syntax and diff whitespace pass; 100 repository relative links
resolve. One known failed disposable broker fixture was removed. VM keys and
overlays remaining: zero.

The pinned KVM/systemd gate executes the actual packaged SDK against the rebuilt
production Root broker and verifies `request_version: 2` in signed events before
and after ACK/restart retry. Kernel same-UID wrong-unit denial, both protocol
revisions, no duplicate request, original cancellation signatures and all earlier
helper/catalog/namespace/proxy/worker/stock-tool/journal components pass. Runtime
archive SHA-256 is
`373b037c15520837cd8e69a93687771b96e676ddad24f32a23863abebd0e94af`;
exact rebuilt Rust artifact hashes are retained in the JSON. The MCP bundle hash
stays `0d28394377588163edeb3a0653244049adeb88b44cff8cb3984bd86d90436958`.
Shortened helper cleanup is 2,145ms with the existing 2s override. This guest's
MCP portion provisions no source/controller; browser probes still use a synthetic
Root lease. Separate actual HTTP and VM proofs do not establish the production
node/controller/broker browser lifecycle.

Production signed grant dispatch and outside runtime supervision, private-helper
identity before source delivery/lost-login reply recovery, verified website/
helper/browser reconciliation, retention/pruning, P04-D4/native backup, ordered
elicitation/fallback, Node 24, actual Claude/Codex tasks and every original/inherited
gate remain required. This controller consumes metadata only, no source/password/
session plaintext. Grant/closure metadata remains distinct from browser readiness
and verified cleanup. Full P05 is not accepted; no commit or push was made.


## Private helper kernel identity and durable source gate — 2026-10-01

The trusted transport now challenges the actual socket-activated private helper
before any source write. The worker connects itself to a separate fixed
Root-owned helper group socket. Root retains its kernel pidfd, verifies the
non-root dedicated UID and installed helper template, and journals the exact
manager-observed unit/invocation before sending the password job. Workload/browser
proof cannot use the helper's separate challenge book. Claimed identity fields,
raw-job socket requests and extra/malformed control data fail before login.
The fd-3/fd-4 mode remains an explicit trusted fixture harness.

Schema 3 preserves helper identity before a login reply exists. Lost reply or
restart keeps the account blocked; another helper cannot replace that invocation.
Missing/partial/invalid helper fields and failed persistence fail closed. A
schema-2 unfinished record retains its existing metadata without inventing a
helper identity or authorizing another login. Confirmed website and process
cleanup clears helper/browser identity while retaining the original closed record
for 24 hours. Rollback to an older reader requires a matching journal backup.
Broker/helper socket versions must upgrade together; broker snapshot stays 5 and
controller database stays 14. This slice changes no dependency or manifest.

Root temporarily consumes plaintext in a protected framed job until call/drop.
The held helper proof plus durable identity gate precedes source delivery. The
private helper/Chromium consume the source during the bounded login; the workload
gets only a separately validated intentional copyable website session. The
approved authentication endpoint also consumes the password after TLS decryption;
application-side memory and retention are outside Root's buffer lifetime. Buffers
are cleared on release, but V8/Chromium strings and disk deletion do not provide
forensic erasure. Current signed authority, runtime dispatch and cleanup remain
the production coordinator's responsibility.

### Behavioral failure and passing checks

Tests first reproduced: login accepted without durable helper identity; a raw
source job accepted in socket mode (`login_failed` rather than refusal); and a
schema-3 active record accepted with both helper fields absent. The completed
implementation passes 14 journal, 6 identity and 7 worker/client checks, included
in 167 passing broker cases. Thirteen helper cases include actual sandboxed HTTPS
browser/worker checks. Seventeen fixture/native checks also pass.

The approved host root build, npm tests, full locked serial Rust workspace and
all-target Clippy pass. Rust retains four inherited ignored checks: three
Quickshell offscreen tests and one PostgreSQL outage test. SPS retains 101 skipped
checks in ordinary npm. They are unexecuted here. A mistaken restricted full
broker run hit denied Unix IPC and stalled; its exact process was stopped and
the full host gate rerun passed. No restricted runtime success is claimed.

### Actual systemd VM

The pinned Ubuntu 24.04/systemd 255.4-1ubuntu8.17/kernel 6.8.0-139/QEMU 11.1.1
profile passes with Node 26.10.0 and sandboxed Chromium 145.0.7632.6:

- A same-UID wrong service is denied without consuming the legitimate ticket;
  the actual installed socket helper then succeeds. Replay is denied and the
  held pidfd fails after helper exit. This portion supplies no source job.
- During actual fixture authentication, the durable Root journal already has
  the helper unit/invocation and matches the running manager identity.
- A 64 KiB tmpfs is filled after reservation. Kernel proof completes, then the
  identity journal write encounters actual ENOSPC. Source delivery is withheld
  and no second website authentication starts. A one-second test startup delay
  makes failure timing deterministic; this is not a production time-bound test.
- Existing catalog, production-broker packaged MCP/version-2 event/ACK-restart,
  isolated namespace/proxy/reverse-worker, stock two reads/one reconnect, copied
  session revocation (401), cgroup/profile cleanup and journal SIGKILL/ENOSPC
  gates still pass. Shortened helper deadline cleanup measures 2,143 ms for a
  2,000 ms override. Full 60-second and suspend bounds remain unmeasured.
- Zero helper units, disposable SSH key directories or VM overlays remain.
  Persistence-only probes use private mounts and preserve earlier helper proof
  records; their operation/time/handle metadata remains synthetic.

The first VM attempt passed identity checks but failed before login because the
probe adopted optional fd 4 after internal descriptors could reuse its number.
The inherited descriptor is now captured before internal opens, with the complete
VM rerun passing. That first run is recorded as failed, not passing evidence.

Exact passing runtime archive SHA-256:
`b81699f01070e052db3deb5c9658e6bb4b2b7bb811ea0ae4ee84225aa663e715`.
The corresponding five release binary hashes are retained in
[p05-runtime-foundations.json](p05-runtime-foundations.json), under
`checks.privateHelperIdentity.vm`. The standalone MCP bundle remains
`0d28394377588163edeb3a0653244049adeb88b44cff8cb3984bd86d90436958` and
notice inventory remains
`5a85fa2580077453ec2166870206a52c1a8f3c81e3a01bf71c2deaed01affc1a`.

This proves helper transport/identity/persistence with synthetic Root probe
operation bindings. It does not run a production signed grant/source workflow.
The MCP portion provisions no controller/source; the browser lease is synthetic.
Production dispatch/current-authority checks/outside supervisor, integrated
lost-login recovery, website/helper/browser reconciliation, retention/pruning,
managed Grafana production clocks, P04-D4/native restic, URL elicitation/fallback,
Node 24, actual Claude/Codex tasks and inherited acceptance remain open. P05 is active.

## Root outside supervisor execution — 2026-10-01

The fixed `browser-supervisor-worker.mjs` now owns the outside private channel,
application-only opaque TLS forwarding and operation-hashed Root backend. It
runs as Root with a clean environment and inherited full-duplex fd 3; normal
stdout/stderr are empty. It accepts fixed configuration and bounded private
control, with no source credential or selectable path/target. Worker metadata
remains a discovery hint, not kernel/manager authority. Import acknowledgement
is private and creates no backend. Explicit Root publication alone opens the
Root 0600 single-link socket beneath Root 0700 directories. Existing operation
directories are refused. Current authority, manager/profile and journal checks
remain the production broker's responsibility before import/publication.

Linux `/proc/uptime` supplies suspend-aware time. Startup is capped at 120s;
a delayed publication cannot renew startup. Session time is independently
bounded by configuration and original login expiry. A new failure test caught
acceptance of a BOOTTIME deadline beyond that original expiry; it now fails
before cookie forwarding. References are cleared after private import without
claiming V8/browser forensic memory erasure. Chromium deliberately retains the
copyable session until closure/expiry. The supervisor receives no source job.

Eleven supervisor cases pass, with 23 passing when combined with the adjacent
transport/session cases. Six initial no-op protocol cases and three worker
stubs reproduce behavioral failures on the approved host. The initial restricted
attempt reported a generic runner failure, which is not behavioral evidence.
The original-expiry failure was demonstrated before fixing that behavior.
Workspace build/npm, locked serial Rust workspace and all-target Clippy pass:
167 broker, 50 core and 13 relay cases; npm includes 39 helper/channel cases.
Four inherited Rust cases (three Quickshell and one PostgreSQL outage) are
ignored, and 101 ordinary SPS cases are skipped. These are unexecuted here.

### Actual systemd component VM

The complete pinned Ubuntu 24.04/systemd 255.4-1ubuntu8.17/kernel 6.8.0-139/
QEMU 11.1.1/Node 26.10.0/Chromium 145.0.7632.6 gate passes:

- Actual Root invalid launches (missing private fd, extra argument, DEBUG)
  return 64 with empty normal output.
- The backend is absent after successful cookie import. Explicit publication
  creates the actual protected backend; the workload cannot read it. Normal
  stop removes its directory.
- The actual stock tool makes two report reads and one reconnect through this
  supervisor and the production Rust invocation proxy. Actual same-UID wrong
  unit and restarted invocation receive explicit denial. Reverse worker proof
  still precedes import; its held pidfd fails after exit.
- Browser cgroup/profile cleanup and the separately authenticated fixture
  account revoke/copied-cookie401 check pass. Fresh prepared-browser parent EOF
  and supervisor SIGKILL measure 60ms and 50ms cgroup/profile removal. **These
  fault cases have no source or imported session** and do not establish website
  recovery after an imported-session crash.
- Catalog, packaged production-broker MCP metadata/version2/ACK-restart (no
  controller/source), helper reverse identity/journal-before-authentication,
  actual ENOSPC source withholding, canaries and journal SIGKILL/ENOSPC remain
  passing. The shortened helper 2s override measures 2,172ms cleanup; full
  production time/suspend bounds remain open. Zero active helper units,
  disposable key directories and VM overlays remain.

Two earlier VM attempts reached the actual stock task but failed the new
restarted-invocation outcome assertion. The bounded final drain separates old
close/revoke/reset replies and still requires the replacement's explicit denial.
Earlier logs did not identify the exact old outcome; no specific transport-reset
diagnosis is claimed. A third launch was rejected without execution because
workspace credits prevented automatic approval review. After the user's
restoration confirmation, the approved complete rerun passed. Failed and
unexecuted attempts remain recorded.

Passing runtime archive SHA256:
`aa8f095c8b7e6c75c9c8d58ded69c1fc740c531a286cc8f9d80dcad7f8670c39`.
Exact binary hashes and attempts are in
[p05-runtime-foundations.json](p05-runtime-foundations.json), under
`checks.browserSupervisor.vm`. The MCP bundle/notices inventory hashes remain
unchanged. No manifest, lockfile or dependency version changed in this slice.

The Root driver still supplies a synthetic browser lease. Production Root
launch/signed-grant dispatch, held workload lease, current-authority/profile/
journal gates, stale private backend reconciliation and actual website/helper/
browser recovery remain open. A killed published supervisor can leave a private
backend directory; it must not be reused before Root reconciliation. No `stopped`
IPC reply is cgroup or website proof. Full production deadlines/suspend/managed
Grafana 30-minute VM behavior, retention/pruning, P04-D4/native restic,
elicitation/ordered fallback, Node24, actual Claude/Codex, small slice commits
and all inherited/two-host/pilot gates remain required. P05 is active.

## Native supervisor activation and complete recipe binding — 2026-10-01

The native broker's current service denies INET networking and executable
memory. The Node outside supervisor therefore uses its own Root-only
socket-activated service; the original broker unit remains unchanged. The fixed
`/run/blindpass-private/supervisor.sock` is Root 0600 beneath Root 0700. Exact
`--socket` uses private fd0; the existing fd3 embedding profile remains for
component fault probes. Other descriptors/paths/arguments, unsafe environment,
non-Root UID and non-socket transports are rejected. The outside service has
no capabilities, null stdout/stderr, bounded runtime and only Unix/application
network access. A shared Root backend directory is installed through tmpfiles;
it is not owned as an individual instance RuntimeDirectory.

The Rust private client checks fixed socket ownership/group/modes/single link,
Root peer and stable inode, then uses bounded 4BE messages with BOOTTIME
budgets. Prepared identity/DevTools metadata is redacted in Debug and remains a
hint: independent kernel/profile/journal checks are still required. Import and
publication are separate, and EOF/private failure removes transport readiness.
A stopped acknowledgment is not website/cgroup proof.

A new behavioral test exposed a complete-recipe binding gap: a session approved
for the same origin/account with a different source credential mapping reached
private import IO instead of rejecting before writes. Validated sessions now
carry the full Root recipe fingerprint and the client binds it at preparation;
the mismatch returns before any cookie byte. Canonical recipe hashing, broker
snapshot5, journal3, controller database14 and on-wire helper session schema are
unchanged. Protected cookie/challenge copies are cleared after serialization
without a forensic-erasure claim. Source passwords never enter this client or
outside supervisor; Root Rust and V8 briefly consume approved session material,
and namespace Chromium deliberately retains that copyable website session.

Seven Rust client cases and twelve JS supervisor cases pass. Test-first stubs
failed the initial three framing cases and socket-selection case; the new
source-mapping mismatch failed behaviorally before its correction. The ordinary
npm helper/channel group now passes 40 cases. Build, complete host npm, serial
locked Rust workspace and all-target Clippy pass: 174 broker, 50 core and 13
relay cases. Four inherited Rust checks (three Quickshell and one PostgreSQL
outage) remain ignored; 101 ordinary SPS checks remain skipped. They are
unexecuted here. Existing source helper/identity/journal and browser/proxy checks
remain covered by the VM and full Rust gates.

### Actual service VM evidence

The full pinned Ubuntu 24.04/systemd255/kernel6.8/QEMU11.1.1/Node26.10.0/
Chromium145.0.7632.6 gate passes through the actual Rust client:

- The disposable Rust caller keeps `AF_UNIX` and `MemoryDenyWriteExecute=yes`.
  Its startup function actually requires INET socket creation and anonymous
  RW-to-RX `mprotect` to fail; it executes no code and attempts no network
  connection in those checks. It then completes actual private prepare/proof/
  validated cookie import/explicit publication/stock task/stop through the
  separate production supervisor service.
- The Root supervisor's kernel `CapEff` is zero and its manager stdout/stderr
  are null. Protected socket/backend permissions, absent backend before
  publication, normal backend removal, separate DynamicUser/private network,
  reverse browser proof before import and held-proof failure after exit pass.
- The actual stock tool performs two report reads and one reconnect. Another
  same-UID unit and a restarted invocation are explicitly denied by the real
  Rust proxy. Canaries/private discovery are absent from returned model task
  material, agent files and all relevant helper/browser/supervisor/probe journals.
- Exact browser cgroup/profile removal and separately authenticated fixture
  account revocation/copied-cookie401 pass. Prepared-only embedding EOF and
  SIGKILL cleanup both measure60ms; these faults import no session and establish
  no lost website-session recovery. Helper shortened2s cleanup measures2,170ms.
  Full source/runtime deadlines/suspend/30-minute managed application behavior
  are still open.
- Catalog, packaged production-broker MCP metadata/version2/ACK-restart with no
  controller/source in that portion, helper kernel identity/journal-before-auth/
  ENOSPC withholding and journal SIGKILL/ENOSPC all remain passing. No helper,
  supervisor or native caller service remains running; disposable SSH keys and
  overlays are removed.

The first service VM passed before the new full-recipe binding fix. Its unit
verification emitted ignored template `Service=` warnings; final socket units
use their matching automatic template selection and the complete final VM
rerun passes without those warnings. This first run remains historical evidence,
not the final resource-binding artifact. Runtime archive SHA256 for the final
run is `5bde1b9035f8ab4a931c6ea20e57750f96bd9e6cdba4082ac4001be19890b133`.
Exact six binary hashes are recorded in
[p05-runtime-foundations.json](p05-runtime-foundations.json) under
`checks.nativeSupervisorService`. No dependency/manifest/lockfile changes
were introduced by this slice.

The VM still uses synthetic Root recipe/time/lease metadata. The production
broker does not yet launch this transport from signed grants. Held original
workload leases, asynchronous dispatch, usable administrator-owned revoke
configuration before source, current-authority/profile/journal gates before
import/publication, imported-session crash/restart/website/helper/browser
reconciliation and account blocking remain open. P04-D4/native restic,
retention/pruning, full clocks/bounds/Grafana profile, elicitation/fallback,
Node24/actual Claude/Codex, small slice commits and all original inherited/
two-host/pilot gates remain required. P05 remains active.

## Root administrator revocation and source gate — 2026-10-01

P05-RV01–P05-RV06 refine the original P05-I03/P05-I06 and B-E10–B-E13 gates;
phase acceptance remains open. The optional strict Root resource `revocation`
profile selects a separate mapped administrator credential and, for managed
Grafana, the exact established external account/user ID. It accepts no endpoint,
selector or arbitrary service unit. The full recipe fingerprint now includes
this profile/mapping; old requests cannot silently acquire new revocation
settings. Catalog version1, broker snapshot5, journal3 and helper wire schema
remain unchanged. Legacy catalog entries still support metadata, but fresh
browser preparation without administrator configuration fails closed.

Preparation validates mapped administrator custody before source copying and
journal reservation. The protected administrator copy is consumed once by
`PreparedBrowserLogin::begin_revocation`, outside the broker state mutex. The
native Root client connects only to the installed Root 0600 socket, verifies
parent/owner/group/single link/stable inode and Root peer, and performs bounded
4BE IPC under BOOTTIME deadlines. Source delivery requires fresh successful
online preflight for the exact operation/full recipe and a held private channel.
The gate expires at most 30 seconds after confirmation and by the original
grant deadline. The helper's guarded request rechecks current authority and
preflight after actual durable helper identity immediately before source writes.
Cookie validation additionally rejects a managed user ID which differs from
its administrator profile. Cleanup can use the held revoker after the short
source-preflight window expires; an uncertain reply never becomes cleanup proof.

The separate installed Root Node revoker is socket-activated independently from
the browser, capability-free, fixed argv/environment, null stdout/stderr and
bounded to 32 minutes. Fixture preflight checks administrator/account access
without logging out an existing session. Its bearer header is created only
after HTTPS hostname/certificate validity and CA trust or an explicitly installed
SPKI pin are verified. Redirects are refused. Selected managed Grafana uses only
the fixed protected Root Unix backend; preflight checks administrator privilege
and exact login/user ID. Logout targets only the prepared account or validated
nonbearer handle. Application confirmation alone does not prove helper/browser
cgroup termination or authorize account reuse.

Administrator plaintext consumers are protected broker custody/preparation and
the Root revoker. The preflight broker copy is temporary; the delivered revoker
copy stays in runtime memory until private close/failure or its 32-minute
BOOTTIME/manager limit. Custody expiry prevents new copies but cannot erase an
already delivered consumer copy. No administrator credential reaches helper,
namespace browser, model output, normal diagnostics or session journal. Source
password consumers remain broker/helper/private authentication and the approved
endpoint. Buffers/references are cleared, without a runtime forensic-erasure
claim; website sessions remain intentionally copyable and independently bounded.

### Executed regression and application checks

The missing-admin preparation test failed behaviorally against the previous
implementation, which returned preparation rather than the required denial.
The managed-user binding test separately exposed acceptance of user 3 under
administrator user 2, then passed after validation was added before cookies.
Initial JS no-op implementation stubs failed the fixed-profile and actual
fixture cases before implementation. The initial native stub run was restricted
by Unix socket EPERM and is not counted as behavioral host evidence.

Five JS cases pass: strict profiles; actual pinned HTTPS nondestructive preflight
and session/account replay denial; worker ordering/credential-reference clearing;
late preflight and lost-cleanup uncertainty; TLS-before-credential, no redirected
request and actual lost application reply after one cleanup request. Five native
cases pass: exact protected admin/operation/recipe framing; duplicate/extra/
oversized/lost replies; invalid administrator input before bytes; cleanup after
source-window expiry with handle/binding denial; and readiness loss on EOF.
Four preparation/importer cases cover missing administrator configuration,
missing/malformed/expired custody, strict profile fingerprint/mapping and exact
managed user binding. The full broker suite passes 183 cases.

The actual managed Grafana OSS13.2.3 check passes with its established external
OAuth account, private backend, actual private helper browser and copied-cookie
401 after administrator logout. Setup establishes the external account first;
preflight precedes the operation's subsequent source login. Negative account-ID
and non-administrator preflights cause no additional issuer credential acceptance;
public asserted identity returns401. The host uses a trusted disposable private
backend adapter and does not establish the production Root fixed-path manager
ownership gate. Earlier attempts with an administrator-created local user did
not establish suitability: the first hit the test harness's 10-second cutoff,
and the 60-second-budget retry returned only uncertain at the private helper's
55-second limit. No exact provider failure cause is claimed. Actual established
managed-account setup completes the passing case in about 4.7 seconds. The
bounded worker harness can now explicitly use its service-sized budget.

Final `npm run build`, host `npm test`, locked serial Rust workspace and all-target
Clippy pass. The final ordinary helper/channel group passes45; Rust includes
183 broker/50 core/13 relay cases. The 101 SPS skips and four inherited Rust
ignored cases (three Quickshell and one PostgreSQL outage) remain unexecuted.
No dependencies, package boundaries or upstream notice inventory changed in
this slice. Syntax, formatting, whitespace and current-guide links are checked.

### Actual installed-service VM

Two complete Ubuntu24.04/systemd255.4/kernel6.8.0-139/QEMU11.1.1/Node26.10.0
component runs pass. The first archive
`e6279016eedf003200c33be1d18ad312f86f28ac38bc53394b1196a9ae2ce008`
precedes the unified verified Unix connector and additional source callback
probe. The final archive is
`2bb5b8de32de86be7bcee81a578163860ee41836758cf4c7e5f53af6b0bfb865`.
Both use the pinned image hash and disposable SSH key recorded in the structured
evidence; KVM read/write and QEMU are checked by the approved host wrapper.

The native Rust driver executes the real revocation client under Unix-only and
executable-memory-denied settings, requiring actual INET socket creation and
RW-to-RX memory denial. The actual installed revoker has zero effective
capabilities, protected Root 0600 activation and null output. Preflight leaves
the original copied cookie active, exact session revoke returns401, and account
recovery revoke returns401 for a later copied cookie. Wrong-admin preflight
performs no authentication. Journal scans contain none of the generated source,
administrator or website-cookie canaries.

An additional actual separate-UID helper gate completes reverse kernel proof,
persists the observed exact helper identity, then rejects the immediate source
authorization callback. No second website authentication occurs. This is a
Root-only test-driver switch exercising the production guarded transport;
it is not an actual signed cancellation/policy/retained-workload gate. The
existing ENOSPC-before-source, journal SIGKILL/ENOSPC, production packaged-MCP
metadata/ACK-restart and stock browser/proxy identity regressions also pass.
The final helper2s override clears its verified cgroup in2141ms. Prepared-only
browser EOF/SIGKILL cleanup is60/50ms, with no source or session imported in
those fault cases. The stock tool performs two actual reads and one reconnect;
wrong unit/restarted invocation are denied. All active helper/supervisor/revoker/
native-caller units and disposable VM/key directories are zero after success.
Exact six Rust release hashes are preserved in the JSON evidence.

### Remaining production requirements

This slice connects administrator configuration/custody and fresh preflight to
the typed source job. Production browser dispatch is still not enabled. The
coordinator must retain the original accepted workload pidfd, establish browser
kernel/manager/profile proof and durable identity before import, recheck current
signed authority throughout readiness, close proxy authority first, stop the
exact helper before logout, terminate the verified browser cgroup, and release
an uncertain account only after actual reconciliation. Startup/unknown-helper
and stale backend recovery, retention/pruning, independent clocks/full30-minute
managed VM soak, P04-D4 fleet provisioning/native restic, elicitation/ordered
fallback, Node24, complete Claude/Codex tasks, small slice commits and all
inherited/two-host/pilot gates remain required. Preparing an uncertain operation
result ahead of asynchronous IO also still needs a durable relay/result-lifecycle
review before production dispatch. No phase or release gate is waived.


## Original workload process lease — 2026-10-01

P05-OW01–P05-OW06 refine P05-I02/I03 and B-E02/E05/E06/E10–E13. Production
workload admission now retains the accepted child process's SO_PEERPIDFD before
replying. Its immutable node/workload/event/unit/invocation/account binding and
liveness gate fresh browser preparation and native-path browser consumption.
Retry/status metadata, labels and a replacement PID cannot install a new lease.
ACK retains the original descriptor; broker restart restores request metadata
without reconstructing process authority. The book holds at most 16 original
leases; fresh admission is refused before events when full. Test-only surrogate
leases are compiled out of production.

The original held pidfd revalidates its current systemd unit/invocation outside
the broker state mutex, under the existing request deadline, before browser
consumption. Typed preflight/helper execution also require this bounded manager
check, and the immediate source callback checks original liveness again. A
100ms local sweep withdraws dead original requests through the durable browser
cancellation path without fresh signed time or outbox room. Storage failure
keeps the stop/fence and removes runtime authority. Cancel/signed closure releases
retained descriptors; an active job may still retain proof for cleanup but cannot
use cancelled authority. No source or administrator bytes enter this book.

### Executed checks

- Corrected restart regression: removing the owner authorization guard fails
  the explicit current-authority assertion (exit101); restoring it passes and
  denies preparation before source, journal reservation or result effects.
  The initial snapshot fixture lacked its final typed binding; it was corrected
  to persist that binding before claiming this regression evidence.
- Five new broker cases cover restart denial, exact binding/liveness, process
  exit under normal/missing-time/full-outbox/failed-storage conditions, ACK and
  closure, and the 16-lease admission bound with metadata retry. Explicit legacy
  test fixtures now install their test-only surrogate instead of claiming an
  actual kernel process. Full host broker suite: 188 passed.
- `npm run build` and `npm test`: pass; 45 helper/channel cases and 34 MCP cases,
  with 101 SPS service-gated skips reported. `cargo test --workspace --locked
  -- --test-threads=1`: pass (188 broker, 50 core and 13 relay-main cases, plus
  the remaining workspace/SQLite controller suites); four ignored checks are
  three offscreen Quickshell cases and the PostgreSQL outage case. Workspace
  Clippy `--all-targets --locked -- -D warnings`: pass. No new PostgreSQL-specific
  rerun is claimed. Formatting/syntax/diff and 136 relative links: pass/0 missing.
- Approved host execution confirms `/dev/kvm` read/write and QEMU11.1.1. Actual
  Ubuntu24.04/systemd255.4-1ubuntu8.17/kernel6.8.0-139 guest uses signed registration,
  policy, fresh time and grants with the production broker and actual non-root
  child process. After ACK, the original lease still authorizes the fail-closed
  native browser path; after broker restart it cannot be reconstructed. Killing
  the original child while its parent/service remains active withdraws authority
  and emits exactly one correctly signed cancellation in **86ms**. A replacement
  child in the same UID/unit/invocation gets original retry metadata/status but
  cannot consume the old grant. No source was provisioned: scope is process
  authority, not complete browser execution.
- First VM attempt stopped in the new issuer fixture, which supplied null for
  an absent optional approval reference; the strict signed schema rejects that
  value. Omitting the field yields the passing rerun. Existing helper/revoker,
  protected journal ENOSPC/SIGKILL, production catalog/MCP metadata, outside
  supervisor/native sandbox and stock two-read/one-reconnect regressions pass.
  Helper 2s manager override cleanup: 2155ms. Prepared supervisor EOF/SIGKILL:
  60/60ms, without source/session. Disposable VM/key cleanup completes.

Runtime archive SHA256:
`53f3babd464d355c0e94f8ec6b2a9fddedc9bed9225c691b63efc1e092af9b72`.
Pinned guest image SHA256 remains
`612b2c0cc1bc413a6cb8c38fd611794caf0f2b436c50013d8b3794db12ad7354`.
Six exact Rust release hashes are retained in the JSON record. Broker snapshot5,
session journal3, helper/catalog schemas, manifests, dependencies and package
boundaries are unchanged by this slice.

### Remaining production requirements

The production coordinator must use this retained original lease while running
private login outside the short state mutex, establish actual browser
kernel/manager/profile proof and durable identity before import, and check
current signed authority during readiness. The provisional uncertain result
keeps the controller operation executing; asynchronous final results need
separate immutable durable events because the relay can ACK the provisional
pair during login. Verified cleanup must close public authority first, stop the
exact helper before logout, invalidate the website session/account and destroy
the verified browser cgroup/profile before releasing an uncertain account.
Startup/unknown-helper and stale backend recovery, retention/pruning, independent
clocks/full30-minute managed VM soak, P04-D4 provisioning/native restic,
elicitation/ordered fallback, Node24, full Claude/Codex tasks, small slice commits
and all inherited/two-host/pilot acceptance gates remain open. No gate is waived.


## Asynchronous helper and immutable closure results — 2026-10-01

P05-AT01–P05-AT07 refine P05-I02/I03, B-E02/E05/E06/E10–E13 and the relay result
contract. Root preparation now fsyncs the exact proved helper and creates a
sealed, single-use source permission. The owned exchange runs with no journal
or broker state borrow; callers must release those locks first. Journal drop,
failed persistence or operation withdrawal invalidates permission. Its duplicate
file retains the lifetime flock until released, so a second journal cannot
reopen while detached source authority exists. Source writes check original
process/current authority/administrator readiness; response reads check current
authority independently of the short source window. Authority withdrawal closes
stalled IPC within its 250ms polling bound. Normal helper exit after its framed
reply can be valid; EOF does not prove website or cgroup cleanup.

Confirmed protected browser closure publishes a separate immutable result/audit
pair using deterministic keys and the original durable close time. It does not
modify the provisional pair after ACK. Exact closed resource/account/recipe/
workload binding is required; local authority is removed before outbox work.
Queue/persistence failure remains fenced with retryable journal evidence. Partial
ACK and broker/journal restart preserve canonical bodies and keys. Unit fixtures
use trusted reconciliation observations; they do not establish actual effects.

The controller accepts `browser_session_closed` only for a signed browser
operation; native marker and browser results cannot substitute for each other.
Consumed browser execution now remains independent of short grant expiry.
Cleanup after cancellation preserves revoked authority, and a late provisional
uncertain result cannot overwrite confirmed cleanup or advance its version.
The MCP exposes only `closed`/`completed` metadata. Closure evidence alone does
not prove a useful authenticated AI task.

### Executed checks

- Behavioral red checks reproduced rejected final HTTP completion, executing
  becoming uncertain at actual 1-second grant expiry, rejected MCP completion,
  and late uncertainty overwriting confirmed revoked cleanup. The last HTTP
  regression exits101 before the fix. Missing journal/producer API compilation
  failures are separately recorded and are not behavioral evidence.
- Nine new broker cases: three permission/flock/drop/failure cases, two actual
  Unix I/O authority/window cases, four completion/binding/queue/failure/ACK/
  restart cases. Full host broker suite: **197 passed**. Stalled-authority test
  verifies bounded client return and the server cannot write after channel close;
  actual helper stopping remains a separate requirement.
- Actual HTTP browser suite: **15 passed on SQLite and PostgreSQL**, including
  signed completion after provisional ACK, exact action/mode, grant clock and
  cancellation ordering. PostgreSQL browser intents11, approvals7, channel3 and
  lifecycle4 also pass. No PostgreSQL outage execution is claimed.
- Root build/npm and locked serial Rust workspace pass; MCP35 and helper/channel45
  pass. First npm attempt failed because an old malformed-reply fixture still
  rejected the now-valid completed outcome. Updated extra-field/private-canary
  and unknown-outcome denials pass in the full rerun. 101 SPS service-gated skips
  remain; four Rust ignores remain (three Quickshell, one PostgreSQL outage).
  All-target workspace Clippy, formatting, syntax, relative links and diff pass.
- Approved host execution verifies KVM read/write and QEMU11.1.1. Actual Ubuntu
  24.04/systemd255.4/kernel6.8 guest proves helper reverse identity, durable helper
  binding, detached journal access, source withholding after journal withdrawal
  and **zero second authentications**. Catalog/MCP metadata/original process,
  administrator revocation, outside supervisor/native sandbox, stock two-read/
  one-reconnect and protected ENOSPC/SIGKILL regressions pass. Original exit
  cancellation110ms; helper 2-second override cleanup2147ms. Prepared supervisor
  EOF/SIGKILL cleanup60/50ms excludes source/session. Disposable VM/key cleanup
  completes with zero remaining directories.

Runtime archive SHA256:
`bb4b866a7076134fd9a45fa779fa4f1eccbfca299ac1c7189ff2bbc83dfa72cb`.
Pinned image SHA256:
`612b2c0cc1bc413a6cb8c38fd611794caf0f2b436c50013d8b3794db12ad7354`.
Six exact release binary hashes are in the JSON record. Broker snapshot5 now
accepts locally verified browser `completed` closures; pre-change v5 rollback
requires a matching protected-state backup. Journal3, database14, signed closure
protocol, dependencies, manifests and package boundaries are unchanged.

### Remaining production requirements

The production coordinator must actually dispatch signed grants outside short
locks, verify browser kernel/manager/profile and persist identity before import,
check current authority through readiness, close proxy authority first, stop the
exact helper before logout, invalidate the website session/account and destroy
the verified browser cgroup/profile. Startup unknown helpers, lost responses,
stale backend and uncertain account recovery, protected retention/pruning,
independent clocks/full30-minute managed VM soak, P04-D4 fleet provisioning,
native restic backup/restore, elicitation/ordered fallback, Node24, full
Claude/Codex tasks, small slice commits and all inherited/two-host/pilot gates
remain required. No phase or release gate is waived.


## Signed-fixture production coordinator results — 2026-10-01

The opt-in coordinator now completes the actual systemd combined regression
gate with signed grants, HPKE source, private login, exact browser proof before
import, stock two reads/reconnect, cancellation cleanup and actual SIGKILL/restart
recovery. Copied cookies return401 after both cleanup paths; recovery performs no
second login and emits distinct signed final results. Exact request correlation
now lives in journal schema4. A behavioral regression reproduced withdrawing
another request's lease; corrected journal selection and stdout-drain tests
prevent previously observed false recovery assertions and truncated replies.

The complete scope, failed attempts, execution hashes, open acceptance and
plaintext limits are in [the coordinator record](p05-coordinator-2026-10-01.md).
This actual runtime evidence uses a Root signed issuer fixture; P05-PC08 still
requires the production controller/node workflow, useful stock AI-client tasks
and all original native/two-host/lifetime/inherited gates. P05 is not accepted.

## Actual Claude application task — 2026-10-01

The later managed profile completes actual Claude Code2.1.286 on Node26.10.0:
broker request, controller approval/node dispatch, local HPKE provisioning,
independently verified helper login, two authenticated report reads across stock
reconnect, parsed final12 artifacts, cancellation, copied-session401 and exact
runtime cleanup. The complete combined VM gate finishes0. Connected closure
measures28,790ms including final client-result observation. Full host workspace
gates pass110 helper/channel and38 MCP cases on both pinned Node profiles;
101 SPS skips remain. Scope and earlier failures are recorded in the
[coordinator evidence](p05-coordinator-2026-10-01.md).

The first actual Codex attempt exits1 during guest preparation/original-workload
precheck, before client task entry. Its authenticated task was unverified at
that checkpoint; the later VM3 pass is recorded below.
The Claude pass uses API operator/local HPKE provisioning; GUI provisioning,
URL elicitation/fallback, full lifetime/native/two-host/inherited and acceptance
gates remain open. No phase completion is claimed.

## Both actual stock tasks and ordered delivery — 2026-10-02

Codex CLI0.159.3 VM3 now completes the actual selected managed Grafana task and
combined VM gate, exit0. One independently verified private login, two real
report reads across stock reconnect and parsed final12 artifacts pass. Copied
session200 becomes401 after cancellation, exact runtime/profile removal and
controller closure pass; closure measures19,710ms. Root transport denial and
normal-channel canary scans pass, and owned disposable profiles/keys/VM overlays
are removed. VM2's invalid TOML configuration is reproduced and fixed. VM1's
original-workload failure remains unexplained. Both clients' task evidence is
API operator/local HPKE on Node26/systemd255 in separate disposable guests;
it does not complete GUI/URL-capable/unavailable client variants or the phase.

The MIT protocol router now has14 component and10 actual SDK stdio cases under
P05-DR01–DR07. It enforces the original deadline, fixed routing order, exact
SDK capability/revision/reviewed-client gate, definite versus uncertain delivery,
reservation/retry/persistence behavior and intended-host/authenticated-operator
fences. Production durable ledger, provider integration and reviewed client UI
privacy remain open. The actual built exports pass. Both Node24.21.0 and26.10.0
full build/workspace runs exit0:62 MCP cases and110 helper/channel cases each;
101 SPS skips remain. Eight Python cases pass again. Rust sources/dependencies
are unchanged in this delivery slice. Failed and aborted runs remain recorded.
See [delivery evidence](p05-delivery-2026-10-02.md) for exact scope and limitations.

## Fleet provisioning contract and crypto exchange — 2026-10-02

The separate browser-source binding now has four Rust/five browser-library
cases and seven actual JS-library-to-Rust exchanges per pinned Node profile.
Canonical metadata binds full grant/node version/original destination and
deadline to HPKE AAD. Exact UTF-8 decryption passes; changed destination,
operation, offer, recipient, legacy empty AAD and truncated ciphertext reach
actual opening and fail. The first probe decoder mistake is corrected and
retained as failed evidence. No GUI action, signed offer, controller relay or
one-use receiver is enabled. P04-D4 remains open.

Fresh locked Rust workspace exits0 with472 pass/four inherited ignores;
all-target Clippy exits0. Both supported Node build/workspace gates exit0 with
27 browser UI,62 MCP and110 helper/channel cases;101 SPS skips remain. Default
Rust database checks use SQLite; PostgreSQL outage and three desktop checks
are ignored. Real GUI/fleet and full lifetime/native/inherited/release gates
remain required. [Provisioning evidence](p05-provisioning-2026-10-02.md) records
the exact crypto/component scope and plaintext limits.


## Controller recipient offer ingestion — 2026-10-02

[Controller offer execution](p05-controller-offers-2026-10-02.md) adds versioned administrator-only
node/resource Source destinations and atomic public signed-offer ingestion from
current enrolled keys and retained original signed grants. Eleven actual HTTP
cases pass on SQLite and PostgreSQL; 500 full Rust cases pass with four
inherited ignores, and both pinned Node build/workspace gates pass with 101 SPS
skips. Scoped operator Source submission, automatic offer publication, durable
node ciphertext relay and actual GUI/systemd acceptance remain open.
