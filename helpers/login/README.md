# Private login helper

This AGPL helper uses the reviewed, exact Playwright 1.58.2 runtime. The separate
worker consumes one administrator-selected HTTPS recipe and its source password
through private IPC. The password exists in worker/Chromium form memory until
cleanup; JavaScript strings and disk deletion do not provide forensic erasure.
The approved website authentication endpoint also consumes the password after
TLS decryption; its memory and retention are governed by that application.
Approved website cookies and a non-bearer revocation handle return only to the
trusted broker. The workload browser deliberately receives a copyable session.

The binary frame is a four-byte big-endian body length followed by UTF-8 JSON,
maximum 16,384 bytes, exactly one frame followed by input EOF. Request keys are
`version: 1`, `configuration` and `credential: {account, password}`. Result is a
fixed `status`, with cookies/deadline/revoke handle only on `authenticated`.
Duplicate jobs, trailing bytes, oversized/invalid input and unsafe debug options
are refused. The broker must persist uncertain operation/account state before
sending a credential and validate the entire protected response before import.
The worker does not perform authorization or lifecycle reconciliation itself.

Default invocation uses inherited socket descriptors 3 (input) and 4 (output).
The socket-activated unit uses `--socket`, descriptors 0/1 of a root-only Unix
connection. Stdout is private IPC in this mode; it is never the journal. Stderr
is discarded. The supervisor supplies a clean environment before Node starts,
a pinned runtime/browser tree owned by root, and enforces the process/cgroup
maximum. The worker gives authentication 55 seconds, the manager has a 60-second
runtime maximum and a five-second stop grace for verified cgroup termination.
Interruption returns only `uncertain` (or no complete response); the broker must
retain account reconciliation state. Node preload/inspection settings take effect before script validation.

Socket mode requires a separate control frame before the source job:
`{"version":2,"challenge":"<64 lowercase hex characters>"}` (maximum 256 bytes).
The worker connects itself to the fixed
`/run/blindpass-helper-identity/identity.sock`; Root verifies its kernel pidfd,
dedicated helper UID and installed `blindpass-login-helper@…service` template.
The Root-owned parent is 0750 and the single-link socket is 0660, both using the
dedicated helper group. Workload/browser proof uses a separate socket and book.
Claimed unit/invocation fields, raw-job socket requests and extra control data
are refused. Only a valid one-use proof allows the worker to read the source job.

The trusted Rust caller retains the actual helper proof and must persist its
exact manager-observed unit/invocation in the schema-3 protected session journal
before writing any source bytes. Failed proof, peer exit, deadline or journal
write prevents delivery. Root may hold the framed source in protected memory
while preparing/proving the helper; the call clears that buffer on return and
cannot repeat the job. The independent signed operation budget remains at most
120 seconds and helper transport at most 60 seconds. JavaScript/Chromium memory
has the limitations stated above. Deploy updated broker/helper together; an
older socket client cannot use the new handshake.

Schema 2 reads retain their available recovery metadata without inventing a
helper identity. Unfinished records remain blocked after restart; a lost login
reply cannot authorize a new helper. Only verified website and process cleanup
can close the account. Schema-3 rollback requires a matching older journal backup.
The helper proof and transport are components; production signed dispatch,
current-authority coordination and cleanup remain open.

The Rust coordinator API now separates `prepare_helper_exchange` from
`PreparedHelperExchange::execute`. Preparation fsyncs the exact helper identity
and creates one sealed source permission; execution retains no journal or broker
state borrow. Release those locks before execution. The permission keeps the
journal's file lock and is withdrawn by revocation, journal drop or failed
persistence. Source and response authority are checked during bounded I/O;
closing the channel does not prove helper, website or browser cleanup. The
legacy `call_helper` facade still borrows the journal for the whole call.

The proposed [socket](../../deploy/native/blindpass-login-helper.socket) and
[service](../../deploy/native/blindpass-login-helper@.service) run under the
separate `blindpass-login` account. They require an installed runtime at
`/usr/lib/blindpass/login/runtime/bin/node`, source/dependencies at the parent
login directory, and browser binaries at `browsers/`. The pinned disposable
systemd VM executes this installed layout; production installation is not automated.
Chromium sandboxing stays enabled; private capture options are absent before
navigation. Browser control uses request-stage Chromium Fetch filtering of every
redirect hop; approved pages also have WebSocket connections denied. This fixed
page guard does not establish OS network isolation or private browser ownership.
Those require the real VM supervisor/workload tests in P05.

From the repository root:

```bash
npm run test:p05:helper
npm run test:p05:helper:grafana # requires verified P05_GRAFANA_HOME
```

[Decision 0006](../../docs/product/decisions/0006-p05-browser-runtime-review.md)
records user approval, Socket signals and retained sandbox/client/notice gates.
Upstream Playwright/core Apache licenses and notices remain in the installed
packages and must accompany distribution. Never copy source credentials into a
workload profile, argv, environment, journal, MCP result or managed capture.

## Ubuntu sandbox prerequisite

Ubuntu 24.04 restricts unprivileged user namespaces. The
[exact executable profile](../../deploy/native/blindpass-login-chromium.apparmor)
grants `userns` to the installed, root-owned Chromium binary, following
[Chromium's documented per-binary approach](https://chromium.googlesource.com/chromium/src/+/main/docs/security/apparmor-userns-restrictions.md).
It supplies this permission and does not provide full AppArmor confinement.
The global `apparmor_restrict_unprivileged_userns` stays enabled. Protect the
entire runtime/browser tree against unprivileged modification and validate this
profile again when changing the pinned browser path/version.

`./tests/browser-handoff/private-helper-vm.sh` uses the pinned image and disposable
SSH key variables from [fleet setup](../../tests/fleet/README.md), plus
`BLINDPASS_FLEET_RUNNER_OWNER`. It requires actual readable/writable KVM and QEMU.
VM state defaults to ignored `test-results/` to avoid tmpfs quota exhaustion;
an 8 GiB disposable overlay supplies the browser/library prerequisites. The
pinned base image is unchanged. Generated overlays, profiles, serial output and
staging data are removed on exit. Normal Node 26 guest runtime also needs
`libatomic1`; browser shared libraries come from signed Ubuntu repositories.

## Isolated workload browser

[browser-worker.mjs](src/browser-worker.mjs) is a persistent private framed
channel activated through the root-only
[browser socket](../../deploy/native/blindpass-browser.socket). Its
[service template](../../deploy/native/blindpass-browser@.service) uses
`DynamicUser=yes`, `PrivateNetwork=yes`, a new 0700 runtime profile and the same
pinned sandboxed Chromium binary. The profile must not exist before launch.
The root broker must verify the actual unit, invocation, UID and namespace,
then persist browser identity before sending approved cookies. The worker
reports `prepared` before import and `active` only after the import succeeds.
No source password or private helper profile enters this worker.

The namespace's localhost CONNECT proxy accepts only the administrator-selected
application HTTPS authority. Bounded framed channels carry opaque TLS records
to a separately trusted outside connector; each endpoint chooses its connector
from fixed configuration. Frames contain no network target. CDP uses separate
channels and is refused before import. Neither the namespace's CDP port nor
its proxy port should be accessible on the host. Source diagnostics are fixed;
duplicate JSON keys, malformed UTF-8, excessive nesting and oversized frames
close the private channel. Queue/channel limits and backpressure bound memory.

The root-only channel retains cookie copies briefly for import; V8 strings
cannot be deterministically zeroized. Cookie references are cleared after
import, while Chromium intentionally retains the website session until revoke
or expiry. TLS forwarding handles encrypted records. The unrestricted stock
browser tool can extract its own session; this is separate from protecting the
source password. Parent loss closes the context/profile, but website revocation
and verified manager cgroup cleanup remain the root reconciler's responsibility.

The [Rust public proxy](../../crates/blindpass-broker/src/browser_proxy.rs) accepts
only the fixed `/current` route on a root-owned per-workload Unix socket. It
retains the kernel peer pidfd and verifies the actual manager unit, invocation
and UID before backend attachment and throughout bounded forwarding. Generation
changes, authority loss and the boot-time deadline close attached channels.
Private DevTools discovery remains root-only. Seven local checks and the actual
namespace guest pass, including another same-UID unit with a spoofed unit header
and a restarted invocation denied before backend attachment.

Production dispatch, the signed-grant coordinator and verified reconciliation
remain to be integrated. The guest uses a synthetic Root test-driver lease and
does not establish a complete stock AI task.

### Root outside supervisor

[browser-supervisor-worker.mjs](src/browser-supervisor-worker.mjs) is the fixed
Root executable for the outside channel. A clean environment and inherited
full-duplex socket on fd 3 carry private embedding control; normal output is empty. It
connects only to the protected browser activation socket. Its bounded mux
forwards opaque TLS records only to the configured application HTTPS authority.
It accepts neither source credentials nor a selectable backend/network target.

Root sends configuration, the operation identity and a BOOTTIME startup deadline
of at most 120 seconds. Prepared worker metadata is a private discovery hint;
the broker must independently verify kernel identity, manager/profile and
current signed authority and persist browser identity before cookie import.
Successful import produces `imported`, with no backend. A separate Root
`publish` command opens the operation-hashed private Unix backend under
`/run/blindpass-backends/`: Root 0700 directories and a Root 0600 single-link
socket. Existing operation directories are refused. The public Rust proxy owns
workload authorization and the `/current` route.

Linux `/proc/uptime` supplies suspend-aware time. Publication cannot extend the
startup deadline while pending; the independent session deadline cannot exceed
the original login expiry or configured session maximum. Cookie references are
cleared after private import, without a V8 memory-erasure guarantee. Normal
closure removes the backend and closes the private worker channel. A `stopped`
reply acknowledges worker IPC only: website revocation and exact manager cgroup
verification remain broker duties. A killed supervisor can leave a private
backend directory; Root must reconcile it before reuse. The executable alone
does not establish production grant dispatch or cleanup.

The production [supervisor socket](../../deploy/native/blindpass-browser-supervisor.socket)
activates a separate [Root service](../../deploy/native/blindpass-browser-supervisor@.service)
using exact `--socket` and private fd 0; stdout/stderr are null. The fixed path
is `/run/blindpass-private/supervisor.sock`, Root 0600 beneath Root 0700.
This keeps the broker's Unix-only networking and executable-memory denial
unchanged while the separate Node unit uses executable memory and application
egress. The supervisor has no capabilities. Install its
[tmpfiles rule](../../deploy/native/blindpass-browser-supervisor.tmpfiles) as
`/usr/lib/tmpfiles.d/blindpass-browser-supervisor.conf` and run
`systemd-tmpfiles --create /usr/lib/tmpfiles.d/blindpass-browser-supervisor.conf` before activating it. The shared backend parent is
not an instance RuntimeDirectory, so ending one supervisor cannot cause manager
cleanup of another operation's backend.

The [native Rust client](../../crates/blindpass-broker/src/browser_supervisor.rs)
checks the fixed path's owner/group/modes/single link/stable inode and Root peer,
then uses bounded private frames and BOOTTIME deadlines. Prepared hints are
redacted in Debug and remain non-authoritative. Cookie import is bound to the
complete prepared recipe fingerprint, including source/workload mappings; a
session validated for another recipe sends no cookie bytes. Transport EOF or
failure removes readiness, without claiming website or cgroup cleanup. The VM
executes this actual client under the broker's key sandbox restrictions through
a disposable Rust probe. Synthetic lease and production coordinator limits
still apply.


## Administrator resource catalog and signed requests

`blindpass-broker --browser-resources` enables the fixed
`/etc/blindpass/browser-resources.json` startup catalog. `/`, `/etc` and
`/etc/blindpass` must be root-owned directories without group/other write access.
The file must be root-owned, mode 0600, regular and single-link; every path
component is opened relative to a retained directory descriptor with symlinks
refused. Files are limited to 64 KiB and 128 resources. The catalog uses
`{"version":1,"resources":[...]}` with the exact trusted
[BrowserResource](../../crates/blindpass-broker/src/ops/browser_session.rs) format:
resource/workload IDs, mapped source unit/name and a fixed helper configuration.
Passwords, selectors, scripts, endpoints supplied by workloads and capture
options are not catalog fields. Duplicate resource/account aliases fail.

Browser operation requests select only a resource ID. Admission checks the
installed resource, current workload and policy, exact action/mode pair and
independent operation/policy/registration ceilings (operation at most 120s).
The controller verifies broker-signed request evidence and the existing named
approval policy before signing a browser grant. Its signed `request_event_key`
binds the grant to the original request. Fresh preparation and status require
that request's workload/invocation owner; a signed closure ends its authority.
Native grants retain their existing canonical fields. The browser profile
requires the updated controller/node/broker contract; older implementations
refuse the browser action/extra field. No compatibility profile is accepted yet.

Status returns only `granted` plus opaque grant/operation IDs to that owner.
The synchronous native consumer returns `browser_runtime_unavailable` before
consuming a browser grant. The asynchronous runtime coordinator and reconciler
still need integration; enabling the catalog does not provide a working browser
operation. The deployed broker unit keeps its existing startup configuration.


## Root administrator revocation before source delivery

The [fixed revoker socket](../../deploy/native/blindpass-session-revoker.socket)
and [Root service](../../deploy/native/blindpass-session-revoker@.service)
run separately from the browser at `/run/blindpass-private/revocation.sock`
(Root 0600 under Root 0700). Install these units with the pinned private Node
runtime; enable the socket only in the administrator-managed deployment. The
service has no capabilities, fixed argv/environment, null normal output and a
32-minute manager maximum. It uses only fixture HTTPS or the fixed managed
Grafana backend `/run/blindpass-app/grafana.sock`; the latter requires Root 0700
parent/0600 single-link socket with stable ownership/inode. The Grafana profile
uses its selected managed app's trusted-user header over this private backend;
public asserted identities remain denied. This is not a generic Grafana adapter.

An administrator resource can add `revocation` alongside its five existing fields:

```json
{"kind":"fixture-admin","credential_unit":"blindpass-session-revoker@.service","credential_name":"fixture-admin"}
```

For managed Grafana use `kind: "grafana-admin"` and an exact positive `user_id`
for an already-established external managed account. The credential name selects
the administrator's separate protected broker mapping: a 64-character lowercase
hex fixture administrator bearer or the selected Grafana administrator login
identity. Credential values are not catalog fields. Unknown fields, arbitrary
units/endpoints, mismatched profile kinds and a shared source/admin destination
are refused. The full recipe fingerprint includes the revocation profile and
mapping; changing them requires a new request. Legacy resources without this
profile retain metadata compatibility but fresh login preparation fails closed.

[Broker preparation](../../crates/blindpass-broker/src/ops/browser_session.rs)
requires available, unexpired and valid administrator custody before copying the
source. `begin_revocation` performs online preflight outside the state mutex;
`call_helper` requires this exact resource/operation's fresh native
[revocation client](../../crates/blindpass-broker/src/session_revoker.rs).
The client checks the fixed Root transport, private framing and BOOTTIME budgets.
The source-delivery gate runs again after durable helper identity, immediately
before source writes, together with the caller's current-authority check.
Preflight is bounded to five seconds and usable for source delivery for at most
30 seconds and the original grant deadline. Lost connection removes that
permission. Cleanup remains usable after the short source window expires.

Fixture preflight checks administrator/account access without revoking a live
session. Bearer headers are built only after TLS hostname, certificate validity,
normal CA trust or the explicit Root-installed SPKI pin is verified; redirects
are not followed. Managed preflight checks the administrator role and exact
account/user ID before the operation's login. Cookie validation checks that
same managed user before import. Session/account cleanup sends only a validated
nonbearer handle or the prepared fixed account. Lost cleanup replies are
`uncertain`; an application acknowledgement alone does not prove cgroup cleanup.

Administrator plaintext consumers are protected broker custody/preparation and
the Root revoker only. The temporary broker preflight copy is consumed once;
the revoker retains its administrator copy in runtime memory until private
connection close, failure or its 32-minute BOOTTIME/manager bound. Existing
custody expiry prevents new copies but does not erase an already delivered
consumer copy. The helper, namespace browser, model, normal output and session
journal receive no administrator credential. Buffers/references are cleared on
close; V8/runtime memory is not a forensic-erasure guarantee. Source plaintext
continues to be consumed only by broker/helper/private authentication and the
approved endpoint. Browser sessions remain copyable and independently bounded.

Actual fixture/systemd and managed Grafana component checks pass; the Grafana
host test uses a trusted adapter to its disposable private Unix backend and does
not prove production Root manager ownership. The production dispatcher must
still use the retained original workload pidfd, recheck signed authority, stop the
exact helper before logout, terminate the browser cgroup and reconcile durable
account state before reuse. No new full-workflow profile is accepted.

## Production coordinator staging opt-in

This is an implementation profile awaiting acceptance. Actual signed-fixture
guest runs verify private login, stock reads, copied-cookie denial after cancel,
and actual SIGKILL/restart account cleanup without relogin. The complete combined
systemd regression run passes. Unfinished accounts remain blocked when cleanup
cannot be confirmed. Full controller/node and AI client tasks
have not run in this profile.

The native broker's `--browser-resources --browser-runtime` flags dispatch a
signed grant only from the retained original workload process. Preparation holds
short state/journal locks; private login, manager checks, cookie import and
cleanup run in a separate actor. Browser activation uses its reverse kernel
proof; numeric discovery hints do not authorize it. The exact browser identity
is fsynced before import. Status exposes only `ready` plus an opaque `ctx_`
reference. The invocation proxy rechecks current authority on every connection
and while forwarding.

Install the fixed private runtime/socket/service templates and apply
[the tmpfiles entries](../../deploy/native/blindpass-browser-supervisor.tmpfiles)
after sysusers. The [staging broker drop-in](../../deploy/examples/browser-runtime.conf)
adds the flags, source/admin destinations and write access to both proof socket
parents. Adapt the fixed Root resource and workload registrations to the staging
profile. Credentials arrive through protected provisioning; they are not unit
settings or catalog values. No host installation is performed by the VM harness.

The [runtime manager](src/runtime-manager.mjs) is a separate Root service with
`CAP_SYS_PTRACE` for cross-UID namespace metadata and `CAP_DAC_READ_SEARCH` for
metadata inside a DynamicUser 0700 profile. It accepts fixed class/unit/invocation/
UID selections, never caller PID/path, source, administrator or cookie values.
It checks installed executable/hardening, actual procfs UID/cgroup/network and
profile metadata. Native broker Unix-only/MDWE/CAP_CHOWN restrictions remain.
This manager belongs to the trusted host boundary; its capabilities are not a
new source confidentiality guarantee against a compromised Root service.

Cleanup withdraws public authority first, stops the exact helper before logout,
revokes the website session/account, stops the browser and checks actual cgroup
emptiness and profile absence. Unknown unproved runtime termination remains
uncertain. At startup the Root manager stops all fixed managed helper/browser/
supervisor instances and removes only validated stale Root backends. Pending
records block new login; recovery waits for fresh signed time and matching
administrator custody, then revokes the fixed account without source or relogin.
A changed recipe/account or unavailable cleanup stays blocked. Ephemeral custody
must be re-provisioned after broker restart; this is not unattended reboot support.

The coordinator periodically prunes closed reconciliation records after the
existing 24-hour signed-time retention. Owner/withdrawal records retain their
separate capacity and still need retention work. Closed-result delivery retries
have broker coverage for queue/storage failures; complete delivery E2E, actual clock/suspend/full 30-minute
managed application testing and the full controller/AI-client/native workflows
remain acceptance requirements. See [coordinator execution evidence](../../docs/testing/evidence/p05-coordinator-2026-10-01.md).

Journal schema 4 retains the exact original request event key. Delivery retries
may withdraw or complete only that request after checking the full binding.
Schemas 2/3 remain readable with their existing recovery metadata; missing
request correlation never authorizes guessing an owner from workload or recipe.
Their confirmed closures can still be reported without changing an inferred
request. An older broker cannot read schema 4; rollback requires a matching
pre-upgrade protected journal backup.

Source custody checks both runnable time and BOOTTIME. A prepared login retains
the original Source expiry and rechecks it before every Source write, independently
of the grant and website deadlines. Expired or missing custody metadata denies
new Source delivery before journal reservation. The new broker cases are portable
component evidence; actual suspend remains a VM acceptance requirement. Source
copies remain private broker/helper memory and are discarded with the one-use
exchange; neither the runtime metadata manager nor the workload consumes Source.


Pending HPKE recipient keys also use runnable time and BOOTTIME, with authority
checked before and after opening. A clock failure withdraws pending keys, and
unrepresentable lifetimes return a safe error. This does not renew Source
custody, grant or website deadlines. Keys are discarded on purge or attempted
opening; this is not instantaneous forensic erasure during suspend. The actual
recipient-key clock component gate is described in the
[coordinator record](../../docs/testing/evidence/p05-coordinator-2026-10-01.md).
