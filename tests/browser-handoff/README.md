# P05 application suitability preparation

This directory implements P05.1 application prerequisites, two rejected Grafana
profiles, a passing managed-OAuth Grafana staging profile and component harnesses
for the private helper, broker, namespace worker, packaged MCP tools and stock
browser channel. Full production coordination and the two-host/AI-client
workflow remain open.

The full phase and acceptance requirements remain in the
[implementation plan](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/phases/05-workflows-and-clients.md)
and [paired test plan](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/testing/phases/05-workflows-and-clients.md).
See the [execution record](../../docs/testing/evidence/p05-workflows-and-clients-execution.md)
and [support matrix](../../docs/product/p05-support-matrix.md).

## Fixture checks

Run from the repository root:

```bash
npm test                     # includes the 12 fixture HTTP cases, without Chromium
npm run test:p05:fixture      # HTTP cases plus the real Chromium fixture UI case
npm run test:p05:oauth        # two issuer HTTP/config cases plus a native Chromium OAuth form
```

Requires Node.js, OpenSSL and, for the UI case, the Chromium build belonging to
the repository's locked Playwright dependency:

```bash
npm exec --workspace=packages/console -- playwright install chromium
```

Loopback sockets and browser processes must be permitted. A denied bind or
browser sandbox failure fails the test rather than skipping the scenario.
The UI test enables Chromium's sandbox and trusts the disposable certificate's
specific public key. It does not disable all HTTPS verification. The HTTP suite
separately verifies the generated CA and rejects a connection without that CA.
This does not establish system CA installation or a helper's production TLS policy.

`fixture-app/server.mjs` exports `startFixture` for disposable harnesses. The
caller supplies TLS material, a generated administrator token and two generated
test account passwords; it listens only on a random loopback HTTPS port. There
are no shipped passwords, private keys, refresh tokens or framework dependencies.
The fixture is not a general account service or a deployment package.

| Endpoint | Contract |
|---|---|
| `GET /login`, `GET /login.js` | Local sign-in UI; form input cleared; no third-party assets |
| `POST /login` | JSON username/password; fixed errors and bounded body/attempt/session limits; issues only the host-only `__Host-bp-fixture` cookie |
| `GET /reports` | Authenticated account's read-only backup report; no credential-management controls |
| `GET /api/session` | Account, viewer role, original deadline and non-bearer session reference; never refreshes authority |
| `POST /admin/sessions/revoke` | Separate administrator bearer authentication, no browser Origin; account-bound session reference; idempotent revocation |
| Other viewer API/mutation requests | Denied, including password, recovery, authenticator, integration, account and token changes |

The default independent session maximum is 30 minutes. Both the original wall
deadline and the original monotonic deadline must remain live. Activity does
not refresh either. Fast tests shorten this maximum; the simulated clock tests
are not suspend or wall-clock rollback evidence from a VM. All sessions are
memory-only, contain only bearer digests in server state, and are invalidated
on application restart. No claim of unattended persistence is made.

The test caller, sign-in page and Chromium consume generated plaintext passwords
in memory during sign-in. The fixture retains salted scrypt hashes. Cookies
intentionally authorize the browser and controlled replay test until revocation
or expiry. The test browser intentionally receives that session; this is not
session-extraction protection. The administrator token is separate and retained
only by the test caller/server. Temporary TLS private keys stay in a private
temporary directory and are deleted on normal cleanup. JavaScript/browser
memory disposal and file deletion do not prove forensic erasure.

No trace, screenshot, video, HAR or storage-state file is created. The browser
test replaces errors with fixed stage/code diagnostics to avoid dumping input,
cookie or live URL values. Hooks close browsers/HTTPS servers and delete TLS
directories after assertion failures as well as successful tests.

### Certificate pin semantics

`certificateSpkiPins` (at most two SHA-256 SPKI hashes) feeds Chromium's
`--ignore-certificate-errors-spki-list`. That flag adds trust: a certificate whose
key is listed is accepted even when its hostname, validity period or chain would
be refused. It does not restrict a connection to the pin. The private login helper
therefore keeps the flag, because a private service has no public CA chain, and
additionally reads the certificate Chromium actually used (CDP
`Network.getCertificate`, after `Network.enable`). CDP answers only for the origin of
the document Chromium is showing, so the login origin is checked before any credential
is typed and the application origin after the login lands on it, before the session is
published (when the two differ, the application origin is not checked before the OAuth
redirect first reaches it). Each check requires all of the following:

- the served leaf's SPKI hash equals a configured pin (a pin on the CA or any
  other chain member does not count);
- the leaf's SAN (or, without SANs, CN) matches the origin's hostname or IP;
- the current time is inside the leaf's validity period.

The chain is not validated against a CA: for a pinned service the pin is the trust
anchor, which is the same rule `session-revoker.mjs` applies to its own TLS
connection. A failed check returns the fixed `login_failed` before typing, or
`uncertain` once authentication has started; nothing about the certificate is
reported. Without pins nothing is added and Chromium's normal validation applies.
Residual: the isolated workload browser (`browser-worker.mjs`) still passes the
same flag without a post-connection check; it only reaches the single approved
authority through the fixed proxy, and the session is already established.

[`certificate-pins.test.mjs`](certificate-pins.test.mjs) covers the verifier
(matching pin, wrong or CA pin, wrong host, IP, expired, not yet valid, malformed
and empty input). [`private-login-pins.test.mjs`](private-login-pins.test.mjs)
drives the actual helper and Chromium against the fixture TLS app: a matching pin
with a valid certificate reaches credential entry, a certificate Chromium accepted
whose key is not configured fails first, and a matching pin does not excuse an
expired or wrong-host certificate. The test page reports the first typed
character, so each negative case asserts that nothing was typed or submitted. The
`private-login-pins` test needs Chromium and is run by the explicit command
`node --test --test-isolation=none tests/browser-handoff/private-login-pins.test.mjs`.

### Helper time budget, cancellation and transport limits

The private worker draws the control/identity-proof wait (5 s), the job-frame wait
(5 s) and the login from one monotonic 55 s budget, so the total stays inside the
unit's `RuntimeMaxSec=60s`; the login receives only what is left. The job frame is
parsed with the same duplicate-key-rejecting parser as every other private frame.
SIGTERM aborts the in-progress login (the browser is closed) and, if that does not
finish, the worker still answers `uncertain` and exits after two seconds. The
Playwright library also closes its browser on SIGTERM, so the actual-worker
SIGTERM test passes without the new abort path; the unit-level abort test and the
early-abort check cover the new code.

The supervisor/worker pipe sizes its outbound queue from 32 channels times the
largest 32 KiB data frame (about 1.4 MiB); when it is full senders wait in order and
only a peer that accepts nothing for 10 s fails the session (the former fixed
256 KiB cap failed with about six busy egress channels). A read carrying more
than 128 frames is decoded in batches with the stream paused instead of failing.
Late tunnel frames after `stop` are dropped so they cannot turn `stopped` into
`uncertain`, and late browser disposal removes the proxy and profile even if
closing the context throws.

## Grafana suitability probe

Download the pinned **Grafana OSS 13.2.3** Linux amd64 archive from the
[official download page](https://grafana.com/grafana/download?edition=oss)
and verify SHA-256
`6107ad27016296aac38e0d7ffa8753ab540b5541ad27e94790f771289d733235`.
Set `P05_GRAFANA_HOME` to its extracted distribution directory, containing
`bin/grafana`, `conf` and `public`, then run:

```bash
node tests/browser-handoff/grafana-suitability.mjs "$P05_GRAFANA_HOME"
```

The harness starts the pinned binary with a new private SQLite state directory,
generated administrator and Viewer passwords, HTTPS, a configured 30-minute
maximum, and disabled update reporting/preinstallation. It uses the real profile
UI and direct HTTP APIs, tests server logout with copied-cookie replay, then
stops its process and deletes its private state. It never targets a pre-existing
application. Browser captures and upstream diagnostic output are disabled.

The observed local-password Viewer profile is **rejected**: account/email and
password updates succeed. A zero harness exit confirms that rejection probe's
assertions, not suitability or P05 acceptance. Sustained use beyond the candidate's
30-minute maximum is not run once its role prerequisite fails. Alternate
authentication/proxy/plugin configurations require their own suitability tests.

## Selected managed Grafana staging profile

Using the same verified distribution, run:

```bash
npm run test:p05:grafana
```

`managed-grafana.mjs` starts a disposable HTTPS frontend, a separate HTTPS
authorization-code issuer and the real Grafana backend on a private 0600 Unix
socket. The issuer has exactly the generated primary/isolation account identities;
it serves immutable Viewer/org claims, binds its single client and callback,
requires PKCE S256, consumes codes once, and issues no refresh tokens. It is
test infrastructure, not a production identity service. Grafana only sees the
OAuth identity. All ordinary APIs are forwarded without asserted identity or
Authorization headers; Grafana itself authorizes them. The frontend does not
apply a role-based API filter. A private trusted-user header is used only for
disposable admin setup/logout over the Unix socket and is stripped at the public
frontend. Same-UID fixture execution does not prove fleet/helper separation.

The passing profile disables local password login/recovery and uses external
managed accounts in separate organizations. Valid profile/password/token/service
account/data source/user mutations return 403. Actual report UI works; managed
name/email/username inputs are disabled and no password-change control is shown.
Administrator logout invalidates all sessions for the selected account, including
a copied cookie, while the isolation account stays live. A future broker/helper
must enforce exclusive account use and protected admin access; this is not a
per-operation revoke implementation.

The live ceiling test repeatedly reads the user API and invokes Grafana's actual
token-rotation API. Five rotations and 297 reads did not extend the original
five-minute maximum: last live at 298,761 ms, rejected at 299,765 ms. The
[sanitized result](../../docs/testing/evidence/p05-grafana-13.2.3-managed-oauth-suitability.json)
is application-only evidence, not a 30-minute soak, VM-clock or integrated
browser/stock-client result. Auth proxy alone was also rejected: metadata said
external, but valid profile mutation still returned 200. It is not the selected
account authentication profile.

The test caller, private issuer form and private test Chromium consume generated
source passwords in runtime memory. The issuer retains salted scrypt hashes.
Authorization tickets live at most 60 seconds, one-use codes 30 seconds, and
read-only identity access tokens 10 minutes, stored as digests in issuer memory;
Grafana receives the identity token and may retain it in its private disposable
state. The independent website session lives at most five minutes and is copyable
by its browser owner. These are separate authorities and deadlines. TLS private
keys, OAuth client secret and Grafana admin secret/configuration stay in private
temporary files until cleanup. No source credentials or bearer data are passed
on process arguments, saved in evidence, or emitted by upstream logs. Deletion
and memory disposal do not prove forensic erasure.


### Native helper and reconciliation persistence checks

From the repository root:

```bash
cargo test -p blindpass-broker private_helper
cargo test -p blindpass-broker session_journal
cargo build -p blindpass-broker --bin blindpass-private-helper-probe
node --test tests/browser-handoff/private-helper-native-probe.test.mjs
```

Use the real host clock/socket environment for the IPC checks. The existing
`private-helper-vm.sh` command and fleet image/key/runner prerequisites also run
the actual Rust caller, SIGKILL journal recovery and ENOSPC fencing on disposable
guest tmpfs. Native probes consume generated private input only and are test
programs, not workload tools. Journal probes use synthetic time and nonbearer
metadata; they establish persistence only. The coordinator, actual website and
verified helper/browser cleanup, namespace channel, and full production/suspend
bounds remain separate gates. Temporary guest state and keys are disposed by
the harness; this does not establish forensic erasure.

The socket-mode caller now begins with a protected challenge and reverse kernel
proof from the actual dedicated helper, then persists its exact manager unit and
invocation in journal schema 3 before source delivery. The separate fixed proof
socket/book cannot accept browser/workload proof. Schema 2 preserves recovery
metadata without inventing helper identity; unfinished operations stay blocked
after restart. Require the updated broker/helper together and a matching backup
for rollback to an older journal reader. The fd-3/fd-4 fixture mode is unchanged.

The VM adds [helper identity checks](helper-identity-guest.mjs): same-UID wrong
unit denial preserves the legitimate ticket, actual installed helper proof,
replay denial and held pidfd failure after worker exit, with no source job.
[The private login driver](private-helper-guest.mjs) observes exact persisted
manager identity during actual authentication. It also fills a 64 KiB tmpfs
after reservation, obtains the real proof, and checks that failed identity
persistence withholds source and starts no second authentication. Its one-second
test startup delay supplies deterministic failure timing; it does not establish
full production bounds. A private probe observation reports only `proof_verified`.
Persistence-only journal fixtures use separate mounts and preserve the real
helper proof journal. These remain component checks, with synthetic probe
operation bindings; no production signed grant/source dispatch is implied.

### Harness positive controls and shipped units

Several VM units log nothing (`StandardError=null`, output on the private socket),
so a plain "canary not in journal" check could not fail. Every canary scan in the
VM guests now uses [`journal-canary-scan.mjs`](journal-canary-scan.mjs). A scan
passes only if the source is non-empty, every expected unit shows a systemd
lifecycle line, and the scanner detects an injected random token. For the journal,
a transient unit also logs a token through journald that the same query reads back.
For output and home directories, a control file must be found by the same walk and
a harness marker file must still be present. Failures use fixed codes and never
print canaries or scanned bytes. A canary hit is never retried; only a missing
control, a missing unit or an empty source is retried, for a bounded time, while
journald catches up. The helper guest rescans the journal after its deadline stage
before printing `journal_canaries=absent`. The scanner has host unit tests
(`journal-canary-scan.test.mjs`: empty input, missing unit, injected canary, clean
data); the guest wiring and the real `journalctl --sync`/`systemd-run` control are
VM-only and were not executed by these checks.

The end-of-run leak check lists `blindpass-browser@*`, `blindpass-runtime-manager@*`,
`blindpass-browser-supervisor@*`, `blindpass-session-revoker@*`, the login helper
and broker units with `systemctl list-units --all`. Any state other than
inactive/dead fails, and so does a failing `systemctl`
(`private-helper-leak-check.test.mjs` runs the real function against a stub
`systemctl`). A unit left `failed` by a deliberate stage must be reset by that stage.

The VM guests now install and start the shipped `blindpass-broker.service` with the
shipped `browser-runtime.conf` drop-in instead of ad-hoc `systemd-run` properties.
A generated `p05-guest.conf` swaps only the workload group, appends one
`--workload` and sets `Restart=no`, `TimeoutStopSec=5s` and `RuntimeMaxSec`
(the guests SIGKILL the broker and watch it fail, which `Restart=on-failure` would
race). `systemd-analyze verify` passes on the units and drop-ins statically. The
unit's sandbox (`SystemCallFilter=@system-service`, `UMask=0027` and so on) has
not run in a P05 VM and is NOT VM-verified; `p05-enrollment-broker` is still an
ad-hoc unit. Destination restriction for browser traffic is enforced in code
(`browser-network.mjs`); `IPAddressDeny=any` with `IPAddressAllow=` is an optional,
unverified drop-in documented in `deploy/examples/browser-runtime.conf`, and
`RestrictAddressFamilies` limits address families, not destinations.

### Browser preparation and namespace channel

```bash
cargo test -p blindpass-broker browser_
cargo test -p blindpass-broker browser_proxy
node --test tests/browser-handoff/isolated-browser-agent.test.mjs
node --test --test-isolation=none tests/browser-handoff/browser-transport.test.mjs tests/browser-handoff/isolated-browser.test.mjs
node --test --test-isolation=none tests/browser-handoff/fixture-app/app.test.mjs tests/browser-handoff/fixture-app/revocation.test.mjs
```

The first command covers administrator recipe/custody selection, grant and OS
binding, one-use preparation, authority recheck and staged cookie/handle
validation. This component probe does not exercise production request dispatch. Later
sections record selected actual controller/node fixture and managed dispatch. The pure JS cases
cover framing, tunnel directions, import sequencing and fixed safe failure;
their test doubles do not prove kernel/browser isolation.

The existing `private-helper-vm.sh` additionally runs
[isolated-browser-guest.mjs](isolated-browser-guest.mjs). It installs the reviewed
stock Playwright MCP package and launches the browser under the actual
DynamicUser/PrivateNetwork template. The guest driver checks manager invocation,
different UID/net namespace, host-loopback CDP denial, private profile, stock
Unix CDP report/reconnect, canaries and profile/cgroup cleanup. Its Unix proxy
is now the actual Rust kernel-pidfd/manager-unit/invocation component. Another
same-UID unit (including a spoofed unit header) and a restarted invocation are
denied before backend attachment. Two actual stock reads and a reconnect run
within the original invocation. The root driver still supplies a synthetic lease;
production signed-grant dispatch/coordinator are not established by this run.
Agent-control subprocess checks require the actual host: empty subprocess IO
in the restricted sandbox is not a passing execution. See the execution record
for actual results, including failed attempts.

### Outside supervisor component

```bash
node --test --test-isolation=none tests/browser-handoff/browser-supervisor.test.mjs tests/browser-handoff/browser-supervisor-worker.test.mjs
```

The twelve cases are also included in `npm test`. They cover private import,
explicit publication, strict message ordering, fixed paths/permissions, original
expiry bounds, delayed publication, parent loss and safe failure. Test doubles
establish state-machine behavior; the disposable VM separately launches the
fixed [Root executable](../../helpers/login/src/browser-supervisor-worker.mjs)
through its protected socket-activated service and attaches the actual stock tool through the
Rust invocation proxy. The VM checks that no backend exists at import
acknowledgment, only explicit publication creates its Root 0600 socket under
Root 0700 directories, and normal stop removes it. Private fd/argument/debug
launch failures have empty normal output.

The VM's EOF and SIGKILL checks start fresh prepared browsers without source or
session import and measure actual cgroup/profile removal. These are not lost
website-session recovery tests. The Root driver still supplies a synthetic
lease; production broker launch/current-authority/journal/publication gates and
website reconciliation remain required. Published supervisor crashes may leave
a private operation directory, which is refused until Root reconciles it.

```bash
cargo test -p blindpass-broker browser_supervisor --locked -- --test-threads=1
```

Seven native client cases cover private framing, strict hints, fixed paths,
original deadline, EOF readiness loss and full-recipe session binding. The VM
adds a disposable socket-activated Rust driver of the actual client. It keeps
`RestrictAddressFamilies=AF_UNIX` and `MemoryDenyWriteExecute=yes`, functionally
requires INET socket creation and RW-to-RX `mprotect` to fail, and still performs
actual prepare/proof/validated cookie import/publication/stock task/stop through
the separate production supervisor. That Root supervisor has no effective
capabilities and null normal output. The original broker unit is unchanged.
The test driver supplies synthetic Root recipe/time/lease metadata; it is not
a production signed grant/source dispatcher. This verifies the native transport
under the two sandbox constraints, not the whole production broker lifecycle.

`POST /admin/accounts/revoke` is the fixture's separately authenticated recovery
endpoint when a login reply/handle was lost. It revokes every selected-account
session and fences authentication already in progress while preserving other
accounts. The integration must stop the private helper before revoking and keep
the account blocked until website and both cgroups are confirmed clean.


### Catalog and signed browser operation checks

```bash
cargo test -p blindpass-broker browser_catalog
cargo test -p blindpass-broker tests::browser_
cargo test -p blindpass-broker signed_browser_grant
cargo test -p blindpass-core browser_grant
cargo test -p blindpass-controller --test fleet_browser_operations
```

The controller suite uses real HTTP, broker-signed evidence, named approval and
controller-signed grants. It supports the usual `P02_TEST_BACKEND=postgres` and
`P02_TEST_POSTGRES_URL` isolated-schema profile. It does not execute login or an
AI-client task. The broker control case uses actual Unix transport and signatures
with fixture workload identities; actual systemd pidfd evidence remains in the
separate VM proxy gate. Request correlation and one-use preparation are exercised
without calling the private helper. Native grants retain their canonical format.

The existing VM command also runs
[browser-catalog-guest.sh](browser-catalog-guest.sh): the actual production broker
starts with the root-installed catalog and refuses unsafe permissions, symlinks,
a writable parent and malformed configuration before exposing workload sockets.
No browser grant is consumed by that startup probe. Runtime coordination and
verified reconciliation remain separate mandatory gates.

### Reverse worker identity proof before import

```bash
cargo test -p blindpass-broker runtime_identity --locked
node --test --test-isolation=none tests/browser-handoff/runtime-identity-client.test.mjs tests/browser-handoff/isolated-browser.test.mjs
```

The namespace worker must prove itself before importing cookies. Socket
activation identifies systemd's listener, so the actual worker makes a reverse
connection to the fixed `/run/blindpass-runtime/identity.sock`. The Root listener
checks the kernel pidfd and atomic manager unit/invocation/UID against expected
administrator metadata. The socket is Root-owned 0660 inside a Root-owned 0750
directory; only browser workers receive the `blindpass-runtime` supplementary
group. Workloads do not receive it. Proof is bounded to 15s of boot time and 16
pending challenges. The coordinator must also enforce the original operation
deadline and persist verified runtime identity before cookie import.

Challenges cross only protected IPC, never normal output/argv/environment. The
Root book retains a hash, consumes it once and holds the worker pidfd. Wrong-unit
attempts cannot consume the legitimate ticket. Listener shutdown fences verified
tokens. Node drops challenge and cookie references promptly; this does not claim
forensic erasure of V8 strings or browser sessions.

The existing disposable VM gate runs the actual Rust listener and worker client,
a same-UID wrong-unit attempt, proof before import and held-pidfd failure after
worker exit. It retains the stock tool, namespace/profile, revocation and journal
checks. Expected runtime metadata and the proxy lease still come from the Root
test driver. Production signed-grant coordination and reconciliation remain open.

### Packaged MCP tools against the production broker

Run `npm run build` before the existing `private-helper-vm.sh` command above.
The runtime archive includes the standalone MCP wrapper and its full upstream
license inventory. [broker-mcp-guest.mjs](broker-mcp-guest.mjs) starts the real
Root broker and a non-root systemd workload using that packaged wrapper.
[broker-mcp-guest-client.mjs](broker-mcp-guest-client.mjs) makes actual request,
retry, status and cancellation calls under both 2025-11-25 and 2026-07-28.

The Root driver verifies broker event signatures, ACKs the first request and
restarts the broker before retry. The retry returns its original event ID and
creates no duplicate request. A different unit using the same UID and claimed
invocation is denied by the actual kernel/systemd check. Cancellation produces
the original signed owner-bound event. Dummy issuer keys stay in disposable
memory/private state; no source is provisioned and no controller runs here.
Fixed summary output contains no private recipe or source canary. Known guest
units/state and host overlay/SSH key are removed on exit.

The guest also verifies signed `request_version: 2` on every new browser request.
`cargo test -p blindpass-controller --test fleet_browser_intents --locked
-- --test-threads=1` separately exercises actual HTTP automatic operation/approval/
grant creation on SQLite or the standard isolated PostgreSQL profile. Existing
unversioned/manual and native contracts remain supported; old evidence is not
silently converted into an execution intent. Updated broker/controller are
required together. Neither component test runs the complete fleet lifecycle.

This is metadata/identity/transport evidence. The other browser component probes
still use a synthetic Root lease; none establishes controller-driven operation
creation, signed-grant runtime dispatch, website/helper/browser reconciliation
or complete Claude/Codex tasks. Host SDK tests are documented in the
[MCP package guide](../../packages/mcp-server/README.md).


## Administrator preflight and revocation component checks

Run from the repository root:

```sh
node --test tests/browser-handoff/session-revoker.test.mjs
P05_GRAFANA_HOME=/path/to/verified/grafana-13.2.3 node --test tests/browser-handoff/session-revoker-grafana.test.mjs
cargo test -p blindpass-broker session_revoker --lib --locked -- --test-threads=1
```

Five ordinary JS cases cover fixed profiles, actual pinned HTTPS preflight and
session/account replay denial, worker ordering/deadlines, TLS-before-credential,
no redirects and uncertain lost cleanup replies. Five native client cases cover
private framing/binding, malformed/oversized/lost replies, input denial before
bytes, cleanup after source-preflight expiry and lost readiness connection.
Four additional broker/importer cases cover missing/unavailable/expired admin
custody, strict fingerprint configuration and exact managed user validation.
These tests need the same approved loopback/subprocess access as other P05 gates.

The managed Grafana check uses actual OSS 13.2.3, its private Unix backend and
actual helper browser. Setup first establishes a real external OAuth account
before installing its exact ID into the resource profile. Preflight occurs before
the operation's subsequent login; failed preflights cause no additional issuer
credential acceptance. Public asserted identities fail and logout makes copied
cookies return 401. A failed earlier local-user setup is recorded separately;
creating a local user does not establish managed-account suitability.
The private host test adapter checks its owner/inode/mode; it is not the
production fixed-path Root manager proof.

The existing `private-helper-vm.sh` also installs the actual revoker units.
The Rust native probe executes the real fixed client under AF_UNIX and
MemoryDenyWriteExecute restrictions, requiring actual INET socket and RW-to-RX
denials. The guest checks Root 0600 activation, zero effective revoker
capabilities, nondestructive preflight, both copied-cookie revocations, failed
admin preflight without authentication, null output and journal canaries. An
additional actual helper proof/durable-journal probe denies the immediate source
authorization callback and starts no second authentication. This uses a
Root-only test-driver switch, not workload authority or a production bypass.
The guest's operation/workload/time inputs remain synthetic. Full signed
production dispatch and actual website/helper/browser reconciliation are
separate gates.

## Original workload process lease

`cargo test -p blindpass-broker --locked --lib -- --test-threads=1` now includes
five new P05-OW01–P05-OW06 cases (188 total broker cases). They cover original
request/grant/process binding, missing runtime proof after a durable restart,
process exit under absent signed time/full outbox/failed persistence, ACK and
closure, and the 16-lease fresh-admission limit. Test fixture process leases are
compiled out of production. These checks require host Unix sockets for the full
suite; restricted socket failures do not establish host behavior.

The existing disposable `private-helper-vm.sh` includes
[browser-owner-guest.mjs](browser-owner-guest.mjs) and its
[non-root workload parent/child](browser-owner-guest-client.mjs). The production
broker receives real signed registration/policy/time/grants and retains the
actual accepted child pidfd. ACK keeps that lease. Broker restart cannot
reconstruct it. Killing the original child leaves the parent/service active,
then a new child with the same UID, unit and invocation cannot consume the old
grant or replace its original process through metadata retry. Correctly signed
cancellation appears once; the measured exit-to-cancel bound was 86ms.

No source is provisioned in this lease check. The native browser path remains
fail-closed after valid authority; no private login/import or complete production
browser lifecycle is claimed. Issuer private keys stay in Root test memory and
are disposed with the guest. No administrator/source/session plaintext enters
the runtime lease or ordinary evidence. Full coordinator, immutable asynchronous
results, recovery, provisioning/native, actual AI tasks and inherited gates
remain required; see [execution evidence](../../docs/testing/evidence/p05-workflows-and-clients-execution.md#original-workload-process-lease--2026-10-01).


## Detached helper source permission

The same `private-helper-vm.sh` gate now runs the actual Rust helper caller with
a sealed channel after identity fsync and no borrowed journal during I/O. The
disposable Root probe withdraws journal permission before sending source; the
actual worker records no additional authentication. The probe-only flag is not a
production configuration option. This scope verifies source withholding; it
does not execute asynchronous production dispatch, browser import or cleanup
under a fleet controller. P05-AT01–AT07 and exact gate evidence are recorded in
[the execution record](../../docs/testing/evidence/p05-workflows-and-clients-execution.md#asynchronous-helper-and-immutable-closure-results--2026-10-01).

## Actual controller and node browser workflow

After `npm run build`, use the same pinned image, disposable SSH key and runner
owner prerequisites as the private-helper gate:

```bash
BLINDPASS_P05_FLEET_BROWSER=1 ./tests/browser-handoff/private-helper-vm.sh
```

This opt-in P05-PC08 scenario stages the real controller and node binaries. It
creates a disposable SQLite controller with generated private credential files
and an administrator seed, verifies TLS with a disposable CA, enrolls the actual
broker identity with an operator issuer pin, and approves its matching
fingerprint. Policy and workload registration come from the controller API;
grants, signed time, broker events and acknowledgements travel through the
unprivileged node relay. No synthetic issuer document is delivered by this
driver.

The workload's real unit/invocation performs a browser request, obtains actual
approval, reads the authenticated fixture report with the stock browser tool,
and cancels. A second operation covers actual broker SIGKILL/restart, copied
cookie denial, account reconciliation without another login, and the
controller's final result. Source/admin input enters the broker through the
actual HPKE provisioner; it is not fleet GUI provisioning. The website and
operator are fixtures. This command does not run useful Claude/Codex tasks, a
second host or native backup acceptance. Check the dated execution record for
actual results; the presence of this driver is not passing evidence.

Generated website Source/admin values live in Root driver memory and broker
custody for this disposable test. Controller root/JWT/issuer material lives in
Root0600 files under its private0700 runtime directory until cleanup. Operator
sessions and enrollment tokens pass only through private HTTP/child pipes and
are never printed. The node cannot read broker key storage. Session copying
uses a private Root scan pipe to prove replay denial; copied values never enter
normal logs or evidence. Deletion does not establish forensic erasure.

Keep the driver and staged sources unchanged during execution. The run must
finish and clean up before a dependent script is edited or rerun.

### Selected managed Grafana application

The same opt-in actual controller/node driver supports the selected managed
Grafana 13.2.3 profile:

```bash
P05_GRAFANA_HOME=/path/to/verified/grafana-13.2.3 \
BLINDPASS_P05_FLEET_BROWSER=1 BLINDPASS_P05_BROWSER_APP=grafana-managed \
  ./tests/browser-handoff/private-helper-vm.sh
```

Reuse the previously checksum-verified distribution with `bin`, `conf`,
`public`, full upstream `LICENSE` and `NOTICE.md`. The runner records its exact
runtime bundle hash and stages it only in the disposable guest. The harness
checks the actual API version, disables plugin preinstallation/update checks,
and retains the public asset licenses and notices. No package dependency graph
or selected upstream version changes.

App setup establishes an actual external OAuth Viewer through a descriptor-mode
private worker under the separate login UID with Chromium sandbox enabled, then
revokes its session. That one setup login is counted separately. The two actual
production operations still require signed controller approval, HPKE custody,
reverse kernel helper proof, durable helper/browser identity, and fixed installed
socket services. The Root-only 0700/0600 backend adapter exposes the disposable
Grafana backend at the revoker's installed fixed path; no backend test override
is supplied to the production worker.

The stock tool reads the real report and reconnects, the private scanner probes
valid direct account mutations/recovery, and cancellation and broker restart
must deny both copied sessions without another login. Source remains in trusted
setup/helper memory and ephemeral broker custody. The administrator principal
is delivered through custody; its fixed Root-only Unix connection is authority.
Only the two approved website cookies reach the workload browser. Copy tests
remain private Root pipe data, and no Source/session bytes are printed.

This command is a scenario definition. Consult the dated execution record for
its actual result. It does not establish useful actual AI-client tasks, GUI
provisioning, the full independent-clock/maximum-lifetime matrix or two hosts.


The managed guest profile uses Root0700 `/run/p05-managed-app` for disposable
application database/config/identity state. The application stays live while the
broker is killed and restarted; application/guest reboot remains untested. The
broker recovery journal stays on disk. Application startup logs are drained in a
trusted private Root pipe, with bounded transient partial-line memory and fixed
flags/counters only. Raw logs are withheld and transient buffers cleared on
close; this provides no forensic erasure guarantee. The selected managed
Node24.21.0 and26.10.0 complete lifecycle/component gates pass P05-PC12.
See [dated execution](../../docs/testing/evidence/p05-coordinator-2026-10-01.md).


## Actual stock-client readiness

Run the opt-in dummy-report probe from the repository root:

```sh
python3 tests/browser-handoff/stock-client-readiness.py
```

This makes real model calls using the installed CLI and existing host
authentication. It supplies only a dummy metadata report, permits the named MCP
read tool, emits fixed protocol/capability/tool-use metadata and byte counts, and
withholds raw client stdout/stderr. Temporary0700 configuration/trace files are
removed; authentication is not copied into a guest or test configuration.
Raw output lives transiently in trusted Python memory; bytes/strings have no
forensic erasure guarantee. Model/provider traffic contains the dummy report.

Claude uses print/restricted mode, explicit positional separation after its
variadic MCP config argument, strict server configuration and disabled session
persistence. Codex uses ephemeral read-only execution with user configuration
excluded while preserving host authentication. The current installed options
are checked against [Claude CLI documentation](https://code.claude.com/docs/en/cli-reference)
and [official Codex CLI documentation](https://learn.chatgpt.com/docs/developer-commands?surface=cli);
[Codex MCP configuration](https://learn.chatgpt.com/docs/extend/mcp?surface=cli)
describes the named stdio server and tool policy.

Both recorded CLIs execute the dummy tool once and answer12 artifacts. Claude
advertises modern `2026-07-28` per-request capabilities; Codex initializes with
`2025-06-18` despite declaring URL mode. The latter must fail the reviewed URL
revision gate. Four pure metadata cases cover explicit capability, revision,
modern envelopes and private-field nonreflection. The probe is preparation;
it does not execute a broker grant, authenticated report, human delivery,
URL elicitation or the actual P05-E01/M06/M07 acceptance workflow.

### Actual host AI application task profile

The opt-in `BLINDPASS_P05_AI_CLIENT=claude` or `codex` extends the managed
controller/node guest with an actual registered workload MCP process and the
actual pinned stock browser subprocess in that same systemd invocation. Set
`BLINDPASS_P05_FLEET_BROWSER=1`, `BLINDPASS_P05_BROWSER_APP=grafana-managed` and
the existing verified `P05_GRAFANA_HOME`, then run the existing
`private-helper-vm.sh` with the image/key/runner prerequisites above. Each client
runs in a fresh disposable VM; this profile does not establish concurrent
account reuse or the two-host backup workflow.

[The host runner](ai-client-task.py) uses existing host authentication in place.
Its one-off configuration selects only the six broker/browser tools. A fixed
SSH connector uses the disposable VM key; Source and website-session data are
never put in the host configuration. Root guest model and transcript sockets
are0600 under0700 directories; a real different-UID connection must fail.
The MCP peer and stock subprocess run as the registered non-root workload.
The stock configuration is Root-owned and readable by its group; home/output
directories are private to that workload. Its0700 temporary directory is inside
the permitted home and selected through `TMPDIR`; `UMask=0077`, Unix-only
addressing and a read-only system remain enforced. The pinned stock tool's
standard tool-list-change notification is consumed without expanding the
three advertised browser tools. Private diagnostics retain only fixed failure
categories, never upstream error text or private paths/values.

[The Root observer](ai-task-guest.mjs) requires actual broker request and status,
controller approval, signed node dispatch, local HPKE provisioning, exact
persisted helper/browser identities, two actual report snapshots, one stock
reconnect, a parsed final artifact count and cancellation. It privately copies
the website session and requires a401 response, exact cgroup/profile removal
and a confirmed controller closure. Private control replies never reach the
model channel. The prompt does not contain the expected artifact count.

Normal MCP and final stdout/stderr are scanned for generated Source/admin/session
canaries and private endpoint fragments. Final client output is limited to2MiB
in transient memory and passed only to the private Root scanner; evidence keeps
fixed results and byte counts. Temporary host profiles, keys and VM overlays are
removed. Workload-browser cookies remain intentionally copyable authority;
memory disposal and file removal do not establish forensic erasure.

Twenty-three pure tests cover framing, namespace fences, private demultiplexing,
cancellation, EOF, deadlines, selected stock schemas and observed task steps.
Eight Python cases require actual Claude/Codex final messages, bounded host
execution, bounded guest preparation and actual TOML environment overrides. These tests
do not establish a real authenticated task. This API operator/local HPKE profile
also leaves GUI provisioning, URL elicitation and ordered fallback, full lifetime
and two-host/native/inherited acceptance gates open. See the
[execution record](../../docs/testing/evidence/p05-coordinator-2026-10-01.md)
for actual runs and their limits.

## Fleet provisioning signature and crypto checks

Build `cargo build -p blindpass-core --example provisioning-hpke-probe --locked`,
then run:

```bash
node --test tests/browser-handoff/provisioning-hpke.test.mjs tests/browser-handoff/provisioning-offer-interoperability.test.mjs tests/browser-handoff/provisioning-offer-chromium.test.mjs
```

The combined 16 cases pass on Node24.21.0 and26.10.0. Eight exercise actual Rust
Ed25519 offers through WebCrypto and verified HPKE; one uses sandboxed Chromium
145.0.7632.6 through existing Playwright1.58.2. The browser case compiles the MIT
helper in memory and uses a disposable secure localhost origin with capture
and service workers disabled. Generated dummy Source remains in browser/native
child memory; the native child retains its private signing/recipient keys.
The fixed canary is absent from child output and browser console/page errors.
These are crypto components, not actual operator GUI, TLS enrollment, broker
minting, controller relay or one-use custody evidence. See the
[signed-offer record](../../docs/testing/evidence/p05-signed-offer-2026-10-02.md).
