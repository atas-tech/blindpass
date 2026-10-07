# Official MCP server

This workspace package is `@blindpass/mcp-server-lib`: a private library that is **not published**. The
public npm package `@blindpass/mcp-server` is the self-contained esbuild bundle of the OpenClaw/MCP entrypoint
that wraps it (`packages/openclaw-plugin/dist`, staged by [`scripts/publish_dist.sh`](../../scripts/publish_dist.sh)
and released only by the approved [release workflow](../../docs/release/README.md)); it has `bin` entries and no
runtime dependencies.

This MIT package uses approved `@modelcontextprotocol/server@2.2.0` and Zod 4.6.5.
`createMcpServer({tools, brokerClient})` registers trusted callbacks with JSON input
schemas and, when supplied, the three broker operation tools below.
`runMcpServerStdio` uses the official newline transport and `serveStdio` era
selection: four older initialize revisions and the modern per-request envelope
have actual stdio contract evidence. One message may be up to 64 KiB (per line,
see the transport limits below). Thrown and returned tool
failures marked `isError` become a fixed error; transport errors are not logged
(an optional fixed-vocabulary diagnostics file is described below).
The legacy adapter also normalizes its existing caught-failure text before
returning it, keeping upstream links/codes out of normal tool content.
Every registered callback has a cancellable 30s response deadline. Linux fleet
calls use kernel uptime; the broker client's own bound is 27s and reserves five
seconds within it for independent withdrawal after an interrupted submission, so
the agent receives the explicit uncertain result well before the outer bound
could turn it into the fixed error. `createMcpServer` refuses a broker client
whose advertised bound is not at least one second shorter than the tool bound. A
bounded response does not prove an arbitrary legacy callback stopped its own I/O.

## Broker operation tools

The packaged wrapper enables these tools only with `BLINDPASS_FLEET_MCP=1`:

| Tool | Input | Output |
|---|---|---|
| `blindpass_request_operation` | `action: "browser.session"`, `resourceId`, stable opaque `requestKey`; optional purpose and TTL ≤120s | Original request event ID or explicit uncertainty/withdrawal metadata |
| `blindpass_operation_status` | `eventKey` | Exact safe state and opaque request/grant/operation IDs |
| `blindpass_cancel_operation` | Exactly one of `eventKey` or `requestKey` | Withdrawal requested, closed outcome or explicit uncertainty |

The administrator supplies `BLINDPASS_NODE_ID`, `BLINDPASS_WORKLOAD_ID` and
`BLINDPASS_WORKLOAD_UNIT`; the process inherits systemd `INVOCATION_ID`. These
values identify the claimed registration. Root independently checks the actual
kernel peer, unit, invocation and account. Tool JSON and `params.context` cannot
replace identity or select an origin, account, source, socket or browser option.
The Linux client uses only `/run/blindpass/workload.sock`, requiring Root-owned
safe directories and an unchanged Root 0660 single-link socket. Disabled fleet
mode retains the existing legacy registry. Invalid enabled configuration denies
startup without diagnostics.

Choose a 16–128 character `[A-Za-z0-9_-]` request key once and reuse it unchanged
for identical retries. Root retains original request/recipe binding across ACK
and restart. Reply loss, timeout, SDK cancellation or stdin EOF withdraws a
submitted request by that key; it does not submit a replacement. Ordinary calls
are bounded to twelve concurrently, with four reserved cancellation slots.
Replies require one bounded complete newline frame plus EOF. Unexpected or
secret-bearing replies become fixed errors or safe uncertainty metadata.

These tools consume no source plaintext and return no password, cookie, URL or
browser endpoint. Purpose is request metadata. Temporary reply buffers are
wiped; JavaScript strings have no forensic erasure guarantee. Request/grant/
cancellation status does not establish browser readiness, website invalidation
or verified runtime cleanup. New Root browser events carry `request_version: 2`:
the updated controller creates their workload-requested operation and named
approval automatically. Existing unversioned evidence retains the manual
contract; a human create call cannot claim a versioned intent. Updated broker
and controller are required together. Signed runtime coordination and
reconciliation remain required.

## OpenClaw entrypoint and legacy tools

The [OpenClaw wrapper](../openclaw-plugin/mcp-server.mjs) explicitly starts this
SDK transport. It adapts the existing MIT legacy tool callbacks and their JSON
schemas, preserving `request_secret`, `request_secret_exchange`,
`fulfill_secret_exchange`, `list_secrets`, `delete_secret` and
`confirm_delete_secret`. `store_secret` remains explicitly enabled only.
`createMcpOptions` supplies the trusted callback adapter; optional `toolContext`
comes from the embedding runtime, never a caller's JSON-RPC `params.context`.

The wrapper's `createMcpServer` now returns the SDK server, and
`runMcpServerStdio` accepts wrapper options. The old custom
`handleMcpRpcRequest` export and Content-Length transport are removed. Client
profiles use standard newline MCP. The library receives callbacks without
importing the plugin, helper or AGPL controller/broker, so this adapter does not
create a package cycle.

Trusted embeddings can use the wrapper's `createProtocolServer` and
`runProtocolStdio` exports to supply their own callbacks without registering the
legacy tools. It also re-exports the existing broker client and environment
identity reader. These are the same MIT protocol functions already in the
bundle; no application implementation or dependency is added. Actual older and
modern stdio regressions check both the legacy wrapper and the protocol-only
embedding, including strict schemas and fixed errors.

The build creates a standalone `dist/mcp-server.mjs`; staged npm and skill install
paths launch this actual bundle. CLI console notices are suppressed before tool
registration, keeping stdout protocol-only and upstream diagnostics out of
stderr. This is not a guarantee about arbitrary trusted callbacks writing
raw bytes directly to streams.

The build retains [upstream notices](THIRD_PARTY_NOTICES.md), complete emitted
package license texts and a version/hash inventory. A build check rejects AGPL
workspace implementation in the MIT bundle. The legacy MCP process decrypts temporary secret buffers and wipes them in
handler finally blocks. Named runtime-only copies have no automatic TTL: they
remain until explicit disposal, replacement or process exit. Managed values
persist in the encrypted local store. These are the existing client limits;
the browser operation tools use broker metadata.

## Checks and remaining work

Run `npm run test --workspace=@blindpass/mcp-server-lib` from the repository root.
One hundred and eight SDK/client cases pass (Node 26.10.0, 2026-10-02), including actual
older/modern stdio, cancellation/EOF/SIGTERM, bounded callbacks, transport
robustness, fleet legacy-surface and diagnostics cases and Unix reply/socket checks. Legacy handlers
and all three configured startup profiles have separate regression evidence.
The [disposable systemd VM](../../tests/browser-handoff/README.md#packaged-mcp-tools-against-the-production-broker)
also executes the packaged tools against the production broker, verifies signed
request/cancel events, retry after ACK/restart and same-UID wrong-unit denial.
Bundled license checks, staged npm startup and isolated installations are
additional gates. This VM portion provisions no source and runs no controller.

Node24.21.0 and26.10.0 pass local build/workspace and selected systemd
coordinator/stock-browser checks. Workspace engine declarations use
`^24.21.0 || ^26.10.0`, and CI is configured for both exact profiles; remote
CI execution remains unverified. Both actual Claude Code2.1.286 and Codex
CLI0.159.3 complete the selected Node26 managed Grafana application task with
real controller/node approval, local HPKE provisioning, reconnect and verified
closure; see [execution evidence](../../docs/testing/evidence/p05-coordinator-2026-10-01.md).
GUI provisioning, reviewed client URL delivery, ordered real fallback and the
full client/lifetime/two-host variants remain required by P05. Protocol/packaging evidence alone does not
complete M01 or establish full workflow support.


## Confirmed browser closure metadata

Broker status may return `closed` with `outcome: completed` after confirmed
protected browser cleanup. This is metadata, without a source credential or
browser endpoint. Actual older/modern stdio tests preserve its exact shape.
A cleanup completion event alone does not prove that an AI completed a useful
application task. The separately recorded actual stock tasks establish the
selected API operator profile; full stock-client acceptance remains open.

## Ready browser metadata

Broker status can also return `{status: "ready", eventKey, contextHandle}`.
The context handle must be exactly `ctx_` followed by 64 lowercase hex digits;
raw endpoints, extensions and private fields are rejected. Older/modern actual
stdio tests cover this shape. Stock browser configuration comes from the trusted
invocation setup, outside model results. This adds no URL elicitation or complete
Claude/Codex task acceptance. The ready-metadata slice had38 SDK/client cases;
the later delivery component brought that suite to 62; the 2026-10-02 review
hardening below brings it to 108.

## Ordered delivery component — 2026-10-02

`createDeliveryRouter` and `createUrlElicitationProvider` are exported by the
protocol package and the packaged OpenClaw entrypoint. The embedding supplies
trusted private input, reviewed human delivery callbacks, authenticated operator
and host context, and an atomic durable ledger. No delivery tool or production
provider is enabled by these exports. Providers run in this fixed order:
URL elicitation, OpenClaw, Telegram, explicit intended-host local-open,
authenticated operator app. Only a definite pre-delivery failure permits the
next provider. Decline/cancel, invalid reply, timeout or thrown error stops
routing; uncertain delivery requires reconciliation.

The ledger must durably reserve the operation before delivery and preserve exact
URL/operator/node/invocation/elicitation/deadline binding. Exact concurrent or
completed retries do not resend; changed binding denies. Failed persistence
stays uncertain. The ledger receives only an opaque operation key, SHA-256
binding fingerprint and fixed outcome, never the URL. The test ledger is in
memory and does not establish durable restart behavior. The embedding must bind
the trusted `deadlineMs` to the original request using Linux kernel uptime;
an expired deadline denies before reservation and cannot be extended by retry.
The entire delivery call is bounded to25s, inside the SDK30s callback budget.

URL mode requires actual SDK initialize state at exactly `2025-11-25`, an explicit
`elicitation.url` object and an exact reviewed client name/version. Empty,
form-only, older and unreviewed declarations fall through. The newer
`2026-07-28` SDK uses an input-required continuation rather than this push API;
its delivery implementation and client UI review remain open. Tool arguments or
`params.context` cannot replace initialize capabilities. Acceptance means
consent to navigate; approval/provisioning must be confirmed independently.
Protocol requirements are in the [MCP URL elicitation specification](https://modelcontextprotocol.io/specification/2025-11-25/client/elicitation).

Only trusted allow-listed HTTPS origins are accepted. URL/code strings are
consumed by the selected provider and URL-mode client transport, never returned
in safe results or audit records. They remain temporarily in JavaScript memory;
abort is cooperative and cannot prove an arbitrary callback stopped its I/O or
erased its copies. Browser-session raw-link/plaintext flags are refused.

Fourteen component cases and ten actual SDK stdio cases cover P05-DR01–DR07.
They include definite/uncertain delivery, retry/capacity/persistence failures,
host/operator fences, deadlines, forged context, decline/cancel/timeout,
capability/revision checks and normal-channel canary scans. These are transport
and component evidence. Reviewed stock-client UI/transcript privacy, durable
production ledger/reconciliation, real operator provisioning and provider
integration remain required. No external chat messages were sent.

## Review hardening — 2026-10-02

**Fleet mode drops the legacy exposure switches (P05-D8).** When a broker client
is present (`BLINDPASS_FLEET_MCP=1`), the packaged wrapper refuses to start with
`invalid_startup` (exit 64, nothing printed or echoed) if `OPENCLAW_SECRETS_RAW_LINK`
or `BLINDPASS_ALLOW_EXPOSE_PLAINTEXT` is set to anything other than empty,
`0`, `false`, `no` or `off`. The legacy tool schemas no longer list `raw_link`,
`channel_id`, `channel` or `target`, and the adapter answers any call that still
carries one of them (or `chat_id`) with the fixed `Operation failed` error before
the legacy handler runs. The SDK's strict-schema validation normally rejects such
calls first with an error that names the key, never the value. Non-fleet behaviour is
unchanged. Other legacy environment routing (`OPENCLAW_MESSAGE_CHANNEL`,
`OPENCLAW_MESSAGE_TARGET`) is not covered by this change.

**Diagnostics sink.** `createDiagnostics({directory})` (default: the first entry
of systemd `STATE_DIRECTORY`; a no-op when unset, relative or missing) appends one
line per event to `mcp-diagnostics.log` in that directory: a timestamp plus
`stage`, `status`, `reason` and optionally `provider`, each looked up in a closed
vocabulary (anything else is written as `unknown`). Errors are classified by
structure only; messages, causes, URLs, codes, cookies, endpoints, tool names and
arguments are never read into the file. The file is opened with `O_NOFOLLOW`,
must be a single-link regular file owned by the process, is forced to mode 0600,
and rotates to `.1` at 64 KiB (at most about 128 KiB on disk). It is wired as the
SDK `onerror` sink, for tool failures and SIGTERM, and as the delivery router's
default `audit`. Stdout stays protocol-only and stderr empty either way.

**Transport limits and behaviour.** The SDK's stdio buffer limit counts an unread
partial line plus a whole read chunk, so it also closed the connection for
back-to-back legal messages that were individually under 64 KiB (verified: four
40 KB messages in one write left three unanswered). `createStdioTransport`
re-frames input into whole lines and enforces 64 KiB per message (excluding the
newline). An over-limit line, terminated or not, gets one fixed JSON-RPC error
(`-32600`, id `null`, `Message too large`) and a clean close that aborts in-flight
calls through the same path as EOF, so a submitted broker request is withdrawn
before exit. JSON-RPC batch arrays and malformed lines are not executed, echoed or
answered (the SDK drops them silently); the connection stays usable. An initialize
for an unknown revision is answered with `2025-11-25`. The SDK 2.2.0 initialize
handler overwrites the negotiated version, client identity and capabilities on every
call, so a second initialize could swap what the URL gate reads; the transport
forwards only the first and answers later ones with a fixed `Already initialized`
error. SIGTERM closes the connection like EOF (broker withdrawal, then exit 0) and
a process that is still alive after eight seconds stops itself.

**Purpose text.** The broker `purpose` rejects every Unicode Cc control character
and the format/bidi characters U+00AD, U+061C, U+200B–U+200F, U+2028–U+2029,
U+202A–U+202E, U+2060–U+2064, U+2066–U+2069 and U+FEFF (the Rust broker applies the
identical rule), plus lone surrogates.

**Delivery router.** After a successful reservation every exit records a result:
a deadline, caller abort or failed completion now records `uncertain` explicitly
under a separate one-second `recordTimeoutMs` budget instead of leaving the record
pending. `uncertain` is final for the `operationKey`. A definite `unavailable` (no
provider supported, nothing sent) may be re-evaluated with the same key if the
ledger offers the optional compare-and-set `reopen(operationKey, fingerprint,
signal)`; without it the cached result is returned. `intendedHostId` is now a
required bound request field, so it cannot change between reservation and retry
(a routing-context `intendedHostId` that differs from it disables local-open).
If `reserve()` itself is interrupted the router cannot know whether the pending
record was committed; the ledger owner must expire stale pending records. The SDK
does not expose the version a client requested (it records only the negotiated
one, which falls back to the latest), so `createUrlElicitationProvider` accepts an
optional `requestedProtocolVersion()` and then also requires it to be exactly
`2025-11-25`; `createStdioTransport(...).requestedProtocolVersion` supplies it.
Without that function only the negotiated version is checked.

**zod.** zod 4.6.5 is installed three times (this package and the SDK's server and
core). The lockfile is deliberately not deduplicated here; `tests/zod-identity.test.mjs`
fails if any copy resolves to a different version than the pin.
