# P05 review hardening execution record — 2026-10-02

Scope: fixes for the P05 review findings in the MCP packages, private helper,
VM/browser harness, systemd unit comments, CI workflows and support matrix. This is
a host-test record. No disposable VM guest and no GitHub runner was used; the
checks that need them are listed under "Not verified".

Environment: Linux 7.2, Node v26.10.0 (engines `^24.21.0 || ^26.10.0`), Node 25.0.0
as a closer-to-24 compatibility check, Chromium headless shell 1208 (Playwright
1.58.2), OpenSSL 3.6.4. Node 24.21.0 was not available locally. No dependency or
lockfile change was made; the approved set is unchanged. All canaries are generated
dummy strings; none appears in any recorded output.

## Commands and results

| Command | Result |
|---|---|
| `npm run build` | exit 0 (the bundle guard and notices checks pass with the new MCP modules) |
| `npm test` | exit 0: 108 MCP, 146 helper/channel, 30 browser UI, 3 i18n; SPS 80 passed, 101 skipped |
| `node --test tests/*.test.mjs` in `packages/mcp-server` on Node 25.0.0 | 108 pass |
| Helper/harness unit files on Node 25.0.0 (transport, supervisor, isolated browser, private login, worker, certificate pins, scanner, shipped unit, leak check, pin browser test) | 72 pass |
| `node --test --test-isolation=none` on `private-login-browser`, `private-login-worker-browser` and `private-login-pins` test files (Chromium) | 10 pass (2 + 2 + 6) |

The MCP suite grew from 62 to 108 cases and the ordinary helper/channel group from
110 to 146. The Rust workspace was not run: other agents were editing the crates,
and a `cargo test -p blindpass-broker --locked` check of the shared tree showed
five `owner_retention` unit tests failing in that in-progress state. This work
changed no Rust file.

## Findings, tests and status

MCP (`packages/mcp-server`, `packages/openclaw-plugin/mcp-server.mjs`):

- **P05-D8 / M07 fleet exposure.** Fleet mode (a broker client is present) refuses to
  start with `invalid_startup` (exit 64, no output, no echo) when
  `OPENCLAW_SECRETS_RAW_LINK` or `BLINDPASS_ALLOW_EXPOSE_PLAINTEXT` is set to
  anything but empty/`0`/`false`/`no`/`off`; legacy schemas drop `raw_link`,
  `channel_id`, `channel`, `target` and the adapter rejects them (and `chat_id`) with
  the fixed `Operation failed` before the legacy handler runs. Tests: actual stdio
  startup in both modes, env refusal, schema listing, rejected arguments
  (`fleet-legacy-surface.test.mjs`, 7). Host-tested.
- **Diagnostics sink.** Fixed-vocabulary lines in `mcp-diagnostics.log` under
  `STATE_DIRECTORY`, mode 0600, `O_NOFOLLOW`, rotation at 64 KiB, no-op when unset;
  SDK `onerror` and the delivery router's default `audit`. A nested-canary upstream
  error, audit item, and an actual stdio failure never reach the file
  (`diagnostics.test.mjs`, 8). Host-tested.
- **Stdio robustness (M01).** Verified the SDK buffer bug: four legal 40 KB messages
  in one write left three unanswered. Fixed with a per-line bound (64 KiB) that also
  gives an over-limit line a fixed error and a clean close that withdraws in-flight
  work; a second `initialize` (the SDK 2.2.0 handler overwrote negotiated version,
  identity and capabilities) is refused; SIGTERM follows the EOF withdrawal path.
  Batches and malformed lines are dropped without echo (SDK behaviour, pinned by
  tests). Unknown initialize revisions negotiate to `2025-11-25`; unknown modern
  claims are refused (`stdio-protocol.test.mjs`, 10, actual newline stdio
  subprocesses). Host-tested.
- **Time bounds.** Broker client bound 27 s (was 29.9 s) under the 30 s outer bound;
  `createMcpServer` rejects a client bound within one second of the tool bound; a
  scaled stdio test shows the agent receives `uncertain`, not `Operation failed`.
  Host-tested at scaled timing; the real 27 s/30 s values are asserted as constants
  only.
- **Delivery router.** Timeout/abort/failed completion now record `uncertain` under a
  separate budget; definite `unavailable` can be re-evaluated through an optional
  `reopen` compare-and-set, `uncertain` never; `intendedHostId` is a bound request
  field; the client-requested protocol version can also be required through
  `createStdioTransport(...).requestedProtocolVersion` (the SDK does not expose it).
  Seven component cases and one stdio case added. Host-tested.
- **Purpose text.** All Cc controls and the listed format/bidi characters (plus lone
  surrogates) are refused, with per-category tests and neighbouring-character
  acceptance (`purpose.test.mjs`, 12). Host-tested. The Rust broker rule is another
  agent's change and is not covered here.
- **zod.** `zod-identity.test.mjs` fails if the package, SDK server and SDK core
  copies differ from the 4.6.5 pin. The lockfile was not changed.

Helper (`helpers/login`) and tests:

- **Worker budget, parser, SIGTERM.** One 55 s monotonic budget covers the control
  and job waits and the login; the job frame uses the duplicate-key-rejecting
  parser; SIGTERM aborts the login and the worker answers `uncertain` and exits within
  two seconds. The actual-worker SIGTERM test also passes against the old code,
  because the Playwright library closes its browser on SIGTERM; the new abort path is
  covered by a unit test (closing the browser rejects pending calls; a pre-aborted
  signal never launches). Host-tested.
- **Transport.** The outbound queue is sized from 32 channels times the largest data
  frame; a full queue makes senders wait in order and only a peer that is stalled for
  10 s fails the session; a read with more than 128 frames is decoded in batches.
  Red check: with the former fixed 256 KiB fail-on-exceed behaviour the new
  eight-channel test fails. Host-tested.
- **Isolated browser / supervisor.** Cleanup runs even when closing the context
  throws; frames in flight after `stop` are dropped so `stopped` stays `stopped`.
  Both new tests fail against the old code (mutation check). Host-tested.
- **SPKI pins.** Chromium's flag adds trust; the helper now also verifies, through CDP
  `Network.getCertificate`, leaf SPKI == a pin, hostname/IP and validity. Browser
  tests against the fixture TLS app: matching pin passes; non-matching pin, expired
  and wrong-host certificates with a matching pin fail with nothing typed. Mutation
  check: with the verification disabled the three negative tests fail. The isolated
  workload browser still passes the flag without a post-connection check (documented
  in `tests/browser-handoff/README.md`). Host-tested against the single-origin fixture.
  **Correction found by the first managed-Grafana VM run (2026-10-02):** as first
  written the helper checked both origins before typing, but CDP answers only for the
  origin of the document Chromium is showing, so the managed login (application origin
  redirects to a separate issuer origin) always returned `login_failed`. The fixture
  recipe forces one origin, which is why no fixture test could see it; the host test
  `private-login-grafana.test.mjs` (needs `P05_GRAFANA_HOME`) reproduced it. The helper
  now checks the login origin before anything is typed and the application origin
  after the login lands on it, before the session is published. The application
  origin is therefore not checked before the OAuth redirect first reaches it.

Harness (VM guests), units, CI and docs:

- **Positive controls (F1, F2, F4, F5).** Shared scanner
  `tests/browser-handoff/journal-canary-scan.mjs` (empty input, missing unit,
  injected canary, clean data: 15 host cases); guests wired to it; end-of-run leak
  check over `list-units --all` for the browser, manager, supervisor, revoker, helper
  and broker units (4 host cases against a stub `systemctl`); `--locked` added to the
  VM cargo build; the dead branch removed; outcome drain bound to driver arrival
  sequence plus marker (the Rust probe's outcome lines carry no connection id, so an
  exact id binding needs a Rust change). Scanner and leak-check logic host-tested;
  guest wiring statically checked only.
- **Shipped broker unit (F6).** Guests install and start `blindpass-broker.service`
  with `browser-runtime.conf` plus a generated drop-in (3 host cases).
  `systemd-analyze verify` passes on the broker unit and drop-ins and on the helper,
  supervisor, revoker, runtime-manager and browser units. Statically verified only;
  **not VM-verified**. `p05-enrollment-broker` remains ad hoc.
- **Units (I).** Comments and documentation only, with optional
  `IPAddressDeny=any`/`IPAddressAllow=` and `RestrictAddressFamilies` guidance in
  `deploy/examples/browser-runtime.conf`; destination restriction is enforced in code
  (`browser-network.mjs`). Existing VM-verified settings unchanged.
- **CI (J).** Workflows parse with PyYAML; `actionlint` is not installed. Not run on a
  runner. A P05 VM job was added to `fleet-vm.yml` (self-hosted KVM runner,
  dispatch-only).
- **Housekeeping and docs (K, L).** `.gitignore`, `LICENSES.md` P05 dependency
  summary, the bundle guard as an allowlist with tests, test counts in
  `docs/testing/README.md`, and the support matrix corrections.

## Not verified

- Node 24.21.0 for any change here; the CI matrix covers it once run.
- Every VM-only change: guest canary scans and their controls, the end-of-run leak
  check, the shipped broker unit sandbox, the sequence-bound drain, and the
  `reset-failed` acknowledgement in the helper deadline stage.
- All workflow changes on a runner (including Chromium installation and the
  `kernel.apparmor_restrict_unprivileged_userns` workaround on ubuntu-24.04).
- Rust suites (see above).
- Production durability of a delivery ledger (`reopen` is an optional contract; only
  an in-memory test ledger exists).
