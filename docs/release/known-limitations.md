# Known limitations of the pilot release

**Skeleton, 2026-10-06.** Every statement below is taken from a recorded runbook or evidence file and
links to it. This page is not a support statement for any release, because none has been published and
no phase P00–P06 review row has been accepted. P07.6 replaces it with the limits of the actual
candidate; do not add a claim here without a source.

## Supported-host scope

- The broker's accepted scope is the exact tested profile: Ubuntu 24.04, systemd 255, no TPM
  ([release layout](../deploy/release-layout.md)). A build that links on Debian bookworm does not
  establish broker support there.
- The native controller candidate targets x86_64 Debian 12 and Ubuntu 24.04 with real systemd, Python 3,
  OpenSSL 3 and CA certificates; other architectures remain open ([native quickstart](../deploy/native-quickstart.md)).
- aarch64: an emulated arm64 controller image passed the Compose profile checks; no native arm64 hardware,
  VM or SBOM run exists ([record](../testing/evidence/p06-aarch64-emulated-2026-10-05.md)). The
  release workflow builds aarch64 archives, but they carry no support claim until those gates pass.
- Neither deployment candidate is advertised as supported until its common and package-specific
  scenarios pass; containerized controller tests do not show host-broker isolation.

## Operating limits recorded by P06

- **Downgrade is restore-only.** There is no schema downgrade; the rollback is to restore the automatic
  pre-upgrade backup ([upgrade](../deploy/upgrade.md)). A restored controller serves again only through the
  [protected recovery activation](../deploy/recovery-activation.md). The native installer has no way back to the
  previous **program** either: it refuses an older archive, so a native upgrade is a ratchet and a rollback restores
  state under the installed version only. Rehearsed on real guests 2026-10-06 and **not passed** because of that
  ([rollback](rollback.md)); the owner has not yet chosen between accepting it for the pilot and adding an installer path.
- **PostgreSQL controllers** need the pinned PostgreSQL toolkit that only the controller image carries; a
  host without it refuses an older PostgreSQL schema unchanged ([upgrade](../deploy/upgrade.md)).
- **Fail-closed authority (D12).** The owner fences on any unanswerable epoch check, so a PostgreSQL outage
  needs a fresh activation after the database returns ([open decisions](../testing/evidence/p06-open-decisions-2026-10-05.md)).
- **Recovering-lane denial of service (accepted pilot limit).** While a node key rotation is pending,
  anyone who can reach the recovering lane can bind a wrong key version and make that node's page fail
  verification; pages cannot be forged. Keep the recovering controller reachable only by the recovery
  operator and the nodes being reconciled, and do not rotate node keys during recovery
  ([recovery stage](../deploy/recovery-stage.md#recovering-lane-exposure-accepted-pilot-limit)).
- **Planned handoff** is exercised for SQLite controllers only; it was not run for the native package,
  native-to-Compose moves, PostgreSQL controllers, multiple nodes or DNS cutover, and it is not a rollback
  once the destination has activated ([handoff](../deploy/handoff.md)).
- **Node reconnect.** After a recovery activation a real node passed `status --nodes --require-online`
  1.6–5.7 s after start on one host; under load a native node reconnect took about 63 s against a 120 s bound,
  attributed (from the code and timings, not instrumented) to the node's 60 s back-off cap ([compose-node](../testing/evidence/p06-compose-node-2026-10-05.md),
  [loaded bounds](../testing/evidence/p06-loaded-bounds-2026-10-06.md)).

## Client and interface limits

- **Stock AI clients.** Claude Code completed the managed-application task against the packaged native
  controller; Codex could not run because its workspace was out of credits
  ([record](../testing/evidence/p06-stock-ai-client-2026-10-06.md)).
- **Approval app.** Provisioning links (P04-D4) are not implemented, so the app shows no provisioning
  control; a real Omarchy session lock/logout/restart and a remote TLS controller are not covered
  ([approval app README](../../desktop/approval-app/README.md)). It is Quickshell QML for x86_64 desktops
  that match the tested profile only.
- **MCP package.** `@blindpass/mcp-server` is the self-contained esbuild bundle of the OpenClaw/MCP
  entrypoint: no runtime dependencies and the executables `mcp-server` (what `npx @blindpass/mcp-server`
  runs), `blindpass-mcp-server` and `blindpass-resolver`. The workspace library behind it is the private,
  unpublished `@blindpass/mcp-server-lib` ([library README](../../packages/mcp-server/README.md)). Candidate
  verification installs the tarball offline into an empty directory outside the repository and runs the
  executables and `npx` ([verify script](../../scripts/release/verify-npm-candidate.mjs)); with no broker
  or store configured the only tool result reachable there is the fixed failure "Operation failed", so a
  clean install is not evidence of secret delivery. The earlier scope warning about frozen x402 payment code
  and its viem dependency in the bundle no longer applies: that payment code was removed on 2026-10-07 and
  is in git history before the removal commit. The bundle now has 10 bundled third-party packages, with a
  single `zod` (major 4); its remaining unchanged legacy client modules carry attribution in the package
  notices and no support claim.

## Endpoint configuration

- **No default SPS endpoint in the published bundle (finding F-3, decided by the owner 2026-10-07).** The
  `@blindpass/mcp-server` bundle (not yet published) and its manifest carry no built-in host: with no
  `SPS_BASE_URL` set, `request_secret`, `request_secret_exchange` and `fulfill_secret_exchange` answer
  `Error: SPS_BASE_URL is not set…` and send nothing, so an enrolled `BLINDPASS_API_KEY` is never posted to a
  public host by default ([test](../../scripts/tests/mcp-bundle-endpoint.test.mjs),
  [record](../testing/evidence/p07-endpoint-default-2026-10-07.md)). Limits: the unbundled legacy OpenClaw
  plugin (source and `openclaw.plugin.json`) still defaults to `https://sps.blindpass.dev` by decision, the
  legacy image workflow that built with a different host (`https://sps.atas.tech`) was removed on 2026-10-07,
  an `http://` or otherwise odd value is accepted as given, and no release endpoint has been chosen or
  probed (P07-E02). The Rust controller has no default at all (it requires `BLINDPASS_PUBLIC_URL`)
  ([finding F-3 and test gap G-8](../security/finding-disposition.md)).

## Deferred security items

The owner chose to ship the pilot candidate with these open. Each is recorded, with its test gap, in the
[finding disposition](../security/finding-disposition.md) and the
[operator authentication and headers design](../security/operator-auth-and-headers.md).

- **Temporary passwords do not expire.** A temporary password (bootstrap through the admin socket, or an
  administrator reset) stays valid until it is used. Expiry needs a timestamp column (schema 20) that
  touches upgrade, backup and the authority layouts, and the owner deferred it on 2026-10-06. There is no
  test for expiry because nothing is built ([finding N-05](../security/finding-disposition.md), [design](../security/operator-auth-and-headers.md)).
- **Test mode still starts on a hand-edited profile with `BLINDPASS_PROXY_REQUIRED=0`.** Every shipped
  native, image and Compose profile sets `BLINDPASS_PROXY_REQUIRED=1`, which refuses test mode, and
  `check-config` warns when it is on. A hand-edited profile with `BLINDPASS_PROXY_REQUIRED=0` and test
  mode starts without the ownership requirement, with the seed route mounted and loopback
  `X-Forwarded-For` trusted. Do not claim that test mode is impossible ([finding N-03](../security/finding-disposition.md), [design](../security/operator-auth-and-headers.md)).
- **The legacy SPS and `dashboard` images and their workflow were removed on 2026-10-07; the `ui` image stays
  excluded from release claims.** The owner excluded all three on 2026-10-06. P08 then removed
  `packages/sps-server`, `packages/dashboard` and `build-and-push-images.yml` (git history before the removal
  commit). The separately hosted input-page image source, `packages/browser-ui/Dockerfile`, remains and no
  workflow publishes it. The dashboard's `localStorage` refresh token and its `connect-src` that admitted bare
  `http: https: ws: wss:` went with it; the removal is not a fix of either, and the findings record them as removed
  with their original status ([findings F-8, F-9, N-06](../security/finding-disposition.md), [design](../security/operator-auth-and-headers.md)).
- **Lockout residual.** Five or more attacker addresses can lock an operator account for every source for
  15 min (the lockout period) until a password reset. One address locks only itself, and operators behind
  one shared address share a pair counter with an attacker behind it ([finding N-02](../security/finding-disposition.md), [design](../security/operator-auth-and-headers.md)).
- **The confirmation code has about 12.6 bits and is a correlation aid only.** It is one of 8 × 8 × 100 =
  6,400 combinations, returned as display metadata. No controller route accepts it as input or authority,
  but no test asserts that ([confirmation codes and gap G-2](../security/finding-disposition.md), [design](../security/operator-auth-and-headers.md)).

## Not yet evidenced

Hosted CI runs of the P02–P06 workflows, the clean-host quickstart installs (P07-E01), the rollback
rehearsal on Compose and on a genuine previous release (P07-E03: native rehearsed and not passed, see [rollback](rollback.md)), the exposure scan of archives and image layers (P07-I04), release endpoint probes
(P07-E02), landing analytics and CTA evidence (P07-I06, P07-E04) and every phase acceptance review are open.
See [required scenarios](required-scenarios.json) and the
[P07 plan](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/phases/07-security-and-release.md).
