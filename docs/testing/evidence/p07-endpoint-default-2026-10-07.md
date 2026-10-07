# P07 evidence: no default SPS endpoint in the published bundle (finding F-3)

**Date:** 2026-10-07
**Scope:** owner decision 2026-10-07: the published esbuild bundle (`@blindpass/mcp-server`) refuses to use an SPS endpoint until
`SPS_BASE_URL` is set, so an enrolled agent key is never sent to a built-in public host. The unbundled legacy OpenClaw plugin
keeps its current default.
**Status:** DONE in the working tree (uncommitted). Status words are literal: **Done** = the command ran in this working tree and the result is quoted;
**Not run** = no result exists. Nothing is committed or pushed.

## Design

The decision is one behavior: the published bundle must not choose an SPS host for the operator.

- `packages/openclaw-plugin/sps-bridge.mjs::resolveSpsBaseUrl` is the only place that picks the endpoint. It returns
  `__BLINDPASS_REQUIRE_EXPLICIT_SPS__ === true ? <trimmed SPS_BASE_URL, else throw SpsBaseUrlRequiredError> :
  (SPS_BASE_URL ?? "https://sps.blindpass.dev")`. The identifier is undeclared in the unbundled source, so the legacy
  OpenClaw plugin behaves exactly as before; `scripts/build_bundle.sh` passes
  `--define:__BLINDPASS_REQUIRE_EXPLICIT_SPS__=true` to the three esbuild calls, which folds the conditional and drops the
  literal from the artifact. The first attempt kept the default in a top-level constant behind an early `return`; esbuild
  left both in the output (the bundle test caught it), so the literal now sits inline in the folded branch.
- The three SPS handlers in `blindpass-core.mjs` resolve the endpoint **before** their `try` and before any key or token is
  touched, and answer `Error: SPS_BASE_URL is not set. This BlindPass build has no default endpoint, so nothing was sent…`.
  The text must start `Error:`: the OpenClaw MCP adapter flattens text starting `Failed` to the fixed `Operation failed`,
  and the SDK boundary turns an `isError` result into the same safe failure, so only a plain text result reaches the operator.
  The message names the setting, never a host and never a key.
- `getAgentAuthToken` posts `BLINDPASS_API_KEY` as `x-agent-api-key` to `${spsBaseUrl}/api/v2/agents/token`; with the
  endpoint refused first, the key has nowhere to go until the operator names one.
- The bundle manifest is written by `scripts/strip-sps-default.mjs` (shared by `build_bundle.sh` and the `publish_dist.sh`
  stage): `configSchema.properties.SPS_BASE_URL.default` is removed and the description no longer names the host. The source
  manifest keeps its default. `publish_dist.sh` also refuses a dist whose code or manifest still names the host, so a bundle
  built before this change cannot be staged by accident; `BLINDPASS_BUNDLE_OUT` lets it stage a bundle built elsewhere.
- The three client examples in `agents/` show `https://controller.example.com`.
- Not validated, as before: scheme and host (an `http://` value is accepted).

## Red first versus written after

Written before the implementation and run to confirm the failure:

- `packages/openclaw-plugin/tests/sps-base-url.test.mjs` (6 tests): red because `resolveSpsBaseUrl` and
  `SpsBaseUrlRequiredError` were not exported; green after the helper and call sites changed.
- `scripts/tests/mcp-bundle-endpoint.test.mjs` (4 tests at first; a fifth, the client examples, was added afterwards):
  3 of 4 red before the build change (host still in the bundle and manifest; tools reached for the default instead of
  refusing). After the define it was still red on `blindpass.mjs` (the dead constant survived), which led to the inline
  restructuring above; then green.
- Written after the fact: the client-example test and the `publish_dist.sh` staging checks in
  `scripts/tests/mcp-bundle-package.test.mjs` (staged package names no host; a dist seeded with the host is refused).

## Gates

Run in this working tree on 2026-10-07:

- `node --test scripts/tests/mcp-bundle-endpoint.test.mjs`: 5/5 pass (fresh `build_bundle.sh` into a scratch directory).
- `cd packages/openclaw-plugin && node --test tests/sps-base-url.test.mjs`: 6/6 pass; `node tests/index.test.mjs`: 62 ok, 0 not ok
  (legacy behavior unchanged, including the three client-example launch smokes).
- `node --test --test-isolation=none scripts/tests/mcp-bundle-package.test.mjs`: 21 pass, 1 skipped (the clean-install case
  needs `BLINDPASS_PACKAGE_INSTALL_TEST=1`); that case, run with the variable set against the rebuilt bundle, passed:
  the packed tarball installs outside the repository, the bins answer `initialize`, `tools/list` (6 tools) and `tools/call`.
- `scripts/tests/release_metadata.test.mjs`, `scripts/tests/audience_packaging.test.mjs`, `scripts/tests/release-docs.test.mjs`
  and `npm test --workspace=packages/mcp-server` (108/108): pass.
- `npm run build` exit 0 and `npm test` exit 0 (460 pass, 2 skipped, 0 fail in the node-test summaries; sps-server's 101
  vitest cases stay skipped without services). The three new files are wired into `npm test`
  (`packages/openclaw-plugin/package.json`, `scripts/tests/run-workspace-tests.mjs`).
- `git diff --check`: clean.

## Not run / what remains

- Not run: a live bundle against a real controller with an explicit `SPS_BASE_URL`; the bundle test uses a local HTTP stub
  that records the request. No release endpoint has been chosen, so no DNS/TLS probe exists (P07-E02).
- The legacy OpenClaw plugin source and its `openclaw.plugin.json` keep `https://sps.blindpass.dev`; the legacy image
  workflow still builds with `https://sps.atas.tech`. Both stay outside release claims.
- No URL validation was added: an `http://` or malformed `SPS_BASE_URL` is accepted as given, as before.
- `packages/openclaw-plugin/dist` is rebuilt (gitignored); a dist built before this change is now refused at staging.
- Nothing is committed or pushed.
