# Dummy-data demos

These helpers exercise the existing encrypted payload/exchange implementation. They do not prove model blindness, host attestation or the proposed browser session-handoff operation. Use an isolated development database and dummy credentials: helpers can write database state, rotate demo agent keys and print values/links.

## A2A fixture

Follow the [quick start](../guides/quickstart.md) for infrastructure, build and app startup. Before creating the demo workspace, configure a registry/policy fixture for both demo names in the SPS environment:

```bash
export SPS_X402_ENABLED=0
export SPS_SECRET_REGISTRY_JSON='[{"secretName":"stripe.api_key.prod","classification":"finance"},{"secretName":"restricted.secret","classification":"sensitive"}]'
export SPS_EXCHANGE_POLICY_JSON='[{"ruleId":"demo-auto","secretName":"stripe.api_key.prod","mode":"allow"},{"ruleId":"demo-manual","secretName":"restricted.secret","mode":"pending_approval"}]'
```

The first name is a script fixture name; do not supply an actual production Stripe key. Export these before starting SPS. In hosted mode they seed new workspace policy; if `demo-space` already exists, use its dashboard Policy page to update the two arrays instead of expecting changed env values to overwrite it.

From a shell with the same database/API configuration:

```bash
node scripts/demo-a2a.mjs auto
```

The script creates/reuses `demo@example.com` and `demo-space`, directly marks records verified/active, enrolls or rotates `agent-a`/`agent-b`, submits a built-in dummy value and completes an exchange. It prints demo login credentials, a secret URL and the final value. This is a functional test helper, not normal onboarding or a leakage acceptance test.

## Manual approval

```bash
node scripts/demo-a2a.mjs manual
```

The script still automates the dummy credential submission. The manual action is approval of the exchange for `restricted.secret`. Log into the local dashboard using the printed dummy account, open **Approvals** at `/approvals`, and approve the pending request. The script's older `/inbox` prompt is stale; use the current dashboard route. If no request appears, inspect the actual workspace policy and script response rather than assuming the env seed applied.

Use the same frontend origin as the rest of your development setup. The helper prints `localhost` URLs; the standard guide uses `127.0.0.1`, whose cookies/storage are separate.

## Legacy helper limitations

- `npm run e2e:human` starts an ephemeral-port SPS instance and appends an `api_url` query parameter. The browser intentionally ignores that parameter and uses its configured API origin. The helper also defaults to browser port 5173 while the input-page Vite config uses 5175. It needs a coordinated origin/port fix before it can be advertised as an executable human-input quickstart. Do not re-enable query-controlled API routing to make it pass.
- `scripts/dev-setup.mjs` is an older interactive startup helper that may launch services. Use the explicit [test setup](README.md) commands for predictable infrastructure/configuration.
- `scripts/db-reset.mjs` drops/recreates database state. It is not a routine prerequisite and must only target a deliberately disposable database.
- Tier-change and x402 demos exercise retained commercial code. They are outside the active pilot and must not imply current pricing or payment readiness. Consult [historical test plans](../archive/README.md) only when maintaining those paths under a concrete task.

The [dashboard E2E suite](README.md#test-matrix) is the maintained automated browser-test entry point for existing app behavior. New host/browser guarantees require the separate [fleet pilot plan](Linux%20Fleet%20Pilot.md).
