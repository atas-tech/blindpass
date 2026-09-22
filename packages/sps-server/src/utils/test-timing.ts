const TEST_ONLY_TIMING_ENV_NAMES = [
  "SPS_TEST_REQUEST_TTL_SECONDS",
  "SPS_TEST_SUBMITTED_TTL_SECONDS",
  "SPS_TEST_REVOKED_TTL_SECONDS",
  "SPS_TEST_APPROVAL_TTL_SECONDS",
  "SPS_TEST_RATE_LIMIT_WINDOW_MS",
  "SPS_TEST_LONG_RATE_LIMIT_WINDOW_MS",
  "SPS_TEST_AGENT_TOKEN_RATE_WINDOW_MS",
  "SPS_TEST_WORKSPACE_BURST_WINDOW_MS",
  "SPS_TEST_WORKSPACE_THROTTLE_WINDOW_MS",
  "SPS_TEST_REFRESH_TOKEN_TTL_SECONDS",
  "SPS_TEST_ACCESS_TOKEN_TTL_SECONDS"
] as const;

type TestOnlyTimingEnvName = (typeof TEST_ONLY_TIMING_ENV_NAMES)[number];

function isTestEnvironment(): boolean {
  return process.env.NODE_ENV === "test";
}

function parsePositiveInteger(name: TestOnlyTimingEnvName, fallback: number): number {
  const raw = process.env[name]?.trim();
  if (!raw) {
    return fallback;
  }

  const parsed = Number(raw);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new Error(`${name} must be a positive integer`);
  }

  return parsed;
}

export function assertTestOnlyTimingOverridesSafe(): void {
  const configured = TEST_ONLY_TIMING_ENV_NAMES.filter((name) => process.env[name]?.trim());
  if (configured.length > 0 && !isTestEnvironment()) {
    throw new Error(`Test-only timing overrides are disabled outside NODE_ENV=test: ${configured.join(", ")}`);
  }
}

export function testTimingOverride(name: TestOnlyTimingEnvName, fallback: number): number {
  if (!isTestEnvironment()) {
    return fallback;
  }

  return parsePositiveInteger(name, fallback);
}

export function requestTtlSeconds(): number {
  return testTimingOverride("SPS_TEST_REQUEST_TTL_SECONDS", 180);
}

export function submittedTtlSeconds(): number {
  return testTimingOverride("SPS_TEST_SUBMITTED_TTL_SECONDS", 60);
}

export function revokedTtlSeconds(): number {
  return testTimingOverride("SPS_TEST_REVOKED_TTL_SECONDS", 300);
}

export function approvalTtlSeconds(): number {
  return testTimingOverride("SPS_TEST_APPROVAL_TTL_SECONDS", 600);
}

export function rateLimitWindowMs(): number {
  return testTimingOverride("SPS_TEST_RATE_LIMIT_WINDOW_MS", 60_000);
}

export function agentTokenRateLimitWindowMs(): number {
  return testTimingOverride("SPS_TEST_AGENT_TOKEN_RATE_WINDOW_MS", rateLimitWindowMs());
}

export function longRateLimitWindowMs(): number {
  return testTimingOverride("SPS_TEST_LONG_RATE_LIMIT_WINDOW_MS", 15 * 60 * 1000);
}

export function workspaceBurstWindowMs(): number {
  return testTimingOverride("SPS_TEST_WORKSPACE_BURST_WINDOW_MS", 60 * 60 * 1000);
}

export function workspaceThrottleWindowMs(): number {
  return testTimingOverride("SPS_TEST_WORKSPACE_THROTTLE_WINDOW_MS", 60 * 1000);
}

export function refreshTokenTtlSeconds(): number {
  return testTimingOverride("SPS_TEST_REFRESH_TOKEN_TTL_SECONDS", 7 * 24 * 60 * 60);
}

export function accessTokenTtlSeconds(): number {
  return testTimingOverride("SPS_TEST_ACCESS_TOKEN_TTL_SECONDS", 15 * 60);
}
