import { defineConfig, devices } from "@playwright/test";

/**
 * See https://playwright.dev/docs/test-configuration.
 */
export default defineConfig({
  testDir: "./e2e",
  testIgnore: ["**/controller-browser.spec.ts"],
  globalSetup: "./e2e/global-setup.ts",
  /* Run tests in files in parallel */
  fullyParallel: false,
  /* Fail the build on CI if you accidentally left test.only in the source code. */
  forbidOnly: !!process.env.CI,
  /* Retry on CI only */
  retries: process.env.CI ? 2 : 1,
  /* Opt out of parallel tests on CI. */
  workers: 1,
  /* Global timeout for each test */
  timeout: 120 * 1000,
  expect: {
    timeout: 60 * 1000,
  },
  /* Reporter to use. See https://playwright.dev/docs/test-reporters */
  reporter: [["html", { open: "never" }]],
  /* Shared settings for all the projects below. See https://playwright.dev/docs/api/class-testoptions. */
  use: {
    /* Base URL to use in actions like `await page.goto('/')`. */
    baseURL: "http://127.0.0.1:5173",
    launchOptions: process.env.BLINDPASS_PLAYWRIGHT_EXECUTABLE_PATH
      ? { executablePath: process.env.BLINDPASS_PLAYWRIGHT_EXECUTABLE_PATH }
      : undefined,

    /* Collect trace when retrying the failed test. See https://playwright.dev/docs/trace-viewer */
    trace: "on-first-retry",
    
    /* Take screenshot on failure */
    screenshot: "only-on-failure",
    
    /* Viewport size */
    viewport: { width: 1920, height: 1080 },
  },

  /* Configure projects for major browsers */
  projects: [
    {
      name: "setup",
      testMatch: /preflight\.setup\.ts/,
    },
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
      dependencies: ["setup"],
    },
  ],

  /* Run your local dev server before starting the tests */
  webServer: [
    {
      command: "npx vite dev --host 127.0.0.1",
      url: "http://127.0.0.1:5173",
      timeout: 240000,
      reuseExistingServer: !process.env.CI,
      cwd: "./",
      env: {
        VITE_SPS_API_URL: "http://127.0.0.1:3100"
      }
    },
    {
      command: "npx vite dev --host 127.0.0.1",
      url: "http://127.0.0.1:5175",
      timeout: 240000,
      reuseExistingServer: !process.env.CI,
      cwd: "../browser-ui",
      env: {
        VITE_SPS_API_URL: "http://127.0.0.1:3100"
      }
    },
    {
      command: "npx tsx src/index.ts",
      url: "http://127.0.0.1:3100/healthz",
      reuseExistingServer: !process.env.CI,
      cwd: "../sps-server",
      timeout: 300000,
      env: {
        DATABASE_URL: process.env.DATABASE_URL || "postgresql://blindpass:localdev@127.0.0.1:5433/blindpass",
        REDIS_URL: "redis://127.0.0.1:6380",
        SPS_PG_INTEGRATION: "1",
        NODE_ENV: "test",
        SPS_ENABLE_TEST_SEED_ROUTES: "1",
        SPS_E2E_SEED_TOKEN: "blindpass-e2e-seed-token",
        SPS_USER_JWT_SECRET: "test-user-jwt-secret",
        SPS_AGENT_JWT_SECRET: "test-agent-jwt-secret",
        SPS_HMAC_SECRET: "test-hmac",
        SPS_HOSTED_MODE: "1",
        SPS_HOST: "127.0.0.1",
        STRIPE_SECRET_KEY: "sk_test_dummy",
        STRIPE_WEBHOOK_SECRET: "whsec_test",
        SPS_AUTH_REGISTRATION_LIMIT: "1000",
        SPS_AUTH_LOGIN_LIMIT: "1000",
        SPS_AGENT_TOKEN_RATE_LIMIT: "1000",
        SPS_MEMBER_LIMIT_FREE: "100",
        SPS_AGENT_LIMIT_FREE: "100",
        SPS_EXCHANGE_LIMIT_FREE: "100",
        SPS_X402_ENABLED: "1",
        SPS_X402_PRICE_USD_CENTS: "5",
        SPS_X402_FREE_EXCHANGE_MONTHLY_CAP: "10",
        SPS_X402_FACILITATOR_URL: "http://127.0.0.1:3101",
        SPS_X402_PAY_TO_ADDRESS: "0x0000000000000000000000000000000000000001",
        SPS_SECRET_REGISTRY_JSON: '[{"secretName": "stripe.api_key.prod", "classification": "finance"}]',
        SPS_EXCHANGE_POLICY_JSON: '[{"ruleId": "allow-test", "secretName": "stripe.api_key.prod", "mode": "allow"}]',
        SPS_CORS_ALLOWED_ORIGINS: "http://127.0.0.1:5173,http://127.0.0.1:5175",
        SPS_UI_BASE_URL: "http://127.0.0.1:5175",
        PORT: "3100"
      },
      stdout: "pipe",
      stderr: "pipe"
    }
  ],
});
