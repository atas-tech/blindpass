import { defineConfig, devices } from "@playwright/test";

// Each spec file starts its own isolated controller and console preview
// (e2e/support/stack.ts), so specs run serially in one worker.
export default defineConfig({
  testDir: "e2e",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 60_000,
  expect: { timeout: 10_000 },
  reporter: process.env.CI ? [["list"], ["json", { outputFile: "test-results/results.json" }]] : "list",
  outputDir: "test-results/artifacts",
  use: {
    ...devices["Desktop Chrome"],
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    launchOptions: process.env.BLINDPASS_PLAYWRIGHT_EXECUTABLE_PATH ? { executablePath: process.env.BLINDPASS_PLAYWRIGHT_EXECUTABLE_PATH } : undefined
  }
});
