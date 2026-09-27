import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: ".",
  testMatch: "controller-browser.spec.ts",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 60_000,
  reporter: "list",
  use: {
    ...devices["Desktop Chrome"],
    baseURL: "http://127.0.0.1:5175",
    launchOptions: process.env.BLINDPASS_PLAYWRIGHT_EXECUTABLE_PATH
      ? { executablePath: process.env.BLINDPASS_PLAYWRIGHT_EXECUTABLE_PATH }
      : undefined
  }
});
