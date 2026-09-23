import { expect, type Page, request as playwrightRequest } from "@playwright/test";

const E2E_SEED_TOKEN = process.env.SPS_E2E_SEED_TOKEN || "blindpass-e2e-seed-token";
const API_URL = process.env.VITE_SPS_API_URL || "http://127.0.0.1:3100";
const DASHBOARD_URL = "http://127.0.0.1:5173";
const BROWSER_UI_URL = "http://127.0.0.1:5175";

export interface WorkspaceFixture {
  adminEmail: string;
  password: string;
  workspaceId: string;
  workspaceSlug: string;
  userId: string;
  accessToken: string;
  refreshToken: string;
  agents: Record<string, string>;
}

/**
 * Seeds a new workspace and user via the SPS E2E seed API and injects the session
 * into the browser context for BOTH the dashboard and browser-ui origins.
 */
export async function setupWorkspace(
  page: Page, 
  prefix = "default", 
  role = "workspace_admin", 
  agents: string[] = [],
  targetPath = "/",
  initialUsage = 0
): Promise<WorkspaceFixture> {
  const workerIndex = process.env.TEST_WORKER_INDEX ?? "0";
  const workerPrefix = `${prefix}-w${workerIndex}`;

  const api = await playwrightRequest.newContext();
  let data: any;
  try {
    let response: any;
    let attempts = 3;
    while (attempts > 0) {
      try {
        response = await api.post(`${API_URL}/api/v2/auth/test/seed-workspace`, {
          headers: {
            "x-blindpass-e2e-seed-token": E2E_SEED_TOKEN
          },
          data: { prefix: workerPrefix, role, agents, initial_usage: initialUsage }
        });

        if (response.status() === 201) {
          break;
        }
        
        if (response.status() === 503 && attempts > 1) {
          console.warn(`[E2E setup] Seed API returned 503, retrying in 2s... (${attempts - 1} left)`);
          await new Promise(resolve => setTimeout(resolve, 2000));
          attempts--;
          continue;
        }

        const body = await response.text();
        throw new Error(`Seed API failed with status ${response.status()}: ${body}`);
      } catch (err) {
        if (attempts > 1) {
          console.warn(`[E2E setup] Seed API connection failed, retrying in 2s... (${attempts - 1} left). Error: ${err instanceof Error ? err.message : err}`);
          await new Promise(resolve => setTimeout(resolve, 2000));
          attempts--;
          continue;
        }
        throw err;
      }
    }
    
    data = await response.json();
    console.log(`[setupWorkspace] Successfully seeded workspace ${workerPrefix} for ${data.email}`);
  } finally {
    await api.dispose();
  }

  const uuidRegex = /^[0-9a-f-]{36}$/;
  expect(data.workspace_id, "Seed route returned invalid workspace_id").toMatch(uuidRegex);
  expect(data.user_id, "Seed route returned invalid user_id").toMatch(uuidRegex);

  if (process.env.E2E_DEBUG) {
    page.on("console", msg => {
      console.log(`[Browser console event] type=${msg.type()}`);
    });
  }

  // 1. Prime the Browser-UI origin (Port 5175)
  await page.goto(`${BROWSER_UI_URL}/test-prime`, { waitUntil: "commit" }).catch(() => {}); // /test-prime might 404 but origin is set
  await page.evaluate(({ refreshToken }) => {
    // localStorage.clear(); // Removed to avoid clearing locale or other state
    localStorage.setItem("blindpass_refresh_token", refreshToken);
  }, { refreshToken: data.refresh_token });

  // 2. Prime the Dashboard origin (Port 5173) and navigate to the target
  const fullTargetPath = targetPath.startsWith("http") ? targetPath : `${DASHBOARD_URL}${targetPath}`;
  await page.goto(fullTargetPath, { waitUntil: "commit" });

  await page.evaluate(({ refreshToken }) => {
    localStorage.setItem("blindpass_refresh_token", refreshToken);
  }, { refreshToken: data.refresh_token });

  // Final navigation to ensure context is fully aware of the token
  await page.goto(fullTargetPath, { waitUntil: "commit" });
  
  // Wait for appropriate hydration based on the target path
  if (fullTargetPath.includes(DASHBOARD_URL)) {
    try {
      await expect(page.getByTestId("nav-sidebar")).toBeVisible({ timeout: 20000 });
      console.log(`[setupWorkspace] Session hydrated successfully for ${data.email} at ${fullTargetPath}`);
      // Add a small stable delay for heavy data-driven pages (Billing, Policy) to settle React render cycles
      await page.waitForTimeout(500);
    } catch (err) {
      const url = page.url();
      console.error(`[setupWorkspace] Hydration failed at ${url}. Sidebar not found.`);
      throw err;
    }
  }

  return {
    adminEmail: data.email,
    password: data.password,
    workspaceId: data.workspace_id,
    workspaceSlug: data.workspace_slug,
    userId: data.user_id,
    accessToken: data.access_token,
    refreshToken: data.refresh_token,
    agents: data.agents || {}
  };
}
