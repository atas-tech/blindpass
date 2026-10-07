#!/usr/bin/env node

/**
 * Interactive E2E test against a running controller: opens the Browser UI
 * in your default browser, waits for a human to enter a secret,
 * then retrieves + decrypts it on the agent side.
 *
 * Usage (CC02 runs this against the Rust controller):
 *   SPS_E2E_BEARER_TOKEN=... node scripts/e2e-human.mjs --base-url http://127.0.0.1:3100
 */

import os from "node:os";
import { exec, spawn } from "node:child_process";
import { GatewaySpsClient } from "../packages/gateway/dist/sps-client.js";
import { RequestSecretInterceptor } from "../packages/gateway/dist/interceptor.js";
import { decrypt, destroyKeyPair, generateKeyPair } from "../packages/agent-skill/dist/key-manager.js";
import { SpsClient } from "../packages/agent-skill/dist/sps-client.js";

// ── Helpers ──

const BOLD = "\x1b[1m";
const GREEN = "\x1b[32m";
const CYAN = "\x1b[36m";
const YELLOW = "\x1b[33m";
const RED = "\x1b[31m";
const DIM = "\x1b[2m";
const RESET = "\x1b[0m";

function log(label, message) {
    const time = new Date().toLocaleTimeString();
    console.log(`${DIM}${time}${RESET} ${BOLD}[${label}]${RESET} ${message}`);
}

async function isServerRunning(url) {
    try {
        await fetch(url);
        return true;
    } catch {
        return false;
    }
}

function argumentValue(name) {
    const index = process.argv.indexOf(name);
    return index >= 0 ? process.argv[index + 1] : undefined;
}

function openBrowser(url) {
    const platform = os.platform();
    const cmd =
        platform === "darwin" ? "open" :
            platform === "win32" ? "start" :
                "xdg-open";

    exec(`${cmd} "${url}"`, (err) => {
        if (err) {
            log("BROWSER", `${YELLOW}Could not auto-open browser. Please open manually:${RESET}`);
            log("BROWSER", `${CYAN}${url}${RESET}`);
        }
    });
}

// ── Main ──

async function run() {
    console.log();
    console.log(`${BOLD}═══════════════════════════════════════════════════════${RESET}`);
    console.log(`${BOLD}  🔐 blindpass — Interactive E2E Test${RESET}`);
    console.log(`${BOLD}═══════════════════════════════════════════════════════${RESET}`);
    console.log();

    const requestedBaseUrl = argumentValue("--base-url") ?? process.env.SPS_E2E_BASE_URL;
    const externalBearerToken = process.env.SPS_E2E_BEARER_TOKEN?.trim();
    if (!requestedBaseUrl) {
        throw new Error("--base-url (or SPS_E2E_BASE_URL) is required: this test runs against a running controller");
    }
    if (!externalBearerToken) {
        throw new Error("--base-url requires SPS_E2E_BEARER_TOKEN for the running controller");
    }
    const baseUrl = requestedBaseUrl.replace(/\/$/, "");
    let uiProcess;

    log("SETUP", `Using controller at ${CYAN}${baseUrl}${RESET}`);

    // 1.5. Ensure Browser UI is running
    const uiBaseUrl = process.env.VITE_SPS_UI_URL ?? "http://localhost:5173";
    if (!(await isServerRunning(uiBaseUrl)) && uiBaseUrl.includes("localhost:5173")) {
        log("SETUP", `${YELLOW}Browser UI server not detected at ${uiBaseUrl}. Starting it...${RESET}`);
        
        // Don't ignore stdio completely, so we can capture errors if it fails to start
        uiProcess = spawn("npm", ["run", "dev", "--workspace=packages/browser-ui"], { stdio: "pipe" });
        uiProcess.stderr.on('data', (data) => console.error(`${DIM}[VITE ERR] ${data}${RESET}`));
        
        let started = false;
        for (let i = 0; i < 30; i++) {
            await new Promise((r) => setTimeout(r, 500));
            // Also try 127.0.0.1 if localhost fetch fails due to IPv6 Node bindings
            if (await isServerRunning(uiBaseUrl) || await isServerRunning("http://127.0.0.1:5173")) {
                log("SETUP", `${GREEN}Browser UI server started.${RESET}`);
                started = true;
                break;
            }
        }
        
        if (!started) {
            uiProcess.kill();
            throw new Error(`Browser UI failed to start at ${uiBaseUrl} after 15 seconds. Please check the logs above or run "npm run dev --workspace=packages/browser-ui" manually.`);
        }
    }

    // 2. Check the controller is reachable.
    if (!(await isServerRunning(`${baseUrl}/healthz`))) {
        throw new Error(`Controller is not reachable at ${baseUrl}/healthz`);
    }
    log("CONTROLLER", `Connected to ${CYAN}${baseUrl}${RESET}`);

    // 3. Generate agent HPKE keypair
    log("AGENT", "Generating HPKE keypair...");
    const keyPair = await generateKeyPair();

    try {
        // 4. Gateway creates secret request
        const gatewayToken = externalBearerToken;
        const gatewayClient = new GatewaySpsClient({
            baseUrl,
            gatewayBearerToken: gatewayToken,
        });

        const chatMessages = [];
        const chatAdapter = {
            async sendMessage(_channelId, message) {
                chatMessages.push(message);
            },
        };

        const interceptor = new RequestSecretInterceptor({
            spsClient: gatewayClient,
            chatAdapter,
        });

        log("GATEWAY", "Creating secret request...");
        const llmResponse = await interceptor.interceptToolCall("request_secret", {
            description: "E2E Test — please enter any secret value",
            public_key: keyPair.publicKey,
            channel_id: "terminal",
        });

        if (!llmResponse) {
            throw new Error("Interceptor did not handle request_secret tool call");
        }

        // 5. Extract URL from the chat message
        const chatMessage = chatMessages[0];
        const linkMatch = chatMessage?.match(/Open link:\s*(\S+)/);
        if (!linkMatch?.[1]) {
            throw new Error("Could not extract secret URL from chat message");
        }

        const secretUrlObject = new URL(linkMatch[1]);
        secretUrlObject.searchParams.set("api_url", baseUrl);
        const secretUrl = secretUrlObject.toString();

        // 6. Extract confirmation code
        const codeMatch = chatMessage.match(/Confirmation code:\s*(\S+)/);
        const confirmationCode = codeMatch?.[1] ?? "???";

        // 7. Present instructions to the human
        console.log();
        console.log(`${BOLD}───────────────────────────────────────────────────────${RESET}`);
        console.log(`${BOLD}  📋 Instructions for the human tester${RESET}`);
        console.log(`${BOLD}───────────────────────────────────────────────────────${RESET}`);
        console.log();
        if (process.env.SPS_E2E_SKIP_BROWSER === "1") {
            console.log(`  1. Browser launch is disabled for this automated run.`);
        } else {
            console.log(`  1. Your browser should open automatically.`);
        }
        console.log(`     If not, open this URL manually:`);
        console.log();
        console.log(`     ${CYAN}${secretUrl}${RESET}`);
        console.log();
        console.log(`  2. Verify the confirmation code matches:`);
        console.log();
        console.log(`     ${GREEN}${BOLD}${confirmationCode}${RESET}`);
        console.log();
        console.log(`  3. Enter any secret value and click "Encrypt and Submit".`);
        console.log();
        console.log(`  ⏳ You have ${YELLOW}3 minutes${RESET} before the request expires.`);
        console.log();
        console.log(`${BOLD}───────────────────────────────────────────────────────${RESET}`);
        console.log();

        // 8. Open the browser
        if (process.env.SPS_E2E_SKIP_BROWSER !== "1") {
            openBrowser(secretUrl);
        }

        // 9. Poll for submission (agent-side)
        const agentToken = externalBearerToken;
        const agentClient = new SpsClient({
            baseUrl,
            gatewayBearerToken: agentToken,
        });

        log("AGENT", "Polling for secret submission... (waiting for human)");

        const pollResult = await agentClient.pollStatus(
            llmResponse.request_id,
            1000,   // 1s initial interval
            180000, // 3 min pending timeout
            60000   // 1 min retrieve grace
        );

        log("AGENT", `${GREEN}Secret submitted!${RESET} Status: ${pollResult.status}`);

        // 10. Retrieve + decrypt
        log("AGENT", "Retrieving encrypted payload...");
        const payload = await agentClient.retrieveSecret(llmResponse.request_id);

        log("AGENT", "Decrypting with private key...");
        const plaintext = await decrypt(keyPair.privateKey, payload.enc, payload.ciphertext);
        const secretValue = plaintext.toString("utf8");

        console.log();
        console.log(`${BOLD}───────────────────────────────────────────────────────${RESET}`);
        console.log(`${BOLD}  ✅ E2E Test Complete!${RESET}`);
        console.log(`${BOLD}───────────────────────────────────────────────────────${RESET}`);
        console.log();
        console.log(`  Decrypted secret: ${GREEN}${BOLD}${secretValue}${RESET}`);
        console.log();
        console.log(`  ${DIM}Verify this matches what you entered in the browser.${RESET}`);
        console.log();

        // 11. Verify second retrieve fails (atomic single-use)
        log("VERIFY", "Attempting second retrieve (should fail — atomic single-use)...");
        try {
            await agentClient.retrieveSecret(llmResponse.request_id);
            log("VERIFY", `${RED}FAIL — second retrieve succeeded (should have been 410)${RESET}`);
            process.exitCode = 1;
        } catch {
            log("VERIFY", `${GREEN}PASS — second retrieve correctly returned 410 Gone${RESET}`);
        }

        console.log();
    } finally {
        destroyKeyPair(keyPair);
        if (uiProcess) {
            uiProcess.kill();
        }
        log("CLEANUP", "Browser UI helper stopped.");
    }
}

run().catch((err) => {
    console.error(`\n${RED}${BOLD}E2E test failed:${RESET}`, err.message ?? err);
    process.exit(1);
});
