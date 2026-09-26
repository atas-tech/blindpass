"use strict";

// Renders reel.html to PNG frames at 120 fps. Resumable: existing frames are skipped, so a crash or
// hang costs one relaunch. The browser is recycled every 400 frames; long sessions stalled otherwise.
// FRAMES="636 1000" renders only those frame numbers (for spot checks).
const { chromium } = require("@playwright/test");
const fs = require("node:fs");
const path = require("node:path");
const { pathToFileURL } = require("node:url");

const FPS = 120;
const TOTAL = 15 * FPS;
const RECYCLE = 400;
const DIR = process.env.FRAMES_DIR || path.join(__dirname, "build", "frames");
const name = (i) => path.join(DIR, `f_${String(i).padStart(4, "0")}.png`);
const within = (promise, ms, what) => Promise.race([promise, new Promise((_, reject) => setTimeout(() => reject(new Error(`timeout: ${what}`)), ms))]);

(async () => {
  fs.mkdirSync(DIR, { recursive: true });
  const wanted = process.env.FRAMES ? process.env.FRAMES.split(/\s+/).map(Number) : [...Array(TOTAL).keys()];
  const todo = wanted.filter((i) => !fs.existsSync(name(i)));
  if (!todo.length) { console.log("all frames present"); process.exit(0); }
  console.log(`rendering from frame ${todo[0]}, ${todo.length} left`);
  const browser = await chromium.launch({ args: ["--disable-dev-shm-usage"] });
  const page = await browser.newPage({ viewport: { width: 1920, height: 1080 } });
  page.on("crash", () => { console.error("renderer crashed"); process.exit(2); });
  page.on("pageerror", (error) => { console.error(error.message); process.exit(1); });
  await page.goto(`${pathToFileURL(path.join(__dirname, "reel.html")).href}?render`);
  await within(page.evaluate(() => window.ready), 30000, "page ready");
  const cdp = await page.context().newCDPSession(page);
  let done = 0;
  for (const i of todo) {
    await within(page.evaluate((t) => render(t), i / FPS), 15000, `render ${i}`);
    const { data } = await within(cdp.send("Page.captureScreenshot", { format: "png" }), 15000, `capture ${i}`);
    fs.writeFileSync(`${name(i)}.tmp`, Buffer.from(data, "base64"));
    fs.renameSync(`${name(i)}.tmp`, name(i));
    if (++done % 100 === 0) console.log(`frame ${i}`);
    if (done >= RECYCLE && done < todo.length) { await browser.close(); console.log("recycling browser"); process.exit(3); }
  }
  await browser.close();
  console.log("all frames present");
  process.exit(0);
})().catch((error) => { console.error(error.message); process.exit(1); });
