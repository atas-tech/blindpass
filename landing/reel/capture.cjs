"use strict";

// Captures the landing page the reel animates, at 2x, plus the element geometry reel.html hard-codes.
// The "In motion" section is removed first: the reel's geometry predates it, and the reel must not contain itself.
const { chromium } = require("@playwright/test");
const fs = require("node:fs");
const path = require("node:path");
const { pathToFileURL } = require("node:url");

const BUILD = path.join(__dirname, "build");

(async () => {
  fs.mkdirSync(BUILD, { recursive: true });
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2 });
  await page.route(/googletagmanager/, (route) => route.abort());
  await page.goto(pathToFileURL(path.join(__dirname, "../dist/index.html")).href);
  await page.evaluate(() => document.querySelector("#reel")?.remove());
  await page.waitForTimeout(1000);
  const geometry = await page.evaluate(() => {
    const rect = (el) => {
      const b = el.getBoundingClientRect();
      return [b.x, b.y + scrollY, b.width, b.height].map((v) => Math.round(v * 10) / 10);
    };
    const all = (selector) => [...document.querySelectorAll(selector)].map(rect);
    return {
      height: document.documentElement.scrollHeight,
      outerOrbit: all(".outer-orbit"), agentA: all(".agent-node"), agentB: all(".resource-node"), broker: all(".broker-node"),
      principles: all(".principles"), intro: all(".approach .section-intro"), rows: all(".principle-row"),
      wfHead: all(".workflow-section .section-heading"), picker: all(".flow-picker"), shell: all(".workflow-shell"),
      roadHead: all(".roadmap .section-heading"), cards: all(".roadmap-grid article"), closingTitle: all("#closing-title")
    };
  });
  fs.writeFileSync(path.join(BUILD, "geom.json"), JSON.stringify(geometry, null, 1));
  await page.screenshot({ path: path.join(BUILD, "page2x.jpg"), fullPage: true, type: "jpeg", quality: 92 });
  await browser.close();
  console.log(`captured page ${geometry.height}px tall`);
})().catch((error) => { console.error(error); process.exit(1); });
