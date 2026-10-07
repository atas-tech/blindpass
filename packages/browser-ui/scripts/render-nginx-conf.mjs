#!/usr/bin/env node
// Render the legacy input image's nginx config for one API origin (P07-D6).
//   render-nginx-conf.mjs <template> <origin|""> <output> [--allow-loopback]
// An empty origin means same-origin only. Anything but a bare https origin is
// refused; loopback is accepted only for a development image.
import { readFileSync, writeFileSync } from "node:fs";

const args = process.argv.slice(2);
const allowLoopback = args.includes("--allow-loopback");
const [templatePath, rawOrigin, outputPath] = args.filter((arg) => arg !== "--allow-loopback");
if (!templatePath || rawOrigin === undefined || !outputPath) {
  console.error("usage: render-nginx-conf.mjs <template> <origin|\"\"> <output> [--allow-loopback]");
  process.exit(2);
}

function refuse(reason) {
  // Never echo the value: an origin can carry userinfo.
  console.error(`render-nginx-conf: ${reason}`);
  process.exit(1);
}

function connectSource(raw) {
  const text = raw.trim();
  if (text === "") return "'self'";
  let url;
  try {
    url = new URL(text);
  } catch {
    return refuse("the API origin is not a URL");
  }
  if (url.username || url.password) return refuse("the API origin carries credentials");
  if (url.pathname !== "/" || url.search || url.hash) return refuse("the API origin must be a bare origin");
  if (text.replace(/\/$/, "") !== url.origin) return refuse("the API origin is not in canonical form");
  const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname) || url.hostname.endsWith(".localhost");
  if (loopback && !allowLoopback) return refuse("a loopback API origin is refused outside a development image");
  if (url.protocol !== "https:" && !(loopback && url.protocol === "http:")) return refuse("the API origin must use https");
  if (/[*;\s"']/.test(url.origin)) return refuse("the API origin has characters a CSP source cannot carry");
  return `'self' ${url.origin}`;
}

const template = readFileSync(templatePath, "utf8");
if (!template.includes("__CONNECT_SRC__")) refuse("the template has no __CONNECT_SRC__ placeholder");
writeFileSync(outputPath, template.replaceAll("__CONNECT_SRC__", connectSource(rawOrigin)));
