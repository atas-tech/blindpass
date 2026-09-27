// Initial-route budget (P04 bounds): the gzipped JavaScript and CSS that the
// entry HTML loads before any lazy route must stay under 250 kB.
import { readFile } from "node:fs/promises";
import path from "node:path";
import { gzipSync } from "node:zlib";
import { fileURLToPath } from "node:url";

const dist = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../dist");
const BUDGET = 250 * 1024;
const html = await readFile(path.join(dist, "index.html"), "utf8");
const assets = [...html.matchAll(/(?:src|href)="\/(assets\/[^"]+\.(?:js|css))"/g)].map((match) => match[1]);
if (assets.length === 0) throw new Error("no entry assets found in dist/index.html");
let total = 0;
for (const asset of assets) {
  const size = gzipSync(await readFile(path.join(dist, asset))).length;
  total += size;
  console.log(`${asset}  ${(size / 1024).toFixed(1)} kB gzip`);
}
for (const forbidden of [/https?:\/\/(?!127\.0\.0\.1|localhost)[^"'\s]*(?:fonts\.googleapis|fonts\.gstatic|unpkg|jsdelivr|cdnjs)/]) {
  if (forbidden.test(html)) throw new Error("dist/index.html references a third-party CDN");
}
console.log(`initial route: ${(total / 1024).toFixed(1)} kB gzip (budget ${BUDGET / 1024} kB)`);
if (total > BUDGET) {
  console.error("initial route exceeds the 250 kB gzip budget");
  process.exit(1);
}
