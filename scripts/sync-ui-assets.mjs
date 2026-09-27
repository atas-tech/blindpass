// Copy the shared UI assets into the static landing site, which has no build
// step. `--check` exits non-zero when the copies differ from assets/ui.
import { copyFile, mkdir, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const source = path.join(repoRoot, "assets/ui");
const target = path.join(repoRoot, "landing/dist/assets/ui");
export const SYNCED_FILES = ["tokens.css", "fonts.css", "fonts/InterVariable.woff2", "fonts/OFL.txt"];

async function same(file) {
  try {
    const [a, b] = await Promise.all([readFile(path.join(source, file)), readFile(path.join(target, file))]);
    return a.equals(b);
  } catch {
    return false;
  }
}

const check = process.argv.includes("--check");
const stale = [];
for (const file of SYNCED_FILES) {
  if (await same(file)) continue;
  if (check) {
    stale.push(file);
    continue;
  }
  await mkdir(path.dirname(path.join(target, file)), { recursive: true });
  await copyFile(path.join(source, file), path.join(target, file));
  console.log(`synced ${file}`);
}
if (stale.length) {
  console.error(`landing/dist/assets/ui is out of date: ${stale.join(", ")}. Run node scripts/sync-ui-assets.mjs`);
  process.exit(1);
}
