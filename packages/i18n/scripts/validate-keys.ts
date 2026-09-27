import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { analyzeTranslationDrift, collectKeys, type JsonObj } from "./validation-lib.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const LOCALES_DIR = path.join(__dirname, "..", "locales");
const IDENTICAL_KEY_ALLOWLIST: Record<string, string[]> = {
  "browser-ui": ["brand.name"],
  console: ["locale.en", "locale.vi", "system.notFound.eyebrow"],
  layout: ["brand.name"],
  offers: ["intentDetail.txHash"],
  policy: ["rules.requesterIdsPlaceholder", "rules.purposesPlaceholder", "rules.requesterRingsPlaceholder"]
};

async function listNamespaces(locale: string): Promise<string[]> {
  const dir = path.join(LOCALES_DIR, locale);
  const entries = await readdir(dir, { withFileTypes: true });
  return entries
    .filter((e) => e.isFile() && e.name.endsWith(".json"))
    .map((e) => e.name.replace(".json", ""))
    .sort();
}

async function loadNamespace(locale: string, ns: string): Promise<JsonObj> {
  const filePath = path.join(LOCALES_DIR, locale, `${ns}.json`);
  const content = await readFile(filePath, "utf8");
  return JSON.parse(content) as JsonObj;
}

async function main(): Promise<void> {
  const localeDirs = await readdir(LOCALES_DIR, { withFileTypes: true });
  const locales = localeDirs
    .filter((e) => e.isDirectory())
    .map((e) => e.name)
    .sort();

  if (locales.length < 2) {
    console.log("✓ Only one locale found, nothing to compare.");
    return;
  }

  console.log(`Validating locales: ${locales.join(", ")}\n`);

  const referenceLocale = "en";
  const referenceNs = await listNamespaces(referenceLocale);
  let hasErrors = false;

  for (const locale of locales) {
    if (locale === referenceLocale) continue;

    console.log(`\n--- Comparing ${referenceLocale} → ${locale} ---`);

    const targetNs = await listNamespaces(locale);
    const missingNs = referenceNs.filter((ns) => !targetNs.includes(ns));
    const extraNs = targetNs.filter((ns) => !referenceNs.includes(ns));

    if (missingNs.length > 0) {
      console.error(`✗ Missing namespace files in ${locale}/: ${missingNs.join(", ")}`);
      hasErrors = true;
    }

    if (extraNs.length > 0) {
      console.warn(`⚠ Extra namespace files in ${locale}/: ${extraNs.join(", ")}`);
    }

    const commonNs = referenceNs.filter((ns) => targetNs.includes(ns));

    for (const ns of commonNs) {
      const refObj = await loadNamespace(referenceLocale, ns);
      const targetObj = await loadNamespace(locale, ns);

      const refKeys = collectKeys(refObj);
      const targetKeys = collectKeys(targetObj);

      const missing = refKeys.filter((k) => !targetKeys.includes(k));
      const extra = targetKeys.filter((k) => !refKeys.includes(k));

      if (missing.length > 0) {
        console.error(`✗ ${locale}/${ns}.json missing keys:\n  ${missing.join("\n  ")}`);
        hasErrors = true;
      }

      if (extra.length > 0) {
        console.warn(`⚠ ${locale}/${ns}.json has extra keys:\n  ${extra.join("\n  ")}`);
      }

      if (missing.length === 0 && extra.length === 0) {
        const drift = analyzeTranslationDrift(refObj, targetObj, {
          ignoredKeys: new Set(IDENTICAL_KEY_ALLOWLIST[ns] ?? [])
        });
        if (drift.suspicious) {
          const sampleKeys = drift.identicalKeys.slice(0, 8).join(", ");
          console.error(
            `✗ ${locale}/${ns}.json appears untranslated: ` +
              `${drift.identicalKeys.length}/${drift.comparableStrings} comparable strings still match ${referenceLocale}.`
          );
          console.error(`  Sample keys: ${sampleKeys}`);
          hasErrors = true;
          continue;
        }

        console.log(`✓ ${ns}.json — ${refKeys.length} keys match`);
        if (drift.identicalKeys.length > 0) {
          console.warn(
            `⚠ ${locale}/${ns}.json retains ${drift.identicalKeys.length} identical English strings ` +
              `(sample: ${drift.identicalKeys.slice(0, 5).join(", ")})`
          );
        }
      }
    }
  }

  console.log("\n");
  if (hasErrors) {
    console.error("✗ Validation FAILED — missing keys or suspicious untranslated namespaces detected.");
    process.exit(1);
  }

  console.log("✓ All locale files validated successfully.");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
