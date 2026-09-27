export { SUPPORTED_LOCALES, DEFAULT_LOCALE, isSupportedLocale } from "./supported.js";
export type { SupportedLocale } from "./supported.js";
import { isSupportedLocale, DEFAULT_LOCALE } from "./supported.js";
import type { SupportedLocale } from "./supported.js";

/** Namespace identifiers matching JSON file names */
export const NAMESPACES = [
  "common",
  "auth",
  "dashboard",
  "agents",
  "members",
  "billing",
  "audit",
  "approvals",
  "settings",
  "layout",
  "browser-ui",
  "email",
  "analytics",
  "offers",
  "policy",
  "console",
] as const;

export type Namespace = (typeof NAMESPACES)[number];

/**
 * Resolve the best supported locale from a raw locale string.
 *
 * Strategy:
 * 1. Exact match (e.g. "vi" → "vi")
 * 2. Language prefix match (e.g. "vi-VN" → "vi")
 * 3. Fallback to "en"
 */
export function resolveLocale(raw: string | null | undefined): SupportedLocale {
  if (!raw) {
    return DEFAULT_LOCALE;
  }

  const normalized = raw.trim().toLowerCase();

  // Exact match
  if (isSupportedLocale(normalized)) {
    return normalized;
  }

  // Language prefix (e.g. "vi-VN" → "vi")
  const prefix = normalized.split("-")[0];
  if (prefix && isSupportedLocale(prefix)) {
    return prefix;
  }

  return DEFAULT_LOCALE;
}

/**
 * Resolve locale from navigator.languages or navigator.language.
 * Returns the first matching supported locale, or the default.
 */
export function resolveLocaleFromBrowser(): SupportedLocale {
  if (typeof globalThis.navigator === "undefined") {
    return DEFAULT_LOCALE;
  }

  const candidates = globalThis.navigator.languages?.length
    ? globalThis.navigator.languages
    : [globalThis.navigator.language];

  for (const candidate of candidates) {
    const resolved = resolveLocale(candidate);
    if (resolved !== DEFAULT_LOCALE || candidate.startsWith("en")) {
      return resolved;
    }
  }

  return DEFAULT_LOCALE;
}
