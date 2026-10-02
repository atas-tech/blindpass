import { resolveLocale, resolveLocaleFromBrowser } from "@blindpass/i18n";
import en from "@blindpass/i18n/locales/en/browser-ui.json";
import vi from "@blindpass/i18n/locales/vi/browser-ui.json";

/** Shared with the console, so a language chosen there carries over. */
export const LOCALE_STORAGE_KEY = "blindpass_locale";

const translations = { en, vi };
let activeLocale = "en";
// Fleet links show the operator-bound wording wherever an element names a
// `data-i18n-fleet` key; everything else is shared with the legacy page.
let fleetMode = false;

export function setFleetMode(on) {
  fleetMode = Boolean(on);
}

/** The fleet wording for `path` when it exists, otherwise the shared wording. */
export function tf(path, params) {
  if (!fleetMode) return t(path, params);
  const fleet = `fleet.${path}`;
  const text = t(fleet, params);
  return text === fleet ? t(path, params) : text;
}

function getValueByPath(source, path) {
  return path.split(".").reduce((value, key) => (value && typeof value === "object" ? value[key] : undefined), source);
}

function interpolate(template, params = {}) {
  return template.replace(/\{\{\s*(\w+)\s*\}\}/g, (_match, key) => String(params[key] ?? ""));
}

function readStoredLocale() {
  try {
    return globalThis.localStorage?.getItem(LOCALE_STORAGE_KEY) ?? null;
  } catch {
    return null;
  }
}

export function currentLocale() {
  return activeLocale;
}

export function t(path, params) {
  const template = getValueByPath(translations[activeLocale], path) ?? getValueByPath(translations.en, path) ?? path;
  return typeof template === "string" ? interpolate(template, params) : path;
}

export function applyTranslations(root = document) {
  root.documentElement.lang = activeLocale;
  root.querySelectorAll("[data-i18n]").forEach((element) => {
    const key = fleetMode && element.dataset.i18nFleet ? element.dataset.i18nFleet : element.dataset.i18n;
    if (key) element.textContent = t(key);
  });
  root.querySelectorAll("[data-i18n-aria-label]").forEach((element) => {
    if (element.dataset.i18nAriaLabel) element.setAttribute("aria-label", t(element.dataset.i18nAriaLabel));
  });
  root.title = t("meta.title");
}

export function initI18n(root = document) {
  activeLocale = resolveLocale(readStoredLocale() ?? resolveLocaleFromBrowser());
  applyTranslations(root);
  return activeLocale;
}

/** Switch language for this browser. Storage failure only loses the preference. */
export function setLocale(locale, root = document) {
  activeLocale = resolveLocale(locale);
  try {
    globalThis.localStorage?.setItem(LOCALE_STORAGE_KEY, activeLocale);
  } catch {
    // Private windows may refuse storage; the page still switches.
  }
  applyTranslations(root);
  return activeLocale;
}
