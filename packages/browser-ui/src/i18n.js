import { resolveLocale, resolveLocaleFromBrowser } from "@blindpass/i18n";
import en from "@blindpass/i18n/locales/en/browser-ui.json";
import vi from "@blindpass/i18n/locales/vi/browser-ui.json";

/** Shared with the console, so a language chosen there carries over. */
export const LOCALE_STORAGE_KEY = "blindpass_locale";

const translations = { en, vi };
let activeLocale = "en";

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
    if (element.dataset.i18n) element.textContent = t(element.dataset.i18n);
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
