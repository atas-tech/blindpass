import i18next from "i18next";
import { initReactI18next } from "react-i18next";
import { resolveLocale, resolveLocaleFromBrowser, SUPPORTED_LOCALES, type SupportedLocale } from "@blindpass/i18n";
import en from "@blindpass/i18n/locales/en/console.json";
import vi from "@blindpass/i18n/locales/vi/console.json";

/** Shared with the input page so one preference follows the operator. */
export const LOCALE_STORAGE_KEY = "blindpass_locale";

function storedLocale(): string | null {
  try {
    return globalThis.localStorage?.getItem(LOCALE_STORAGE_KEY) ?? null;
  } catch {
    return null;
  }
}

export function initialLocale(): SupportedLocale {
  return resolveLocale(storedLocale() ?? resolveLocaleFromBrowser());
}

export async function initI18n(locale: SupportedLocale = initialLocale()) {
  await i18next.use(initReactI18next).init({
    resources: { en: { console: en }, vi: { console: vi } },
    lng: locale,
    fallbackLng: "en",
    supportedLngs: [...SUPPORTED_LOCALES],
    defaultNS: "console",
    ns: ["console"],
    interpolation: { escapeValue: false },
    returnNull: false
  });
  document.documentElement.lang = locale;
  return i18next;
}

export function setLocale(locale: SupportedLocale): void {
  void i18next.changeLanguage(locale);
  document.documentElement.lang = locale;
  try {
    globalThis.localStorage?.setItem(LOCALE_STORAGE_KEY, locale);
  } catch {
    // A locale preference is a convenience; ignore blocked storage.
  }
}

export { SUPPORTED_LOCALES };
export type { SupportedLocale };
