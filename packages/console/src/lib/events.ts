import type { i18n as I18n, TFunction } from "i18next";

/**
 * Human label for an audit event code. Unknown codes are shown verbatim, so
 * a new controller event is visible rather than silently mislabelled.
 */
export function eventLabel(event: string, t: TFunction, i18n: I18n): { label: string; known: boolean } {
  const key = `events.${event}`;
  if (/^[a-z_.]+$/.test(event) && i18n.exists(key) && typeof i18n.t(key, { returnObjects: true }) === "string") {
    return { label: t(key), known: true };
  }
  return { label: event, known: false };
}
