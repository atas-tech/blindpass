import { afterEach } from "vitest";
import { cleanup } from "@testing-library/react";
import { initI18n } from "../i18n/index.js";

// Node 26 defines its own (disabled) localStorage global, which hides the
// jsdom one; restore jsdom's storage so tests see real browser semantics.
const jsdomWindow = (globalThis as { jsdom?: { window: Window } }).jsdom?.window;
if (jsdomWindow) {
  for (const name of ["localStorage", "sessionStorage"] as const) {
    if (!globalThis[name]) Object.defineProperty(globalThis, name, { configurable: true, value: jsdomWindow[name] });
  }
}

// jsdom has no modal dialog implementation.
if (typeof HTMLDialogElement !== "undefined" && !HTMLDialogElement.prototype.showModal) {
  HTMLDialogElement.prototype.showModal = function showModal(this: HTMLDialogElement) {
    this.setAttribute("open", "");
  };
  HTMLDialogElement.prototype.close = function close(this: HTMLDialogElement) {
    this.removeAttribute("open");
    this.dispatchEvent(new Event("close"));
  };
}

if (!window.matchMedia) {
  window.matchMedia = (query: string) =>
    ({
      matches: false,
      media: query,
      onchange: null,
      addEventListener: () => undefined,
      removeEventListener: () => undefined,
      addListener: () => undefined,
      removeListener: () => undefined,
      dispatchEvent: () => false
    }) as MediaQueryList;
}

await initI18n("en");

afterEach(() => {
  cleanup();
});
