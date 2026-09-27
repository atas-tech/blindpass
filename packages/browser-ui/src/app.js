import { ICONS } from "../../../assets/ui/icons.js";
import "../../../assets/ui/fonts.css";
import "../../../assets/ui/tokens.css";
import { createDeadline, formatRemaining } from "./clock.js";
import { sealBase64 } from "./crypto.js";
import { revealControls } from "./display-text.js";
import { enforceTopLevelWindow } from "./frame-guard.js";
import { applyTranslations, currentLocale, initI18n, setLocale, t } from "./i18n.js";
import { TERMINAL_STATES, capabilityOutcome, metadataOutcome, statusOutcome, submitOutcome } from "./lifecycle.js";
import { isValidRequestContext, parseContext } from "./request-context.js";
import { MAX_SECRET_BYTES, formatBytes, hasLineBreak, secretBytes } from "./secret-value.js";
import "./style.css";

// Fixed at build time (vite.config.ts); empty means the same origin as the page.
const API_ORIGIN = String(import.meta.env.VITE_BLINDPASS_API_ORIGIN || import.meta.env.VITE_SPS_API_URL || "").replace(/\/+$/, "");
const REVEAL_MS = 12_000;
const RECHECK_AFTER_HIDDEN_MS = 5_000;
const SIZE_HINT_BYTES = 16 * 1024;
const URGENT_MS = 60_000;

const TONES = { loading: "neutral", ready: "ok", submitting: "neutral", submitted: "ok", used: "warn", expired: "warn", invalid: "danger", auth: "warn", error: "danger", unknown: "warn" };
const SYMBOLS = { loading: "clock", submitting: "arrow-up-right", submitted: "check", used: "check", expired: "clock", invalid: "cross", auth: "lock", error: "alert", unknown: "alert" };
const SVG = "http://www.w3.org/2000/svg";

function icon(name, size = 20) {
  const svg = document.createElementNS(SVG, "svg");
  for (const [key, value] of Object.entries({ viewBox: "0 0 24 24", width: size, height: size, fill: "none", stroke: "currentColor", "stroke-width": 1.6, "stroke-linecap": "round", "stroke-linejoin": "round", "aria-hidden": "true", focusable: "false" })) {
    svg.setAttribute(key, String(value));
  }
  for (const [tag, attributes] of ICONS[name] ?? []) {
    const part = document.createElementNS(SVG, tag);
    for (const [key, value] of Object.entries(attributes)) part.setAttribute(key, String(value));
    svg.append(part);
  }
  return svg;
}

function now() {
  return { perf: performance.now(), wall: Date.now() };
}

async function call(path, init = {}) {
  const sentAt = Date.now();
  let response;
  try {
    // Signed links carry their own authority: no cookies, no referrer, no cache.
    response = await fetch(`${API_ORIGIN}${path}`, { ...init, credentials: "omit", cache: "no-store", referrerPolicy: "no-referrer" });
  } catch {
    return { status: 0, body: null };
  }
  const receivedAt = Date.now();
  const perfAt = performance.now();
  let body = null;
  try {
    body = await response.json();
  } catch {
    body = null;
  }
  return { status: response.status, body, date: response.headers.get("date"), sentAt, receivedAt, perfAt };
}

function badgeKey(state, reason) {
  return state === "unknown" && reason === "checking" ? "checking" : state;
}

function validMetadata(body) {
  return Boolean(body && typeof body.public_key === "string" && body.public_key && typeof body.description === "string" && typeof body.confirmation_code === "string" && typeof body.expiry === "number");
}

/** The earlier page kept a hosted refresh token here; this page has no session, so drop it. */
function removeLegacyRefreshToken() {
  try {
    globalThis.localStorage?.removeItem("blindpass_refresh_token");
  } catch {
    // Storage may be unavailable; there is then nothing to remove.
  }
}

function init() {
  if (enforceTopLevelWindow()) return;
  removeLegacyRefreshToken();
  initI18n();

  const $ = (id) => document.getElementById(id);
  const ui = {
    card: $("secret-card"),
    badge: $("status-badge"),
    entry: $("entry-panel"),
    description: $("request-description"),
    code: $("confirmation-code"),
    expiry: $("expiry"),
    expiryHint: $("expiry-hint"),
    form: $("secret-form"),
    label: $("secret-label"),
    clear: $("clear"),
    singleField: $("single-field"),
    single: $("secret-single"),
    visibility: $("visibility"),
    multi: $("secret-multi"),
    multiline: $("multiline"),
    size: $("input-size"),
    help: $("input-help"),
    error: $("input-error"),
    submit: $("submit"),
    outcome: $("outcome-panel"),
    symbol: $("outcome-symbol"),
    title: $("outcome-title"),
    body: $("outcome-body"),
    note: $("outcome-note"),
    action: $("outcome-action"),
    followup: $("outcome-followup"),
    announcer: $("announcer"),
    language: $("language")
  };
  for (const element of document.querySelectorAll("[data-icon]")) element.replaceChildren(icon(element.dataset.icon, 18));

  const ctx = parseContext(window.location.search);
  // statusSig is the CT19 status-only capability: memory only, never stored.
  const page = { state: "loading", reason: null, metadata: null, deadline: null, statusSig: null, busy: false, error: null, revealTimer: null, tick: null, urgentAnnounced: false, hiddenAt: null };
  const metadataPath = () => `/api/v2/secret/metadata/${encodeURIComponent(ctx.requestId)}?sig=${encodeURIComponent(ctx.metadataSig)}`;
  const submitPath = () => `/api/v2/secret/submit/${encodeURIComponent(ctx.requestId)}?sig=${encodeURIComponent(ctx.submitSig)}`;
  const capabilityPath = () => `/api/v2/secret/browser-status/${encodeURIComponent(ctx.requestId)}/capability?sig=${encodeURIComponent(ctx.metadataSig)}`;
  const statusPath = (sig) => `/api/v2/secret/browser-status/${encodeURIComponent(ctx.requestId)}?sig=${encodeURIComponent(sig)}`;

  /**
   * Read the request's status through the CT19 browser contract: the
   * metadata signature buys a status-only signature, which reads pending or
   * submitted and nothing else. Returns submitted, pending, gone or unavailable.
   */
  async function checkStatus() {
    if (!page.statusSig) {
      const issued = await call(capabilityPath(), { method: "POST" });
      const capability = capabilityOutcome(issued.status, issued.body);
      if (capability.gone) return "gone";
      if (capability.unavailable) return "unavailable";
      page.statusSig = capability.sig;
    }
    const read = await call(statusPath(page.statusSig));
    return statusOutcome(read.status, read.body);
  }

  const activeInput = () => (ui.multiline.checked ? ui.multi : ui.single);
  const currentValue = () => activeInput().value;

  function announce(message) {
    ui.announcer.textContent = "";
    // A fresh text node after clearing makes screen readers repeat identical messages.
    window.setTimeout(() => (ui.announcer.textContent = message), 30);
  }

  function mask() {
    window.clearTimeout(page.revealTimer);
    page.revealTimer = null;
    ui.single.type = "password";
    ui.visibility.textContent = t("form.show");
    ui.visibility.setAttribute("aria-label", t("form.showLabel"));
    ui.visibility.setAttribute("aria-pressed", "false");
  }

  function reveal() {
    ui.single.type = "text";
    ui.visibility.textContent = t("form.hide");
    ui.visibility.setAttribute("aria-label", t("form.hideLabel"));
    ui.visibility.setAttribute("aria-pressed", "true");
    window.clearTimeout(page.revealTimer);
    page.revealTimer = window.setTimeout(mask, REVEAL_MS);
  }

  function clearValues() {
    ui.single.value = "";
    ui.multi.value = "";
    mask();
    renderSize();
  }

  function showError(key, params, tone = "danger") {
    page.error = key ? { key, params, tone } : null;
    ui.error.hidden = !key;
    ui.error.textContent = key ? t(`errors.${key}`, params) : "";
    ui.error.dataset.tone = tone;
    const invalid = Boolean(key) && tone === "danger";
    ui.single.setAttribute("aria-invalid", String(invalid));
    ui.multi.setAttribute("aria-invalid", String(invalid));
  }

  function renderSize() {
    const bytes = secretBytes(currentValue()).length;
    const show = bytes > 0 && (ui.multiline.checked || bytes >= SIZE_HINT_BYTES);
    ui.size.textContent = show ? t("form.size", { size: formatBytes(bytes, currentLocale()), limit: formatBytes(MAX_SECRET_BYTES, currentLocale()) }) : "";
    ui.size.dataset.over = String(bytes > MAX_SECRET_BYTES);
  }

  function renderMode() {
    const multiline = ui.multiline.checked;
    ui.singleField.hidden = multiline;
    ui.multi.hidden = !multiline;
    ui.label.htmlFor = multiline ? ui.multi.id : ui.single.id;
    ui.help.textContent = t(multiline ? "form.multilineHelp" : "form.singleHelp");
    ui.single.placeholder = t("form.singlePlaceholder");
    ui.multi.placeholder = t("form.multiPlaceholder");
  }

  function setMultiline(on, value) {
    ui.multiline.checked = on;
    if (on) {
      ui.multi.value = value;
      ui.single.value = "";
    } else {
      ui.single.value = value;
      ui.multi.value = "";
    }
    mask();
    renderMode();
    renderSize();
  }

  function renderExpiry() {
    const deadline = page.deadline;
    ui.expiry.hidden = !deadline;
    ui.expiryHint.hidden = !deadline || deadline.serverClock;
    if (!deadline) return;
    if (!deadline.serverClock) {
      const time = new Intl.DateTimeFormat(currentLocale(), { hour: "2-digit", minute: "2-digit" }).format(deadline.expiresAt);
      ui.expiry.textContent = t("card.validUntil", { time });
      ui.expiry.dataset.urgent = "false";
      return;
    }
    const remaining = deadline.remaining(now());
    ui.expiry.textContent = t("card.remaining", { time: formatRemaining(remaining) });
    const urgent = remaining < URGENT_MS;
    ui.expiry.dataset.urgent = String(urgent);
    if (urgent && !page.urgentAnnounced && page.state === "ready") {
      page.urgentAnnounced = true;
      announce(t("card.minuteLeft"));
    }
  }

  function renderRequest() {
    const metadata = page.metadata;
    // Server-provided text is rendered as text nodes only.
    ui.description.textContent = revealControls(metadata?.description ?? "");
    ui.code.textContent = metadata?.confirmation_code ?? "";
    renderExpiry();
  }

  function stopTicking() {
    window.clearInterval(page.tick);
    page.tick = null;
  }

  function startTicking() {
    stopTicking();
    if (!page.deadline?.serverClock) return;
    page.tick = window.setInterval(() => {
      if (page.state === "ready" && page.deadline.expired(now())) {
        setState("expired", "whileOpen", { focus: true });
        return;
      }
      renderExpiry();
    }, 1000);
  }

  function outcomeCopy(state, reason) {
    const base = `state.${state}`;
    let body = t(`${base}.body`);
    let note = t(`${base}.note`);
    if (state === "submitted" && reason === "confirmed") body = t("state.submitted.bodyConfirmed");
    if (state === "unknown" && reason === "checking") body = t("state.unknown.bodyChecking");
    if (state === "unknown" && reason === "unavailable") body = t("state.unknown.bodyUnavailable");
    if (state === "unknown" && reason === "gone") {
      body = t("state.unknown.bodyGone");
      note = t("state.unknown.noteGone");
    }
    if (state === "expired" && reason === "whileOpen") body = t("state.expired.bodyWhileOpen");
    if (state === "expired" && reason === "submit") body = t("state.expired.bodyOnSubmit");
    if (state === "invalid" && reason === "submit") body = t("state.invalid.bodySubmit");
    return { title: t(`${base}.title`), body, note };
  }

  function renderState() {
    const { state, reason } = page;
    const entry = state === "ready";
    ui.card.dataset.state = state;
    ui.badge.textContent = t(`badge.${badgeKey(state, reason)}`);
    ui.badge.dataset.tone = TONES[state];
    ui.entry.hidden = !entry;
    ui.outcome.hidden = entry;
    for (const control of [ui.single, ui.multi, ui.multiline, ui.visibility, ui.clear, ui.submit]) control.disabled = !entry;
    ui.outcome.dataset.tone = TONES[state];
    ui.outcome.dataset.state = state;
    if (!entry) {
      const copy = outcomeCopy(state, reason);
      ui.symbol.replaceChildren(icon(SYMBOLS[state], 22));
      ui.title.textContent = copy.title;
      ui.body.textContent = copy.body;
      ui.note.textContent = copy.note;
      const unknownAction = state === "unknown" && reason === "unavailable";
      ui.action.hidden = state !== "error" && state !== "submitted" && !unknownAction;
      ui.action.textContent = state === "error" ? t("state.error.action") : unknownAction ? t("state.unknown.action") : t("state.close");
      if (state !== "submitted") ui.followup.hidden = true;
    }
    renderMode();
    if (page.error) showError(page.error.key, page.error.params, page.error.tone);
  }

  function setState(state, reason = null, options = {}) {
    page.state = state;
    page.reason = reason;
    if (TERMINAL_STATES.has(state)) {
      clearValues();
      showError(null);
      stopTicking();
    }
    renderState();
    announce(t(`badge.${badgeKey(state, reason)}`));
    if (options.focus) (state === "ready" ? activeInput() : ui.title).focus();
  }

  async function load() {
    if (!isValidRequestContext(ctx)) {
      // No request is sent for an incomplete link: there is nothing honest to ask.
      setState("invalid", "load");
      return;
    }
    const focus = page.state === "error";
    setState("loading");
    const result = await call(metadataPath());
    const outcome = metadataOutcome(result.status);
    if (outcome.state !== "ready") {
      setState(outcome.state, outcome.reason, { focus });
      return;
    }
    if (!validMetadata(result.body)) {
      setState("error", null, { focus });
      return;
    }
    page.metadata = result.body;
    page.deadline = createDeadline({ expirySeconds: result.body.expiry, dateHeader: result.date, sentAt: result.sentAt, receivedAt: result.receivedAt, perfAt: result.perfAt });
    renderRequest();
    if (page.deadline?.expired(now())) {
      setState("expired", "whileOpen", { focus });
      return;
    }
    // Metadata stays readable after submission; the status read tells the two apart.
    const status = await checkStatus();
    if (status === "submitted") {
      setState("used", "load", { focus });
      return;
    }
    if (status === "gone") {
      setState("expired", "load", { focus });
      return;
    }
    setState("ready", null, { focus });
    startTicking();
  }

  /** After the tab was hidden, recheck the deadline and the link before accepting input. */
  async function recheck() {
    if (page.state !== "ready" || page.busy) return;
    if (page.deadline?.expired(now())) {
      setState("expired", "whileOpen", { focus: true });
      return;
    }
    const result = await call(metadataPath());
    if (page.state !== "ready" || page.busy) return;
    const outcome = metadataOutcome(result.status);
    if (outcome.state === "ready" && validMetadata(result.body)) {
      page.deadline = createDeadline({ expirySeconds: result.body.expiry, dateHeader: result.date, sentAt: result.sentAt, receivedAt: result.receivedAt, perfAt: result.perfAt }) ?? page.deadline;
      renderExpiry();
      startTicking();
      // Another tab may have submitted in the meantime.
      if ((await checkStatus()) === "submitted" && page.state === "ready" && !page.busy) setState("used", "load", { focus: true });
    } else if (outcome.state === "expired") {
      setState("expired", "whileOpen", { focus: true });
    } else if (outcome.state === "invalid" || outcome.state === "auth") {
      setState(outcome.state, outcome.reason, { focus: true });
    }
    // A failed recheck leaves the page as it was; the submit answer still decides.
  }

  async function submit() {
    if (page.state !== "ready" || page.busy) return;
    const value = currentValue();
    if (!value.length) {
      showError("empty");
      activeInput().focus();
      return;
    }
    const bytes = secretBytes(value).length;
    if (bytes > MAX_SECRET_BYTES) {
      showError("tooLarge", { size: formatBytes(bytes, currentLocale()), limit: formatBytes(MAX_SECRET_BYTES, currentLocale()) });
      activeInput().focus();
      return;
    }
    if (page.deadline?.expired(now())) {
      setState("expired", "whileOpen", { focus: true });
      return;
    }
    page.busy = true;
    showError(null);
    let payload;
    try {
      payload = await sealBase64(page.metadata.public_key, value);
    } catch {
      page.busy = false;
      showError("encryption");
      return;
    }
    setState("submitting", null, { focus: true });
    const result = await call(submitPath(), { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload) });
    payload = null;
    page.busy = false;
    const outcome = submitOutcome(result.status);
    if (outcome.state === "ready") {
      // A definite refusal: nothing was stored and the value is still here to fix.
      setState("ready");
      showError(outcome.error, outcome.error === "tooLarge" ? { size: formatBytes(bytes, currentLocale()), limit: formatBytes(MAX_SECRET_BYTES, currentLocale()) } : undefined);
      activeInput().focus();
      if (page.deadline?.serverClock) startTicking();
      return;
    }
    if (outcome.state === "unknown") {
      void reconcile();
      return;
    }
    setState(outcome.state, outcome.reason, { focus: true });
  }

  /**
   * After a lost or failed reply, ask the controller what happened (P04-I03).
   * Only a status of submitted reports success, pending returns to entry
   * with an empty field, and nothing is ever resubmitted automatically.
   */
  async function reconcile() {
    setState("unknown", "checking", { focus: true });
    const status = await checkStatus();
    if (page.state !== "unknown") return;
    if (status === "submitted") {
      setState("submitted", "confirmed", { focus: true });
    } else if (status === "pending" && page.deadline?.expired(now())) {
      // Known not received, but the link can no longer accept it.
      setState("expired", "submit", { focus: true });
    } else if (status === "pending") {
      setState("ready");
      showError("notReceived", undefined, "info");
      activeInput().focus();
      startTicking();
    } else {
      setState("unknown", status, { focus: true });
    }
  }

  ui.form.addEventListener("submit", (event) => {
    event.preventDefault();
    void submit();
  });
  ui.visibility.addEventListener("click", () => (ui.single.type === "password" ? reveal() : mask()));
  ui.clear.addEventListener("click", () => {
    clearValues();
    showError(null);
    activeInput().focus();
  });
  ui.multiline.addEventListener("change", () => {
    const turningOn = ui.multiline.checked;
    const value = turningOn ? ui.single.value : ui.multi.value;
    if (!turningOn && hasLineBreak(value)) {
      ui.multiline.checked = true;
      showError("lineBreaks");
      return;
    }
    setMultiline(turningOn, value);
    showError(null);
    activeInput().focus();
  });
  for (const input of [ui.single, ui.multi]) {
    input.addEventListener("input", () => {
      if (page.error?.key !== "lineBreaks") showError(null);
      renderSize();
    });
  }
  // A single-line input drops line breaks from pasted or dropped text. Move the
  // value to multiline instead, so nothing is silently lost.
  const keepLineBreaks = (event, text) => {
    if (!hasLineBreak(text)) return;
    event.preventDefault();
    const start = ui.single.selectionStart ?? ui.single.value.length;
    const end = ui.single.selectionEnd ?? start;
    const value = ui.single.value.slice(0, start) + text + ui.single.value.slice(end);
    setMultiline(true, value);
    ui.multi.focus();
    ui.multi.setSelectionRange(start + text.length, start + text.length);
    showError("switchedToMultiline", undefined, "info");
    announce(t("errors.switchedToMultiline"));
  };
  ui.single.addEventListener("paste", (event) => keepLineBreaks(event, event.clipboardData?.getData("text/plain") ?? ""));
  ui.single.addEventListener("drop", (event) => keepLineBreaks(event, event.dataTransfer?.getData("text/plain") ?? ""));

  ui.action.addEventListener("click", () => {
    if (page.state === "unknown" && page.reason === "unavailable") {
      void reconcile();
      return;
    }
    if (page.state === "error") {
      void load();
      return;
    }
    if (page.state === "submitted") {
      window.close();
      // Browsers only let scripts close tabs they opened; say so instead of failing silently.
      window.setTimeout(() => {
        if (!window.closed) {
          ui.followup.hidden = false;
          ui.followup.textContent = t("state.closeRefused");
          announce(t("state.closeRefused"));
        }
      }, 400);
    }
  });

  ui.language.value = currentLocale();
  ui.language.addEventListener("change", () => {
    setLocale(ui.language.value);
    for (const element of document.querySelectorAll("[data-icon]")) element.replaceChildren(icon(element.dataset.icon, 18));
    if (ui.single.type === "password") mask();
    else reveal();
    renderRequest();
    renderSize();
    renderState();
  });

  window.addEventListener("blur", mask);
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) {
      page.hiddenAt = Date.now();
      mask();
      return;
    }
    const hiddenFor = page.hiddenAt === null ? 0 : Date.now() - page.hiddenAt;
    page.hiddenAt = null;
    if (hiddenFor >= RECHECK_AFTER_HIDDEN_MS || page.deadline?.expired(now())) void recheck();
  });
  // Leaving the page clears the field, so a back/forward cache restore never shows it.
  window.addEventListener("pagehide", () => {
    clearValues();
    stopTicking();
  });
  window.addEventListener("pageshow", (event) => {
    if (!event.persisted) return;
    startTicking();
    void recheck();
  });

  applyTranslations();
  mask();
  renderState();
  void load();
}

init();
