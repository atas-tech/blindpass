// SPDX-License-Identifier: AGPL-3.0-only
// Reads the approval app's metadata-only summary
// ($XDG_RUNTIME_DIR/blindpass/summary.json). Only v, state, pending and
// updated_at are read; anything else in the file is ignored. The widget
// never reads the session file and holds no controller credential.
.pragma library

/** Older than this, the app is treated as not running (it writes every 30 s). */
var STALE_MS = 90 * 1000;
var STATES = ["ready", "locked", "signed_out", "unreachable"];

/**
 * The widget's view of the summary text at `now`.
 * Returns { state, pending } where state is one of
 * ready | locked | signed_out | unreachable | not_running,
 * and pending is a non-negative integer or null.
 */
function read(text, now) {
  var parsed = null;
  try {
    parsed = JSON.parse(text);
  } catch (error) {
    parsed = null;
  }
  if (!parsed || parsed.v !== 1 || STATES.indexOf(parsed.state) === -1 || typeof parsed.updated_at !== "number") {
    return { state: "not_running", pending: null };
  }
  if (now - parsed.updated_at > STALE_MS || parsed.updated_at - now > STALE_MS) return { state: "not_running", pending: null };
  var pending = null;
  if ((parsed.state === "ready" || parsed.state === "locked") && typeof parsed.pending === "number" && isFinite(parsed.pending) && parsed.pending >= 0) {
    pending = Math.min(9999, Math.floor(parsed.pending));
  }
  return { state: parsed.state, pending: pending };
}

/** The bar label: the pending count when above zero, else empty. */
function label(view) {
  if (view.pending === null || view.pending === 0) return "";
  return view.pending > 99 ? "99+" : String(view.pending);
}

function tooltip(view) {
  switch (view.state) {
  case "ready":
    if (view.pending === 0) return "BlindPass: nothing waiting for you";
    return "BlindPass: " + view.pending + (view.pending === 1 ? " approval waiting" : " approvals waiting") + " · click to open";
  case "locked":
    return "BlindPass: locked" + (view.pending ? " · " + view.pending + " waiting" : "") + " · click to unlock";
  case "signed_out":
    return "BlindPass: signed out · click to sign in";
  case "unreachable":
    return "BlindPass: can't reach the controller";
  default:
    return "BlindPass approval app isn't running · click to open";
  }
}

/** Whether the count should draw attention. */
function urgent(view) {
  return (view.state === "ready" || view.state === "locked") && view.pending !== null && view.pending > 0;
}
