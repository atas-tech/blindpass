// SPDX-License-Identifier: AGPL-3.0-only
// P04-D3 desktop session policy. The access token lives only in memory; the
// refresh token lives only in $XDG_RUNTIME_DIR/blindpass/session (0600,
// tmpfs) through bin/blindpass-session-store. Pure functions so the timing
// rules are unit-tested.
.pragma library

/** Rotate on every start and at least this often while running. */
var ROTATE_MS = 15 * 60 * 1000;
/** Lock decisions after this long without input in the app window. */
var IDLE_LOCK_MS = 10 * 60 * 1000;
/** Poll the pending count this often while signed in or locked. */
var COUNT_POLL_MS = 30 * 1000;
/** Refresh the open list this often while the window is visible. */
var LIST_POLL_MS = 15 * 1000;

/** The stored record. Only these fields are written. */
function record(controllerOrigin, refreshToken, username, lastActiveAt) {
  return { v: 1, controller: controllerOrigin, refresh_token: refreshToken, username: username, last_active_at: Math.floor(lastActiveAt) };
}

/**
 * Validate a stored record against the configured controller. A token
 * stored for another controller is never sent anywhere: the caller deletes
 * it. Returns { ok: true, record } or { ok: false, reason }.
 */
function readRecord(text, controllerOrigin) {
  var parsed;
  try {
    parsed = JSON.parse(text);
  } catch (error) {
    return { ok: false, reason: "corrupt" };
  }
  if (!parsed || parsed.v !== 1 || typeof parsed.refresh_token !== "string" || parsed.refresh_token.length < 16
    || typeof parsed.controller !== "string" || typeof parsed.username !== "string" || typeof parsed.last_active_at !== "number") {
    return { ok: false, reason: "corrupt" };
  }
  if (parsed.controller !== controllerOrigin) return { ok: false, reason: "other_controller" };
  return { ok: true, record: parsed };
}

/** Whether a restarted app should open locked (idle since the last input). */
function startsLocked(lastActiveAt, now) {
  return now - lastActiveAt >= IDLE_LOCK_MS;
}

function shouldLock(lastInputAt, now) {
  return now - lastInputAt >= IDLE_LOCK_MS;
}

/** Milliseconds until the next rotation, rotating early before the server's 20-minute cap. */
function nextRotationIn(rotatedAt, now) {
  return Math.max(0, rotatedAt + ROTATE_MS - now);
}

/**
 * What a controller answer means for the session:
 *   "ok"       keep going
 *   "signed_out" the session is gone (401): drop memory and the file
 *   "forbidden"  the session is fine but this action isn't allowed
 *   "retry"    transient; keep the session and try later
 */
function sessionEffect(response) {
  if (!response.ok) return "retry";
  if (response.status === 401) return "signed_out";
  if (response.status === 403) return "forbidden";
  if (response.status >= 500 || response.status === 429) return "retry";
  return "ok";
}

/** Map a login refusal to a message key. */
function loginError(response) {
  if (!response.ok) return "errors." + response.kind;
  var code = response.body && response.body.error;
  if (response.status === 401) return "signIn.invalid";
  if (code === "password_change_required") return "signIn.changePassword";
  if (code === "desktop_origin_denied") return "errors.network";
  if (response.status === 404) return "errors.noFleet";
  if (response.status === 429) return "errors.rateLimited";
  return "errors.unavailable";
}
