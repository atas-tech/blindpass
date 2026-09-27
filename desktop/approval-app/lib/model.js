// SPDX-License-Identifier: AGPL-3.0-only
// Display model for /api/v3/approvals items, matching the console's
// approvals model (packages/console/src/pages/approvals/model.ts): who the
// authority goes to, its scope, and whether this operator may decide.
.pragma library

function isOperation(approval) {
  return !!approval && approval.kind === "operation";
}

function key(approval) {
  return isOperation(approval) ? approval.id : approval.reference;
}

function text(value) {
  return typeof value === "string" && value.length > 0 ? value : null;
}

// C0/C1 controls except tab and line breaks, bidi embeddings, overrides and
// isolates, and zero-width characters: the console's revealControls set.
var INVISIBLE = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\u061C\u200B-\u200F\u2028\u2029\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF]/g;

/** Untrusted text with invisible characters shown as code points (O05). */
function revealControls(value) {
  return String(value).replace(INVISIBLE, function (character) {
    var hex = character.charCodeAt(0).toString(16).toUpperCase();
    while (hex.length < 4) hex = "0" + hex;
    return "⟨U+" + hex + "⟩";
  });
}

/** Requester-written purpose. Untrusted: render as plain text only. */
function purpose(approval) {
  var value = isOperation(approval) ? text(approval.requester_summary && approval.requester_summary.purpose) : text(approval.purpose);
  return value === null ? null : revealControls(value);
}

function requester(approval) {
  if (isOperation(approval)) {
    var summary = approval.requester_summary || {};
    return text(summary.requester) || text(summary.operator_id) || "—";
  }
  return approval.requester_id || "—";
}

/** The stable facts the pre-decision recheck compares. */
function fingerprint(approval) {
  if (isOperation(approval)) return approval.status + ":" + approval.version + ":" + (approval.operation_ids || []).join(",");
  return String(approval.status);
}

/**
 * Whether this operator may decide, as far as the app can tell. The
 * controller re-checks everything. Returns null, "not_pending", "not_named"
 * or "self". Exchange approvals don't expose approvers, so the server answers.
 */
function decisionBlock(approval, operator) {
  if (!approval || approval.status !== "pending") return "not_pending";
  if (!operator || !isOperation(approval)) return null;
  var me = [operator.id, operator.username];
  var named = (approval.approver_ids || []).some(function (id) { return me.indexOf(id) !== -1; });
  if (!named) return "not_named";
  var summary = approval.requester_summary || {};
  var requesters = [summary.operator_id, summary.requester];
  (approval.operations || []).forEach(function (operation) { requesters.push(operation.requested_by); });
  var self = requesters.some(function (id) { return typeof id === "string" && me.indexOf(id) !== -1; });
  return self ? "self" : null;
}

/**
 * Recipient and scope lines for the confirmation, as string keys plus
 * arguments so the view localises them. Every value comes from the
 * controller's verified record, never from requester text.
 */
function authority(approval) {
  if (isOperation(approval)) {
    var scope = approval.verified_identity || {};
    return {
      recipient: { key: "confirm.operationRecipient", args: { node: scope.node_id || "—" } },
      scope: { key: "confirm.operationScope", args: { action: scope.action || "—", unit: scope.unit || "—", account: scope.account || "—", mode: scope.mode || "—" } },
      count: (approval.operation_ids || []).length
    };
  }
  return {
    recipient: { key: "confirm.exchangeRecipient", args: { requester: requester(approval) } },
    scope: { key: "confirm.exchangeScope", args: { secret: approval.secret_name || "—" } },
    count: 1
  };
}

/** The decision request for the unified route: path, body and headers. */
function decisionRequest(approval, verb, idempotencyKey) {
  if (verb !== "approve" && verb !== "reject") throw new Error("verb rejected");
  var id = encodeURIComponent(key(approval));
  if (isOperation(approval)) {
    return {
      path: "/api/v3/approvals/" + id + "/" + verb,
      body: { expected_status: "pending", expected_version: approval.version, operation_ids: approval.operation_ids },
      headers: { "Idempotency-Key": idempotencyKey, "If-Match": "\"" + approval.version + "\"" }
    };
  }
  // The unified route treats an exchange approval as version 1.
  return {
    path: "/api/v3/approvals/" + id + "/" + verb,
    body: { expected_status: "pending", expected_version: 1 },
    headers: { "Idempotency-Key": idempotencyKey, "If-Match": "\"1\"" }
  };
}

/** 32 random bytes as hex from a caller-supplied byte source. */
function idempotencyKey(randomByte) {
  var out = "";
  for (var index = 0; index < 32; index += 1) {
    var byte = randomByte() & 0xff;
    out += (byte < 16 ? "0" : "") + byte.toString(16);
  }
  return out;
}

/** Remaining milliseconds on the controller clock, or null without an expiry. */
function remaining(approval, serverNow) {
  if (!isOperation(approval) || typeof approval.expires_at !== "number") return null;
  return Math.max(0, approval.expires_at - serverNow);
}

function formatRemaining(ms) {
  if (ms === null || ms === undefined) return "";
  var seconds = Math.ceil(ms / 1000);
  if (seconds <= 0) return "0:00";
  var minutes = Math.floor(seconds / 60);
  var rest = seconds % 60;
  if (minutes >= 60) {
    var hours = Math.floor(minutes / 60);
    return hours + ":" + pad(minutes % 60) + ":" + pad(rest);
  }
  return minutes + ":" + pad(rest);
}

function pad(value) {
  return value < 10 ? "0" + value : String(value);
}

/**
 * The metadata-only summary the widget may read. Only these fields are
 * written; nothing about any individual request leaves the app.
 */
function widgetSummary(state, pending, now) {
  var states = ["ready", "locked", "signed_out", "unreachable"];
  var safeState = states.indexOf(state) === -1 ? "signed_out" : state;
  var count = safeState === "ready" || safeState === "locked" ? Math.max(0, Math.min(9999, Math.floor(Number(pending) || 0))) : null;
  return { v: 1, state: safeState, pending: count, updated_at: Math.floor(now) };
}
