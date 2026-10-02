// SPDX-License-Identifier: AGPL-3.0-only
// One monotonic budget for the whole private login job. The unit's
// RuntimeMaxSec is 60 s; control/proof wait, job wait and login all draw from
// the same 55 s so their sum can never exceed it (they used to be added up as
// 5 s + 5 s + 55 s). No wall clock and no caller-supplied time is consulted.
export const LOGIN_TOTAL_MS = 55_000;
const MAX_TOTAL_MS = 60_000;

export function createBudget(totalMs, now = () => performance.now()) {
  if (!Number.isSafeInteger(totalMs) || totalMs < 1 || totalMs > MAX_TOTAL_MS || typeof now !== 'function') throw new Error('invalid_budget');
  const started = now();
  const remaining = () => Math.floor(totalMs - (now() - started));
  return Object.freeze({
    remaining,
    expired: () => remaining() <= 0,
    // A wait of at most maxMs, never longer than what is left and never zero.
    stage: (maxMs) => Math.max(1, Math.min(maxMs, remaining())),
  });
}
