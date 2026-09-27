// C0/C1 controls except tab and line breaks, bidi embeddings, overrides and
// isolates, and zero-width or invisible formatting characters. Same set as
// the console's revealControls (packages/console/src/lib/format.ts).
const INVISIBLE = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\u061C\u200B-\u200F\u2028\u2029\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF]/g;

/**
 * Requester text with invisible characters shown as code points, so a bidi
 * override or terminal escape can't reorder or hide what the human reads.
 * The result is still plain text for textContent.
 */
export function revealControls(value) {
  return String(value).replace(INVISIBLE, (character) => `⟨U+${character.charCodeAt(0).toString(16).toUpperCase().padStart(4, "0")}⟩`);
}
