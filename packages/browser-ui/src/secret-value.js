/**
 * The controller caps base64 ciphertext at 524,288 characters. HPKE with
 * ChaCha20-Poly1305 adds a 16-byte tag, so 393,216 - 16 plaintext bytes is
 * the largest value that fits.
 */
export const MAX_SECRET_BYTES = 393_200;

/** UTF-8 bytes exactly as typed: nothing is trimmed or normalised here. */
export function secretBytes(value) {
  return new TextEncoder().encode(value);
}

export function hasLineBreak(value) {
  return /[\r\n]/.test(value);
}

export function formatBytes(bytes, locale) {
  const format = (value) => new Intl.NumberFormat(locale, { maximumFractionDigits: 1 }).format(value);
  if (bytes < 1024) return `${format(bytes)} B`;
  return `${format(bytes / 1024)} KB`;
}
