type Translate = (key: string, options?: Record<string, unknown>) => string;

/** Mirrors the controller's account-name rule (3–128 of A–Z a–z 0–9 . _ @ -). */
export function validateAccountName(value: string, t: Translate): string | null {
  if (value.length < 3) return t("auth.errors.usernameShort");
  if (value.length > 128) return t("auth.errors.usernameLong");
  if (!/^[A-Za-z0-9._@-]+$/.test(value)) return t("auth.errors.usernameChars");
  return null;
}

/** Mirrors the controller's password length rule (12–1024 bytes). */
export function validateNewPassword(value: string, t: Translate): string | null {
  const bytes = new TextEncoder().encode(value).length;
  if (bytes < 12) return t("auth.errors.passwordShort");
  if (bytes > 1024) return t("auth.errors.passwordLong");
  return null;
}
