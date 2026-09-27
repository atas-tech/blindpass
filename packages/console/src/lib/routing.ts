/** Only same-origin relative paths are accepted as a post-login return. */
export function safeReturnPath(value: unknown): string {
  if (typeof value !== "string" || !value.startsWith("/") || value.startsWith("//") || value.startsWith("/\\")) return "/";
  if (value.startsWith("/login") || value.startsWith("/setup") || value.startsWith("/logout")) return "/";
  return value;
}
