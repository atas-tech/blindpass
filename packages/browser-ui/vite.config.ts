import { defineConfig, loadEnv, type Plugin } from "vite";

/**
 * The controller origin this page talks to, fixed at build time. Empty means
 * same origin (the embedded controller build). A signed link's api_url is
 * never used, so a crafted link can't redirect the page to another server.
 */
function apiOrigin(env: Record<string, string>): string | null {
  const raw = env.VITE_BLINDPASS_API_ORIGIN || env.VITE_SPS_API_URL;
  if (!raw) return null;
  const url = new URL(raw);
  if (url.protocol !== "https:" && url.protocol !== "http:") throw new Error(`unsupported API origin ${raw}`);
  return url.origin;
}

/** The P04 same-origin CSP plus, for a separately hosted page, exactly one approved API origin. */
function contentSecurityPolicy(origin: string | null, options: { dev?: boolean; header?: boolean } = {}): string {
  return [
    "default-src 'none'",
    "script-src 'self'",
    // Vite's dev server injects CSS through <style> elements; builds emit files.
    options.dev ? "style-src 'self' 'unsafe-inline'" : "style-src 'self'",
    "img-src 'self' data:",
    "font-src 'self'",
    `connect-src 'self'${origin ? ` ${origin}` : ""}`,
    "base-uri 'none'",
    "form-action 'self'",
    ...(options.header ? ["frame-ancestors 'none'"] : [])
  ].join("; ");
}

function cspMeta(origin: string | null, dev: boolean): Plugin {
  return {
    name: "blindpass-csp-meta",
    transformIndexHtml: () => [{ tag: "meta", attrs: { "http-equiv": "Content-Security-Policy", content: contentSecurityPolicy(origin, { dev }) }, injectTo: "head-prepend" }]
  };
}

// `--mode embedded` builds the copy the controller serves (P04-D9): same
// origin API whatever VITE_* says, assets under /input/ so they can't
// collide with the console's, written to dist-embedded/.
export default defineConfig(({ command, mode }) => {
  const embedded = mode === "embedded";
  const origin = embedded ? null : apiOrigin(loadEnv(mode, process.cwd(), "VITE_"));
  const dev = command === "serve" && mode !== "production";
  const headers = {
    "Content-Security-Policy": contentSecurityPolicy(origin, { dev, header: true }),
    "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Cache-Control": "no-store"
  };
  return {
    ...(embedded ? { base: "/input/", build: { outDir: "dist-embedded", emptyOutDir: true } } : {}),
    plugins: [cspMeta(origin, dev)],
    server: { headers, port: 5175 },
    preview: { headers: { ...headers, "Content-Security-Policy": contentSecurityPolicy(origin, { header: true }) } }
  };
});
