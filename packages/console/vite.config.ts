import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";
import type { Plugin } from "vite";
import react from "@vitejs/plugin-react";

// The controller serves the built console from its own origin (P04-D9), so
// the preview server mirrors that profile: same-origin API through a proxy
// and the production security headers.
const controllerUrl = process.env.BLINDPASS_CONTROLLER_URL ?? "http://127.0.0.1:3200";

export const CONSOLE_CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self'",
  "frame-ancestors 'none'",
  "base-uri 'none'",
  "form-action 'self'"
].join("; ");

const securityHeaders = {
  "Content-Security-Policy": CONSOLE_CSP,
  "Cross-Origin-Opener-Policy": "same-origin",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff"
};

/**
 * The embedded controller's cache profile (P04-D9) for `vite preview`:
 * hashed assets immutable, everything else no-store. Proxied API responses
 * keep the controller's own headers.
 */
function embeddedCacheProfile(): Plugin {
  return {
    name: "blindpass-embedded-cache-profile",
    configurePreviewServer(server) {
      server.middlewares.use((request, response, next) => {
        if (/^\/(api|healthz)(\/|$|\?)/.test(request.url ?? "")) return next();
        const immutable = request.url?.startsWith("/assets/") ?? false;
        const setHeader = response.setHeader.bind(response);
        response.setHeader = (name, value) => (name.toLowerCase() === "cache-control" ? response : setHeader(name, value));
        setHeader("Cache-Control", immutable ? "public, max-age=31536000, immutable" : "no-store");
        next();
      });
    }
  };
}

const INPUT_DIST = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../browser-ui/dist-embedded");
const INPUT_TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".woff2": "font/woff2",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".svg": "image/svg+xml"
};

/**
 * The embedded controller serves the secret-input page at `/` for a complete
 * signed link and its files under `/input/` (crates/blindpass-controller
 * embedded_ui.rs). `vite preview` mirrors that from the built browser-ui copy
 * (`packages/browser-ui` `npm run build`, which writes dist-embedded), so a fleet
 * Source link opened from the console lands on the real input page on the
 * console's own origin, where the operator's session cookie and the API proxy
 * apply. Without that build the link path answers 404, never the console shell.
 */
function embeddedInputPage(): Plugin {
  return {
    name: "blindpass-embedded-input-page",
    configurePreviewServer(server) {
      server.middlewares.use(async (request, response, next) => {
        if (request.method !== "GET" && request.method !== "HEAD") return next();
        const url = new URL(request.url ?? "/", "http://preview.local");
        const signed = url.pathname === "/" && ["id", "metadata_sig", "submit_sig"].every((name) => url.searchParams.has(name));
        const asset = url.pathname.startsWith("/input/");
        if (!signed && !asset) return next();
        const file = signed ? path.join(INPUT_DIST, "index.html") : path.join(INPUT_DIST, url.pathname.slice("/input".length));
        if (!file.startsWith(`${INPUT_DIST}${path.sep}`) || (asset && path.basename(file) === "index.html")) {
          response.statusCode = 404;
          response.end();
          return;
        }
        let body: Buffer;
        try {
          body = await readFile(file);
        } catch {
          response.statusCode = 404;
          response.end();
          return;
        }
        response.statusCode = 200;
        response.setHeader("Content-Type", INPUT_TYPES[path.extname(file)] ?? "application/octet-stream");
        response.setHeader("Content-Length", String(body.length));
        response.setHeader("Cache-Control", "no-store");
        for (const [name, value] of Object.entries(securityHeaders)) response.setHeader(name, value);
        response.setHeader("X-Frame-Options", "DENY");
        response.end(request.method === "HEAD" ? undefined : body);
      });
    }
  };
}

const proxy = {
  "/api": { target: controllerUrl, changeOrigin: false, xfwd: false },
  "/healthz": { target: controllerUrl, changeOrigin: false }
};

export default defineConfig({
  plugins: [react(), embeddedInputPage(), embeddedCacheProfile()],
  server: {
    host: "127.0.0.1",
    port: 5176,
    strictPort: true,
    proxy,
    headers: {
      "Referrer-Policy": "no-referrer",
      "X-Content-Type-Options": "nosniff"
    }
  },
  preview: {
    host: "127.0.0.1",
    port: 5176,
    strictPort: true,
    proxy,
    headers: securityHeaders
  },
  build: {
    target: "es2022",
    outDir: "dist",
    assetsDir: "assets",
    sourcemap: false,
    reportCompressedSize: true,
    chunkSizeWarningLimit: 400
  },
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
    include: ["src/**/*.test.{ts,tsx}"],
    restoreMocks: true
  }
});
