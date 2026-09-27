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

const proxy = {
  "/api": { target: controllerUrl, changeOrigin: false, xfwd: false },
  "/healthz": { target: controllerUrl, changeOrigin: false }
};

export default defineConfig({
  plugins: [react(), embeddedCacheProfile()],
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
