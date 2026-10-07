#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLUGIN_DIR="${ROOT_DIR}/packages/openclaw-plugin"
DIST_DIR="${PLUGIN_DIR}/dist"

if [[ -n "${BLINDPASS_BUNDLE_OUT:-}" ]]; then
  # Verification builds write beside the shared dist, never into a directory that already holds files.
  DIST_DIR="$(realpath -m "${BLINDPASS_BUNDLE_OUT}")"
  if [[ -d "${DIST_DIR}" && -n "$(ls -A "${DIST_DIR}")" ]]; then
    echo "[blindpass] BLINDPASS_BUNDLE_OUT is not empty: ${DIST_DIR}" >&2
    exit 1
  fi
else
  rm -rf "${DIST_DIR}"
fi
mkdir -p "${DIST_DIR}/skills"

echo "[blindpass] building workspace dependencies for bundle inputs..."
(cd "${ROOT_DIR}" && npm run build --workspace=packages/gateway)
(cd "${ROOT_DIR}" && npm run build --workspace=packages/agent-skill)

# P07 F-3: the published bundle has no default SPS endpoint. The define folds the legacy default away in the
# bundles; the manifest copy below drops the declared default. The unbundled OpenClaw plugin keeps both.
echo "[blindpass] bundling plugin entrypoints with esbuild..."
(cd "${ROOT_DIR}" && npx --yes esbuild "${PLUGIN_DIR}/blindpass-core.mjs" \
  --bundle \
  --platform=node \
  --format=esm \
  --target=node20 \
  --minify \
  --define:__BLINDPASS_REQUIRE_EXPLICIT_SPS__=true \
  --outfile="${DIST_DIR}/blindpass.mjs")

MCP_BUNDLE_METADATA=$(mktemp /tmp/blindpass-mcp-bundle-metadata.XXXXXXXX)
RESOLVER_BUNDLE_METADATA=$(mktemp /tmp/blindpass-resolver-bundle-metadata.XXXXXXXX)
MIGRATE_BUNDLE_METADATA=$(mktemp /tmp/blindpass-migrate-bundle-metadata.XXXXXXXX)
trap 'rm -f -- "$MCP_BUNDLE_METADATA" "$RESOLVER_BUNDLE_METADATA" "$MIGRATE_BUNDLE_METADATA"' EXIT
(cd "${ROOT_DIR}" && npx --yes esbuild "${PLUGIN_DIR}/mcp-server.mjs" \
  --bundle \
  --platform=node \
  --format=esm \
  --target=node20 \
  --minify \
  --define:__BLINDPASS_REQUIRE_EXPLICIT_SPS__=true \
  --metafile="${MCP_BUNDLE_METADATA}" \
  --banner:js='#!/usr/bin/env node
import { createRequire as blindpassCreateRequire } from "node:module"; const require = blindpassCreateRequire(import.meta.url);' \
  --outfile="${DIST_DIR}/mcp-server.mjs")

# The resolver imports ./encrypted-store.mjs, so copying it alone ships a bin that fails with
# ERR_MODULE_NOT_FOUND on a clean host; bundle it like the other entrypoints.
(cd "${ROOT_DIR}" && npx --yes esbuild "${PLUGIN_DIR}/blindpass-resolver.mjs" \
  --bundle \
  --platform=node \
  --format=esm \
  --target=node20 \
  --minify \
  --define:__BLINDPASS_REQUIRE_EXPLICIT_SPS__=true \
  --metafile="${RESOLVER_BUNDLE_METADATA}" \
  --banner:js='#!/usr/bin/env node' \
  --outfile="${DIST_DIR}/blindpass-resolver.mjs")

# P09: the OpenClaw credential migration CLI. The bin source starts with its own shebang, which esbuild
# keeps, so no banner is added. It bundles the vendored credential matrix and encrypted-store.mjs only.
(cd "${ROOT_DIR}" && npx --yes esbuild "${PLUGIN_DIR}/bin/blindpass-openclaw-migrate" \
  --bundle \
  --platform=node \
  --format=esm \
  --target=node20 \
  --minify \
  --metafile="${MIGRATE_BUNDLE_METADATA}" \
  --outfile="${DIST_DIR}/blindpass-openclaw-migrate.mjs")

cat > "${DIST_DIR}/index.mjs" <<'EOF'
export { default } from "./blindpass.mjs";
export * from "./blindpass.mjs";
EOF

node "${ROOT_DIR}/scripts/strip-sps-default.mjs" "${PLUGIN_DIR}/openclaw.plugin.json" "${DIST_DIR}/openclaw.plugin.json"
cp "${PLUGIN_DIR}/LICENSE" "${DIST_DIR}/LICENSE"
cp "${ROOT_DIR}/packages/mcp-server/THIRD_PARTY_NOTICES.md" "${DIST_DIR}/THIRD_PARTY_NOTICES.md"
cp -R "${ROOT_DIR}/packages/mcp-server/licenses" "${DIST_DIR}/licenses"
node "${ROOT_DIR}/scripts/bundle-mcp-notices.mjs" "$MCP_BUNDLE_METADATA" "$RESOLVER_BUNDLE_METADATA" "$MIGRATE_BUNDLE_METADATA" "$DIST_DIR"
cp -R "${PLUGIN_DIR}/skills/blindpass" "${DIST_DIR}/skills/blindpass"

chmod +x "${DIST_DIR}/mcp-server.mjs" "${DIST_DIR}/blindpass-resolver.mjs" "${DIST_DIR}/blindpass-openclaw-migrate.mjs"

echo "[blindpass] bundle staged in ${DIST_DIR}"
