#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/publish_dist.sh [options]

Builds BlindPass distribution artifacts, stages a dist-repo layout, and can
optionally sync/push to a dist repository and publish release channels.

Options:
  --stage-dir <dir>             Stage output directory (default: temp dir)
  --repo-dir <dir>              Existing dist-repo working tree to sync
  --branch <name>               Branch to push when --push is used (default: main)
  --skip-build                  Skip npm run build:skill
  --skip-validate               Skip publish_clawhub dry-run validation gate
  --push                        Commit + push synced changes in --repo-dir
  --publish-clawhub             Run clawhub publish from stage dir
  --publish-npm                 Run npm publish from stage dir
  --npm-tag <tag>               npm publish tag (default: latest)
  --yes                         Non-interactive overwrite/sync confirmation
  --dry-run                     Print actions without mutating files or publishing
  --help                        Show this help text

Examples:
  scripts/publish_dist.sh --dry-run
  scripts/publish_dist.sh --repo-dir ../blindpass-skill --yes --push
  scripts/publish_dist.sh --publish-clawhub --publish-npm
USAGE
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLUGIN_DIR="${ROOT_DIR}/packages/openclaw-plugin"
DIST_DIR="${PLUGIN_DIR}/dist"
SKILL_FILE="${PLUGIN_DIR}/skills/blindpass/SKILL.md"
PLUGIN_MANIFEST_JSON="${PLUGIN_DIR}/openclaw.plugin.json"
PLUGIN_LICENSE_FILE="${PLUGIN_DIR}/LICENSE"

STAGE_DIR=""
REPO_DIR=""
TARGET_BRANCH="main"
SKIP_BUILD=0
SKIP_VALIDATE=0
DO_PUSH=0
DO_PUBLISH_CLAWHUB=0
DO_PUBLISH_NPM=0
NPM_TAG="latest"
ASSUME_YES=0
DRY_RUN=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --stage-dir)
      if [[ $# -lt 2 ]]; then
        echo "[blindpass] missing value for --stage-dir" >&2
        exit 1
      fi
      STAGE_DIR="$2"
      shift 2
      ;;
    --repo-dir)
      if [[ $# -lt 2 ]]; then
        echo "[blindpass] missing value for --repo-dir" >&2
        exit 1
      fi
      REPO_DIR="$2"
      shift 2
      ;;
    --branch)
      if [[ $# -lt 2 ]]; then
        echo "[blindpass] missing value for --branch" >&2
        exit 1
      fi
      TARGET_BRANCH="$2"
      shift 2
      ;;
    --skip-build)
      SKIP_BUILD=1
      shift
      ;;
    --skip-validate)
      SKIP_VALIDATE=1
      shift
      ;;
    --push)
      DO_PUSH=1
      shift
      ;;
    --publish-clawhub)
      DO_PUBLISH_CLAWHUB=1
      shift
      ;;
    --publish-npm)
      DO_PUBLISH_NPM=1
      shift
      ;;
    --npm-tag)
      if [[ $# -lt 2 ]]; then
        echo "[blindpass] missing value for --npm-tag" >&2
        exit 1
      fi
      NPM_TAG="$2"
      shift 2
      ;;
    --yes)
      ASSUME_YES=1
      shift
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --help)
      usage
      exit 0
      ;;
    *)
      echo "[blindpass] unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ "$DO_PUSH" -eq 1 && -z "$REPO_DIR" ]]; then
  echo "[blindpass] --push requires --repo-dir pointing to a git checkout" >&2
  exit 1
fi

if [[ "$DO_PUSH" -eq 1 && "$DRY_RUN" -eq 1 ]]; then
  echo "[blindpass] --push with --dry-run is allowed; push will be printed only"
fi

read_skill_version() {
  awk '
    BEGIN { in_frontmatter = 0; found = 0 }
    NR == 1 && $0 == "---" { in_frontmatter = 1; next }
    in_frontmatter && $0 == "---" { exit }
    in_frontmatter && $1 == "version:" {
      line = $0
      sub(/^version:[[:space:]]*"?/, "", line)
      sub(/"?[[:space:]]*$/, "", line)
      print line
      found = 1
      exit
    }
    END { if (!found) exit 1 }
  ' "$SKILL_FILE"
}

skill_version="$(read_skill_version)"

read_plugin_manifest_version() {
  node -e '
    const fs = require("fs");
    const manifestPath = process.argv[1];
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    if (!manifest.version || typeof manifest.version !== "string") {
      process.exit(1);
    }
    process.stdout.write(manifest.version);
  ' "$PLUGIN_MANIFEST_JSON"
}

plugin_manifest_version="$(read_plugin_manifest_version)"
if [[ "$skill_version" != "$plugin_manifest_version" ]]; then
  echo "[blindpass] version mismatch detected:" >&2
  echo "  SKILL.md version:          $skill_version" >&2
  echo "  openclaw.plugin.json:      $plugin_manifest_version" >&2
  echo "[blindpass] keep release metadata synchronized before publishing." >&2
  exit 1
fi

ensure_dist_artifacts() {
  local required=(
    "${DIST_DIR}/blindpass.mjs"
    "${DIST_DIR}/index.mjs"
    "${DIST_DIR}/mcp-server.mjs"
    "${DIST_DIR}/blindpass-resolver.mjs"
    "${DIST_DIR}/openclaw.plugin.json"
    "${DIST_DIR}/skills/blindpass/SKILL.md"
    "${DIST_DIR}/LICENSE"
  )
  local missing=0
  for path in "${required[@]}"; do
    if [[ ! -f "$path" ]]; then
      echo "[blindpass] missing dist artifact: $path" >&2
      missing=1
    fi
  done
  if [[ "$missing" -ne 0 ]]; then
    exit 1
  fi
}

confirm_or_exit() {
  local prompt="$1"
  if [[ "$ASSUME_YES" -eq 1 || "$DRY_RUN" -eq 1 ]]; then
    return 0
  fi

  printf "%s [y/N]: " "$prompt" >&2
  read -r answer
  case "$answer" in
    y|Y|yes|YES) return 0 ;;
    *)
      echo "[blindpass] aborted by user" >&2
      exit 1
      ;;
  esac
}

copy_if_exists() {
  local src="$1"
  local dest="$2"
  if [[ -e "$src" ]]; then
    mkdir -p "$(dirname "$dest")"
    cp -R "$src" "$dest"
  else
    echo "[blindpass] warning: optional file missing, skipped: $src"
  fi
}

generate_dist_package_json() {
  local target="$1"

  cat > "$target" <<JSON
{
    "name": "@blindpass/mcp-server",
    "version": "${skill_version}",
    "private": false,
    "license": "MIT",
    "type": "module",
    "description": "BlindPass MCP server and OpenClaw plugin distribution artifacts.",
    "bin": {
        "blindpass-mcp-server": "./dist/mcp-server.mjs",
        "blindpass-resolver": "./dist/blindpass-resolver.mjs"
    },
    "files": [
        "dist",
        "SKILL.md",
        "AGENTS.md",
        "agents",
        "openclaw.plugin.json",
        "scripts",
        "LICENSE",
        "README.md"
    ]
}
JSON
}

prepare_stage_layout() {
  local stage="$1"

  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "[blindpass] [dry-run] stage dist layout at: $stage"
    return 0
  fi

  rm -rf "$stage"
  mkdir -p "$stage"
  mkdir -p "$stage/scripts"

  cp -R "$DIST_DIR" "$stage/dist"
  cp "$DIST_DIR/skills/blindpass/SKILL.md" "$stage/SKILL.md"
  cp "$PLUGIN_MANIFEST_JSON" "$stage/openclaw.plugin.json"
  cp "$PLUGIN_LICENSE_FILE" "$stage/LICENSE"
  cp "$ROOT_DIR/scripts/install_skill.sh" "$stage/scripts/install_skill.sh"

  # Optional agent-specific instructions/configs are copied when present.
  copy_if_exists "$ROOT_DIR/AGENTS.md" "$stage/AGENTS.md"
  copy_if_exists "$ROOT_DIR/agents" "$stage/agents"
  copy_if_exists "$ROOT_DIR/README.md" "$stage/README.md"

  generate_dist_package_json "$stage/package.json"

  chmod +x "$stage/scripts/install_skill.sh" "$stage/dist/mcp-server.mjs" "$stage/dist/blindpass-resolver.mjs"
}

sync_stage_to_repo() {
  local stage="$1"
  local repo="$2"

  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "[blindpass] [dry-run] sync stage -> repo: $stage -> $repo"
    return 0
  fi

  if [[ ! -d "$repo" ]]; then
    echo "[blindpass] repo directory does not exist: $repo" >&2
    exit 1
  fi

  confirm_or_exit "[blindpass] Sync staged release into '$repo' (existing files may be overwritten)?"

  if command -v rsync >/dev/null 2>&1; then
    rsync -a --delete --exclude '.git' "$stage"/ "$repo"/
  else
    echo "[blindpass] warning: rsync not found, using cp fallback (no delete sync)."
    cp -R "$stage"/. "$repo"/
  fi

  echo "[blindpass] synced staged files into repo: $repo"
}

push_repo_changes() {
  local repo="$1"
  local version="$2"
  local branch="$3"

  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "[blindpass] [dry-run] git -C '$repo' add -A"
    echo "[blindpass] [dry-run] git -C '$repo' commit -m 'chore(release): sync blindpass skill v${version}'"
    echo "[blindpass] [dry-run] git -C '$repo' push origin '$branch'"
    return 0
  fi

  if [[ ! -d "$repo/.git" ]]; then
    echo "[blindpass] --push requires a git repo at: $repo" >&2
    exit 1
  fi

  git -C "$repo" add -A
  if git -C "$repo" diff --cached --quiet; then
    echo "[blindpass] no staged changes to commit in $repo"
    return 0
  fi

  git -C "$repo" commit -m "chore(release): sync blindpass skill v${version}"
  git -C "$repo" push origin "$branch"
  echo "[blindpass] pushed dist repo changes to origin/$branch"
}

publish_clawhub_from_stage() {
  local stage="$1"

  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "[blindpass] [dry-run] (cd '$stage' && clawhub publish)"
    return 0
  fi

  if ! command -v clawhub >/dev/null 2>&1; then
    echo "[blindpass] clawhub CLI not found on PATH" >&2
    exit 1
  fi

  (
    cd "$stage"
    clawhub publish
  )

  echo "[blindpass] clawhub publish complete"
}

publish_npm_from_stage() {
  local stage="$1"
  local tag="$2"

  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "[blindpass] [dry-run] (cd '$stage' && npm publish --tag '$tag' --access public)"
    return 0
  fi

  (
    cd "$stage"
    npm publish --tag "$tag" --access public
  )

  echo "[blindpass] npm publish complete"
}

if [[ "$SKIP_BUILD" -eq 0 ]]; then
  npm run build:skill
fi

ensure_dist_artifacts

if [[ "$SKIP_VALIDATE" -eq 0 ]]; then
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "[blindpass] [dry-run] validation gate: scripts/publish_clawhub.sh --dry-run --skip-build"
  else
    bash "$ROOT_DIR/scripts/publish_clawhub.sh" --dry-run --skip-build
  fi
fi

if [[ -z "$STAGE_DIR" ]]; then
  STAGE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/blindpass-dist-${skill_version}-XXXXXX")"
fi

prepare_stage_layout "$STAGE_DIR"

echo "[blindpass] staged distribution at: $STAGE_DIR"

if [[ -n "$REPO_DIR" ]]; then
  sync_stage_to_repo "$STAGE_DIR" "$REPO_DIR"
  if [[ "$DO_PUSH" -eq 1 ]]; then
    push_repo_changes "$REPO_DIR" "$skill_version" "$TARGET_BRANCH"
  fi
fi

if [[ "$DO_PUBLISH_CLAWHUB" -eq 1 ]]; then
  publish_clawhub_from_stage "$STAGE_DIR"
fi

if [[ "$DO_PUBLISH_NPM" -eq 1 ]]; then
  publish_npm_from_stage "$STAGE_DIR" "$NPM_TAG"
fi

if [[ "$DO_PUSH" -eq 0 && "$DO_PUBLISH_CLAWHUB" -eq 0 && "$DO_PUBLISH_NPM" -eq 0 ]]; then
  echo "[blindpass] no publish actions requested."
  echo "[blindpass] next steps:"
  echo "  1) sync staged files to dist repo checkout"
  echo "  2) run with --repo-dir <path> --push"
  echo "  3) optionally add --publish-clawhub and/or --publish-npm"
fi
