#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/install_skill.sh [options]

Options:
  --mode global|project          Install into user home config (global) or current workspace (project).
  --agent codex|claude|antigravity|openclaw|clawhub|all
                                 Target agent runtime(s). Default: all.
  --skip-build                   Skip `npm run build:skill`.
  --dry-run                      Print planned actions only.
  --yes                          Do not prompt before replacing existing installs.
  --help                         Show this help message.

Examples:
  scripts/install_skill.sh --mode global --agent codex
  scripts/install_skill.sh --mode project --agent all --dry-run
  scripts/install_skill.sh --agent clawhub
USAGE
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ -d "${ROOT_DIR}/packages/openclaw-plugin/dist" ]]; then
  INSTALL_LAYOUT="source"
  DIST_DIR="${ROOT_DIR}/packages/openclaw-plugin/dist"
elif [[ -d "${ROOT_DIR}/dist" ]]; then
  INSTALL_LAYOUT="dist-repo"
  DIST_DIR="${ROOT_DIR}/dist"
else
  INSTALL_LAYOUT="unknown"
  DIST_DIR="${ROOT_DIR}/packages/openclaw-plugin/dist"
fi

MODE="project"
AGENT="all"
SKIP_BUILD=0
DRY_RUN=0
ASSUME_YES=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)
      if [[ $# -lt 2 ]]; then
        echo "[blindpass] missing value for --mode" >&2
        exit 1
      fi
      MODE="$2"
      shift 2
      ;;
    --agent)
      if [[ $# -lt 2 ]]; then
        echo "[blindpass] missing value for --agent" >&2
        exit 1
      fi
      AGENT="$2"
      shift 2
      ;;
    --skip-build)
      SKIP_BUILD=1
      shift
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --yes)
      ASSUME_YES=1
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

case "$MODE" in
  global|project) ;;
  *)
    echo "[blindpass] invalid --mode: $MODE (expected global|project)" >&2
    exit 1
    ;;
esac

case "$AGENT" in
  codex|claude|antigravity|openclaw|clawhub|all) ;;
  *)
    echo "[blindpass] invalid --agent: $AGENT (expected codex|claude|antigravity|openclaw|clawhub|all)" >&2
    exit 1
    ;;
esac

ensure_dist_artifacts() {
  local required=(
    "${DIST_DIR}/blindpass.mjs"
    "${DIST_DIR}/index.mjs"
    "${DIST_DIR}/mcp-server.mjs"
    "${DIST_DIR}/THIRD_PARTY_NOTICES.md"
    "${DIST_DIR}/licenses/modelcontextprotocol-server-LICENSE"
    "${DIST_DIR}/licenses/modelcontextprotocol-core-LICENSE"
    "${DIST_DIR}/licenses/zod-LICENSE"
    "${DIST_DIR}/blindpass-resolver.mjs"
    "${DIST_DIR}/openclaw.plugin.json"
    "${DIST_DIR}/skills/blindpass/SKILL.md"
    "${DIST_DIR}/LICENSE"
  )

  local missing=0
  for path in "${required[@]}"; do
    if [[ ! -f "$path" ]]; then
      echo "[blindpass] missing required artifact: $path" >&2
      missing=1
    fi
  done

  if [[ "$missing" -ne 0 ]]; then
    echo "[blindpass] run npm run build:skill first (or omit --skip-build)." >&2
    exit 1
  fi
}

confirm_replace() {
  local target="$1"

  if [[ "$ASSUME_YES" -eq 1 || "$DRY_RUN" -eq 1 ]]; then
    return 0
  fi

  printf "[blindpass] '%s' already exists. Backup and replace? [y/N]: " "$target" >&2
  read -r answer
  case "$answer" in
    y|Y|yes|YES)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

install_payload() {
  local target="$1"
  local label="$2"
  local timestamp backup

  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "[blindpass] [dry-run] install ${label} -> ${target}"
    if [[ -d "$target" ]] && find "$target" -mindepth 1 -print -quit 2>/dev/null | grep -q '.'; then
      echo "[blindpass] [dry-run] existing target will be backed up before replace"
    fi
    return 0
  fi

  mkdir -p "$(dirname "$target")"

  if [[ -d "$target" ]] && find "$target" -mindepth 1 -print -quit 2>/dev/null | grep -q '.'; then
    if ! confirm_replace "$target"; then
      echo "[blindpass] skipped ${label}"
      return 0
    fi

    timestamp="$(date +%Y%m%d%H%M%S)"
    backup="${target}.backup-${timestamp}"
    mv "$target" "$backup"
    echo "[blindpass] backed up existing install: $backup"
  fi

  mkdir -p "$target/dist"
  mkdir -p "$target/skills/blindpass"
  mkdir -p "$target/scripts"

  cp "$DIST_DIR/blindpass.mjs" "$target/dist/blindpass.mjs"
  cp "$DIST_DIR/index.mjs" "$target/dist/index.mjs"
  cp "$DIST_DIR/mcp-server.mjs" "$target/dist/mcp-server.mjs"
  cp "$DIST_DIR/THIRD_PARTY_NOTICES.md" "$target/dist/THIRD_PARTY_NOTICES.md"
  cp -R "$DIST_DIR/licenses" "$target/dist/licenses"
  cp "$DIST_DIR/blindpass-resolver.mjs" "$target/dist/blindpass-resolver.mjs"

  cp "$DIST_DIR/openclaw.plugin.json" "$target/openclaw.plugin.json"
  cp "$DIST_DIR/skills/blindpass/SKILL.md" "$target/SKILL.md"
  cp "$DIST_DIR/skills/blindpass/SKILL.md" "$target/skills/blindpass/SKILL.md"
  cp "$DIST_DIR/LICENSE" "$target/LICENSE"
  cp "$ROOT_DIR/scripts/install_skill.sh" "$target/scripts/install_skill.sh"

  chmod +x "$target/dist/mcp-server.mjs" "$target/dist/blindpass-resolver.mjs" "$target/scripts/install_skill.sh"

  echo "[blindpass] installed ${label} -> ${target}"
}

target_path_for_agent() {
  local agent="$1"

  if [[ "$MODE" == "global" ]]; then
    case "$agent" in
      codex) echo "$HOME/.codex/skills/blindpass" ;;
      claude) echo "$HOME/.claude/skills/blindpass" ;;
      antigravity) echo "$HOME/.gemini/skills/blindpass" ;;
      openclaw) echo "$HOME/.openclaw/skills/blindpass" ;;
      *) return 1 ;;
    esac
  else
    case "$agent" in
      codex) echo "$ROOT_DIR/.codex/skills/blindpass" ;;
      claude) echo "$ROOT_DIR/.claude/skills/blindpass" ;;
      antigravity) echo "$ROOT_DIR/.gemini/skills/blindpass" ;;
      openclaw) echo "$ROOT_DIR/.openclaw/skills/blindpass" ;;
      *) return 1 ;;
    esac
  fi
}

install_clawhub() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "[blindpass] [dry-run] clawhub install command: openclaw skills install blindpass"
    return 0
  fi

  if ! command -v openclaw >/dev/null 2>&1; then
    echo "[blindpass] openclaw CLI not found on PATH; cannot run clawhub install" >&2
    echo "[blindpass] run manually: openclaw skills install blindpass" >&2
    return 1
  fi

  openclaw skills install blindpass
  echo "[blindpass] installed via ClawHub"
}

if [[ "$SKIP_BUILD" -eq 0 ]]; then
  if [[ "$INSTALL_LAYOUT" == "source" ]]; then
    npm run build:skill
  elif [[ "$INSTALL_LAYOUT" == "dist-repo" ]]; then
    echo "[blindpass] dist-repo layout detected; skipping build step (prebuilt dist artifacts expected)."
  else
    echo "[blindpass] unable to determine install layout from ROOT_DIR: $ROOT_DIR" >&2
    exit 1
  fi
fi

ensure_dist_artifacts

install_agent() {
  local agent="$1"

  if [[ "$agent" == "clawhub" ]]; then
    install_clawhub
    return 0
  fi

  local target
  target="$(target_path_for_agent "$agent")"
  install_payload "$target" "$agent"
}

if [[ "$AGENT" == "all" ]]; then
  install_agent codex
  install_agent claude
  install_agent antigravity
  install_agent openclaw
  echo "[blindpass] note: ClawHub install is not included in --agent all. Use --agent clawhub when needed."
else
  install_agent "$AGENT"
fi

if [[ "$AGENT" == "codex" || "$AGENT" == "all" ]]; then
  echo "[blindpass] codex MCP path: <install-root>/dist/mcp-server.mjs"
fi
if [[ "$AGENT" == "claude" || "$AGENT" == "all" ]]; then
  echo "[blindpass] claude MCP path: <install-root>/dist/mcp-server.mjs"
fi
if [[ "$AGENT" == "antigravity" || "$AGENT" == "all" ]]; then
  echo "[blindpass] antigravity MCP path: <install-root>/dist/mcp-server.mjs"
fi
if [[ "$AGENT" == "openclaw" || "$AGENT" == "all" ]]; then
  echo "[blindpass] openclaw plugin path: <install-root>/dist/blindpass.mjs"
fi
