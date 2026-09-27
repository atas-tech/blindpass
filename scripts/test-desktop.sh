#!/bin/sh
# P04 desktop surfaces (desktop/approval-app, desktop/omarchy-widget):
# the session-store helper, the QML library/view suites and the widget under
# Quickshell. The controller-backed approval-app E2E is a Rust test:
#   cargo test -p blindpass-controller --test desktop_app_e2e -- --ignored
set -eu
cd "$(dirname "$0")/.."
runner="${QMLTESTRUNNER:-/usr/lib/qt6/bin/qmltestrunner}"

node --test desktop/approval-app/tests/session-store.test.mjs

if [ ! -x "$runner" ]; then
  echo "test:desktop: SKIPPED QML suites — Qt 6 qmltestrunner not found at $runner (set QMLTESTRUNNER)" >&2
  exit 2
fi
export QT_QPA_PLATFORM=offscreen QT_FORCE_STDERR_LOGGING=1
"$runner" -input desktop/approval-app/tests
QML_XHR_ALLOW_FILE_READ=1 "$runner" -input desktop/omarchy-widget/tests

if ! command -v quickshell >/dev/null 2>&1; then
  echo "test:desktop: SKIPPED widget-under-Quickshell test — quickshell not found" >&2
  exit 2
fi
node --test desktop/omarchy-widget/tests/widget-e2e.test.mjs
