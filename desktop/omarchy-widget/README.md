# BlindPass Omarchy widget

An Omarchy bar widget (`blindpass.approvals`) showing how many BlindPass approvals are waiting. Clicking it opens the separate [approval app](../approval-app/README.md), where signing in and deciding happen.

The widget runs inside `omarchy-shell`, whose QML scene other plugins can traverse. It therefore holds nothing worth taking:
- It reads only `$XDG_RUNTIME_DIR/blindpass/summary.json`, which the approval app writes. Of that file it uses only `v`, `state`, `pending` and `updated_at`, and ignores anything else.
- It never reads the session file, never contacts the controller and has no approval, provisioning or credential path.
- Its one action runs the configured open command, `blindpass-approvals` by default.

It isn't an OS security boundary: same-user code can already read the app's files.

| State | Shown |
|---|---|
| `ready` with requests waiting | Padlock and count in lime |
| `ready`, nothing waiting | Padlock only |
| `locked` | Padlock and count; tooltip says the app is locked |
| `signed_out` | Dim padlock, no count |
| `unreachable` | Amber padlock |
| No summary, a stale one (over 90 s) or an unknown state | Dim padlock; tooltip says the app isn't running. Set `hideWhenNotRunning` to hide it instead |

## Install

```bash
ln -s "$PWD/desktop/omarchy-widget" ~/.config/omarchy/plugins/blindpass.approvals
omarchy-shell shell rescanPlugins
omarchy plugin enable blindpass.approvals
```

Put `desktop/approval-app/bin/blindpass-approvals` on `PATH`, or set the widget's `launchCommand`.

## Tests

`npm run test:desktop` runs [`tests/tst_summary.qml`](tests/tst_summary.qml) and [`tests/widget-e2e.test.mjs`](tests/widget-e2e.test.mjs).
- The QML suite covers the summary reader, including stale, future, malformed and extra-field input. It also inspects the widget source and fails on any reference to the session file, the helper, `Authorization`, curl, controller routes, XHR, `Process` or IPC.
- The Node test loads `Widget.qml` under Quickshell, with a stand-in for the bar, through [`e2e.qml`](e2e.qml). It checks that the widget follows summaries written by the real helper, marks a stale summary as not running, and runs the open command only on a click.

Placement in a live Omarchy bar, and lock/logout/restart of a real session, aren't covered.
