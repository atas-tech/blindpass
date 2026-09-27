# BlindPass approval app

A desktop application, separate from the Omarchy shell, where an operator signs in to a BlindPass controller and approves or rejects pending fleet operations and secret exchanges. It is Quickshell QML under [Decision 0001](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/decisions/0001-dashboard-ui-stack.md) and runs as its own process; the [Omarchy widget](../omarchy-widget/README.md) only shows a count and opens this app.

The app reads approval metadata only (`/api/v3/approvals`). No secret value, ciphertext or provisioning link passes through it.

## Run

```bash
ln -s "$PWD/desktop/approval-app/bin/blindpass-approvals" ~/.local/bin/   # once
blindpass-approvals                                                         # opens, or shows the running window
BLINDPASS_CONTROLLER_URL=https://controller.example blindpass-approvals     # preset the controller
```

Requirements: Quickshell 0.3 with Qt 6 (tested with Quickshell 0.3.1, Qt 6.11.2 on Omarchy 4.0.4), `curl` 7.84 or later and a POSIX shell. The controller address and language are saved in `$XDG_CONFIG_HOME/blindpass/approval-app.json`, which holds no credential.

## Session handling (P04-D3)

| What | Where | Lifetime |
|---|---|---|
| Password | The sign-in field and one `POST /api/v3/admin/session/login` with `kind: "desktop"` | Cleared from the field after every attempt |
| Access token | App memory only; sent as `Authorization: Bearer` without `Origin` | Rotated at start and every 15 minutes; the controller refuses it 20 minutes after it was issued, on logout, idle timeout, password change or reset, removal, or family revocation |
| Refresh token | `$XDG_RUNTIME_DIR/blindpass/session`, mode 0600 in a 0700 directory, written atomically by [`bin/blindpass-session-store`](bin/blindpass-session-store) from stdin | Used once per rotation. Deleted on sign-out and on any controller 401. A record for a different controller address is deleted without being sent |
| Widget summary | `$XDG_RUNTIME_DIR/blindpass/summary.json`: only `v`, `state`, `pending`, `updated_at` | Rewritten on every count poll (30 s) and state change |

- **Scope.** The controller accepts a desktop bearer only on session read, refresh and logout and on the `/api/v3/approvals` routes. An administrator's desktop session still can't administer operators, policy, nodes, grants or workloads. A request that carries `Origin` never takes the desktop path, so page script can't use these tokens. See the `desktopBearer` scheme in the [controller OpenAPI](../../docs/api/controller.openapi.yaml).
- **Temporary passwords.** A temporary password is refused at login (403 `password_change_required`) without creating a session. Change it in the console first.
- **Idle lock.** After 10 minutes without input in the window, the list and details are cleared from memory and decisions lock. The pending count keeps updating. To unlock, the operator enters the password: that is a fresh desktop login, and the previous session is revoked. A restart after 10 idle minutes opens locked.
- **Sign-out.** Revokes the session on the controller, deletes the file and publishes `signed_out`. If the controller can't be reached, the app says so and the access token expires within 20 minutes of its last rotation. The refresh token still exists server-side until its TTL or a family revocation.
- **Same-user limit.** A 0600 file and process separation don't protect the refresh token from other code running as the same desktop user. The app doesn't claim that boundary.

## Transport and trust (P04-D6)

Controller requests go through `curl -q --config -`: the request, including the bearer or password, is written to curl's stdin, so no credential appears in argv or the environment. The config:
- refuses redirects (`max-redirs 0`, and a 3xx is reported and not followed);
- ignores `~/.curlrc`;
- requires TLS 1.2 or later;
- verifies the CA chain and host name against the system trust store;
- allows `https` only, plus `http` for `127.0.0.1`, `localhost` and `[::1]`.

Qt's `XMLHttpRequest` isn't used, because it follows cross-origin redirects and forwards `Authorization`, and a 307 would re-send the login body. No certificate pin is configured, so trust rotation is the system CA store's.

## Decisions

The detail view leads with the recipient and scope taken from the controller's verified record:
- operation: `Broker on <node>` and `<action> for <unit> as <account> (<mode>)`;
- exchange: `Agent <requester>` and `One delivery of <secret>`.

The requester-written purpose is shown only as quoted plain text. Approve and Reject open a confirmation that repeats recipient and scope and focuses Cancel. Escape or Return on Cancel dismisses it, and no key approves.

On confirm, the app re-reads the approval and stops if its status, version or members changed. It then sends one decision with a fresh `Idempotency-Key` and `If-Match`. A missing reply is reported as unconfirmed and isn't resent automatically.

Named-approver and self-request blocks mirror the controller's rules; the controller re-checks both.

**Provisioning links (P04-D4) are not implemented.** No route mints an operator-scoped link for an approved operation, so the app shows no provisioning control. The open questions are recorded in the P04 evidence: who retrieves the ciphertext, its HPKE context/AAD, and how cancellation or key rotation invalidates the link.

## IPC

The only same-user IPC target is `blindpass-approvals` with `show()` and `hide()`. It exposes no approvals, decisions or session values (`quickshell ipc -p shell.qml show`).

## Layout and tests

| Path | Role |
|---|---|
| `shell.qml` | Quickshell entry: window, IPC, real transport and vault |
| `ApprovalApp.qml`, `ApprovalController.qml`, `ui/` | Views and state machine, plain QtQuick |
| `CurlTransport.qml`, `SessionVault.qml` | Quickshell-only transport and storage |
| `lib/` | Pure JavaScript: URL policy and curl format, display model, session policy, EN/VI strings, tokens from `assets/ui` |
| `e2e.qml` | Test-only scenario runner used by the Rust E2E; it sits here because Quickshell resolves types only inside the config folder |

```bash
npm run test:desktop                                                             # helper, QML suites, widget
cargo test -p blindpass-controller --test desktop_session                        # D3 transport
cargo test -p blindpass-controller --test desktop_app_e2e -- --ignored --nocapture   # app against a real controller
```

The QML view tests drive a scripted controller with real key and pointer events. The E2E test runs the real app offscreen, with its curl transport and helper, against an in-process Rust controller holding a real pending operation approval. It then checks the database and the files left behind. The Omarchy session itself isn't covered: no lock/logout/restart of a real Hyprland session, and no remote TLS controller. See the P04 evidence.
