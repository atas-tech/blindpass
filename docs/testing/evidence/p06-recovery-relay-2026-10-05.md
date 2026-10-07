# P06 node recovery relay (component level) — 2026-10-05

**Status:** component and unit evidence (the real broker, verified-HTTPS and VM run is recorded in [p06-relay-vm-2026-10-05.md](p06-relay-vm-2026-10-05.md)) on the uncommitted tree above `8a595ad`. This implements the node side of RC09-RR03 (the relay between the broker control socket and the recovering controller). It does **not** establish RC09-RR03 "actual", RR04 on real nodes or RR05: no VM, no real broker daemon, no verified HTTPS exchange with a recovering controller ran. P06 acceptance remains false.

## Built

- `blindpass-node recovery-relay --controller <https-url> [--socket <path>]` (`crates/blindpass-node/src/recovery_relay.rs`, `main.rs`). It prints `recovery_relay state=<s> pages=<n> activation_permitted=false`.
- Flow: broker `RECOVERY_CHALLENGE` frame → node projects exactly the seven challenge fields into `{version:1,node_id,node_key_version,broker_challenge}` → `POST /api/recovery/request` → the controller's signed request bytes are forwarded to the broker unchanged as `RECOVERY_REPORT <len>\n<bytes>` → the broker's page frame is forwarded unchanged as `{body,broker_signature}` to `POST /api/recovery/page` → repeat while the status is `collecting`.
- The relay never interprets or re-signs the signed bytes and never forwards secrets: it sees only metadata. Status JSON with `activation_permitted:true` is refused.
- Bounds: 64 pages, 4096-byte challenge/request, 25 s overall deadline (the broker nonce lives 30 s), 3 s socket timeouts, 10 s HTTPS timeout. Failures map to fixed error strings; no peer text is echoed.
- Transport (`transport.rs`): `post_recovery_json` reaches exactly `/api/recovery/request` and `/api/recovery/page`, public POST only, HTTPS only, no redirect following, config on stdin. The authenticated `/api/v3/` path check is unchanged.

## Tests

`cargo test -p blindpass-node --locked --offline`: 33 bin tests plus 6 lib tests pass; clippy clean for the package.

- Frame parsing (binary length, no trailing newline, bounded), exact challenge projection, `activation_permitted:true` refusal, and rejection of unknown or missing fields.
- Unchanged-bytes relay over exactly the two paths, with stub broker and controller; a real `UnixListener` broker for the framing; partial and oversized page frames never reach the controller; static error strings.
- Transport: only the two recovery paths are reachable, HTTPS only, unauthenticated.
- `p06_rr04_a_failed_https_exchange_fails_closed_without_any_plaintext_fallback`: an unreachable HTTPS controller stops the relay after one broker frame; `http://` is refused.

**Test order.** The relay tests were written with stubs first (four red), but the transport tests and the implementation landed together, so they are not a full red/green record.

## Gates run

- `cargo fmt --all -- --check` and `cargo clippy --workspace --all-targets --locked --offline -- -D warnings`: clean.
- `cargo test --workspace --locked --offline`: 751 passed, 0 failed, 122 ignored (ignored cases run through the authority driver or in-image scripts and were not rerun for this change).
- `tests/deployment/{native-package-test,release-artifacts-test,container-config-test}.py`: pass. The native VM matrix, Compose gates and authority driver were not rerun after the node change.

## Limits

- No real broker or recovering controller. The stubs prove framing and byte preservation, not that a real broker signs pages the controller accepts.
- An actual verified-TLS relay cannot be exercised on the host: the node's curl runs with a cleared environment and trusts only the system CA store. RR05 needs a guest with CA trust (the P03 TLS-proxy harness is the starting point) and a recovering controller.
- RR04 fault cases beyond a failed HTTPS exchange (expired nonce, key rotation, restart, cache loss, TLS errors on a real path) are not run.
- No packaged systemd unit for the relay, and the native VM matrix was not rerun with the changed node binary.
- The deferred review item "caller-chosen `node_key_version` pinning" is not fixed: the controller still accepts the caller's value; the relay only sends the broker's.
- `status --nodes` now exists ([record](p06-status-nodes-2026-10-05.md)); migration scripts, slice 8 transfer tests and slice 9 remain open.
