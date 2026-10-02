# P05 signed recipient offer components — 2026-10-02

## Scope

PV05-S01–S04 were defined in both authoritative P05 vault plans before this
implementation. Shared Rust signing, Rust/browser verification and verified
browser sealing now exist. Actual broker offer creation, authenticated operator
routes, signed links, ciphertext relay and one-use offer custody remain open.
These results do not close P04-D4 or full P05 acceptance.

The later [broker receiver slice](p05-broker-provisioning-2026-10-02.md) implements
offer minting and controller-signed ciphertext admission through the Unix control
listener. Its host tests use fixture grant/workload authority. Live controller
operator GUI/relay and real kernel acceptance remain open; this record's hashes
describe the earlier shared-signature snapshot.

## Contract and plaintext

The [core helpers](../../../crates/blindpass-core/src/provisioning.rs) sign the
validated browser-source binding as a version1 fleet document with distinct
`recipient_offer` kind, node-ID/key-version `kid`, and node-key-version epoch.
The existing canonical Ed25519 fleet-document domain is used. The complete
grant, ephemeral recipient key/offer, fixed destination and original deadlines
remain bound to the existing [HPKE AAD contract](p05-provisioning-2026-10-02.md).

The [browser helper](../../../packages/browser-ui/src/fleet-provisioning.js)
requires independently trusted enrolled signing key, current authorized grant,
key version and fixed destination. Offer-supplied data cannot replace that
context. It verifies before sealing, snapshots the binding and freezes the
returned binding/grant. Failure returns only `invalid_provisioning_offer`.
Production callers must still enforce current authorization and one-use custody.
The legacy exchange path retains its empty-AAD behavior.

Only the operator browser and recipient broker/helper consume Source plaintext.
This harness uses a fixed generated dummy Source and fixture grant/time. Rust
recipient/signing private keys stay inside an owned disposable child. Public
offer/context metadata and ciphertext cross the test channel. The browser wipes
its temporary UTF-8 buffer; caller strings/browser memory have no forensic
erasure guarantee. No real Source, bearer input link or external message is used.

## Executed checks

| Case | Evidence | Result |
|---|---|---|
| PV05-S01/S02 Rust signature | [Three core tests](../../../crates/blindpass-core/tests/provisioning_signed_offer.rs): round trip, fixed context, foreign key, altered body/kid, wrong kind/epoch/version and stale time | 3 pass |
| PV05-S02/S03 browser signature | [Three library tests](../../../packages/browser-ui/tests/fleet-provisioning-offer.test.mjs): immutable snapshot, strict envelope, signature mutation, independently pinned identity/context and original expiry | 3 pass on each Node profile through ordinary npm |
| PV05-S04 actual native signature | [Eight subprocess cases](../../../tests/browser-handoff/provisioning-offer-interoperability.test.mjs): Rust signature → WebCrypto → verified HPKE → Rust opening; seven altered/foreign/stale cases deny before ciphertext delivery | 8 pass per profile |
| PV05-S04 actual browser engine | [Sandboxed Chromium case](../../../tests/browser-handoff/provisioning-offer-chromium.test.mjs): secure localhost WebCrypto verifies native Ed25519, rejects tampering, preserves exact Unicode/whitespace Source and Rust opens; console/page errors absent | 1 pass per profile |
| Earlier HPKE interoperability rerun | Seven real library-to-Rust positive/negative exchanges, including changed AAD, wrong recipient, empty AAD and truncation | 7 pass per profile |
| Controller authority denial | [Unix control regression](../../../crates/blindpass-broker/src/control.rs): foreign node-style and pinned-controller-signed recipient offers both rejected; no request, lease or policy mutation | 1 pass |
| Both Node24.21.0/26.10.0 full gates | `npm run build`, `npm test` | exit0; 30 browser UI, 62 MCP, 110 helper/channel; 101 SPS cases skipped |
| Full final locked Rust workspace | `cargo test --workspace --locked -- --test-threads=1`, exact exit retained | 476 pass, 4 inherited ignores, exit0; SQLite default |
| Rust formatting and all-target lint | `cargo fmt --all -- --check`; `cargo clippy --workspace --all-targets --locked -- -D warnings` | exit0 |

The combined explicit browser/native matrix reports 16 passed, zero skipped on
each Node profile:

```bash
cargo build -p blindpass-core --example provisioning-hpke-probe --locked
node --test tests/browser-handoff/provisioning-hpke.test.mjs tests/browser-handoff/provisioning-offer-interoperability.test.mjs tests/browser-handoff/provisioning-offer-chromium.test.mjs
```

Chromium runs through the existing Playwright1.58.2 profile with its sandbox
enabled. The in-memory compiled MIT helper is served only on a disposable
loopback origin with restrictive CSP; tracing/video/HAR/capture are disabled.
This verifies browser engine crypto, not the actual operator GUI, TLS enrollment,
controller authority, live clock/rotation/restart or fleet custody.

Initial missing core/browser exports produced retained first-red logs. The
structured [runtime evidence](p05-runtime-foundations.json) records dated source
and log SHA-256 snapshots. Earlier provisioning hashes describe the earlier
binding slice, not current versions of the subsequently extended files. No
dependency, manifest or lockfile change was made in this slice.

The four Rust ignores are three inherited Quickshell/desktop cases and the
PostgreSQL outage/recovery case. The 101 SPS skips remain unexecuted; ordinary
green gates do not establish PostgreSQL, desktop or inherited acceptance.

## Remaining integration

The broker must mint and bind offers from its actual enrolled key and current
grant/catalog/retained workload. Operator metadata must obtain independent
enrollment and authorized context. Scoped link/submit and durable ciphertext
relay must preserve original expiry and atomically consume the original broker
key once. Cancellation, rotation, restart, loss and replay need actual GUI and
controller/node tests. All original stock-client delivery, native/two-host,
lifetime, inherited acceptance and release gates remain required.
