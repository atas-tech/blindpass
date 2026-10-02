# P05 provisioning binding and cryptographic interoperability — 2026-10-02

## Scope

The P04-D4/P05-PV01–PV06 test details were added to both authoritative vault P05
plans before implementation. This slice implements the shared browser-source
binding and tests the actual existing HPKE engines across JavaScript and Rust.
P04-D4, signed broker offer, controller/operator/GUI routes, ciphertext relay,
one-use custody and integrated cancellation/key-rotation/restart remain open.
No fleet GUI action is enabled and no plaintext was sent to a controller.

This is the earlier binding slice. The later
[signed-offer component record](p05-signed-offer-2026-10-02.md) extends the shared
helpers and disposable probe with signatures and actual Chromium crypto checks.
The source hashes below describe the earlier snapshot. Actual broker minting,
operator GUI, relay and one-use custody remain open.

## Contract

[Rust](../../../crates/blindpass-core/src/provisioning.rs) and the separate
[browser helper](../../../packages/browser-ui/src/fleet-provisioning.js) validate
exact version1/browser-source metadata: full browser grant, node/key version,
original operation/workload/invocation/resource, offer ID/ephemeral public key,
fixed source unit/credential and original offer/grant deadlines. Canonical bytes
are prefixed with the explicit `blindpass:fleet-browser-source:v1` domain and a
zero byte. The existing X25519/HKDF-SHA256/ChaCha20-Poly1305 uses empty HPKE info
and those bytes as additional authenticated data. Legacy empty-AAD exchange
behavior is unchanged.

Only a current authenticated grant and enrolled broker offer may authorize the
future receiver. The core comparison function takes an already verified current
grant; matching metadata alone is not authorization. Source plaintext is consumed
by the operator browser and ultimately the trusted broker/helper. The browser
returns only ciphertext/encapsulation and wipes its temporary UTF-8 buffer.
Caller strings and browser memory are not forensically erased. The credential
is bounded64KiB and encoded exactly, including Unicode/whitespace. Metadata and
encryption errors have fixed messages and reflect no upstream private text.

## Executed evidence

| Scope | Executed assertion | Result |
|---|---|---|
| P05-PV01/PV02/PV03/PV04 component portions | Four Rust contract cases: canonical exact schema, ambiguous/unknown/unsafe metadata, mode/key/lifetime/current-grant fences and real HPKE changed-AAD authentication |4 pass |
| P05-PV01/PV02/PV03/PV04 browser-library portions | Five JavaScript cases: identical domain/canonical full grant bytes, schema/time/destination validation, real library HPKE exact bytes and fixed nested/accessor errors |5 pass |
| P05-PV01/PV04 actual library interoperability | Disposable Rust example generates its own private recipient key; JS seals, Rust opens. Canonical bytes match. Changed destination, operation, offer, recipient, empty AAD and truncation all reach HPKE opening and deny |7 pass on each Node24.21.0/26.10.0 |
| Full locked Rust workspace | `cargo test --workspace --locked -- --test-threads=1` on approved host |472 pass,4 inherited ignores, exit0 |
| All-target Rust lint | `cargo clippy --workspace --all-targets --locked -- -D warnings` |exit0 |
| Node26 full build/workspace | `npm run build`, `npm test` on approved host |exit0;27 browser UI,62 MCP and110 helper/channel cases;101 SPS skips |
| Node24 full build/workspace | Same commands with pinned24.21.0 `bin` in PATH |exit0; same case counts/skips |

The interoperability command is explicit after building its disposable example:

```bash
cargo build -p blindpass-core --example provisioning-hpke-probe --locked
node --test --test-isolation=none tests/browser-handoff/provisioning-hpke.test.mjs
```

It exercises the browser's library under Node, not Chromium UI. The example uses
a fixed dummy plaintext and fixture grant/time. It is not a live broker or
custody/clock/replay test. Private recipient keys stay inside the disposable
child and are never output. Normal output is public binding metadata followed
by a fixed accepted/denied stage; Source canary is absent. The complete command
and source/log hashes are recorded in the structured P05 runtime evidence.

First-red missing modules are retained. The first Rust test also had an incorrect
test call to the existing three-argument `open`; it was corrected before green.
Restricted Node execution reported only a file result and does not establish
case execution. The approved host reports all five cases. A meaningful private
error regression first reflected the generated canary, then passes with a plain
data snapshot and fixed errors.

The first cross-language attempt denied even the valid payload because its
fixture decoder used a maximum where the decoder expects an exact length.
Those initial negative results are not authentication evidence. The corrected
probe validates actual decoded length and reports fixed `stage=open` for all
cryptographic negative cases; the final positive/negative matrix passes.

The four Rust ignores remain the three inherited Quickshell/desktop checks and
the PostgreSQL outage/recovery gate. This default workspace run uses SQLite;
it does not establish the separately gated PostgreSQL profile. The101 SPS service skips remain
unexecuted. These are not full GUI or inherited acceptance evidence. No new
dependency, manifest or lockfile change was made. Native candidate dependency
review remains pending; no Go toolkit/restic/rest-server binary runs.

## Remaining integration

The broker must mint/sign and durably bind ephemeral offers; authenticated
controller/operator routes must issue the separately scoped signed input link,
admit ciphertext once and relay it to the original broker. The receiver must
consume its original key once, reject current cancellation/rotation/expiry and
validate source delivery before the private helper sees plaintext. Real GUI,
stock-client delivery/privacy, native/two-host and original lifetime/owner/
release gates remain required. Shared crypto tests do not close P04-D4 or P05.
