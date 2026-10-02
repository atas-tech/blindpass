# P05 broker recipient offer and Source admission — 2026-10-02

## Scope

PV06-B01–B05 were added to both authoritative vault plans before receiver code.
The [broker receiver](../../../crates/blindpass-broker/src/provisioning.rs) now
mints an ephemeral offer using its actual enrolled signing key and admits
controller-authorized ciphertext into volatile Source custody. Its new Unix
commands are wired into the production control listener. Host tests exercise
real identity/key files, Ed25519, HPKE and Unix frames with fixture grant/time
and original-workload authority. They do not establish real systemd/kernel
identity, controller operator authorization, live GUI or fleet relay acceptance.

## Authority and lifetime

An offer requires one current accepted browser grant, the original retained live
workload lease, current policy/registration, the fixed installed catalog/loader
mapping, matching enrolled node/key version and trusted controller time. The
offer signs the complete existing binding. Its collection window is capped by
the original local grant deadline, original signed grant expiry and the existing
configured recipient-key lifetime (30seconds by default). Exact mint retries keep the original ID, key,
signature and deadline. Expired/spent metadata remains until the original grant
deadline, so a retry cannot mint a successor key within that grant. The book
holds at most16 pending/spent records and never evicts a live offer for admission.

HPKE public-key encryption does not authenticate the sender. The distinct
`provisioning_delivery` document contains the complete original binding and
canonical encapsulation/ciphertext. The broker verifies its controller signature
and exact current issuer epoch before touching key custody; it separately checks
the current node key, original offer and current grant/destination/owner. The
future controller route must sign only after an authorized scoped submit commits.
The receiver signature check alone does not establish that missing route.

Initial admission spends the private key before opening/validating plaintext.
Authenticated corruption or invalid plaintext consumes that key and stores no
replacement Source. Foreign signatures/changed binding fail before consumption.
Source is nonempty exact UTF-8, at most64KiB, and enters only the protected broker
registry. Its lifetime is the independent configured Source custody TTL. The
existing private-helper path still rechecks manager identity and current authority
before exposing Source to its plaintext consumer. Neither input bytes nor
encryption failures are reflected in public results.

The broker's one-second custody sweep drops expired private keys and withdraws
keys whose grants are no longer candidates. Clock failure withdraws pending keys.
Each initial admission checks deadlines before and after opening. Successful
delivery retry acknowledges the exact signed receipt without a second open,
Source write or TTL renewal; this acknowledgement does not restore operation
authority. An authenticated changed receipt cannot reuse a spent key. Receipt
and pending keys are memory-only. Restart loses them and the retained original
workload lease; the old delivery cannot reconstruct either. Re-provision through
a new authorized request after loss. Durable relay reconciliation remains open.

## Unix contract

The existing control peer/group check applies before either command:

```text
BROWSER_OFFER <grant-id>\n
  → OFFER <length>\n<signed-public-offer-json>\n
PROVISION_SOURCE <length>\n<controller-signed-delivery-json>
  → OK browser_source_provisioned\n
  → OK browser_source_already_provisioned\n
  → ERR browser_provisioning_denied\n
```

The dedicated Source frame permits at most131072 encoded bytes, covering64KiB
plaintext plus HPKE/base64/binding/signature overhead. Other controller document
bounds remain64KiB. Lengths reject zero prefixes, overflow and oversized values;
partial data fails bounded reading. The output contains public offer metadata
or fixed status only. No controller/node/operator UI route uses this new contract
yet, and no external message was sent.

## Executed receiver checks

[Ten broker cases](../../../crates/blindpass-broker/src/provisioning_tests.rs)
and the capacity case in the receiver module pass on approved host execution:

| Portion | Executed assertion |
|---|---|
| PV06-B01/B02 | Actual enrolled key verifies the offer; exact retry unchanged; configured1.5s cap is honored and zero lifetime denies; authorized delivery preserves whitespace/newline Source; exact receipt retry does not re-open; consumed offer cannot remint |
| PV06-B02 capacity | Internal book fixture holds16 real private keys; new admission is denied and every original key still opens its own test ciphertext; not16 real systemd workloads |
| PV06-B03 | Foreign signature/changed destination does not consume the key; subsequent valid delivery succeeds; authenticated ciphertext corruption spends key and leaves original Source untouched |
| PV06-B04 | Cancellation, policy/catalog/node/offer-deadline fences deny before storage; periodic withdrawal cannot be reversed by restoring metadata; native identity rotation and changed controller epoch deny old delivery; restart fixture loses key/lease |
| PV06-B05 | Actual Unix control exchange preserves the complete64KiB Source, returns only fixed initial/retry statuses, denies invalid/oversized lengths and unsafe IDs, and rejects partial frames; empty/non-UTF8 plaintext spends the key without replacing Source |

Two [core delivery cases](../../../crates/blindpass-core/tests/provisioning_delivery.rs)
validate canonical signed-body round trip/original issuer epoch and reject
unknown/duplicate fields, short/zero encapsulation, empty/oversized/padded
ciphertext. The first broker run failed on absent receiver APIs; its red log is
retained. Tests use generated dummy Sources and private disposable key files;
they are not actual controller authorization or real kernel lease evidence.

### Full regression gates

| Gate | Actual result |
|---|---|
| Locked full Rust workspace, serial host execution | 489 passed, zero failed, four inherited ignores, explicit exit0 |
| All-target Clippy with warnings denied; Rust formatting | exit0 for both |
| Node24.21.0/26.10.0 build and ordinary workspace | exit0 for all four commands; 30 browser UI, 62 MCP and 110 helper/channel; 101 SPS skips per profile |
| Rebuilt native probe and actual browser/signature/HPKE matrix | 16 passed, zero skipped on each Node profile; sandboxed Chromium enabled |

The Rust ignores are three inherited Quickshell/desktop cases and the PostgreSQL
outage/recovery case. Default database coverage is SQLite. Neither those ignores
nor the101 service-gated SPS skips establish inherited acceptance. Source/log
SHA-256 snapshots and exact commands are in the
[structured runtime record](p05-runtime-foundations.json). Earlier signed-offer
hashes remain historical snapshots of files extended by this receiver slice.

## Remaining phase work

The controller/node must obtain and independently verify offers, enforce the
scoped operator link/metadata/submit transaction, persist ciphertext/receipt
once and reconcile signed delivery/acknowledgement. The actual input page and
operator app must use the trusted enrollment/context verification helper. Run
real GUI/controller/node/kernel identity, cancellation, rotation, deadline,
restart/replay/canary and stock-client delivery tests. Native/two-host backup,
full lifetime/retention, inherited acceptance and original release gates remain
required. No dependency graph or package boundary changed in this slice.


## Subsequent controller slice

[Controller offer ingestion](p05-controller-offers-2026-10-02.md) adds actual
HTTP/database destination bindings and public offer admission. The 489-case
receiver result and source hashes above are historical snapshots; the later
structured controller section carries current changed event/controller hashes.
Scoped submit, automatic publication, node ciphertext relay and GUI remain open.
