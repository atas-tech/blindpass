# P05 controller recipient offer ingestion — 2026-10-02

## Implemented scope

PV06-C01–C07 were added to the authoritative paired vault plan before their
implementation. The controller now stores an independent administrator source
destination and admits signed public broker offers over its actual authenticated
node HTTP channel. The [store](../../../crates/blindpass-controller/src/store/provisioning.rs),
[destination routes](../../../crates/blindpass-controller/src/routes/provisioning.rs)
and [HTTP tests](../../../crates/blindpass-controller/tests/fleet_provisioning_offers.rs)
use existing reviewed dependencies. No package or dependency graph changed.

This slice does not collect Source. The controller/node see public recipient
offer metadata only; no plaintext consumer or recipient private key is introduced.
The [broker receiver](p05-broker-provisioning-2026-10-02.md) retains volatile
one-use keys and independent Source custody. Its later private-helper delivery
still requires current workload/manager authority. Neither this HTTP suite nor
public offer persistence establishes real Root/systemd or operator GUI behavior.

## Trust and persistence

`GET`/`PUT /api/v3/nodes/{node_id}/source-bindings/{resource_id}` require an
administrator browser cookie. `PUT` also requires Origin/CSRF, valid fixed unit
and credential names and the expected binding version: 0 creates; a current
positive version updates. Node inactive/pending rotation/revocation or a stale
version returns 409. No Source, operator URL or arbitrary receiver key is accepted.
The configured destination must independently match the installed broker catalog.
The console has no binding editor yet; these are actual HTTP APIs.

A `recipient_offer` node event contains the broker-signed `recipient_offer`
envelope. The outer event signature must first verify under node-session
transport. The store transaction then locks current authority and independently
recovers/verifies the original full controller-signed grant from retained inbox
evidence. It uses current enrolled signing key/version and administrator
unit/credential to verify the inner offer. Active node/workload, current
registration/policy, granted operation, unconsumed issued/delivered grant,
current issuer, original request/invocation/resource and original deadlines must
match. An offer cannot supply its own trusted grant/key/destination/expiry.
The checked database clock is sampled again after authority locks, so a lock
wait cannot extend the original collection window.

Offer, exact authenticated event receipt and safe audit commit together. Failed
writes roll everything back. Exact/concurrent replay retains one original
recipient/deadline; changed bytes and successor offers cannot replace it. A
retained receipt cannot reconstruct deleted offer metadata, even under a new
event key. Existing correctly signed irrecoverable-event handling remains: a
fixed discarded result and signed ACK prevent queue stalling; no admitted-offer
receipt is written. Rejection audit contains safe identifiers/reason only.
Current issuer changes fence the old node session before ingestion.

Schema 15 adds `fleet_source_bindings` and `fleet_provisioning_offers`. Upgrading
from 14 preserves its hashed sessions; reported 15 with missing tables fails
closed. Older controllers require a matching database backup to roll back.
Public offer metadata prunes seven days after original expiry, with the existing
maintenance cap of 1,000 rows per pass. The execution checks one live/expired row
and repeated pruning, not 1,000/10,000 concurrent workflows. Neither a sweep nor
persisted metadata renews authority. Later link/metadata/submit must recheck the
stored binding version and current authority; those routes are still absent.

## Actual checks

| Gate | Actual result |
|---|---|
| New real HTTP/transaction suite on SQLite | 11 passed, zero failed/ignored |
| Same suite on isolated PostgreSQL schemas | 11 passed, zero failed/ignored |
| Affected PostgreSQL store transitions, session/security, retention, browser intents and operations | 71 passed, zero failed/ignored |
| Locked full Rust workspace, serial host execution | 500 passed, zero failed, 4 inherited ignores, exact exit0 |
| All-target Clippy with warnings denied; Rust formatting | exit0 for both |
| Both pinned Node 24.21.0/26.10.0 full build/workspace gates | exit 0; 30 browser UI, 62 MCP, 110 helper/channel; 101 SPS skips per profile |
| OpenAPI mounted-route/security/generated-types gate | 13 passed, zero failed/skipped |

The new suite covers administrator/viewer/operator/CSRF denial, identifiers,
optimistic versioning, actual enrollment and grant issuance, inner foreign
signature/destination/grant/key/time mismatch, missing original grant evidence,
consumed/revoked/expired grants, cancellation, registration/policy/unit/issuer
changes, tenant isolation, pending node revocation and actual HTTP rotation
initiation, concurrent replay, controller storage reopen and deletion replay.
Injected SQLite/PostgreSQL failures at offer/receipt/audit writes prove atomic
rollback/retry. A 450ms database lock exceeds a 250ms original offer window and
denies admission on both backends. These are actual database locks, not simulated
wall-clock/suspend or full phase lifetime evidence. The schema and retention
checks are executed on both backends. Native key rotation completion and Root
custody are separately scoped to the earlier broker receiver checks.

The first-red missing-API and missing-retention-field logs and API-contract red
log are retained. Early test corrections aligned existing 401 issuer fencing,
202 asynchronous rotation and replacement-key fingerprint contracts; only the
final passing logs establish this slice. Full regression also caught two stale
schema 14 assertions, now tied to the current schema constant; red logs remain.
One earlier broad PostgreSQL attempt received an HTTP 408 before enrollment
completed; the isolated existing concurrent-intent case then passed. Its failed
log and diagnostic remain, and only the fresh broad passing run counts in the gate table above.
No privileged service-credit rejection occurred. No external message, native candidate toolkit or backup binary ran.

## Commands and evidence

From repository root, approved host loopback execution:

```bash
cargo test -p blindpass-controller --test fleet_provisioning_offers --locked -- --test-threads=1
P02_TEST_BACKEND=postgres P02_TEST_POSTGRES_URL='<disposable-url>' cargo test -p blindpass-controller --test fleet_provisioning_offers --locked -- --test-threads=1
P02_TEST_BACKEND=postgres P02_TEST_POSTGRES_URL='<disposable-url>' cargo test -p blindpass-controller --test store_transitions --test security_perf_regressions --test fleet_lifecycle --test fleet_browser_intents --test fleet_browser_operations --locked -- --test-threads=1
npm run generate:api
npm run test:controller-openapi
npm run build
npm test
cargo test --workspace --locked -- --test-threads=1
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo fmt --all -- --check
```

Run the npm gates under each pinned Node profile. Local logs use
`test-results/p05-controller-offer-*`; exact source/log SHA256 snapshots are in
[the structured record](p05-runtime-foundations.json), `checks.fleetControllerOffers`.
Manual full CI now names this suite in both database profiles; remote execution
was not run. The four Rust ignores are the three inherited desktop checks and
PostgreSQL outage profile; 101 SPS skips remain. Existing website/client/crypto
VM records are historical evidence and were not rerun by this slice.

## Remaining work

Scoped named-operator link/metadata/submit and durable signed ciphertext delivery
are next. Automatic broker offer publication, node outbox/relay support,
reconciliation and actual operator input page/app are not enabled by this slice.
Later metadata/submit must enforce changed binding/key/policy/grant authority;
public offer storage/replay alone does not pass that gate. P04-D4/PV05/PV06 and
full P05 acceptance remain open, including original stock-client URL/delivery
variants, native/two-host, clock/suspend/lifetime/retention pressure, inherited
owner/release gates and small-slice commits. Native graph approval is still
pending; no unapproved dependency resolution/build/run occurred.
