# P05 scoped Source link, submit and node relay — 2026-10-02

## Implemented scope

PV06-S01–S09 are implemented in the controller, with the matching core limit,
node relay and broker control-socket changes. The
[store](../../../crates/blindpass-controller/src/store/provisioning_links.rs),
[routes](../../../crates/blindpass-controller/src/routes/provisioning.rs),
[migration 0016](../../../crates/blindpass-controller/src/store/migrations/sqlite/0016_provisioning_links.sql)
(and its [PostgreSQL twin](../../../crates/blindpass-controller/src/store/migrations/postgres/0016_provisioning_links.sql)),
[HTTP suite](../../../crates/blindpass-controller/tests/fleet_provisioning_submit.rs)
and [node relay](../../../crates/blindpass-node/src/provisioning_relay.rs) use
only dependencies already in `Cargo.lock`; no manifest or lockfile changed.

Plaintext consumers and lifetimes: Source plaintext exists only in the operator
browser (sealed there) and in the broker's one-use custody. The controller and
node handle HPKE ciphertext, public offers and signed documents; canary checks
cover rows, audit and logs.

## Contract

- `POST /api/v3/admin/operations/{id}/provisioning-link` (named operator
  cookie, Origin/CSRF, `Idempotency-Key`) creates one immutable link per original
  browser grant and answers `{id, metadata_sig, submit_sig, operator_id,
  operation_id, expires_at_ms, input_path}`; `input_path` is
  `/?kind=fleet&id=…&metadata_sig=…&submit_sig=…`.
- `GET /api/v3/fleet/provisioning/{id}/metadata?sig=` returns `{status:"ready",
  server_time_ms, expires_at_ms, offer, expected:{grant, node_key_version,
  source_unit, credential, signing_public}, summary}`; after a submit it returns the
  receipt. A read never consumes or mutates authority.
- `POST /api/v3/fleet/provisioning/{id}/submit?sig=` takes only canonical bounded
  `{enc, ciphertext}` (body cap 128 KiB) and answers `201` with `{status:
  "submitted", offer_id, ciphertext_digest, delivery_digest, submitted_at_ms,
  expires_at_ms}`; an exact retry returns `200` with the same receipt and different
  ciphertext is `409`.
- Owner: the deciding operator for a `pending_approval` grant, or the
  administrator who configured the destination for an `allow` grant. The
  capability uses its own `fleet-provisioning-sig` signing domain, so a legacy
  browser capability is refused with 403. The capability, a live named session
  and CSRF/Origin are all required; seconds are rounded up while the database
  millisecond deadline remains authoritative.
- One transaction commits the ciphertext digest, the immutable receipt, one
  controller-signed `provisioning_delivery` document (envelope epoch equal to the
  original grant issuer epoch) for the node inbox and the `fleet.source_submitted`
  audit event. Failure rolls all of it back; retries never requeue.
- Authority is re-read after locks with the database clock re-sampled, so a lock
  wait cannot extend the deadline. Cancellation, consumption, registration or
  policy change, node, key or issuer change, destination version, operator logout,
  removal, role or password change, expiry and lock-wait all deny.

Schema 16 adds `fleet_provisioning_links` and `fleet_provisioning_receipts`
(no foreign keys between them or the offers table, so each retains
independently for seven days past expiry in batches of 1,000). A pre-existing
table with wrong columns, at any marker including 0015's tables, fails closed.

Size caps come from one core rule, `DocumentKind::max_document_bytes()`: 128 KiB
for `provisioning_delivery` only, 64 KiB for every other kind, enforced at the
node relay, controller inbox enqueue and broker control socket. A poll response
stops adding documents past a 512 KiB budget, since the node transport caps
responses at 1 MiB.

The node asks the broker for a signed offer (`BROWSER_OFFER_EVENT`, a new
control command because only the broker can make the outer node-event signature)
after relaying an accepted browser grant, posts it unchanged as a
`recipient_offer` node event and relays deliveries only through
`PROVISION_SOURCE`. The broker's browser-offer lifetime is a separate field,
180 seconds by default and still capped by grant expiry and the consumption
deadline.

## Actual checks

| Gate | Actual result |
|---|---|
| New real HTTP/transaction suite on SQLite | 24 passed, zero failed/ignored |
| Same suite on PostgreSQL (container, isolated schemas) | 24 passed, zero failed/ignored |
| Full controller package, SQLite, `--test-threads=1` | 195 passed, zero failed, 4 inherited ignores |
| Full controller package, PostgreSQL, `--test-threads=1` | 195 passed, zero failed, 4 inherited ignores |
| `blindpass-core` | 69 passed across 5 binaries, zero failed |
| `blindpass-node` | 29 passed (25 binary incl. 11 relay, 4 transport), zero failed |
| Broker `provisioning` and `control` filters | 17 and 35 passed, zero failed |
| Clippy, controller/core/node, all targets, `-D warnings` | exit 0 for each |
| `rustfmt --edition 2024 --check` on every touched Rust file | clean |
| OpenAPI mounted-route/security/generated-types gate | 13 passed; regenerated types identical |

The four ignores are the three desktop checks and the PostgreSQL outage profile.
Suites that do not read the backend variable run on SQLite in both profiles.

The HTTP suite includes one end-to-end chain with no VM: a signed grant, offer
ingestion, link, metadata, a Rust HPKE seal, submit and an inbox delivery that
verifies against the original issuer and decrypts to the exact dummy bytes,
including a full 64 KiB Source in a document above 64 KiB. Further cases cover
the named-owner and scope matrix, never-consume reads, concurrent and exact
retry, altered ciphertext, authority withdrawal on every listed cause, write-failure
rollback and retry, a real HTTP server restart over the same database, an actual
database lock longer than the offer window, real-time expiry, retention of live
and expired rows, damaged and rolled-back schemas, and canary scans of every
database row (PostgreSQL row text; SQLite file, WAL and SHM), audit and captured
logs.

Size limits are tested in both directions at every hop with synthetic documents,
since a real delivery of a 64 KiB Source is about 104 KiB and cannot sit exactly
on the cap. The node relay uses a fake broker Unix socket; the broker tests use
its real control framing.

## Honest limits

- Core tests went red, then green. The controller implementation preceded the
  extended S-suite, so no recorded red run exists for those cases, and none is
  claimed for the node relay or broker changes.
- Two intermittent failures appeared while the host load average was about 17 and
  were fixed in the tests, not the product: a scoped tracing capture lost
  request events when another test thread registered the callsite first (now one
  process-wide subscriber), and the lock-wait case used a 3 second lifetime that
  setup could exhaust (now 4 seconds with an explicit liveness assertion, below the
  store's 5 second busy timeout, which would otherwise deny at the session
  check). One PostgreSQL run also saw an approval read return non-200 under that
  load; later full runs passed.
- No real systemd/VM, stock client, operator GUI or hosted CI ran. The packaged
  input page does not yet call the fleet routes; the HTTP suite stands in for it.
- The 1,000-row retention batch is configured but not pressure-tested.
- `BLINDPASS_BODY_LIMIT_BYTES` must stay at or above 131072 for a 64 KiB Source.
- The 180 second offer lifetime and 128 KiB cap are not exercised across a real
  broker, node and controller process chain.
- `packages/contract-tests/tests/openapi-types.test.ts` still asserts
  `schema_version: 12` against the generated type; it predates this slice and lies
  outside its editable scope.

## Commands

From the repository root, approved host loopback execution:

```bash
cargo test -p blindpass-controller --locked --test fleet_provisioning_submit
P02_TEST_BACKEND=postgres P02_TEST_POSTGRES_URL='<disposable-url>' cargo test -p blindpass-controller --locked --test fleet_provisioning_submit
cargo test -p blindpass-controller --locked -- --test-threads=1
P02_TEST_BACKEND=postgres P02_TEST_POSTGRES_URL='<disposable-url>' cargo test -p blindpass-controller --locked -- --test-threads=1
cargo test -p blindpass-core --locked
cargo test -p blindpass-node --locked
cargo test -p blindpass-broker --lib --locked provisioning
cargo test -p blindpass-broker --lib --locked control
cargo clippy -p blindpass-controller -p blindpass-core -p blindpass-node --all-targets --locked -- -D warnings
npm run generate:api
npm run test:controller-openapi
```
