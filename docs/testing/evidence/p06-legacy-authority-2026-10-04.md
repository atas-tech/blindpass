# P06 legacy JWT/HMAC authority versioning — 2026-10-04

Work started 2026-10-03 against the test-first LA01–LA06 scenarios in the
[product plan](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/phases/06-deployment-and-recovery.md)
and [paired testing plan](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/testing/phases/06-deployment-and-recovery.md).
This is a source candidate within slice 6. All nine slices remain required;
P06, restore activation and deployment profiles remain unaccepted. No dependency,
manifest, lockfile, package boundary or schema change accompanies this work.

## Behavior and secret lifetime

Generation one retains the accepted SPS raw-key behavior and golden vectors.
Each later generation derives independent 32-byte root and agent-JWT keys with
existing HS256, binding the domain, purpose, length-delimited tenant and safe
integer epoch. It never falls back to a raw or earlier-generation key. Local
agent and fulfillment JWTs also require an exact integer epoch claim at later
generations; absent, null, floating, string, unsafe or wrong-generation claims
refuse even when their MAC is correct. Existing tokens remain opaque to clients.

All secret metadata, submit and status HMACs and fleet Source link HMACs use
the current root key. Fulfillment retains its existing nested purpose derivation.
Routes read current schema, tenant and epoch together through the guarded Store,
with a three-second bound; they refuse a changed tenant, unsupported schema or
unsafe epoch. SQLite additionally requires persisted integer/text/integer types,
preventing its CAST from accepting malformed markers. PostgreSQL retains its
INT4-to-BIGINT decoder widening, with column types enforced by the database.
Errors fence a bound holder. Pending recovery and lost ownership remain fenced.
There is no startup-cached generation, recovery clear or activation API.

Master keys remain in controller process memory for its lifetime. Request-owned
derived keys use existing SecretBytes clearing on drop; owned derivation buffers
are cleared. Library copies, allocator/OS memory and complete media erasure are
not guaranteed. Test keys and credentials are generated dummy fixtures in private
files/process memory; tokens and live links are not included in these logs. In
LA05 the test's browser-equivalent process holds Source plaintext in memory for
the test lifetime and encrypts it to the signed recipient; the controller receives ciphertext, not that plaintext.

External asymmetric-provider credentials and node-channel signing have independent
trust. The existing Octet/HS256 external-provider refusal is unchanged; this
candidate does not revoke independently trusted provider tokens. Provider trust,
credentials and persistent actors still require recovery review before unfence.
Generation-one compatibility does not permit resetting the protected external
high-watermark or activating an old cloned snapshot. Mandatory production
external ownership is still unwired.

## Executed scenarios

| Scenario | Actual coverage |
|---|---|
| LA01 | Actual agent mint/request; old JWT rejects with agent, master keys and request retained; current JWT works across controller reopen; seven independently signed malformed/wrong claims reject |
| LA02 | Actual old metadata/submit/status HMACs reject with pending request retained; current mint, metadata, status capability and submit succeed; retrieval succeeds once then returns 410 |
| LA03 | Old fulfillment JWT rejects with pending exchange retained and current agent JWT; independently verified current-key token and seven malformed/wrong claim forgeries exercise epoch enforcement; fresh fulfill/submit/one-use retrieval succeeds |
| LA04 | Known-kid symmetric provider cannot rescue old local JWT; unsafe epochs, changed tenant, future schema and SQLite malformed text/real schema markers return fixed 503 without creating secret requests |
| LA05 | Current generation-nine signed grant/offer, named-owner approval and Source link; raw-root HMAC for the same live link rejects for metadata and submit; current HPKE submit delivers exactly once |
| LA06 | Three normal unit tests cover independent dummy HS256 vectors, generation-one compatibility, purpose/tenant/generation separation and safe boundaries; existing ownership and persisted recovery regressions execute separately |

The final post-fix driver matrix executes four legacy cases on each backend,
25 Source cases on each backend, six recovery cases on each backend and 25
ownership cases: 95 passes in total. [Regression summary](p06-legacy-authority-2026-10-04/verified-regressions-summary.txt)
and per-run logs retain actual durations, exit codes and zero owned cleanup errors.
The Source suite's stale-epoch capability expectation is now 403 because the HMAC
is retired before the stale-grant check; other stale-authority cases remain 410,
and their no-submission/no-delivery assertions remain intact.

Fixture SQL epoch changes isolate authority versioning. They are not external
reservations, protected restores or activation. LA05 uses real controller crypto,
signed Source admission and HPKE, but not a real host broker/browser/VM profile.
No node protocol or core SPS golden-vector implementation was changed.

## Failures and negative controls

The [first legacy runtime run](p06-legacy-authority-2026-10-04/first-red.txt)
failed all four cases on admitted old authority. The first Source test used the
wrong named owner and failed for that fixture error; after correction,
[the pre-implementation Source run](p06-legacy-authority-2026-10-04/source-corrected-red.txt)
failed because raw-root metadata was accepted. An initial compile attempted to
call a private core helper; it was replaced by the existing reviewed controller
HS256 primitive without widening core APIs. Initial formatting and one Clippy
style finding were corrected.

[Changed-tenant testing](p06-legacy-authority-2026-10-04/metadata-red.txt)
found that cached tenant metadata admitted a request (201 instead of 503).
[SQLite type testing](p06-legacy-authority-2026-10-04/sqlite-type-red.txt)
then found CAST accepted a malformed schema marker (201 instead of 503).
Both red assertions preceded their fixes; final backend runs exercise the fixes.

Three private source controls failed at real assertions: allowing raw keys after
generation one admitted old metadata (200 versus 403); removing agent claim
enforcement admitted a correctly signed missing-claim JWT (201 versus 401);
removing fulfillment claim enforcement admitted its correctly signed missing-claim
JWT (200 versus 401). [Control summary](p06-legacy-authority-2026-10-04/controls-summary.txt)
records all three exit 101, unchanged production hashes and removed private trees.
Their three protected production source pins still match after the metadata fix.

## Workspace gates and limits

- [Node 26.10.0 build](p06-legacy-authority-2026-10-04/node26-build.txt) and
  [npm tests](p06-legacy-authority-2026-10-04/node26-test.txt): exit 0 outside
  restricted execution. SPS reports 80 passes and 101 skips in 17 files; skips
  provide no execution evidence.
- [Full Rust workspace](p06-legacy-authority-2026-10-04/rust-workspace.txt):
  exit 0, 694 passes, 0 failures, 43 ignores across 73 result targets.
  The three new normal crypto cases and Source case passed; existing generation-one
  SPS golden-vector tests and authenticated schema16 backup compatibility passed.
- [Clippy](p06-legacy-authority-2026-10-04/clippy.txt): workspace/all targets,
  locked/offline, warnings denied, exit 0. [Formatting](p06-legacy-authority-2026-10-04/format.txt)
  and [OpenAPI](p06-legacy-authority-2026-10-04/openapi.txt): exit 0.

Of the 43 ordinary Rust ignores, 25 ownership, six recovery and four legacy
cases were executed separately above (recovery/legacy on both stores). Four
PostgreSQL snapshot cases, three Quickshell cases and one optional PostgreSQL
outage case were not rerun here; historical snapshot evidence retains its own
pins. Node24, real systemd/VM/broker/browser/stock-client acceptance, separate
cloned hosts, native/OCI restore or new packaged artifacts were not run. Earlier
release artifacts remain schema16 and do not contain this source candidate.
The current [catalog check](p06-legacy-authority-2026-10-04/authority-final-cleanup.txt)
found zero generated authority/snapshot databases and roles.

[Source pins](p06-legacy-authority-2026-10-04/source-pins.json) cover the current
crypto, route, Store, ownership/recovery, fixture/driver and unchanged golden-vector
boundaries. [Final QA](p06-legacy-authority-2026-10-04/final-qa.txt) checks actual
results, relative links, credential markers, pins, owned-resource cleanup, both
vault checkpoints and diff formatting. The unrelated user P03 evidence remains
66 additions/0 deletions, unstaged and untouched. No slice 5/6 commit was made.

Mandatory external production serve/configuration/maintenance/local-admin wiring,
previous-source stop proof, complete server/body quiescence, complete authenticated
broker challenges/current keys/coverage, legacy/pruned-history mapping, provider
cleanup, offline quarantine, persistent-authority review and explicit protected
unfence remain required. This request-key guard does not prove those properties.
PostgreSQL custom-dump/full isolated restore still awaits its separate
[toolkit review](../../product/decisions/0011-p06-postgresql-backup-toolkit-review.md).
Verified locked upgrades and retained backups, both native↔Compose transfer
directions and all three profiles' stock-client/browser parity remain required.
The full goal stays active.
