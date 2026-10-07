# 0012: P06 external recovery authority boundary

**Status:** The user selected the separate PostgreSQL architecture on 2026-10-03.
Protected metadata, process ownership and router/transport gates are implementation
candidates with scoped execution evidence. Production `serve` and maintenance
require this authority. Authenticated SQLite restore now uses a recovering holder
and publishes only fenced state; protected activation remains unimplemented. The authoritative
[P06 plan](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/phases/06-deployment-and-recovery.md)
and [paired tests](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/testing/phases/06-deployment-and-recovery.md)
retain all nine slices and full acceptance gates.

## Independent custody

Use a separately administered PostgreSQL database with the existing reviewed
SQLx stack. It applies to native SQLite and both Compose controller profiles.
The authority database, administrator access and runtime credential stay outside
controller database/key backups and migration payloads. Keep an independent
durable recovery copy of that authority; restoring or losing it requires
external recovery review, never automatic controller initialization.
Authority availability is a production issuance prerequisite.

Provision [schema version 4](../../../deploy/controller/recovery-authority.sql)
through the independent administrator. Startup refuses missing, older and newer
layouts without changing them. Existing version-2 authority databases require
the [v2→v3 administrator migration](../../../deploy/controller/recovery-authority-v2-to-v3.sql),
followed by the [v3→v4 migration](../../../deploy/controller/recovery-authority-v3-to-v4.sql),
after authenticated previous issuer/server shutdown. All tenants must be fenced
and no process guard held. The migration preserves high-watermarks, revisions
and immutable attempts; historical attempts retain a NULL proof digest. Its
database exclusion checks do not establish source shutdown or activation.
The second step preserves current/pending keys, revocation and historical
attempts while adding protected receipt storage and observed-epoch bounds.
Explicitly register the tenant, issuer key ID and installation owner with a
positive high-watermark/revision and `fenced` phase; a conflict refuses.
An administrator's initial ledger insertion also creates its immutable guard
row. The runtime role gets schema USAGE, table SELECT and EXECUTE on only:

- `reserve_recovery(TEXT,TEXT,TEXT,BIGINT,BIGINT)`
- `claim_process(TEXT,TEXT,TEXT,BIGINT,BIGINT,TEXT,BYTEA)`
- `register_active_process(TEXT,TEXT,TEXT,BIGINT,BIGINT,INTEGER,BYTEA)`
- `publish_broker_trust(TEXT,TEXT,TEXT,BIGINT,BIGINT,INTEGER,BYTEA,BIGINT,TEXT,BIGINT,TEXT,TEXT,TEXT,BIGINT,TEXT,TEXT,TEXT)`
- `open_recovery_challenge(TEXT,TEXT,TEXT,BIGINT,BIGINT,INTEGER,BYTEA,TEXT,TEXT,BIGINT,BIGINT,BIGINT,TEXT,TEXT)`
- `stage_recovery_page(TEXT,TEXT,TEXT,BIGINT,BIGINT,INTEGER,BYTEA,TEXT,TEXT,TEXT,BIGINT,BIGINT,TEXT,TEXT,TEXT)`
- `finish_recovery_challenge(TEXT,TEXT,TEXT,BIGINT,BIGINT,INTEGER,BYTEA,TEXT,TEXT,TEXT,BIGINT,BIGINT,BYTEA,BOOLEAN,BIGINT)`

Grant no table writes, schema CREATE, administrator membership, superuser,
CREATEROLE or CREATEDB. The adapter refuses write-capable credentials for any
protected table and all such role memberships, including NOINHERIT escalation
through SET ROLE. It also refuses missing function grants, unsupported layout
and any database containing `controller_meta`. These checks do not authenticate
an independently supplied endpoint; deployment must protect its connection
configuration and trust.

SQLx consumes credentials in private controller process memory for the pool/
connection lifetime. Caller-owned configuration can also retain them; no memory
zeroization guarantee is established. Errors are fixed and contain no URL,
password or query values. Production configuration uses the protected
`BLINDPASS_AUTHORITY_URL_FILE`, tenant and owner options; the restore command accepts
only a protected authority URL file. Complete installer provisioning and protected
recovery activation remain open.

## Monotonic reservation

The protected ledger binds tenant, issuer key and installation owner to an
epoch, revision and fenced/recovering/active phase. Integers are bounded to
1–9007199254740991. Triggers refuse deletion/truncation, key/tenant replacement,
decreasing epochs, skipped revisions and owner transfer outside the fenced
phase. Independently trusted administrators can alter the schema; these
protections constrain runtime credentials and ordinary table mutations.

The reservation function uses a fixed `pg_catalog` search path and qualified
references. It compares owner/key/tenant, expected revision and fenced phase,
then commits an epoch above both the current protected high-watermark and a
trusted observed broker maximum. Exactly one reservation per revision succeeds;
exhaustion and mismatch refuse. A live process guard prevents reservation or
owner transfer. An administrator may fence the same owner/epoch with the next
revision while its holder remains, allowing the holder's check to detect loss.

A committed reservation remains `recovering`. A snapshot epoch or unsigned
caller value cannot prove broker history, source shutdown or safe activation.
An ambiguous failure never triggers a hidden retry or high-watermark rollback.
Read current external state while fenced and reconcile explicitly.

## Held process and one-use active revision

A dedicated SQLx connection is detached from the general pool and starts a
READ COMMITTED transaction. The claim function takes the tenant's guard row
with `FOR UPDATE NOWAIT` only alongside an exact current record. The socket and
transaction stay owned by a non-cloneable holder; drop/fence closes the socket,
and a live transaction never returns to the pool. This follows
[PostgreSQL 16 row-lock lifetime](https://www.postgresql.org/docs/16/explicit-locking.html#LOCKING-ROWS).
The holder excludes another cooperating connection, including one carrying
cloned owner context. Different tenants have independent guards.

The actual held connection also acquires a fixed tenant advisory lock and two
distinct token-derived advisory locks. A fresh 32-byte random proof stays in
private process memory and travels as an SQLx parameter to the authority server;
the immutable attempt stores only its SHA-256 digest. The registering/publishing
function requires all three locks on that exact backend in that authority
database. A caller-named PID or unrelated token locks alone refuse. The lock
encoding uses [PostgreSQL 16 lock metadata](https://www.postgresql.org/docs/16/view-pg-locks.html)
and its [built-in binary SHA-256](https://www.postgresql.org/docs/16/functions-binarystring.html).
The owned token buffer receives a best-effort wipe on release. SQLx, PostgreSQL
and OS copies have their own lifetimes; this does not prove their erasure.
Protect database transport and server logging configuration as part of the
independent authority deployment. No token is stored in a controller archive,
environment variable, command argument or this adapter's diagnostic output.

Version 3 also retains independently current broker public keys, approved
pending rotation keys, immutable prior keys and irreversible revocations.
An actual active holder publishes each validated enrollment, staged rotation,
acknowledged rotation and revocation before committing controller state. A
controller commit failure therefore leaves conservative approved-key/revocation
evidence outside its backup and permanently fences uncertain database work.
An already approved rotation acknowledged after revocation may update the key
version while preserving revocation. It cannot revive the identity or approve
new pending keys. Recovering holders may read current trust but cannot publish
these active transitions. These are metadata foundations; the actual recovering
controller workflow, node relay, complete coverage and activation remain open.

Version 4 adds nonce/receipt storage outside controller backups. An actual
recovering holder binds a fresh 32-byte controller nonce to tenant, issuer,
installation owner, external epoch/revision, recovery ID, snapshot epoch/time/
digest and independently current or approved pending broker public key/version.
Reopening preserves the same nonce and consumed state. Signed pages remain
bounded to 128 rows/64 KiB and are immutable once staged; sequential indexes,
the exact manifest and pending exact retries are checked transactionally.
Authenticated observed epochs are monotonic and survive partial collection.
Reservation locks the ledger first, then reads these protected bounds rather
than trusting stale caller input alone.

The Rust collector verifies signatures against protected keys, then re-verifies
the entire ordered history/digest in batches of at most eight pages before
atomically consuming a challenge. The full read has a 30-second bound; individual
authority operations retain their three-second bound. Coverage requires known
genesis, no unmapped intents and a pruning boundary strictly before snapshot
time. Missing coverage remains blocked; observation at or above the proposed
epoch requires a new higher reservation. Nonce validity follows the exact live
recovery context, while the broker's separate local export nonce retains its
existing 30-second suspend-aware expiry. Neither is a bearer credential.

Receipt rows and returned status are metadata, not admission capabilities.
They do not acknowledge a pending key rotation, revive revoked nodes, resolve
provider effects or activate an issuer. The application performs Ed25519
verification; PostgreSQL definer functions enforce holder/context/CAS, bounds
and immutable publication, not independent cryptographic software attestation.
Authority administrators and runtime credentials remain part of the reviewed
deployment trust boundary. A future local consumer must verify the protected
pages before applying them, preserve uncertain operations and node quarantine,
and satisfy the separate provider/roles/source-stop/activation gates.

All six expanded schema-4 receipt cases passed on the disposable PostgreSQL
authority, including current/pending/retired keys, socket-loss uncertainty and
runtime privilege refusals. The administrator migration also passed. Workspace
credits were restored before this execution; broader current gates pass. See the [current execution boundary](../../testing/evidence/p06-durable-receipts-2026-10-04.md).

An active claim additionally commits an append-only `active_process` attempt
through a separate connection before returning. Its unique tenant/epoch/revision
binds the held backend. Reuse refuses even after connection loss or an ambiguous
registration; ordinary deletion/update/truncation cannot reset it. Fenced and
recovering candidates may be reclaimed explicitly, but cannot issue. No runtime
method activates a revision or clears a fenced holder. A fresh transport does
not supply an ownership transfer or source-stop proof.

Connect, read, reservation, claim and holder checks have three-second Tokio
deadlines; connections also set two-second statement and one-second lock
limits. A failed, timed-out or cancelled check permanently latches fenced and
refuses new work. Admitted operation permits retain the held socket until their
Rust futures end or cancel; explicit three-second quiescence refuses a timeout
without releasing a live permit. This is not proof that an already submitted
server-side mutation rolled back. A one-second monitor checks during idle periods and
retains only a Weak reference between checks. Changed current metadata or a
missing/mismatched active-process attempt also fences. Measured bounds use the
running host's monotonic clock; suspend-inclusive/VM wall-time behavior still
requires the full profile fault gates.

## Router candidate and remaining integration

`build_app_with_ownership` checks the actual local tenant/configured issuer key;
a mismatch or missing store fences its holder. Active protected handling and
readiness also read and require the matching current local issuer epoch, with a
three-second bound. The candidate gate covers API, UI, fallback and all methods,
including CORS preflight. Exact `/healthz` and `/readyz` remain diagnostic;
readiness reports database and optional authority checks separately. Loss cancels
pending handler delivery and returns a fixed 503 with no-store/security headers.

[Scoped process/router evidence](../../testing/evidence/p06-process-ownership-2026-10-03.md)
uses real PostgreSQL connections, owned TCP faults and actual Axum HTTP.
It is not a separate-host packaged-controller rehearsal. At that 2026-10-03
checkpoint, production startup and local administration remained unintegrated;
the later mandatory production entrypoint and transport records below supersede
that wiring limitation. The bound candidate now shares one immutable ownership
binding across existing Store clones and attached signer clones, cancels pending
protected store futures, gates maintenance and checks live authority at direct
node signing. Rebinding cannot clear a failed holder. The two direct node reply
paths use the same guarded signer as transactional inbox documents.

[Operation/store evidence](../../testing/evidence/p06-owned-store-2026-10-03.md)
includes real PostgreSQL guard retention and a real SQLite write-lock retrieval.
Handler/future cancellation is not rollback of ambiguous server-side work,
streamed-body drainage or source shutdown. Later records add mandatory production
wiring and transport/database uncertainty handling. Complete quiescence, source-stop
and recovery reconciliation are still required before accepting a profile.

Owner ID and backend PID are labels, not uncopyable host identities. Explicit
transfer must prove the previous issuer stopped and cannot restart. The schema17 [local invalidation candidate](../../testing/evidence/p06-recovery-invalidation-2026-10-03.md)
commits durable prepared intent before atomic stale legacy/fleet invalidation.
Reopening that intent fences ordinary HTTP, Store operations and signing; no
method clears it. Exact reserved epochs, idempotent replay and quarantined
node/operation/persistent-authority queues are covered on both stores.
Local schema18 now adds [authenticated archive snapshot binding](../../testing/evidence/p06-authenticated-recovery-snapshot-2026-10-04.md).
Only private verified restore staging can create it. A distinct Ed25519 signature
binds snapshot epoch/time and canonical manifest digest to tenant/issuer/owner/
recovery ID and protected epoch/revision. The bound live recovering holder verifies
that signature; missing or modified metadata cannot supply collection scope.
Schema16/17 archives migrate explicitly, while historical recovery rows receive no
guessed context. Public signatures/digests are metadata; the existing issuer key
retains its reviewed runtime lifetime. This does not consume protected pages,
prove source/server stop or activate a restored controller.

The [scoped Store collection candidate](../../testing/evidence/p06-scoped-recovery-collection-2026-10-04.md)
now uses that signed local scope for open/stage/finish, checks the protected
challenge's complete snapshot context before mutation/consumption and validates
local/protected scope again before returning metadata. A matching node signature
alone cannot admit a report from another snapshot. The real pre-write omission
control catches mutation even though later validation refuses delivery. This
collection layer does not apply records, release quarantine, expose a node relay
or activate. The later local application candidate retains quarantine metadata.

The [local application candidate](../../testing/evidence/p06-recovery-application-2026-10-04.md) rereads protected current/pending trust, consumed challenge, page signatures and full ordered digest before one local quarantine transaction commits. External consumption and local application remain separate, resumable commits; a status field alone never authorizes application. Actual relay, source/provider review and protected activation remain open.

The [legacy authority candidate](../../testing/evidence/p06-legacy-authority-2026-10-04.md)
now derives distinct tenant/epoch root and agent-JWT keys after generation one;
later local/fulfillment JWTs also require the matching epoch claim. It reads
actual schema/tenant/epoch through guarded state with no older/raw-key fallback.
Generation-one SPS vectors remain compatible; this exception never authorizes
resetting the external high-watermark or activating a stale snapshot. Master
keys remain in existing process memory; request-local derived SecretBytes are
cleared on drop with no library/OS erasure guarantee. Node crypto and independent
asymmetric-provider trust are unchanged. Complete authenticated broker coverage,
challenges/current keys, provider credential/trust cleanup and offline quarantine
before unfence. Repeated stale restores must stay above all prior reserved generations.
Test separate cloned hosts, outages/reconnects and interrupted transfers on all
shipped profiles. Historical [version-1 metadata evidence](../../testing/evidence/p06-recovery-authority-ledger-2026-10-03.md)
retains its own source pins.

No dependency is added. This architecture selection does not approve the
separately proposed [PostgreSQL dump/restore toolkit](0011-p06-postgresql-backup-toolkit-review.md).


The [production ownership entrypoint](../../testing/evidence/p06-production-ownership-2026-10-04.md)
now requires a protected authority URL file and explicit tenant/owner identifiers.
It acquires before local clock writes and binds HTTP, retention/signing and local
administration to the same immutable guard. Fenced/recovering startup remains
nonissuing. Initial/current-schema migration and clock repair require protected
fenced maintenance; older upgrades refuse pending verified backups/locking.
Offline capture uses an immutable nonissuing snapshot Store, leaving the source
clock untouched and never connecting to authority or adding its credentials to
the four-member archive. The public builder cannot enable unbound production.
A one-use active revision is never replayed after process death. Packaged startup
revision sequencing still needs integration with slice7; no automatic activation
or metadata provisioning is introduced. This does not establish complete body/
server quiescence, source stop, broker/provider coverage or protected unfence.


The [transport/shutdown candidate](../../testing/evidence/p06-transport-ownership-2026-10-04.md)
extends active permits to accepted HTTP/TLS/admin IO and closes IO before permit
release. Old accepted connections can close on fencing; fresh diagnostic routing
remains available. Known local tasks/pools drain under bounds, and no successful
complete-quiescence or activation claim is inferred from those counts. Server-side
SQL/ambiguous COMMIT and authenticated source-stop/broker coverage remain gates.
A proposed direct http-body edge was reviewed and not added: the existing Tokio
transport APIs provide lifetime tracking without a graph/manifest change.

The [database cancellation candidate](../../testing/evidence/p06-database-uncertainty-2026-10-04.md)
adds an irreversible local uncertainty latch around admitted Store/startup/
maintenance/recovery futures. Cancellation or a failed database acknowledgement
retains the live guard and refuses local quiescence; late PostgreSQL insert/COMMIT
outcomes are observed independently. This changes no protected ledger layout or
ACL. The latch is not persisted outside the process: disappearance can still
release the connection, so it supplies neither durable source-stop proof nor
permission to reserve/activate after a lost source. Protected recovery and QF08
remain open. Routine shutdown can specifically refuse local drain when it cancels
background database work; this is a review requirement, not success.
