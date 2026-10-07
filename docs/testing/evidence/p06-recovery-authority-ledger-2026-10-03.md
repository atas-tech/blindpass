# P06 protected recovery authority ledger — 2026-10-03

The user selected a separate PostgreSQL authority database with existing SQLx.
OA01/OA01b/OA01c/OA02/OA03/OA09 pass against PostgreSQL 16.15 with an independently
owned database and restricted runtime role; OA08 passes without a connection.
This is protected metadata preparation. No live controller route, readiness,
CLI, backup, restore or activation uses it yet. It does not establish two-host
issuer exclusion or complete P06-I03/I05. See [decision 0012](../../product/decisions/0012-p06-external-recovery-authority.md)
and the authoritative [paired plan](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/testing/phases/06-deployment-and-recovery.md).

## Actual red and green results

The paired plans record OA01–OA10 before implementation. The
[first red](p06-recovery-authority-ledger-2026-10-03/first-red.txt) is a missing-module
compile failure (exit 101), not unsafe old live authority behavior. The added
[startup privilege regression](p06-recovery-authority-ledger-2026-10-03/privilege-red.txt)
then actually fails because the initial adapter accepts administrator-capable
credentials: four pass/one fail, exit 101. The wrapper removes its disposable
database/roles. The corrected adapter refuses that privilege boundary. A further
[NOINHERIT membership control](p06-recovery-authority-ledger-2026-10-03/membership-red.txt)
proves the initial current-user-only check misses SET ROLE capability: five
pass/one fail, exit 101. The fixture proves owner membership with no inherited
CREATE privilege and a successful SET ROLE before the startup refusal assertion.
The final guard checks every membership, including noninherited roles; its
[six-case PostgreSQL run](p06-recovery-authority-ledger-2026-10-03/membership-green.txt)
passes in 0.94s with [zero cleanup errors](p06-recovery-authority-ledger-2026-10-03/membership-green-wrapper.txt).

The [earlier reproducible PostgreSQL run](p06-recovery-authority-ledger-2026-10-03/postgres.txt)
passes the earlier five integration cases in 1.53s, exit 0. Its
[driver result](p06-recovery-authority-ledger-2026-10-03/postgres-wrapper.txt) records
zero cleanup errors. Independent [teardown metadata](p06-recovery-authority-ledger-2026-10-03/environment.txt)
confirms PostgreSQL 16.15 and zero scoped generated databases/roles. The
[later membership teardown](p06-recovery-authority-ledger-2026-10-03/membership-environment.txt)
also checks owner/runtime/member roles and confirms zero resources remain.

| Case | Executed result |
|---|---|
| OA01 | Restricted runtime cannot insert/update/delete/truncate, alter tables/schema or replace the function; invalid/missing identity refuses unchanged; ordinary administrator DML cannot decrease epoch, skip revisions, change issuer or delete |
| OA01b | Administrator-capable runtime credentials refuse; missing layout refuses without recreation; controller_meta in the database refuses; restored valid layout permits reading the same intact epoch |
| OA01c | NOINHERIT administrator membership with real SET ROLE capability refuses startup; direct restricted credentials still work |
| OA02 | Four durable reservations from epoch 21 yield 22, 23, 41 and 42 despite stale observed values; target exceeds external and trusted observed maximum; recovering phase refuses another reservation; explicit test-admin fencing preserves HWM |
| OA03 | Wrong owner/key refuses; racing the same expected revision admits exactly one reservation (epoch 6/revision 2); active ledger phase refuses reservation unchanged |
| OA08 | SQLite, malformed query encoding and unknown PostgreSQL option refuse before connection with fixed diagnostic and no dummy option/URL canary |
| OA09 | Zero/unsafe integers and exhausted maximum epoch refuse without ledger mutation or wrap |

Initial fenced rows and phase transitions are test administrator fixtures,
not proof that a controller process stopped. Owner IDs are labels, not host
proofs. The adapter never initializes missing state and never retries a
reservation implicitly. An ambiguous commit must be read/reconciled while
fenced. The independent administrator remains trusted; a hostile superuser
can alter schema/permissions. No controller artifact embeds its credential.

## Reproduction and required checks

Run from the repository root with the existing reviewed PostgreSQL fixture:

```sh
cargo test -p blindpass-controller --test recovery_authority --locked
python3 tests/deployment/recovery-authority-postgres.py --log /tmp/p06-authority-test.txt
```

The first command executes OA08 and explicitly ignores the six PostgreSQL
cases. The driver creates a separate generated database and three generated
roles (owner, restricted runtime and negative NOINHERIT member), provisions the checked-in SQL as the independent owner, grants only
USAGE/SELECT/one function EXECUTE, passes private credential URLs through the
child environment and executes all six ignores serially. It creates the
public test log exclusively with mode 0600, bounds administration and removes
only its generated resources. Never put credential values into argv or output.
No new scanner, PostgreSQL toolkit or dependency is installed/invoked here.

The earlier [host Rust workspace](p06-recovery-authority-ledger-2026-10-03/rust-workspace.txt)
passes 689 cases with zero failures and 13 ordinary ignores across 71 targets,
exit 0, before the added membership case. The [final required workspace gate](p06-recovery-authority-ledger-2026-10-03/membership-rust-workspace.txt)
on the membership guard terminates exit 0: 689 passes, zero failures and
14 ordinary ignores over 71 targets. All six authority ignores have separate
actual execution. Four SQLx snapshot ignores have [earlier independent execution](p06-postgres-snapshot-2026-10-03.md).
Three Quickshell and one opt-in PostgreSQL outage remain unexecuted by this gate.
[Final all-target Clippy](p06-recovery-authority-ledger-2026-10-03/membership-clippy.txt), format and
`git diff --check` pass. Node26 build and retry workspace results for the same
unchanged Node inputs are retained with the journal checkpoint; full profile,
GUI and inherited phase acceptance are not inferred.

Two earlier target reruns supply no PostgreSQL pass: one
[waited on Cargo's shared build lock](p06-recovery-authority-ledger-2026-10-03/cargo-lock-timeout.txt)
and hit its actual 300s bound. Its
[cleanup also timed out](p06-recovery-authority-ledger-2026-10-03/cargo-lock-timeout-wrapper.txt).
The initial reproducible driver hit a
[setup timeout](p06-recovery-authority-ledger-2026-10-03/fixture-setup-timeout.txt)
and acknowledged no creation. Later private catalog inspection found one
uniquely generated 24-hex driver role, no database and no active connections.
That exact role was removed without deleting dependencies. The corrected
driver registers cleanup intent before CREATE, uses IF EXISTS on its own
names, private `psql -X` sessions and per-connection 5s lock/10s statement
limits. The final successful run happens after the workspace job releases the
build lock; zero remaining resources is actually checked. No shared server,
pre-existing controller or host service is changed. Timeout observations do
not diagnose CPU/memory exhaustion or establish authority-outage behavior.

The working tree remains uncommitted at base
`8a595ad18783634da59e046595942e729b56147b`. No manifest/lockfile or license/package
boundary changes. Protected P03 evidence remains unstaged, 66 additions/zero
removals. Exact source pins:

| Source | SHA256 |
|---|---|
| `crates/blindpass-controller/src/recovery_authority.rs` | `fa332867675466d9062a2fc7e9174bfa9400b4d2fecd5703f1d1455b254681e8` |
| `crates/blindpass-controller/tests/recovery_authority.rs` | `bcb83010ebf38305a62f194d86997afea2a34b12435b14002cf2989e52627311` |
| `deploy/controller/recovery-authority.sql` | `8a53cb97221c6011b12aa8dd7bf432677c0c7af07fa4aa187dd672da394de98d` |
| `tests/deployment/recovery-authority-postgres.py` | `fa8a6b72214d35e69c343be3f94a234de964266b5879cb706ee36c2e9eb812d6` |
| `crates/blindpass-controller/src/config.rs` | `f4a09c24709ee10355de5f69778c5088d76f54e710f57f70610ea70a02c22f12` |
| `crates/blindpass-controller/src/lib.rs` | `233038d2f8b5304b0a9f352a05ec997271224bcd457152a3d06afec37ab0913f` |

## Plaintext and open acceptance

Ledger rows contain opaque identity/owner IDs, epochs, revisions and phase;
no secret payload, browser session bearer, private signing key or cleanup
handle. Generated database passwords/URLs stay in private fixture/SQLx process
memory and are revoked by role teardown. SQLx may retain connection options
for its pool lifetime; this is not a zeroization guarantee. The retained
logs contain no private-key, credential-bearing PostgreSQL URL or bearer-header
markers; that scoped marker check is not proof about arbitrary secret contents.

Complete external process/session ownership, bounded authority-loss fencing
and all protected routes, in-flight quiescence and explicit source-stop proof;
full stale transient-authority invalidation, broker journal coverage/pagination,
fresh challenges/current enrolled keys, provider cleanup and offline-node
quarantine; then actual cloned issuers, outages/reconnect and interrupted
transfer. OA04–OA07/OA10 remain open; partial metadata checks do not satisfy
those scenarios. Keep every one of the nine slices and all three shipped,
remote/browser/native and inherited acceptance gates. No new shipped native
archive or OCI candidate is built for this source-only adapter. P06 remains
active and unaccepted. The external-database choice does not approve
[ADR 0011's separate dump/restore toolkit](../../product/decisions/0011-p06-postgresql-backup-toolkit-review.md).
