# P06 serving disk-full on both Compose profiles — 2026-10-06

**Status:** actual Docker runs of `tests/deployment/compose-up.py --profile sqlite` and `--profile postgres` on image `blindpass-p06-controller:node`, uncommitted tree above `8a595ad`, x86-64 host. The new gate `P06-F4` fills the controller's store volume while it serves. It completes the slice 9 "disk full" row for the Compose profiles next to the native result in [p06-serving-faults](p06-serving-faults-2026-10-06.md). Both full runs exited 0 (12 and 13 PASS lines; every earlier gate in the file still passes). P06 acceptance remains false.

## How the fault is made

The store volume (`blindpass-data` for SQLite, `blindpass-postgres` for PostgreSQL) is replaced by a named volume bound to a **loop-mounted ext4 image** (64 MiB SQLite, 256 MiB PostgreSQL, `-m 0`), copied from the original with ownership preserved. A tmpfs volume was tried first and does not work: Docker recreates it empty for every container. No root on the host is needed, but the mount is made by a short `docker run --privileged` helper with the host `/dev` and shared mount propagation; it is unmounted and the loop device detached afterwards (no loop device, mount or `*-small-store` volume remained after the final runs). The recovery authority is a separate container with its own disk, so filling the store cannot stop it.

Sequence: controller activated and ready on the small volume; the volume is filled to ENOSPC (a probe write by an unprivileged user fails); PostgreSQL is made to try to extend its own files (`CREATE TABLE ... generate_series`, which must fail with no space); readiness and a store write are probed; space is freed without restarting the controller; the harness waits 15 s, then follows whatever state it finds; finally the store is copied back to the original volume so the remaining gates run unchanged.

## Results

| Profile | During the fault | After space was freed | Recovery |
|---|---|---|---|
| SQLite | readiness 503 `disk_full`; a wrong-credential login (which must write its rate-limit row) answered `503`, twice; process kept running | still `503 recovery_required` | one fresh activation, ready 0.3 s later; identity, keys and state unchanged; SQLite `integrity_check` ok |
| PostgreSQL | readiness stayed `200` (reads still work; an idle full volume does not make the controller notice); the first store write got **no response** (connection closed), the next write `503`, then readiness `503 recovery_required`; process kept running | still `503 recovery_required` | one fresh activation, ready 1.2 s later; identity, keys and state unchanged |

Reading it:

- **Same outcome on both profiles once a write fails:** fail closed, no success claimed, process stays up, and space alone does not unfence the owner (P06-D12, owner-confirmed). One ordinary activation brings it back within the 15 s bound.
- **Without a write, PostgreSQL does not notice.** Earlier runs without the write probe saw readiness stay true through the whole fault and the controller ready by itself afterwards. Readiness on that profile reflects read health, so an operator monitoring only `/readyz` will not see a full PostgreSQL volume until something writes. This is a monitoring limit, not a data risk.
- **The dropped connection is the fence, by design.** The first failing write fences the owner and `OwnedIo` closes every admitted socket locally (`crates/blindpass-controller/src/owned_transport.rs`), so that request gets no response even though the controller logs a 503 for it. The same request on SQLite got a clean 503 because the SQLite error was classified before the fence closed the socket. Not changed: a fenced owner is meant to cut its clients off. Clients must treat a closed connection during a storage fault like a 503.
- No loss or corruption was found: state compared equal before and after on both profiles and SQLite integrity was ok. PostgreSQL integrity beyond that comparison (no `pg_dump` or checksum scan) was not run.

## Limits

- Compose only; the native fault is in the serving-faults record. One run per profile in its final form, plus earlier runs of the same gate during development (they differed only in probes added afterwards).
- A full PostgreSQL volume where PostgreSQL itself crashes (WAL segment creation PANIC) was not produced: the extension fault errored without a PANIC in these runs.
- The write probe is a login attempt; other write paths (approval, grant, backup) were not individually probed. A full backup volume while serving and a full journal were not run.
- The harness uses a privileged helper container for the loop mount, which needs Docker access equivalent to root on the host. It is test-only.
- Not run: loaded Compose runs of this gate.
