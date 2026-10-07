# P06 slice 9, Compose fault-injection subset — 2026-10-05

**Status:** three fault scenarios added to the Compose bring-up gate and run identically on the SQLite and PostgreSQL profiles (image `blindpass-p06-controller:pg-sbom`, x86-64, Docker host). This is a **subset** of slice 9: no native VM, no remote controller, no stock-client workflow, no UI-logout or serving disk-full fault, no load, and no full parity matrix. P06 acceptance remains false.

## Scenarios (`tests/deployment/compose-up.py`)

| ID | Fault | Asserted | Measured (SQLite / PostgreSQL) |
| --- | --- | --- | --- |
| P06-F1 | `docker kill` (SIGKILL) of the serving controller | Not ready afterwards; a recreate without activation stays not ready; after a fresh administrator activation (retried until the authority releases the dead backend) it becomes ready within 15 s; metadata (tenant, epoch, schema) and key digest unchanged | ready 0.306 s / 1.164 s after the recreate that follows activation |
| P06-F2 | `docker pause` for 20 s, then unpause | Ready again within 30 s, or fenced and recoverable by a fresh activation (the test accepts either safe outcome and prints which); metadata and keys unchanged | Both profiles stayed **ready**, 0.613 s / 0.410 s after resume |
| P06-F3 | Loss of the controller database (SQLite: all `controller.db*` files removed; PostgreSQL: `DROP SCHEMA controller CASCADE` then recreated empty), with a fresh activation and intact keys | `serve` refuses with the fixed reason `state_missing` (not an authority reason), within the call, never recreates the database, and prints no credential or canary | refused in 0.3 s / 0.9 s |

F3 was first written without an activation in place and could have passed for the wrong reason; it now activates first and asserts the reason. The full gate on both profiles passes with the new scenarios (all earlier PASS lines unchanged).

## Test order and limits

- The scenarios exercise existing behavior and were written after it; they are not red-first, and no product code was mutated to prove them non-vacuous beyond the F3 correction above.
- Timings are single runs on an idle developer host; they are readiness-after-start figures, not the plan's 15 s container-startup bound under load, nor the ≤ 120 s node-reconnect bound (no node was connected).
- F2 observed no fencing after a 20 s pause; longer suspends or a suspended authority were not tried.
- Not covered: UI logout under fault, disk-full while serving (only the backup path is covered by `compose-backup.py`), shutdown under in-flight load beyond the existing O05 stop timing, the native profile, the remote-controller topology, and the P06-E01/E04 matrix and pilot E14/E15/D09-D11 workflows.
