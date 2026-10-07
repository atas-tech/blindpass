# P06 SQLite backup size boundary — 2026-10-03

P06-BS01/B10 passes with a real SQLite database at the largest page-aligned size
admitted by backup format 1's 512-MiB bound. Full encryption/authentication/extraction
and SQLite integrity/metadata verification precede publication. Growing the
payload by one overflow page fails with `backup exceeds limit`; the earlier
archive remains unchanged and fully verifies again.

This source component runs the current uncommitted debug controller above
`8a595ad`, on host OpenSSL 3.6.4. It is separate from earlier native/OCI artifact
evidence and does not measure serving latency or sudden power loss.

| Observed quantity | Result |
|---|---:|
| Complete bundle cap |536,870,912 bytes |
| Database member budget after three 32-byte keys and reserved manifest/tar overhead |536,797,088 bytes |
| Largest admitted 4096-byte-page database |536,793,088 bytes |
| Dummy blob payload |535,766,060 bytes |
| Published encrypted archive |536,801,218 bytes |
| Next-page database; 96 bytes over the member budget |536,797,184 bytes |
| Complete creation and verification before publication |15.709 seconds |
| Independent complete verification |7.754 seconds |
| Oversize refusal |1.611 seconds |

The paired vault plan records BS01 before execution. The harness adjusts from
observed compact file sizes and requires exact equality with the page boundary;
it does not infer the result from declared limits or a sparse oversized header.
The refusal leaves exactly the old published archive and no staging residue.
Source integrity, payload length, tenant/epoch/schema and all three key hashes
are checked. The verifier then fully checks the old archive again.

Generated source keys, recovery credential, dummy plaintext and work files live
only in private 0700 temporary directories/0600 key files, consumed by SQLite,
the controller and OpenSSL. They never enter captured output. All fixtures are
removed on normal exit; deletion is not secure erasure. No mounted host paths,
shared services, credentials or dependency proposals change.

Run from the repository root with patched OpenSSL and about 8 GiB temporary free
space:

```bash
python3 tests/deployment/backup-size-limit.py
```

The [sanitized actual output](p06-backup-size-boundary-2026-10-03/result.txt)
records measured sizes/times. Syntax and diff whitespace pass. Required Node/Rust
gates for the current source are recorded in the
[PostgreSQL snapshot record](p06-postgres-snapshot-2026-10-03.md).

Full slice 5 remains uncommitted. PostgreSQL dump/full isolated restore and its
toolkit review, sudden power loss, protected external recovery authority/ownership,
stale-state fencing, locked upgrades, transfers and complete three-profile/browser/
native acceptance remain required. This bound check authorizes no restored state.
