# Fail-closed exposure scanner

`scripts/tests/canary-scan.sh` (P07-I04, pilot S06/S07) looks for dummy canaries, key material and
secret-shaped values in archives, container image exports, backups, crash dumps, client transcripts and
logs. It replaces the pattern "grep a journal and pass when nothing matched". The earlier VM scanners
could pass because they saw nothing: an empty journal, an unreadable archive, a scanner that could not
find its own control. This scanner treats *could not look* as a failure.

Implementation: `scripts/tests/canary_scan.py` (Python 3.10+ standard library; `zstd` binary or Python 3.14
`compression.zstd`). Self-tests: `scripts/tests/canary_scan_test.py`. A separate static check,
`scripts/tests/check-core-limits.py`, covers the crash-dump side (see [below](#core-dump-limits)).

## Contract

| Exit | Meaning |
|---|---|
| 0 | Every requested class was found, fully read and is clean. Allowlisted hits are still printed with their reason |
| 1 | A canary, key material, secret-shaped value, forbidden file name or unsafe artifact was found (takes precedence over 3) |
| 2 | Configuration error: no canaries, a canary under 12 bytes or with under 8 distinct bytes, bad allowlist, bad usage |
| 3 | The scan is **incomplete** and therefore not a pass |

Incomplete means any of: path missing or unreadable; special file (FIFO, socket, device); truncated, corrupt or
trailing-garbage stream (gzip, bzip2, xz, zstd) or archive (tar without an end-of-archive block, zip without
a central directory or with a bad CRC, ar); encrypted zip member; a recognised container the scanner cannot
open (7z, rar, cpio, rpm, squashfs, qcow2, vmdk, vdi, lz4, lzip, lzop, compress, cab); a missing codec
(`CANARY_SCAN_ZSTD=none`, or no zstd decoder); nesting beyond `--max-depth` (default 10); more than
`--max-bytes` (256 GiB) read or `--max-entries` (5 000 000) entries; an empty top-level log, transcript, dump
or backup; a `.jsonl` transcript where no line is JSON; a docker image export that omits a layer, config or
manifest it references, or whose `blobs/sha256/<digest>` content does not hash to its name; a backup whose DER
length does not match its size; zero files scanned; a requested class (`--archives`, `--images`, `--backups`,
`--dumps`, `--transcripts`, `--logs`) with no artifact; with `--strict-allowlist`, an unused allowlist entry;
and any unexpected scanner exception. Exclusions (`--exclude GLOB`) are never silent: each is listed in the
report.

Before touching a real artifact the scanner builds one artifact per supported container or encoding
(tar, gz, bz2, xz, zstd, zip, ar, tar.gz, JSONL split over stream deltas, a line-wrapped canary) with a random
planted token and a same-length twin, and requires the real pipeline to find the first and not the second.
A control that fails makes the run incomplete (`scanner_control_failed`); an unavailable codec is listed
under `controls.unavailable` and makes any artifact that needs it incomplete.

## Usage

```sh
# Make dummy canaries (mode 0600, refuses to overwrite, values are never printed).
scripts/tests/canary-scan.sh --generate-canaries run/canaries.txt --count 8

# Scan what a run left behind. Flags mean "require and check this class"; every file under PATH is scanned anyway.
scripts/tests/canary-scan.sh --canaries run/canaries.txt --archives --images --backups \
    --dumps --transcripts --logs --allowlist allowlist.json --report run/scan.json artifacts/

# An existing local image (docker save, scan, delete the export).
TMPDIR=/path/on/real/disk scripts/tests/canary-scan.sh --canaries run/canaries.txt --images \
    --docker-image blindpass-p06-controller:TAG empty-dir/
```

Options: `--key-material FILE` (raw key bytes or a PEM key; searched in every encoding, never printed),
`--class-glob log=GLOB` (extra file-name classes), `--no-pattern-scan`, `--max-depth`, `--max-bytes`,
`--max-entries`. A canary list is one value per line, or a JSON array of strings. Use harness-generated random
canaries; never put a real secret in the list. The scanner never prints a canary, an encoding of one, key
material or a matched secret. Hits carry the first 8 hex digits of the canary's SHA-256, a location in which
canary-bearing names are replaced by `<canary>`, a byte offset and a count. Secret-shaped hits carry the shape
name and a SHA-256 prefix of the match.

## What it finds

Every canary is searched in these renderings: raw UTF-8, UTF-16LE/BE, hex (both cases), base64 and
base64url at all three byte alignments (so a canary inside a longer base64 stream is found), URL percent
encoding (minimal, form and every byte, both cases), JSON string escapes (ASCII, `\/`, `\uXXXX`), HTML
entities, a Rust `Vec<u8>` debug list (`80, 48, ...`) and `\xNN` escapes. Matches that straddle a 1 MiB read
chunk are found. Text-like files are searched a second time with CR, LF, space and tab removed
(`+wrapped`), which finds a canary wrapped over lines. `.jsonl`/`.ndjson` transcripts are parsed and their
string values concatenated per key and overall (`json-joined`), which finds a canary split over streaming
deltas. Names are scanned too: top-level file names, tar member names, link targets, user/group names, pax
headers, zip names and comments, ar member names, symlink targets (symlinks are never followed).

Containers are unpacked recursively: tar (ustar, pax, GNU), zip, ar (`.deb`), gzip, bzip2, xz and zstd
including concatenated streams. Docker-save and OCI exports are checked as images: every layer is scanned
(including content a later layer deletes), each blob is hashed against its digest name, every manifest, config
and layer reference must be present, and the config is checked for secret-named environment values and
secret-looking assignments in `history`.

Secret shapes (default on): PEM private-key header **with a following base64 body** (a header string alone is a
literal inside OpenSSL, Node and Go binaries), age secret keys, JWTs, `Bearer` tokens with a digit, agent API
keys `ak_<uuid>_...`, enrollment tokens `en_<uuid>_...`, signed-link parameters (`metadata_sig`, `submit_sig`,
`sig` with 40 or more characters) and the bootstrap-token header value.

Forbidden names (anywhere in a tree or archive): `root-secret`, `agent-jwt-secret`, `issuer-key`,
`controller-backup-signing-credential`, `recovery-credential`, `authority-password*`, recipient or recovery
*key* files (certificates are fine), age identities, `.env` and `.env.*` (not `.example`/`.sample`), SSH
private keys, `.git-credentials`, `.netrc`, `.pgpass`, `*.key`, `*-key.pem`, `*private*.pem`, `*.p12`,
`*.pfx`, `*.jks` and P06 staging directories `.backup-<32 hex>`.

Class checks:

* **Backups** (`.bpbackup`, `.cms`, `.p7m`, or a file starting with a DER SEQUENCE and the CMS signedData OID):
  must be a CMS envelope whose DER length equals the file size, with ciphertext-grade entropy (at least 7.9
  bits/byte over a sample of 32 KiB or more), no canary or key bytes, and no plaintext SQLite or `pg_dump`
  file in the same directory or in a staging directory directly below it. The live database in a parent
  directory is not residue. Authenticity and decryptability are **not** checked here; `blindpass backup verify`
  does that.
* **Dumps**: ELF core files (by header) and conventional names (`core`, `core.*`, `*.core`, `*.dmp`,
  `*.crash`, `*.coredump*`); `core.*.zst` from systemd-coredump is decompressed first. A dump is raw memory:
  a canary in a dump of the consumer process is **expected** (it holds the delivered secret by design), so
  that case needs an allowlist entry with a reason and the real control is `LimitCORE=0` (below).
* **Transcripts / logs**: by extension and name; empty ones fail.

## Allowlist

A JSON array of `{kind, id, path, reason[, sha256]}`. `kind` is `canary` (id = 8-hex canary id or `*`),
`pattern` (secret shape name or `*`), or a finding kind (`forbidden-name` with the rule id such as
`root-secret` or `.backup-staging`, `backup-not-cms`, `backup-not-ciphertext`,
`plaintext-database-next-to-backup`, `image-env-secret`, `image-history-secret`). `path` is a glob over the
printed location (`archive.tar.zst!zst!dir/file`). `reason` must be at least 10 characters. `sha256`
optionally pins the exact leaf content, so a changed file no longer matches. An allowlisted hit is printed
with its reason and counted; it is never dropped. Unused entries are reported (and fail under
`--strict-allowlist`). The reviewed allowlist for the P06 images is
[evidence/p07-exposure-2026-10-06/allowlist.json](evidence/p07-exposure-2026-10-06/allowlist.json).

## Blind spots

These are not detected, and a clean result must be read with them in mind:

* Anything compressed or encrypted by something the scanner does not unpack: a compressed or encrypted blob
  inside a database or JSON field, zlib or brotli streams inside non-archive files, encrypted zip members
  (fail), password-protected or encrypted files (including the `.bpbackup` ciphertext itself, which is only
  checked for the absence of known plaintext and key bytes), squashfs/qcow2/vmdk/cpio/rpm (fail rather than
  skip), compressed swap or memory.
* Transformed values: case-folded, truncated below a rendering's minimum (8 bytes), hashed, derived (HKDF
  output), XOR'd, base32, base64 of base64, UTF-32, EBCDIC, hex with separators, a canary split across
  different files or archive members, or split over text lines that are not JSON records and not wrapped by
  CR/LF/space/tab.
* Secrets that are not canaries and do not look like the listed shapes (an arbitrary password in a log).
* Live state: running processes (`/proc/*/cmdline`, `environ`), tmpfs and RAM, swap, kernel memory. Capture
  them into files inside the VM or container and scan the captures; the in-guest scanners in the P01/P05
  harnesses do this for argv/environ today.
* Exposure that is by design. A hit is *evidence*; whether it is accidental disclosure or the documented
  session, service-delivery or controller-visible-metadata boundary is the reviewer's decision, recorded as
  an allowlist reason.
* Correctness of the signature, the authenticated encryption or the restore of a backup, and image
  provenance. This is an exposure scanner, not a verifier.

## Core dump limits

`scripts/tests/check-core-limits.py PATH...` requires `LimitCORE=0` in the `[Service]` section of every
`*.service` and `ulimits.core: 0` (or soft and hard 0) on every service of every `compose*.yml` (YAML
anchors resolved), with a reasoned `--exceptions` file, and fails closed on unparsable input or no input.
It exists because a crash dump of a process that holds decrypted keys or credentials is the artifact most
likely to leak them, and the scanner above can only find that leak afterwards.

## Harness integration (P07_RUN) and fail-closed in-run scans

The P06 harnesses no longer run `secret in text` against whatever a capture returned. They call
`tests/deployment/canary_log_scan.py::assert_log_clean` (standard library only, so a guest harness can carry it
next to itself: `native-install.sh` and `p06-native-node-vm.py` copy it with `native-guest.py`). It fails when the
capture is missing, empty or under a minimum size, when it lacks content a genuine capture must hold, when there
is no usable canary, or when its finder cannot see a random token planted in a copy of the same log (a positive
control, through the same function as the real scan). A failure names the label, counts and SHA-256 prefixes,
never a canary or log text. Its tests are `tests/deployment/canary_log_scan_test.py`.

When `P07_RUN=<absolute directory>` is set, each scanned log is also exported to `$P07_RUN/logs/` (mode 0600) and
every canary the offline scanner can use (at least 12 bytes, 8 distinct bytes, one line) is appended to
`$P07_RUN/canaries.txt`; markers such as the PEM header are checked but never registered. Then scan the directory:

```sh
scripts/tests/canary-scan.sh --canaries "$P07_RUN/canaries.txt" --logs --exclude '*/canaries.txt' \
    --allowlist docs/testing/evidence/p07-exposure-2026-10-06/allowlist.json \
    --report "$P07_RUN.scan.json" "$P07_RUN"
```

Add `--archives`, `--images`, `--backups`, `--dumps`, `--transcripts` for the classes the run produced: a class you ask for
and that has no artifact is exit 3 by design (a run that produced no dump, such as a `LimitCORE=0` crash, is
reported as `no dump files` in the evidence rather than scanned with `--dumps`). The canary list is excluded
because the scanner would otherwise report it as the exposure it is; the exclusion is printed in the report. Keep the
report outside the scanned directory.

Without `P07_RUN` nothing is written. Not every capture reaches the host: `native-guest.py` (the single-guest native
lifecycle) scans in the guest with the same helper and exports nothing; `compose-backup*.py` still check command
output and Compose logs for the PEM header only.

The shell fleet harnesses use the same export through `tests/fleet/p07_export.py` (tests: `tests/fleet/p07_export_test.py`).
`p03-vm.sh` registers the generated root, agent and issuer secrets, the admin seed's temporary password and session id
(its identifiers, username and CSRF value are skipped: the controller stores them by design) and each enrolment token
before it is deleted, and exports the guest journals, the controller, proxy and serial logs and the E01 state dump. A
failed run exports the same captures from `cleanup()`. The `P03VISIBLE` positive-control value goes on a separate list,
`$P07_RUN/control/canaries.txt`: scanning the export with that list must exit 1, scanning it with the real list must not.
The helper prints counts only and writes nothing to stdout, because `p03-vm.sh` calls it inside command substitutions.
`RUST_LOG=debug` is passed to the controller of `p06-relay-vm.py` (and so of the harnesses built on it) when set; it
applies to the host controller only. `p06-relay-vm.py::scan_logs` requires 256 bytes from a controller that served and,
from a `stale*` controller, at least 32 bytes that contain `"startup_failed"` (its genuine single refusal line).

## Decisions applied pending owner confirmation (2026-10-06)

* **Consumer and service dumps.** `LimitCORE=0` / `ulimits.core: 0` is enforced by `check-core-limits.py` as a CI
  step (`npm run test:exposure`). A dump that contains a canary is acceptable only from a disposable guest in
  which the limit was lifted on purpose, and only with an allowlist entry whose reason says so.
* **Image gate scope.** The gate covers images a release path publishes or a shipped Compose profile runs
  (controller, edge, the legacy images). The 7 GB `pgtest` toolkit image carries test keys and the repository
  source by design and is excluded; that is sound only while nothing builds, pushes or runs it, which
  `scripts/tests/release-workflow.test.mjs` asserts (only the Dockerfile stage may name it). It must never be
  published.
* **Allowlist governance.** An entry needs a written reason of at least 10 characters and, when the object is a
  file, a `sha256` pin. The repository maintainer reviews every new entry; `--strict-allowlist` fails on stale
  ones. An allowlisted hit is still printed.
* **Language.** The scanner stays standard-library Python (3.10+, `zstd` binary or 3.14 `compression.zstd`).

## Tests

```sh
python3 -m unittest scripts/tests/canary_scan_test.py        # 68 tests, ~25 s
python3 -m unittest scripts/tests/check_core_limits_test.py  # 6 tests
python3 tests/deployment/canary_log_scan_test.py             # 23 tests, the in-run helper
```

The tests were written first and run red (every test failed because the scanner did not exist), then green.
They contain a planted positive for every encoding, every container type, every class and the nested case;
clean controls for each; and fail-closed cases for every incomplete reason listed above. They also assert that
no stdout, stderr or report ever contains a canary in any rendering. The execution record, the mutation check
(deliberately broken scanners that the tests must reject) and the scan of existing artifacts are in
[evidence/p07-exposure-2026-10-06.md](evidence/p07-exposure-2026-10-06.md).
