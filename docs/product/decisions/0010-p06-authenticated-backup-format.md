# 0010: P06 authenticated complete backup candidate

**Status:** Implementation candidate, 2026-10-03. Selected SQLite source component gates
are verified in the [execution record](../../testing/evidence/p06-backup-components-2026-10-03.md).
PostgreSQL capture/isolated verification, shipped native/OCI
backup rehearsals and complete P06-D5 acceptance remain open. This record does
not authorize activating a restored issuer. [P06](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/phases/06-deployment-and-recovery.md)
and its [paired tests](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/testing/phases/06-deployment-and-recovery.md)
remain authoritative.

**Amended 2026-10-05:** the single-credential custody described below is superseded for shipped packaging by [0013](0013-p06-backup-key-custody-split.md), which splits the signing credential from an offline recipient key and stages restores on tmpfs. The archive format below is unchanged and the single credential is still accepted for verification and restore of every archive made under this record.

## Format and custody

Use standard OpenSSL CMS. Encrypt a complete canonical USTAR bundle with
AES-256-GCM AuthEnvelopedData, RSA-OAEP/SHA-256 recipient key transport, then
sign the entire encrypted CMS object with CMS SignedData, RSA-PSS/SHA-256.
The dedicated recovery credential is a mode-0600 PKCS#8 RSA-3072 key and one
certificate, created explicitly without overwrite in a mode-0700 directory.
It is independent of the controller's root, JWT and issuer keys. Keep a
protected offline recovery copy; losing this key loses backup access.
The command does not accept a password or key value in argv/environment.
Passphrase-based archives and encrypted PKCS#8 credentials are not implemented.

Verification first checks the outer SignedData type and the independently
provided recovery certificate using `cms -verify -nointern`. `-noverify` skips
certificate-chain/expiry validation for this exact offline pinned certificate;
it does **not** skip signature verification. No embedded certificate is trusted.
Only after successful signature verification is the AuthEnvelopedData object
passed to `cms -decrypt`. This requires both authenticated decryption and the
expected signer. Possession of a public recipient certificate cannot authorize
a forged replacement bundle. CBC and unsigned inputs are refused.

OpenSSL implements the cryptography and CMS parser. The repository checks a
small definite-length ContentInfo header/type before each parser operation.
It implements no cipher, KDF, signature primitive or general ASN.1 decoder.
Both CMS objects use definite-length DER. [OpenSSL documents CMS authenticated
encryption](https://docs.openssl.org/3.0/man1/openssl-cms/), and
[RFC 5084](https://www.rfc-editor.org/rfc/rfc5084.html) specifies AES-GCM in CMS.

The archive contains exactly `manifest.json`, `root-secret`, `agent-jwt-secret`,
`issuer-key` and either `database.sqlite` or `database.pgcustom`. The manifest
binds format/controller/schema version, backend, tenant, snapshot issuer epoch,
persisted clock watermark, every table's row count and member sizes/SHA-256
digests. Digests provide inner consistency; the signature and GCM provide
authenticity. The snapshot epoch is **not** a protected external recovery
high-watermark. Slice 6 must bind external continuity and invalidate/reconcile
stale authority before any activation command exists.

Version 1 accepts one canonical regular-file USTAR encoding: fixed names/order,
mode 0600, zero UID/GID/time, empty link/prefix fields, valid checksum, exact
sizes, zero padding and two terminal blocks. It refuses extensions, links,
duplicates, traversal, extra members and trailing data. The extractor uses
compiled allowed names and exclusively creates private files. It never passes
arbitrary archive paths to a filesystem extractor.

## Capture, publication and limits

SQLite uses completed `VACUUM INTO`, including committed WAL state. Matching
metadata comes from the resulting read-only immutable snapshot. Verification
runs integrity, foreign-key and current-schema checks and compares snapshot
metadata with the manifest; it neither migrates nor initializes the snapshot.
PostgreSQL must use `pg_dump -Fc` with a held exported snapshot and matching
metadata, followed by an actual isolated `pg_restore`. That adapter and its
matching tools remain required work; the current candidate refuses it explicitly.

Capture holds a shared controller key-directory lock and copies immutable key
values, comparing all three with loaded configuration. Key-changing tools must
hold the exclusive directory lock. Privileged manual replacement outside this
protocol is not covered. No replacement key or missing database is generated
as a backup side effect.

All work uses private staging. Creation validates the entire decrypted bundle
before atomic no-replace publication of the encrypted file and directory flush.
The complete plaintext USTAR limit is 512 MiB; encrypted CMS overhead is bounded
to an additional 1 MiB. Each child has a 60-second deadline, a file-size limit,
no core dumps, no new privileges and parent-death termination; ordinary failures
kill/reap children and remove staging. SQLite capture is also bounded to 60
seconds. This is a small-fleet limit, not an unlimited database-backup claim.
OpenSSL buffers CMS payloads in memory; the archive limit is not a measured
512-MiB total-RAM guarantee.

Plaintext consumers are the backup process, OpenSSL children and private staging
files (database, complete tar and recovery credential). The controller database
backup includes metadata and encrypted legacy payloads, not the broker's
volatile Source custody. Verification creates another private plaintext copy
for database checks. Ordinary return removes these files; SIGKILL/power loss can
leave private residue requiring explicit cleanup. Unlinking is not secure media
erasure. The published archive is encrypted; temporary staging is protected by
permissions, not by archive encryption while it exists. A stopped subprocess's
address space is released; this record does not claim swap/forensic erasure.

Use `blindpass backup cleanup --work-directory <absolute-private-directory>`
after interruption. The explicit command locks the parent exclusively and
preflights every reserved `.backup-<32 lowercase hex>` directory for private
current-UID ownership, no linked ancestors and an exclusive directory lock.
Managed capture and verification hold conflicting locks for their lifetime;
busy or unsafe residue refuses cleanup. Only reserved staging directories are
removed; encrypted backups, recovery credentials and unrelated names remain.
Symlinks within a removable private stage are unlinked without following them.
Normal successful cleanup flushes the parent directory. This is private residue
removal, not secure media erasure or restored-state activation.

## Tool review and prerequisites

No Cargo/npm dependency or lockfile changes are needed. The existing deployment
already uses OpenSSL/libcrypto; `openssl` is now an explicit backup prerequisite.
An additional age/archive library would need a fresh dependency-guard review.
This choice preserves [decision 0004](0004-controller-dependency-review-2026-09.md)'s
boundary against bespoke crypto. It is not an independent cryptographic audit.

CMS handling requires a patched OpenSSL, including the fix for
[CVE-2025-15467](https://openssl-library.org/news/secadv/20260127.txt).
The candidate accepts the documented upstream fixes: 3.0.19, 3.3.6, 3.4.4,
3.5.5 or 3.6.1 and later patch releases in those lines. For the supported native
distributions, it checks both command and library package versions against
Debian 12's `3.0.18-1~deb12u2` or Ubuntu 24.04's `3.0.13-0ubuntu3.7` backports.
These minima come from [Debian's tracker](https://security-tracker.debian.org/tracker/CVE-2025-15467)
and [Ubuntu's tracker](https://ubuntu.com/security/CVE-2025-15467).
Unknown/prerelease version lines are refused. This prerequisite addresses
that parser vulnerability; it is not a claim that all platform vulnerabilities
have been reviewed. Actual vendor-backport and packaged artifact gates remain
separate from the development host's OpenSSL 3.6.4 check.
