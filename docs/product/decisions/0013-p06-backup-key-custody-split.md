# 0013: P06 backup key custody split (signing credential and offline recipient key)

**Status:** Accepted by the project owner on 2026-10-05 (P06-D29), implemented and gated as recorded in the [execution record](../../testing/evidence/p06-backup-custody-split-2026-10-05.md). This amends the custody rules of [0010](0010-p06-authenticated-backup-format.md); the archive format is unchanged. It does not authorize activating a restored issuer and does not establish P06 acceptance.

## Context

0010 used one dedicated recovery credential (an RSA-3072 key and certificate) for both roles: the backup job signed the sealed archive with it and the same file decrypted it. The backup job must therefore hold a key that can read every archive it ever produced. Anyone who obtains that credential from the backup host and the archive store together reads all retained archives, and can forge new ones. Restores also staged the decrypted bundle (including the three controller keys) in a directory on persistent disk, so a crashed restore left plaintext keys behind.

What the split does **not** change: the backup job runs next to the controller, so it can already read the *live* keys and database through `BLINDPASS_KEYS_DIR` and the store. A compromised backup host still exposes current secrets. The split protects archives at rest (the confidentiality of history) and narrows what a stolen host credential can do to future restores.

## Decision

1. **Two credentials, two roles.**
   - **Signing credential** (`backup key-init --role signing`): RSA-3072 private key and certificate in one mode-0600 file, `keyUsage=digitalSignature`. It lives on the host that runs `backup create` and signs archives. Its certificate is also written to a certificate-only file for the operator's restore machine.
   - **Recipient credential** (`backup key-init --role recipient`): RSA-3072 private key and certificate, `keyUsage=keyEncipherment`. The private credential stays **offline or off the backup host**. Only the certificate-only file is placed on the backup host.
2. **Create path (backup host).** `backup create --signing-credential-file S --recipient-certificate-file C`. The recipient file must contain exactly one certificate and **no private key block**, must differ from the signing certificate, and must not be the same file as the signing credential; each violation refuses before any output exists. The host never holds a key that can decrypt what it writes.
3. **Open path (verify, restore, handoff import).** `--recipient-key-file R --signing-certificate-file S`. Verification still checks the pinned signer before parsing attacker-controlled AEAD parameters, then decrypts with the recipient key. The signing file may be certificate-only or a full credential; only its certificate is used. An optional `--expected-archive-sha256` on `verify` and `restore` rejects an archive whose digest is not the one the operator recorded off-host.
4. **Create-time verification without a standing decrypt key.** `create` generates a throwaway RSA-3072 key in private staging and encrypts the bundle to **two** recipients in one OpenSSL invocation: the offline recipient certificate and the throwaway certificate. It then runs the existing full verification (signature check, authenticated decryption, extraction and the isolated restore) with the throwaway key, publishes, and destroys the throwaway key with the staging directory. Create-time `verified:true` therefore keeps its meaning (complete decrypt and isolated restore of the exact sealed bytes) while the host keeps no key that decrypts past archives. The offline recipient's own key-transport entry is made by the same OpenSSL call from the same content key but is **not** decrypted at create time; only an operator `backup verify` with the recipient key proves it. Operators must run that verification (or a restore drill) on a schedule.
5. **Restore staging on tmpfs.** `restore` and `handoff import` decrypt and extract into a private directory on a tmpfs or ramfs mount (`--staging-directory`, else `BLINDPASS_RESTORE_STAGING_DIR`, else `$XDG_RUNTIME_DIR/blindpass-restore`, else `/dev/shm/blindpass-restore-<uid>`). They refuse when none is a tmpfs/ramfs mount owned by the current user with mode 0700 (the directory is created if absent), or when its free space is below twice the archive size plus 8 MiB. The decrypted tar, the extracted members and the three keys exist only there; the database is copied to the disk stage because the store must open it, and the keys are copied into the disk stage only after the database work and invalidation succeed, immediately before publication. The tmpfs stage is removed on every exit. Power loss or SIGKILL leaves nothing on persistent disk beyond the destination stage that existed before this change. The PostgreSQL verification cluster stays in the disk work directory.
6. **Backward compatibility.** `--recovery-key-file` (one credential for both roles) is still accepted by `create`, `verify`, `restore`, `migrate` and `handoff`, and every archive made under 0010 verifies and restores unchanged with it. Legacy `create` keeps the old full self-verification and has the old property that the creating host can decrypt. New archives made in split mode are structurally the same CMS objects plus a second `RecipientInfo`, so no manifest or format-version change is needed and restore with either credential model reads either kind. Shipped packaging uses the split model.

## What a stolen signing credential still allows

An attacker holding the signing key and the public recipient certificate can produce archives that a restore accepts as authentic. This is a forgery risk, not a confidentiality risk. Mitigations, none of which is cryptographic proof:

- Restore binds the manifest tenant to the operator-supplied tenant and the restored issuer key to the external authority record, then invalidates all restored authority state; a forged archive cannot take over an issuer it does not hold.
- `create` prints the sealed archive's SHA-256. Record it somewhere the backup host cannot write; `--expected-archive-sha256` then refuses any other file.
- Rotate the signing credential after any suspected compromise and treat archives signed after the suspected start as untrusted; archives signed earlier are still verified with the old certificate.

No sequence number or anti-rollback counter is added: the attacker controls anything inside a forged archive, so a counter would not help, and the out-of-band digest record is the control.

## Rotation and loss

- **Rotate signing:** create a new signing credential, switch the job, keep the old certificate for verifying old archives. A compromised key is rotated at once; see above for the trust window.
- **Rotate recipient:** create a new recipient credential and put its certificate on the host. Older archives still need the older recipient key; keep it offline until the archives age out of retention. A new recipient does not re-encrypt old archives.
- **Lose the recipient private key:** every archive encrypted to it is unreadable. Keep at least two protected offline copies. Loss of the signing key only stops new archives until a new one is created.
- **Lose the throwaway key:** by design it is destroyed at the end of each create.

## Alternatives considered

- **Verify the plaintext before encryption and only check the sealed object's structure.** Cheaper, but then no step proves that the sealed bytes decrypt; a bug in encryption would surface only at restore time.
- **Keep the single credential and rely on file permissions.** Does not meet the owner's direction; one stolen file reads and forges everything.
- **Wrap the recipient key with a passphrase or an HSM.** Passphrase-based archives and encrypted PKCS#8 are not implemented (0010) and an HSM adds a dependency; the offline recipient key can still be held in either by the operator.
- **A signing authority separate from the backup host.** Stronger against forgery, but needs a signing service the project does not have.

## Consequences and limits

- The create host can no longer open its own archives; operators need the offline key for verification, drills and restores.
- The throwaway key exists in private staging for the length of one create run; the host process and OpenSSL children can use it during that time.
- tmpfs holds the decrypted bundle during restore (at most the 512 MiB bundle limit plus overhead). Containers need a tmpfs for it; the shipped restore examples mount one. This is not swap or forensic erasure: unlinking tmpfs files is not secure erasure and a swapped page is outside this record.
- Tests ran on x86-64 with OpenSSL 3.6.4 (host) and the pinned distribution OpenSSL in the guests and images; no independent cryptographic audit was made.
