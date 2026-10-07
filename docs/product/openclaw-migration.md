# OpenClaw credential migration — contract (P09.1)

**Status:** implementing (activated by owner instruction on 2026-10-07; operator need not named, recorded as open in the
[P09 plan](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/phases/09-openclaw-migration.md)).
**Supported release:** OpenClaw `2026.8.35` only. Any other release is refused, not best-effort.
**Package:** `packages/openclaw-plugin` (MIT), `src/migrate/`, npm bin `blindpass-openclaw-migrate`.
**Tests:** `packages/openclaw-plugin/tests/migrate/` (hermetic) and `tests/openclaw/` (disposable VM, real OpenClaw).

This document is the contract the implementation and its tests are held to. Where it says "implemented in slice N" the
slice table at the end is the only statement of what exists today.

## Pinned release

| Item | Value |
|---|---|
| npm package | `openclaw@2026.8.35` (dist-tag `extended-stable` on 2026-10-07) |
| npm integrity | `sha512-7Bk/IeHTk04gfR4rW2SEVwwmGiXg2CcRxL3K1U2JzTgwbSSSlbX/yoLEbkiiSMOLtOuAi1ZfVbgmSsSlOA/E6g==` |
| CLI build | `OpenClaw 2026.8.35 (713ba57)` |
| Source tag | `v2026.8.35` (tag object `51d9d172a047`) |
| Node engines | `>=22.22.3 <23 \|\| >=24.15.0 <25 \|\| >=25.9.0`; the guest runs Node 26.10.0 |
| Credential matrix | `docs/reference/secretref-user-supplied-credentials-matrix.json` at the tag, vendored unmodified as `src/migrate/registry/openclaw-2026.8.35.credential-matrix.json` (sha256 `0c07989dca9dc4dce46e12daecb7af8246da9c41ec64d326facd53109e548921`): 112 `openclaw.json` targets, 2 SQLite auth-profile targets |
| Reviewed docs | [Secrets management](https://github.com/openclaw/openclaw/blob/v2026.8.35/docs/gateway/secrets.md), [apply plan contract](https://github.com/openclaw/openclaw/blob/v2026.8.35/docs/gateway/secrets-plan-contract.md), [CLI `secrets`](https://github.com/openclaw/openclaw/blob/v2026.8.35/docs/cli/secrets.md), [credential surface](https://github.com/openclaw/openclaw/blob/v2026.8.35/docs/reference/secretref-credential-surface.md) |

Dependency review: OpenClaw, `sops` and `age` each fail Socket review (`openclaw@2026.8.35`: block, deep scores
35/50/35/50, a high CVE in `@modelcontextprotocol/sdk`, install scripts, 396 transitives; `sops` v3.13.3: block;
`age` v1.3.2: block pending human review). The owner approved running them **only inside the disposable VM guest** on
2026-10-07. They are never installed on the host, and no repository manifest or lockfile lists them. The sops and age
release binaries are hash-pinned in `tests/openclaw/tools.lock`; OpenClaw is installed from npm inside the guest only.

## Architecture

BlindPass does not rewrite OpenClaw's files itself. OpenClaw 2026.8.35 ships `openclaw secrets audit|apply|reload`, a
versioned apply-plan contract and SQLite-backed auth profiles; writing those formats ourselves would mean owning a schema
the runtime owns. The migration therefore orchestrates the native workflow:

1. **Inventory** `openclaw.json` (and `.env`) read-only; classify each credential field with the vendored matrix.
2. **Preflight** the destination SOPS/age store, key, exec-provider command and the `openclaw` CLI.
3. **Back up** the files that will change into a protected directory.
4. **Import** the plaintext values into the encrypted store in one batch and verify them through the real resolver.
5. **Rewrite** by generating an apply plan (`version 1`, `protocolVersion 1`) with an exec provider alias and refs, then
   running `openclaw secrets apply --from <plan> --allow-exec` (after a `--dry-run --allow-exec`).
6. **Verify, commit and report**; the operator runs `openclaw secrets reload` (or `--reload`) and the migration is
   **not** complete until the runtime has consumed the new references after that reload.

The apply plan always sets `scrubEnv: false` and `scrubAuthProfilesForProviderTargets: false`: removing plaintext
originals other than the rewritten config fields is a separate explicit operator action (see "Residual plaintext").

## Supported and unsupported forms

| Source | Treatment |
|---|---|
| `openclaw.json` strict JSON, any of the 112 matrix paths holding a non-empty string | **Supported.** Imported, rewritten to `{source:"exec", provider:<alias>, id:<store name>}` |
| `openclaw.json` with comments, trailing commas or other JSON5 | `unsupported: not-strict-json`, file untouched (OpenClaw itself writes strict JSON) |
| Field already a SecretRef (`env`, `file`, `exec`, `store`) | Skipped, `already-reference` |
| `${VAR}` / `$VAR` env shorthand | Skipped, `env-reference` |
| `secretref-env:` legacy marker, `__OPENCLAW_REDACTED__`, `oc-sent-v*` sentinel | `unsupported`, reported; `openclaw doctor --fix` owns the legacy marker |
| Structured value (e.g. inline Google Chat `serviceAccount` JSON), array, number, boolean, null | `unsupported: structured-value` / `non-string-value` |
| Empty or whitespace-only string | Skipped, `empty` |
| Key segment that is empty, contains `.`, or is `__proto__`/`prototype`/`constructor` | `unsupported: ambiguous-path-segment` / `forbidden-path-segment` (the plan contract rejects such paths) |
| `.env` in the config directory | **Inventoried only**, parsed exactly as `dotenv` 17.4.2 does, never sourced or expanded. A value equal to a migrated config value is reported as residual plaintext; any other credential-looking name is `unsupported: no structured SecretRef` and left untouched |
| SQLite auth profiles (`state/openclaw.sqlite`, 108 tables, no documented export) | **Not inspected, unsupported.** Reading an unreviewed internal schema is out of scope; use `openclaw secrets configure` for those |
| Legacy `auth-profiles.json` / `auth.json` | Retired by the release; `openclaw doctor --fix` owns it. Not read |
| Node-host `gateway.cloudflareAccess.*` (SQLite machine state) | Not a `secrets apply` target; unsupported |
| Files over 1 MiB | `unsupported: too-large` |

Per-value classes are implemented in `src/migrate/classify.mjs`; matrix expansion in `src/migrate/registry.mjs`;
`.env` parsing in `src/migrate/dotenv.mjs`. Diagnostics carry a path or line number and a reason, never a value.

## Path and ownership rules (P09-D3)

Operation is limited to one explicitly selected config root (`--config-dir`); there is no filesystem discovery. The tool
runs on Linux only and fails closed elsewhere. Every path component is resolved beneath an opened directory descriptor
(`/proc/self/fd/<n>/<name>` with `O_NOFOLLOW`), and the following are refused:

- a root or ancestor that is not owned by root or the current user, or is group/other-writable without the sticky bit;
- any symlink, non-regular file, hard-linked file (`nlink > 1`) or file owned by another user;
- a file or directory that is group/other-writable (group/other-readable only produces a warning);
- source content or identity that changed between inventory and the point of use.

Exclusive migration and store locks are held for the whole run. Created files are `0600` (directories `0700`), written
to an exclusive temp name in the target directory, `fsync`ed, renamed, and the parent is `fsync`ed.

## Exec provider contract

OpenClaw runs `command` directly, never through a shell, and requires it to be an absolute path that is **not a symlink**,
not group/world-writable and owned by the current user. An npm `bin` shim is a symlink, so the resolver must be a real
file. The migration requires `--resolver-command <abs path>`, applies the same checks before planning, and writes:

```json
{"source":"exec","command":"<abs>","args":["--store","<abs store path>"],"passEnv":["PATH"],"jsonOnly":true}
```

`PATH` is passed because the resolver is `#!/usr/bin/env node` and shells out to `sops`. Protocol v1 is
`{protocolVersion, provider, ids}` on stdin; store entry names are limited to `[A-Za-z0-9._-]{1,128}` (the resolver's
pattern) and are derived from the config path. `openclaw secrets apply --dry-run` only runs the resolver with
`--allow-exec`; write mode rejects exec providers without it.

## Key and store availability (P09-D5)

Dry run never creates a key, `.sops.yaml` or store and never calls `openclaw` or the resolver. Mutation requires: `sops`
>= 3.9.0 and `age-keygen` on `PATH` (verified against sops 3.13.3 / age 1.3.2), an existing store that decrypts with its
key, and `bootstrap_backup_pending` cleared. Creating a store/key is the distinct `--init-store` action. Clearing the
pending flag is the distinct `--ack-backup <key backup file>` action, which first proves the backup can decrypt a dummy
value for the store's recipient: an acknowledgement alone is not evidence that the key can be restored. A missing or wrong
key fails preflight before any file changes; there is no plaintext fallback.

## Journal, backups and rollback (P09-D4)

`.blindpass-migrate.journal.json` (`0600`, config directory) records the migration ID and, for each stage in
`inventory → backup → import → rewrite → commit`, a durable *intent* before effects and a *completion* after. It holds
paths, store names and the whole-file hash of `openclaw.json`; never a value or a per-value hash. A mutating run holds
`.blindpass-migrate.lock` (pid plus process start time, so a stale lock from a dead process is detected and a recycled pid
is not mistaken for a live owner). A journal older than 24 h produces a staleness warning.

- **Backup.** Originals are copied to `.blindpass-backup/<migration id>/` (`0700`, files `0600`, hash-verified, with a
  `MANIFEST.json`). **These backups contain plaintext by design.** They are inventoried in the journal and the report
  states the residual exposure; no automatic deletion happens and erasure of historical copies is never claimed. The backup
  is the source of truth for every later stage: import reads the values from it, rewrite verifies the config still holds
  them, rollback restores from it.
- **Resume.** A rerun of `--apply` continues the unfinished migration (same settings required, otherwise
  `journal-mismatch`). Each stage re-derives its state from the files and the store, not from the journal: import skips
  entries that already hold the identical value, rewrite skips the native write when the config already holds every
  reference and the planned provider.
- **Config changed since the backup.** If a migrated field no longer holds the backed-up plaintext (the operator rotated
  it) the rewrite stops with `config-changed` and the credential is never overwritten. Unrelated edits are carried through
  by the native write.
- **Rollback.** `--rollback [--migration-id <id>]` is valid from any state, including a crashed run and a crashed
  rollback. If the config still has the exact bytes the native write produced **and** the rewrite started from the
  backed-up bytes, the original is restored byte for byte. Otherwise each migrated path is restored only where it still
  holds this migration's reference, the provider is removed only if this migration added it and nothing references it
  any more, and the file keeps its indentation; later unrelated edits survive. Encrypted store entries and the backup are
  kept. If a secret was rotated in the store after the migration, rollback restores the value from before the migration.
- **Several migrations.** A committed or rolled-back journal is archived as `.blindpass-migrate.journal.<id>.json` when a
  later migration starts, so an earlier migration stays available to `--rollback --migration-id`.

## Residual plaintext

Observed on 2026.8.35: **every config write leaves `openclaw.json.bak` (plus rotated `.bak.N`) holding the previous
plaintext config, and `openclaw secrets audit` does not scan them.** After a successful migration those files, the
original `.env` values, generated `agents/*/agent/models.json` files and the SQLite auth profiles can still hold the
migrated secrets. The migration scans a fixed, bounded set of such files inside the config root for the exact migrated
values and lists file names (never values) as residual plaintext in the report and the exit status. It does not delete
them: removal is a separate operator action with storage-erasure limits.

## Reload semantics (observed, real gateway)

The gateway resolves exec references at activation. After rotating `gateway.auth.token` in the store: **before**
`openclaw secrets reload` the old token was still accepted and the new one rejected; **after** reload the old token was
rejected and the new one accepted. `openclaw secrets reload` closes its own connection when the gateway auth changes and
returns `ok:false` (`gateway closed (4001): gateway auth changed`) even though the swap succeeded, so the migration
verifies by authenticated behaviour, not by that exit code.

## Findings that shaped the contract

| ID | Finding (2026-10-07, disposable guest) | Consequence |
|---|---|---|
| F-1 | The existing managed store never worked with real `sops`/`age`: `sops --encrypt` found no creation rule, and `.age-key.txt` held a `Public key:` line sops rejects | Fixed in `506b2d8`; `sops encrypt` on stdin with `--filename-override`, sops >= 3.9 enforced |
| F-2 | `openclaw config validate` and `secrets audit` create `state/openclaw.sqlite` in a pristine directory | The dry run never invokes `openclaw` |
| F-3 | `openclaw.json.bak` keeps prior plaintext after every write and is not audited | Residual-plaintext scan and explicit reporting |
| F-4 | A BlindPass resolver at an absolute non-symlink path, with `passEnv:["PATH"]`, resolved 4/4 refs under `apply --dry-run --allow-exec` | `--resolver-command` contract above |
| F-5 | `apply` preserved key order, wrote strict JSON, inserted `secrets.providers.<alias>`, left `.env` untouched with `scrubEnv:false` | Plans always disable both scrubs |
| F-6 | `secrets audit` flags only known provider env names in `.env` | Our own bounded `.env` inventory is required |
| F-7 | Reload behaves as described above, including the misleading 4001 result | Verify by authenticated use |
| F-8 | The native `apply` accepts only target types the installed runtime and its plugins know: a plan containing one unknown type is rejected as a whole (`Invalid secrets plan file`) | The inventory tries the whole plan and, only on rejection, each target alone; unaccepted targets are reported `runtime-does-not-accept-target`, left as they were and never imported |
| F-9 | `apply` also writes `meta.lastTouchedVersion` and `meta.migrations` (observed in the real before/after fixtures) | Verification ignores `meta` and lists any other changed path as a warning |
| F-10 | Which exec providers `--allow-exec` runs beyond the planned one is not established for 2026.8.35 (checked in slice 5) | Treated conservatively: a pre-existing provider alias that differs from ours is refused (`provider-alias-conflict`); when other exec providers exist the post-migration native audit is skipped and reported |

## Bounds

| Bound | Value |
|---|---|
| Config/env file size | 1 MiB each |
| Journal staleness warning | 24 h since the last stage |
| Backup retention | none automatic; operator-approved, with the residual-exposure notice |
| Apply plan size | well under OpenClaw's 16 MiB limit; plan holds references only |

## Slice status

| Slice | Scope | State |
|---|---|---|
| 0 | Real-sops store fix | done (`506b2d8`) |
| 1 | This contract, vendored matrix, fixtures, registry/classifier/dotenv | done |
| 2 | Safe filesystem layer, inventory, dry run, output rules | done (hermetic: P09-I01) |
| 3 | Key preflight, backup/import/native rewrite, journal, rollback | done (hermetic: P09-I02, every stage killed and resumed or rolled back; real-runtime interruption is slice 5) |
| 4 | Key recovery and acknowledgement | not started |
| 5 | Reload, authenticated use on a real installation | not started |
| 6 | Packaging, operator docs, rollback rehearsal | not started |
