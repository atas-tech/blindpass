# Migrating OpenClaw credentials to the BlindPass store

`blindpass-openclaw-migrate` moves the plaintext credentials in an OpenClaw `openclaw.json` into the BlindPass
SOPS/age encrypted store and replaces each one with an exec-provider reference that OpenClaw resolves through
`blindpass-resolver`. It is reversible, journaled and restartable. The contract, findings and limits are in
[openclaw-migration.md](../product/openclaw-migration.md); the evidence is in the
[P09 execution record](../testing/evidence/p09-openclaw-migration-2026-10-07.md).

It is **not** a mandatory part of the fleet product, and it supports exactly one OpenClaw release today: **2026.8.35**.
Another release is refused (`native-version`), not guessed at.

## What it does and does not do

| Does | Does not |
|---|---|
| Moves plaintext string credentials in `openclaw.json` that the installed OpenClaw accepts as references | Migrate `.env` values, `models.json` copies or the SQLite auth profiles (`state/openclaw.sqlite`): they are reported, not changed |
| Rewrites `openclaw.json` through OpenClaw's own `openclaw secrets apply` (it never edits OpenClaw's formats itself) | Delete any plaintext original: the protected backup, `openclaw.json.bak*`, `openclaw.json.last-good` and `.env` all stay until **you** remove them |
| Verifies every imported value through the real resolver before the config changes | Reload the runtime for you (see [Activation](#activation)) |
| Leaves fields the installed runtime does not accept exactly as they were and lists them | Run on Windows or macOS: path safety is Linux-only and fails closed elsewhere |

## Prerequisites

- Linux, Node.js `^24.21.0 || ^26.10.0`, `sops` >= 3.9.0 and `age`/`age-keygen` on `PATH`.
- OpenClaw 2026.8.35 and its absolute `openclaw` executable path.
- The config directory (the OpenClaw state directory containing `openclaw.json`): owned by you, not group/other
  writable, no symlinks anywhere in its path. The tool refuses anything else with exit code 3.
- A **real, non-symlink** `blindpass-resolver` executable, owned by you and not group/other writable. OpenClaw refuses
  an exec provider whose command is a symlink, and an npm `bin` shim is one; copy or write a small launcher script:

  ```bash
  install -m 0755 /dev/stdin "$HOME/.openclaw/blindpass/blindpass-resolver" <<'EOF'
  #!/usr/bin/env node
  import { main } from "/absolute/path/to/blindpass-resolver.mjs";
  await main();
  EOF
  ```

## Procedure

Run every step with the same `--config-dir`; paths are absolute.

```bash
CFG="$HOME/.openclaw"
STORE="$CFG/blindpass/secrets.enc.json"          # default for --store

# 1. Read-only inventory. Nothing is created and no program runs unless you name a store.
blindpass-openclaw-migrate --dry-run --config-dir "$CFG" --store "$STORE"

# 2. One-time store and key setup. This is the only step that generates a key.
blindpass-openclaw-migrate --init-store --store "$STORE"
cp "$(dirname "$STORE")/.age-key.txt" /safe/offline/location/age-key.txt && chmod 600 /safe/offline/location/age-key.txt

# 3. Prove the backup works, then clear the pending flag. Required before --apply.
blindpass-openclaw-migrate --ack-backup /safe/offline/location/age-key.txt --store "$STORE"

# 4. Migrate.
blindpass-openclaw-migrate --apply --config-dir "$CFG" --store "$STORE" \
  --resolver-command "$CFG/blindpass/blindpass-resolver" --openclaw-bin "$(command -v openclaw)"
```

`blindpass-openclaw-migrate` is a bin of the `@blindpass/mcp-server` package (the staged bundle) and of the
`@blindpass/openclaw-plugin` workspace. `npx @blindpass/mcp-server` runs the MCP server, not this tool; invoke it as
`npx --package @blindpass/mcp-server blindpass-openclaw-migrate ...` once that package is published, or from this
repository as `node packages/openclaw-plugin/bin/blindpass-openclaw-migrate ...` or the built
`packages/openclaw-plugin/dist/blindpass-openclaw-migrate.mjs`.

`--ack-backup` does not trust your word: it decrypts the real store using **only** the backup key file (no ambient
key variables, no default key file) and clears `bootstrap_backup_pending` only if that works. The backup must be an
absolute, non-symlink regular file owned by you, not readable by group or others, and not the live key file.

`--dry-run` output is a table of `file`, `key path`, the fixed literal `[REDACTED]`, `status` and the proposed
reference. No length, prefix, suffix or hash of any value is ever printed, here or anywhere else; add `--json` for the
same fields in machine form.

## Activation

The migration is not complete until the runtime has used the references.

- A gateway that **watches `openclaw.json`** (the default) notices the rewrite and restarts itself within seconds; it
  then resolves `gateway.auth.token` and the other references through the resolver. Confirm with an authenticated request.
- A value you later change **in the store only** (rotation, a new secret) is *not* live until a reload. Before it, the
  running gateway keeps the previously activated value and rejects the new one. Run `openclaw secrets reload`, or
  `blindpass-openclaw-migrate --reload --config-dir "$CFG" --openclaw-bin ...`.
- `openclaw secrets reload` closes its own connection when the gateway token changes and may report `4001`
  (`gateway auth changed`) although the swap succeeded; `--reload` reports that as **unverified**, exit 0. If you rotated
  `gateway.auth.token` itself, the CLI authenticates with the new value and is rejected: run
  `openclaw secrets reload --token <the token the gateway is currently using>` yourself or restart the gateway.
  `--reload` then exits 1 with that hint.

## Residual plaintext (read this)

After a successful migration the report lists files that still hold the migrated values. The tool never deletes them:

| File | Why it exists |
|---|---|
| `.blindpass-backup/<migration id>/` | The protected backup used for rollback (mode 0700/0600). **Plaintext by design.** |
| `openclaw.json.bak`, `openclaw.json.bak.N` | OpenClaw's own copy of the previous config; `openclaw secrets audit` does not scan it |
| `openclaw.json.last-good` | OpenClaw's last-known-good copy of the config the gateway started on |
| `.env`, `agents/*/agent/models.json` | Untouched originals; `.env` values cannot hold references |
| `state/openclaw.sqlite` | OpenClaw's own database (auth profiles); not opened or changed |

Removing a plaintext original is a separate decision for you; erasing a file does not erase historical copies on
journaled or copy-on-write storage, snapshots or backups. Retention of the protected backup is your policy.

## Interruption, resume, rollback

- The journal `.blindpass-migrate.journal.json` (0600) records `inventory → backup → import → rewrite → commit`, an
  intent before each stage and a completion after. Paths, store names and the whole-file hash of `openclaw.json` only;
  never a value.
- **A killed or failed run** is continued by running `--apply` again with the same settings. A failure after the
  journal exists exits 1 and says which stage; a refusal before any change exits 3. `--status` shows the state.
- **`--rollback`** is valid from any state, including a crashed run and a crashed rollback. If `openclaw.json` still has
  the exact bytes the native write produced and nothing was edited in between, the original is restored byte for byte;
  otherwise each migrated field is restored only where it still holds this migration's reference, so your later edits
  survive. Encrypted store entries and the backup are kept. If you rotated a secret in the store after the migration,
  rollback restores the value from before the migration.
- A changed credential during a run (you rotated it between backup and rewrite) stops the migration with
  `config-changed`; it is never overwritten.
- Older migrations stay available: `--rollback --migration-id <id>`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Done (or nothing to do) |
| 1 | Failed after a change started, or `--reload` failed; run `--status`, then `--apply` or `--rollback` |
| 2 | Usage error |
| 3 | Refused before any change (unsafe path, unsupported release, missing or locked store/key, untrusted resolver, a different provider already uses the alias, ...) |

## Common refusals

| Reason | What to do |
|---|---|
| `key-backup-pending` | Run `--ack-backup <backup file>` |
| `key-unavailable` | The store's key file is missing or wrong; restore the correct key from your backup and rerun. There is no plaintext fallback |
| `resolver-untrusted` | The resolver command is a symlink, writable by others, or not owned by you |
| `provider-alias-conflict` | `secrets.providers.<alias>` already exists with a different definition; pass another `--provider-alias` |
| `store-name-conflict` | A store entry already holds a different value for a name this migration would write |
| `native-version`, `native-config-mismatch` | The `openclaw` executable is not 2026.8.35, or it would operate on a different config file |
| `native-config-invalid` | OpenClaw itself considers the current config invalid; fix that first |
| `journal-mismatch` | An unfinished migration was started with other settings; use the same ones or `--rollback` |
