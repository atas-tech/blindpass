# P06 deployment verification

The [vault acceptance plan](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/testing/phases/06-deployment-and-recovery.md)
owns the scenario IDs and complete matrix. Component/artifact checks below do
not establish any supported native/Compose profile, real broker runtime or
recovery/migration behavior. See [release layout](../../docs/deploy/release-layout.md).

From the repository root:

```sh
cargo test -p blindpass-cli --test keys --locked
cargo test -p blindpass-controller --test deployment_layout --test shell_config --locked
python3 tests/deployment/release-artifacts-test.py
# After the pinned bookworm build from the release-layout guide:
python3 tests/deployment/release-archive.py --arch x86_64 \
  --bin-dir /tmp/blindpass-bookworm-binaries
```

The key tests cover P06-K01–K08 with disposable synthetic key material, exact
permissions, no silent trust replacement, symlink/hardlink denial, bounded
FIFO refusal and safe output. Layout/version cases cover P06-L01–L07; existing
shell tests preserve the legacy configuration/readiness envelope. Loopback
and Unix sockets require permitted host execution.

The eight archive unit cases cover real ELF inspection, wrong architecture,
incompatible glibc requirements, unsafe/missing inputs, manifest hashes,
no-replace archive publication and failed compression. The actual archive gate
packages only explicit build inputs, adds a dummy exclusion canary, verifies
every extracted member's hash/mode/size, rejects duplicate publication and
starts the extracted controller/CLI with disposable private key/data roots.
It checks both embedded HTML surfaces, CSP and readiness and bounds shutdown.
This uses production config rules over loopback; it is not a systemd installer,
TLS proxy, Compose or two-host browser/native-backup E2E. The separate
`release-node-archive.py` gate (arguments in the release-layout guide) validates
the complete node archive, references from every shipped native unit to included
executables, full notices, helper/MCP resolution and a real packaged sandboxed
headless Chromium launch. It does not approve a browser task or consume a Source.

Still required: installer/uninstaller VM tests; both Compose profiles and image
inspection; consistent authenticated encrypted backups on both stores; stale
restore against live/offline brokers; external ownership and interrupted source
fencing; protected upgrades/restore-only rollback; migration in both directions
with fault injection; the three-profile and remote-controller common-workflow
matrix; measured numerical bounds and inherited phase acceptance. P06-E05
SQLite/PostgreSQL conversion is explicitly unsupported and never counted passed.
