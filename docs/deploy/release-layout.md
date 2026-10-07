# P06 release layout and controller keys

P06 packaging is in progress. These are build/install candidates, not accepted
native or Compose release profiles. The authoritative [phase plan](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/phases/06-deployment-and-recovery.md)
and [acceptance plan](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/testing/phases/06-deployment-and-recovery.md)
own the remaining gates. SQLite/PostgreSQL conversion is unsupported; use a fresh
controller and explicit reenrollment instead.

## Explicit initialization

Native layout uses `/etc/blindpass/controller.env` (0640 root:blindpass),
`/etc/blindpass/keys` (0700 blindpass:blindpass) and
`/var/lib/blindpass/controller` (0700 blindpass:blindpass). The service account
must own both directories. Container candidates use `/keys` and `/data` with
the same private ownership/modes; mount the keys read-only after initialization.
Never create controller keys implicitly at service/container startup.

```sh
# After creating the dedicated blindpass account and its private directories:
sudo -u blindpass blindpass keys init --directory /etc/blindpass/keys
sudo -u blindpass blindpass keys check --directory /etc/blindpass/keys
```

`keys init` creates `root-secret`, `agent-jwt-secret` and `issuer-key` as three
independent random raw 32-byte files (0600). Run it once, explicitly, as the
account that will consume them. It accepts a new directory or an existing empty
private directory; existing key material causes refusal without replacement.
A failed/interrupted initialization can leave an incomplete key set, which
remains invalid. Recover it explicitly after confirming it has never been used;
there is no automatic repair or rotation. Do not remove an established key set
to make initialization succeed.

The CLI reads randomness into a short-lived 32-byte memory buffer, wipes that
buffer after each write, flushes files and directory entries, and prints only
status. The controller reads key material into its runtime memory until shutdown.
Keys remain plaintext in private credential files; access to those files is
sensitive administration. Runtime memory and protected files do not provide
encrypted recovery backups. P06's authenticated encrypted backup and stale
restore reconciliation are separate unfinished work.

## Configuration

Use the [environment example](../../deploy/native/controller.env.example).
`BLINDPASS_KEYS_DIR` resolves the three fixed key filenames; explicit
`BLINDPASS_ROOT_SECRET_FILE`, `BLINDPASS_AGENT_JWT_SECRET_FILE` and
`BLINDPASS_ISSUER_KEY_FILE` override the respective files (for example, systemd
credential paths). `BLINDPASS_DATA_DIR` supplies the default SQLite URL
`sqlite:///var/lib/blindpass/controller/controller.db?mode=rwc` when no database
URL/file is specified. An explicit database URL file takes precedence.
Inline database URLs remain test-only. With no explicit data root, the legacy
requirement for a database URL/file still applies.

Both layout roots must already exist, be absolute, owned by the invoking account
and mode 0700. Validation creates no directories, keys or databases. Paths are
opened through directory descriptors without following symlink components;
credential files must be private regular files with a single hard link. Secret
reads are bounded to 4 KiB (issuer seed exactly 32 bytes); URL-file reads to
16 KiB. Symlinks, hardlinks and FIFOs are refused. Run `check-config` and explicit
`migrate` before the first `serve`. Production serving refuses missing/uninitialized
or incompatible state and never creates replacement trust. See
[startup, readiness and HTTPS](controller-ingress.md) for diagnostics and both
ingress modes. Full deployment/recovery gates are still unfinished.

## Controller image assets

The release publishes the controller image twice, from one build. `blindpass-controller-image-X.Y.Z-linux-amd64.oci.tar`
is the OCI archive with the BuildKit SBOM and provenance attestations; `controller-image.digest` holds its index
digest, which is the registry identity. A stock Docker (overlay2 image store) cannot `docker load` that archive
(`invalid archive: does not contain a manifest.json`). `blindpass-controller-image-X.Y.Z-linux-amd64.docker.tar` is
derived from it by `scripts/release/oci-to-docker-archive.py`: the linux/amd64 image's config and layer blobs are copied
unchanged after every size and sha256 is checked, a `manifest.json` is added, and the multi-platform index and
attestations are dropped. The output is deterministic and never replaces an existing file. `docker load` reports the
tag `ghcr.io/atas-tech/blindpass-controller:X.Y.Z` and the image ID equals the config digest the script prints
(`image_id sha256:…`). Both archives are listed in the signed `SHA256SUMS`. The registry image exists only after the
approved publish step; before that, the `.docker.tar` is the way to a verified image.

## Building and inspecting candidate archives

The pinned official Node 26.10.0 and Rust 1.98.1 bookworm build images compile
embedded UI before the Rust binaries, with dynamic CRT linking. No broker runs
inside these build containers. The default image digests are x86_64; pass the
reviewed arm64 image digests for native aarch64 builds, as the CI matrix does.

```sh
docker build --file scripts/release/Dockerfile --target export \
  --output type=local,dest=/tmp/blindpass-bookworm-binaries .
scripts/release/build-tarballs.sh --profile controller --arch x86_64 \
  --bin-dir /tmp/blindpass-bookworm-binaries --output-dir /tmp/blindpass-release
scripts/release/checksums.sh /tmp/blindpass-release
(cd /tmp/blindpass-release && sha256sum --check SHA256SUMS)
```

Archive names include workspace version, profile and architecture. The controller
archive contains `bin/blindpass-controller`, `bin/blindpass`, the native files under
`deploy/native/`, the recovery authority SQL, the Compose files (`compose.*.yml`, `.env.example`,
`postgres-init/`) and the reverse proxy examples under `deploy/`, the operator documents under `docs/`
(start with `docs/deploy/README.md`; the build rewrites links to repository-only files to the release tag and
fails on a link that resolves nowhere), the complete AGPL text, licensing matrix and `manifest.json`. The
Dockerfile and entrypoint are build inputs and are not shipped; the image comes from the release assets
below. The node archive carries only `docs/deploy/node-candidate.md`, which states that the package has no
installer and no operator procedure. The manifest binds
member hashes/modes, source revision/dirty state, UI availability, schema/protocol
and each Rust binary's direct ELF library/symbol requirements. Only explicit
build inputs enter the archives. Missing binaries/UI, version/architecture
mismatch, unreviewed runtime libraries and glibc requirements above 2.36 fail
packaging. Archives and checksum inventories are flushed and published without
replacing an existing release. Checksums detect accidental damage; they do not
authenticate an archive or replace signed release provenance/encrypted backups.

The node archive additionally requires the reviewed installed Node runtime root,
pinned Playwright Chromium cache and built MCP bundle with its notices:

```sh
# NODE_RUNTIME_ROOT is the reviewed Node 24.21.0 or 26.10.0 installation.
# PLAYWRIGHT_CACHE contains chromium_headless_shell-1208.
scripts/release/build-tarballs.sh --profile node --arch x86_64 \
  --bin-dir /tmp/blindpass-bookworm-binaries --output-dir /tmp/blindpass-node-release \
  --node-root "$NODE_RUNTIME_ROOT" --browser-root "$PLAYWRIGHT_CACHE"
scripts/release/checksums.sh /tmp/blindpass-node-release
```

It preserves helper source/runtime assets, complete Node/Playwright/browser/MCP
licenses and native units. Chromium's host prerequisites are broader than the
controller's runtime library set. A build that links on bookworm does not
establish broker support there: the P01 accepted scope remains its exact tested
Ubuntu 24.04/systemd 255, no-TPM profile. Neither candidate architecture is
advertised as a supported release until its artifact and real-host gates pass.

The two known npm `.bin` launcher symlinks nested under `@playwright/mcp` are
omitted after checking their exact upstream targets. The runtime imports the
package directly; other symlinks are refused. Helper sources come from the
tracked `.mjs` inventory. Included P01 consumer/backup/workload probe binaries
and units are disabled examples; they do not implement a production backup.

The actual node archive gate additionally checks every member and unit executable,
full notices, helper/stock MCP module resolution and a real sandboxed launch of
the packaged headless shell. Run it with the reviewed runtime/cache roots:

```sh
python3 tests/deployment/release-node-archive.py --arch x86_64 \
  --bin-dir /tmp/blindpass-bookworm-binaries \
  --node-root "$NODE_RUNTIME_ROOT" --browser-root "$PLAYWRIGHT_CACHE"
```
