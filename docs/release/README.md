# Release process and verification

**Status: not yet exercised.** No BlindPass release has been published. The tooling below is built
and unit-tested; the hosted workflow has never run, the maintainer release key does not exist yet,
and the P07.6 go/no-go has not been taken. Plan and acceptance:
[P07](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/phases/07-security-and-release.md),
[P07 tests](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/testing/phases/07-security-and-release.md).

## What a release contains

One immutable candidate, built from the exact tagged commit by
[`.github/workflows/release.yml`](../../.github/workflows/release.yml), is staged, signed and
verified, then published on approval. The same bytes are published; nothing is rebuilt.

| Asset | Source |
|---|---|
| `blindpass-controller-X.Y.Z-linux-{x86_64,aarch64}.tar.zst`, `blindpass-node-X.Y.Z-linux-{x86_64,aarch64}.tar.zst` | `scripts/release/build-tarballs.sh` ([layout](../deploy/release-layout.md)) (P06 archives; the aarch64 pair is optional and only together). The controller archive also carries the Compose files, `.env.example`, the proxy examples and the operator documents, with their links checked at build time |
| `blindpass-approval-app-X.Y.Z-linux-x86_64.tar.zst` | `scripts/release/build-desktop-archive.py` (tracked QML/JS/shell only; no compiled code) |
| `PKGBUILD` | `desktop/packaging/arch/PKGBUILD` rendered with this release's version and archive hash |
| `blindpass-mcp-server-X.Y.Z.tgz`, `blindpass-mcp-server-X.Y.Z.cdx.json` | `npm pack` of the staged esbuild bundle (`scripts/publish_dist.sh` over `packages/openclaw-plugin/dist`; bins `mcp-server`, `blindpass-mcp-server`, `blindpass-resolver`; no runtime dependencies); CycloneDX SBOM of the bundled components from the bundle's licence inventory (`scripts/release/bundle-sbom.mjs`) |
| `blindpass-controller-image-X.Y.Z-linux-amd64.oci.tar`, `controller-image.digest`, `blindpass-controller-image-X.Y.Z.spdx.json` | The controller image as an OCI archive with BuildKit SBOM and provenance attestations; its index digest; the three SPDX inventories read from it |
| `blindpass-controller-image-X.Y.Z-linux-amd64.docker.tar` | The same linux/amd64 image content (identical config and layer bytes) in the format `docker load` accepts on a stock Docker; derived from the OCI archive by `scripts/release/oci-to-docker-archive.py` ([Compose quickstart](../deploy/compose-quickstart.md#image-and-private-state)) |
| `LICENSES-X.Y.Z.md` | Snapshot of [`LICENSES.md`](../../LICENSES.md) |
| `SHA256SUMS`, `SHA256SUMS.sig` | Inventory of every asset above, and its SSH signature |

Names and tags: GitHub release/tag `vX.Y.Z`; npm `@blindpass/mcp-server@X.Y.Z`; controller image
`ghcr.io/atas-tech/blindpass-controller:X.Y.Z` and `:X.Y` (no `v` prefix, matching the Compose
default image tag in `deploy/controller/`). The aarch64 archives and the image are not claimed as
supported: see [known limitations](known-limitations.md).

## Verify a download

Trust rests on two independent facts: the signature verifies under the release public key
(`RELEASE_KEY.pub`), **and** that key's fingerprint equals one you obtained from a channel other than the
place you downloaded the key from (the release notes, the maintainers directly, a second copy of the key). A
checksum match alone authenticates nothing: it detects damage, the signature authenticates the publisher.

**Where the key is.** `RELEASE_KEY.pub` is not one of the release assets and is not listed in `SHA256SUMS`
(a key cannot vouch for itself). Download it from the repository at the release tag:
`https://raw.githubusercontent.com/atas-tech/blindpass/vX.Y.Z/docs/release/RELEASE_KEY.pub`
(the same file as `docs/release/RELEASE_KEY.pub` in a checkout). The fingerprint you compare it with must
come from somewhere else, because anyone who can change the repository can change the key file. The key does
not exist yet (see [owner actions](#owner-actions-before-the-first-release)).

### With only the downloaded files (no repository checkout)

Put `SHA256SUMS`, `SHA256SUMS.sig` and the assets you downloaded in one directory, keep `RELEASE_KEY.pub`
outside it, and run from that directory (`ssh-keygen` from OpenSSH 8.0 or newer, and `sha256sum`):

```sh
KEY=/path/to/RELEASE_KEY.pub
FINGERPRINT='SHA256:...'        # the value you were given elsewhere, not read from the downloads
[ "$(ssh-keygen -lf "$KEY" | cut -d' ' -f2)" = "$FINGERPRINT" ] || { echo 'KEY FINGERPRINT MISMATCH'; exit 1; }
ALLOWED=$(mktemp)
printf 'blindpass-release namespaces="blindpass-release-v1" %s\n' "$(cut -d' ' -f1,2 "$KEY")" > "$ALLOWED"
ssh-keygen -Y verify -f "$ALLOWED" -I blindpass-release -n blindpass-release-v1 -s SHA256SUMS.sig < SHA256SUMS
sha256sum --check --strict SHA256SUMS
UNLISTED=$(comm -13 <(awk '{print $2}' SHA256SUMS | sort) <(ls -A | grep -vxF -e SHA256SUMS -e SHA256SUMS.sig | sort))
[ -z "$UNLISTED" ] || { echo "NOT IN THE SIGNED INVENTORY: $UNLISTED"; exit 1; }
echo 'download verified'
```

Save it as a file and run it with `bash -eu` (it uses `exit`). It stops on a fingerprint mismatch, prints
`Good "blindpass-release-v1" signature` for a valid signature, reports every listed file as `OK` and ends with
`download verified`. Treat anything else as a failed verification and discard the download. If the maintainers have announced a revoked key and you hold their `REVOKED_KEYS` list, add
`-r REVOKED_KEYS` to the `ssh-keygen -Y verify` line: plain `ssh-keygen` does not consult any revocation list
by itself, so without that option a signature by a revoked key still verifies here. The fingerprint you were
given is the real guard: a key you were told is revoked is a key whose fingerprint you do not accept.

### With a repository checkout

`scripts/release/verify.sh` does the same and also applies `docs/release/REVOKED_KEYS` (the file beside the key,
or one named with `--revoked`; a key downloaded alone has none beside it) and fails on any file the signed
inventory does not list:

```sh
# 1. The fingerprint you were given must match the key file you hold.
ssh-keygen -lf docs/release/RELEASE_KEY.pub

# 2. Verify the signature, the inventory format and every asset in the download directory.
scripts/release/verify.sh --fingerprint 'SHA256:...' --check-dir ./assets \
  ./assets/SHA256SUMS ./assets/SHA256SUMS.sig docs/release/RELEASE_KEY.pub
```

`verify.sh` has no mode that trusts the key file alone. The identity (`blindpass-release`) and namespace
(`blindpass-release-v1`) are fixed by the verifier; a signature made under another namespace, by another key,
or over a changed inventory fails.

### After verifying

The operator documents (the quickstarts, ingress, upgrade and recovery runbooks) are inside the signed
controller archive, so the copies you unpack are covered by the signature; a copy read on the web is not.
`makepkg` cannot verify an SSH signature; compare the archive line in `SHA256SUMS` with the `sha256sums` entry
of the published `PKGBUILD` after verifying as above.

## Owner actions before the first release

None of these can be done by the tooling or by an agent; the workflow fails closed in its first job
until they exist.

1. **Release key ceremony.** On an offline machine, generate a dedicated Ed25519 key:
   `ssh-keygen -t ed25519 -C blindpass-release -f release_key`. The key used by CI must have no
   passphrase (`sign.sh` cannot answer a prompt); keep a passphrase-protected offline copy as the
   root of trust. Commit only the public half as `docs/release/RELEASE_KEY.pub` (exactly one
   `ssh-ed25519` line, no options). Record its fingerprint (`ssh-keygen -lf`) in at least two places
   that are not this repository, for example the maintainer's account profile and the release notes.
2. **Repository variable** `RELEASE_KEY_FINGERPRINT` = that fingerprint (the workflow passes it to
   `verify.sh`; it is deliberately not read from the tree).
3. **Environment `release-signing`**: secret `RELEASE_SIGNING_KEY` (the private key, restricted to
   version tags). Only the `assemble-and-sign` job references it.
4. **Environment `release-approval`**: required reviewers (the named P07.6 reviewer) and secret
   `NPM_TOKEN`. Every publishing job references this environment, so each pauses for approval.
5. **Registries.** Confirm the npm scope `@blindpass` belongs to the maintainer account before the
   first publish (`npm view @blindpass/mcp-server` and `@blindpass/sdk` returned 404 on 2026-10-06, which
   shows the packages are unpublished, not who owns the scope); `ghcr.io/atas-tech/blindpass-controller`
   must accept pushes from this repository.
6. **Rotation and revocation.** To retire a key normally, keep its public half in the repository
   history so earlier releases stay verifiable, replace `RELEASE_KEY.pub`, and publish the new
   fingerprint in the same places. To revoke after a compromise, add the old public key to
   `docs/release/REVOKED_KEYS` (one key per line): `verify.sh` then rejects everything signed with it,
   including earlier releases, so re-sign and re-issue anything still supported. A revocation list
   in the repository helps only while the verifier trusts the repository; the independently supplied
   fingerprint is what stops a swapped key file.

## Cutting a release

1. Bump the workspace version (`Cargo.toml`), the `version` in `packages/openclaw-plugin/skills/blindpass/SKILL.md`,
   `packages/openclaw-plugin/openclaw.plugin.json` and `packages/openclaw-plugin/package.json` together (the staged
   npm package takes its version from `SKILL.md`); the workflow refuses a tag or a manifest that differs from any.
   The workspace library `packages/mcp-server` (`@blindpass/mcp-server-lib`) is private and never published.
2. Run the release scenarios on the candidate commit and record each as a result file under
   `docs/release/vX.Y.Z/results/` (schema `blindpass-release-evidence-v1`; scenario catalog
   [`required-scenarios.json`](required-scenarios.json)). A skipped or unsupported scenario needs a
   reason; a pass needs an evidence link.
3. Generate `docs/release/vX.Y.Z/evidence.md` with
   `scripts/release/collect-evidence.sh X.Y.Z --commit <tested commit> --output docs/release/vX.Y.Z/evidence.md`.
   It writes **Release gate: BLOCKED** unless every required row passes, and never writes a go decision.
   Commit the results and `evidence.md` (this evidence-only commit is the only change allowed after the tested commit).
4. Record the dated go/no-go in the P07 review record, then push the tag `vX.Y.Z`.
5. The workflow stages the candidate and a **draft** release. Each publishing job re-runs
   `scripts/release/check-publish-gate.sh` (evidence regenerates identically, matrix eligible, tested commit
   an ancestor, only `docs/release/vX.Y.Z/` changed since), re-verifies the signature and checksums, and waits
   for the `release-approval` reviewer. Approving is the go decision.
6. Publication order: image, npm package, then the draft becomes the public release.
   Nothing is published to npm or GHCR from a developer machine: `scripts/publish_dist.sh --publish-npm` and
   the staged package's `prepublishOnly` guard both run `scripts/release/check-publish-context.mjs` and refuse
   outside the approved workflow, `publishConfig.provenance` makes npm refuse to publish outside a supported CI
   identity, and the legacy image workflow `build-and-push-images.yml` has no controller input (controller images
   go through `release.yml` only). `publish_dist.sh --push` (dist-repository git push) and `--publish-clawhub`
   are not covered by that guard and remain developer-run.

## What is not automated

Clean-host installs of the native and Compose quickstarts (P07-E01), the rollback rehearsal (P07-E03), the
canary scan of archives and image layers (P07-I04), live endpoint probes (P07-E02) and the landing checks
(P07-I06, P07-E04) are separate gates whose results feed step 2; this workflow only checks signature,
checksum, tamper rejection, and an offline install of the staged npm bundle with its executables run over stdio
and through `npx`.
