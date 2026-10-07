# P07 slice 7 evidence: operator documentation and operator-path packaging

**Date:** 2026-10-06 **Workstream:** H2 **Scope:** P07.5 operator docs, P07.4 packaging of the operator path, P07-E01 preparation.
**Source of the work list:** the cold-operator dry run (`~/.cache/p07-dryrun/cold-operator-notes.md`, kept outside the repository; summarised in [p07-dryrun-env-2026-10-06](p07-dryrun-env-2026-10-06.md)).

**Status: documentation and packaging work done in the working tree; open items listed at the end.** This file is written literally and updated after every step. "Ran" means the command ran in this working tree and the result is quoted; "Not run" means no result exists. Nothing here is a release decision.

Limits of the dry run this record answers: the operator was a model agent, not a human; the signing key was a throwaway; no endpoints or DNS exist; the node and broker host profile (Ubuntu 24.04 / systemd 255) was not available.

## Work list (from the dry run)

| # | Finding | Task | State |
|---|---|---|---|
| 1 | Compose files, `.env.example`, `postgres-init/`, proxy examples and the Compose quickstart are in no release asset | Ship them in the controller archive | **done**, tested, real archive built |
| 2 | `docker load` of the `.oci.tar` fails on the default overlay2 store; no document says how to get the image | Verified image acquisition procedure | **done**: `.docker.tar` asset, converter, tests, real `docker load` |
| 3 | 14 distinct relative links in the shipped `native-quickstart.md` resolve to nothing | Ship the link closure, add an archive link test | **done**, build-time gate and tests |
| 4 | Quickstarts open with status paragraphs, no prerequisites, no single-host path, PostgreSQL 16 on Debian 12 unexplained | Start-here rewrite, status section at the end | **done**; native evaluation partly assembled from dry-run results (see Task 4) |
| 5 | Uninstall/reinstall snippet, release verification order, `REVOKED_KEYS` on the fallback, MCP default endpoint | Small fixes and known limitations | **done** (documented; no script change needed, see Task 5) |
| 6 | Compose-from-release never ran | End-to-end run with docker | **done** (curl checks; no browser sign-in) |

## Results

### Task 2: image acquisition (ran)

- On this host (Docker 29.7.2, overlay2 image store, no containerd image store) `docker load` of the release
  `.oci.tar` fails: `invalid archive: does not contain a manifest.json` (reproduced directly here; G3 and the dry run found it first). `skopeo`, `podman`, `crane`, `regctl` and `nerdctl` are absent; only `ctr` exists, and it imports into
  containerd, not into this Docker store, so no tool-free command works for an operator.
- Honest fix chosen: a companion asset `blindpass-controller-image-X.Y.Z-linux-amd64.docker.tar` derived from
  the already verified OCI archive by `scripts/release/oci-to-docker-archive.py` (stdlib; verifies every
  descriptor, copies the config and layer blobs byte for byte, adds the `manifest.json` Docker reads, drops the
  multi-platform index and attestations, deterministic, no-replace output). The OCI archive stays the
  registry-push source; `controller-image.digest` stays its index digest. The signed `SHA256SUMS` covers the new
  asset.
- Tests written first, red (2 of 4 failing, the third passing vacuously because the script did not exist), green
  after: `scripts/tests/release-image-docker-archive.test.mjs` (4 tests: structure and byte identity, determinism
  and no-replace, refusal of tampered blob / zero or two linux images / unsafe tags, opt-in real `docker load`).
  `release-sums.test.mjs` and `release-workflow.test.mjs` gained the asset and a conversion-step test, red first,
  green after (workflow test red once more for a too-rigid regex of mine).
- Real run: converter on the real candidate `blindpass-controller-image-0.1.0-linux-amd64.oci.tar`
  (sha256 of the output `40abb5a0…`), `docker load` reported `Loaded image: ghcr.io/atas-tech/blindpass-controller:0.1.0`
  and the image ID equals the config digest (`sha256:b6952cd8…`). The opt-in test
  (`BLINDPASS_TEST_DOCKER_LOAD=1 BLINDPASS_TEST_OCI_ARCHIVE=…`) passed 4 of 4 and removed its test image.
- `make-sums.sh` now requires the new asset; `release.yml` gained a "Derive the docker-load archive" step in the
  image job. **Not run:** the workflow itself (never run on a hosted runner).

### Task 1 and 3: operator files and self-contained documents (ran)

- `release-artifacts.py` now stages, inside the existing controller archive (P06-D1 shape kept, no new asset):
  the eleven Compose files and `.env.example`, `postgres-init/`, the proxy examples, every operator document
  (`docs/deploy/*.md`, `docs/security/operator-auth-and-headers.md`, `docs/release/{README,known-limitations,rollback}.md`),
  a root `README.md` pointer, and for the node archive `docs/deploy/node-candidate.md` and a root `README.md`.
  `Dockerfile` and `entrypoint.sh` are build inputs and are not shipped.
- Links: relative links that resolve inside the archive stay relative; links to repository-only files (evidence,
  decision records, tests) are rewritten at build time to `https://github.com/atas-tech/blindpass/{blob,tree}/vX.Y.Z/…`
  (valid after the tag exists); a link that resolves nowhere, or leaves the repository, fails the build; links in
  fenced code are neither rewritten nor checked. `LICENSES.md` is processed the same way. Source documents keep
  relative links (AGENTS.md rule).
- Tests (`tests/deployment/release-artifacts-test.py`, in `ci.yml`): three new tests, red first (3 errors,
  attributes absent), green after (11 tests): link rewrite semantics incl. dead and escaping links, controller
  operator files complete and every relative link resolves inside the staged archive, the unresolved-link checker.
  `tests/deployment/release-archive.py` (needs release binaries, **not run here**) now applies the same link rule
  to every Markdown file of the extracted archive and asserts the Compose files exist.
- Real build: `scripts/release/build-tarballs.sh --profile controller --arch x86_64 --allow-dirty` with the released
  bookworm binaries (taken from the dry-run archive, so binary bytes are unchanged) published an archive with 58 files,
  30 MB unpacked; the unresolved-link gate passed on the real documents.
- Before the change the dry run found 14 distinct dead relative links in the archive's `native-quickstart.md`.

### Task 6: Compose from release assets (ran)

Method: the fenced `sh` blocks of the README section "Docker Compose evaluation on one host" were extracted
mechanically and run with `bash -euo pipefail` from an empty directory against the rebuilt controller archive and the
converted `.docker.tar` (the locally preloaded image tag was removed first, so `docker load` really loaded it).

- First runs found two defects in my own draft of the steps, both fixed in the document and re-run from scratch:
  Docker's allocator gave the authority container `172.29.6.2`, the controller's static address ("Address already in use");
  and removing the evaluation directory failed because `eval/authority` is owned by UID 10001 (teardown now uses a root container).
- Passing run (blocks 1–8): archive unpack, `docker load`, keys-init, issuer ID, TLS authority container,
  authority schema and runtime role, register, `migrate`, activate, `up -d controller`, nginx edge container on the
  trusted address, `/readyz` through the TLS edge `{"ok":true,"checks":{"database":"up","authority":"up"}}`,
  `blindpass admin bootstrap` (temporary password, `must_change_password`). Total wall time about 5 s once images were present.
- After it: `/`, `/login`, `/setup` and the input origin answer 200 `text/html`; a foreign Host answers 421; a plain
  `docker restart` ends with `Exited (1)` and `{"event":"startup_failed","reason":"fenced"}` and the edge answers 504.
- The documented teardown block was run from a fresh shell with only the exports; all `blindpass-eval*` containers,
  networks, volumes and the `eval/` directory were gone afterwards.
- **Not run:** a browser sign-in with the temporary password (curl only), the PostgreSQL profile, the backup and restore overlays
  from this archive, aarch64, a pulled-from-GHCR image (none exists), anything on the Debian guest.

### Task 4: start-here rewrite (ran in part)

- New `docs/deploy/README.md` ("Start here"): what the release is, prerequisites, verify the download, choose a
  path, a worked single-host evaluation for each path, "After the console is up", "Status and limits". It states
  PostgreSQL 16 on Debian 12 (PGDG apt), the authority URL format, the tools, one certificate per name, the
  reverse proxy and the non-443 `Host`/`X-Forwarded-Host` caveat with a tested `sed` edit, and plain
  support-status statements (no host support is claimed beyond the tested profiles).
- `native-quickstart.md` and `compose-quickstart.md` now open with a short intro and requirements that point at
  the README; the former opening status paragraphs moved verbatim (links fixed for position) to a "Status and
  limits" section at the end. Added: the authority database is created first and the SQL is applied as a
  superuser with `-f - < file`; the URL format with `sslmode=verify-full&sslrootcert=`; `deploy/controller/…`
  paths; `sudo -u blindpass blindpass keys issuer-id`; image acquisition in the Compose quickstart (the
  `docker build` from the repository root is kept only as the contributor path); `-T` on the
  `issuer-id` command so the value can be captured; the first-administrator flow difference
  (native: one-use setup token and `/setup`; Compose: temporary password for `admin`); the backup `verify`
  requirements (absolute paths, private work directory and input directories, checked against `backup.rs`);
  `reset-password <username-or-id>` and `admin operators list` (H1's change, SQLite tested by H1).
- Native evaluation steps: the PGDG apt commands and the installer sequence were run by the dry run on a clean
  Debian 12 guest; the SQL-over-stdin form, the `sed` edit, the certificate command and `nginx -t` were checked
  separately. **Not run as one pass:** the whole native evaluation block from an empty guest (the Debian guest was not
  available to this workstream). The README says so.
- `docs/deploy/node-candidate.md` states plainly that the node package has no operator procedure and no accepted
  host beyond the P01 profile.

### Task 5: small fixes (ran)

- Uninstall/reinstall snippet in the native quickstart now runs `authority-activate.sql` before `--start` and
  re-enables `blindpass-controller-backup.timer`.
- `docs/release/README.md`: verification leads with the commands that need only the downloads (a script-ready
  block: fingerprint comparison, `ssh-keygen -Y verify`, `sha256sum --check --strict`, an unlisted-file check);
  the repository-checkout `verify.sh` follows; `RELEASE_KEY.pub` is stated to be a repository file at the release
  tag (raw URL given), not a release asset and not in `SHA256SUMS`; the asset table gained the `.docker.tar` and the
  controller archive's new contents. The fallback block was run against a synthetic signed release: good download
  passes (`download verified`), a wrong fingerprint stops, a tampered asset fails, an extra unlisted file fails.
- `REVOKED_KEYS` gap: `verify.sh` already applies a `REVOKED_KEYS` beside the key (tested in
  `release-signing.test.mjs`), so no script change. Plain `ssh-keygen -Y verify` does not: checked directly
  (`rc=0` without `-r`, `rc=255` with `-r REVOKED_KEYS` for a revoked key). The README now states that and gives `-r`.
- `docs/release/known-limitations.md`: new "Open items for the owner" section records the MCP default endpoint
  (finding F-3, `https://sps.blindpass.dev`) as **OPEN**, with the file and line citations, and says the default
  was not changed.
- `docs/deploy/release-layout.md`: describes the Compose files and operator documents in the controller archive,
  the node archive's single document and the two image assets.

## Checks run in this working tree

- `python3 tests/deployment/release-artifacts-test.py`: 11 tests OK.
- `node --test scripts/tests/release-sums.test.mjs scripts/tests/release-workflow.test.mjs scripts/tests/release-image-docker-archive.test.mjs`: 24 pass, 1 skipped (opt-in real docker load; it passed when enabled, see Task 2).
- Relative-link and anchor check (own script, fenced code ignored) over `docs/deploy/*.md` and `docs/release/*.md`:
  no missing file; one reported anchor in `handoff.md` is a false positive of my checker on a heading that contains a link.
- `bash -n` over every fenced `sh`/`bash` block of the README, both quickstarts, the release README and release layout: 0 syntax errors.
- `git diff --check -- docs scripts tests`.

## Not run, and open

- The hosted `release.yml` run (never executed), including the new conversion step.
- `tests/deployment/release-archive.py` (needs release binaries; compiles).
- The native evaluation end to end from an empty guest, a remote native authority with a private CA (where the CA
  file is placed and who can read it is unverified), the PostgreSQL Compose profile and the Compose backup and restore
  overlays from this archive, aarch64, a pulled-from-GHCR image (none exists), a browser sign-in in either path.
- `docs/security/operator-auth-and-headers.md` still names `<operator-id>` for `reset-password`; it belongs to workstream B.
- `backup verify` messages and `install.sh --start` exit status are H1 items still in progress; the documents state the
  requirements and the readiness check and do not depend on H1's wording.
- Owner decisions: whether `RELEASE_KEY.pub` should also be a signed release asset; release endpoints for the MCP default (F-3).
