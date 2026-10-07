# P06 controller image on aarch64 (emulated) — 2026-10-05

**Status:** first aarch64 execution evidence for the controller container. It ran under QEMU user-mode emulation (binfmt) on an x86-64 host, so it shows the arm64 image builds, starts and passes the Compose gates; it is **not** native arm64 hardware, not a performance or timing measurement, and not a support guarantee. P06 acceptance remains false.

## What ran

- Image: `deploy/controller/Dockerfile --target runtime --platform linux/arm64`, built with the reviewed arm64 Node and Rust digests from the CI matrix (`NODE_IMAGE=node:26.10.0-bookworm@sha256:838c3eef…`, `RUST_IMAGE=rust:1.98.1-bookworm@sha256:5b993f23…`). Build took about 32 minutes under emulation. Image ID `sha256:30ec72e11276dda207dc33e2060b72935c530ba179cfbdacfc4a1c2b1637b78d`, 440,132,391 bytes. The controller is ELF machine `0xb7` (AArch64), reports schema 19 and embedded UI, and the pinned PGDG 16.15 packages install at the same versions as x86-64 (`postgresql-16 16.15-1.pgdg12+2`, arch arm64). No snakeoil key or certificate.
- `compose-up.py --profile sqlite` and `--profile postgres` against that image: all PASS lines (O01 image/all-layer scan, O02/O03, O04, O05/O06/O08 nginx and caddy, P06-U upgrade after a verified encrypted backup, O07 PostgreSQL outage on the postgres profile, key-refusal case, cleanup).
- `compose-backup-postgres.py`: PGC01–PGC05 pass, including the isolated-restore verification with the aarch64 toolkit.

## Findings

1. **A plain `--platform linux/arm64` build silently produced an x86-64 binary.** The default `RUST_IMAGE` and `NODE_IMAGE` are single-platform amd64 digests, so the builder stages ran amd64 and only the runtime base resolved to arm64 (ELF machine `0x3e` in an arm64 image, `not found` on exec). This matches the documented posture (`docs/deploy/release-layout.md`: "default image digests are x86_64; pass the reviewed arm64 digests") but nothing refuses the mismatch. **Guard added:** the Dockerfile's `binaries` stage now first checks `TARGETARCH` against `uname -m` and fails in about 0.2 s with a message naming the reviewed-digest requirement (verified: the default digests with `--platform linux/arm64 --target binaries` are refused; the default x86-64 build passes it end to end; for the arm64 digests only the builder's `uname -m` (`aarch64`) was checked against the pattern, not a full rebuild). It was verified by running the mismatched build, not by a committed test, and the attested x86-64 image and SBOM were not rebuilt with the new stage.
2. **The O01 image gate hardcoded the x86-64 libgnutls path** for its single allowed public test key, so any arm64 image failed with "private PEM added to image". Fixed in `tests/deployment/compose-up.py`: the multiarch directory follows the image architecture, and the base-image hash is taken from the platform manifest inside the pinned index (the local image store keeps one platform per index digest, so a second platform cannot be pulled by the index digest). The x86-64 behavior is unchanged; the gate was not re-run on the x86-64 attested image after this edit.

## Not covered

- Native arm64 hardware, native systemd VM matrix on aarch64, release archives/node archive on aarch64 beyond what CI already builds, and the in-image Rust tests (`restore_postgres`, `production_ownership`, PGT) on arm64.
- Timing bounds (readiness, restore, backup) are meaningless under emulation and were not recorded.
- The attested SBOM scan was not run for the arm64 image.
