# P06 deployment verification

The [vault acceptance plan](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/testing/phases/06-deployment-and-recovery.md)
owns the scenario IDs and complete matrix. Component/artifact checks below do
not establish any supported native/Compose profile, real broker runtime or
recovery/migration behavior. See [release layout](../../docs/deploy/release-layout.md).

From the repository root:

```sh
cargo test -p blindpass-cli --test keys --locked
cargo test -p blindpass-controller --test deployment_layout --test shell_config --locked
cargo test -p blindpass-controller --test deployment_startup --test deployment_proxy --locked
python3 tests/deployment/controller-tls.py
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

Startup/readiness cases preserve P06-S01–S06, including production process
refusal of absent/empty/older/damaged state, stable identity across restart and
adapter-specific missing metadata and clock-fence checks. Proxy cases preserve
P06-X01–X06 with actual TCP peers, reviewed IPv4/IPv6 CIDRs, forwarded-header
refusal, HSTS and rate-limit identity. The TLS script preserves P06-T01–T04;
build the current controller with embedded UI first. It needs OpenSSL for a
generated disposable certificate, validates it with Python's SSL trust store,
checks distinct input/console HTML, rate limiting and plaintext rejection,
saturates 64 handshakes and measures recovery and graceful shutdown. It consumes
no protected Source and is not a VM or full deployment-profile result.

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

Still required: complete native/Compose workflow parity; consistent
authenticated encrypted backups on both stores; stale
restore against live/offline brokers; external ownership and interrupted source
fencing; protected upgrades/restore-only rollback; migration in both directions
with fault injection; the three-profile and remote-controller common-workflow
matrix; measured numerical bounds and inherited phase acceptance. P06-E05
SQLite/PostgreSQL conversion is explicitly unsupported and never counted passed.

## OCI and HTTPS edge candidates

```sh
cargo test -p blindpass-controller --test deployment_health --locked
python3 tests/deployment/container-config-test.py
docker build -f deploy/controller/Dockerfile -t blindpass-p06-controller:local .
docker build -f tests/deployment/edge.Dockerfile -t blindpass-p06-edge:local tests/deployment
tests/deployment/compose-up.sh --profile sqlite
tests/deployment/compose-up.sh --profile postgres
python3 tests/deployment/controller-sbom.py --archive /path/to/named-attested-image.tar
```

The first two gates cover H01/H02 and Compose/Unraid O09 configuration. The
actual TLS script also covers H03's verified CA/name and refusal cases. The
profile driver uses uniquely named disposable projects, private dummy keys,
password/URL files and certificates, actual volume initialization, real
process/mount checks, both shipped nginx/Caddy examples, untrusted network
peer and forged-header denials, controller recreation, PostgreSQL outage and
bounded Docker readiness. It captures bootstrap credentials only in memory;
logs assert they never appear. It removes only its own containers, networks,
volumes and private fixture files. Docker host access is required. It never
installs a controller on the host or runs a broker container.

O01 scans every exported image layer for the generated exposure canary and
encoded private PEMs. The sole exception is a public self-test key inside the
identical GnuTLS binary from the pinned official Debian base. It is digest-bound
rather than a blanket skip for libraries or lower layers. The image also
preserves available upstream npm/Cargo notices with path/hash inventories.

O10 needs an attestation-capable Buildx driver and a named OCI export; the
classic Docker driver cannot export attestations. Use the exact user-approved
scanner and additive cataloger expression in the
[controller image workflow](../../.github/workflows/build-and-push-images.yml).
The verifier checks all OCI descriptor hashes, image/subject binding, the three
SPDX documents, required OS packages, every Cargo registry lock entry and every
non-optional npm lock entry. `--config-digest` additionally binds the artifact
to the tested local image ID. Build-stage inventories include source/fixture
and declared dependencies; they do not imply all packages execute at runtime.
Local OCI attachment is separate from unexecuted GHCR publication/aarch64 CI.

The [Compose guide](../../docs/deploy/compose-quickstart.md) documents credential
consumers/lifetimes, explicit initialization, ingress and retained-state removal.
Real Unraid GUI/pool/lifecycle checks, complete browser/native backup workflows,
recovery/fencing/upgrade/migration and the full three-profile/remote matrix remain
required. Selected Compose lifecycle checks do not establish P06 acceptance.
