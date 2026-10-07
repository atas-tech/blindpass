# P06 backup image SBOM and container faults — 2026-10-03

**Status:** Selected O10/SB01–SB04 and CB05/B06 checks pass. Actual backup and
both baseline HTTPS profiles pass on the exact attested image. Slice 5 remains
an uncommitted candidate above `8a595ad`; PostgreSQL backup and full P06 remain open.

## Exact artifact and execution

The current Dockerfile uses the reviewed Node26/Rust/bookworm pins and the
explicitly approved scanner digest from [decision 0009](../../product/decisions/0009-p06-sbom-scanner-dependency-review.md).
Its additive catalogers scan runtime, UI and Rust build stages. A separately
named disposable builder reuses the cached BuildKit digest
`sha256:cec9f139f45e93c5c69c60f8b07cfad9f43f4ef6b6a6cd917527fea5ff2e3dea`.
The default builder is unchanged. No proposed PostgreSQL toolkit or npm/Cargo
manifest/lockfile change was applied. A generated dummy `.env` exclusion canary
is removed after the builds; exported runtime layers contain none of its bytes.

| Binding | SHA-256 |
|---|---|
| Tested Docker config ID | `3e84437a30e9e0f9419c2a77d40e8b18987597808000c7893c8ef718f45307a3` |
| OCI runtime manifest | `6f04b1b20ee325f9459a9c48756b45742e90284fc3a3c48792f43a2dd2560686` |
| OCI index | `9dbe6b7e5d6adf3ffb6a6e2f2c377284a248e41decfcbb0fd8355a564915e7c3` |
| Named local OCI archive | `72448158e063569881d52740d686715f0e511c4f1b225f504ff6a9a866d30c41` |

The version/schema are 0.1.0/16. Direct OCI loading fails because this Docker
daemon requires `manifest.json`. The same builder's cached Docker exporter
loads `blindpass-p06-controller:backup-sqlite-sbom` with the exact config ID above.
The original OCI archive retains its actual SBOM/provenance attestations; no
manual inventory or conversion substitutes for them. Local attachment/loading
does not establish GHCR publication or aarch64 execution.

Actual create/verify, wrong/missing/exposed recovery refusal, separate ordinary
controller custody, retained identity and distinct repeated backup all pass.
Serving and backup container IDs are checked against the same image config.
The 100,000,000-byte fixture takes 7.950 s initially and 4.741 s after recreation,
with 386/232 continuous embedded-console requests and zero failures. Both stay
below I02's 30-second bound, including concurrent baseline profile gates.
SQLite and PostgreSQL nginx/Caddy HTTPS/header/peer/privacy/lifecycle gates pass
on this image. Ordinary PostgreSQL outage preserves liveness, denies readiness
and recovers with unchanged identity; this is not PostgreSQL backup evidence.

## Verifier corrections

First-red synthetic cases demonstrate that a union of build/runtime package
names accepts missing or duplicate runtime/build inventory names. The verifier
now requires exactly `sbom`, `sbom-ui` and `sbom-binaries` for this configured,
pinned scanner. Every locked Cargo registry entry must appear in the Rust
inventory; every non-optional locked npm entry must appear in the UI inventory.
Correct labels with swapped contents also refuse.

Runtime Debian package/version pairs must exactly equal the list queried from
the tested image, rather than borrowing matching pairs from another stage.
All 91 actual installed pairs match the runtime SPDX document, with no missing
or extra pairs. The three SPDX documents contain 1671 unique package names;
build inventories include declared/source/fixture packages and do not imply
that every package executes at runtime.

A further first-red case keeps valid descriptor hashes while supplying a wrong
uncompressed layer hash in the image config. The verifier now checks each
runtime layer against its ordered `rootfs.diff_ids`, in addition to every OCI
descriptor digest/size, image/subject binding and actual tested config ID.
The [OCI config specification](https://github.com/opencontainers/image-spec/blob/v1.1.1/config.md#layer-diffid)
defines DiffIDs over uncompressed layer archives; the
[manifest specification](https://github.com/opencontainers/image-spec/blob/v1.1.1/manifest.md#image-manifest-property-descriptions)
defines ordered layer descriptors. This candidate's gzip/plain layer encodings
are supported by this verifier; other encodings refuse. Eight parser cases pass. They are
synthetic regression evidence, separate from the actual scanner/image runs.

## Actual container ENOSPC

CB05 runs capture/encryption/decryption failures inside the shipped non-root,
read-only/no-capabilities/no-network backup service. Private per-container
tmpfs quotas are 50,000,000 / 250,000,000 / 150,000,000 bytes for the 100-MB
fixture. A monitor observes actual named output growth before accepting the
phase-specific fixed failure. The wrapper inspects empty staging **before**
container exit/unmount, so loss of tmpfs cannot masquerade as error cleanup.
Verification reads the original encrypted archive through a separate read-only
data mount while tmpfs hides the ordinary backup output directory.

Every failure publishes nothing and preserves original archive metadata,
source payload/integrity/identity and ordinary controller readiness. Both
original archives still fully verify afterward. Recovery remains a protected
read-only bind; credential contents never enter arguments/logs. No host/global mount
changes, credentials or shared database resources are involved. All test
containers/volumes/private fixtures and the disposable builder/cache are removed.
The built local image/artifact remain for further gates. Plaintext staging and
process memory exist only for the job; protected recovery source persists under
operator custody. Normal cleanup is not secure media erasure.

## Recorded outputs and remaining gates

| Gate | Output |
|---|---|
| Cached builder / actual SBOM build | [builder](p06-backup-sbom-container-faults-2026-10-03/builder.txt), [build](p06-backup-sbom-container-faults-2026-10-03/build.txt) |
| OCI loader refusal / matching runtime export | [refusal](p06-backup-sbom-container-faults-2026-10-03/oci-load-refusal.txt), [export](p06-backup-sbom-container-faults-2026-10-03/runtime-export.txt) |
| Tests-first parser and layer failures / final eight cases | [parser red](p06-backup-sbom-container-faults-2026-10-03/parser-red.txt), [layer red](p06-backup-sbom-container-faults-2026-10-03/layer-red.txt), [final](p06-backup-sbom-container-faults-2026-10-03/parser-final.txt) |
| Actual artifact/config/layer/inventory binding | [verification](p06-backup-sbom-container-faults-2026-10-03/verify-final.txt), [installed packages](p06-backup-sbom-container-faults-2026-10-03/runtime-packages.tsv) |
| First container fault run / exact attested backup and faults | [first](p06-backup-sbom-container-faults-2026-10-03/container-faults-first.txt), [attested](p06-backup-sbom-container-faults-2026-10-03/attested-backup-faults.txt) |
| Exact attested baseline profiles | [SQLite](p06-backup-sbom-container-faults-2026-10-03/attested-sqlite-profile.txt), [PostgreSQL serving](p06-backup-sbom-container-faults-2026-10-03/attested-postgres-profile.txt) |
| Disposable builder teardown | [output](p06-backup-sbom-container-faults-2026-10-03/builder-teardown.txt) |

Python syntax, configuration, 130 current relative links and diff
whitespace pass. Docker executes `npm run build` and locked release compilation.
Final required [Rust workspace](p06-backup-sbom-container-faults-2026-10-03/workspace-rust.txt)
passes 672/four inherited ignores; [Clippy](p06-backup-sbom-container-faults-2026-10-03/clippy.txt)
and [format](p06-backup-sbom-container-faults-2026-10-03/format.txt) pass.
[Node26 workspace tests](p06-backup-sbom-container-faults-2026-10-03/workspace-node26.txt)
pass, including 108 MCP and 147 helper/channel cases. SPS has 80 passes/101
service-gated skips in 17 files. The three Quickshell and one opt-in PG outage
Rust ignores remain unexecuted by that workspace gate; actual Compose PG outage
runs separately above. Node24 and full broker/browser workflows are not rerun.
Existing user P03 evidence remains untouched/un-staged (66 additions).

The separate [PostgreSQL toolkit review](../../product/decisions/0011-p06-postgresql-backup-toolkit-review.md)
is still pending. Exported snapshot/custom dump/full isolated restore and
PostgreSQL backup artifacts remain required. Sudden power loss, maximum-size,
external non-restored authority/ownership, stale restore/fencing, upgrades,
interrupted transfer, complete three-profile/remote workflows and inherited
acceptance remain open. Keep all nine slices; no full slice/phase acceptance
or restored issuance is authorized by these checks.
