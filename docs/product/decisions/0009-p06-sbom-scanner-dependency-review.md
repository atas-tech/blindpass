# 0009 — P06 build-time SBOM scanner

**Status:** Scoped user approval, 2026-10-02. This is dependency authorization,
not controller image publication or P06 acceptance.

P06-D8 requires an attached release SBOM. Use the official BuildKit scanner
`docker/buildkit-syft-scanner:stable-1` pinned to the OCI index digest
`sha256:ae4f3b554449e7e25548e7d8ccc029d17357348e30c6e3df01b92bc93654d6a9`.
Its attached x86_64 SPDX inventory identifies scanner v1.12.0, Syft v1.51.0
and 273 packages. The scanner is a build-time tool, not a controller runtime
package. It receives the public build-stage filesystem snapshots, no private
credentials, tokens, BuildKit secret inputs or host socket. No Cargo/npm
manifest or lockfile changes are needed.

The dependency-guard CLI deep reports for
`pkg:golang/github.com/docker/buildkit-syft-scanner@v1.12.0` and
`pkg:golang/github.com/anchore/syft@v1.51.0` report 282/915 transitive packages,
overall 50/25, supply-chain 70/36, vulnerability 77/25 and license 50/50.
They include high/critical npm examples (lodash/form-data/brace-expansion),
unresolved Yarn and Maven/Ruby fixtures. Those npm/Maven fixture examples are
absent from the actual scanner inventory. This does not prove every broad
alert irrelevant or replace dependency review. Go crypto/native-code,
filesystem/environment, network/eval/shell/unsafe signals and medium alerts
remain. The broad reports trigger the guard's block/human-review rules;
autonomous approval was not inferred from Docker's default scanner choice.

After the exact digest, inventory comparison, scope and remaining signals
were presented, the user answered **“Approve this scoped scanner.”** Use only
this reviewed digest for the proposed controller workflow. Existing Docker
Actions versions are reused. Future scanner/version changes need a new review.
A hand-written partial package inventory would not satisfy the requested full
build/runtime SBOM; it was not substituted to avoid this review.

The workflow must mark both UI and Rust build stages for scanning, attach the
SBOM to versioned controller output and keep legacy image jobs. Verify local
attachment/content separately from unexecuted remote GHCR publishing. Debian
and PostgreSQL OCI/OS prerequisites are not Socket-supported package-manager
reviews; the Go report does not audit those images.

The exact scanner exposes `BUILDKIT_SCAN_SELECT_CATALOGERS` through BuildKit's
`SELECT_CATALOGERS` attestation parameter. Actual default output omitted Cargo.
Use the additive expression
`+sbom-cataloger,+rust-cargo-lock-cataloger,+javascript-package-cataloger,+dpkg-db-cataloger`.
It adds no package/binary and preserves the default source catalogers. The
artifact gate checks the bound descriptor graph, in-toto subjects, three SPDX
documents, every Cargo registry lock entry and every non-optional npm lock
entry. Build-stage inventories include declared source/fixture dependencies;
they are not a claim that every listed package executes in the runtime.
See the [exact upstream scanner configuration](https://github.com/docker/buildkit-syft-scanner/blob/v1.12.0/internal/target.go).
