# P05 native backup dependency review — 2026-10-01

**Status: blocked. No dependency or manifest change authorized by this review.**

The native host-B acceptance workflow needs real restic backup and restore using
validated raw password bytes delivered through systemd credentials. Existing
browser/MCP implementations do not satisfy this requirement. The proposed
rest-server would host the disposable REST repository on host B.

## Exact reviewed proposals

Socket CLI deep reviews completed for these exact PURLs. Reports include category
scores and transitive alerts; shallow scores alone do not establish acceptability.

| Proposal | Dependency count | Deep scores | Significant reported alerts | Decision |
|---|---:|---|---|---|
| `pkg:golang/github.com/restic/restic@v0.19.1` | 97 | Overall70, maintenance75, quality100, supply chain70, vulnerability70, license50 | High CVE alert for `google.golang.org/grpc@v1.81.1`; medium CVE, network, shell/eval/native-code and potential-vulnerability alerts | Block |
| `pkg:golang/github.com/restic/rest-server@v0.14.0` | 19 | Overall25, maintenance75, quality100, supply chain71, vulnerability25, license80 | Critical and high CVE alerts for `golang.org/x/crypto@v0.38.0`; medium network, shell/eval/native-code alerts | Block |

Both package-only scores are 100. The global dependency-guard skill requires a
block when a high/critical alert is present or a category is below50. The exact
reports are retained as [restic evidence](../../testing/evidence/p05-restic-0.19.1-socket.md)
and [rest-server evidence](../../testing/evidence/p05-rest-server-0.14.0-socket.md).
Importing these artifacts initially failed when approval-service credits were
exhausted; ordinary execution access subsequently recovered. This table records
the observed results. It does not establish exploitability or actual binary
reachability of a module-level alert.

The official [restic release](https://github.com/restic/restic/releases/tag/v0.19.1)
and [rest-server release](https://github.com/restic/rest-server/releases/tag/v0.14.0)
exist. Their pinned source manifests include the reported modules:
[restic go.mod](https://github.com/restic/restic/blob/v0.19.1/go.mod) and
[rest-server go.mod](https://github.com/restic/rest-server/blob/v0.14.0/go.mod).
This is source provenance, not a security approval.

## Next proposal

Review a security-updated upstream release or an explicitly identified reproducible
build using reviewed fixed dependencies. Preserve the exact source/build/module
inventory, upstream notices, binary hashes and vulnerability evidence before
adoption. The potentially narrower binary package surface may be investigated,
but it must not be assumed to resolve the reported alerts. A substitute fixture
backup would not complete the original real restic acceptance requirement.

No proposed binary was installed or executed, and no manifest/lockfile was changed
for this proposal. Native service implementation work that needs these binaries
must wait for a reviewed acceptable proposal. Other authorized P05 work continues;
the phase and its inherited gates remain open.

## Security-updated candidate preparation — 2026-10-01

**Decision: block_pending_human_review for candidate preparation. Original
release adoption remains blocked.** This proposes private candidate builds and
complete resolved-graph review; it does not approve deployment or replace the
required real restic workflow with a fixture.

### Exact candidate

- Restic source `v0.19.1`, official source archive SHA256
  `bb9b1a19040744d26d8a79be029d4e6b189c45ccc9d8831d7fe367d3c33df725`:
  raise `google.golang.org/grpc` to `v1.84.0` and `golang.org/x/crypto` to
  `v0.57.0` in a private candidate workspace.
- Rest-server source `v0.14.0`, official source archive SHA256
  `6c23d0c7020b375ae4307f3776fa634fd4a7e86ccc493d0ccdf4934c9e5d8311`:
  raise `golang.org/x/crypto` to `v0.57.0` in a separate candidate workspace.
- Official `go1.27.1.linux-amd64.tar.gz`, SHA256
  `63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445`,
  private tooling only. Use `CGO_ENABLED=0`, `GOTOOLCHAIN=local`, checksum
  verification and an explicitly recorded module proxy/checksum database.
  The toolkit has official release provenance; it has no Socket module-category
  score. Do not describe that absence as a health score.

No upstream application algorithms, authentication or backends are removed.
The selected server remains the real rest-server and the ordinary consumer
remains restic. Existing standard-library/Rust backup probes exercise credential
delivery only and cannot satisfy real backup/restore acceptance.

### Observed review results

| Updated module | Direct/transitive count | Deep category scores | Alerts and decision |
|---|---:|---|---|
| `google.golang.org/grpc@v1.84.0` | 42 | Overall70, maintenance100, quality100, supply chain70, vulnerability98, license80 | No reported high/critical; medium network/shell/eval/native/potential-vulnerability; low SDK CVE and license uncertainty; human review required |
| `golang.org/x/crypto@v0.57.0` | 4 | Overall74, maintenance100, quality100, supply chain74, vulnerability100, license100 | No reported CVE/high/critical; medium network/shell/eval/native/potential-vulnerability; human review required |

Exact [gRPC report](../../testing/evidence/p05-grpc-1.84.0-socket.md) and
[crypto report](../../testing/evidence/p05-xcrypto-0.57.0-socket.md) are retained.
These module scores do not establish the final restic/rest-server graph score.
Go's version selection may raise additional modules. A complete generated
`go.mod`/`go.sum` inventory and Socket review are still required before candidate
binary execution or VM adoption. Any remaining high/critical alert or category
below50 still blocks that artifact; new medium/unavailable risk requires review.

Upstream [gRPC release notes](https://github.com/grpc/grpc-go/releases/tag/v1.84.0)
include security-related credential/redirect and authorization changes. Its
[manifest](https://github.com/grpc/grpc-go/blob/v1.84.0/go.mod) raises OpenTelemetry
to1.44.0. The selected [crypto manifest](https://github.com/golang/crypto/blob/v0.57.0/go.mod)
requires Go1.26 and updated network/system/text modules; the proposal uses a
newer official toolchain from [Go release metadata](https://go.dev/dl/?mode=json).
These are source facts, not final vulnerability clearance.

### Required preparation and adoption gates

1. Verify official source archive digests and captured manifest/license hashes
   against [provenance](../../testing/evidence/p05-native-updated-candidate-provenance.json).
2. Resolve the candidate module graphs in private disposable directories,
   retaining generated manifests/checksums and exact changes. Review the full
   graphs with dependency-guard before building or executing candidate binaries.
3. Build twice with pinned flags/toolchain and compare binary hashes. Retain
   Go build/module information and every upstream license/notice, including
   transitive license obligations; preserve the repository's MIT/AGPL boundary.
4. Inspect vulnerability evidence for the exact resulting graph and binaries.
   Narrow reachability evidence does not override a remaining policy block.
5. Only after the resulting artifacts clear review, run the original two-host
   real backup/restore, raw password-file, ≤5s delivery, identity/partial-delivery,
   custody/reboot/rotation, logout/concurrency and native credstore comparison.

Only public release metadata, source manifests/checksums and licenses were
fetched for this proposal. No Go toolkit, restic or rest-server binary has been
downloaded, installed or executed. No project manifest or lockfile changed.
