# Provenance and consumers of the contract fixtures

The CV fixtures are frozen data. Each one has a TypeScript consumer that no longer imports SPS source (it uses the
oracles in `src/oracle`) and, except CV02, a Rust consumer that reads the same file, so neither runtime is the sole
oracle for itself (P08-D2). Snapshot provenance is in [snapshots/PROVENANCE.md](snapshots/PROVENANCE.md).
Never regenerate a fixture after SPS removal; a change needs a decision record.

| Fixture | Source | TypeScript consumer | Rust consumer |
|---|---|---|---|
| `cv01-signed-link.json` | Signed-link vector minted by the legacy SPS signer | `tests/vectors.test.ts` CV01 | `crates/blindpass-controller/src/routes/exchanges.rs`, `crates/blindpass-core/src/signing.rs` |
| `cv02-derived-secrets.json` | Domain-separated secret derivation | `tests/vectors.test.ts` CV02 | Expected values asserted as literals in `crates/blindpass-core/src/signing.rs`; the file itself is not read |
| `cv03-fulfillment-token.json` | Exact HS256 token bytes minted by SPS with a fixed issued-at | `tests/vectors.test.ts` CV03 | `exchanges.rs` |
| `cv04-confirmation-code.json` | Dictionary and shape of confirmation codes | `tests/vectors.test.ts` CV04, and CT03 checks live responses against it | `crates/blindpass-controller/src/routes/secrets.rs` |
| `cv05-policy.json` | Five policy cases | `tests/vectors.test.ts` CV05 | `exchanges.rs` |
| `cv05-hash-escaping.json` | Decision hashes for strings that need JSON escaping, from SPS `hashPolicyDecision` | `tests/vectors.test.ts` CV05 | `exchanges.rs` |
| `cv05-policy-matrix.json` | 32 seeded rule sets, 311 cases, minted by the legacy SPS engine (seed `0xc05a`, source commit `8a595ad` recorded inside). The generator was a parity test against the live SPS engine; it was removed with SPS and was never committed, so the file is the record | `tests/vectors.test.ts` CV05 matrix | `exchanges.rs` |
| `cv05-policy-decided.json` | 7 rule sets, 11 cases, hand-authored from the owner decision of 2026-10-07; only the hashes are computed, with `hashPolicyDecision` | `tests/vectors.test.ts` CV05 decided semantics | `exchanges.rs` |
| `cv06-hpke.json` | RFC 9180 vector and a cross-runtime sealed fixture | `tests/vectors.test.ts` CV06 | `crates/blindpass-core/tests/hpke_interop.rs` |
| `required-cases.json` (formerly `rust-pending.json`) | Required case IDs and the CT14 exclusion read by `scripts/tests/assert-contract-progress.mjs`; `pendingIds` is empty | n/a | n/a |

## Policy matrix scope

The matrix holds documents that the Rust policy validator also accepts, and none of the shapes on which the legacy
engine and the Rust controller disagreed. Those shapes are in `cv05-policy-decided.json` with the controller's
behaviour, which the owner chose on 2026-10-07: an empty `requesterIds` or `fulfillerIds` list matches every agent, a
blank `reason` falls back to the generated text, a padded `reason`, rule id or rule secret name is trimmed. An
unrecognised rule mode denies by contract and is in neither file. `exchanges.rs` and `admin_policy.rs` carry the
direct Rust tests.
