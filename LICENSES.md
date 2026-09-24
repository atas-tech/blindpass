# BlindPass Licensing Matrix

BlindPass uses a mixed-license monorepo model. The applicable license depends on the package you are using.

## Package Matrix

| Package | License | Notes |
| :--- | :--- | :--- |
| `packages/sps-server` | `AGPL-3.0-only` | Secret Provisioning Service / trust anchor |
| `packages/dashboard` | `AGPL-3.0-only` | Hosted control plane UI |
| `packages/i18n` | `AGPL-3.0-only` | Declared in package metadata; no standalone package LICENSE file currently present |
| `packages/agent-skill` | `MIT` | Agent-side SDK / skill logic |
| `packages/browser-ui` | `MIT` | Client-side encryption sandbox |
| `packages/gateway` | `MIT` | Interception / delivery middleware |
| `packages/openclaw-plugin` | `MIT` | Runtime integration plugin |
| `packages/contract-tests` | `AGPL-3.0-only` | Black-box compatibility and acceptance harness; private test package |
| `crates/blindpass-core` | `AGPL-3.0-only` | Shared identity, delivery, custody and protocol contracts |
| `crates/blindpass-broker` | `AGPL-3.0-only` | Root host broker and native consumer probes |
| `crates/blindpass-controller` | `AGPL-3.0-only` | Rust controller implementation in progress |
| `crates/blindpass-cli` | `AGPL-3.0-only` | Local controller administration CLI implementation in progress |

## Repository Notes

- The root workspace package is marked `private` and uses `SEE LICENSE IN LICENSES.md` because the repository contains packages under more than one license.
- The six original application/integration packages include `LICENSE` files. The shared i18n package currently declares its license in `package.json` only; this documentation update does not add or change licensing terms.
- The [original licensing proposal](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/archive/Licensing_Proposal.md) in the docs vault is historical rationale; the package metadata/license files and this matrix describe the current repository.

### P02 Rust controller dependencies

The user approved this controller/CLI dependency set on 2026-09-24 after reviewing the Socket findings in [decision 0004](docs/product/decisions/0004-controller-dependency-review-2026-09.md). Cargo.lock pins the resolved versions. The direct package licenses are:

| Crate | Locked version | License |
| :--- | :--- | :--- |
| `argon2` | 0.5.3 | MIT OR Apache-2.0 |
| `axum` | 0.8.9 | MIT |
| `base64` | 0.22.1 | MIT OR Apache-2.0 |
| `clap` | 4.6.7 | MIT OR Apache-2.0 |
| `jsonwebtoken` | 9.3.1 | MIT |
| `rand` | 0.8.8 | MIT OR Apache-2.0 |
| `serde` | 1.0.229 | MIT OR Apache-2.0 |
| `serde_json` | 1.0.151 | MIT OR Apache-2.0 |
| `sqlx` | 0.8.6 | MIT OR Apache-2.0 |
| `tokio` | 1.53.1 | MIT |
| `tower-http` | 0.6.11 | MIT |
| `tracing` | 0.1.44 | MIT |
| `tracing-subscriber` | 0.3.23 | MIT |

This approval is for the P02 dependency proposal and its resolved Cargo graph. It does not change the license or dependency boundary of `blindpass-core`; that crate remains dependency-free.

## Boundary Expectations

- MIT packages are intended to remain separable integrations around the protocol and service.
- MIT packages should not vendor or embed AGPL application code.
- The Rust broker uses host `libsystemd` and `libcrypto` through a narrow FFI
  surface; no third-party Cargo crypto or zeroization dependency is included
  in this phase.
- If package boundaries change materially, the licensing split should be reviewed again.
