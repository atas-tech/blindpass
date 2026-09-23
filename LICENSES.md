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
| `crates/blindpass-controller` | `AGPL-3.0-only` | Future local controller scaffold |
| `crates/blindpass-cli` | `AGPL-3.0-only` | Future enrollment and administration CLI scaffold |

## Repository Notes

- The root workspace package is marked `private` and uses `SEE LICENSE IN LICENSES.md` because the repository contains packages under more than one license.
- The six original application/integration packages include `LICENSE` files. The shared i18n package currently declares its license in `package.json` only; this documentation update does not add or change licensing terms.
- The [original licensing proposal](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/archive/Licensing_Proposal.md) in the docs vault is historical rationale; the package metadata/license files and this matrix describe the current repository.

## Boundary Expectations

- MIT packages are intended to remain separable integrations around the protocol and service.
- MIT packages should not vendor or embed AGPL application code.
- The Rust broker uses host `libsystemd` and `libcrypto` through a narrow FFI
  surface; no third-party Cargo crypto or zeroization dependency is included
  in this phase.
- If package boundaries change materially, the licensing split should be reviewed again.
