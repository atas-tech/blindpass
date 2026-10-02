# 0008: P06 controller TLS adapter review

**Status:** Scoped proposal explicitly approved by the user on 2026-10-02
after review of the Socket findings below. Runtime/deployment gates remain required.

**Companions:** [P02 dependency decision](0004-controller-dependency-review-2026-09.md)
· [P06 plan](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/phases/06-deployment-and-recovery.md)
· [Repository dependency policy](../../../AGENTS.md)

## Proposal

Add exactly `tokio-rustls = { version = "=0.26.6", default-features = false,
features = ["ring", "tls12"] }` to the controller. It adapts the existing Tokio
listener to the maintained rustls TLS implementation, with the existing ring
provider. The repository already resolves rustls 0.23.45, rustls-pki-types
1.15.1 and ring 0.17.14 through SQLx; the proposed change must preserve those
versions and exclude the default AWS-LC provider. Review the actual resolved
manifest/lockfile graph before committing any authorized addition.

The prior `axum-server@0.8.0` proposal was blocked. There is no existing Tokio
server TLS adapter in the controller. A handwritten TLS implementation is not
an acceptable alternative. Reverse-proxy TLS is already available but does not
fulfil the built-in TLS option. No scope reduction is inferred from this block.

## Socket evidence and decision

The required CLI deep reports were obtained before any dependency change:

| Package | Direct score | Deep score / count | Reported risk |
|---|---|---|---|
| tokio-rustls 0.26.4 | 100 | 12 / 132 direct and transitive dependencies | High AWS-LC/FIPS vulnerability, medium bytes vulnerability and native build/shell/eval flags |
| tokio-rustls 0.26.6 | 100, no direct alerts | 12 / 123 direct and transitive dependencies | Supply-chain minimum 12 (`r-efi`); vulnerability 98 (`time`); medium AWS-LC security, time vulnerability, native build/shell/eval/network flags |

The reports describe broad package graphs, not Cargo's selected production
feature closure. They include AWS-LC and other packages outside the proposed
ring-only adapter. That limits attribution; it does not make the resolved
proposal reviewed or override the guard's score/alert thresholds. The outcome
was `block`. The user explicitly approved the narrowly scoped proposal on
2026-10-02 after the findings and feature-closure limits were presented. This
provides the required human review for this exact addition; no broader dependency
change is authorized by it. Do not classify a shallow
score of 100 as proof of transitive safety.

The upstream adapter uses MIT OR Apache-2.0 licensing. If approved, record its
direct license in the controller row of the licensing matrix. Cargo feature
and version assertions, invalid-key/certificate refusal, real HTTPS serving,
handshake bounds and shutdown tests are still required; a review does not
establish runtime behavior.


## Resolved graph verification — 2026-10-02

Comparison with the pre-slice Cargo.lock adds only tokio-rustls 0.26.6
(checksum c9cc2678c2cdd569ef8215e2afd7954ada2ae20b4fdd2c5fe6139a3b02d105db).
No existing package version was changed or removed. Its normal dependencies
are rustls and tokio; it has no build script. The compiled controller feature
closure contains ring and tls12 and contains no AWS-LC package. Existing rustls
0.23.45, rustls-pki-types 1.15.1 and ring 0.17.14 remain locked. The broad Socket
report is retained with its limitations; selected features are not a rescore or
a claim that the transitive stack has no vulnerabilities.
