# Decision records

Decision records fix a direction that the [roadmap](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/Roadmap.md) or [specification](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/Specification.md) left open, using the evidence available on the decision date. They govern how forward work is built. They do not establish that anything is implemented, tested or released.

| Record | Decision | Status |
|---|---|---|
| [0001 Dashboard UI stack](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/decisions/0001-dashboard-ui-stack.md) | Rebuild the operator dashboard on React 19, Vite and plain CSS tokens, contract-first against the controller API | Accepted 2026-09-22 |
| [0002 Rust controller and broker](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/decisions/0002-rust-controller-and-broker.md) | Implement the host broker and the new controller in Rust behind the existing 13-endpoint machine contract; retire the TypeScript SPS after the pilot; port test-first through the [Controller Contract Suite](../../testing/Controller%20Contract%20Suite.md) | Accepted 2026-09-22; P00 gates the port, W0 gates P03/P02.6 |
| [0003 Dependency baseline](0003-dependency-baseline-2026-09.md) | Security-driven upgrade set for the existing packages and the version baseline for the rebuild; further manifest changes require Socket review | Partially implemented 2026-09-23 |

**Status vocabulary.** *Proposed*: written, waiting on the named gate. *Accepted*: direction chosen; implementation still follows roadmap gates. *Superseded*: replaced by a later record and kept for history.

The Obsidian-vault implementation phase index turns these directions into separately reviewable P00–P10 plans and matching acceptance documents. Phase acceptance and test execution are tracked separately from an accepted architectural direction.

Write a new record when a choice changes the stack, a trust boundary, a wire contract or a deployment shape. Keep it short: context, decision, alternatives, consequences and dated evidence. Update the roadmap or specification row that the record settles and link back here.
