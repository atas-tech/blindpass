# Repository instructions

## Start here

- Read [docs/README.md](docs/README.md) for documentation ownership, current limits and links to the authoritative vault Roadmap, Specification and Linux Fleet Pilot. Historical plans do not override the roadmap or reactivate frozen features.
- See [architecture](docs/architecture/README.md) for the package map and [test setup](docs/testing/README.md) for commands and prerequisites. Code lives in `packages/` and `crates/`; scripts in `scripts/`; service templates in `deploy/`.
- Read [LICENSES.md](LICENSES.md) before changing package boundaries.

## Working conventions

- Follow surrounding style; avoid unrelated reformatting. TypeScript is strict ESM/NodeNext: keep `.js` suffixes on local imports. Use kebab-case filenames, camelCase values/functions, PascalCase types and UPPER_SNAKE_CASE environment variables.
- Use relative repository links and stable docs-vault URLs, never machine-specific paths. Repair inbound links when moving or deleting documents.
- Keep credentials, `.env` files, private keys, live links and bearer tokens out of commits, chat, logs and evidence. Use generated dummy canaries for exposure checks.
- State who consumes plaintext and its lifetime; runtime memory, encrypted storage, service delivery and browser sessions have different limits.
- For dependency additions, upgrades, removals or reviews, use the global `dependency-guard` skill before changing manifests or lockfiles. Evaluate Socket signals and stop for unresolved risk as the skill requires.

## Tests and acceptance

- **Prefer tests first:** derive test scenarios from acceptance criteria, then write or update meaningful tests before implementation code. Run them to confirm the expected failure, implement the behavior, and rerun to confirm it passes. Cover authorization, secret handling, transport fallback, TTL and one-use retrieval where relevant.
- For each phase/milestone, define comprehensive E2E and integration scenarios in the paired vault plan under `blindpass/docs/testing/phases/`. Implement those tests with the feature, preserve scenario IDs and record actual execution evidence in this repository.
- Run commands from the repository root. Workspace scripts run in package directories; do not assume they load the root `.env`. Follow [test setup](docs/testing/README.md) for service prerequisites and suite gates.
- For implementation changes, run `npm run build`, `npm test` and relevant integration/E2E and Rust gates. Inspect skipped suites and report unexecuted checks; source inspection, plans and skipped tests do not establish working behavior.
- For documentation-only edits, check links, command accuracy and `git diff --check`; report runtime checks not run.
- Linux pilot guarantees require real systemd VM and stock-client tests. Before declaring P01 VM testing unavailable, check `/dev/kvm` read/write access and QEMU through an approved unsandboxed command, then run `./tests/fleet/p01-vm.sh` with the pinned image and disposable SSH key from [fleet setup](tests/fleet/README.md). Report denied host access precisely: sandbox visibility and portable Rust tests are not VM evidence.

## Commits and reviews

Use Conventional Commit subjects. PRs should describe the behavior change, affected packages, checks run and material limits. Include screenshots or message samples for visible UI/chat changes, without secret values.
