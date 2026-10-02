# Upstream notices

The official `@modelcontextprotocol/server@2.2.0` and transitive
`@modelcontextprotocol/core@2.2.0` npm metadata says MIT. Their actual license
files describe Apache-2.0 for new/consented contributions and MIT for retained
contributions. Preserve these complete upstream files with redistribution:

- [Server license](licenses/modelcontextprotocol-server-LICENSE)
- [Core license](licenses/modelcontextprotocol-core-LICENSE)
- [Zod 4.6.5 MIT license](licenses/zod-LICENSE)

BlindPass MCP integration code is MIT; these upstream terms remain applicable.
This package contains no copied AGPL broker/controller/helper implementation.


The standalone MCP bundle also retains attribution for unchanged legacy client
modules. The build uses emitted esbuild inputs to copy each included package's
complete license/notice files and records their versions and SHA-256 hashes in
`dist/licenses/bundle-packages.json`. It rejects AGPL workspace code, missing
license text and unsupported license metadata rather than silently distributing
an incomplete MIT bundle.

The existing `@x402/core`, `@x402/fetch` and `@x402/evm` 2.8.0 npm archives omit a
license file and declare Apache-2.0. The retained [canonical upstream text](licenses/x402-Apache-LICENSE)
was copied from [Coinbase's public upstream license](https://raw.githubusercontent.com/coinbase/x402/main/LICENSE)
on 2026-09-30 (SHA-256 `50e6751797c50dedd75ef1b8a0d9e42f5f8472e9fbce91f34718e9f97b0c780a`).
This is an attribution repair for unchanged legacy modules; it does not extend
or reactivate the frozen payment feature. No dependency versions were changed.
