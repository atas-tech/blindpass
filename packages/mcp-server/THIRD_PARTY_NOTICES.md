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
