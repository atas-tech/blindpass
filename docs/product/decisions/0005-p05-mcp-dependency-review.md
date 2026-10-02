# 0005: P05 official MCP SDK dependency review

**Date:** 2026-09-30. **Status:** The user approved the smaller official SDK
proposal on 2026-09-30 after reviewing the Socket findings. The approved pinned
server/Zod dependencies are now installed in `packages/mcp-server`; the original
client, phase and release gates remain required.

## Proposed change

Use exact `@modelcontextprotocol/server@2.2.0` and `zod@4.6.5` runtime dependencies
in the proposed MIT `packages/mcp-server`. Keep its broker client and legacy
integration boundary separable from AGPL controller/broker code. Extract the
necessary MIT plugin modules without a plugin/server import cycle. Retain the
existing OpenClaw startup entrypoint and legacy tools through their own contract.

The SDK supplies maintained MCP framing, validation and protocol handling.
The existing plugin hand-rolls Content-Length framing and pins 2024-11-05;
it does not provide the required current stdio or URL elicitation behavior.
An in-house replacement is not the proposed alternative.

The [official SDK](https://github.com/modelcontextprotocol/typescript-sdk)
now publishes separate server/client packages. Its
[stdio compatibility entry](https://ts.sdk.modelcontextprotocol.io/v2/serving/legacy-clients.html)
supports 2025-era clients by default as well as the modern protocol. This
documentation supports choosing a candidate, not a stock-client support claim.
Actual initialization, version negotiation, capability gating and transcript
checks must still pass the full P05/M01–M07 gates.

## Dependency-guard results

Socket CLI `package score` reviews include transitives. Scores and capabilities
are signals, not proof of safety. No package installation code was executed.

| Exact package | Graph | Deep category scores | Alerts/capabilities | Decision |
|---|---|---|---|---|
| `@modelcontextprotocol/sdk@1.31.0` | 95 direct/transitive dependencies | Overall 48; maintenance 50, quality 66, supply chain 66, vulnerability 96, license 80 | High `socketUpgradeAvailable`; medium security/CVE/network/shell/eval alerts; environment/filesystem/network/shell/eval/unsafe capabilities | **block**; [report](../../testing/evidence/p05-mcp-sdk-1.31.0-socket.md) |
| `@modelcontextprotocol/server-legacy@2.2.0` | 76 direct/transitive dependencies | Overall 48; maintenance 50, quality 66, supply chain 66, vulnerability/license 100 | High `socketUpgradeAvailable`; medium deprecated/network/eval alerts; environment/filesystem/network/eval/unsafe capabilities | **block**; [report](../../testing/evidence/p05-mcp-server-legacy-2.2.0-socket.md) |
| `@modelcontextprotocol/server@2.2.0` | 2 direct/transitive dependencies: core 2.2.0 and zod 4.6.5 in this review | Overall 84; maintenance 93, quality 84, supply chain 99, vulnerability/license 100 | Medium network access; low anomaly/URL alerts; network/URL capabilities | **block_pending_human_review**; [report](../../testing/evidence/p05-mcp-server-2.2.0-socket.md) |
| `zod@4.6.5` | No dependencies | Overall/maintenance 94, quality 100, supply chain 99, vulnerability/license 100 | Low anomaly/URL alerts; URL capability | **allow_with_warning**; [report](../../testing/evidence/p05-zod-4.6.5-socket.md) |

Network access is expected in a general protocol SDK, although this integration
uses stdio and a protected broker socket. Dependency-guard's stricter medium-alert
rule requires human review before proceeding. The recommended replacement
avoids the blocked all-in-one and deprecated HTTP/SSE graphs. Current package
metadata has no preinstall/install/postinstall hooks; upstream build/publishing
scripts are not runtime installation hooks. A fresh lockfile must pin the
reviewed resolved graph; unexpected resolution needs another review.

The user completed that review and approved the smaller server/Zod proposal.
This does not authorize installing the blocked all-in-one or deprecated package.

## License and implementation limits

The published server archive declares MIT in package metadata but includes a
LICENSE describing Apache-2.0 for new/consented contributions and retained MIT
for contributions without relicensing consent. Preserve the actual upstream
license/notice material; do not describe the dependency as wholly MIT based
only on npm metadata. The proposed BlindPass integration's own code remains
MIT. No AGPL source is copied into that package.

Node metadata requires >=20. It does not establish BlindPass support for Node
24/26; run the actual package and workspace gates on both before changing the
published engine range. No direct client SDK or HTTP middleware is proposed.
Any later addition receives its own dependency review.

P01–P03 acceptance/P02.6 and P04-D4 provisioning remain separate integration
gates. Approving this dependency proposal does not accept those phases, prove
browser handoff, or waive any P05 scenario.

## Review record

| Date | Reviewer | Result |
|---|---|---|
| 2026-09-30 | Automated preparation | Reports collected; proposed server replacement requires human review |
| 2026-09-30 | User | Approved the smaller official server 2.2.0 and Zod 4.6.5 proposal, with the reported alerts/notices and phase/client gates retained |
