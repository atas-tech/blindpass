// SPDX-License-Identifier: AGPL-3.0-only
import { spawn } from 'node:child_process';
import { startAiAgent } from './ai-client-agent.mjs';
import { StockMcpClient } from './stock-mcp-client.mjs';
import { guestBrowserProfile } from './guest-browser-profile.mjs';
import { runProtocolStdio, createBrokerClient, brokerIdentityFromEnvironment } from '/usr/lib/blindpass/login/mcp/mcp-server.mjs';
try {
  if (process.getuid() === 0 || process.argv.length !== 2) throw new Error();
  const identity = brokerIdentityFromEnvironment(); if (!identity) throw new Error();
  if (!/^p05-ai-(claude|codex)\.service$/.test(identity.unit)) throw new Error();
  const name = identity.unit.slice(0, -'.service'.length);
  const agent = await startAiAgent({ input: process.stdin, output: process.stdout,
    brokerClient: createBrokerClient(identity), runProtocolStdio,
    onStockFailure: (name, reason) => process.stderr.write(`P05-AI-STOCK failed tool=${name} reason=${reason}\n`),
    profile: guestBrowserProfile(process.env.BLINDPASS_P05_BROWSER_APP),
    openStock: () => new StockMcpClient({ onFailure: reason => process.stderr.write(`P05-AI-TRANSPORT failed reason=${reason}\n`), child: spawn('/usr/lib/blindpass/login/runtime/bin/node',
      ['/usr/lib/blindpass/login/node_modules/@playwright/mcp/cli.js', '--config', `/run/${name}/stock-config.json`],
      { stdio: ['pipe', 'pipe', 'pipe'] }) }) });
  await agent.closed; if (agent.failed) process.exitCode = 70;
} catch (error) {
  if (['stock-open', 'stock-initialize', 'stock-registry', 'sdk-start'].includes(error?.stage)) process.stderr.write(`P05-AI-AGENT failed stage=${error.stage}\n`);
  process.exitCode = 70;
}
