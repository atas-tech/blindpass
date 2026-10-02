// SPDX-License-Identifier: AGPL-3.0-only
import { createServer } from 'node:http';
import { connect } from 'node:net';
import { approvedConnectAuthority } from './isolated-browser.mjs';
import { compileRecipe } from './private-login.mjs';

// Root supervisor side: fixed application HTTPS destination, selected once from
// the administrator recipe. Tunnel frames contain no hostname/port authority.
// TLS stays end-to-end between Chromium and the app; the supervisor forwards
// opaque TLS records and consumes no password or website cookie.
export function createApprovedEgressConnector(configuration) {
  const recipe = compileRecipe(configuration); const origin = new URL(recipe.origin);
  const host = origin.hostname.replace(/^\[|\]$/g, ''); const port = Number(origin.port || 443);
  return () => new Promise((resolve, reject) => {
    const socket = connect({ host, port });
    const timer = setTimeout(() => { socket.destroy(); reject(new Error('egress_unavailable')); }, 5000);
    socket.once('error', () => { clearTimeout(timer); reject(new Error('egress_unavailable')); });
    socket.once('connect', () => { clearTimeout(timer); socket.pause(); resolve(socket); });
  });
}

// Namespace worker side: only CONNECT to the selected application is accepted.
// The localhost proxy and CDP listener are reachable only inside PrivateNetwork.
export async function startApprovedConnectProxy(configuration, mux) {
  const authority = approvedConnectAuthority(configuration); const sockets = new Set();
  const server = createServer((_req, res) => { res.writeHead(403); res.end(); });
  server.headersTimeout = 5000; server.requestTimeout = 5000; server.maxConnections = 64;
  server.on('connection', (socket) => { sockets.add(socket); socket.on('error', () => {});
    socket.on('close', () => sockets.delete(socket)); });
  server.on('upgrade', (_req, socket) => socket.destroy());
  server.on('connect', (request, socket, head) => {
    socket.pause();
    if (request.url !== authority) { socket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n'); return; }
    // Node's CONNECT parser has relinquished this socket. Preserve initial TLS
    // bytes and acknowledge only when the outside connector actually succeeds.
    if (head.length) socket.unshift(head);
    try { mux.attach('egress', socket, { onReady: () => socket.write('HTTP/1.1 200 Connection Established\r\n\r\n') }); }
    catch { socket.destroy(); }
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  return { url: `http://127.0.0.1:${server.address().port}`, close: async () => {
    for (const socket of sockets) socket.destroy();
    await new Promise((resolve) => server.close(resolve));
  } };
}
