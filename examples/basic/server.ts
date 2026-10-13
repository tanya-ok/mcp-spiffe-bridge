/**
 * Minimal example: an MCP server that requires a SPIFFE identity on every
 * incoming request and exposes a single tool that echoes the caller back.
 *
 * Run locally against a SPIRE agent (see docs/kubernetes-lab.md
 * for agent setup). For pure offline dev, set the bridge's `degrade.mode`
 * to `warn-and-skip`; see the comment below.
 *
 *   pnpm tsx examples/basic/server.ts
 */

import { createMcpSpiffeBridge, getCallerIdentity } from '../../src/index.js';

const bridge = createMcpSpiffeBridge({
  workloadApi: {
    // Standard SPIRE agent env var; fall back to the default Kubernetes path.
    socketPath: process.env.SPIFFE_ENDPOINT_SOCKET ?? 'unix:///run/spire/sockets/agent.sock',
  },
  validator: {
    // Only accept peers whose SPIFFE ID is under our own trust domain's
    // `clients/` namespace. Adjust the glob for your deployment.
    allowedCallers: ['spiffe://example.org/clients/*'],
    minTtlSeconds: 60,
  },
  transport: {
    mode: 'mtls-server',
    sse: { host: '127.0.0.1', port: 8443 },
  },
  // Uncomment for local development without a SPIRE agent.
  // degrade: { mode: 'warn-and-skip' },
});

bridge.setAuthorizedHandler(async (req, res, identity) => {
  // The MCP SSE transport wiring goes here. For this example we just echo
  // the caller identity so you can curl the endpoint with a client cert and
  // see it came through.
  const caller = getCallerIdentity();
  res.statusCode = 200;
  res.setHeader('Content-Type', 'application/json');
  res.end(
    JSON.stringify(
      {
        method: req.method,
        url: req.url,
        caller: {
          spiffe_id: identity.spiffeId.full,
          trust_domain: identity.spiffeId.trustDomain,
          expires_at: identity.notAfter.toISOString(),
        },
        // Demonstrates that AsyncLocalStorage-based context is populated
        // inside the authorized handler scope.
        context_caller: caller?.spiffeId.full ?? null,
      },
      null,
      2,
    ),
  );
});

await bridge.start();

process.on('SIGINT', () => {
  void bridge.stop().then(() => process.exit(0));
});
process.on('SIGTERM', () => {
  void bridge.stop().then(() => process.exit(0));
});

console.log('mcp-spiffe-bridge example listening on https://127.0.0.1:8443');
