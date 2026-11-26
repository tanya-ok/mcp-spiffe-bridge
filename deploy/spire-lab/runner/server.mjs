// Bridge under test, run as uid 1000 in runner-a with a real SPIRE Workload API.
import http from 'node:http';
import {
  createMcpSpiffeBridge,
  FileAuditLogger,
  getCallerIdentity,
  MtlsTransportServer,
  SpiffeValidator,
} from 'mcp-spiffe-bridge';

const socketPath = 'unix:///run/spire/sockets/agent.sock';
const local = 'spiffe://example.org/agent/research';
const billing = 'spiffe://partner.example.net/agent/billing';
const counts = {};
const metrics = {
  increment(name, labels) {
    const key = labels ? `${name}{${Object.values(labels).join(',')}}` : name;
    counts[key] = (counts[key] ?? 0) + 1;
  },
};
const audit = new FileAuditLogger({ path: '/bench/out/audit.jsonl' });
const bridge = createMcpSpiffeBridge({
  workloadApi: { socketPath },
  validator: {
    allowedCallers: [local, billing],
    minTtlSeconds: 5,
    federatedTrustDomains: ['partner.example.net'],
  },
  transport: { mode: 'mtls-server', sse: { host: '0.0.0.0', port: 8443 } },
  audit: { logger: audit },
  metrics,
});

function handler(req, res) {
  const caller = getCallerIdentity()?.spiffeId.full ?? null;
  if (req.url === '/stream') {
    res.writeHead(200, { 'Content-Type': 'text/event-stream' });
    const timer = setInterval(() => res.write(`data: ${caller}\n\n`), 500);
    res.on('close', () => clearInterval(timer));
    return;
  }
  res.setHeader('Content-Type', 'application/json');
  res.end(JSON.stringify({ caller }));
}
bridge.setAuthorizedHandler(handler);
await bridge.start();

// Mismatched pieces: federated transport with a validator that lacks federatedTrustDomains.
const mismatched = new MtlsTransportServer({
  fetcher: bridge.fetcher,
  validator: new SpiffeValidator(
    { allowedCallers: [local, billing], minTtlSeconds: 5 },
    bridge.fetcher,
  ),
  audit,
  transport: { mode: 'mtls-server', sse: { host: '0.0.0.0', port: 8444 } },
  federatedTrustDomains: ['partner.example.net'],
});
mismatched.setAuthorizedHandler(handler);
await mismatched.start();

// No federation configured: partner.example.net is not an accepted trust domain.
const localOnly = new MtlsTransportServer({
  fetcher: bridge.fetcher,
  validator: new SpiffeValidator(
    { allowedCallers: [local, billing], minTtlSeconds: 5 },
    bridge.fetcher,
  ),
  audit,
  transport: { mode: 'mtls-server', sse: { host: '0.0.0.0', port: 8445 } },
});
localOnly.setAuthorizedHandler(handler);
await localOnly.start();

http
  .createServer(async (_req, res) => {
    let svid = null;
    try {
      const s = await bridge.fetcher.getX509Svid();
      svid = {
        id: s.spiffeId.full,
        chainLength: s.certChain.length,
        notAfter: s.notAfter.toISOString(),
        federated: [...(s.federatedBundles?.keys() ?? [])],
        crls: s.crls?.length ?? 0,
      };
    } catch (err) {
      svid = { error: String(err?.code ?? err) };
    }
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ ready: bridge.isReady(), counts, svid, audit: audit.stats() }));
  })
  .listen(9090, '127.0.0.1');
console.log('bench server ready');
