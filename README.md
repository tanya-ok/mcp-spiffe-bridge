# mcp-spiffe-bridge

SPIFFE/SPIRE workload identity for MCP servers written in TypeScript.

The bridge terminates mutual TLS inside your MCP server or gateway using the
workload's own X.509-SVID from the SPIRE Workload API. Every caller must present
a short-lived SVID that chains to the bundle of its own trust domain (local, or
explicitly federated) and matches a SPIFFE ID allowlist before a request reaches
your handler. The verified caller identity is
available to tool code, and every decision produces a structured audit event.

Why: static API keys for service-to-service MCP calls are long-lived, shared and
hard to rotate. SPIFFE identities are attested by the platform, expire quickly
and rotate automatically.

## Status

- `package.json` version 0.0.1, unreleased. [CHANGELOG.md](CHANGELOG.md)
  lists the API intended for the first release; the version number is the
  maintainer's decision.
- Not published to npm yet. Install from a local checkout.
- Code-level gaps are closed and tested, including on a real two-domain SPIRE
  federation [bench](docs/spire-bench.md). Not declared production-ready until
  the maintainer-owned gates in [production readiness](docs/production-readiness.md)
  are closed: independent review, npm publication and the version decision.

## Requirements

- Node.js 26 or newer
- pnpm 12, pinned through `packageManager`
- A SPIRE agent Workload API socket, or synthetic certificates for local tests

## Install from a local checkout

```sh
pnpm install --frozen-lockfile
pnpm build
mkdir -p /tmp/mcp-spiffe-bridge
npm pack --pack-destination /tmp/mcp-spiffe-bridge
```

Then, in the consuming project:

```sh
npm install /tmp/mcp-spiffe-bridge/mcp-spiffe-bridge-0.0.1.tgz
```

`@modelcontextprotocol/sdk` `>=1.32.0 <2.0.0` is an optional peer dependency.
The library does not import it; the range is the one its tests run against.

## Usage

```ts
import { createMcpSpiffeBridge, getCallerIdentity } from 'mcp-spiffe-bridge';

const bridge = createMcpSpiffeBridge({
  workloadApi: { socketPath: 'unix:///run/spire/sockets/agent.sock' },
  validator: {
    allowedCallers: ['spiffe://example.org/agent/*'],
    minTtlSeconds: 60,
  },
  transport: { mode: 'mtls-server', sse: { port: 8443 } },
});

bridge.setAuthorizedHandler(async (_req, res) => {
  // Attach your MCP Streamable HTTP transport here.
  res.end(getCallerIdentity()?.spiffeId.full);
});

await bridge.start();
```

Use `bridge.isReady()` for readiness probes. For durable audit, pass a file
sink: `log()` resolves only after the event is fsynced (group commit), a failed
write refuses the request with 503, and the sink reopens itself with backoff:

```ts
import { FileAuditLogger } from 'mcp-spiffe-bridge';

const audit = new FileAuditLogger({ path: '/var/log/mcp/audit.jsonl' });
// createMcpSpiffeBridge({ ..., audit: { logger: audit } })
// After renaming the file for rotation: await audit.reopen();
```

To trust callers from a federated SPIRE trust domain, name it explicitly and
allow its callers:

```ts
validator: {
  allowedCallers: ['spiffe://example.org/agent/*', 'spiffe://partner.example.net/agent/billing'],
  minTtlSeconds: 60,
  federatedTrustDomains: ['partner.example.net'],
},
```

Defaults are conservative: the listener binds `127.0.0.1`, TLS 1.3 is the
minimum version and only the local trust domain is trusted. Set
`transport.sse.host: '0.0.0.0'` only inside an isolated pod, and
`transport.minTlsVersion: 'TLSv1.2'` only for peers that cannot negotiate
TLS 1.3. A runnable example is in [`examples/basic`](examples/basic/README.md).

## Architecture

```text
SPIRE agent --Workload API stream--> fetcher --> TLS context (own SVID, bundle)
caller --mTLS--> listener --> validator (SAN, trust domain, TTL, allowlist)
                                 |--> audit event
                                 +--> your handler, caller identity in context
```

- `WorkloadApiSvidFetcher` streams SVIDs and trust bundles, refuses invalid or
  expired material and reconnects without limit, with capped backoff and jitter.
- `MtlsTransportServer` requires a client certificate, binds each peer chain to
  the anchors of its own trust domain, rotates its TLS context without a
  restart and drains connections that stay valid.
- `SpiffeValidator` applies SPIFFE checks (SAN, trust domain, TTL, allowlist).
- `FileAuditLogger` writes durable JSON Lines audit; `BridgeMetrics` hooks
  report handshakes, refusals, drops, rotation and reconnects.
- `getCallerIdentity` exposes the verified caller through `AsyncLocalStorage`.

Details: [operations](docs/operations.md), [credential lifecycle](docs/credential-lifecycle.md),
[SPIRE bench](docs/spire-bench.md) and [Kubernetes integration](docs/kubernetes-lab.md).

## Limits and threat model

- Refuses: callers without a certificate, certificates from untrusted roots,
  disallowed, expired or short-lived SPIFFE IDs, and requests while the
  bridge's own credential is unavailable.
- Trusts: the SPIRE agent socket and its workload attestation.
- Federation is off by default. Domains in `validator.federatedTrustDomains`
  are trusted only while the agent supplies their bundle, and each peer chain
  must lead to the bundle of its own trust domain.
- Caller matchers need an exact trust domain; `spiffe://*/**` and a bare `**`
  path are rejected.
- Revocation in practice is short SVID lifetimes. CRL support is experimental:
  SPIRE 1.16.0 sent no CRLs in the bench. `transport.crlScope` chooses between
  `all-issuers` (default, fail closed, refuses federated callers whose domain
  publishes no CRL) and `per-trust-domain`.
- Authentication only. Per-tool authorization, user identity and OAuth remain
  the consuming application's responsibility.
- Audit events go to stdout by default. `FileAuditLogger` gives durable local
  delivery; shipping the file to central storage is the deployment's job.
  Handshake denials use a rate-limited channel and may be dropped; drops are
  counted.
- `stdio-identity-only` mode cannot carry TLS and does not authenticate callers.
- Node.js 26 or newer only, a deliberate support decision.

## Documentation

- [Overview](docs/index.md)
- [Operations](docs/operations.md)
- [Audit event contract](docs/architecture/contracts/audit-event.md)
- [Installed package demo](docs/installed-demo.md)
- [SPIRE bench](docs/spire-bench.md)
- [Credential lifecycle](docs/credential-lifecycle.md)
- [Kubernetes integration](docs/kubernetes-lab.md)
- [Production readiness](docs/production-readiness.md)
- [Publication readiness](docs/publication-readiness.md)
- [Development plan](docs/development-plan.md)

## Development

```sh
pnpm test
pnpm typecheck
pnpm lint
pnpm build
pnpm run check:package
pnpm run bench:spire   # real SPIRE federation bench in a Lima VM, see docs/spire-bench.md
```

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md) and
[CHANGELOG.md](CHANGELOG.md).

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
