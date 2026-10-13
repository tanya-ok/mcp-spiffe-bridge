# mcp-spiffe-bridge

SPIFFE/SPIRE workload identity for MCP servers written in TypeScript.

The bridge terminates mutual TLS inside your MCP server or gateway using the
workload's own X.509-SVID from the SPIRE Workload API. Every caller must present
a short-lived SVID that chains to the local trust bundle and matches a SPIFFE ID
allowlist before a request reaches your handler. The verified caller identity is
available to tool code, and every decision produces a structured audit event.

Why: static API keys for service-to-service MCP calls are long-lived, shared and
hard to rotate. SPIFFE identities are attested by the platform, expire quickly
and rotate automatically.

## Status

- Version 0. The API may change.
- Not production-ready. See [limits and threat model](#limits-and-threat-model).
- Not published to a package registry yet. Install from a local checkout.

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

`@modelcontextprotocol/sdk` 1.x is a peer dependency.

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
  expired material and reconnects with a bounded budget.
- `MtlsTransportServer` requires a client certificate, rotates its TLS context
  without a restart and closes existing connections on every credential change.
- `SpiffeValidator` applies SPIFFE checks on top of TLS chain verification.
- `getCallerIdentity` exposes the verified caller through `AsyncLocalStorage`.

Details: [credential lifecycle](docs/credential-lifecycle.md) and
[Kubernetes integration](docs/kubernetes-lab.md).

## Limits and threat model

- Refuses: callers without a certificate, certificates from untrusted roots,
  disallowed, expired or short-lived SPIFFE IDs, and requests while the
  bridge's own credential is unavailable.
- Trusts: the SPIRE agent socket and its workload attestation.
- Federation is unsupported. Non-local `allowedTrustDomains` fail at startup.
- CRLs are not processed; a Workload API snapshot that carries CRLs is refused.
- Authentication only. Per-tool authorization, user identity and OAuth remain
  the consuming application's responsibility.
- Audit events go to stdout by default; durable delivery is not provided.
- `stdio-identity-only` mode cannot carry TLS and does not authenticate callers.

## Documentation

- [Overview](docs/index.md)
- [Installed package demo](docs/installed-demo.md)
- [Credential lifecycle](docs/credential-lifecycle.md)
- [Kubernetes integration](docs/kubernetes-lab.md)
- [Publication readiness](docs/publication-readiness.md)
- [Development plan](docs/development-plan.md)

## Development

```sh
pnpm test
pnpm typecheck
pnpm lint
pnpm build
```

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md) and
[CHANGELOG.md](CHANGELOG.md).

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
