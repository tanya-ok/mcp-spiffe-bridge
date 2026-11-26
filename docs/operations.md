# Operations

How to configure and run the bridge in a deployment. Option names match
`src/types.ts`; `validateBridgeOptions` rejects unknown values.

## Configuration reference

| Option | Default | Effect |
|---|---|---|
| `workloadApi.socketPath` | required | Absolute path or `unix://` URI of the SPIRE agent socket |
| `workloadApi.connectTimeoutMs` | `rpcTimeoutMs`, then 10000 | Time for each stream attempt to deliver its first SVID |
| `workloadApi.rpcTimeoutMs` | 10000 | Wait for the first SVID in `getX509Svid()` |
| `workloadApi.reconnect.maxAttempts` | unlimited | Consecutive retries; zero disables recovery |
| `workloadApi.reconnect.initialDelayMs` / `maxDelayMs` | 250 / 5000 | Exponential backoff with equal jitter, never above the cap |
| `validator.allowedCallers` | required | Exact SPIFFE IDs or patterns with an exact trust domain; `*` is one segment, `**` any depth, and a wildcard pattern needs a literal segment |
| `validator.minTtlSeconds` | required | Refuse peers whose SVID expires sooner |
| `validator.federatedTrustDomains` | none | Foreign trust domains to trust through Workload API federated bundles |
| `validator.allowedTrustDomains` | all trusted | Narrows the accepted domains; entries must be local or federated |
| `transport.mode` | required | `mtls-server`, or `stdio-identity-only` (no authentication) |
| `transport.sse.host` / `port` | `127.0.0.1` / required | Listener address |
| `transport.minTlsVersion` | `TLSv1.3` | `TLSv1.2` only for peers that cannot negotiate 1.3 |
| `transport.rotation` | `drain` | `drain` keeps still-valid connections on an update; `close` closes all |
| `transport.maxConnectionAgeMs` | 300000 | Upper bound on a connection's lifetime (1000 to 86400000) |
| `transport.crlScope` | `all-issuers` | CRL enforcement, see below. Experimental |
| `audit.logger` | `StdoutJsonAuditLogger` | Any `AuditLogger`; `FileAuditLogger` for durable local audit |
| `audit.backgroundFailure` | `fail-closed` | What a failed `svid_rotated` audit does |
| `metrics` | none | `BridgeMetrics` hooks |
| `degrade.mode` | `fail-fast` | `warn-and-skip` only for local development |

Every connection also ends at the earlier of the server SVID it was opened
with and the peer's SVID expiry, so no connection outlives its credentials.

## Federation setup

1. Federate the SPIRE servers (bundle endpoints and `federates_with`), and
   create registration entries with `-federatesWith` so the agent delivers the
   foreign bundle to this workload.
2. List the foreign domain in `validator.federatedTrustDomains`.
3. Allow its callers explicitly in `validator.allowedCallers`. A wildcard trust
   domain is rejected.

Each request is bound to its own trust domain: the transport validates the
peer chain against only that domain's anchors, checking validity, CA and
keyCertSign on every certificate, and exploring every candidate path. A
domain whose bundle is missing or withdrawn is not trusted. The
[SPIRE bench](spire-bench.md) runs this setup with real SPIRE servers.

## Revocation

SPIRE 1.16.0 did not deliver CRLs in the bench (`crl` field empty), so CRL
support is experimental. The revocation mechanism in practice is a short SVID
TTL: keep `default_x509_svid_ttl` short and `minTtlSeconds` above zero.

When a Workload API snapshot does carry CRLs:

| `transport.crlScope` | Behavior |
|---|---|
| `all-issuers` (default, fail closed) | OpenSSL checks every issuer of every peer chain. With any CRL present, an issuer without a current CRL fails the handshake, so federated callers are refused unless their domain also publishes CRLs |
| `per-trust-domain` | Checked per request, only for domains that publish a CRL; within such a domain every issuer on the path needs a current CRL. Delta, indirect and critical-extension CRLs are refused, and an unusable CRL refuses every caller |

## Audit sink

`FileAuditLogger({ path, maxQueue, maxUnauthenticatedQueue, unauthenticatedPerSecond, groupCommitMs, retryInitialMs, retryMaxMs })`:

| Topic | Behavior |
|---|---|
| Durability | `log()` resolves only after the batch is written and fsynced. `groupCommitMs` (default 5) adds latency, never loses an acknowledged event |
| File | Opened with `O_NOFOLLOW`; must be a regular file owned by the process user with no group or other permissions. Created with mode 0600 |
| Failure | A failed write or fsync rejects the batch, refuses later authentication requests with 503 and makes `healthy()` and `isReady()` false. The sink reopens automatically with backoff (500 ms doubling to 30 s) |
| Rotation | Rename the file and call `reopen()`, or let the next write reopen the path when it names a new inode |
| Handshake denials | Separate queue (default 64) and rate limit (default 20 per second). Excess is dropped and counted in `stats().droppedUnauthenticated` |
| Background failure | A failed `svid_rotated` write under `fail-closed` stops serving until `bridge.clearAuditFailure()` |

The event format is the [audit event contract](architecture/contracts/audit-event.md).
Shipping the file to central storage is the deployment's job.

## Readiness probe

`bridge.isReady()` is true only when the bridge started, its own SVID is inside
its validity window, the audit sink reports healthy, no background audit
failure is latched and the listener is bound. Expose it on a local port for
the orchestrator:

```ts
import http from 'node:http';

http
  .createServer((_req, res) => {
    res.statusCode = bridge.isReady() ? 200 : 503;
    res.end();
  })
  .listen(9090, '127.0.0.1');
```

Workload API loss makes readiness false; it returns when a fresh SVID arrives.

## Metrics

Pass `metrics: { increment(name, labels), observe(name, value, labels) }`.
Hooks must not throw; errors are ignored.

| Name | Kind | Labels |
|---|---|---|
| `handshake_accepted` | counter | none |
| `handshake_refused` | counter | `reason` |
| `request_authorized` | counter | none |
| `request_refused` | counter | `reason` (lowercase error code) |
| `request_auth_seconds` | histogram | `outcome` |
| `audit_dropped` | counter | `channel` |
| `svid_rotated` | counter | none |
| `workload_api_reconnect` | counter | none |

## Supported runtime

Node.js 26 or newer (`engines.node >=26`) is a deliberate support decision of
the maintainer. Older Node.js lines are not supported.
