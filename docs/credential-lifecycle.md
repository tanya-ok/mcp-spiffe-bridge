# Credential recovery and TLS lifecycle

The bridge never serves cached credentials during failure. The SPIFFE Workload API delivers
complete snapshots, not incremental additions. Stream loss, an empty or invalid
snapshot, or a malformed CRL invalidates the cached credential immediately.
Requests are denied and active transport connections are closed. A later stream
must deliver fresh valid material before the transport accepts requests again.
No cached-credential grace period exists.

## Recovery budget

`workloadApi.reconnect` accepts `maxAttempts` (default 5), `initialDelayMs`
(default 250) and `maxDelayMs` (default 5000). `maxAttempts` counts retries after
the initial RPC; zero disables retries. Exponential delay is capped, without
jitter. A valid response resets the consecutive failure budget. Each attempt
must deliver its first response within `connectTimeoutMs`, falling back to
`rpcTimeoutMs` and then 10000 ms. `close()` aborts the RPC and any pending backoff.
After exhaustion, create a new fetcher or bridge instance. Startup failure still
closes the bridge and requires a new instance; recovery applies to a running
host that keeps the bridge alive. The Kubernetes gateway currently chooses
process restart instead.

The fetcher rejects expired/not-yet-valid credentials, a key that does not match
the leaf, mismatched or multiple URI SANs, empty trust bundles and malformed
CRLs. The Workload API socket and its workload attestation remain the credential
source's trust boundary. `bridge.isReady()` is false whenever the cached
credential is unusable, including after the recovery budget is spent.

## Revocation lists

CRLs from a snapshot are loaded into the listener's TLS context with the next
credential update. OpenSSL then checks revocation for every certificate in a
peer chain:

| Case | Result |
|---|---|
| Peer serial listed in its issuer's CRL | Handshake fails, `TLS certificate revoked` audited |
| CRL past `nextUpdate` | Handshake fails |
| An issuer in the chain has no CRL while other CRLs are present | Handshake fails |
| Snapshot carries no CRLs | No revocation check |

A rotation that adds or replaces CRLs closes existing connections like any other
update.

## Connections and trust roots

Deploy a root overlap snapshot (A+B), rotate leaves to B, then remove A. Every
credential or bundle notification closes all existing TCP connections, including
pending TLS handshakes and HTTP streams, before updating the TLS context. This
also happens for identical snapshots. An invalid context keeps the transport
unavailable until a later successful update. New requests are checked against
the current credential state; a request waiting for validation or audit cannot
enter the handler if the credential generation changed meanwhile.

A connection ends at the earlier of its own leaf expiry, its peer leaf expiry
and five minutes after the handshake. Session tickets are disabled, no session
ID cache is installed, and a resumed connection is refused defensively. TLS
options are reapplied when replacing the context. Clients must establish a fresh
handshake and retry interrupted streams according to their application protocol.
Closing a connection cannot roll back a handler side effect that already began.

Custom `SvidFetcher` implementations should provide `watchAvailability` for
immediate connection closure on credential loss. Without this optional callback,
request checks and certificate/session deadlines still apply, but immediate
stream-loss notification is unavailable.

## Audit delivery

`FileAuditLogger` appends one JSON line per event and calls fsync before `log()`
resolves. The listener awaits authentication audit events, so a full queue, a
failed write or a failed fsync answers the request with 503 instead of serving
it unaudited. The sink then stays failed until `reopen()` succeeds. TLS
handshake denials and rotation events happen outside a request; their audit is
best effort and failures are reported on stderr. Shipping the file to central
storage is the deployment's responsibility.

## Federation

Off by default: only the local trust domain is trusted. To trust another SPIRE
trust domain, list it in `validator.federatedTrustDomains` and add its callers to
`allowedCallers`.

| Rule | Effect |
|---|---|
| Bundle source | Workload API federated bundles, keyed `spiffe://td` or `td` |
| TLS trust store | Local bundle plus bundles of listed domains that the agent currently supplies |
| Chain binding | The validator requires the peer chain to reach the bundle of the trust domain in the peer's SPIFFE ID, so one domain's CA cannot mint another domain's identities |
| Missing bundle | Peers from that domain fail the TLS handshake |
| Withdrawn bundle | Removed at the next update; existing connections close |
| `allowedTrustDomains` | Narrows the accepted set; each entry must be local or federated, otherwise `start()` fails |
| Local domain in `federatedTrustDomains` | `start()` fails with `ConfigInvalidError` |

## Local evidence

The bridge suite covers bounded recovery, exhausted budgets, cancellation,
first-response timeout, invalid updates and real TLS connections. Rotation
scenarios cover A, overlap A+B, removal of A, the exact newly served leaf,
certificate-specific refusal of A under TLS 1.3 and opt-in TLS 1.2, and
active-stream closure. A default listener refuses TLS 1.2 clients.
Additional tests cover full handshakes with a session-caching client, own/peer
certificate expiry, the five-minute cap, invalid TLS material and a request held
in validation across a credential update. Federation, CRL and audit sink tests use
synthetic CAs and real TLS. These are synthetic local tests, not proof of a
production SPIRE rollout.

The recovery fixture also uses the installed `spiffe` gRPC client against a local
HTTP/2 Unix socket endpoint: dropping the transport denies cached reads, a new
RPC alone does not restore service, and a fresh response restores it. It tests
client behavior without impersonating a real SPIRE agent deployment.

References: [SPIFFE Workload API](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md)
and [Node TLS API](https://nodejs.org/api/tls.html).
