# Credential recovery and TLS lifecycle

The bridge never serves cached credentials during failure. The SPIFFE Workload
API delivers complete snapshots, not incremental additions. Stream loss, an
empty or invalid snapshot, or a malformed CRL invalidates the cached credential
immediately. Requests are denied, active connections are closed and
`isReady()` turns false. A later stream must deliver fresh valid material
before the transport accepts requests again. No cached-credential grace period
exists.

## Recovery

`workloadApi.reconnect` accepts `maxAttempts` (default unlimited),
`initialDelayMs` (default 250) and `maxDelayMs` (default 5000). Delays grow
exponentially with equal jitter and never exceed the cap; a valid response
resets the backoff. Each attempt must deliver its first response within
`connectTimeoutMs`, falling back to `rpcTimeoutMs` and then 10000 ms. `close()`
aborts the RPC and any pending backoff. With an explicit `maxAttempts`, an
exhausted budget is terminal: create a new fetcher or bridge. Startup failure
closes the bridge and requires a new instance.

The fetcher rejects expired or not-yet-valid credentials, a key that does not
match the leaf, mismatched or multiple URI SANs, empty trust bundles and
malformed CRLs. The Workload API socket and its workload attestation remain the
credential source's trust boundary.

## Revocation lists

SPIRE 1.16.0 sent no CRLs in the [SPIRE bench](spire-bench.md); CRL support is
experimental and short SVID lifetimes are the practical revocation mechanism.
When a snapshot carries CRLs, `transport.crlScope` decides how they apply.

| Case | `all-issuers` (default) | `per-trust-domain` |
|---|---|---|
| Peer serial listed in its issuer's CRL | Handshake fails, `TLS certificate revoked` audited | 401, `certificate revoked` audited |
| CRL past `nextUpdate` | Handshake fails | 401 |
| An issuer on the path has no CRL while its domain publishes CRLs | Handshake fails | 401 |
| A federated domain publishes no CRLs while the local one does | Handshake fails | Not checked |
| CRL with a critical extension (delta, indirect, distribution point) | Interpreted by OpenSSL | Every caller refused |
| Snapshot carries no CRLs | No revocation check | No revocation check |

## Connections and trust roots

Deploy a root overlap snapshot (A+B), rotate leaves to B, then remove A. With
`transport.rotation: 'drain'` (default), an update closes pending handshakes
and keeps an established connection only while its peer chain is still valid
against the new bundles and the snapshot carries no CRLs. With `close`, every
update closes every connection, as before. An invalid context closes all
connections and keeps the transport unavailable until a later successful
update. A request whose validation crossed an update gets 503 and never reaches
the handler.

A connection ends at the earlier of the server SVID it was opened with, the
peer's SVID expiry and `transport.maxConnectionAgeMs` (default five minutes).
Session tickets are disabled, no session ID cache is installed, and a resumed
connection is refused defensively. Clients must establish a fresh handshake and
retry interrupted streams according to their application protocol. Closing a
connection cannot roll back a handler side effect that already began.

Custom `SvidFetcher` implementations should provide `watchAvailability` for
immediate connection closure on credential loss. Without this optional callback,
request checks and certificate and connection deadlines still apply.

## Audit delivery

Authentication decisions are awaited: a failed audit write answers the request
with 503 instead of serving it unaudited. Handshake denials come from
unauthenticated peers, so they use a separate, rate-limited channel whose drops
are counted. A failed `svid_rotated` write follows `audit.backgroundFailure`
(default `fail-closed`). `FileAuditLogger` details are in
[operations](operations.md#audit-sink) and the event format in the
[audit event contract](architecture/contracts/audit-event.md).

## Federation

Off by default: only the local trust domain is trusted. To trust another SPIRE
trust domain, list it in `validator.federatedTrustDomains` and add its callers
to `allowedCallers`.

| Rule | Effect |
|---|---|
| Bundle source | Workload API federated bundles, keyed `spiffe://td` or `td` |
| TLS trust store | Local bundle plus bundles of listed domains that the agent currently supplies |
| Chain binding | The transport validates each peer chain against only the anchors of the trust domain in the peer's SPIFFE ID, checking validity, CA and keyCertSign on every certificate and exploring every candidate path. It does not rely on the path OpenSSL chose or on the validator's options |
| Missing bundle | Peers from that domain fail the TLS handshake |
| Withdrawn bundle | Removed at the next update; connections from that domain close |
| `allowedTrustDomains` | Narrows the accepted set; each entry must be local or federated, otherwise `start()` fails |
| Local domain in `federatedTrustDomains` | `start()` fails with `ConfigInvalidError` |

## Local evidence

The unit suite covers bounded and unlimited recovery, cancellation,
first-response timeout, invalid updates and real TLS connections: root overlap
and removal under TLS 1.3 and opt-in TLS 1.2, drain and close rotation,
maximum connection age, certificate expiry, invalid TLS material, a request
held in validation across an update, cross-domain path attacks and CRL scopes
with OpenSSL-generated CRLs. The [SPIRE bench](spire-bench.md) repeats the
federation, rotation and credential-loss cases with real SPIRE servers and
agents.

The recovery fixture also uses the installed `spiffe` gRPC client against a
local HTTP/2 Unix socket endpoint: dropping the transport denies cached reads,
a new RPC alone does not restore service, and a fresh response restores it.

References: [SPIFFE Workload API](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md)
and [Node TLS API](https://nodejs.org/api/tls.html).
