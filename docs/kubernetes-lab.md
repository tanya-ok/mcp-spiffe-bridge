# Kubernetes and FHIR integration

The sibling `mcp-svid-auth` project owns the shared local lab. It runs k3s
Kubernetes with containerd in a dedicated CNCF Lima VM, with SPIRE projected-token
node attestation and namespace/ServiceAccount workload registration. The sibling
`hipaa-fhir-mcp` service loads this library into its Streamable HTTP gateway.
ECS is excluded; this bridge is a library, not another background daemon.

The gateway calls `createMcpSpiffeBridge`, registers an authorized handler and
attaches `StreamableHTTPServerTransport` inside that handler. The validated peer
remains available through `getCallerIdentity` across awaited operations. The
FHIR factory uses that trusted context for each invocation rather than a client
header or mutable shared configuration. The gateway also checks a resource-bound
OAuth token from the authorization project. Its FHIR adapter is explicitly an
offline synthetic fixture.

The listener binds `127.0.0.1` when `transport.sse.host` is omitted. The lab
gateway sets `host: "0.0.0.0"` explicitly because it runs alone in a pod network
namespace and is reached through a cluster Service. Use `0.0.0.0` only in that
kind of isolated pod; on a shared host keep the loopback default or bind a
specific interface.

Run `make demo` from the sibling authorization project with all three repositories
checked out side by side. The dedicated VM has 2 CPUs and 4 GiB memory. Services
and runtime data are removed with `make down`; `make runtime-stop` releases the
VM's compute resources. The lab does not use or stop other projects' containers.

## Credential and transport lifecycle

`WorkloadApiSvidFetcher` rejects cached credentials outside their validity window,
an ended stream, a failed stream and empty/invalid updates. A bridge startup
failure closes its resources and is terminal for that instance. Create a new
bridge after failed startup or stop. Concurrent `start` calls share the same
startup task. The application decides when to replace a failed instance; the
Kubernetes gateway currently exits and lets Kubernetes restart it after stream loss.
The library can recover without restarting when its host keeps it alive; see the
[recovery and rotation policy](credential-lifecycle.md).

The mTLS server requires a client certificate and a verified chain, then applies
the SPIFFE caller allowlist and validity checks on every HTTP request. Its own
credential must still be available before dispatch. TLS rotation updates the
context for new connections and closes existing connections, including open
streams and pending handshakes. Every connection also ends at the earlier of
either certificate expiry or five minutes. Requests whose validation crosses a
credential update cannot reach the handler. Listener failures unsubscribe rotation watchers, handler rejection
returns a fixed 503 without exception text, and shutdown closes active HTTP
connections. The minimum TLS version is 1.3 by default; set
`transport.minTlsVersion: 'TLSv1.2'` only for peers that cannot negotiate 1.3.
Request and header deadlines are bounded.

## Evidence

The local tests include real TLS sockets with runtime-generated CA and workload
certificates: allowed caller/context, missing certificate, foreign CA, disallowed
SPIFFE ID, missing own credential, throwing handler and busy listener cleanup.
Fetcher tests cover ended streams, expiry, rotation, timeout and terminal failed
startup. The shared integration additionally exercises real SPIRE credentials,
the official TypeScript MCP SDK and the FHIR tools in Kubernetes.

This remains a prototype. Bounded stream reconnection and strict connection
revocation are implemented and locally tested. Production operational policy and
durable audit delivery remain outside the demonstrated scope.

## Runtime convention

The library and installed-package TLS demo run directly in Node.js. The shared
integration uses Lima, Kubernetes and containerd. Buildah builds OCI images; no
Docker or Podman daemon is required. The authorization repository owns lab
lifecycle; the library does not start, stop or delete the VM.
