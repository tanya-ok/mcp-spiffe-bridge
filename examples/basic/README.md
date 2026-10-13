# basic example

Minimal MCP server protected by SPIFFE mTLS.

## Run with a real SPIRE agent

1. Start a SPIRE server + agent (see `docs/kubernetes-lab.md`).
2. Register a workload entry for your own process, e.g.
   `spiffe://example.org/servers/mcp-basic`.
3. Register at least one client entry under
   `spiffe://example.org/clients/*`, the matcher used in `server.ts`.
4. Export `SPIFFE_ENDPOINT_SOCKET=unix:///run/spire/sockets/agent.sock`.
5. Run the server:

   ```fish
   pnpm tsx examples/basic/server.ts
   ```

6. Call it with a curl that presents a client SVID:

   ```fish
   # Fetch a client SVID manually via the workload API CLI, or have your
   # client use mcp-spiffe-bridge on the caller side (future release).
   curl --cacert bundle.pem --cert client.pem --key client.key \
        https://localhost:8443/
   ```

## Run without SPIRE (offline dev)

Uncomment the `degrade` block in `server.ts`:

```ts
degrade: { mode: 'warn-and-skip' },
```

The bridge logs a warning, does NOT start the TLS listener, and the process
stays up so you can iterate on the handler shape. Production deployments
must leave `degrade` unset (or set it to `fail-fast`).
