# SPIRE federation bench

A scripted, repeatable integration test with real SPIRE servers and agents for
two federated trust domains. It is not part of `pnpm test`.

## Topology

| Component | Trust domain `example.org` | Trust domain `partner.example.net` |
|---|---|---|
| SPIRE server | `spire-server-a`, upstream root A (disk), `default_x509_svid_ttl` 1m | `spire-server-b`, upstream root B (disk), same TTL |
| Federation | `https_spiffe` bundle endpoint, bundles bootstrapped with `bundle set` | same, towards A |
| Agent | `agent-a`, join token, unix workload attestor | `agent-b`, same |
| Workloads | uid 1000 `spiffe://example.org/mcp/server` (the bridge), uid 1001 `spiffe://example.org/agent/research` | uid 1000 `spiffe://partner.example.net/agent/billing`, uid 1001 `spiffe://partner.example.net/agent/intruder` |

All entries use `-federatesWith`, so the Workload API delivers the other
domain's bundle. The bridge runs from the packed tarball with
`WorkloadApiSvidFetcher`, `FileAuditLogger` and metrics hooks on port 8443. Two
more listeners share its fetcher: 8444 with a federated transport but a
validator without `federatedTrustDomains`, and 8445 without federation. Callers
verify the server with its domain's bundle; TLS verification stays on. Roots,
keys and forged certificates are synthetic and generated per run.

## Run

Requires Lima, Node 26, pnpm, OpenSSL and network access for image pulls inside
the VM. Create the VM once, run the bench, stop the VM:

```sh
limactl create --name bridge-fed-lab --cpus 2 --memory 4 --disk 12 --tty=false template://docker
limactl start bridge-fed-lab
pnpm run bench:spire
limactl stop bridge-fed-lab
```

`deploy/spire-lab/bench.sh` builds and packs the library, generates roots and
forged material (`forge.mjs`), copies the stage into the VM, runs
`run-in-vm.sh` with Docker Compose, removes the containers and volumes, and
checks `work/results.jsonl` with `assert.mjs`. It exits nonzero on any failed
check. It uses only the VM named by `BRIDGE_LAB_VM` (default `bridge-fed-lab`).

## Checks

| Scenario | Expected |
|---|---|
| Local caller | 200, caller identity in context |
| Allowlisted federated caller | 200 |
| Federated caller not on the allowlist | 401 `SPIFFE_ID_DISALLOWED` |
| Federated domain not configured (port 8445) | TLS refused |
| Root B signs a leaf with a local SPIFFE ID (ports 8443 and 8444) | 401 `TRUST_DOMAIN_MISMATCH` |
| Expired local intermediate re-certified by root B (ports 8443 and 8444) | 401 `TRUST_DOMAIN_MISMATCH` |
| Stream across SVID rotation (drain) | Stream continues through rotation and ends no later than the expiry of the server SVID it was opened with |
| New request after rotation | 200 |
| Agent A stopped | `isReady()` false, requests refused |
| Agent A restarted | `isReady()` true again through reconnect, request 200 |
| Audit | Four chain-binding denials recorded; file mode 0600 |
| Workload API | Federated bundle delivered; CRL count recorded |

## Result - 2026-11-26

Revision `288c092` on `feat/production-readiness`. 18 of 18 checks passed.

| Component | Version |
|---|---|
| SPIRE server and agent | 1.16.0, digests pinned in `deploy/spire-lab/compose.yaml` |
| Runner image | `node:26-bookworm-slim`, digest pinned in `runner/Dockerfile`, Node v26.13.1 |
| Docker in VM | 29.10.1, Compose 5.8.0 |
| Lima | 2.2.1, `template://docker`, aarch64, 2 CPUs, 4 GiB |
| Host | Node v26.10.0, OpenSSL 4.1.0 |

Observations:

- SVIDs arrived as `[leaf, SPIRE intermediate]`, chaining to the upstream root.
- The SPIRE 1.16.0 Workload API returned an empty `crl` field on both sides.
  The CRL code paths are therefore tested only with CRLs injected through the
  fetcher seam (unit tests with OpenSSL-generated CRLs), not with SPIRE CRLs.
- The stream stayed open through three Workload API updates (`svid_rotated` 3) and closed after 55.4 s,
  at the expiry of the server SVID used for its handshake.
- Stopping agent A made `isReady()` false within seconds; after restart the
  fetcher reconnected (`workload_api_reconnect` 3) and served again.
- Not exercised here: CRL delivery by SPIRE, Kubernetes attestation, and the
  MCP SDK (covered by `tests/mcp-sdk.test.ts`).
