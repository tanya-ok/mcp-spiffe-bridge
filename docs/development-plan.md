# Development plan for mcp-spiffe-bridge

Updated on 2026-10-06. The decision milestone now has a real consumer: the shared FHIR gateway uses this library with the official MCP SDK and actual SPIRE credentials in Lima/Kubernetes/containerd. Keep the component a small transport library, with the sibling authorization project owning orchestration and the FHIR project owning its domain tools.

## Current integration and remaining work

Local commit `2cbf610` added TLS transport and lifecycle tests, credential expiry/stream-loss refusal and request-local verified caller context. The local gate was freshly rerun on 2026-10-06: 56 tests, typecheck, lint and build passed, with nine pre-existing lint warnings. The shared eighteen-scenario integration and teardown were also freshly rerun that day, including allowed, disallowed and absent client certificates and audited FHIR calls. See the [integration and lifecycle guide](kubernetes-lab.md).

The gateway exits after credential-stream loss and Kubernetes restarts it. Automatic stream reconnect within a bridge instance is still unimplemented. Trust-root overlap/removal, existing-connection revocation and independent audit delivery need explicitly bounded tests before broader production claims.

A future human login provider identifies the user; this library continues to authenticate the acting workload. Do not infer human roles or clinical consent from a SPIFFE allowlist. Keep user authorization and token verification in the consuming gateway. ECS remains outside this lab. The [shared plan](https://github.com/tanya-ok/mcp-svid-auth/blob/main/docs/portfolio-development-plan.md) defines the optional human identity increment and its acceptance gates.

## Historical review on 2026-10-04

The following snapshot was recorded against local commit `600d875`, before the integration milestone. Its descriptions of absent tests and an unverified build are historical, not the current status.

## What exists and what remains unverified

The source includes a Workload API stream, certificate identity checks, allowlists, TLS context rotation, and request context. `examples/basic/server.ts` responds with the authenticated identity; its MCP wiring is a placeholder. At that time the README referred to architecture and deployment documents that did not exist.

Tests cover configuration, SPIFFE ids, the identity validator, the mocked fetcher, and audit event builders. There are no transport or bridge lifecycle test files. An offline frozen installation failed because `@protobufjs/base64` was missing from the local package store. Tests, typecheck, lint, and build were not executed in this review.

[agentgateway](https://agentgateway.dev/docs/kubernetes/latest/reference/api/) already documents SPIFFE Workload API integration. [SPIFFE guidance](https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/) describes the different replay properties of JWT and X.509 credentials. The useful potential niche here is a compact TypeScript integration where applications directly terminate mTLS and need verified caller context. Demand for that niche remains a hypothesis.

## One week decision milestone

| Priority | Proposed work | Acceptance criterion |
|---|---|---|
| P0 | Attach a real Streamable HTTP MCP server | An independent client initializes, lists tools, and calls a tool under mTLS; absent, untrusted, expired, and disallowed peer credentials never reach the handler |
| P0 | Specify fetcher failure and expiry behavior | A stream ending or failing after the first SVID updates health; expired cached credentials cannot be returned as current; reconnect has bounded backoff and explicit stop semantics |
| P0 | Repair lifecycle behavior | Failed `start()` does not leave the object marked started; retry, shutdown, listener errors, and handler exceptions release resources and produce safe outcomes |
| P1 | Prove TLS and bundle rotation | New sessions use new credentials and trust roots; removed roots cannot authenticate new peers; long-running sessions have a documented expiry and revocation policy |
| P1 | Clarify validation boundaries | Direct identity validation cannot be mistaken for certificate-chain verification; test the TLS boundary, SAN constraints, and allowed trust domains together |
| P1 | Supply runnable documentation | Replace missing document links with an actual quickstart, supported versions, expected denials, and an offline testing path |

Use the [current MCP Streamable HTTP specification](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http). Keep authentication and per-tool authorization separate. Matching a SPIFFE allowlist is not sufficient evidence of an application's tool permissions, and direct mTLS is not a claim of compatibility with every OAuth-only MCP host.

Timebox the milestone to approximately five focused days. Continue only if one real synthetic MCP consumer benefits from the adapter and its lifecycle contract is testable. Otherwise pause feature expansion and retain the component as an explicit experimental reference. Do not merge its code into the Python project merely to reduce repository count; the transport models and language consumers differ.

## Changes to avoid in the first milestone

Defer ECS setup, federation expansion, multiple transport modes, a policy language, and a management UI. First decide whether direct application mTLS provides an advantage over placing the same application behind an existing gateway. Tighten the unbounded MCP peer dependency only after testing the supported SDK range.

The FHIR prototype should not depend on this package until real MCP transport and failure handling pass. A stdio child cannot infer the host's cryptographically verified identity simply from an environment variable or its own SVID.

When dependencies are available, run typecheck, tests, lint, and build, then test the actual TLS transport against synthetic certificates. Add lifecycle and request-context isolation tests that exercise behavior rather than merely reproduce implementation details. Never use real keys, tokens, or private trust domains in committed fixtures.

## Task tracking checkpoint

The [2026-10-07 portfolio checkpoint](https://github.com/tanya-ok/mcp-svid-auth/blob/main/docs/portfolio-checkpoint-2026-10-07.md) reconciles this plan with local beads tasks. Use `bd --sandbox ready` before starting work and update task status and validation evidence as work progresses. Public task snapshots are in `.beads/issues.jsonl`; local databases stay untracked. Remote synchronization is disabled.
