# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### API stability for 0.1.0

- Stable within 0.1.x: `createMcpSpiffeBridge`, `BridgeOptions` and its
  nested option types, `getCallerIdentity`, `getCallContext`, the error
  classes and their `code` values, `SpiffeAuditEvent` field names, the
  `AuditLogger`, `SvidFetcher` and `SvidValidator` interfaces,
  `FileAuditLogger` and `isReady()`.
- May change in 0.x minor releases: `McpSpiffeBridgeImpl` internals,
  `MtlsTransportServer` constructor options, and `stdio-identity-only` mode.
- Breaking changes before 1.0 bump the minor version and are listed here.

### Added

- Opt-in federation through `validator.federatedTrustDomains`, with each peer
  chain bound to the bundle of its own trust domain.
- CRL enforcement for Workload API snapshots that carry CRLs, and audited
  revocation denials.
- `FileAuditLogger`: fsync per event, bounded queue, explicit fail-closed
  failure mode and `reopen()` for rotation. `AuditDeliveryError`
  (`AUDIT_DELIVERY_FAILED`).
- Optional `AuditLogger.close()`, awaited by `bridge.stop()`.
- `isReady()` on the bridge and the mTLS listener.
- `pnpm run check:package` tarball verification in CI, `publishConfig` with
  provenance and an inactive release workflow.
- MCP SDK Streamable HTTP integration tests behind the mTLS listener.

- SPIRE Workload API fetcher with bounded reconnect, validity checks and
  refusal of invalid, expired or CRL-carrying snapshots.
- mTLS listener that requires client certificates, rotates its TLS context
  without restart and closes existing connections on credential changes.
- SPIFFE validator for SAN, trust domain, validity window, minimum TTL and
  caller allowlist with `*` and `**` patterns.
- Request-local caller identity through `getCallerIdentity`.
- Structured audit events for authentication, tool calls and rotation.
- `transport.minTlsVersion` to opt in to TLS 1.2.
- Installed package demo, CI workflow, gitleaks rules, lefthook pre-commit
  config, NOTICE, SECURITY, CONTRIBUTING and repository templates.

### Changed

- The listener binds `127.0.0.1` by default instead of all interfaces.
- TLS 1.3 is the default minimum version.
- `validateBridgeOptions` returns frozen parsed options without unknown keys.
- Denied callers receive a generic `unauthorized` body.
- Node.js 26, pnpm 12 and an MCP SDK peer range bounded to major 1.
- MCP SDK peer range is `>=1.32.0 <2.0.0`, the tested range, and optional.
- Workload API snapshots with CRLs are enforced instead of refused.
- Federated bundle keys are normalized from `spiffe://td` to `td`.
- `SvidValidator.validate` takes an optional issuer chain.

### Fixed

- CommonJS consumers get CommonJS declarations (`.d.cts` tree) instead of
  TS1479 errors.
- `biome.json` migrated to the Biome 2.6 schema.

### Security

- Without `federatedTrustDomains`, only the local trust domain is accepted.
  Foreign `allowedTrustDomains` entries that are not federated fail at startup.
- A failed authentication audit write refuses the request with 503.
