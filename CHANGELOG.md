# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

`package.json` is still 0.0.1. The section below describes the API intended for
the first tagged release; the version number of that release is the
maintainer's decision.

### API stability for the first release

- Stable within the first minor line: `createMcpSpiffeBridge`, `BridgeOptions`
  and its nested option types, `getCallerIdentity`, `getCallContext`, the error
  classes and their `code` values, the `SpiffeAuditEvent` contract
  (`schema_version` 1), the `AuditLogger`, `SvidFetcher`, `SvidValidator` and
  `BridgeMetrics` interfaces, `FileAuditLogger`, `isReady()` and
  `clearAuditFailure()`.
- May change in later 0.x minor releases: `McpSpiffeBridgeImpl` internals,
  `MtlsTransportServer` constructor options, experimental CRL support and
  `stdio-identity-only` mode.
- Breaking changes before 1.0 bump the minor version and are listed here.

### Added

- SPIRE Workload API fetcher with validity checks, refusal of invalid or
  expired snapshots, and reconnect without limit by default (capped backoff
  with equal jitter).
- mTLS listener that requires client certificates, rotates its TLS context
  without restart, binds every peer chain to its own trust domain and drains
  connections that stay valid (`transport.rotation`, default `drain`).
- `transport.maxConnectionAgeMs`, replacing the fixed five-minute cap.
- Opt-in federation through `validator.federatedTrustDomains`.
- Experimental CRL enforcement with `transport.crlScope`: `all-issuers`
  (default) or `per-trust-domain`.
- SPIFFE validator for SAN, trust domain, validity window, minimum TTL and
  caller allowlist with `*` and `**` patterns; `isValidCallerMatcher`.
- Request-local caller identity through `getCallerIdentity`.
- Structured audit events with `schema_version`, and the
  [audit event contract](docs/architecture/contracts/audit-event.md).
- `FileAuditLogger`: group commit with fsync, bounded queue, separate
  rate-limited channel for handshake denials, automatic reopen with backoff,
  `reopen()`, `healthy()` and `stats()`. `AuditDeliveryError`
  (`AUDIT_DELIVERY_FAILED`). Optional `AuditLogger.close()`,
  `logUnauthenticated()` and `healthy()`.
- `audit.backgroundFailure` (`fail-closed` default, or `report`) for rotation
  audit failures.
- `isReady()` on the bridge and the listener, covering own SVID validity and
  audit sink health; `clearAuditFailure()`.
- `BridgeMetrics` hooks for handshakes, refusals, audit drops, rotation,
  reconnects and request authentication time.
- `transport.minTlsVersion` to opt in to TLS 1.2.
- `pnpm run check:package` tarball verification in CI, `publishConfig` with
  provenance and an inactive two-job release workflow.
- MCP SDK Streamable HTTP integration tests, and a real two-domain SPIRE
  federation bench (`pnpm run bench:spire`).
- Installed package demo, CI workflow, gitleaks rules, lefthook pre-commit
  config, NOTICE, SECURITY, CONTRIBUTING and repository templates.

### Changed

- The listener binds `127.0.0.1` by default instead of all interfaces.
- TLS 1.3 is the default minimum version.
- `validateBridgeOptions` returns frozen parsed options without unknown keys.
- Denied callers receive a generic `unauthorized` body.
- Node.js 26 or newer only, a deliberate support decision; pnpm 12.
- MCP SDK peer range is `>=1.32.0 <2.0.0`, the tested range, and optional.
- Federated bundle keys are normalized from `spiffe://td` to `td`.
- `SvidValidator.validate` takes an optional issuer chain and binds the chain
  whenever one is supplied.
- `workloadApi.reconnect.maxAttempts` is optional and no longer capped at 100.
- A request whose validation crossed a credential update gets 503.

### Fixed

- CommonJS consumers get CommonJS declarations (`.d.cts` tree) instead of
  TS1479 errors.
- `biome.json` migrated to the Biome 2.6 schema.
- A synchronous logger throw during rotation is no longer lost.

### Security

- Chain binding runs in the transport for every request, against only the
  claimed trust domain's anchors, with validity, CA and keyCertSign checks on
  every certificate. This closes a path where an expired local intermediate
  re-certified by a federated CA authenticated a local SPIFFE ID, and a path
  where a validator without `federatedTrustDomains` skipped the binding.
- Caller matchers require an exact trust domain and a literal path segment.
- Handshake denials can no longer fill the authenticated audit queue.
- The audit file refuses symlinks, other owners and group or other access, and
  follows the path when it names a new inode.
- The release workflow publishes the checked tarball from a job that holds
  `id-token` and runs no build.
- Without `federatedTrustDomains`, only the local trust domain is accepted.
  Foreign `allowedTrustDomains` entries that are not federated fail at startup.
- A failed authentication audit write refuses the request with 503.
