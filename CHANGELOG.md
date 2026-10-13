# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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

### Security

- Federation configuration is rejected at startup, and the validator accepts
  only the local trust domain.
