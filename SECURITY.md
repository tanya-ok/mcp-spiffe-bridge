# Security Policy

## Reporting a vulnerability

This repository is not published yet. Once it is published on GitHub, use
private vulnerability reporting (Security tab, "Report a vulnerability").
Do not open public issues for security problems.

## Supported versions

Only the latest commit on `main` is supported. Version 0 has no backports.

## Scope

In scope:

- mTLS listener: client certificate enforcement, TLS context rotation and
  connection closure on credential changes
- SVID validation: SAN parsing, trust domain, validity window, allowlist
- Workload API fetcher: handling of invalid, expired or missing credentials
- Configuration validation and audit event content

Out of scope:

- The SPIRE agent, its workload attestation and the Workload API socket
  permissions, which are trust boundaries of the deployment
- Per-tool authorization, user identity and OAuth in consuming applications
- Federation, which is unsupported and rejected at startup

## Secure defaults

- The listener binds `127.0.0.1` when `transport.sse.host` is omitted. Bind
  `0.0.0.0` only inside an isolated pod.
- TLS 1.3 is the minimum unless `transport.minTlsVersion` allows TLS 1.2.
- Denied callers receive a generic `unauthorized` body; the reason is recorded
  only in the audit event.
- Only the local trust domain is trusted.
