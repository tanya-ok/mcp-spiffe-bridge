# Security Policy

## Reporting a vulnerability

Use GitHub private vulnerability reporting (Security tab, "Report a
vulnerability") once the maintainer has enabled it. Do not open public issues
for security problems.

## Supported versions

Only the latest commit on `main` is supported. Version 0 has no backports.
Node.js 26 or newer is required (`engines.node >=26`), a deliberate support
decision.

## Scope

In scope:

- mTLS listener: client certificate enforcement, TLS context rotation and
  connection closure on credential changes
- SVID validation: SAN parsing, trust domain, validity window, allowlist and
  caller matcher rules
- Per-trust-domain chain binding in the transport (validity, CA and
  keyCertSign on every certificate of every candidate path)
- Workload API fetcher: handling of invalid, expired or missing credentials
- Configuration validation and audit event content
- Federation: per-trust-domain chain binding and bundle withdrawal
- CRL enforcement in both `transport.crlScope` modes (experimental)
- `FileAuditLogger` durability, file checks, rate-limited handshake channel
  and fail-closed behavior; readiness reporting
- The release workflow's separation of build and publish

Out of scope:

- The SPIRE agent, its workload attestation and the Workload API socket
  permissions, which are trust boundaries of the deployment
- Per-tool authorization, user identity and OAuth in consuming applications
- Delivery of audit files to central storage after `FileAuditLogger` writes them

## Secure defaults

- The listener binds `127.0.0.1` when `transport.sse.host` is omitted. Bind
  `0.0.0.0` only inside an isolated pod.
- TLS 1.3 is the minimum unless `transport.minTlsVersion` allows TLS 1.2.
- Denied callers receive a generic `unauthorized` body; the reason is recorded
  only in the audit event.
- Only the local trust domain is trusted unless `federatedTrustDomains` names
  others, and every chain is bound to the claimed domain's anchors.
- Caller matchers need an exact trust domain.
- CRLs, when present, are enforced for every issuer (`all-issuers`).
- Rotation audit failures stop serving (`audit.backgroundFailure: fail-closed`).
- A failed authentication audit write refuses the request.
