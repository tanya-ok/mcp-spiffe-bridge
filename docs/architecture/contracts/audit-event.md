# Audit event contract

Contract for `SpiffeAuditEvent`, shared with consumers such as the sibling
`mcp-svid-auth` project. Source of truth: `src/types.ts` and
`src/audit/logger.ts`. Current version: `schema_version: 1`
(`AUDIT_SCHEMA_VERSION`).

## Decision

Every authentication decision and credential rotation produces exactly one
JSON object with all fields present. The library emits `auth_success`,
`auth_failure` and `svid_rotated`; `tool_call` and the `error` outcome are
reserved in the schema for consumers and are not emitted by the library. Fields
that do not apply are `null`, never omitted. Field names are snake_case.

| Field | Type | Rule |
|---|---|---|
| `schema_version` | integer | `1`. See versioning below |
| `timestamp` | string | ISO 8601 UTC with milliseconds, time of the decision |
| `event_type` | string | `auth_success`, `auth_failure`, `tool_call`, `svid_rotated` |
| `caller_spiffe_id` | string or null | See identifier rules |
| `caller_trust_domain` | string or null | Trust domain part of `caller_spiffe_id`, or null |
| `svid_expires_at` | string or null | ISO 8601 expiry of the caller's SVID (own SVID for `svid_rotated`) |
| `tool_name` | string or null | Set only for `tool_call` |
| `request_id` | string | UUID v4, unique per decision; handshake denials get their own |
| `outcome` | string | `allowed`, `denied`, `error` |
| `denial_reason` | string or null | `<CODE>: <message>` when `outcome` is `denied`, else null |

## Reason vocabulary

`<CODE>` is one of the `AuthError` codes. Consumers may switch on the code;
the message is human-readable and may contain identifiers or timestamps.

| Code | Messages emitted by the library |
|---|---|
| `SVID_INVALID` | `TLS client certificate required`, `TLS certificate revoked`, `TLS certificate verification failed`, `TLS handshake failed` (handshake denials); `failed to parse peer certificate`; `peer certificate has no SPIFFE URI in SAN`; `peer certificate has no valid SPIFFE ID`; `peer certificate SAN contains malformed SPIFFE ID: <value>`; `certificate revoked`, `no current CRL for an issuer in the peer chain`, `unusable CRL in the Workload API snapshot` (`per-trust-domain` CRL scope) |
| `SVID_EXPIRED` | `peer cert expired at <time>`; `peer cert remaining TTL <n>s is below minTtlSeconds <m>s` |
| `SVID_NOT_YET_VALID` | `peer cert not valid until <time>` |
| `TRUST_DOMAIN_MISMATCH` | `trust domain <td> not in allowed set {...}`; `peer chain does not lead to the trust bundle of <td>` |
| `SPIFFE_ID_DISALLOWED` | `SPIFFE ID <id> is not in the allowlist` |

Metrics `reason` labels use the lowercase code for request refusals
(`spiffe_id_disallowed`) and `no_client_certificate`, `certificate_revoked`,
`certificate_untrusted` or `handshake_failed` for handshake refusals.

## Identifier rules

- `caller_spiffe_id` on `auth_success` and `tool_call` is a parsed, validated
  SPIFFE ID from the peer's single URI SAN.
- On `auth_failure` it is the value the peer presented, or null when none could
  be read (all handshake denials). It is attacker-controlled: do not use it for
  authorization, and escape it before display.
- `caller_trust_domain` is derived from `caller_spiffe_id` text only.
- No certificate bytes, keys, tokens or request bodies are ever included.

## Versioning

- Adding a field does not change `schema_version`; consumers must ignore
  unknown fields.
- Removing or renaming a field, changing its type, or changing the meaning of
  an `event_type`, `outcome` or code increments `schema_version`.
- New messages within an existing code do not change the version. New codes do.
- Events without `schema_version` come from releases before this contract and
  are equivalent to version 1 without that field.

## Delivery

- Authentication decisions are awaited: a failed write refuses the request
  with 503.
- Handshake denials use a separate, rate-limited channel and may be dropped;
  drops are counted (`audit_dropped` metric, `stats()`), never silent.
- `svid_rotated` follows `audit.backgroundFailure` (default `fail-closed`).
