# Production readiness

Gaps between the library and a dependency a team can run in production, as of
2026-11-26 on branch `feat/production-readiness`. "Closed" means implemented and
pinned by tests in this repository. It does not mean released.

## Summary

| State | Count |
|---|---|
| Closed in code, tested | 9 |
| Ready, needs the maintainer to run | 2 |
| Open, needs the maintainer, infrastructure or a decision | 6 |
| Boundaries by design | 2 |

The library is not declared production-ready until every open row is closed.

## Gap table

Severity: High blocks production use, Medium weakens operation or adoption, Low
is polish. Needs: Code means no account, infrastructure or decision is required.

| # | Gap | Severity | Needs | State | Evidence or plan |
|---|---|---|---|---|---|
| 1 | Federation unsupported | High | Code | Closed | `validator.federatedTrustDomains` opt-in. Federated bundles join the TLS store only while supplied, each peer chain must reach the bundle of its own trust domain, and callers still need an allowlist entry. `tests/federation.test.ts` |
| 2 | CRL snapshots refused | Medium | Code | Closed | CRLs load into the TLS context. Revoked peers, expired CRLs and issuers without a CRL fail the handshake, and revocation denials are audited. `tests/crl.test.ts` |
| 3 | Audit to stdout only, no durable delivery | High | Code | Closed | `FileAuditLogger`: fsync before `log()` resolves, mode 0600, bounded queue, sticky failure until `reopen()`. A rejected authentication audit refuses the request with 503. `tests/file-sink.test.ts`, `tests/mtls.test.ts` |
| 4 | MCP SDK range unbounded and untested | Medium | Code | Closed | Peer `>=1.32.0 <2.0.0`, optional because the library does not import the SDK. A real SDK client and server run behind the listener. `tests/mcp-sdk.test.ts` |
| 5 | CommonJS type declarations failed with TS1479 | High | Code | Closed | Build writes a `.d.cts` tree. `pnpm run check:package` type checks CJS and ESM consumers |
| 6 | Tarball contents unverified | Medium | Code | Closed | `check:package` enforces a file allowlist, secret patterns, export targets and runtime `require` and `import`. CI runs it |
| 7 | No readiness signal | Medium | Code | Closed | `bridge.isReady()` and `MtlsTransportServer.isReady()` turn false on credential loss, failed rotation and stop |
| 8 | Biome configuration broke `biome ci` after the 2.6 bump | Medium | Code | Closed | Migrated `biome.json` |
| 9 | Lint warnings recorded on 2026-10-06 | Low | Code | Closed | `biome ci .` reports no warnings |
| 10 | Provenance | Medium | Maintainer | Ready | `publishConfig.provenance` and `.github/workflows/release.yml`, not run. Needs npm trusted publishing for this repository and an `npm` environment with required reviewers |
| 11 | Remote CI on this branch | Medium | Maintainer | Ready | Local checks pass. Needs a push and pull request to run `ci.yml`, including `check:package` |
| 12 | Not published to npm | High | Maintainer | Open | Needs npm account, package name ownership and a tagged release through the release workflow |
| 13 | Version 0 | Medium | Decision | Open | Stability notes for 0.1.0 are in `CHANGELOG.md`. Bumping the version and tagging is a release decision |
| 14 | Shared SPIRE lab not rerun for federation and CRLs | Medium | Infrastructure | Open | Run the lab with two federated SPIRE trust domains. Confirm whether the deployed SPIRE agent ever sends CRLs; that was not verified |
| 15 | Independent security review | High | Decision | Open | Review federation chain binding, CRL semantics and audit failure policy before a production claim |
| 16 | Handshake denial and rotation audit are best effort | Low | Decision | Open | These events happen outside a request, so there is nothing to refuse; a failed write is reported on stderr. Decide whether a failed write should stop the listener |
| 17 | Documentation site build not rerun | Low | Maintainer | Open | `zensical build --strict` needs the docs virtualenv; not run in this session |
| - | Authentication only | - | - | By design | Per-tool authorization, user identity and OAuth stay in the consuming gateway |
| - | `stdio-identity-only` does not authenticate | - | - | By design | stdio cannot carry TLS. Use `mtls-server` for authenticated callers |

## Operating notes

| Topic | Behavior |
|---|---|
| Reconnect | Bounded by `workloadApi.reconnect`. After the budget is spent, `isReady()` stays false; restart the process or create a new bridge |
| Audit file rotation | Rename the file, then call `FileAuditLogger.reopen()` |
| Audit failure | Authentication events fail closed: the request gets 503. The sink stays failed until `reopen()` succeeds |
| CRL semantics | When a snapshot carries any CRL, every issuer in a peer chain needs a current CRL (OpenSSL CRL check on the full chain). Snapshots without CRLs do not check revocation |
| Federation | Off by default. A bundle withdrawn by the agent removes that domain at the next update and closes existing connections |

## Verify locally

```sh
pnpm install --frozen-lockfile
pnpm exec biome ci .
pnpm typecheck
pnpm test
pnpm build
pnpm run check:package
```
