# Production readiness

Gaps between the library and a dependency a team can run in production, as of
2026-11-26 on branch `feat/production-readiness`. "Closed" means implemented
and pinned by tests in this repository; items marked "Bench" also passed on the
real [SPIRE bench](spire-bench.md). It does not mean released.

## Summary

| State | Count |
|---|---|
| Closed in code and tested | 24 |
| Open, needs the maintainer | 6 |
| Boundaries by design | 3 |

The library is not declared production-ready while any open row remains. Every
open row needs the maintainer's account, infrastructure or decision.

## Closed

| # | Gap | Severity | Evidence |
|---|---|---|---|
| 1 | Federation unsupported | High | `validator.federatedTrustDomains`; `tests/federation.test.ts`; Bench |
| 2 | Chain binding depended on the TLS-chosen path and skipped validity (expired local intermediate re-certified by a federated CA authenticated a local ID; reproduced first) | High | Transport validates every candidate path against only the claimed domain's anchors with validity, CA and keyCertSign checks; `tests/path.test.ts`, `tests/path-attack.test.ts`; Bench |
| 3 | Binding skipped when transport and validator options differed (reproduced first) | High | Binding runs in the transport for every request; `tests/path-attack.test.ts`; Bench |
| 4 | Wildcard trust domain in caller matchers | Medium | Exact trust domain and a literal segment required; `tests/spiffe-id.test.ts` |
| 5 | Reconnect budget ended after about 20 s | High | Unlimited by default with capped backoff and jitter; `tests/fetcher.test.ts`; Bench (agent stop and restart) |
| 6 | Audit to stdout only, no durable delivery | High | `FileAuditLogger` with fsync and group commit; `tests/file-sink.test.ts`; Bench (mode 0600) |
| 7 | Readiness ignored the audit sink and own SVID validity | High | `isReady()` covers both; `tests/mtls.test.ts`; Bench (credential loss) |
| 8 | Audit sink failure latched until manual `reopen()` | High | Automatic reopen with backoff; `tests/file-sink.test.ts` |
| 9 | Handshake denials shared the authenticated audit queue | High | Separate rate-limited channel, counted drops; `tests/mtls.test.ts`, `tests/file-sink.test.ts` |
| 10 | Handshake and rotation audit failure policy undecided | Medium | Handshake: dropped and counted. Rotation: `audit.backgroundFailure`, default `fail-closed`; `tests/mtls.test.ts` |
| 11 | fsync per event | Medium | Group commit, `groupCommitMs` default 5; acknowledged events are always on disk |
| 12 | Audit file followed symlinks, kept loose modes and unlinked inodes | Low | `O_NOFOLLOW`, regular file, owner and 0600 checks, inode follow |
| 13 | `reopen()` and writes could race | Low | All file operations serialized |
| 14 | Rotation and the fixed cap cut every connection | Medium | `transport.rotation` (`drain` default), `transport.maxConnectionAgeMs`; `tests/mtls.test.ts`; Bench (stream across rotation, closed at the handshake credential's expiry) |
| 15 | CRLs refused, then all-issuers only | Medium | `transport.crlScope`: `all-issuers` (default) or `per-trust-domain`; OpenSSL-generated CRLs in `tests/crl-scope.test.ts`. Marked experimental |
| 16 | No metrics | Medium | `BridgeMetrics` hooks; `tests/mtls.test.ts`, `tests/fetcher.test.ts` |
| 17 | Audit format not versioned or specified | Medium | `schema_version` 1 and [audit event contract](architecture/contracts/audit-event.md) |
| 18 | MCP SDK range unbounded and untested | Medium | Peer `>=1.32.0 <2.0.0`, optional; `tests/mcp-sdk.test.ts` |
| 19 | CommonJS declarations failed with TS1479 | High | `.d.cts` tree; `pnpm run check:package` |
| 20 | Tarball contents unverified | Medium | `check:package` in CI |
| 21 | Release job built with `id-token` and repacked on publish | Low | Build job without `id-token`; publish job uploads the checked tarball. Inactive |
| 22 | Biome configuration broke `biome ci` | Medium | Migrated to the 2.6 schema |
| 23 | No real SPIRE federation run | Medium | [SPIRE bench](spire-bench.md), 18 of 18 checks |
| 24 | Installed-package verifier and strict docs build not rerun | Low | Both pass on 2026-11-26 ([publication readiness](publication-readiness.md)) |

## Open, needs the maintainer

| # | Gap | Severity | Needs | Plan |
|---|---|---|---|---|
| 25 | Not published to npm | High | npm account | Package name ownership and a release through `.github/workflows/release.yml` |
| 26 | Provenance not exercised | Medium | npm account | Configure npm trusted publishing for the repository and an `npm` environment with required reviewers |
| 27 | Version still 0.0.1 | Medium | Decision | Choose the first release version; `CHANGELOG.md` lists the intended API |
| 28 | Independent security review of this revision | High | Decision | Review chain binding, CRL scopes, the audit failure policy and the drain rule |
| 29 | Shared Kubernetes lab not rerun on this revision | Medium | Infrastructure | The lab belongs to the sibling `mcp-svid-auth` project and its VM; rerun it there |
| 30 | Remote CI and private vulnerability reporting for the latest commits | Low | Maintainer | Push the branch and enable reporting in the repository settings |

## Boundaries by design

| Boundary | Why |
|---|---|
| Authentication only | Per-tool authorization, user identity and OAuth stay in the consuming gateway |
| `stdio-identity-only` does not authenticate | stdio cannot carry TLS; use `mtls-server` for authenticated callers |
| Node.js 26 or newer | `engines.node >=26` is a deliberate support decision of the maintainer |

## Verify locally

```sh
pnpm install --frozen-lockfile
pnpm exec biome ci .
pnpm typecheck
pnpm test
pnpm build
pnpm run check:package
pnpm run bench:spire
```
