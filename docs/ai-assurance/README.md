# Proposed AI Assurance profile

**Pending maintainer review. No installation or execution evidence is included.**

Scope: Node-only synthetic mTLS/SVID validation, credential refresh and safe transport audit; no deployment, Google identity or Python runtime installation.

Prepared base: `70e9ae0157cc7c242478114d4f01af39a9dfb3da`.
This base revision is not published; verify its remote availability before opening.
Candidate source: AI Assurance 0.2.1, commit
`353d374a00b43479870a6dee300dd200529cc60c`, verified locally against an immutable Git bundle.
This source revision is not published; remote availability must be checked before adoption.
The source checkout and CLI must be trusted separately from a target lock.

| Control | Proposed bounded claim | Existing evidence surface |
|---|---|---|
| access-boundary | mTLS peer identity and expected SPIFFE trust domain are validated. | `tests/mtls.test.ts`, `tests/validator.test.ts`, `tests/spiffe-id.test.ts` |
| data-exposure | Transport audit output avoids leaking credentials and private peer material. | `tests/audit.test.ts` |
| untrusted-instructions | Malformed or untrusted identity material fails validation without changing authority. | `tests/validator.test.ts`, `tests/fetcher-wire.test.ts` |
| consequential-actions | Credential fetch failures fail closed rather than silently trusting stale identity. | `tests/fetcher.test.ts`, `tests/mtls.test.ts` |
| evidence-lineage | Audit outcomes identify transport decisions using synthetic test identities. | `tests/audit.test.ts` |
| bounded-claims | Unit transport results remain distinct from full live SPIRE interoperability. | `README.md`, `tests/mtls.test.ts` |

CI workflow: `.github/workflows/ci.yml`. Candidate checks: `check`, `secrets`.
These names come from workflow definitions. Before accepting records, match the
actual provider job names, exact project commit, completed job conclusion and
run URL. A CI suite's success is coarse evidence; it cannot establish untested
claims or substitute for review of individual test coverage.

All six controls are proposed for scoped review, with missing proof retained as
`not_verified`. This is not an accepted applicability decision. Only a maintainer
may approve or change applicability. Any future exclusion needs rationale and
`decided_by`. Agents must not manufacture executed records or approve exclusions.

Skip installation for this Node-only repository. AI Assurance needs Python 3.12+ and Git in a separate approved verifier environment. The private CI also needs a reviewed collector; no source packet or new external review is authorized.

## Adoption gate

1. Review claims and approve the project-specific profile; keep limitations.
2. Use a trusted collector to select real CI evidence for an existing full
   40-hex project commit, a non-future timestamp, and a run URL or artifact hash.
   The current installer also requires publicly verifiable GitHub run/job metadata.
3. Keep records outside this proposal until independently collected. There are
   no empty evidence arrays or fabricated execution outcomes here.
4. Obtain explicit installation approval. Then use the separately reviewed CLI,
   source commit and approved candidate. Do not install by copying this directory.

`proposal.json` is a review envelope, deliberately not an installer input.
No `.ai-assurance/` directory, managed AGENTS block, workflow, dependency, tracker
integration or model call is added. No publication, deployment or certification
is implied. Linear and other trackers remain optional adapters.
