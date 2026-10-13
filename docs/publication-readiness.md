# Publication and demonstration gates

This page defines acceptance criteria, not an approval badge. Publication stays
separate from local preparation. No remote deployment is implied by a successful
local documentation build.

!!! note "Not published"
    This repository is not published yet. Publication is a separate maintainer
    decision.

## Reproduce the project

Run from a fresh checkout with the documented runtime and package manager:

```sh
pnpm install --frozen-lockfile
pnpm typecheck
pnpm test
pnpm lint
pnpm build
```

Run the [installed package demo](installed-demo.md), then follow the separate
[shared lab guide](kubernetes-lab.md) when that integration run is authorized. Capture the source revision, environment,
command, observed positive and negative outcomes and cleanup result. Saved
screenshots or an older report must identify their capture date. Re-run an
applicable integration check after changing the behavior it exercises.

The bridge is a library. Its executable product demo is the FHIR gateway in the shared security lab. Real TLS 1.3 (and opt-in TLS 1.2) credential-loss and trust-root tests complement the shared SPIRE scenarios.

## Build the documentation

Documentation tooling is separate from the application runtime:

```sh
python3 -m venv .venv-docs
.venv-docs/bin/python -m pip install -r requirements-docs.txt
.venv-docs/bin/zensical build --strict --clean
.venv-docs/bin/zensical serve --dev-addr 127.0.0.1:8000
```

The pinned generator produces `site/`. Check navigation, code blocks, diagrams,
search and project-subpath asset URLs in a browser. Never add private overlays,
state databases, credentials or private vaults to documentation sources.

## GitHub Pages handoff

The prepared workflow builds on pull requests and publishes only from `main`
after an authorized push or explicit workflow dispatch. It uploads the static
`site/` directory and uses the GitHub Pages environment with job-scoped
`pages: write` and `id-token: write`; no long-lived deploy key is required.
The repository owner must select GitHub Actions as the Pages source before the
first deployment. Preparing this file does not enable Pages or execute a deploy.

Before publication, inspect the exact staged diff and distributable contents,
run the secret gates below, reproduce the demo from a clean checkout, verify the
strict docs build and retain its evidence.

## Secret gates

| Gate | Where | What it runs |
|---|---|---|
| Pre-commit hook | Local, after `lefthook install` | Biome on staged files and `gitleaks git --pre-commit --staged` |
| Full history scan | Local, before publication | `gitleaks git --log-opts=--all --redact --config .gitleaks.toml` |
| CI `secrets` job | GitHub Actions, once published | gitleaks action plus the same full history scan |

`.gitleaks.toml` extends the default gitleaks rules with generic checks for
absolute home directory paths and `op://` secret references. The hook needs the
standalone `lefthook` and `gitleaks` binaries. The CI job does not run until the
repository is published. Remote CI and the resulting
Pages URL still need verification after publication is explicitly authorized.

Generator behavior and configuration follow the
[official Zensical guide](https://zensical.org/docs/create-your-site/).

## Local verification - 2026-10-12

Base revision `2235f40`, plus the installed-demo verifier and
documentation changes. Node v26.10.0, pnpm 9.15.0. Typecheck, build and
all 79 tests passed. Lint passed with nine existing warnings. The new verifier
passed against an independently installed archive, including denial, credential
loss, fresh-credential recovery and cleanup. The archive contains nine entries,
including Apache-2.0 LICENSE and both module formats, with no source, scripts or
local task database.

Archive SHA-256: `b3f6c41bb8a3b4942014fb27c9478660aa2c75e50ecd001efdc5a8356ad2bbe5`.

Strict Zensical build passed. This is local package and synthetic-certificate
evidence, not a new shared SPIRE run. No publication or
remote CI was performed.

## Revision references

Revision hashes in dated records that do not resolve in this repository identify
development commits. They were squashed into the 2026-10-13 release commit and are
archived locally. The release tree was checked again after the squash.
