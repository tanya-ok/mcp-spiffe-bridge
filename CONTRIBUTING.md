# Contributing

## Setup

Requires Node.js 26 and the pnpm version pinned in `package.json`.

```sh
pnpm install --frozen-lockfile
lefthook install   # pre-commit: biome on staged files and a staged gitleaks scan
```

`lefthook` and `gitleaks` are standalone binaries (for example
`brew install lefthook gitleaks`).

## Rules

- English only. Use plain hyphens, not em dashes or en dashes.
- Synthetic identities, certificates and data only. Never commit keys, tokens
  or real trust bundles.
- Biome is the only linter and formatter.
- Commits use `type: Capitalized subject` or `type(scope): Capitalized subject`
  with one of feat, fix, docs, ci, chore, refactor, test, security, perf.
- Never bypass hooks.

## Before a pull request

```sh
pnpm exec biome ci .
pnpm typecheck
pnpm test
pnpm build
pnpm run check:package
```

Changes to federation, rotation, readiness or audit delivery should also pass
the real SPIRE bench, `pnpm run bench:spire` (Lima, see
[docs/spire-bench.md](docs/spire-bench.md)). Update the docs when behavior
changes and check them with `zensical build --strict` (see
`requirements-docs.txt`).
