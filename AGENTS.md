# Agent instructions

## Local maintainer instructions

- At the start of every task, check whether `AGENTS.local.md` exists in the repository root.
- If it exists, read it and follow it together with this file. It is git-ignored: never commit it and never quote it in tracked files, commit messages, issues or pull requests.
- It may add restrictions. It must not relax or contradict this file. If the two conflict, follow this file and report the conflict to the maintainer.

## Working rules

- Keep repository content in English. Use plain hyphens, not em dashes or en dashes.
- Use synthetic identities, certificates and data only. Never commit keys, tokens or real trust bundles.
- Run `pnpm test`, `pnpm typecheck`, `pnpm lint` and `pnpm build` before committing.
- Commits use `type: Capitalized subject`, without a trailing period. Never bypass hooks.
- Keep work local. Pushes, releases and publication need an explicit maintainer instruction.
