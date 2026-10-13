# Installed package demo

A real TLS connection, with synthetic identities and a local certificate source.
It proves package usability and allow/deny behavior. It does not prove SPIRE
attestation. Use the [shared lab](kubernetes-lab.md) for that separate boundary.

## Run

Requires Node 26 or newer, OpenSSL, npm and the pinned pnpm version.
Run these commands from the repository root. The consumer is temporary and uses
npm only to exercise the distributable independently of this checkout.

```sh
pnpm install --frozen-lockfile
pnpm build
DEMO_DIR=$(mktemp -d)
npm pack --pack-destination "$DEMO_DIR"
mkdir "$DEMO_DIR/consumer"
printf '{"private":true}\n' > "$DEMO_DIR/consumer/package.json"
npm install --prefix "$DEMO_DIR/consumer" --ignore-scripts --no-audit --no-fund \
  "$DEMO_DIR/mcp-spiffe-bridge-0.0.1.tgz"
node scripts/verify-installed.mjs "$DEMO_DIR/consumer"
```

Success is one JSON record with `passed: true`. A failed assertion exits nonzero.
The verifier deletes its generated private keys and stops its own listener,
including on failure. Remove the disposable consumer when finished:

```sh
rm -r "$DEMO_DIR"
```

## What it checks

| Request or event | Required result |
|---|---|
| Allowed agent certificate | HTTP 200, matching request-local caller identity |
| Trusted certificate for a different agent | HTTP 401, denial audit, handler not called |
| No client certificate | TLS rejection, handler not called |
| Credential source lost | Access refused, handler not called |
| Fresh server credential supplied | HTTP 200 without restarting the transport |
| Stop | Listener reusable, subscriptions removed, generated keys deleted |

Server certificate validation stays enabled. Certificates use `example.org`
SPIFFE IDs and are generated at runtime; no real keys or Workload API socket are
needed. The verifier opens only a temporary loopback listener.

!!! note "Not published"
    This repository and package are not published yet.
