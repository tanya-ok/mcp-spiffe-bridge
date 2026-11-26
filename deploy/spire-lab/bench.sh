#!/usr/bin/env bash
# Real SPIRE federation bench for mcp-spiffe-bridge. Runs inside the Lima VM
# named by BRIDGE_LAB_VM (default bridge-fed-lab, template://docker).
# Usage: deploy/spire-lab/bench.sh   (from any directory; needs pnpm, openssl, node, limactl)
set -euo pipefail

VM="${BRIDGE_LAB_VM:-bridge-fed-lab}"
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
WORK="$HERE/work"

vms="$(limactl list --format '{{.Name}} {{.Status}}')"
if ! grep -qx "$VM Running" <<<"$vms"; then
  echo "Lima VM $VM is not running. Create it once with:" >&2
  echo "  limactl create --name $VM --cpus 2 --memory 4 --disk 12 --tty=false template://docker && limactl start $VM" >&2
  exit 2
fi

rm -rf "$WORK"
mkdir -p "$WORK"/ca-a "$WORK"/ca-b "$WORK"/out "$WORK"/stage

echo "== build and pack"
(cd "$REPO" && pnpm build >/dev/null && pnpm pack --pack-destination "$WORK" >/dev/null)

echo "== synthetic upstream roots"
for side in a b; do
  td=$([ "$side" = a ] && echo example.org || echo partner.example.net)
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$WORK/ca-$side/ca.key" 2>/dev/null
  openssl req -new -x509 -key "$WORK/ca-$side/ca.key" -days 1 -subj "/CN=Synthetic bench root $td" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -out "$WORK/ca-$side/ca.pem"
  chmod 0644 "$WORK/ca-$side/ca.key"
done
(cd "$REPO" && node "$HERE/forge.mjs" "$WORK")

echo "== stage"
STAGE="$WORK/stage/bridge-fed-lab"
mkdir -p "$STAGE/work"
cp -R "$HERE/compose.yaml" "$HERE/config" "$HERE/runner" "$HERE/run-in-vm.sh" "$STAGE/"
cp -R "$WORK/ca-a" "$WORK/ca-b" "$WORK/forged" "$STAGE/work/"
mkdir -p "$STAGE/work/out"
cp "$WORK"/mcp-spiffe-bridge-*.tgz "$STAGE/runner/package.tgz"

# shellcheck disable=SC2016 # $HOME must expand inside the VM
REMOTE_HOME="$(limactl shell "$VM" -- sh -c 'printf %s "$HOME"')"
limactl shell "$VM" -- rm -rf "$REMOTE_HOME/bridge-fed-lab"
limactl copy -r "$STAGE" "$VM:$REMOTE_HOME/"

echo "== run in $VM"
status=0
limactl shell --workdir "$REMOTE_HOME/bridge-fed-lab" "$VM" -- bash run-in-vm.sh || status=$?
limactl copy "$VM:$REMOTE_HOME/bridge-fed-lab/work/out/results.jsonl" "$WORK/results.jsonl" || true
limactl copy "$VM:$REMOTE_HOME/bridge-fed-lab/work/out/server.log" "$WORK/server.log" || true
limactl shell --workdir "$REMOTE_HOME/bridge-fed-lab" "$VM" -- docker compose down -v --remove-orphans >/dev/null 2>&1 || true
if [ "$status" -ne 0 ]; then
  echo "bench run failed with status $status; see $WORK" >&2
  exit "$status"
fi
node "$HERE/assert.mjs" "$WORK/results.jsonl"
