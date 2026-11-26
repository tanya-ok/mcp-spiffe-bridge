#!/usr/bin/env bash
# Executed inside the Lima VM by bench.sh.
set -euo pipefail
cd "$(dirname "$0")"
chmod 0777 work/out
OUT=work/out/results.jsonl
: > "$OUT"
dc() { docker compose "$@"; }
server() { local side=$1; shift; dc exec -T "spire-server-$side" /opt/spire/bin/spire-server "$@"; }
record() { printf '{"scenario":"%s","at":%s,"result":%s}\n' "$1" "$(date +%s)" "$2" >> "$OUT"; }
health() { dc exec -T runner-a node -e "fetch('http://127.0.0.1:9090').then(r=>r.text()).then(t=>console.log(t))"; }
wait_for() {
  local tries=$1; shift
  for _ in $(seq "$tries"); do
    if "$@" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  echo "timed out waiting for: $*" >&2
  return 1
}
ready_is() { health | grep -q "\"ready\":$1"; }

dc down -v --remove-orphans >/dev/null 2>&1 || true
dc build -q
dc up -d spire-server-a spire-server-b runner-a runner-b
wait_for 60 server a healthcheck
wait_for 60 server b healthcheck

echo "-- federation bootstrap"
server a bundle show -format spiffe > work/a.bundle
server b bundle show -format spiffe > work/b.bundle
server a bundle set -format spiffe -id spiffe://partner.example.net < work/b.bundle
server b bundle set -format spiffe -id spiffe://example.org < work/a.bundle

echo "-- agents and entries"
TOKEN_A=$(server a token generate -spiffeID spiffe://example.org/agent/a | awk '/Token/ {print $2}')
TOKEN_B=$(server b token generate -spiffeID spiffe://partner.example.net/agent/b | awk '/Token/ {print $2}')
server a entry create -parentID spiffe://example.org/agent/a -spiffeID spiffe://example.org/mcp/server \
  -selector unix:uid:1000 -federatesWith spiffe://partner.example.net -dns runner-a >/dev/null
server a entry create -parentID spiffe://example.org/agent/a -spiffeID spiffe://example.org/agent/research \
  -selector unix:uid:1001 -federatesWith spiffe://partner.example.net >/dev/null
server b entry create -parentID spiffe://partner.example.net/agent/b -spiffeID spiffe://partner.example.net/agent/billing \
  -selector unix:uid:1000 -federatesWith spiffe://example.org >/dev/null
server b entry create -parentID spiffe://partner.example.net/agent/b -spiffeID spiffe://partner.example.net/agent/intruder \
  -selector unix:uid:1001 -federatesWith spiffe://example.org >/dev/null
JOIN_TOKEN_A=$TOKEN_A JOIN_TOKEN_B=$TOKEN_B dc up -d agent-a agent-b

probe() { dc exec -T -u "$2" "runner-$1" node probe.mjs; }
fed_ready() { probe "$1" "$2" | grep -q "$3"; }
wait_for 90 fed_ready a node partner.example.net
wait_for 90 fed_ready a second partner.example.net
wait_for 90 fed_ready b node example.org
wait_for 90 fed_ready b second example.org
record probe-a "$(probe a node)"
record probe-b "$(probe b node)"
record versions "{\"spire\":\"$(server a --version 2>&1 | tr -d '\r' | head -1)\",\"node\":\"$(dc exec -T runner-a node --version | tr -d '\r')\",\"docker\":\"$(docker version --format '{{.Server.Version}}')\"}"

echo "-- bridge"
dc exec -d -T -u node runner-a sh -c 'node server.mjs > /bench/out/server.log 2>&1'
wait_for 60 ready_is true
record health-start "$(health)"

call() { dc exec -T -u "$2" "runner-$1" node client.mjs "${@:3}"; }
record local-allowed "$(call a second https://runner-a:8443/)"
record federated-allowed "$(call b node https://runner-a:8443/)"
record federated-not-allowlisted "$(call b second https://runner-a:8443/)"
record federation-not-configured "$(call b node https://runner-a:8445/)"
record cross-domain-forged "$(call b node https://runner-a:8443/ --forged /bench/forged/cross-domain)"
record cross-domain-forged-mismatched-validator "$(call b node https://runner-a:8444/ --forged /bench/forged/cross-domain)"
record expired-intermediate-attack "$(call b node https://runner-a:8443/ --forged /bench/forged/expired-intermediate)"
record expired-intermediate-attack-mismatched-validator "$(call b node https://runner-a:8444/ --forged /bench/forged/expired-intermediate)"

echo "-- rotation while serving (about 75 s)"
record health-before-stream "$(health)"
record stream-across-rotation "$(call b node https://runner-a:8443/stream --stream 75)"
record health-after-stream "$(health)"
record local-after-rotation "$(call a second https://runner-a:8443/)"

echo "-- credential loss"
dc stop agent-a >/dev/null
wait_for 60 ready_is false
record health-agent-stopped "$(health)"
record federated-during-loss "$(call b node https://runner-a:8443/)"
dc start agent-a >/dev/null
wait_for 120 ready_is true
record health-agent-restarted "$(health)"
record federated-after-recovery "$(call b node https://runner-a:8443/)"
record audit-denials "$(dc exec -T runner-a node -e "const l=require('fs').readFileSync('/bench/out/audit.jsonl','utf8').trim().split('\\n').map(JSON.parse);const c={};for(const e of l)if(e.denial_reason)c[e.denial_reason]=(c[e.denial_reason]??0)+1;console.log(JSON.stringify(c))")"
record audit-file "{\"mode\":\"$(dc exec -T runner-a stat -c %a /bench/out/audit.jsonl | tr -d '\r')\"}"
echo "-- done"
