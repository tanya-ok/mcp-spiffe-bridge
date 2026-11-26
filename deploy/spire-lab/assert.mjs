// Check bench results: node deploy/spire-lab/assert.mjs <results.jsonl>
import { readFileSync } from 'node:fs';

const rows = readFileSync(process.argv[2], 'utf8')
  .split('\n')
  .filter(Boolean)
  .map((line) => {
    try {
      return JSON.parse(line);
    } catch {
      return { scenario: 'unparsable', result: line };
    }
  });
const by = Object.fromEntries(rows.map((r) => [r.scenario, r]));
const result = (name) => by[name]?.result ?? {};
const refused = (r) => r.error !== undefined || (r.status !== undefined && r.status !== 200);
const checks = [];
const check = (name, ok, detail) => checks.push({ name, ok: Boolean(ok), detail });

const local = result('local-allowed');
check(
  'local caller accepted',
  local.status === 200 && local.body?.includes('example.org/agent/research'),
  local,
);
const fed = result('federated-allowed');
check(
  'allowlisted federated caller accepted',
  fed.status === 200 && fed.body?.includes('partner.example.net/agent/billing'),
  fed,
);
check(
  'federated caller not on the allowlist refused',
  result('federated-not-allowlisted').status === 401,
  result('federated-not-allowlisted'),
);
check(
  'federated domain not configured refused',
  refused(result('federation-not-configured')),
  result('federation-not-configured'),
);
check(
  'federated CA with a local SPIFFE ID refused',
  refused(result('cross-domain-forged')),
  result('cross-domain-forged'),
);
check(
  'same, validator without federation option',
  refused(result('cross-domain-forged-mismatched-validator')),
  result('cross-domain-forged-mismatched-validator'),
);
check(
  'expired local intermediate re-certified by partner refused',
  refused(result('expired-intermediate-attack')),
  result('expired-intermediate-attack'),
);
check(
  'same, validator without federation option',
  refused(result('expired-intermediate-attack-mismatched-validator')),
  result('expired-intermediate-attack-mismatched-validator'),
);

const before = result('health-before-stream');
const after = result('health-after-stream');
const stream = result('stream-across-rotation');
const rotatedBefore = before.counts?.svid_rotated ?? 0;
const rotatedAfter = after.counts?.svid_rotated ?? 0;
const oldExpiry = Date.parse(before.svid?.notAfter ?? '');
const streamEnd = (by['stream-across-rotation']?.at ?? 0) * 1000;
const survivedRotation = rotatedAfter > rotatedBefore && stream.status === 200 && stream.chunks > 0;
// A drained stream may outlive a rotation but must end by the expiry of the credential it was opened with.
const endedByExpiry = stream.closedEarly === true && streamEnd <= oldExpiry + 2000;
check('SVID rotated while a stream was served', survivedRotation, {
  rotatedBefore,
  rotatedAfter,
  stream,
});
check('stream never outlived the handshake credential', endedByExpiry, {
  oldExpiry: before.svid?.notAfter,
  stream,
});
check(
  'new request after rotation accepted',
  result('local-after-rotation').status === 200,
  result('local-after-rotation'),
);

const stopped = result('health-agent-stopped');
check('readiness false on credential loss', stopped.ready === false, stopped.svid);
check(
  'requests refused during credential loss',
  refused(result('federated-during-loss')),
  result('federated-during-loss'),
);
const restarted = result('health-agent-restarted');
check(
  'readiness recovers after the agent returns',
  restarted.ready === true && (restarted.counts?.workload_api_reconnect ?? 0) > 0,
  restarted.counts,
);
check(
  'request accepted after recovery',
  result('federated-after-recovery').status === 200,
  result('federated-after-recovery'),
);

const reasons = result('audit-denials');
check(
  'forged chains denied for chain binding in audit',
  (reasons['TRUST_DOMAIN_MISMATCH: peer chain does not lead to the trust bundle of example.org'] ??
    0) >= 4,
  reasons,
);
check('audit file mode 0600', result('audit-file').mode === '600', result('audit-file'));
const probe = result('probe-a');
check('Workload API federated bundle delivered', probe.federatedBundleKeys?.length > 0, probe);
const versions = result('versions');
console.log(
  JSON.stringify({
    versions,
    crlCountFromSpire: { a: probe.crlCount, b: result('probe-b').crlCount },
  }),
);
for (const c of checks)
  console.log(`${c.ok ? 'PASS' : 'FAIL'}  ${c.name}${c.ok ? '' : `  ${JSON.stringify(c.detail)}`}`);
const failed = checks.filter((c) => !c.ok).length;
console.log(`${checks.length - failed}/${checks.length} passed`);
process.exit(failed === 0 ? 0 : 1);
