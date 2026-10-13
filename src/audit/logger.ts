import type {
  AuditLogger,
  AuthError,
  SpiffeAuditEvent,
  SpiffeAuditEventType,
  SpiffeCallContext,
  ValidatedIdentity,
  X509Svid,
} from '../types.js';

/**
 * Default logger: emits one JSON line per event to stdout.
 *
 * Stdout is chosen deliberately: on ECS Fargate and Kubernetes, stdout is
 * scraped by the platform's log agent (awslogs, fluent-bit, etc.) into the
 * same pipeline as every other audit source. Consumers who want a different
 * sink (Pino, file, OTel) pass their own `AuditLogger`.
 *
 * The logger intentionally does NOT buffer. Audit events for denied
 * authentication must survive a crash.
 */
export class StdoutJsonAuditLogger implements AuditLogger {
  constructor(private readonly stream: NodeJS.WriteStream = process.stdout) {}

  log(event: SpiffeAuditEvent): void {
    this.stream.write(`${JSON.stringify(event)}\n`);
  }
}

// ─── Event builders ─────────────────────────────────────────────────────
//
// These helpers enforce that every audit event has the full shape declared
// in `types.ts`: no partial records, no string keys drifting over time.

export interface BuildEventCommon {
  readonly requestId: string;
  readonly now?: Date;
}

export function buildAuthSuccessEvent(
  identity: ValidatedIdentity,
  common: BuildEventCommon,
): SpiffeAuditEvent {
  return baseEvent('auth_success', common, {
    caller_spiffe_id: identity.spiffeId.full,
    caller_trust_domain: identity.spiffeId.trustDomain,
    svid_expires_at: identity.notAfter.toISOString(),
    outcome: 'allowed',
    denial_reason: null,
  });
}

export function buildAuthFailureEvent(
  error: AuthError,
  common: BuildEventCommon,
): SpiffeAuditEvent {
  const observedTd = extractTrustDomain(error.observedSpiffeId);
  return baseEvent('auth_failure', common, {
    caller_spiffe_id: error.observedSpiffeId,
    caller_trust_domain: observedTd,
    svid_expires_at: null,
    outcome: 'denied',
    denial_reason: `${error.code}: ${error.message}`,
  });
}

export function buildToolCallEvent(
  ctx: SpiffeCallContext,
  toolName: string,
  outcome: 'allowed' | 'denied' | 'error',
  common: BuildEventCommon,
  denialReason: string | null = null,
): SpiffeAuditEvent {
  const caller = ctx.caller;
  return baseEvent('tool_call', common, {
    caller_spiffe_id: caller?.spiffeId.full ?? null,
    caller_trust_domain: caller?.spiffeId.trustDomain ?? null,
    svid_expires_at: caller?.notAfter.toISOString() ?? null,
    outcome,
    denial_reason: denialReason,
    tool_name: toolName,
  });
}

export function buildSvidRotatedEvent(svid: X509Svid, common: BuildEventCommon): SpiffeAuditEvent {
  return baseEvent('svid_rotated', common, {
    caller_spiffe_id: svid.spiffeId.full,
    caller_trust_domain: svid.spiffeId.trustDomain,
    svid_expires_at: svid.notAfter.toISOString(),
    outcome: 'allowed',
    denial_reason: null,
  });
}

// ─── internals ──────────────────────────────────────────────────────────

type Overrides = Partial<Omit<SpiffeAuditEvent, 'timestamp' | 'event_type' | 'request_id'>>;

function baseEvent(
  type: SpiffeAuditEventType,
  common: BuildEventCommon,
  overrides: Overrides,
): SpiffeAuditEvent {
  const ts = (common.now ?? new Date()).toISOString();
  return {
    timestamp: ts,
    event_type: type,
    caller_spiffe_id: overrides.caller_spiffe_id ?? null,
    caller_trust_domain: overrides.caller_trust_domain ?? null,
    svid_expires_at: overrides.svid_expires_at ?? null,
    tool_name: overrides.tool_name ?? null,
    request_id: common.requestId,
    outcome: overrides.outcome ?? 'allowed',
    denial_reason: overrides.denial_reason ?? null,
  };
}

function extractTrustDomain(spiffeId: string | null): string | null {
  if (!spiffeId) return null;
  if (!spiffeId.startsWith('spiffe://')) return null;
  const rest = spiffeId.slice('spiffe://'.length);
  const slash = rest.indexOf('/');
  return slash === -1 ? rest : rest.slice(0, slash);
}
