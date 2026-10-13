import { describe, expect, it, vi } from 'vitest';
import {
  buildAuthFailureEvent,
  buildAuthSuccessEvent,
  buildSvidRotatedEvent,
  buildToolCallEvent,
  StdoutJsonAuditLogger,
} from '../src/audit/logger.js';
import { parseSpiffeId } from '../src/spiffe-id.js';
import type { AuthError, SpiffeCallContext, ValidatedIdentity, X509Svid } from '../src/types.js';

const REQUEST_ID = '11111111-2222-3333-4444-555555555555';
const NOW = new Date('2026-04-21T10:00:00Z');

function makeIdentity(): ValidatedIdentity {
  const id = parseSpiffeId('spiffe://prod.example.org/svc/payment');
  if (!id) throw new Error('test setup');
  return {
    spiffeId: id,
    notBefore: new Date('2026-04-21T09:00:00Z'),
    notAfter: new Date('2026-04-21T11:00:00Z'),
    peerCertDer: new Uint8Array([1, 2, 3]),
  };
}

describe('audit event builders', () => {
  it('buildAuthSuccessEvent fills every required field', () => {
    const ev = buildAuthSuccessEvent(makeIdentity(), { requestId: REQUEST_ID, now: NOW });
    expect(ev).toEqual({
      timestamp: NOW.toISOString(),
      event_type: 'auth_success',
      caller_spiffe_id: 'spiffe://prod.example.org/svc/payment',
      caller_trust_domain: 'prod.example.org',
      svid_expires_at: '2026-04-21T11:00:00.000Z',
      tool_name: null,
      request_id: REQUEST_ID,
      outcome: 'allowed',
      denial_reason: null,
    });
  });

  it('buildAuthFailureEvent populates denial fields and extracts trust domain', () => {
    const err: AuthError = {
      code: 'SPIFFE_ID_DISALLOWED',
      message: 'not on allowlist',
      observedSpiffeId: 'spiffe://evil.attacker/foo' as AuthError['observedSpiffeId'],
    };
    const ev = buildAuthFailureEvent(err, { requestId: REQUEST_ID, now: NOW });
    expect(ev.event_type).toBe('auth_failure');
    expect(ev.outcome).toBe('denied');
    expect(ev.denial_reason).toBe('SPIFFE_ID_DISALLOWED: not on allowlist');
    expect(ev.caller_spiffe_id).toBe('spiffe://evil.attacker/foo');
    expect(ev.caller_trust_domain).toBe('evil.attacker');
    expect(ev.svid_expires_at).toBeNull();
  });

  it('buildAuthFailureEvent handles null observedSpiffeId', () => {
    const err: AuthError = {
      code: 'SVID_INVALID',
      message: 'bad cert',
      observedSpiffeId: null,
    };
    const ev = buildAuthFailureEvent(err, { requestId: REQUEST_ID, now: NOW });
    expect(ev.caller_spiffe_id).toBeNull();
    expect(ev.caller_trust_domain).toBeNull();
  });

  it('buildToolCallEvent carries tool name and caller', () => {
    const ctx: SpiffeCallContext = { caller: makeIdentity(), requestId: REQUEST_ID };
    const ev = buildToolCallEvent(ctx, 'create_ticket', 'allowed', {
      requestId: REQUEST_ID,
      now: NOW,
    });
    expect(ev.event_type).toBe('tool_call');
    expect(ev.tool_name).toBe('create_ticket');
    expect(ev.caller_spiffe_id).toBe('spiffe://prod.example.org/svc/payment');
    expect(ev.outcome).toBe('allowed');
  });

  it('buildToolCallEvent handles null caller (degrade mode)', () => {
    const ctx: SpiffeCallContext = { caller: null, requestId: REQUEST_ID };
    const ev = buildToolCallEvent(
      ctx,
      'ping',
      'error',
      { requestId: REQUEST_ID, now: NOW },
      'no caller',
    );
    expect(ev.caller_spiffe_id).toBeNull();
    expect(ev.outcome).toBe('error');
    expect(ev.denial_reason).toBe('no caller');
  });

  it('buildSvidRotatedEvent captures own SPIFFE ID and expiry', () => {
    const ownId = parseSpiffeId('spiffe://prod.example.org/svc/mcp-server');
    if (!ownId) throw new Error('test setup');
    const svid: X509Svid = {
      spiffeId: ownId,
      certChain: [new Uint8Array()],
      privateKey: new Uint8Array(),
      notBefore: NOW,
      notAfter: new Date('2026-04-21T12:00:00Z'),
      trustBundle: [],
    };
    const ev = buildSvidRotatedEvent(svid, { requestId: REQUEST_ID, now: NOW });
    expect(ev.event_type).toBe('svid_rotated');
    expect(ev.caller_spiffe_id).toBe(ownId.full);
    expect(ev.svid_expires_at).toBe('2026-04-21T12:00:00.000Z');
  });
});

describe('StdoutJsonAuditLogger', () => {
  it('writes one JSON line per event', () => {
    const writes: string[] = [];
    const fakeStream = {
      write: (s: string) => writes.push(s),
    } as unknown as NodeJS.WriteStream;
    const logger = new StdoutJsonAuditLogger(fakeStream);
    const ev = buildAuthSuccessEvent(makeIdentity(), { requestId: REQUEST_ID, now: NOW });
    logger.log(ev);
    expect(writes).toHaveLength(1);
    expect(writes[0]?.endsWith('\n')).toBe(true);
    const parsed = JSON.parse(writes[0]?.trim() ?? '');
    expect(parsed.request_id).toBe(REQUEST_ID);
    expect(parsed.event_type).toBe('auth_success');
  });

  it('does not buffer; writes are synchronous', () => {
    const stream = { write: vi.fn() } as unknown as NodeJS.WriteStream;
    const logger = new StdoutJsonAuditLogger(stream);
    logger.log(buildAuthSuccessEvent(makeIdentity(), { requestId: REQUEST_ID }));
    expect(stream.write as ReturnType<typeof vi.fn>).toHaveBeenCalledTimes(1);
  });
});
