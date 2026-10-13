import { describe, expect, it } from 'vitest';
import { matchesAllowlist, parseSpiffeId, spiffeIdEquals } from '../src/spiffe-id.js';
import type { SpiffeId } from '../src/types.js';

function mustParse(input: string): SpiffeId {
  const id = parseSpiffeId(input);
  if (!id) throw new Error(`invalid test identity: ${input}`);
  return id;
}

describe('parseSpiffeId', () => {
  it('parses a minimal trust-domain-only ID', () => {
    const id = parseSpiffeId('spiffe://prod.example.org');
    expect(id).not.toBeNull();
    expect(id?.trustDomain).toBe('prod.example.org');
    expect(id?.path).toBe('');
    expect(id?.full).toBe('spiffe://prod.example.org');
  });

  it('parses a full ID with multi-segment path', () => {
    const id = parseSpiffeId('spiffe://prod.example.org/ns/default/sa/payment');
    expect(id?.trustDomain).toBe('prod.example.org');
    expect(id?.path).toBe('/ns/default/sa/payment');
  });

  it.each([
    'http://prod.example.org/foo', // wrong scheme
    'spiffe://', // empty trust domain
    'spiffe:///foo', // empty trust domain, path present
    'spiffe://PROD.example.org/foo', // uppercase
    'spiffe://prod.example.org/', // trailing slash
    'spiffe://prod.example.org/foo//bar', // empty segment
    'spiffe://prod.example.org/../etc/passwd', // path traversal
    'spiffe://prod.example.org/./foo', // path traversal via .
    `spiffe://${'a'.repeat(260)}/foo`, // trust domain too long
    '', // empty
    'spiffe://prod.example.org/seg with space', // invalid path char
  ])('rejects malformed input: %s', (input) => {
    expect(parseSpiffeId(input)).toBeNull();
  });

  it('spiffeIdEquals compares full form', () => {
    const a = mustParse('spiffe://td/a');
    const b = mustParse('spiffe://td/a');
    const c = mustParse('spiffe://td/b');
    expect(spiffeIdEquals(a, b)).toBe(true);
    expect(spiffeIdEquals(a, c)).toBe(false);
  });
});

describe('matchesAllowlist', () => {
  const id = mustParse('spiffe://prod.example.org/svc/payment');

  it('allows exact match', () => {
    expect(matchesAllowlist(id, ['spiffe://prod.example.org/svc/payment'])).toBe(true);
  });

  it('denies non-matching exact entry', () => {
    expect(matchesAllowlist(id, ['spiffe://prod.example.org/svc/notifications'])).toBe(false);
  });

  it('allows single-segment glob', () => {
    expect(matchesAllowlist(id, ['spiffe://prod.example.org/svc/*'])).toBe(true);
  });

  it('rejects single-segment glob across path separators', () => {
    const deep = mustParse('spiffe://prod.example.org/svc/payment/sub');
    expect(matchesAllowlist(deep, ['spiffe://prod.example.org/svc/*'])).toBe(false);
  });

  it('allows `**` across path separators', () => {
    const deep = mustParse('spiffe://prod.example.org/svc/payment/sub');
    expect(matchesAllowlist(deep, ['spiffe://prod.example.org/svc/**'])).toBe(true);
  });

  it('returns false for empty allowlist', () => {
    expect(matchesAllowlist(id, [])).toBe(false);
  });

  it('matches when ANY entry matches', () => {
    expect(
      matchesAllowlist(id, [
        'spiffe://prod.example.org/svc/other',
        'spiffe://prod.example.org/svc/*',
      ]),
    ).toBe(true);
  });
});
