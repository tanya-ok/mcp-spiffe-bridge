import { beforeAll, describe, expect, it } from 'vitest';
import { parseSpiffeId } from '../src/spiffe-id.js';
import { SpiffeValidator } from '../src/svid/validator.js';
import type { SvidFetcher, TrustDomainString, X509Svid } from '../src/types.js';
import { makeSpiffeCert } from './helpers/test-certs.js';

/** Minimal SvidFetcher stub; only `getX509Svid` is exercised by the validator. */
function stubFetcherFor(trustDomain: string): SvidFetcher {
  const parsed = parseSpiffeId(`spiffe://${trustDomain}`);
  if (!parsed) throw new Error(`invalid trust domain in test stub: ${trustDomain}`);
  const fakeSvid: X509Svid = {
    spiffeId: parsed,
    certChain: [new Uint8Array()],
    privateKey: new Uint8Array(),
    notBefore: new Date(0),
    notAfter: new Date(Date.now() + 86_400_000),
    trustBundle: [],
  };
  return {
    getX509Svid: async () => fakeSvid,
    watchSvids: () => () => {},
    close: async () => {},
  };
}

describe('SpiffeValidator', () => {
  const trustDomain = 'prod.example.org';
  const allowedSpiffeId = `spiffe://${trustDomain}/svc/payment`;
  let certDer: Uint8Array;

  beforeAll(async () => {
    const cert = await makeSpiffeCert({ spiffeId: allowedSpiffeId });
    certDer = cert.certDer;
  });

  it('accepts a cert whose SPIFFE ID matches the allowlist', async () => {
    const validator = new SpiffeValidator(
      { allowedCallers: [allowedSpiffeId], minTtlSeconds: 0 },
      stubFetcherFor(trustDomain),
    );
    const result = await validator.validate(certDer);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.identity.spiffeId.full).toBe(allowedSpiffeId);
      expect(result.identity.spiffeId.trustDomain).toBe(trustDomain);
    }
  });

  it('denies a cert whose SPIFFE ID is not allowlisted', async () => {
    const validator = new SpiffeValidator(
      { allowedCallers: [`spiffe://${trustDomain}/svc/other`], minTtlSeconds: 0 },
      stubFetcherFor(trustDomain),
    );
    const result = await validator.validate(certDer);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe('SPIFFE_ID_DISALLOWED');
      expect(result.error.observedSpiffeId).toBe(allowedSpiffeId);
    }
  });

  it('allows via glob', async () => {
    const validator = new SpiffeValidator(
      { allowedCallers: [`spiffe://${trustDomain}/svc/*`], minTtlSeconds: 0 },
      stubFetcherFor(trustDomain),
    );
    const result = await validator.validate(certDer);
    expect(result.ok).toBe(true);
  });

  it('denies on trust-domain mismatch', async () => {
    const validator = new SpiffeValidator(
      { allowedCallers: [allowedSpiffeId], minTtlSeconds: 0 },
      stubFetcherFor('other.trust.domain'),
    );
    const result = await validator.validate(certDer);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe('TRUST_DOMAIN_MISMATCH');
    }
  });

  it('never accepts a foreign trust domain, even when pinned', async () => {
    const foreignId = 'spiffe://partner.example.net/svc/payment';
    const foreign = await makeSpiffeCert({ spiffeId: foreignId });
    const validator = new SpiffeValidator(
      {
        allowedCallers: [allowedSpiffeId, foreignId],
        minTtlSeconds: 0,
        allowedTrustDomains: [trustDomain, 'partner.example.net'] as TrustDomainString[],
      },
      stubFetcherFor(trustDomain),
    );
    const result = await validator.validate(foreign.certDer);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe('TRUST_DOMAIN_MISMATCH');
    expect((await validator.validate(certDer)).ok).toBe(true);
  });

  it('accepts nothing when the pin omits the local trust domain', async () => {
    const validator = new SpiffeValidator(
      {
        allowedCallers: [allowedSpiffeId],
        minTtlSeconds: 0,
        allowedTrustDomains: ['partner.example.net'] as TrustDomainString[],
      },
      stubFetcherFor(trustDomain),
    );
    const result = await validator.validate(certDer);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe('TRUST_DOMAIN_MISMATCH');
  });

  it('denies when cert is not yet valid', async () => {
    const future = await makeSpiffeCert({
      spiffeId: allowedSpiffeId,
      notBefore: new Date(Date.now() + 3600_000),
      notAfter: new Date(Date.now() + 7200_000),
    });
    const validator = new SpiffeValidator(
      { allowedCallers: [allowedSpiffeId], minTtlSeconds: 0 },
      stubFetcherFor(trustDomain),
    );
    const result = await validator.validate(future.certDer);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe('SVID_NOT_YET_VALID');
  });

  it('denies an expired cert', async () => {
    const past = await makeSpiffeCert({
      spiffeId: allowedSpiffeId,
      notBefore: new Date(Date.now() - 7200_000),
      notAfter: new Date(Date.now() - 3600_000),
    });
    const validator = new SpiffeValidator(
      { allowedCallers: [allowedSpiffeId], minTtlSeconds: 0 },
      stubFetcherFor(trustDomain),
    );
    const result = await validator.validate(past.certDer);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe('SVID_EXPIRED');
  });

  it('denies when remaining TTL is below minTtlSeconds', async () => {
    const shortLived = await makeSpiffeCert({
      spiffeId: allowedSpiffeId,
      notBefore: new Date(Date.now() - 60_000),
      notAfter: new Date(Date.now() + 30_000), // 30 s remaining
    });
    const validator = new SpiffeValidator(
      { allowedCallers: [allowedSpiffeId], minTtlSeconds: 300 },
      stubFetcherFor(trustDomain),
    );
    const result = await validator.validate(shortLived.certDer);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe('SVID_EXPIRED');
  });

  it('rejects an unparseable cert', async () => {
    const validator = new SpiffeValidator(
      { allowedCallers: [allowedSpiffeId], minTtlSeconds: 0 },
      stubFetcherFor(trustDomain),
    );
    const result = await validator.validate(new Uint8Array([1, 2, 3, 4]));
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe('SVID_INVALID');
  });

  it('rejects a cert with no SPIFFE URI in SAN', async () => {
    // Cert with a non-SPIFFE URI only; our extractor expects exactly one SPIFFE URI.
    const nonSpiffe = await makeSpiffeCert({
      spiffeId: 'https://example.com/not-a-spiffe-id',
    });
    const validator = new SpiffeValidator(
      { allowedCallers: [allowedSpiffeId], minTtlSeconds: 0 },
      stubFetcherFor(trustDomain),
    );
    const result = await validator.validate(nonSpiffe.certDer);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe('SVID_INVALID');
  });
});
