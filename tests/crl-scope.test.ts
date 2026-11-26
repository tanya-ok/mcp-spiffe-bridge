import { afterEach, describe, expect, it, vi } from 'vitest';
import { checkRevocation, parseCrl } from '../src/svid/crl.js';
import { SpiffeValidator } from '../src/svid/validator.js';
import { MtlsTransportServer } from '../src/transport/mtls.js';
import type { CrlScope, SvidFetcher, TrustDomainString, X509Svid } from '../src/types.js';
import { type OpensslCa, opensslCa } from './helpers/openssl-ca.js';
import { freePort, get, syntheticCa } from './helpers/pki.js';

const partner = 'partner.example.net' as TrustDomainString;
const localCaller = 'spiffe://example.org/agent/research';
const partnerCaller = 'spiffe://partner.example.net/agent/billing';
const cas: OpensslCa[] = [];
afterEach(async () => {
  await Promise.all(cas.splice(0).map((c) => c.cleanup()));
});

async function bench(
  scope: CrlScope | undefined,
  crls: (local: OpensslCa) => Promise<Uint8Array[]>,
) {
  const local = await opensslCa('Synthetic OpenSSL local CA');
  const remote = await opensslCa('Synthetic OpenSSL partner CA');
  cas.push(local, remote);
  const server = await local.issue('spiffe://example.org/mcp/server', '01');
  const good = await local.issue(localCaller, '0a01');
  const revoked = await local.issue(localCaller, '0a02');
  const partnerPeer = await remote.issue(partnerCaller, '0b01');
  const own: X509Svid = {
    ...server,
    federatedBundles: new Map([[partner, [remote.der]]]),
    crls: await crls(local),
  };
  const port = await freePort();
  const fetcher: SvidFetcher = {
    getX509Svid: async () => own,
    watchSvids: () => () => {},
    close: async () => {},
  };
  const audit = { log: vi.fn() };
  const transport = new MtlsTransportServer({
    fetcher,
    validator: new SpiffeValidator(
      {
        allowedCallers: [localCaller, partnerCaller],
        minTtlSeconds: 5,
        federatedTrustDomains: [partner],
      },
      fetcher,
    ),
    audit,
    transport: {
      mode: 'mtls-server',
      sse: { host: '127.0.0.1', port },
      ...(scope ? { crlScope: scope } : {}),
    },
    federatedTrustDomains: [partner],
  });
  transport.setAuthorizedHandler((_req, res) => res.end('served'));
  await transport.start();
  const call = (peer: X509Svid) =>
    get(port, own.trustBundle, peer).then(
      (r) => r.status,
      () => 'tls-refused' as const,
    );
  return { own, good, revoked, partnerPeer, transport, audit, call };
}

describe('CRL scope with an OpenSSL-generated CRL', () => {
  it('all-issuers (default) refuses federated callers when only the local domain publishes CRLs', async () => {
    const b = await bench(undefined, async (local) => [await local.crl(['0a02'])]);
    try {
      expect(await b.call(b.good)).toBe(200);
      expect(await b.call(b.revoked)).toBe('tls-refused');
      expect(await b.call(b.partnerPeer)).toBe('tls-refused');
    } finally {
      await b.transport.stop();
    }
  });

  it('per-trust-domain enforces local CRLs and leaves domains without CRLs unchecked', async () => {
    const b = await bench('per-trust-domain', async (local) => [await local.crl(['0a02'])]);
    try {
      expect(await b.call(b.good)).toBe(200);
      expect(await b.call(b.revoked)).toBe(401);
      expect(b.audit.log).toHaveBeenCalledWith(
        expect.objectContaining({ denial_reason: 'SVID_INVALID: certificate revoked' }),
      );
      expect(await b.call(b.partnerPeer)).toBe(200);
    } finally {
      await b.transport.stop();
    }
  });

  it('per-trust-domain refuses everyone when a CRL carries an unsupported critical extension', async () => {
    const b = await bench('per-trust-domain', async (local) => [
      await local.crl([], { criticalIdp: true }),
    ]);
    try {
      expect(await b.call(b.good)).toBe(401);
      expect(await b.call(b.partnerPeer)).toBe(401);
      expect(b.audit.log).toHaveBeenCalledWith(
        expect.objectContaining({
          denial_reason: 'SVID_INVALID: unusable CRL in the Workload API snapshot',
        }),
      );
    } finally {
      await b.transport.stop();
    }
  });
});

describe('checkRevocation', () => {
  it('parses an OpenSSL CRL and reads its revoked serials', async () => {
    const ca = await opensslCa('Synthetic OpenSSL parse CA');
    cas.push(ca);
    await ca.issue(localCaller, '0a02');
    const crl = parseCrl(await ca.crl(['0a02']));
    expect([...crl.revoked]).toEqual(['A02']);
    expect(crl.nextUpdate.getTime()).toBeGreaterThan(Date.now());
  });

  it('requires a current CRL for every issuer once a domain publishes one', async () => {
    const { X509Certificate } = await import('node:crypto');
    const root = await syntheticCa();
    const mid = await root.intermediate();
    const peer = await mid.issue(localCaller);
    const path = [...peer.certChain, root.der].map((d) => new X509Certificate(Buffer.from(d)));
    const anchors = [new X509Certificate(Buffer.from(root.der))];
    const now = new Date();
    expect(checkRevocation(path, anchors, [await root.crl([])], now)).toBe(
      'no current CRL for an issuer in the peer chain',
    );
    expect(checkRevocation(path, anchors, [await root.crl([]), await mid.crl([])], now)).toBeNull();
    const expired = await mid.crl([], { nextUpdate: new Date(Date.now() - 1000) });
    expect(checkRevocation(path, anchors, [await root.crl([]), expired], now)).toBe(
      'no current CRL for an issuer in the peer chain',
    );
    const other = await syntheticCa();
    expect(checkRevocation(path, anchors, [await other.crl([])], now)).toBeNull();
    expect(checkRevocation(path, anchors, [new Uint8Array([0x30, 0x00])], now)).toBe(
      'unusable CRL in the Workload API snapshot',
    );
  });
});
