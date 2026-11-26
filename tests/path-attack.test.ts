// Cross-domain path attacks against the per-trust-domain chain binding.
import { randomUUID, webcrypto } from 'node:crypto';
import * as x509 from '@peculiar/x509';
import { describe, expect, it, vi } from 'vitest';
import { parseSpiffeId } from '../src/spiffe-id.js';
import { SpiffeValidator } from '../src/svid/validator.js';
import { MtlsTransportServer } from '../src/transport/mtls.js';
import type {
  SvidFetcher,
  SvidValidator,
  TrustDomainString,
  ValidationResult,
  X509Svid,
} from '../src/types.js';
import { freePort, get } from './helpers/pki.js';

x509.cryptoProvider.set(webcrypto as unknown as Crypto);
const alg = { name: 'ECDSA', namedCurve: 'P-256' };
const sigAlg = { name: 'ECDSA', hash: 'SHA-256' };
const partner = 'partner.example.net' as TrustDomainString;
const hour = 3_600_000;

const keys = () => webcrypto.subtle.generateKey(alg, true, ['sign', 'verify']);
const caExt = () => [
  new x509.BasicConstraintsExtension(true, 2, true),
  new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
];

async function root(name: string, k: CryptoKeyPair) {
  return x509.X509CertificateGenerator.createSelfSigned({
    name,
    keys: k,
    signingAlgorithm: sigAlg,
    notBefore: new Date(Date.now() - hour),
    notAfter: new Date(Date.now() + hour),
    extensions: caExt(),
  });
}

async function issueCa(
  subject: string,
  publicKey: CryptoKey,
  issuer: x509.X509Certificate,
  issuerKey: CryptoKey,
  window: [Date, Date],
) {
  return x509.X509CertificateGenerator.create({
    subject,
    issuer: issuer.subject,
    publicKey,
    signingKey: issuerKey,
    signingAlgorithm: sigAlg,
    notBefore: window[0],
    notAfter: window[1],
    extensions: caExt(),
  });
}

async function leaf(id: string, issuer: string, issuerKey: CryptoKey) {
  const k = await keys();
  const cert = await x509.X509CertificateGenerator.create({
    subject: 'CN=Synthetic attack leaf',
    issuer,
    publicKey: k.publicKey,
    signingKey: issuerKey,
    signingAlgorithm: sigAlg,
    notBefore: new Date(Date.now() - 60_000),
    notAfter: new Date(Date.now() + hour),
    extensions: [
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.SubjectAlternativeNameExtension([
        { type: 'url', value: id },
        { type: 'dns', value: 'localhost' },
      ]),
    ],
  });
  return { cert, key: k.privateKey };
}

async function svid(
  id: string,
  chain: x509.X509Certificate[],
  key: CryptoKey,
  bundle: x509.X509Certificate[],
): Promise<X509Svid> {
  const spiffeId = parseSpiffeId(id);
  if (!spiffeId || !chain[0]) throw new Error('test setup');
  return {
    spiffeId,
    certChain: chain.map((c) => new Uint8Array(c.rawData)),
    privateKey: new Uint8Array(await webcrypto.subtle.exportKey('pkcs8', key)),
    trustBundle: bundle.map((c) => new Uint8Array(c.rawData)),
    notBefore: chain[0].notBefore,
    notAfter: chain[0].notAfter,
  };
}

/** Local root L, partner root B, and an expired local intermediate whose key B re-certified. */
async function scenario() {
  const lKeys = await keys();
  const bKeys = await keys();
  const L = await root(`CN=Synthetic local root ${randomUUID()}`, lKeys);
  const B = await root(`CN=Synthetic partner root ${randomUUID()}`, bKeys);
  const iKeys = await keys();
  const iName = `CN=Synthetic local intermediate ${randomUUID()}`;
  const expired = await issueCa(iName, iKeys.publicKey, L, lKeys.privateKey, [
    new Date(Date.now() - 3 * hour),
    new Date(Date.now() - 2 * hour),
  ]);
  const recertified = await issueCa(iName, iKeys.publicKey, B, bKeys.privateKey, [
    new Date(Date.now() - hour),
    new Date(Date.now() + hour),
  ]);
  const serverLeaf = await leaf('spiffe://example.org/mcp/server', L.subject, lKeys.privateKey);
  const own: X509Svid = {
    ...(await svid('spiffe://example.org/mcp/server', [serverLeaf.cert], serverLeaf.key, [L])),
    federatedBundles: new Map([[partner, [new Uint8Array(B.rawData)]]]),
  };
  const forged = await leaf('spiffe://example.org/agent/research', iName, iKeys.privateKey);
  const attacker = await svid(
    'spiffe://example.org/agent/research',
    [forged.cert, expired, recertified],
    forged.key,
    [L],
  );
  return { own, attacker };
}

async function serve(own: X509Svid, validator: (f: SvidFetcher) => SvidValidator) {
  const port = await freePort();
  const fetcher: SvidFetcher = {
    getX509Svid: async () => own,
    watchSvids: () => () => {},
    close: async () => {},
  };
  const handler = vi.fn((_req: unknown, res: import('node:http').ServerResponse) => {
    res.end('served');
  });
  const transport = new MtlsTransportServer({
    fetcher,
    validator: validator(fetcher),
    audit: { log: vi.fn() },
    transport: { mode: 'mtls-server', sse: { host: '127.0.0.1', port } },
    federatedTrustDomains: [partner],
  });
  transport.setAuthorizedHandler(handler);
  await transport.start();
  return { port, handler, transport };
}

describe('cross-domain path attacks', () => {
  it('refuses a local identity signed by an expired local intermediate re-certified by a federated CA', async () => {
    const { own, attacker } = await scenario();
    const s = await serve(
      own,
      (f) =>
        new SpiffeValidator(
          {
            allowedCallers: ['spiffe://example.org/agent/research'],
            minTtlSeconds: 5,
            federatedTrustDomains: [partner],
          },
          f,
        ),
    );
    try {
      const result = await get(s.port, own.trustBundle, attacker).catch((e: Error) => e);
      expect(result instanceof Error ? 'tls-refused' : result.status).not.toBe(200);
      expect(s.handler).not.toHaveBeenCalled();
    } finally {
      await s.transport.stop();
    }
  });

  it('binds chains in the transport even when the validator lacks the federation option', async () => {
    const { own } = await scenario();
    const bKeys = await keys();
    const B = await root(`CN=Synthetic partner root ${randomUUID()}`, bKeys);
    const ownWithB: X509Svid = {
      ...own,
      federatedBundles: new Map([[partner, [new Uint8Array(B.rawData)]]]),
    };
    const forged = await leaf('spiffe://example.org/agent/research', B.subject, bKeys.privateKey);
    const peer = await svid('spiffe://example.org/agent/research', [forged.cert], forged.key, [B]);
    const permissive: (f: SvidFetcher) => SvidValidator = () => ({
      validate: async (der): Promise<ValidationResult> => {
        const id = parseSpiffeId('spiffe://example.org/agent/research');
        if (!id) throw new Error('test setup');
        return {
          ok: true,
          identity: {
            spiffeId: id,
            notBefore: new Date(0),
            notAfter: new Date(),
            peerCertDer: der,
          },
        };
      },
    });
    for (const validator of [
      permissive,
      (f: SvidFetcher) =>
        new SpiffeValidator(
          { allowedCallers: ['spiffe://example.org/agent/research'], minTtlSeconds: 5 },
          f,
        ),
    ]) {
      const s = await serve(ownWithB, validator);
      try {
        const result = await get(s.port, ownWithB.trustBundle, peer);
        expect(result.status).toBe(401);
        expect(s.handler).not.toHaveBeenCalled();
      } finally {
        await s.transport.stop();
      }
    }
  });
});
