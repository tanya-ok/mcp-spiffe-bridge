import { randomUUID, webcrypto } from 'node:crypto';
import * as x509 from '@peculiar/x509';
import { describe, expect, it } from 'vitest';
import { verifyPathToAnchors } from '../src/svid/path.js';

x509.cryptoProvider.set(webcrypto as unknown as Crypto);
const alg = { name: 'ECDSA', namedCurve: 'P-256' };
const signingAlgorithm = { name: 'ECDSA', hash: 'SHA-256' };
const hour = 3_600_000;
const now = new Date();
const valid: [Date, Date] = [new Date(Date.now() - hour), new Date(Date.now() + hour)];
const keys = () => webcrypto.subtle.generateKey(alg, true, ['sign', 'verify']);

interface Node {
  cert: x509.X509Certificate;
  keys: CryptoKeyPair;
  der: Uint8Array;
}

async function make(
  opts: {
    issuer?: Node;
    ca?: boolean;
    usage?: number | null;
    window?: [Date, Date];
    subject?: string;
    keys?: CryptoKeyPair;
  } = {},
): Promise<Node> {
  const k = opts.keys ?? (await keys());
  const subject = opts.subject ?? `CN=Synthetic ${randomUUID()}`;
  const ca = opts.ca ?? true;
  const extensions: x509.Extension[] = [new x509.BasicConstraintsExtension(ca, undefined, true)];
  const usage =
    opts.usage === undefined
      ? ca
        ? x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign
        : x509.KeyUsageFlags.digitalSignature
      : opts.usage;
  if (usage !== null) extensions.push(new x509.KeyUsagesExtension(usage, true));
  if (!ca) {
    extensions.push(
      new x509.SubjectAlternativeNameExtension([{ type: 'url', value: 'spiffe://example.org/a' }]),
    );
  }
  const [notBefore, notAfter] = opts.window ?? valid;
  const cert = await x509.X509CertificateGenerator.create({
    subject,
    issuer: opts.issuer?.cert.subject ?? subject,
    publicKey: k.publicKey,
    signingKey: opts.issuer?.keys.privateKey ?? k.privateKey,
    signingAlgorithm,
    notBefore,
    notAfter,
    extensions,
  });
  return { cert, keys: k, der: new Uint8Array(cert.rawData) };
}

describe('verifyPathToAnchors', () => {
  it('accepts leaf to intermediate to anchor and returns the path', async () => {
    const root = await make();
    const mid = await make({ issuer: root });
    const leaf = await make({ issuer: mid, ca: false });
    expect(verifyPathToAnchors(leaf.der, [mid.der], [root.der], now)?.length).toBe(3);
  });

  it('refuses an expired intermediate', async () => {
    const root = await make();
    const mid = await make({ issuer: root, window: [new Date(0), new Date(Date.now() - hour)] });
    const leaf = await make({ issuer: mid, ca: false });
    expect(verifyPathToAnchors(leaf.der, [mid.der], [root.der], now)).toBeNull();
  });

  it('refuses an expired or not yet valid anchor', async () => {
    const root = await make({
      window: [new Date(Date.now() + hour), new Date(Date.now() + 2 * hour)],
    });
    const leaf = await make({ issuer: root, ca: false });
    expect(verifyPathToAnchors(leaf.der, [], [root.der], now)).toBeNull();
  });

  it('refuses an issuer whose keyUsage lacks keyCertSign', async () => {
    const root = await make();
    const mid = await make({ issuer: root, usage: x509.KeyUsageFlags.digitalSignature });
    const leaf = await make({ issuer: mid, ca: false });
    expect(verifyPathToAnchors(leaf.der, [mid.der], [root.der], now)).toBeNull();
  });

  it('accepts an issuer without a keyUsage extension', async () => {
    const root = await make({ usage: null });
    const leaf = await make({ issuer: root, ca: false });
    expect(verifyPathToAnchors(leaf.der, [], [root.der], now)).not.toBeNull();
  });

  it('refuses a non-CA issuer and a CA leaf', async () => {
    const root = await make();
    const notCa = await make({ issuer: root, ca: false });
    const leaf = await make({ issuer: notCa, ca: false });
    expect(verifyPathToAnchors(leaf.der, [notCa.der], [root.der], now)).toBeNull();
    expect(verifyPathToAnchors(root.der, [], [root.der], now)).toBeNull();
  });

  it('explores every candidate, so a bad first candidate does not hide a valid path', async () => {
    const root = await make();
    const subject = `CN=Synthetic shared ${randomUUID()}`;
    const shared = await keys();
    const expired = await make({
      issuer: root,
      subject,
      keys: shared,
      window: [new Date(0), new Date(Date.now() - hour)],
    });
    const current = await make({ issuer: root, subject, keys: shared });
    const leaf = await make({ issuer: current, ca: false });
    expect(
      verifyPathToAnchors(leaf.der, [expired.der, current.der], [root.der], now),
    ).not.toBeNull();
  });

  it('only reaches the anchors it is given', async () => {
    const local = await make();
    const other = await make();
    const leaf = await make({ issuer: other, ca: false });
    expect(verifyPathToAnchors(leaf.der, [other.der], [local.der], now)).toBeNull();
  });
});
