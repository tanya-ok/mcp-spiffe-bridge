// Synthetic PKI for TLS tests: CAs, intermediates, SVIDs and CRLs generated in memory.
import { randomUUID, webcrypto } from 'node:crypto';
import * as https from 'node:https';
import * as net from 'node:net';
import * as x509 from '@peculiar/x509';
import { parseSpiffeId } from '../../src/spiffe-id.js';
import type { X509Svid } from '../../src/types.js';

x509.cryptoProvider.set(webcrypto as unknown as Crypto);
const algorithm = { name: 'ECDSA', namedCurve: 'P-256' };
const signingAlgorithm = { name: 'ECDSA', hash: 'SHA-256' };

export interface SyntheticCa {
  readonly der: Uint8Array;
  issue(id: string, opts?: { expires?: Date; serial?: string }): Promise<X509Svid>;
  intermediate(): Promise<SyntheticCa>;
  crl(revokedSerials: readonly string[], opts?: { nextUpdate?: Date }): Promise<Uint8Array>;
}

export async function syntheticCa(
  parent?: { keys: CryptoKeyPair; cert: x509.X509Certificate },
  roots?: readonly Uint8Array[],
): Promise<SyntheticCa> {
  const keys = await webcrypto.subtle.generateKey(algorithm, true, ['sign', 'verify']);
  const name = `CN=Synthetic test CA ${randomUUID()}`;
  const notBefore = new Date(Date.now() - 60_000);
  const notAfter = new Date(Date.now() + 3_600_000);
  const extensions = [
    new x509.BasicConstraintsExtension(true, parent ? 0 : 1, true),
    new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
  ];
  const cert = parent
    ? await x509.X509CertificateGenerator.create({
        subject: name,
        issuer: parent.cert.subject,
        publicKey: keys.publicKey,
        signingKey: parent.keys.privateKey,
        signingAlgorithm,
        notBefore,
        notAfter,
        extensions,
      })
    : await x509.X509CertificateGenerator.createSelfSigned({
        name,
        keys,
        signingAlgorithm,
        notBefore,
        notAfter,
        extensions,
      });
  const der = new Uint8Array(cert.rawData);
  const bundle = roots ?? [der];
  const chainTail = parent ? [der] : [];
  return {
    der,
    async issue(id, opts) {
      const leafKeys = await webcrypto.subtle.generateKey(algorithm, true, ['sign', 'verify']);
      const leaf = await x509.X509CertificateGenerator.create({
        serialNumber: opts?.serial,
        subject: 'CN=Synthetic test workload',
        issuer: cert.subject,
        publicKey: leafKeys.publicKey,
        signingKey: keys.privateKey,
        signingAlgorithm,
        notBefore,
        notAfter: opts?.expires ?? notAfter,
        extensions: [
          new x509.BasicConstraintsExtension(false, undefined, true),
          new x509.SubjectAlternativeNameExtension([
            { type: 'url', value: id },
            { type: 'dns', value: 'localhost' },
          ]),
        ],
      });
      const spiffeId = parseSpiffeId(id);
      if (!spiffeId) throw new Error('invalid test identity');
      return {
        spiffeId,
        certChain: [new Uint8Array(leaf.rawData), ...chainTail],
        trustBundle: bundle,
        privateKey: new Uint8Array(await webcrypto.subtle.exportKey('pkcs8', leafKeys.privateKey)),
        notBefore: leaf.notBefore,
        notAfter: leaf.notAfter,
      };
    },
    intermediate() {
      return syntheticCa({ keys, cert }, bundle);
    },
    async crl(revokedSerials, opts) {
      const crl = await x509.X509CrlGenerator.create({
        issuer: cert.subject,
        thisUpdate: new Date(Date.now() - 60_000),
        nextUpdate: opts?.nextUpdate ?? new Date(Date.now() + 3_600_000),
        signingKey: keys.privateKey,
        signingAlgorithm,
        entries: revokedSerials.map((serialNumber) => ({
          serialNumber,
          revocationDate: new Date(Date.now() - 30_000),
        })),
      });
      return new Uint8Array(crl.rawData);
    },
  };
}

export function pem(label: string, value: Uint8Array): string {
  const body = Buffer.from(value)
    .toString('base64')
    .match(/.{1,64}/g)
    ?.join('\n');
  return `-----BEGIN ${label}-----\n${body}\n-----END ${label}-----`;
}

export async function freePort(): Promise<number> {
  const server = net.createServer();
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('port unavailable');
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return address.port;
}

/** HTTPS GET with server verification against `serverTrust` and an optional client SVID. */
export function get(
  port: number,
  serverTrust: readonly Uint8Array[],
  client?: X509Svid,
): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = https.get(
      {
        hostname: 'localhost',
        port,
        family: 4,
        agent: false,
        ca: serverTrust.map((c) => pem('CERTIFICATE', c)),
        ...(client
          ? {
              cert: client.certChain.map((c) => pem('CERTIFICATE', c)).join('\n'),
              key: pem('PRIVATE KEY', client.privateKey),
            }
          : {}),
      },
      (res) => {
        let body = '';
        res.on('data', (chunk) => {
          body += chunk;
        });
        res.on('end', () => resolve({ status: res.statusCode ?? 0, body }));
      },
    );
    req.on('error', reject);
  });
}
