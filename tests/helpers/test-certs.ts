import { webcrypto } from 'node:crypto';
import * as x509 from '@peculiar/x509';

x509.cryptoProvider.set(webcrypto as unknown as Crypto);

/**
 * Generate a self-signed X.509 certificate with a SPIFFE URI SAN, suitable
 * for feeding into `SpiffeValidator.validate()` in tests.
 *
 * The cert is self-signed because we bypass chain validation in unit tests;
 * production chain validation is the TLS layer's job, not the validator's.
 */
export async function makeSpiffeCert(options: {
  spiffeId: string;
  notBefore?: Date;
  notAfter?: Date;
  additionalUris?: string[];
}): Promise<{ certDer: Uint8Array; privateKeyDer: Uint8Array }> {
  const keys = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'sign',
    'verify',
  ]);
  const now = new Date();
  const notBefore = options.notBefore ?? new Date(now.getTime() - 60_000);
  const notAfter = options.notAfter ?? new Date(now.getTime() + 3600_000);

  const sanValues: x509.JsonGeneralName[] = [
    { type: 'url', value: options.spiffeId },
    ...(options.additionalUris?.map((u) => ({ type: 'url' as const, value: u })) ?? []),
  ];

  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: '01',
    name: `CN=${options.spiffeId}`,
    notBefore,
    notAfter,
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
    keys,
    extensions: [
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.SubjectAlternativeNameExtension(sanValues),
    ],
  });

  const privateKeyPkcs8 = await webcrypto.subtle.exportKey('pkcs8', keys.privateKey);
  return {
    certDer: new Uint8Array(cert.rawData),
    privateKeyDer: new Uint8Array(privateKeyPkcs8),
  };
}
