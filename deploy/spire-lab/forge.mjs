// Forge the attacker material for the bench from the synthetic upstream roots of both domains.
// node deploy/spire-lab/forge.mjs <work dir>
import 'reflect-metadata';
import { randomUUID, webcrypto } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import * as x509 from '@peculiar/x509';

x509.cryptoProvider.set(webcrypto);
const work = process.argv[2];
const alg = { name: 'ECDSA', namedCurve: 'P-256' };
const signingAlgorithm = { name: 'ECDSA', hash: 'SHA-256' };
const hour = 3_600_000;
const localId = 'spiffe://example.org/agent/research';

async function loadRoot(dir) {
  const cert = new x509.X509Certificate(await readFile(join(work, dir, 'ca.pem'), 'utf8'));
  const keyPem = await readFile(join(work, dir, 'ca.key'), 'utf8');
  const der = Buffer.from(keyPem.replace(/-----[^-]+-----|\s/g, ''), 'base64');
  const key = await webcrypto.subtle.importKey('pkcs8', der, alg, false, ['sign']);
  return { cert, key };
}
const caExt = () => [
  new x509.BasicConstraintsExtension(true, 0, true),
  new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
];
async function leaf(issuer, issuerKey) {
  const keys = await webcrypto.subtle.generateKey(alg, true, ['sign', 'verify']);
  const cert = await x509.X509CertificateGenerator.create({
    subject: 'CN=Synthetic forged workload',
    issuer,
    publicKey: keys.publicKey,
    signingKey: issuerKey,
    signingAlgorithm,
    notBefore: new Date(Date.now() - 60_000),
    notAfter: new Date(Date.now() + hour),
    extensions: [
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
      new x509.SubjectAlternativeNameExtension([{ type: 'url', value: localId }]),
    ],
  });
  const pkcs8 = await webcrypto.subtle.exportKey('pkcs8', keys.privateKey);
  return { cert, keyPem: x509.PemConverter.encode(pkcs8, 'PRIVATE KEY') };
}
async function write(name, chain, keyPem) {
  const dir = join(work, 'forged', name);
  await mkdir(dir, { recursive: true });
  await writeFile(join(dir, 'chain.pem'), chain.map((c) => c.toString('pem')).join('\n'));
  await writeFile(join(dir, 'key.pem'), keyPem, { mode: 0o644 });
}

const a = await loadRoot('ca-a');
const b = await loadRoot('ca-b');

// 1. Federated root B signs a leaf claiming a local SPIFFE ID.
const cross = await leaf(b.cert.subject, b.key);
await write('cross-domain', [cross.cert], cross.keyPem);

// 2. Expired local intermediate whose key B re-certified with the same subject.
const iKeys = await webcrypto.subtle.generateKey(alg, true, ['sign', 'verify']);
const iName = `CN=Synthetic local intermediate ${randomUUID()}`;
const expired = await x509.X509CertificateGenerator.create({
  subject: iName,
  issuer: a.cert.subject,
  publicKey: iKeys.publicKey,
  signingKey: a.key,
  signingAlgorithm,
  notBefore: new Date(Date.now() - 3 * hour),
  notAfter: new Date(Date.now() - 2 * hour),
  extensions: caExt(),
});
const recertified = await x509.X509CertificateGenerator.create({
  subject: iName,
  issuer: b.cert.subject,
  publicKey: iKeys.publicKey,
  signingKey: b.key,
  signingAlgorithm,
  notBefore: new Date(Date.now() - hour),
  notAfter: new Date(Date.now() + hour),
  extensions: caExt(),
});
const attack = await leaf(iName, iKeys.privateKey);
await write('expired-intermediate', [attack.cert, expired, recertified], attack.keyPem);
console.log('forged material written');
