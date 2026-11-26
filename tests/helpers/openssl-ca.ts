// Synthetic CA driven by the OpenSSL CLI, used to produce real OpenSSL CRLs.
import { execFileSync } from 'node:child_process';
import { X509Certificate } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseSpiffeId } from '../../src/spiffe-id.js';
import type { X509Svid } from '../../src/types.js';

export interface OpensslCa {
  readonly der: Uint8Array;
  issue(id: string, serial: string): Promise<X509Svid>;
  /** Revoke serials and return a DER CRL produced by `openssl ca -gencrl`. */
  crl(
    revoked: readonly string[],
    opts?: { hours?: number; criticalIdp?: boolean },
  ): Promise<Uint8Array>;
  cleanup(): Promise<void>;
}

const der = (pem: string) =>
  new Uint8Array(Buffer.from(pem.replace(/-----[^-]+-----|\s/g, ''), 'base64'));

export async function opensslCa(name: string): Promise<OpensslCa> {
  const dir = await mkdtemp(join(tmpdir(), 'bridge-openssl-ca-'));
  const run = (...args: string[]) => execFileSync('openssl', args, { cwd: dir, stdio: 'pipe' });
  run('genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', 'ca.key');
  run(
    'req',
    '-new',
    '-x509',
    '-key',
    'ca.key',
    '-days',
    '1',
    '-subj',
    `/CN=${name}`,
    '-out',
    'ca.pem',
    '-addext',
    'basicConstraints=critical,CA:TRUE',
    '-addext',
    'keyUsage=critical,keyCertSign,cRLSign',
  );
  const caDer = der(await readFile(join(dir, 'ca.pem'), 'utf8'));
  const issued = new Map<string, string>();
  return {
    der: caDer,
    async issue(id, serial) {
      const base = `leaf-${serial}`;
      run(
        'genpkey',
        '-algorithm',
        'EC',
        '-pkeyopt',
        'ec_paramgen_curve:P-256',
        '-out',
        `${base}.key`,
      );
      run('req', '-new', '-key', `${base}.key`, '-subj', '/CN=localhost', '-out', `${base}.csr`);
      await writeFile(
        join(dir, `${base}.ext`),
        `basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=URI:${id},DNS:localhost\n`,
      );
      run(
        'x509',
        '-req',
        '-in',
        `${base}.csr`,
        '-CA',
        'ca.pem',
        '-CAkey',
        'ca.key',
        '-set_serial',
        `0x${serial}`,
        '-days',
        '1',
        '-extfile',
        `${base}.ext`,
        '-out',
        `${base}.pem`,
      );
      const pem = await readFile(join(dir, `${base}.pem`), 'utf8');
      issued.set(serial, `${base}.pem`);
      const cert = new X509Certificate(pem);
      const keyDer = run('pkcs8', '-topk8', '-nocrypt', '-in', `${base}.key`, '-outform', 'DER');
      const spiffeId = parseSpiffeId(id);
      if (!spiffeId) throw new Error('invalid test identity');
      return {
        spiffeId,
        certChain: [new Uint8Array(cert.raw)],
        privateKey: new Uint8Array(keyDer),
        trustBundle: [caDer],
        notBefore: new Date(cert.validFrom),
        notAfter: new Date(cert.validTo),
      };
    },
    async crl(revoked, opts) {
      await writeFile(join(dir, 'index.txt'), '');
      await writeFile(join(dir, 'crlnumber'), '01\n');
      const ext = opts?.criticalIdp ? 'crl_extensions = crl_ext\n' : '';
      await writeFile(
        join(dir, 'ca.cnf'),
        `[ca]\ndefault_ca = d\n[d]\ndir = .\ndatabase = index.txt\ncrlnumber = crlnumber\ndefault_md = sha256\ncertificate = ca.pem\nprivate_key = ca.key\n${ext}[crl_ext]\nissuingDistributionPoint = critical, @idp\n[idp]\nfullname = URI:http://example.invalid/crl\n`,
      );
      for (const serial of revoked) {
        const file = issued.get(serial);
        if (!file) throw new Error(`unknown serial ${serial}`);
        run('ca', '-config', 'ca.cnf', '-revoke', file, '-batch');
      }
      run(
        'ca',
        '-config',
        'ca.cnf',
        '-gencrl',
        '-crlhours',
        String(opts?.hours ?? 1),
        '-out',
        'crl.pem',
        '-batch',
      );
      return new Uint8Array(run('crl', '-in', 'crl.pem', '-outform', 'DER'));
    },
    cleanup: () => rm(dir, { recursive: true, force: true }),
  };
}
