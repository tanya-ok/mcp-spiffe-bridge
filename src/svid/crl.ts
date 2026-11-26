import { verify, type X509Certificate } from 'node:crypto';
import {
  DerError as CrlFormatError,
  children,
  expect,
  hasKeyUsage,
  KEY_USAGE,
  oid,
  readTlv,
  subjectDer,
  type Tlv,
} from './der.js';

/**
 * Minimal X.509 CRL support for the `per-trust-domain` revocation scope.
 *
 * Deliberately narrow and fail closed: only complete, direct CRLs with a
 * nextUpdate are usable. Any critical CRL or entry extension (delta CRLs,
 * issuing distribution points, indirect CRLs) makes the CRL unusable.
 */
export interface ParsedCrl {
  readonly issuer: Buffer;
  readonly thisUpdate: Date;
  readonly nextUpdate: Date;
  readonly revoked: ReadonlySet<string>;
  readonly tbs: Buffer;
  readonly signatureAlgorithm: string;
  readonly signature: Buffer;
}

export { DerError as CrlFormatError } from './der.js';

function time(buf: Buffer, tlv: Tlv): Date {
  const s = buf.subarray(tlv.contentStart, tlv.end).toString('ascii');
  const utc = tlv.tag === 0x17 ? /^(\d{2})(\d{10})Z$/.exec(s) : null;
  const gen = tlv.tag === 0x18 ? /^(\d{4})(\d{10})Z$/.exec(s) : null;
  const m = utc ?? gen;
  if (!m) throw new CrlFormatError('unsupported time encoding');
  let year = Number(m[1]);
  if (utc) year += year >= 50 ? 1900 : 2000;
  const rest = (m[2] ?? '').match(/\d{2}/g)?.map(Number) ?? [];
  const [mon = 0, day = 0, hh = 0, mm = 0, ss = 0] = rest;
  return new Date(Date.UTC(year, mon - 1, day, hh, mm, ss));
}

function isTime(tlv: Tlv | undefined): tlv is Tlv {
  return tlv?.tag === 0x17 || tlv?.tag === 0x18;
}

/** Normalized serial: uppercase hex without leading zeros. */
export function normalizeSerial(hex: string): string {
  const s = hex
    .replace(/[^0-9a-f]/gi, '')
    .toUpperCase()
    .replace(/^0+/, '');
  return s === '' ? '0' : s;
}

function rejectCriticalExtensions(buf: Buffer, extensions: Tlv, where: string): void {
  for (const ext of children(buf, expect(extensions, 0x30, `${where} extensions`))) {
    const parts = children(buf, expect(ext, 0x30, 'extension'));
    const critical = parts[1];
    if (critical?.tag === 0x01 && buf[critical.contentStart] !== 0x00) {
      throw new CrlFormatError(
        `unsupported critical ${where} extension ${oid(buf, parts[0] as Tlv)}`,
      );
    }
  }
}

export function parseCrl(der: Uint8Array): ParsedCrl {
  const buf = Buffer.from(der);
  const outer = expect(readTlv(buf, 0), 0x30, 'CertificateList');
  if (outer.end !== buf.length) throw new CrlFormatError('trailing data');
  const [tbsTlv, algTlv, sigTlv] = children(buf, outer);
  const tbs = expect(tbsTlv, 0x30, 'TBSCertList');
  const alg = expect(algTlv, 0x30, 'signatureAlgorithm');
  const sig = expect(sigTlv, 0x03, 'signatureValue');
  if (buf[sig.contentStart] !== 0x00) throw new CrlFormatError('unsupported BIT STRING padding');

  const fields = children(buf, tbs);
  let i = 0;
  if (fields[i]?.tag === 0x02) i++;
  const innerAlg = expect(fields[i++], 0x30, 'TBS signature');
  if (!buf.subarray(innerAlg.start, innerAlg.end).equals(buf.subarray(alg.start, alg.end))) {
    throw new CrlFormatError('signature algorithm mismatch');
  }
  const issuer = expect(fields[i++], 0x30, 'issuer');
  const thisTlv = fields[i++];
  if (!isTime(thisTlv)) throw new CrlFormatError('expected thisUpdate');
  const nextTlv = fields[i];
  if (!isTime(nextTlv)) throw new CrlFormatError('nextUpdate is required');
  i++;
  const revoked = new Set<string>();
  if (fields[i]?.tag === 0x30) {
    for (const entry of children(buf, fields[i++] as Tlv)) {
      const [serial, date, exts] = children(buf, expect(entry, 0x30, 'revoked entry'));
      const s = expect(serial, 0x02, 'serial');
      if (!isTime(date)) throw new CrlFormatError('expected revocationDate');
      if (exts) rejectCriticalExtensions(buf, exts, 'entry');
      revoked.add(normalizeSerial(buf.subarray(s.contentStart, s.end).toString('hex')));
    }
  }
  if (fields[i]?.tag === 0xa0) {
    const wrapper = fields[i++] as Tlv;
    rejectCriticalExtensions(buf, readTlv(buf, wrapper.contentStart, wrapper.end), 'CRL');
  }
  if (i !== fields.length) throw new CrlFormatError('unexpected TBSCertList field');

  const algParts = children(buf, alg);
  return {
    issuer: Buffer.from(buf.subarray(issuer.start, issuer.end)),
    thisUpdate: time(buf, thisTlv),
    nextUpdate: time(buf, nextTlv),
    revoked,
    tbs: Buffer.from(buf.subarray(tbs.start, tbs.end)),
    signatureAlgorithm: oid(buf, expect(algParts[0], 0x06, 'algorithm OID')),
    signature: Buffer.from(buf.subarray(sig.contentStart + 1, sig.end)),
  };
}

const HASHES: Readonly<Record<string, string | null>> = {
  '1.2.840.10045.4.3.2': 'sha256',
  '1.2.840.10045.4.3.3': 'sha384',
  '1.2.840.10045.4.3.4': 'sha512',
  '1.2.840.113549.1.1.11': 'sha256',
  '1.2.840.113549.1.1.12': 'sha384',
  '1.2.840.113549.1.1.13': 'sha512',
  '1.3.101.112': null,
};

/** True when `issuer` is a CA whose subject and key match the CRL. */
export function crlIssuedBy(crl: ParsedCrl, issuer: X509Certificate): boolean {
  if (
    !issuer.ca ||
    !hasKeyUsage(issuer, KEY_USAGE.cRLSign) ||
    !crl.issuer.equals(subjectDer(issuer))
  )
    return false;
  if (!(crl.signatureAlgorithm in HASHES)) return false;
  try {
    return verify(HASHES[crl.signatureAlgorithm] ?? null, crl.tbs, issuer.publicKey, crl.signature);
  } catch {
    return false;
  }
}

/**
 * `per-trust-domain` revocation for one validated path (leaf first, anchor
 * last). A domain that publishes any CRL (signed by an issuer on this path or
 * by one of the domain's anchors) must have a current CRL for every issuer on
 * the path. Domains without CRLs are not checked. Returns a denial reason or null.
 */
export function checkRevocation(
  path: readonly X509Certificate[],
  domainAnchors: readonly X509Certificate[],
  crlsDer: readonly Uint8Array[],
  now: Date,
): string | null {
  if (crlsDer.length === 0) return null;
  let crls: ParsedCrl[];
  try {
    crls = crlsDer.map(parseCrl);
  } catch {
    return 'unusable CRL in the Workload API snapshot';
  }
  const issuers = path.slice(1);
  const publishes = crls.some((crl) =>
    [...issuers, ...domainAnchors].some((ca) => crlIssuedBy(crl, ca)),
  );
  if (!publishes) return null;
  for (let k = 0; k + 1 < path.length; k++) {
    const child = path[k] as X509Certificate;
    const issuer = path[k + 1] as X509Certificate;
    const current = crls.filter(
      (crl) => crlIssuedBy(crl, issuer) && crl.thisUpdate <= now && now < crl.nextUpdate,
    );
    if (current.length === 0) return 'no current CRL for an issuer in the peer chain';
    const serial = normalizeSerial(child.serialNumber);
    if (current.some((crl) => crl.revoked.has(serial))) return 'certificate revoked';
  }
  return null;
}
