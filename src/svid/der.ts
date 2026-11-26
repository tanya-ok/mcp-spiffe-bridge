// Minimal DER reading for the certificate and CRL fields the library checks itself.
import type { X509Certificate } from 'node:crypto';

export class DerError extends Error {}

export interface Tlv {
  readonly tag: number;
  readonly start: number;
  readonly contentStart: number;
  readonly end: number;
}

export function readTlv(buf: Buffer, offset: number, limit = buf.length): Tlv {
  if (offset + 2 > limit) throw new DerError('truncated DER');
  const tag = buf[offset] as number;
  let len = buf[offset + 1] as number;
  let contentStart = offset + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4 || contentStart + n > limit) throw new DerError('bad DER length');
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + (buf[contentStart + i] as number);
    contentStart += n;
  }
  const end = contentStart + len;
  if (end > limit) throw new DerError('truncated DER');
  return { tag, start: offset, contentStart, end };
}

export function children(buf: Buffer, parent: Tlv): Tlv[] {
  const out: Tlv[] = [];
  let offset = parent.contentStart;
  while (offset < parent.end) {
    const child = readTlv(buf, offset, parent.end);
    out.push(child);
    offset = child.end;
  }
  return out;
}

export function expect(tlv: Tlv | undefined, tag: number, what: string): Tlv {
  if (!tlv || tlv.tag !== tag) throw new DerError(`expected ${what}`);
  return tlv;
}

export function oid(buf: Buffer, tlv: Tlv): string {
  const bytes = buf.subarray(tlv.contentStart, tlv.end);
  if (bytes.length === 0) throw new DerError('empty OID');
  const first = bytes[0] as number;
  const parts = [
    Math.min(2, Math.floor(first / 40)),
    first - Math.min(2, Math.floor(first / 40)) * 40,
  ];
  let value = 0;
  for (const byte of bytes.subarray(1)) {
    value = value * 128 + (byte & 0x7f);
    if (!(byte & 0x80)) {
      parts.push(value);
      value = 0;
    }
  }
  return parts.join('.');
}

function tbsFields(cert: X509Certificate): { buf: Buffer; fields: Tlv[]; offset: number } {
  const buf = cert.raw;
  const tbs = expect(children(buf, readTlv(buf, 0))[0], 0x30, 'TBSCertificate');
  const fields = children(buf, tbs);
  return { buf, fields, offset: fields[0]?.tag === 0xa0 ? 1 : 0 };
}

/** Subject Name DER of a certificate. */
export function subjectDer(cert: X509Certificate): Buffer {
  const { buf, fields, offset } = tbsFields(cert);
  const subject = expect(fields[offset + 4], 0x30, 'subject');
  return Buffer.from(buf.subarray(subject.start, subject.end));
}

export const KEY_USAGE = { keyCertSign: 0x04, cRLSign: 0x02 } as const;

/**
 * True when the certificate has no keyUsage extension or its keyUsage sets
 * `bit`. RFC 5280: a present keyUsage must assert keyCertSign for CA use.
 */
export function hasKeyUsage(cert: X509Certificate, bit: number): boolean {
  const { buf, fields } = tbsFields(cert);
  const wrapper = fields.find((f) => f.tag === 0xa3);
  if (!wrapper) return true;
  const list = expect(readTlv(buf, wrapper.contentStart, wrapper.end), 0x30, 'extensions');
  for (const ext of children(buf, list)) {
    const parts = children(buf, expect(ext, 0x30, 'extension'));
    if (oid(buf, expect(parts[0], 0x06, 'extension OID')) !== '2.5.29.15') continue;
    const value = expect(parts[parts.length - 1], 0x04, 'extension value');
    const bits = expect(readTlv(buf, value.contentStart, value.end), 0x03, 'keyUsage');
    const first = buf[bits.contentStart + 1];
    return bits.end - bits.contentStart > 1 && ((first ?? 0) & bit) !== 0;
  }
  return true;
}
