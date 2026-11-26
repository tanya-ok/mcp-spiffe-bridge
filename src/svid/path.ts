import { X509Certificate } from 'node:crypto';
import { hasKeyUsage, KEY_USAGE } from './der.js';

const MAX_DEPTH = 8;

/**
 * Independent path validation against one trust domain's anchors.
 *
 * Every certificate walked must be inside its validity window at `now`;
 * every issuer must be a CA whose keyUsage (when present) asserts
 * keyCertSign and whose key verifies the child's signature. The leaf must not
 * be a CA. All candidate paths are explored, so the result does not depend on
 * which path the TLS stack chose. Returns the path from leaf to anchor, or null.
 */
export function verifyPathToAnchors(
  leafDer: Uint8Array,
  candidatesDer: readonly Uint8Array[],
  anchorsDer: readonly Uint8Array[],
  now: Date,
): X509Certificate[] | null {
  const leaf = parse(leafDer);
  if (!leaf || leaf.ca || !within(leaf, now)) return null;
  const anchors = anchorsDer.map(parse).filter((c): c is X509Certificate => c !== null);
  const candidates = candidatesDer.map(parse).filter((c): c is X509Certificate => c !== null);
  const search = (current: X509Certificate, path: X509Certificate[]): X509Certificate[] | null => {
    if (path.length > MAX_DEPTH) return null;
    for (const anchor of anchors) {
      if (validIssuer(current, anchor, now)) return [...path, anchor];
    }
    for (const next of candidates) {
      if (path.some((p) => p.raw.equals(next.raw))) continue;
      if (anchors.some((a) => a.raw.equals(next.raw))) continue;
      if (!validIssuer(current, next, now)) continue;
      const found = search(next, [...path, next]);
      if (found) return found;
    }
    return null;
  };
  return search(leaf, [leaf]);
}

function validIssuer(child: X509Certificate, issuer: X509Certificate, now: Date): boolean {
  try {
    return (
      issuer.ca &&
      within(issuer, now) &&
      hasKeyUsage(issuer, KEY_USAGE.keyCertSign) &&
      child.checkIssued(issuer) &&
      child.verify(issuer.publicKey)
    );
  } catch {
    return false;
  }
}

function within(cert: X509Certificate, now: Date): boolean {
  return new Date(cert.validFrom) <= now && now < new Date(cert.validTo);
}

function parse(der: Uint8Array): X509Certificate | null {
  try {
    return new X509Certificate(Buffer.from(der));
  } catch {
    return null;
  }
}
