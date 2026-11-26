import { X509Certificate } from 'node:crypto';
import {
  SpiffeIdDisallowedError,
  SvidExpiredError,
  SvidInvalidError,
  SvidNotYetValidError,
  TrustDomainMismatchError,
} from '../errors.js';
import { matchesAllowlist, parseSpiffeId } from '../spiffe-id.js';
import type {
  SpiffeIdString,
  SvidFetcher,
  SvidValidator,
  TrustDomainString,
  ValidationResult,
  ValidatorOptions,
  X509Svid,
} from '../types.js';
import { verifyPathToAnchors } from './path.js';

/**
 * Validator for peer X.509-SVIDs.
 *
 * Responsibilities (SPIFFE-specific checks layered on top of TLS):
 *   1. Cert parses.
 *   2. Subject Alternative Name contains exactly one `URI:spiffe://…` entry.
 *   3. SPIFFE ID parses per the SPIFFE spec.
 *   4. Trust domain is the local domain or a configured federated domain whose
 *      bundle is currently available. With federation configured, the peer
 *      chain must lead to the bundle of the peer's own trust domain.
 *   5. Remaining TTL is >= `minTtlSeconds` and not yet expired / not yet valid.
 *   6. SPIFFE ID matches at least one `allowedCallers` entry.
 *
 * Chain validation is NOT re-done here. It is the TLS layer's job using the
 * trust bundle fetched from SPIRE (see `transport/mtls.ts`). This validator
 * runs against already-TLS-validated certs.
 */
export class SpiffeValidator implements SvidValidator {
  constructor(
    private readonly options: ValidatorOptions,
    /** Source of the local trust domain, the only one accepted. */
    private readonly ownFetcher: SvidFetcher,
  ) {}

  async validate(
    peerCertDer: Uint8Array,
    now: Date = new Date(),
    peerChainDer?: readonly Uint8Array[],
  ): Promise<ValidationResult> {
    let cert: X509Certificate;
    try {
      cert = new X509Certificate(Buffer.from(peerCertDer));
    } catch (err) {
      return fail(new SvidInvalidError('failed to parse peer certificate', null, { cause: err }));
    }

    const spiffeIdRaw = extractSpiffeUriFromSan(cert.subjectAltName);
    if (!spiffeIdRaw) {
      return fail(new SvidInvalidError('peer certificate has no SPIFFE URI in SAN', null));
    }

    const parsedId = parseSpiffeId(spiffeIdRaw);
    if (!parsedId) {
      return fail(
        new SvidInvalidError(
          `peer certificate SAN contains malformed SPIFFE ID: ${spiffeIdRaw}`,
          spiffeIdRaw as SpiffeIdString,
        ),
      );
    }

    // Trust domain check
    const own = await this.ownFetcher.getX509Svid();
    const allowedTds = this.allowedTrustDomains(own);
    if (!allowedTds.has(parsedId.trustDomain)) {
      return fail(
        new TrustDomainMismatchError(
          `trust domain ${parsedId.trustDomain} not in allowed set {${[...allowedTds].join(', ')}}`,
          parsedId.full,
        ),
      );
    }
    const federated = this.options.federatedTrustDomains ?? [];
    if (peerChainDer !== undefined || federated.length > 0) {
      const anchors = anchorsFor(own, parsedId.trustDomain, federated);
      if (!verifyPathToAnchors(peerCertDer, peerChainDer ?? [], anchors, now)) {
        return fail(
          new TrustDomainMismatchError(
            `peer chain does not lead to the trust bundle of ${parsedId.trustDomain}`,
            parsedId.full,
          ),
        );
      }
    }

    // Validity window
    const notBefore = new Date(cert.validFrom);
    const notAfter = new Date(cert.validTo);
    if (now < notBefore) {
      return fail(
        new SvidNotYetValidError(
          `peer cert not valid until ${notBefore.toISOString()}`,
          parsedId.full,
        ),
      );
    }
    const remainingSec = Math.floor((notAfter.getTime() - now.getTime()) / 1000);
    if (remainingSec <= 0) {
      return fail(
        new SvidExpiredError(`peer cert expired at ${notAfter.toISOString()}`, parsedId.full),
      );
    }
    if (remainingSec < this.options.minTtlSeconds) {
      return fail(
        new SvidExpiredError(
          `peer cert remaining TTL ${remainingSec}s is below minTtlSeconds ${this.options.minTtlSeconds}s`,
          parsedId.full,
        ),
      );
    }

    // Allowlist check
    if (!matchesAllowlist(parsedId, this.options.allowedCallers)) {
      return fail(
        new SpiffeIdDisallowedError(
          `SPIFFE ID ${parsedId.full} is not in the allowlist`,
          parsedId.full,
        ),
      );
    }

    return {
      ok: true,
      identity: {
        spiffeId: parsedId,
        notBefore,
        notAfter,
        peerCertDer,
      },
    };
  }

  /** Local domain plus configured federated domains with a current bundle, narrowed by any pin. */
  private allowedTrustDomains(own: X509Svid): ReadonlySet<TrustDomainString> {
    const local = own.spiffeId.trustDomain;
    const candidates = [
      local,
      ...(this.options.federatedTrustDomains ?? []).filter(
        (td) => td !== local && (own.federatedBundles?.get(td)?.length ?? 0) > 0,
      ),
    ];
    const pinned = this.options.allowedTrustDomains;
    if (!pinned || pinned.length === 0) return new Set(candidates);
    return new Set(candidates.filter((td) => pinned.includes(td)));
  }
}

// ─── helpers ────────────────────────────────────────────────────────────

/**
 * Extract the SPIFFE URI from an X.509 `subjectAltName` field.
 * Node returns SAN as a string like: `URI:spiffe://td/foo, DNS:example.com`.
 * SPIFFE mandates exactly one URI SAN containing the ID.
 */
export function extractSpiffeUriFromSan(san: string | undefined): string | null {
  if (!san) return null;
  const entries = san.split(',').map((s) => s.trim());
  const uris = entries.filter((e) => e.startsWith('URI:')).map((e) => e.slice('URI:'.length));
  const spiffeUris = uris.filter((u) => u.startsWith('spiffe://'));
  if (spiffeUris.length !== 1) return null;
  return spiffeUris[0] ?? null;
}

/**
 * Anchors that may authenticate `trustDomain`: the local bundle for the local
 * domain, or the federated bundle of a configured federated domain. Empty when
 * the domain is not trusted.
 */
export function anchorsFor(
  own: X509Svid,
  trustDomain: TrustDomainString,
  federated: readonly TrustDomainString[],
): readonly Uint8Array[] {
  if (trustDomain === own.spiffeId.trustDomain) return own.trustBundle;
  if (!federated.includes(trustDomain)) return [];
  return own.federatedBundles?.get(trustDomain) ?? [];
}

function fail(
  error:
    | SvidInvalidError
    | SvidExpiredError
    | SvidNotYetValidError
    | SpiffeIdDisallowedError
    | TrustDomainMismatchError,
): ValidationResult {
  return {
    ok: false,
    error: {
      code: error.code,
      message: error.message,
      observedSpiffeId: error.observedSpiffeId,
    },
  };
}
