import type { CallerMatcher, SpiffeId, SpiffeIdString, TrustDomainString } from './types.js';

const SPIFFE_SCHEME = 'spiffe://';
const MAX_TOTAL_LENGTH = 2048;
const MAX_TRUST_DOMAIN_LENGTH = 255;

// SPIFFE-ID spec allows lowercase ASCII, digits, and `-` `.` `_` in the
// trust domain; path segments additionally allow a few more unreserved chars.
const TRUST_DOMAIN_RE = /^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$/;
const PATH_SEGMENT_RE = /^[A-Za-z0-9._~!$&'()*+,;=:@-]+$/;

/**
 * Parse a SPIFFE ID string per the SPIFFE specification.
 * Returns `null` if the input is not a syntactically valid SPIFFE ID.
 *
 * Intentionally strict: path segments `.` and `..` are rejected so that
 * allowlist glob matching cannot be subverted by path traversal tricks.
 */
export function parseSpiffeId(raw: string): SpiffeId | null {
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > MAX_TOTAL_LENGTH) {
    return null;
  }
  if (!raw.startsWith(SPIFFE_SCHEME)) {
    return null;
  }

  const rest = raw.slice(SPIFFE_SCHEME.length);
  const firstSlash = rest.indexOf('/');

  const trustDomainRaw = firstSlash === -1 ? rest : rest.slice(0, firstSlash);
  const pathRaw = firstSlash === -1 ? '' : rest.slice(firstSlash);

  if (trustDomainRaw.length === 0 || trustDomainRaw.length > MAX_TRUST_DOMAIN_LENGTH) {
    return null;
  }
  if (!TRUST_DOMAIN_RE.test(trustDomainRaw)) {
    return null;
  }

  if (pathRaw.length > 0) {
    if (!pathRaw.startsWith('/')) return null;
    // Disallow trailing slash, empty segments, and path traversal tokens.
    if (pathRaw.endsWith('/')) return null;
    const segments = pathRaw.slice(1).split('/');
    for (const seg of segments) {
      if (seg.length === 0 || seg === '.' || seg === '..') return null;
      if (!PATH_SEGMENT_RE.test(seg)) return null;
    }
  }

  return {
    trustDomain: trustDomainRaw as TrustDomainString,
    path: pathRaw,
    full: raw as SpiffeIdString,
  };
}

/** Non-throwing equality check on the full form. */
export function spiffeIdEquals(a: SpiffeId, b: SpiffeId): boolean {
  return a.full === b.full;
}

// ─────────────────────────────────────────────────────────────────────
// Allowlist matching
// ─────────────────────────────────────────────────────────────────────

/**
 * Check whether `id` matches any entry in `matchers`.
 * Each matcher is either an exact SPIFFE ID string or a pattern with `*`
 * wildcards. The `*` wildcard matches any characters except `/`, so it
 * behaves as a single path-segment wildcard:
 *
 *   spiffe://td/svc/*           matches spiffe://td/svc/foo
 *                               matches spiffe://td/svc/bar
 *                     does NOT  match   spiffe://td/svc/foo/bar
 *
 * Use `**` to match across path separators.
 */
export function matchesAllowlist(id: SpiffeId, matchers: readonly CallerMatcher[]): boolean {
  for (const m of matchers) {
    if (matchesOne(id.full, m)) return true;
  }
  return false;
}

function matchesOne(idFull: string, matcher: string): boolean {
  if (!matcher.includes('*')) {
    return idFull === matcher;
  }
  const re = globToRegExp(matcher);
  return re.test(idFull);
}

function globToRegExp(glob: string): RegExp {
  let out = '^';
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === '*') {
      if (glob[i + 1] === '*') {
        out += '.*';
        i++;
      } else {
        out += '[^/]*';
      }
    } else if (c !== undefined && /[.+?^${}()|[\]\\]/.test(c)) {
      out += `\\${c}`;
    } else if (c !== undefined) {
      out += c;
    }
  }
  out += '$';
  return new RegExp(out);
}
