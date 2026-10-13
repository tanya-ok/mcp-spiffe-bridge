import type {
  AuthError,
  SpiffeBridgeErrorCode,
  SpiffeBridgeErrorShape,
  SpiffeIdString,
} from './types.js';

/**
 * Base class for every error raised by this library.
 *
 * Subclasses fix the `code` to a specific literal so callers can discriminate
 * on `error.code` (preferred) or `instanceof` (also supported).
 *
 * All subclasses preserve `cause` via the standard `Error` options bag so
 * stack traces chain through the underlying failure.
 */
export abstract class SpiffeBridgeError extends Error implements SpiffeBridgeErrorShape {
  public abstract readonly code: SpiffeBridgeErrorCode;

  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = new.target.name;
  }
}

// ─── Runtime / infrastructure errors (thrown) ───────────────────────────

export class SvidUnavailableError extends SpiffeBridgeError {
  public readonly code = 'SVID_UNAVAILABLE' as const;
}

export class WorkloadApiConnectionError extends SpiffeBridgeError {
  public readonly code = 'WORKLOAD_API_CONNECTION_FAILED' as const;
}

export class WorkloadApiTimeoutError extends SpiffeBridgeError {
  public readonly code = 'WORKLOAD_API_TIMEOUT' as const;
}

export class ConfigInvalidError extends SpiffeBridgeError {
  public readonly code = 'CONFIG_INVALID' as const;
}

export class TransportError extends SpiffeBridgeError {
  public readonly code = 'TRANSPORT_ERROR' as const;
}

// ─── Authentication errors (returned in ValidationResult) ───────────────

/**
 * Errors in this group satisfy the `AuthError` interface and are returned
 * from `SvidValidator.validate()` rather than thrown. They can also be
 * thrown if a caller prefers that style.
 */
abstract class SpiffeAuthError extends SpiffeBridgeError implements AuthError {
  public abstract override readonly code: AuthError['code'];
  public readonly observedSpiffeId: SpiffeIdString | null;

  constructor(
    message: string,
    observedSpiffeId: SpiffeIdString | null,
    options?: { cause?: unknown },
  ) {
    super(message, options);
    this.observedSpiffeId = observedSpiffeId;
  }
}

export class SvidExpiredError extends SpiffeAuthError {
  public readonly code = 'SVID_EXPIRED' as const;
}

export class SvidNotYetValidError extends SpiffeAuthError {
  public readonly code = 'SVID_NOT_YET_VALID' as const;
}

export class SvidInvalidError extends SpiffeAuthError {
  public readonly code = 'SVID_INVALID' as const;
}

export class SpiffeIdDisallowedError extends SpiffeAuthError {
  public readonly code = 'SPIFFE_ID_DISALLOWED' as const;
}

export class TrustDomainMismatchError extends SpiffeAuthError {
  public readonly code = 'TRUST_DOMAIN_MISMATCH' as const;
}

// ─── Type guards ────────────────────────────────────────────────────────

export function isSpiffeBridgeError(e: unknown): e is SpiffeBridgeError {
  return e instanceof SpiffeBridgeError;
}

export function isAuthError(e: unknown): e is AuthError {
  return (
    e instanceof SpiffeAuthError ||
    (typeof e === 'object' &&
      e !== null &&
      'code' in e &&
      typeof (e as { code: unknown }).code === 'string' &&
      authErrorCodes.has((e as { code: string }).code))
  );
}

const authErrorCodes: ReadonlySet<string> = new Set([
  'SVID_EXPIRED',
  'SVID_NOT_YET_VALID',
  'SVID_INVALID',
  'SPIFFE_ID_DISALLOWED',
  'TRUST_DOMAIN_MISMATCH',
]);
