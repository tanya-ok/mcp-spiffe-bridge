// ─── Public API: factory + types ────────────────────────────────────────

export { StdoutJsonAuditLogger } from './audit/logger.js';
export { createMcpSpiffeBridge, McpSpiffeBridgeImpl } from './bridge.js';
export { validateBridgeOptions } from './config.js';
// ─── Errors ─────────────────────────────────────────────────────────────
export {
  ConfigInvalidError,
  isAuthError,
  isSpiffeBridgeError,
  SpiffeBridgeError,
  SpiffeIdDisallowedError,
  SvidExpiredError,
  SvidInvalidError,
  SvidNotYetValidError,
  SvidUnavailableError,
  TransportError,
  TrustDomainMismatchError,
  WorkloadApiConnectionError,
  WorkloadApiTimeoutError,
} from './errors.js';
export { matchesAllowlist, parseSpiffeId, spiffeIdEquals } from './spiffe-id.js';
export { WorkloadApiSvidFetcher } from './svid/fetcher.js';
export { SpiffeValidator } from './svid/validator.js';
export {
  callerContext,
  getCallContext,
  getCallerIdentity,
  runWithCallContext,
} from './transport/context.js';
export {
  type AuthorizedRequestHandler,
  MtlsTransportServer,
  type MtlsTransportServerOptions,
} from './transport/mtls.js';

// ─── Types (type-only re-exports) ───────────────────────────────────────
export type {
  AuditLogger,
  AuthError,
  BridgeOptions,
  CallerMatcher,
  DegradeMode,
  DegradeOptions,
  McpSpiffeBridge,
  MinTlsVersion,
  SpiffeAuditEvent,
  SpiffeAuditEventType,
  SpiffeAuditOutcome,
  SpiffeBridgeErrorCode,
  SpiffeBridgeErrorShape,
  SpiffeCallContext,
  SpiffeId,
  SpiffeIdString,
  SvidFetcher,
  SvidValidator,
  SvidWatcher,
  TransportMode,
  TransportOptions,
  TrustDomainString,
  ValidatedIdentity,
  ValidationResult,
  ValidatorOptions,
  WorkloadApiOptions,
  X509Svid,
} from './types.js';
