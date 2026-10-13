/**
 * Public API surface for mcp-spiffe-bridge.
 *
 * Design notes:
 *  - All identity material is exposed as Uint8Array at the public boundary.
 *    Node Buffer is a Uint8Array subclass, so internal gRPC/Buffer values
 *    pass through without copying.
 *  - Validation returns a discriminated `ValidationResult` instead of
 *    throwing, so callers can audit denials without try/catch ceremony.
 *  - `SvidFetcher`, `SvidValidator`, `AuditLogger` are interfaces; every
 *    concrete implementation is swappable for tests.
 */

// ─────────────────────────────────────────────────────────────────────
// SPIFFE identity primitives
// ─────────────────────────────────────────────────────────────────────

/** Opaque brand for a validated SPIFFE ID string (`spiffe://td/path`). */
export type SpiffeIdString = string & { readonly __brand: 'SpiffeIdString' };

/** Opaque brand for a validated trust domain (e.g. `prod.example.org`). */
export type TrustDomainString = string & { readonly __brand: 'TrustDomainString' };

/** Parsed SPIFFE ID. Construct via `parseSpiffeId`. */
export interface SpiffeId {
  readonly trustDomain: TrustDomainString;
  /** Path component including leading slash, or empty string for trust-domain-only IDs. */
  readonly path: string;
  /** Full string form `spiffe://<trustDomain><path>`. */
  readonly full: SpiffeIdString;
}

// ─────────────────────────────────────────────────────────────────────
// SVID material as delivered by the Workload API
// ─────────────────────────────────────────────────────────────────────

/**
 * X.509 SVID issued to this workload.
 * `certChain` is DER-encoded, leaf certificate first.
 * `privateKey` is PKCS#8 DER.
 * `trustBundle` holds CA certs for the issuer's own trust domain.
 * `federatedBundles` holds CA certs for other trust domains. They are parsed but
 * not trusted, because federation is unsupported.
 */
export interface X509Svid {
  readonly spiffeId: SpiffeId;
  readonly certChain: readonly Uint8Array[];
  readonly privateKey: Uint8Array;
  readonly notBefore: Date;
  readonly notAfter: Date;
  readonly trustBundle: readonly Uint8Array[];
  readonly federatedBundles?: ReadonlyMap<TrustDomainString, readonly Uint8Array[]>;
}

/**
 * An identity that passed validation: SPIFFE ID extracted, expiry within
 * `minTtlSeconds`, allowlist match confirmed.
 */
export interface ValidatedIdentity {
  readonly spiffeId: SpiffeId;
  readonly notBefore: Date;
  readonly notAfter: Date;
  /** Leaf cert DER, kept for audit correlation. */
  readonly peerCertDer: Uint8Array;
}

// ─────────────────────────────────────────────────────────────────────
// Errors: referenced here, implemented in errors.ts
// ─────────────────────────────────────────────────────────────────────

export type SpiffeBridgeErrorCode =
  | 'SVID_UNAVAILABLE'
  | 'SVID_EXPIRED'
  | 'SVID_INVALID'
  | 'SVID_NOT_YET_VALID'
  | 'SPIFFE_ID_DISALLOWED'
  | 'TRUST_DOMAIN_MISMATCH'
  | 'WORKLOAD_API_CONNECTION_FAILED'
  | 'WORKLOAD_API_TIMEOUT'
  | 'CONFIG_INVALID'
  | 'TRANSPORT_ERROR';

/** Minimal shape every SpiffeBridgeError instance satisfies. */
export interface SpiffeBridgeErrorShape {
  readonly code: SpiffeBridgeErrorCode;
  readonly message: string;
  readonly cause?: unknown;
}

/** Error returned from validation (never thrown; see ValidationResult). */
export interface AuthError extends SpiffeBridgeErrorShape {
  readonly code:
    | 'SVID_EXPIRED'
    | 'SVID_NOT_YET_VALID'
    | 'SVID_INVALID'
    | 'SPIFFE_ID_DISALLOWED'
    | 'TRUST_DOMAIN_MISMATCH';
  readonly observedSpiffeId: SpiffeIdString | null;
}

// ─────────────────────────────────────────────────────────────────────
// Validation result
// ─────────────────────────────────────────────────────────────────────

export type ValidationResult =
  | { readonly ok: true; readonly identity: ValidatedIdentity }
  | { readonly ok: false; readonly error: AuthError };

// ─────────────────────────────────────────────────────────────────────
// Caller allowlist matcher
// ─────────────────────────────────────────────────────────────────────

/**
 * Allowlist entry. Either an exact `spiffe://...` string or a pattern
 * containing `*` as a path-segment wildcard.
 *
 * Examples:
 *   `spiffe://prod.example.org/svc/payment`              (exact)
 *   `spiffe://prod.example.org/svc/*`                    (any svc/* )
 *   `spiffe://prod.example.org/ns/default/sa/*`          (any SA in default ns)
 */
export type CallerMatcher = string;

// ─────────────────────────────────────────────────────────────────────
// Interfaces for fetcher / validator / logger
// ─────────────────────────────────────────────────────────────────────

export type SvidWatcher = (svid: X509Svid) => void;

export interface SvidFetcher {
  /** Returns the current SVID, refreshing from the agent if none cached. */
  getX509Svid(): Promise<X509Svid>;
  /** Register a callback fired on every SVID rotation. Returns unsubscribe fn. */
  watchSvids(cb: SvidWatcher): () => void;
  /** Optional health notification; false means cached credentials cannot be used. */
  watchAvailability?(cb: (available: boolean) => void): () => void;
  /** Close the underlying stream / connection. */
  close(): Promise<void>;
}

export interface SvidValidator {
  /**
   * Validate a peer-presented certificate against the current trust bundle
   * and configured allowlist. `now` override is for tests.
   */
  validate(peerCertDer: Uint8Array, now?: Date): Promise<ValidationResult>;
}

// ─────────────────────────────────────────────────────────────────────
// Audit
// ─────────────────────────────────────────────────────────────────────

export type SpiffeAuditEventType = 'auth_success' | 'auth_failure' | 'tool_call' | 'svid_rotated';
export type SpiffeAuditOutcome = 'allowed' | 'denied' | 'error';

/** Exactly the audit shape declared in the spec. Field names kept snake_case for log compatibility. */
export interface SpiffeAuditEvent {
  readonly timestamp: string;
  readonly event_type: SpiffeAuditEventType;
  readonly caller_spiffe_id: string | null;
  readonly caller_trust_domain: string | null;
  readonly svid_expires_at: string | null;
  readonly tool_name: string | null;
  readonly request_id: string;
  readonly outcome: SpiffeAuditOutcome;
  readonly denial_reason: string | null;
}

export interface AuditLogger {
  log(event: SpiffeAuditEvent): void | Promise<void>;
}

// ─────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────

export interface WorkloadApiOptions {
  /**
   * Unix socket path to the SPIRE agent's Workload API.
   * Conventional default: `unix:///tmp/spire-agent/public/api.sock`.
   * Environment override: `SPIFFE_ENDPOINT_SOCKET`.
   */
  readonly socketPath: string;
  readonly connectTimeoutMs?: number;
  readonly rpcTimeoutMs?: number;
  /** Consecutive reconnect budget; default 5, zero disables recovery. */
  readonly reconnect?: {
    readonly maxAttempts: number;
    readonly initialDelayMs?: number;
    readonly maxDelayMs?: number;
  };
}

export interface ValidatorOptions {
  readonly allowedCallers: readonly CallerMatcher[];
  /** Reject SVIDs whose remaining lifetime is below this bound. */
  readonly minTtlSeconds: number;
  /**
   * Optional pin of the local trust domain. Federation is unsupported: naming
   * any other trust domain makes `start()` fail with `ConfigInvalidError`.
   */
  readonly allowedTrustDomains?: readonly TrustDomainString[];
}

/**
 * Behavior when the SPIRE agent is unreachable.
 *  - `fail-fast`   : throw at startup. Use in production.
 *  - `warn-and-skip`: log a warning and run without identity validation.
 *                    Use only in local development.
 */
export type DegradeMode = 'fail-fast' | 'warn-and-skip';

export interface DegradeOptions {
  readonly mode: DegradeMode;
  /** Synthetic SVID for dev mode. Ignored when `mode` is `fail-fast`. */
  readonly fakeSvid?: X509Svid;
}

/**
 * Transport modes:
 *  - `mtls-server` : wrap an MCP SSE/HTTP transport with TLS + client-cert
 *                    verification against the SPIRE trust bundle.
 *  - `stdio-identity-only` : stdio transport, no TLS wrapping (stdio cannot
 *                            carry TLS); caller identity must be established
 *                            out-of-band and asserted via header/env.
 *                            Degraded mode; see README.
 */
export type TransportMode = 'mtls-server' | 'stdio-identity-only';

/** Lowest TLS version the mTLS listener accepts. */
export type MinTlsVersion = 'TLSv1.2' | 'TLSv1.3';

export interface TransportOptions {
  readonly mode: TransportMode;
  /** Default `TLSv1.3`. Set `TLSv1.2` only for peers that cannot negotiate TLS 1.3. */
  readonly minTlsVersion?: MinTlsVersion;
  readonly sse?: {
    /** Listen address; default `127.0.0.1`. Set `0.0.0.0` only inside an isolated pod. */
    readonly host?: string;
    readonly port: number;
  };
}

export interface BridgeOptions {
  readonly workloadApi: WorkloadApiOptions;
  readonly validator: ValidatorOptions;
  readonly transport: TransportOptions;
  readonly audit?: { readonly logger?: AuditLogger };
  readonly degrade?: DegradeOptions;
}

// ─────────────────────────────────────────────────────────────────────
// MCP tool-call context with caller identity
// ─────────────────────────────────────────────────────────────────────

/**
 * Context surfaced to MCP tool handlers. `caller` is null only when degrade
 * mode is `warn-and-skip` and no SVID was validated.
 */
export interface SpiffeCallContext {
  readonly caller: ValidatedIdentity | null;
  readonly requestId: string;
}

// ─────────────────────────────────────────────────────────────────────
// Bridge (top-level facade)
// ─────────────────────────────────────────────────────────────────────

/**
 * The bridge object returned by `createMcpSpiffeBridge(options)`.
 * It wraps an existing MCP `Server` instance, injects caller identity into
 * tool contexts, and emits audit events.
 */
export interface McpSpiffeBridge {
  readonly fetcher: SvidFetcher;
  readonly validator: SvidValidator;
  readonly audit: AuditLogger;
  /**
   * Start the bridge: open the Workload API stream, start the MCP transport
   * (or wrap the caller-supplied one), and begin accepting peers.
   */
  start(): Promise<void>;
  /** Stop transports, close the Workload API stream, flush pending audit. */
  stop(): Promise<void>;
}
