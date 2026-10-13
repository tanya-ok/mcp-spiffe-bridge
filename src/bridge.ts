import { StdoutJsonAuditLogger } from './audit/logger.js';
import { validateBridgeOptions } from './config.js';
import { ConfigInvalidError, SvidUnavailableError, WorkloadApiConnectionError } from './errors.js';
import { WorkloadApiSvidFetcher } from './svid/fetcher.js';
import { SpiffeValidator } from './svid/validator.js';
import { type AuthorizedRequestHandler, MtlsTransportServer } from './transport/mtls.js';
import type {
  AuditLogger,
  BridgeOptions,
  McpSpiffeBridge,
  SvidFetcher,
  SvidValidator,
} from './types.js';

/**
 * Concrete bridge returned by `createMcpSpiffeBridge`.
 *
 * Callers typically:
 *   1. Build `BridgeOptions`.
 *   2. `const bridge = await createMcpSpiffeBridge(options)`.
 *   3. `bridge.setAuthorizedHandler((req, res, identity) => …)` to attach
 *      their MCP SSE transport.
 *   4. `await bridge.start()`.
 */
export class McpSpiffeBridgeImpl implements McpSpiffeBridge {
  public readonly fetcher: SvidFetcher;
  public readonly validator: SvidValidator;
  public readonly audit: AuditLogger;

  /** Present only when transport.mode === 'mtls-server'. */
  public readonly mtlsServer: MtlsTransportServer | null;

  private started = false;
  private stopped = false;
  private startTask: Promise<void> | null = null;

  private constructor(
    private readonly options: BridgeOptions,
    fetcher: SvidFetcher,
    validator: SvidValidator,
    audit: AuditLogger,
    mtlsServer: MtlsTransportServer | null,
  ) {
    this.fetcher = fetcher;
    this.validator = validator;
    this.audit = audit;
    this.mtlsServer = mtlsServer;
  }

  static build(options: BridgeOptions): McpSpiffeBridgeImpl {
    // Zod-validated separately by `createMcpSpiffeBridge`; accept pre-validated here.
    const audit = options.audit?.logger ?? new StdoutJsonAuditLogger();

    const fetcher = new WorkloadApiSvidFetcher(options.workloadApi);
    const validator = new SpiffeValidator(options.validator, fetcher);

    const mtls =
      options.transport.mode === 'mtls-server'
        ? new MtlsTransportServer({ fetcher, validator, audit, transport: options.transport })
        : null;

    return new McpSpiffeBridgeImpl(options, fetcher, validator, audit, mtls);
  }

  /**
   * Register a handler that runs after a peer has authenticated successfully.
   * Only meaningful when `transport.mode === 'mtls-server'`.
   */
  setAuthorizedHandler(handler: AuthorizedRequestHandler): void {
    if (!this.mtlsServer) {
      throw new ConfigInvalidError(
        "setAuthorizedHandler is only available when transport.mode === 'mtls-server'",
      );
    }
    this.mtlsServer.setAuthorizedHandler(handler);
  }

  async start(): Promise<void> {
    if (this.stopped) throw new ConfigInvalidError('bridge stopped; create a new instance');
    if (this.started) return;
    if (this.startTask) return this.startTask;
    this.startTask = this.startTransport();
    try {
      await this.startTask;
    } finally {
      this.startTask = null;
    }
  }

  private async startTransport(): Promise<void> {
    try {
      if (this.fetcher instanceof WorkloadApiSvidFetcher) this.fetcher.start();
      const own = (await this.fetcher.getX509Svid()).spiffeId.trustDomain;
      const foreign = (this.options.validator.allowedTrustDomains ?? []).filter((td) => td !== own);
      if (foreign.length > 0) {
        throw new ConfigInvalidError(
          `federation is not supported: allowedTrustDomains may only name the local trust domain ${own}, got ${foreign.join(', ')}`,
        );
      }
      if (this.stopped) throw new ConfigInvalidError('bridge stopped during startup');
      await this.mtlsServer?.start();
      this.started = true;
    } catch (err) {
      await this.mtlsServer?.stop();
      await this.fetcher.close();
      this.stopped = true;
      if (!this.handleDegrade(err)) throw err;
    }
  }

  async stop(): Promise<void> {
    this.stopped = true;
    try {
      await this.startTask;
    } catch {
      /* Startup already reported its error. */
    }
    this.started = false;
    try {
      await this.mtlsServer?.stop();
    } finally {
      await this.fetcher.close();
    }
  }

  /**
   * Apply the configured degrade policy. Returns true if the caller should
   * treat the error as "handled" (warn and continue); false if the error
   * should propagate to the caller.
   */
  private handleDegrade(err: unknown): boolean {
    const degrade = this.options.degrade;
    const isConnErr =
      err instanceof WorkloadApiConnectionError || err instanceof SvidUnavailableError;
    if (!isConnErr) return false;

    if (!degrade || degrade.mode === 'fail-fast') {
      return false;
    }
    // warn-and-skip: emit a stderr warning; do NOT start the mTLS server,
    // since we cannot serve without a trust bundle.
    process.stderr.write(
      '[mcp-spiffe-bridge] WARNING: SPIRE agent unavailable. ' +
        'Transport is NOT started. This is only acceptable in local dev.\n',
    );
    return true;
  }
}

/**
 * Public factory. Validates options via zod, builds the bridge, and returns
 * it *without* starting it. Call `.start()` when you're ready to accept
 * peers.
 *
 * @throws ConfigInvalidError if options are malformed.
 */
export function createMcpSpiffeBridge(options: unknown): McpSpiffeBridgeImpl {
  const validated = validateBridgeOptions(options);
  return McpSpiffeBridgeImpl.build(validated);
}
