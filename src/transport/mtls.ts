import { constants, randomBytes, randomUUID, X509Certificate } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';
import * as https from 'node:https';
import type * as net from 'node:net';
import type * as tls from 'node:tls';
import {
  buildAuthFailureEvent,
  buildAuthSuccessEvent,
  buildSvidRotatedEvent,
} from '../audit/logger.js';
import { Metrics } from '../metrics.js';
import { parseSpiffeId } from '../spiffe-id.js';
import { checkRevocation } from '../svid/crl.js';
import { verifyPathToAnchors } from '../svid/path.js';
import { anchorsFor, extractSpiffeUriFromSan } from '../svid/validator.js';
import type {
  AuditBackgroundFailure,
  AuditLogger,
  AuthError,
  BridgeMetrics,
  MinTlsVersion,
  RotationMode,
  SpiffeAuditEvent,
  SvidFetcher,
  SvidValidator,
  TransportOptions,
  TrustDomainString,
  ValidatedIdentity,
  X509Svid,
} from '../types.js';
import { runWithCallContext } from './context.js';

/**
 * Handler signature for authenticated requests.
 * The MCP SSE transport is wired in by `bridge.ts` via `setAuthorizedHandler`.
 */
export type AuthorizedRequestHandler = (
  req: IncomingMessage,
  res: ServerResponse,
  identity: ValidatedIdentity,
) => void | Promise<void>;

export interface MtlsTransportServerOptions {
  readonly fetcher: SvidFetcher;
  readonly validator: SvidValidator;
  readonly audit: AuditLogger;
  readonly transport: TransportOptions;
  /** Foreign trust domains whose federated bundles join the TLS trust store. */
  readonly federatedTrustDomains?: readonly TrustDomainString[];
  /** What a failed rotation audit does. Default `fail-closed`. */
  readonly auditBackgroundFailure?: AuditBackgroundFailure;
  readonly metrics?: BridgeMetrics;
}

/**
 * HTTPS server that terminates mTLS using the workload's own SVID and
 * validates every peer cert against the SPIFFE allowlist.
 *
 * SVID rotation is handled by `setSecureContext`: Node swaps the cert chain
 * used for new TLS sessions without restarting the listener. Credential or
 * bundle updates close existing connections and invalidate session tickets.
 * Sessions are also bounded by both credential expiries and a five-minute cap.
 *
 * Peer cert verification happens at two layers:
 *   1. Node's TLS stack verifies the chain against the trust bundle we
 *      provide via the `ca` option.
 *   2. Our `SvidValidator` runs SPIFFE-specific checks (SAN, allowlist,
 *      trust domain, TTL) on the validated leaf.
 */
export class MtlsTransportServer {
  private server: https.Server | null = null;
  private handler: AuthorizedRequestHandler | null = null;
  private unwatch: (() => void) | null = null;
  private unwatchAvailability: (() => void) | null = null;
  private readonly sockets = new Set<net.Socket>();
  private credentialEpoch = 0;
  private ready = false;
  private auditFailed = false;
  private current: X509Svid | null = null;
  private droppedHandshakeAudit = 0;
  private handshakeTokens = HANDSHAKE_AUDIT_PER_SECOND;
  private handshakeTokensAt = Date.now();

  private readonly federated: readonly TrustDomainString[];

  private readonly tlsCrls: boolean;
  private readonly metrics: Metrics;
  private readonly rotationMode: RotationMode;
  private readonly maxAgeMs: number;
  private rotationGeneration = 0;
  private readonly handshakeGeneration = new WeakMap<net.Socket, number>();
  private readonly secured = new Map<string, tls.TLSSocket>();

  constructor(private readonly opts: MtlsTransportServerOptions) {
    this.federated = opts.federatedTrustDomains ?? [];
    this.tlsCrls = (opts.transport.crlScope ?? 'all-issuers') === 'all-issuers';
    this.metrics = new Metrics(opts.metrics);
    this.rotationMode = opts.transport.rotation ?? 'drain';
    this.maxAgeMs = opts.transport.maxConnectionAgeMs ?? 300_000;
  }

  setAuthorizedHandler(handler: AuthorizedRequestHandler): void {
    this.handler = handler;
  }

  /**
   * True while the listener is bound and holds usable credentials. Use it for
   * readiness probes; it turns false on credential loss, failed rotation and stop.
   */
  isReady(): boolean {
    const now = Date.now();
    const own = this.current;
    return (
      this.ready &&
      !this.auditFailed &&
      this.server?.listening === true &&
      this.opts.audit.healthy?.() !== false &&
      own !== null &&
      own.notBefore.getTime() <= now &&
      now < own.notAfter.getTime()
    );
  }

  /** Counters for audit events from unauthenticated peers. */
  stats(): { readonly droppedHandshakeAudit: number } {
    return { droppedHandshakeAudit: this.droppedHandshakeAudit };
  }

  /** True after a background audit write failed under the `fail-closed` policy. */
  isAuditFailed(): boolean {
    return this.auditFailed;
  }

  /** Resume serving after a background audit failure, once the sink works again. */
  clearAuditFailure(): void {
    this.auditFailed = false;
  }

  async start(): Promise<void> {
    if (this.opts.transport.mode !== 'mtls-server') {
      throw new Error(
        `MtlsTransportServer requires transport.mode='mtls-server', got '${this.opts.transport.mode}'`,
      );
    }
    const sse = this.opts.transport.sse;
    if (!sse) {
      throw new Error("transport.sse config is required for 'mtls-server' mode");
    }

    let initialSvid = await this.opts.fetcher.getX509Svid();
    this.current = initialSvid;
    const minVersion = this.opts.transport.minTlsVersion ?? 'TLSv1.3';
    const initialOpts = svidToHttpsOptions(initialSvid, minVersion, this.federated, this.tlsCrls);

    this.server = https.createServer(initialOpts, (req, res) => {
      void this.handleRequest(req, res).catch(() => {
        if (res.headersSent) {
          res.destroy();
          return;
        }
        res.writeHead(503, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'service_unavailable' }));
      });
    });
    this.server.on('tlsClientError', (error, socket) => {
      const certificateErrors = new Set([
        'CERT_SIGNATURE_FAILURE',
        'CERT_NOT_YET_VALID',
        'CERT_HAS_EXPIRED',
        'UNABLE_TO_GET_ISSUER_CERT',
        'UNABLE_TO_GET_ISSUER_CERT_LOCALLY',
        'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
        'DEPTH_ZERO_SELF_SIGNED_CERT',
        'SELF_SIGNED_CERT_IN_CHAIN',
        'ERR_SSL_CERTIFICATE_VERIFY_FAILED',
        'INVALID_CA',
        'CERT_UNTRUSTED',
        'UNABLE_TO_GET_CRL',
        'CRL_HAS_EXPIRED',
        'CRL_NOT_YET_VALID',
        'CRL_SIGNATURE_FAILURE',
        'UNABLE_TO_DECRYPT_CRL_SIGNATURE',
      ]);
      const code =
        typeof socket.authorizationError === 'string'
          ? socket.authorizationError
          : ((error as NodeJS.ErrnoException).code ?? '');
      const message =
        code === 'ERR_SSL_PEER_DID_NOT_RETURN_A_CERTIFICATE'
          ? 'TLS client certificate required'
          : code === 'CERT_REVOKED' || /SSLV3_ALERT_CERTIFICATE_REVOKED/.test(code)
            ? 'TLS certificate revoked'
            : certificateErrors.has(code)
              ? 'TLS certificate verification failed'
              : 'TLS handshake failed';
      this.metrics.increment('handshake_refused', { reason: handshakeReason(message) });
      this.auditHandshakeDenial(
        buildAuthFailureEvent(
          { code: 'SVID_INVALID', message, observedSpiffeId: null },
          { requestId: randomUUID() },
        ),
      );
    });
    this.ready = true;
    this.server.on('connection', (socket) => {
      this.sockets.add(socket);
      this.handshakeGeneration.set(socket, this.rotationGeneration);
      socket.once('close', () => {
        this.sockets.delete(socket);
      });
    });
    this.server.on('secureConnection', (socket) => {
      const key = socketKey(socket);
      const raw = [...this.sockets].find((s) => socketKey(s) === key);
      const startedIn = raw ? this.handshakeGeneration.get(raw) : undefined;
      if (
        socket.destroyed ||
        !this.ready ||
        this.auditFailed ||
        socket.isSessionReused() ||
        startedIn !== this.rotationGeneration
      ) {
        // A handshake that straddled a rotation used the previous context.
        socket.destroy();
        return;
      }
      this.secured.set(key, socket);
      socket.once('close', () => {
        if (this.secured.get(key) === socket) this.secured.delete(key);
      });
      const peer = socket.getPeerX509Certificate();
      if (!peer) {
        socket.destroy();
        return;
      }
      this.metrics.increment('handshake_accepted');
      const deadline = Math.min(
        initialSvid.notAfter.getTime(),
        new Date(peer.validTo).getTime(),
        Date.now() + this.maxAgeMs,
      );
      const timer = setTimeout(() => socket.destroy(), Math.max(0, deadline - Date.now()));
      timer.unref();
      socket.once('close', () => {
        clearTimeout(timer);
      });
    });
    this.unwatchAvailability =
      this.opts.fetcher.watchAvailability?.((available) => {
        if (!available) {
          this.ready = false;
          this.disconnect();
        }
      }) ?? null;
    this.server.requestTimeout = 30_000;
    this.server.headersTimeout = 10_000;

    this.unwatch = this.opts.fetcher.watchSvids((newSvid) => {
      this.ready = false;
      if (this.rotationMode === 'close') this.disconnect();
      try {
        this.server?.setSecureContext(
          svidToSecureContextOptions(newSvid, minVersion, this.federated, this.tlsCrls),
        );
        this.server?.setTicketKeys(randomBytes(48));
        initialSvid = newSvid;
        this.current = newSvid;
        if (this.rotationMode === 'drain') this.drain(newSvid);
        this.ready = this.server !== null;
      } catch {
        this.disconnect();
        process.stderr.write('bridge: rotated TLS context unavailable\n');
        return;
      }
      this.metrics.increment('svid_rotated');
      this.backgroundAudit(
        () => buildSvidRotatedEvent(newSvid, { requestId: randomUUID() }),
        'rotation',
      );
    });

    try {
      await new Promise<void>((resolve, reject) => {
        this.server?.once('error', reject);
        this.server?.listen(sse.port, sse.host ?? '127.0.0.1', () => {
          this.server?.off('error', reject);
          resolve();
        });
      });
    } catch (err) {
      this.unwatch?.();
      this.unwatch = null;
      this.unwatchAvailability?.();
      this.unwatchAvailability = null;
      this.ready = false;
      this.disconnect();
      this.server?.close();
      this.server = null;
      throw err;
    }
  }

  async stop(): Promise<void> {
    this.unwatch?.();
    this.unwatch = null;
    this.unwatchAvailability?.();
    this.unwatchAvailability = null;
    this.ready = false;
    this.current = null;
    this.disconnect();
    if (!this.server) return;
    const srv = this.server;
    this.server = null;
    srv.closeAllConnections();
    await new Promise<void>((resolve, reject) => {
      srv.close((err) => {
        if (err) reject(err);
        else resolve();
      });
    });
  }

  // ─── internals ─────────────────────────────────────────────────────────

  /**
   * Handshake denials come from unauthenticated peers, so they use a separate,
   * rate-limited channel that never blocks or fails authenticated audit. Drops
   * are counted in `stats()`.
   */
  private auditHandshakeDenial(event: SpiffeAuditEvent): void {
    const audit = this.opts.audit;
    if (audit.logUnauthenticated) {
      try {
        audit.logUnauthenticated(event);
      } catch {
        this.dropHandshakeAudit();
      }
      return;
    }
    const now = Date.now();
    this.handshakeTokens = Math.min(
      HANDSHAKE_AUDIT_PER_SECOND,
      this.handshakeTokens + ((now - this.handshakeTokensAt) / 1000) * HANDSHAKE_AUDIT_PER_SECOND,
    );
    this.handshakeTokensAt = now;
    if (this.handshakeTokens < 1) {
      this.dropHandshakeAudit();
      return;
    }
    this.handshakeTokens -= 1;
    void Promise.resolve()
      .then(() => audit.log(event))
      .catch(() => {
        this.dropHandshakeAudit();
      });
  }

  private dropHandshakeAudit(): void {
    this.droppedHandshakeAudit++;
    this.metrics.increment('audit_dropped', { channel: 'unauthenticated' });
  }

  /**
   * Audit an event that has no request to refuse. Under `fail-closed` a failed
   * write stops the listener from serving until `clearAuditFailure()`.
   */
  private backgroundAudit(build: () => SpiffeAuditEvent, kind: string): void {
    void Promise.resolve()
      .then(() => this.opts.audit.log(build()))
      .catch(() => {
        process.stderr.write(`bridge: ${kind} audit unavailable\n`);
        if ((this.opts.auditBackgroundFailure ?? 'fail-closed') === 'fail-closed') {
          this.auditFailed = true;
          this.disconnect();
        }
      });
  }

  /**
   * Rotation without cutting healthy streams: pending handshakes close, and an
   * established connection stays open only if its peer chain is still valid
   * against the new bundles and the snapshot carries no CRLs. Kept connections
   * still end at their original deadline (own and peer expiry, maximum age).
   */
  private drain(next: X509Svid): void {
    this.rotationGeneration++;
    for (const raw of this.sockets) {
      const secured = this.secured.get(socketKey(raw));
      if (!secured) {
        raw.destroy();
        continue;
      }
      if (!this.stillTrusted(secured, next)) secured.destroy();
    }
  }

  private stillTrusted(socket: tls.TLSSocket, next: X509Svid): boolean {
    if (next.crls?.length) return false;
    const peer = socket.getPeerX509Certificate();
    if (!peer) return false;
    try {
      return (
        this.bindToTrustDomain(peer, new Uint8Array(peer.raw), peerIssuers(socket), next) === null
      );
    } catch {
      return false;
    }
  }

  private disconnect(): void {
    this.rotationGeneration++;
    this.secured.clear();
    this.credentialEpoch++;
    for (const socket of this.sockets) socket.destroy();
    this.sockets.clear();
  }

  private async handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (!this.ready) throw new Error('credential state unavailable');
    if (this.auditFailed) throw new Error('audit unavailable');
    const epoch = this.credentialEpoch;
    const generation = this.rotationGeneration;
    const started = process.hrtime.bigint();
    const elapsed = () => Number(process.hrtime.bigint() - started) / 1e9;
    const own = await this.opts.fetcher.getX509Svid();
    const requestId = randomUUID();
    // Node 17+: peer cert is exposed as X509Certificate via getPeerX509Certificate().
    const socket = req.socket as tls.TLSSocket;
    const peerCert = socket.getPeerX509Certificate?.();
    if (!peerCert) {
      // Should be impossible when requestCert + rejectUnauthorized are set,
      // but guard defensively: TLS should have rejected the handshake.
      this.deny(res);
      return;
    }

    const peerDer = new Uint8Array(peerCert.raw);
    const issuers = peerIssuers(socket);
    const unbound = this.bindToTrustDomain(peerCert, peerDer, issuers, own);
    if (unbound) {
      this.refused(unbound.code, elapsed());
      await this.opts.audit.log(buildAuthFailureEvent(unbound, { requestId }));
      this.deny(res);
      return;
    }
    const result = await this.opts.validator.validate(peerDer, undefined, issuers);
    if (!result.ok) {
      this.refused(result.error.code, elapsed());
      await this.opts.audit.log(buildAuthFailureEvent(result.error, { requestId }));
      this.deny(res);
      return;
    }

    await this.opts.audit.log(buildAuthSuccessEvent(result.identity, { requestId }));
    this.metrics.increment('request_authorized');
    this.metrics.observe('request_auth_seconds', elapsed(), { outcome: 'allowed' });

    if (!this.handler) {
      res.statusCode = 503;
      res.end('no handler registered');
      return;
    }

    if (res.destroyed) return;
    if (!this.ready || epoch !== this.credentialEpoch || generation !== this.rotationGeneration) {
      // Validation crossed a credential update; the client retries on fresh state.
      res.writeHead(503, { 'Content-Type': 'application/json', Connection: 'close' });
      res.end(JSON.stringify({ error: 'service_unavailable' }));
      return;
    }
    await runWithCallContext({ caller: result.identity, requestId }, async () => {
      await this.handler?.(req, res, result.identity);
    });
  }

  /**
   * Transport-level binding, independent of the configured validator: the peer
   * must have one SPIFFE ID whose trust domain this listener trusts, and a
   * fully valid path to that domain's anchors only.
   */
  private bindToTrustDomain(
    peer: X509Certificate,
    peerDer: Uint8Array,
    issuers: readonly Uint8Array[],
    own: X509Svid,
  ): AuthError | null {
    const raw = extractSpiffeUriFromSan(peer.subjectAltName);
    const id = raw ? parseSpiffeId(raw) : null;
    if (!id) {
      return {
        code: 'SVID_INVALID',
        message: 'peer certificate has no valid SPIFFE ID',
        observedSpiffeId: null,
      };
    }
    const anchors = anchorsFor(own, id.trustDomain, this.federated);
    const now = new Date();
    const path = verifyPathToAnchors(peerDer, issuers, anchors, now);
    if (!path) {
      return {
        code: 'TRUST_DOMAIN_MISMATCH',
        message: `peer chain does not lead to the trust bundle of ${id.trustDomain}`,
        observedSpiffeId: id.full,
      };
    }
    if (!this.tlsCrls && own.crls?.length) {
      const anchorCerts = anchors.map((a) => new X509Certificate(Buffer.from(a)));
      const reason = checkRevocation(path, anchorCerts, own.crls, now);
      if (reason) return { code: 'SVID_INVALID', message: reason, observedSpiffeId: id.full };
    }
    return null;
  }

  private refused(code: string, seconds: number): void {
    const reason = code.toLowerCase();
    this.metrics.increment('request_refused', { reason });
    this.metrics.observe('request_auth_seconds', seconds, { outcome: 'denied' });
  }

  private deny(res: ServerResponse): void {
    if (res.headersSent) {
      res.end();
      return;
    }
    res.statusCode = 401;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ error: 'unauthorized' }));
  }
}

// ─── TLS option helpers ─────────────────────────────────────────────────

function svidToHttpsOptions(
  svid: X509Svid,
  minVersion: MinTlsVersion,
  federated: readonly TrustDomainString[],
  tlsCrls: boolean,
): https.ServerOptions {
  return {
    ...svidToSecureContextOptions(svid, minVersion, federated, tlsCrls),
    minVersion,
    secureOptions: constants.SSL_OP_NO_TICKET,
    requestCert: true,
    rejectUnauthorized: true,
  };
}

function svidToSecureContextOptions(
  svid: X509Svid,
  minVersion: MinTlsVersion,
  federated: readonly TrustDomainString[],
  tlsCrls: boolean,
): tls.SecureContextOptions {
  const certPem = svid.certChain.map(derToPem.bind(null, 'CERTIFICATE')).join('\n');
  const keyPem = derToPem('PRIVATE KEY', svid.privateKey);
  // The validator binds each peer to the bundle of its own trust domain.
  const roots = [
    ...svid.trustBundle,
    ...federated.flatMap((td) => svid.federatedBundles?.get(td) ?? []),
  ];
  const caPem = roots.map(derToPem.bind(null, 'CERTIFICATE')).join('\n');
  return {
    cert: certPem,
    key: keyPem,
    ca: caPem,
    ...(tlsCrls && svid.crls?.length
      ? { crl: svid.crls.map(derToPem.bind(null, 'X509 CRL')) }
      : {}),
    minVersion,
    secureOptions: constants.SSL_OP_NO_TICKET,
  };
}

const HANDSHAKE_AUDIT_PER_SECOND = 20;

function socketKey(socket: {
  readonly remoteAddress?: string | undefined;
  readonly remotePort?: number | undefined;
}): string {
  return `${socket.remoteAddress ?? ''}|${socket.remotePort ?? ''}`;
}

function handshakeReason(message: string): string {
  if (message === 'TLS client certificate required') return 'no_client_certificate';
  if (message === 'TLS certificate revoked') return 'certificate_revoked';
  if (message === 'TLS certificate verification failed') return 'certificate_untrusted';
  return 'handshake_failed';
}

/** Issuer certificates of the verified peer chain, leaf excluded. */
function peerIssuers(socket: tls.TLSSocket): Uint8Array[] {
  const issuers: Uint8Array[] = [];
  let cert = socket.getPeerCertificate(true);
  for (let depth = 0; depth < 10 && cert?.issuerCertificate; depth++) {
    const next = cert.issuerCertificate;
    if (next === cert || next.raw.equals(cert.raw)) break;
    issuers.push(new Uint8Array(next.raw));
    cert = next;
  }
  return issuers;
}

function derToPem(label: string, der: Uint8Array): string {
  const b64 = Buffer.from(der).toString('base64');
  const wrapped = b64.match(/.{1,64}/g)?.join('\n') ?? b64;
  return `-----BEGIN ${label}-----\n${wrapped}\n-----END ${label}-----`;
}
