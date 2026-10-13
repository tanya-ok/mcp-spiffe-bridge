import { constants, randomBytes, randomUUID } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';
import * as https from 'node:https';
import type { Duplex } from 'node:stream';
import type * as tls from 'node:tls';
import {
  buildAuthFailureEvent,
  buildAuthSuccessEvent,
  buildSvidRotatedEvent,
} from '../audit/logger.js';
import type {
  AuditLogger,
  MinTlsVersion,
  SvidFetcher,
  SvidValidator,
  TransportOptions,
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
  private readonly sockets = new Set<Duplex>();
  private credentialEpoch = 0;
  private ready = false;

  constructor(private readonly opts: MtlsTransportServerOptions) {}

  setAuthorizedHandler(handler: AuthorizedRequestHandler): void {
    this.handler = handler;
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
    const minVersion = this.opts.transport.minTlsVersion ?? 'TLSv1.3';
    const initialOpts = svidToHttpsOptions(initialSvid, minVersion);

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
      ]);
      const code =
        typeof socket.authorizationError === 'string'
          ? socket.authorizationError
          : ((error as NodeJS.ErrnoException).code ?? '');
      const message =
        code === 'ERR_SSL_PEER_DID_NOT_RETURN_A_CERTIFICATE'
          ? 'TLS client certificate required'
          : certificateErrors.has(code)
            ? 'TLS certificate verification failed'
            : 'TLS handshake failed';
      void Promise.resolve()
        .then(() =>
          this.opts.audit.log(
            buildAuthFailureEvent(
              {
                code: 'SVID_INVALID',
                message,
                observedSpiffeId: null,
              },
              { requestId: randomUUID() },
            ),
          ),
        )
        .catch(() => {
          process.stderr.write('bridge: TLS denial audit unavailable\n');
        });
    });
    this.ready = true;
    this.server.on('connection', (socket) => {
      this.sockets.add(socket);
      socket.once('close', () => {
        this.sockets.delete(socket);
      });
    });
    this.server.on('secureConnection', (socket) => {
      if (socket.destroyed || !this.ready || socket.isSessionReused()) {
        socket.destroy();
        return;
      }
      const peer = socket.getPeerX509Certificate();
      if (!peer) {
        socket.destroy();
        return;
      }
      const deadline = Math.min(
        initialSvid.notAfter.getTime(),
        new Date(peer.validTo).getTime(),
        Date.now() + 300_000,
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
      this.disconnect();
      try {
        this.server?.setSecureContext(svidToSecureContextOptions(newSvid, minVersion));
        this.server?.setTicketKeys(randomBytes(48));
        initialSvid = newSvid;
        this.ready = this.server !== null;
      } catch {
        process.stderr.write('bridge: rotated TLS context unavailable\n');
        return;
      }
      void Promise.resolve(
        this.opts.audit.log(buildSvidRotatedEvent(newSvid, { requestId: randomUUID() })),
      ).catch(() => {
        process.stderr.write('bridge: rotation audit unavailable\n');
      });
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

  private disconnect(): void {
    this.credentialEpoch++;
    for (const socket of this.sockets) socket.destroy();
    this.sockets.clear();
  }

  private async handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (!this.ready) throw new Error('credential state unavailable');
    const epoch = this.credentialEpoch;
    await this.opts.fetcher.getX509Svid();
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
    const result = await this.opts.validator.validate(peerDer);
    if (!result.ok) {
      await this.opts.audit.log(buildAuthFailureEvent(result.error, { requestId }));
      this.deny(res);
      return;
    }

    await this.opts.audit.log(buildAuthSuccessEvent(result.identity, { requestId }));

    if (!this.handler) {
      res.statusCode = 503;
      res.end('no handler registered');
      return;
    }

    if (!this.ready || epoch !== this.credentialEpoch || res.destroyed) return;
    await runWithCallContext({ caller: result.identity, requestId }, async () => {
      await this.handler?.(req, res, result.identity);
    });
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

function svidToHttpsOptions(svid: X509Svid, minVersion: MinTlsVersion): https.ServerOptions {
  return {
    ...svidToSecureContextOptions(svid, minVersion),
    minVersion,
    secureOptions: constants.SSL_OP_NO_TICKET,
    requestCert: true,
    rejectUnauthorized: true,
  };
}

function svidToSecureContextOptions(
  svid: X509Svid,
  minVersion: MinTlsVersion,
): tls.SecureContextOptions {
  const certPem = svid.certChain.map(derToPem.bind(null, 'CERTIFICATE')).join('\n');
  const keyPem = derToPem('PRIVATE KEY', svid.privateKey);
  const caPem = svid.trustBundle.map(derToPem.bind(null, 'CERTIFICATE')).join('\n');
  return {
    cert: certPem,
    key: keyPem,
    ca: caPem,
    minVersion,
    secureOptions: constants.SSL_OP_NO_TICKET,
  };
}

function derToPem(label: string, der: Uint8Array): string {
  const b64 = Buffer.from(der).toString('base64');
  const wrapped = b64.match(/.{1,64}/g)?.join('\n') ?? b64;
  return `-----BEGIN ${label}-----\n${wrapped}\n-----END ${label}-----`;
}
