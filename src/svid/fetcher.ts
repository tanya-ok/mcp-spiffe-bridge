import { createPrivateKey, X509Certificate } from 'node:crypto';
import { createClient, parseCertificate, parseCertificateBundle } from 'spiffe';
import {
  SvidUnavailableError,
  WorkloadApiConnectionError,
  WorkloadApiTimeoutError,
} from '../errors.js';
import { parseSpiffeId } from '../spiffe-id.js';
import type {
  SvidFetcher,
  SvidWatcher,
  TrustDomainString,
  WorkloadApiOptions,
  X509Svid,
} from '../types.js';

/**
 * Fetcher implementation that wraps the depot `spiffe` client.
 *
 * Behavior:
 *   - Opens a server-streaming `FetchX509SVID` RPC on `start()`.
 *   - Each response from the agent updates the cached SVID and fires every
 *     registered watcher callback.
 *   - `getX509Svid()` returns the cached value once the first message has
 *     arrived; before that, it awaits the first response (or timeout).
 *   - `close()` aborts the stream via an AbortController and releases
 *     watchers.
 *
 * The SPIRE agent drives rotation: we do not schedule a refresh timer.
 * When the agent sees expiry approaching it pushes a new SVID on the stream.
 */
export class WorkloadApiSvidFetcher implements SvidFetcher {
  private readonly client: ReturnType<typeof createClient>;
  private readonly abortController = new AbortController();
  private readonly watchers = new Set<SvidWatcher>();
  private readonly availabilityWatchers = new Set<(available: boolean) => void>();
  private attemptAbort: AbortController | null = null;
  private retries = 0;
  private cachedSvid: X509Svid | null = null;
  private firstMessageDeferred: {
    promise: Promise<X509Svid>;
    resolve: (v: X509Svid) => void;
    reject: (e: unknown) => void;
  };
  private streamTask: Promise<void> | null = null;
  private closed = false;
  private streamFailure: Error | null = null;

  constructor(private readonly options: WorkloadApiOptions) {
    const baseUrl = normalizeSocketUrl(options.socketPath);
    this.client = createClient(baseUrl);
    this.firstMessageDeferred = deferred<X509Svid>();
    void this.firstMessageDeferred.promise.catch(() => {});
  }

  /** Begin consuming the FetchX509SVID stream. Safe to call once. */
  start(): void {
    if (this.closed) throw new SvidUnavailableError('fetcher closed');
    if (this.streamTask) return;
    this.streamTask = this.runWithReconnect();
  }

  async getX509Svid(): Promise<X509Svid> {
    if (this.closed) {
      throw new SvidUnavailableError('fetcher closed');
    }
    if (this.streamFailure) throw this.streamFailure;
    if (this.cachedSvid) {
      const now = Date.now();
      if (now < this.cachedSvid.notBefore.getTime() || now >= this.cachedSvid.notAfter.getTime()) {
        throw new SvidUnavailableError('own SVID outside validity window');
      }
      return this.cachedSvid;
    }
    if (!this.streamTask) this.start();
    const timeoutMs = this.options.rpcTimeoutMs ?? 10_000;
    return withTimeout(this.firstMessageDeferred.promise, timeoutMs, 'FetchX509SVID');
  }

  watchSvids(cb: SvidWatcher): () => void {
    this.watchers.add(cb);
    return () => {
      this.watchers.delete(cb);
    };
  }

  watchAvailability(cb: (available: boolean) => void): () => void {
    this.availabilityWatchers.add(cb);
    return () => {
      this.availabilityWatchers.delete(cb);
    };
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    this.invalidate();
    this.abortController.abort();
    this.attemptAbort?.abort();
    this.availabilityWatchers.clear();
    this.watchers.clear();
    try {
      await this.streamTask;
    } catch {
      // swallow, we're shutting down
    }
  }

  // ─── internals ────────────────────────────────────────────────────────

  private invalidate(error?: unknown): void {
    this.streamFailure =
      error instanceof WorkloadApiTimeoutError
        ? new WorkloadApiTimeoutError('FetchX509SVID timed out')
        : new WorkloadApiConnectionError('Workload API stream unavailable');
    this.cachedSvid = null;
    this.firstMessageDeferred.reject(this.streamFailure);
    this.notifyAvailability(false);
  }

  private notifyAvailability(available: boolean): void {
    for (const watcher of this.availabilityWatchers) {
      try {
        watcher(available);
      } catch {
        /* Observers cannot change credential state. */
      }
    }
  }

  private async runWithReconnect(): Promise<void> {
    const maxAttempts = this.options.reconnect?.maxAttempts ?? 5;
    const initialDelay = this.options.reconnect?.initialDelayMs ?? 250;
    const maxDelay = this.options.reconnect?.maxDelayMs ?? 5000;
    while (!this.closed) {
      try {
        await this.run();
      } catch (error) {
        if (!this.closed) this.invalidate(error);
      }
      if (this.closed || this.retries >= maxAttempts) return;
      const delay = Math.min(initialDelay * 2 ** this.retries, maxDelay);
      this.retries++;
      await abortableDelay(delay, this.abortController.signal);
    }
  }

  private async run(): Promise<void> {
    const abort = new AbortController();
    this.attemptAbort = abort;
    let firstResponseTimedOut = false;
    const firstResponseTimer = setTimeout(
      () => {
        firstResponseTimedOut = true;
        abort.abort();
      },
      this.options.connectTimeoutMs ?? this.options.rpcTimeoutMs ?? 10_000,
    );
    try {
      const call = this.client.fetchX509SVID({}, { abort: abort.signal });
      for await (const response of call.responses) {
        if (this.closed) return;
        const svid = this.pickAndDecode(response);
        if (
          !svid ||
          Date.now() < svid.notBefore.getTime() ||
          Date.now() >= svid.notAfter.getTime()
        ) {
          throw new SvidUnavailableError('Workload API returned no valid SVID');
        }
        clearTimeout(firstResponseTimer);
        this.retries = 0;
        this.streamFailure = null;
        this.cachedSvid = svid;
        this.firstMessageDeferred.resolve(svid);
        this.notifyAvailability(true);
        for (const w of this.watchers) {
          try {
            w(svid);
          } catch {
            // Watchers must not break the stream.
          }
        }
      }
      if (firstResponseTimedOut) throw new WorkloadApiTimeoutError('FetchX509SVID timed out');
      if (!this.closed) throw new WorkloadApiConnectionError('Workload API stream ended');
    } catch (err) {
      if (this.closed) return;
      if (firstResponseTimedOut) throw new WorkloadApiTimeoutError('FetchX509SVID timed out');
      throw wrapStreamError(err);
    } finally {
      clearTimeout(firstResponseTimer);
      abort.abort();
      this.attemptAbort = null;
    }
  }

  /** Decode the first SVID from a response into our public shape. */
  private pickAndDecode(response: {
    svids: Array<{
      spiffeId: string;
      x509Svid: Uint8Array;
      x509SvidKey: Uint8Array;
      bundle: Uint8Array;
    }>;
    federatedBundles: { [key: string]: Uint8Array };
    crl?: Uint8Array[];
  }): X509Svid | null {
    if (response.crl?.length) throw new SvidUnavailableError('Workload API CRLs are not supported');
    const first = response.svids[0];
    if (!first) return null;

    const parsedId = parseSpiffeId(first.spiffeId);
    if (!parsedId) return null;

    const chainCerts = parseCertificateBundle(first.x509Svid);
    const leaf = chainCerts[0] ?? parseCertificate(first.x509Svid);
    const chain =
      chainCerts.length > 0
        ? chainCerts.map((c) => new Uint8Array(c.rawData))
        : [new Uint8Array(leaf.rawData)];

    const ownCertificate = new X509Certificate(Buffer.from(leaf.rawData));
    const uris =
      ownCertificate.subjectAltName
        ?.split(',')
        .map((part) => part.trim())
        .filter((part) => part.startsWith('URI:')) ?? [];
    const ownKey = createPrivateKey({
      key: Buffer.from(first.x509SvidKey),
      format: 'der',
      type: 'pkcs8',
    });
    if (
      uris.length !== 1 ||
      uris[0] !== `URI:${parsedId.full}` ||
      !ownCertificate.checkPrivateKey(ownKey)
    )
      throw new SvidUnavailableError('Workload API returned invalid SVID material');
    const bundleCerts = parseCertificateBundle(first.bundle);
    if (bundleCerts.length === 0)
      throw new SvidUnavailableError('Workload API returned empty trust bundle');
    const trustBundle = bundleCerts.map((c) => new Uint8Array(c.rawData));

    let federated: ReadonlyMap<TrustDomainString, readonly Uint8Array[]> | undefined;
    const federatedEntries = Object.entries(response.federatedBundles);
    if (federatedEntries.length > 0) {
      const m = new Map<TrustDomainString, readonly Uint8Array[]>();
      for (const [td, bytes] of federatedEntries) {
        const parsed = parseCertificateBundle(bytes).map((c) => new Uint8Array(c.rawData));
        m.set(td as TrustDomainString, parsed);
      }
      federated = m;
    }

    const svid: X509Svid = {
      spiffeId: parsedId,
      certChain: chain,
      privateKey: new Uint8Array(first.x509SvidKey),
      notBefore: leaf.notBefore,
      notAfter: leaf.notAfter,
      trustBundle,
      ...(federated ? { federatedBundles: federated } : {}),
    };
    return svid;
  }
}

// ─── helpers ────────────────────────────────────────────────────────────

function normalizeSocketUrl(socketPath: string): string {
  if (socketPath.startsWith('unix://')) return socketPath;
  return `unix://${socketPath}`;
}

function deferred<T>(): {
  promise: Promise<T>;
  resolve: (v: T) => void;
  reject: (e: unknown) => void;
} {
  let resolve!: (v: T) => void;
  let reject!: (e: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

async function withTimeout<T>(p: Promise<T>, ms: number, op: string): Promise<T> {
  let handle: NodeJS.Timeout | null = null;
  const timeout = new Promise<never>((_, reject) => {
    handle = setTimeout(
      () => reject(new WorkloadApiTimeoutError(`${op} timed out after ${ms}ms`)),
      ms,
    );
  });
  try {
    return await Promise.race([p, timeout]);
  } finally {
    if (handle) clearTimeout(handle);
  }
}

function wrapStreamError(err: unknown): Error {
  return new WorkloadApiConnectionError('FetchX509SVID stream failed', {
    cause: err,
  });
}

async function abortableDelay(ms: number, signal: AbortSignal): Promise<void> {
  if (signal.aborted) return;
  await new Promise<void>((resolve) => {
    const done = () => {
      clearTimeout(timer);
      signal.removeEventListener('abort', done);
      resolve();
    };
    const timer = setTimeout(done, ms);
    signal.addEventListener('abort', done, { once: true });
  });
}
