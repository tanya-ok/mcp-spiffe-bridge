import { constants } from 'node:fs';
import { type FileHandle, lstat, open } from 'node:fs/promises';
import { AuditDeliveryError } from '../errors.js';
import type { AuditLogger, AuditSinkStats, SpiffeAuditEvent } from '../types.js';

export interface FileAuditLoggerOptions {
  /** Absolute path of the JSON Lines file. Created with mode 0600 if missing. */
  readonly path: string;
  /** Authenticated events accepted but not yet on disk. Default 1024; a full queue rejects. */
  readonly maxQueue?: number;
  /** Separate budget for unauthenticated events (handshake denials). Default 64; overflow is dropped and counted. */
  readonly maxUnauthenticatedQueue?: number;
  /** Unauthenticated events accepted per second. Default 20; excess is dropped and counted. */
  readonly unauthenticatedPerSecond?: number;
  /** Longest wait to group events into one write and fsync. Default 5 ms. */
  readonly groupCommitMs?: number;
  /** Automatic reopen backoff after a failure. Defaults 500 ms, capped at 30 s. */
  readonly retryInitialMs?: number;
  readonly retryMaxMs?: number;
}

interface Pending {
  readonly line: string;
  readonly resolve: () => void;
  readonly reject: (err: AuditDeliveryError) => void;
}

/**
 * Durable audit sink: JSON Lines with group commit. `log()` resolves only after
 * the batch holding the event is written and fsynced; groupCommitMs bounds the
 * added latency, never the durability of an acknowledged event.
 *
 * Failure mode is explicit and fail closed:
 *  - a full authenticated queue rejects the new event;
 *  - a failed open, write or fsync rejects that batch and every later event,
 *    `healthy()` turns false, and the sink retries reopening with backoff;
 *  - unauthenticated events have their own rate limit and queue, so a flood
 *    of failed handshakes cannot block authenticated audit; drops are counted.
 *
 * The file must be a regular file (symlinks are refused), owned by this user,
 * with no group or other permissions. If the path is replaced or removed, the
 * next write reopens it. All file operations are serialized.
 */
export class FileAuditLogger implements AuditLogger {
  private readonly maxQueue: number;
  private readonly maxUnauth: number;
  private readonly rate: number;
  private readonly groupMs: number;
  private readonly retryInitial: number;
  private readonly retryMax: number;

  private handle: FileHandle | null = null;
  private identity: { dev: number; ino: number } | null = null;
  private queue: Pending[] = [];
  private unauth: string[] = [];
  private inflight = 0;
  private failure: AuditDeliveryError | null = null;
  private closed = false;
  private chain: Promise<void> = Promise.resolve();
  private flushTimer: NodeJS.Timeout | null = null;
  private flushScheduled = false;
  private retryTimer: NodeJS.Timeout | null = null;
  private retries = 0;
  private tokens: number;
  private tokensAt = Date.now();
  private dropped = 0;
  private written = 0;

  constructor(private readonly options: FileAuditLoggerOptions) {
    if (!options.path.startsWith('/')) {
      throw new AuditDeliveryError('audit file path must be absolute');
    }
    this.maxQueue = positive(options.maxQueue ?? 1024, 'maxQueue');
    this.maxUnauth = positive(options.maxUnauthenticatedQueue ?? 64, 'maxUnauthenticatedQueue');
    this.rate = positive(options.unauthenticatedPerSecond ?? 20, 'unauthenticatedPerSecond');
    this.groupMs = nonNegative(options.groupCommitMs ?? 5, 'groupCommitMs');
    this.retryInitial = positive(options.retryInitialMs ?? 500, 'retryInitialMs');
    this.retryMax = positive(options.retryMaxMs ?? 30_000, 'retryMaxMs');
    this.tokens = this.rate;
  }

  log(event: SpiffeAuditEvent): Promise<void> {
    if (this.closed) return Promise.reject(new AuditDeliveryError('audit sink closed'));
    if (this.failure) return Promise.reject(this.failure);
    if (this.queue.length + this.inflight >= this.maxQueue) {
      return Promise.reject(new AuditDeliveryError('audit queue full'));
    }
    return new Promise<void>((resolve, reject) => {
      this.queue.push({ line: `${JSON.stringify(event)}\n`, resolve, reject });
      this.scheduleFlush();
    });
  }

  logUnauthenticated(event: SpiffeAuditEvent): void {
    if (this.closed || this.failure || !this.takeToken() || this.unauth.length >= this.maxUnauth) {
      this.dropped++;
      return;
    }
    this.unauth.push(`${JSON.stringify(event)}\n`);
    this.scheduleFlush();
  }

  healthy(): boolean {
    return !this.closed && this.failure === null;
  }

  stats(): AuditSinkStats {
    return {
      healthy: this.healthy(),
      pending: this.queue.length + this.inflight,
      droppedUnauthenticated: this.dropped,
      written: this.written,
    };
  }

  /** Number of accepted authenticated events not yet confirmed on disk. */
  get pending(): number {
    return this.queue.length + this.inflight;
  }

  /** Flush, then close and reopen the path. Use after external log rotation. */
  reopen(): Promise<void> {
    if (this.closed) return Promise.reject(new AuditDeliveryError('audit sink closed'));
    return this.serial(async () => {
      await this.closeHandle();
      try {
        await this.openHandle();
        this.failure = null;
        this.retries = 0;
        this.clearRetry();
      } catch (err) {
        this.failure = new AuditDeliveryError('audit file unavailable', { cause: err });
        this.scheduleRetry();
        throw this.failure;
      }
    });
  }

  /** Resolve once every event accepted so far is on disk or rejected. */
  async flush(): Promise<void> {
    this.cancelTimer();
    await this.serial(() => this.drain());
    if (this.queue.length > 0 || this.unauth.length > 0) await this.flush();
  }

  /** Flush pending events and close the file. Idempotent. */
  async close(): Promise<void> {
    if (!this.closed) {
      await this.flush();
      this.closed = true;
    }
    this.clearRetry();
    this.cancelTimer();
    await this.serial(() => this.closeHandle());
  }

  // ─── internals ─────────────────────────────────────────────────────────

  private serial(op: () => Promise<void>): Promise<void> {
    const next = this.chain.then(op);
    this.chain = next.catch(() => {});
    return next;
  }

  private scheduleFlush(): void {
    if (this.flushScheduled) return;
    this.flushScheduled = true;
    const run = () => {
      this.flushTimer = null;
      this.flushScheduled = false;
      void this.serial(() => this.drain());
    };
    if (this.groupMs === 0) queueMicrotask(run);
    else this.flushTimer = setTimeout(run, this.groupMs);
  }

  private cancelTimer(): void {
    if (this.flushTimer) clearTimeout(this.flushTimer);
    this.flushTimer = null;
    this.flushScheduled = false;
  }

  private async drain(): Promise<void> {
    const batch = this.queue;
    const unauth = this.unauth;
    this.queue = [];
    this.unauth = [];
    if (batch.length === 0 && unauth.length === 0) return;
    this.inflight = batch.length;
    try {
      if (this.failure) throw this.failure;
      await this.ensureCurrentFile();
      const handle = this.handle;
      if (!handle) throw new AuditDeliveryError('audit file unavailable');
      const data = Buffer.from(unauth.join('') + batch.map((p) => p.line).join(''), 'utf8');
      let offset = 0;
      while (offset < data.length) {
        const { bytesWritten } = await handle.write(data, offset, data.length - offset);
        offset += bytesWritten;
      }
      await handle.sync();
      this.written += batch.length + unauth.length;
      for (const p of batch) p.resolve();
    } catch (err) {
      this.fail(err, 'audit write failed');
      const failure = this.failure as AuditDeliveryError;
      this.dropped += unauth.length + this.unauth.splice(0).length;
      for (const p of batch) p.reject(failure);
      for (const p of this.queue.splice(0)) p.reject(failure);
    } finally {
      this.inflight = 0;
    }
  }

  /** Open the file if needed, and reopen it if the path now names another inode. */
  private async ensureCurrentFile(): Promise<void> {
    if (this.handle && this.identity) {
      const current = await lstat(this.options.path).catch(() => null);
      if (current?.dev === this.identity.dev && current.ino === this.identity.ino) return;
      await this.closeHandle();
    }
    await this.openHandle();
  }

  private async openHandle(): Promise<void> {
    const flags =
      constants.O_WRONLY | constants.O_APPEND | constants.O_CREAT | constants.O_NOFOLLOW;
    const handle = await open(this.options.path, flags, 0o600);
    try {
      const st = await handle.stat();
      const uid = process.getuid?.();
      if (!st.isFile()) throw new AuditDeliveryError('audit path is not a regular file');
      if (uid !== undefined && st.uid !== uid) {
        throw new AuditDeliveryError('audit file is not owned by this user');
      }
      if ((st.mode & 0o077) !== 0) {
        throw new AuditDeliveryError('audit file must not be accessible to group or others');
      }
      this.handle = handle;
      this.identity = { dev: st.dev, ino: st.ino };
    } catch (err) {
      await handle.close();
      throw err;
    }
  }

  private async closeHandle(): Promise<void> {
    const handle = this.handle;
    this.handle = null;
    this.identity = null;
    await handle?.close().catch(() => {});
  }

  private fail(err: unknown, message: string): void {
    this.failure ??=
      err instanceof AuditDeliveryError ? err : new AuditDeliveryError(message, { cause: err });
    void this.closeHandle();
    this.scheduleRetry();
  }

  private scheduleRetry(): void {
    if (this.closed || this.retryTimer) return;
    const delay = Math.min(this.retryInitial * 2 ** Math.min(this.retries, 20), this.retryMax);
    this.retries++;
    this.retryTimer = setTimeout(() => {
      this.retryTimer = null;
      void this.reopen().catch(() => {});
    }, delay);
    this.retryTimer.unref();
  }

  private clearRetry(): void {
    if (this.retryTimer) clearTimeout(this.retryTimer);
    this.retryTimer = null;
  }

  private takeToken(): boolean {
    const now = Date.now();
    this.tokens = Math.min(this.rate, this.tokens + ((now - this.tokensAt) / 1000) * this.rate);
    this.tokensAt = now;
    if (this.tokens < 1) return false;
    this.tokens -= 1;
    return true;
  }
}

function positive(value: number, name: string): number {
  if (!Number.isFinite(value) || value <= 0) {
    throw new AuditDeliveryError(`${name} must be a positive number`);
  }
  return value;
}

function nonNegative(value: number, name: string): number {
  if (!Number.isFinite(value) || value < 0) {
    throw new AuditDeliveryError(`${name} must not be negative`);
  }
  return value;
}
