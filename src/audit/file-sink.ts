import { type FileHandle, open } from 'node:fs/promises';
import { AuditDeliveryError } from '../errors.js';
import type { AuditLogger, SpiffeAuditEvent } from '../types.js';

export interface FileAuditLoggerOptions {
  /** Absolute path of the JSON Lines file. Created with mode 0600 if missing. */
  readonly path: string;
  /** Events accepted but not yet on disk. Default 1024. A full queue rejects new events. */
  readonly maxQueue?: number;
}

interface Pending {
  readonly line: string;
  readonly resolve: () => void;
  readonly reject: (err: AuditDeliveryError) => void;
}

/**
 * Durable audit sink: appends one JSON line per event and calls fsync before
 * `log()` resolves.
 *
 * Failure mode is explicit and fail-closed:
 *  - a full queue rejects the new event with `AuditDeliveryError`;
 *  - a failed open, write or fsync rejects every event in that batch and
 *    every later event, until `reopen()` succeeds;
 *  - after `close()`, `log()` rejects.
 * The mTLS listener awaits `log()` for authentication events, so a rejection
 * refuses the request with 503 instead of serving it unaudited.
 */
export class FileAuditLogger implements AuditLogger {
  private readonly maxQueue: number;
  private handle: FileHandle | null = null;
  private queue: Pending[] = [];
  private inflight = 0;
  private draining: Promise<void> | null = null;
  private failure: AuditDeliveryError | null = null;
  private closed = false;

  constructor(private readonly options: FileAuditLoggerOptions) {
    if (!options.path.startsWith('/')) {
      throw new AuditDeliveryError('audit file path must be absolute');
    }
    this.maxQueue = options.maxQueue ?? 1024;
    if (!Number.isInteger(this.maxQueue) || this.maxQueue < 1) {
      throw new AuditDeliveryError('maxQueue must be a positive integer');
    }
  }

  log(event: SpiffeAuditEvent): Promise<void> {
    if (this.closed) return Promise.reject(new AuditDeliveryError('audit sink closed'));
    if (this.failure) return Promise.reject(this.failure);
    if (this.queue.length + this.inflight >= this.maxQueue) {
      return Promise.reject(new AuditDeliveryError('audit queue full'));
    }
    return new Promise<void>((resolve, reject) => {
      this.queue.push({ line: `${JSON.stringify(event)}\n`, resolve, reject });
      this.scheduleDrain();
    });
  }

  /** Number of accepted events not yet confirmed on disk. */
  get pending(): number {
    return this.queue.length + this.inflight;
  }

  /** Flush, then close and reopen the path. Use after external log rotation. */
  async reopen(): Promise<void> {
    if (this.closed) throw new AuditDeliveryError('audit sink closed');
    await this.flush();
    await this.closeHandle();
    this.failure = null;
    try {
      this.handle = await this.openHandle();
    } catch (err) {
      this.failure = new AuditDeliveryError('audit file unavailable', { cause: err });
      throw this.failure;
    }
  }

  /** Resolve once every event accepted so far is on disk or rejected. */
  async flush(): Promise<void> {
    while (this.draining) await this.draining;
  }

  /** Flush pending events and close the file. Idempotent. */
  async close(): Promise<void> {
    this.closed = true;
    await this.flush();
    await this.closeHandle();
  }

  private scheduleDrain(): void {
    if (this.draining) return;
    this.draining = this.drain().finally(() => {
      this.draining = null;
      if (this.queue.length > 0) this.scheduleDrain();
    });
  }

  private async drain(): Promise<void> {
    const batch = this.queue;
    this.queue = [];
    if (batch.length === 0) return;
    this.inflight = batch.length;
    try {
      if (this.failure) throw this.failure;
      this.handle ??= await this.openHandle();
      const data = Buffer.from(batch.map((p) => p.line).join(''), 'utf8');
      let offset = 0;
      while (offset < data.length) {
        const { bytesWritten } = await this.handle.write(data, offset, data.length - offset);
        offset += bytesWritten;
      }
      await this.handle.sync();
      for (const p of batch) p.resolve();
    } catch (err) {
      this.failure ??=
        err instanceof AuditDeliveryError
          ? err
          : new AuditDeliveryError('audit write failed', { cause: err });
      for (const p of batch) p.reject(this.failure);
      for (const p of this.queue.splice(0)) p.reject(this.failure);
    } finally {
      this.inflight = 0;
    }
  }

  private openHandle(): Promise<FileHandle> {
    return open(this.options.path, 'a', 0o600);
  }

  private async closeHandle(): Promise<void> {
    const handle = this.handle;
    this.handle = null;
    await handle?.close();
  }
}
