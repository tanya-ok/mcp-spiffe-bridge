import { mkdtemp, open, readFile, rename, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { FileAuditLogger } from '../src/audit/file-sink.js';
import { AuditDeliveryError } from '../src/errors.js';
import type { SpiffeAuditEvent } from '../src/types.js';

function event(n: number): SpiffeAuditEvent {
  return {
    timestamp: new Date(Date.UTC(2026, 0, 1, 0, 0, n)).toISOString(),
    event_type: 'auth_success',
    caller_spiffe_id: 'spiffe://example.org/agent/research',
    caller_trust_domain: 'example.org',
    svid_expires_at: null,
    tool_name: null,
    request_id: `request-${n}`,
    outcome: 'allowed',
    denial_reason: null,
  };
}

async function lines(path: string): Promise<SpiffeAuditEvent[]> {
  const text = await readFile(path, 'utf8');
  return text
    .split('\n')
    .filter(Boolean)
    .map((l) => JSON.parse(l) as SpiffeAuditEvent);
}

let dir: string;
beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'bridge-audit-'));
});
afterEach(async () => {
  vi.restoreAllMocks();
  await rm(dir, { recursive: true, force: true });
});

describe('FileAuditLogger', () => {
  it('appends JSON lines with mode 0600 and fsyncs before resolving', async () => {
    const probe = await open(join(dir, 'probe'), 'w');
    const proto = Object.getPrototypeOf(probe) as { sync: () => Promise<void> };
    await probe.close();
    const sync = vi.spyOn(proto, 'sync');
    const path = join(dir, 'audit.jsonl');
    const sink = new FileAuditLogger({ path });
    await sink.log(event(1));
    expect(sync).toHaveBeenCalledTimes(1);
    expect(await lines(path)).toEqual([event(1)]);
    expect((await stat(path)).mode & 0o777).toBe(0o600);
    await sink.close();
  });

  it('keeps order under concurrent writes and reports pending events', async () => {
    const path = join(dir, 'audit.jsonl');
    const sink = new FileAuditLogger({ path });
    const writes = Array.from({ length: 200 }, (_, n) => sink.log(event(n)));
    expect(sink.pending).toBe(200);
    await Promise.all(writes);
    expect(sink.pending).toBe(0);
    expect((await lines(path)).map((e) => e.request_id)).toEqual(
      Array.from({ length: 200 }, (_, n) => `request-${n}`),
    );
    await sink.close();
  });

  it('rejects new events when the bounded queue is full and keeps accepted ones', async () => {
    const path = join(dir, 'audit.jsonl');
    const sink = new FileAuditLogger({ path, maxQueue: 3 });
    const accepted = [sink.log(event(1)), sink.log(event(2)), sink.log(event(3))];
    await expect(sink.log(event(4))).rejects.toThrow(AuditDeliveryError);
    await expect(sink.log(event(4))).rejects.toThrow('audit queue full');
    await Promise.all(accepted);
    await sink.log(event(5));
    expect((await lines(path)).map((e) => e.request_id)).toEqual([
      'request-1',
      'request-2',
      'request-3',
      'request-5',
    ]);
    await sink.close();
  });

  it('fails closed and stays failed after a write error until reopen succeeds', async () => {
    const path = join(dir, 'missing', 'audit.jsonl');
    const sink = new FileAuditLogger({ path });
    const first = sink.log(event(1));
    const second = sink.log(event(2));
    await expect(first).rejects.toMatchObject({ code: 'AUDIT_DELIVERY_FAILED' });
    await expect(second).rejects.toThrow(AuditDeliveryError);
    await expect(sink.log(event(3))).rejects.toThrow('audit write failed');
    await expect(sink.reopen()).rejects.toThrow('audit file unavailable');
    await expect(sink.log(event(4))).rejects.toThrow(AuditDeliveryError);
    await sink.close();
  });

  it('rejects an fsync failure instead of reporting success', async () => {
    const probe = await open(join(dir, 'probe'), 'w');
    const proto = Object.getPrototypeOf(probe) as { sync: () => Promise<void> };
    await probe.close();
    vi.spyOn(proto, 'sync').mockRejectedValueOnce(new Error('EIO'));
    const sink = new FileAuditLogger({ path: join(dir, 'audit.jsonl') });
    await expect(sink.log(event(1))).rejects.toThrow('audit write failed');
    await sink.close();
  });

  it('reopens the path after external rotation', async () => {
    const path = join(dir, 'audit.jsonl');
    const sink = new FileAuditLogger({ path });
    await sink.log(event(1));
    await rename(path, join(dir, 'audit.jsonl.1'));
    await sink.reopen();
    await sink.log(event(2));
    expect((await lines(join(dir, 'audit.jsonl.1'))).map((e) => e.request_id)).toEqual([
      'request-1',
    ]);
    expect((await lines(path)).map((e) => e.request_id)).toEqual(['request-2']);
    await sink.close();
  });

  it('flushes on close and rejects later events', async () => {
    const path = join(dir, 'audit.jsonl');
    const sink = new FileAuditLogger({ path });
    const pending = sink.log(event(1));
    await sink.close();
    await pending;
    expect(await lines(path)).toHaveLength(1);
    await expect(sink.log(event(2))).rejects.toThrow('audit sink closed');
    await sink.close();
  });

  it('rejects relative paths and invalid queue sizes', () => {
    expect(() => new FileAuditLogger({ path: 'audit.jsonl' })).toThrow(AuditDeliveryError);
    expect(() => new FileAuditLogger({ path: '/tmp/a', maxQueue: 0 })).toThrow(AuditDeliveryError);
  });
});
