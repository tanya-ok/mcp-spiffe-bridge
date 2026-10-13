import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// ─── Fake streaming call infrastructure ────────────────────────────────

interface FakeResponse {
  svids: Array<{
    spiffeId: string;
    x509Svid: Uint8Array;
    x509SvidKey: Uint8Array;
    bundle: Uint8Array;
    hint: string;
  }>;
  federatedBundles: Record<string, Uint8Array>;
  crl: Uint8Array[];
}

interface Queue {
  push(r: FakeResponse): void;
  end(): void;
}

function makeCall(): { queue: Queue; responses: AsyncIterable<FakeResponse> } {
  const pending: FakeResponse[] = [];
  const waiters: Array<(r: IteratorResult<FakeResponse>) => void> = [];
  let closed = false;

  const endValue = { value: undefined as unknown as FakeResponse, done: true } as const;

  const queue: Queue = {
    push(r) {
      const w = waiters.shift();
      if (w) w({ value: r, done: false });
      else pending.push(r);
    },
    end() {
      closed = true;
      while (waiters.length > 0) {
        const w = waiters.shift();
        w?.(endValue);
      }
    },
  };

  const responses: AsyncIterable<FakeResponse> = {
    [Symbol.asyncIterator]() {
      return {
        next() {
          const b = pending.shift();
          if (b) return Promise.resolve({ value: b, done: false });
          if (closed) return Promise.resolve(endValue);
          return new Promise<IteratorResult<FakeResponse>>((resolve) => {
            waiters.push(resolve);
          });
        },
      };
    },
  };

  return { queue, responses };
}

// Per-test state. `currentCall` is swapped in `beforeEach`.
let currentCall: { queue: Queue; responses: AsyncIterable<FakeResponse> };
let callCount = 0;

vi.mock('spiffe', async (importOriginal) => {
  const actual = await importOriginal<typeof import('spiffe')>();
  return {
    ...actual,
    createClient: vi.fn(() => ({
      fetchX509SVID: vi.fn((_request: unknown, options: { abort: AbortSignal }) => {
        const call = currentCall;
        callCount++;
        options.abort.addEventListener('abort', () => call.queue.end(), { once: true });
        return { responses: call.responses };
      }),
    })),
  };
});

import { createMcpSpiffeBridge } from '../src/bridge.js';
import { ConfigInvalidError } from '../src/errors.js';
import { WorkloadApiSvidFetcher } from '../src/svid/fetcher.js';
import type { X509Svid } from '../src/types.js';
import { makeSpiffeCert } from './helpers/test-certs.js';

describe('WorkloadApiSvidFetcher', () => {
  const tracked: WorkloadApiSvidFetcher[] = [];

  function track(f: WorkloadApiSvidFetcher): WorkloadApiSvidFetcher {
    tracked.push(f);
    return f;
  }

  function makeFetcher(rpcTimeoutMs = 2000): WorkloadApiSvidFetcher {
    return track(
      new WorkloadApiSvidFetcher({
        socketPath: 'unix:///tmp/fake.sock',
        rpcTimeoutMs,
      }),
    );
  }

  beforeEach(() => {
    currentCall = makeCall();
    callCount = 0;
  });

  afterEach(async () => {
    currentCall.queue.end();
    await Promise.all(tracked.splice(0).map((f) => f.close()));
    vi.useRealTimers();
  });

  it('returns the first SVID from the stream', async () => {
    const fetcher = makeFetcher();
    const cert = await makeSpiffeCert({ spiffeId: 'spiffe://td.test/workload/a' });
    currentCall.queue.push({
      svids: [
        {
          spiffeId: 'spiffe://td.test/workload/a',
          x509Svid: cert.certDer,
          x509SvidKey: cert.privateKeyDer,
          bundle: cert.certDer,
          hint: '',
        },
      ],
      federatedBundles: {},
      crl: [],
    });

    const svid = await fetcher.getX509Svid();
    expect(svid.spiffeId.full).toBe('spiffe://td.test/workload/a');
    expect(svid.trustBundle).toHaveLength(1);
  });

  it('fires the rotation callback when a new SVID arrives', async () => {
    const fetcher = makeFetcher();
    const cert1 = await makeSpiffeCert({ spiffeId: 'spiffe://td.test/workload/a' });
    const cert2 = await makeSpiffeCert({
      spiffeId: 'spiffe://td.test/workload/a',
      notAfter: new Date(Date.now() + 7_200_000),
    });

    const received: X509Svid[] = [];
    fetcher.watchSvids((s) => received.push(s));

    currentCall.queue.push({
      svids: [
        {
          spiffeId: 'spiffe://td.test/workload/a',
          x509Svid: cert1.certDer,
          x509SvidKey: cert1.privateKeyDer,
          bundle: cert1.certDer,
          hint: '',
        },
      ],
      federatedBundles: {},
      crl: [],
    });
    await fetcher.getX509Svid();

    currentCall.queue.push({
      svids: [
        {
          spiffeId: 'spiffe://td.test/workload/a',
          x509Svid: cert2.certDer,
          x509SvidKey: cert2.privateKeyDer,
          bundle: cert2.certDer,
          hint: '',
        },
      ],
      federatedBundles: {},
      crl: [],
    });
    await new Promise((r) => setTimeout(r, 20));

    expect(received.length).toBeGreaterThanOrEqual(2);
    expect(received[0]?.notAfter.getTime()).toBeLessThan(received[1]?.notAfter.getTime() ?? 0);
  });

  it('throws when getX509Svid is called after close', async () => {
    const fetcher = makeFetcher();
    await fetcher.close();
    await expect(fetcher.getX509Svid()).rejects.toThrow(/fetcher closed/);
  });

  it('times out when no SVID arrives within rpcTimeoutMs', async () => {
    const fast = makeFetcher(50);
    await expect(fast.getX509Svid()).rejects.toThrow(/timed out/);
  });
  it('refuses a cached credential after the stream ends', async () => {
    const fetcher = makeFetcher();
    const cert = await makeSpiffeCert({ spiffeId: 'spiffe://example.org/agent/research' });
    currentCall.queue.push({
      svids: [
        {
          spiffeId: 'spiffe://example.org/agent/research',
          x509Svid: cert.certDer,
          x509SvidKey: cert.privateKeyDer,
          bundle: cert.certDer,
          hint: '',
        },
      ],
      federatedBundles: {},
      crl: [],
    });
    await fetcher.getX509Svid();
    currentCall.queue.end();
    await new Promise((resolve) => setTimeout(resolve, 10));
    await expect(fetcher.getX509Svid()).rejects.toThrow('Workload API stream unavailable');
  });

  it('refuses the cached SVID after its validity window', async () => {
    const fetcher = makeFetcher();
    const expires = new Date(Date.now() + 60_000);
    const cert = await makeSpiffeCert({
      spiffeId: 'spiffe://example.org/agent/research',
      notAfter: expires,
    });
    currentCall.queue.push({
      svids: [
        {
          spiffeId: 'spiffe://example.org/agent/research',
          x509Svid: cert.certDer,
          x509SvidKey: cert.privateKeyDer,
          bundle: cert.certDer,
          hint: '',
        },
      ],
      federatedBundles: {},
      crl: [],
    });
    await fetcher.getX509Svid();
    const now = vi.spyOn(Date, 'now').mockReturnValue(expires.getTime() + 1);
    try {
      await expect(fetcher.getX509Svid()).rejects.toThrow('outside validity window');
    } finally {
      now.mockRestore();
    }
  });
  it('closes after startup failure and requires a fresh bridge instance', async () => {
    const bridge = createMcpSpiffeBridge({
      workloadApi: { socketPath: '/tmp/fake.sock', rpcTimeoutMs: 20 },
      validator: { allowedCallers: ['spiffe://example.org/agent/research'], minTtlSeconds: 5 },
      transport: { mode: 'mtls-server', sse: { port: 8443 } },
    });
    await expect(bridge.start()).rejects.toThrow('timed out');
    await expect(bridge.start()).rejects.toThrow('create a new instance');
    await bridge.stop();
    await bridge.stop();
  });

  it.each([
    [['example.org'], true],
    [['example.org', 'partner.example.net'], false],
    [['partner.example.net'], false],
  ])('checks allowedTrustDomains %j against the local trust domain at startup', async (domains, ok) => {
    const cert = await makeSpiffeCert({ spiffeId: 'spiffe://example.org/agent/research' });
    currentCall.queue.push(responseFor(cert));
    const bridge = createMcpSpiffeBridge({
      workloadApi: { socketPath: '/tmp/fake.sock', rpcTimeoutMs: 2000 },
      validator: {
        allowedCallers: ['spiffe://example.org/agent/research'],
        minTtlSeconds: 5,
        allowedTrustDomains: domains,
      },
      transport: { mode: 'stdio-identity-only' },
    });
    try {
      if (ok) await expect(bridge.start()).resolves.toBeUndefined();
      else await expect(bridge.start()).rejects.toThrow(ConfigInvalidError);
    } finally {
      await bridge.stop();
    }
  });
});

function responseFor(cert: { certDer: Uint8Array; privateKeyDer: Uint8Array }): FakeResponse {
  return {
    svids: [
      {
        spiffeId: 'spiffe://example.org/agent/research',
        x509Svid: cert.certDer,
        x509SvidKey: cert.privateKeyDer,
        bundle: cert.certDer,
        hint: '',
      },
    ],
    federatedBundles: {},
    crl: [],
  };
}

describe('bounded stream recovery', () => {
  let fetcher: WorkloadApiSvidFetcher;
  beforeEach(() => {
    currentCall = makeCall();
    callCount = 0;
  });
  afterEach(async () => {
    await fetcher?.close();
    vi.useRealTimers();
  });
  function recovering(maxAttempts = 2) {
    fetcher = new WorkloadApiSvidFetcher({
      socketPath: '/tmp/fake.sock',
      rpcTimeoutMs: 1000,
      connectTimeoutMs: 50,
      reconnect: { maxAttempts, initialDelayMs: 10, maxDelayMs: 20 },
    });
    return fetcher;
  }

  it('denies during loss and reconnect until a fresh valid response arrives', async () => {
    const oldCert = await makeSpiffeCert({ spiffeId: 'spiffe://example.org/agent/research' });
    const newCert = await makeSpiffeCert({ spiffeId: 'spiffe://example.org/agent/research' });
    vi.useFakeTimers();
    const f = recovering();
    const health: boolean[] = [];
    f.watchAvailability((available) => health.push(available));
    currentCall.queue.push(responseFor(oldCert));
    const oldSvid = await f.getX509Svid();
    const oldCall = currentCall;
    oldCall.queue.end();
    await vi.advanceTimersByTimeAsync(0);
    await expect(f.getX509Svid()).rejects.toThrow('stream unavailable');
    currentCall = makeCall();
    await vi.advanceTimersByTimeAsync(10);
    await expect(f.getX509Svid()).rejects.toThrow('stream unavailable');
    currentCall.queue.push(responseFor(newCert));
    await vi.advanceTimersByTimeAsync(0);
    expect((await f.getX509Svid()).certChain).not.toEqual(oldSvid.certChain);
    expect(health).toEqual([true, false, true]);
    expect(callCount).toBe(2);
  });

  it('exhausts its consecutive retry budget and cancels all timers on close', async () => {
    vi.useFakeTimers();
    const f = recovering();
    currentCall.queue.end();
    await expect(f.getX509Svid()).rejects.toThrow('stream unavailable');
    await vi.advanceTimersByTimeAsync(1000);
    expect(callCount).toBe(3);
    await expect(f.getX509Svid()).rejects.toThrow('stream unavailable');
    await f.close();
    expect(vi.getTimerCount()).toBe(0);
  });

  it('cancels backoff immediately on shutdown', async () => {
    vi.useFakeTimers();
    const f = recovering();
    currentCall.queue.end();
    await expect(f.getX509Svid()).rejects.toThrow();
    await f.close();
    await vi.advanceTimersByTimeAsync(10_000);
    expect(callCount).toBe(1);
    expect(vi.getTimerCount()).toBe(0);
  });

  it('times out a recovery stream that never delivers a credential', async () => {
    vi.useFakeTimers();
    const f = recovering(1);
    currentCall.queue.end();
    await expect(f.getX509Svid()).rejects.toThrow();
    currentCall = makeCall();
    await vi.advanceTimersByTimeAsync(60);
    await expect(f.getX509Svid()).rejects.toThrow('timed out');
    expect(callCount).toBe(2);
    expect(vi.getTimerCount()).toBe(0);
  });

  it.each([
    'empty',
    'wrong-key',
    'wrong-identity',
    'crl',
  ])('invalidates rather than ignoring an invalid %s update', async (kind) => {
    const cert = await makeSpiffeCert({ spiffeId: 'spiffe://example.org/agent/research' });
    const other = await makeSpiffeCert({ spiffeId: 'spiffe://example.org/agent/research' });
    vi.useFakeTimers();
    const f = recovering(0);
    currentCall.queue.push(responseFor(cert));
    await f.getX509Svid();
    const invalid = responseFor(cert);
    if (kind === 'empty') invalid.svids = [];
    if (kind === 'wrong-key' && invalid.svids[0])
      invalid.svids[0].x509SvidKey = other.privateKeyDer;
    if (kind === 'wrong-identity' && invalid.svids[0])
      invalid.svids[0].spiffeId = 'spiffe://example.org/another';
    if (kind === 'crl') invalid.crl = [new Uint8Array([1])];
    currentCall.queue.push(invalid);
    await vi.advanceTimersByTimeAsync(0);
    await expect(f.getX509Svid()).rejects.toThrow('stream unavailable');
    expect(callCount).toBe(1);
    expect(vi.getTimerCount()).toBe(0);
  });
});
