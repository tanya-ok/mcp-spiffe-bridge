import { describe, expect, it, vi } from 'vitest';
import { SpiffeValidator } from '../src/svid/validator.js';
import { MtlsTransportServer } from '../src/transport/mtls.js';
import type { SvidFetcher, SvidWatcher, X509Svid } from '../src/types.js';
import { freePort, get, syntheticCa } from './helpers/pki.js';

const caller = 'spiffe://example.org/agent/research';

async function listener(own: X509Svid) {
  const port = await freePort();
  let current = own;
  const watchers = new Set<SvidWatcher>();
  const fetcher: SvidFetcher = {
    getX509Svid: async () => current,
    watchSvids: (cb) => {
      watchers.add(cb);
      return () => watchers.delete(cb);
    },
    close: async () => {},
  };
  const handler = vi.fn((_req: unknown, res: import('node:http').ServerResponse) => {
    res.end('ok');
  });
  const audit = { log: vi.fn() };
  const transport = new MtlsTransportServer({
    fetcher,
    validator: new SpiffeValidator({ allowedCallers: [caller], minTtlSeconds: 5 }, fetcher),
    audit,
    transport: { mode: 'mtls-server', sse: { host: '127.0.0.1', port } },
  });
  transport.setAuthorizedHandler(handler);
  await transport.start();
  return {
    port,
    handler,
    audit,
    transport,
    rotate(next: X509Svid) {
      current = next;
      for (const w of watchers) w(next);
    },
  };
}

describe('CRL enforcement at the TLS boundary', () => {
  it('rejects a revoked caller and accepts a non-revoked one from the same CA', async () => {
    const ca = await syntheticCa();
    const server = await ca.issue('spiffe://example.org/mcp/server');
    const good = await ca.issue(caller, { serial: '0a01' });
    const revoked = await ca.issue(caller, { serial: '0a02' });
    const own = { ...server, crls: [await ca.crl(['0a02'])] };
    const l = await listener(own);
    try {
      expect(await get(l.port, own.trustBundle, good)).toEqual({ status: 200, body: 'ok' });
      await expect(get(l.port, own.trustBundle, revoked)).rejects.toThrow();
      expect(l.handler).toHaveBeenCalledTimes(1);
      await vi.waitFor(() =>
        expect(l.audit.log).toHaveBeenCalledWith(
          expect.objectContaining({
            event_type: 'auth_failure',
            denial_reason: 'SVID_INVALID: TLS certificate revoked',
          }),
        ),
      );
    } finally {
      await l.transport.stop();
    }
  });

  it('applies a CRL delivered by rotation without a restart', async () => {
    const ca = await syntheticCa();
    const server = await ca.issue('spiffe://example.org/mcp/server');
    const peer = await ca.issue(caller, { serial: '0b01' });
    const l = await listener(server);
    try {
      expect((await get(l.port, server.trustBundle, peer)).status).toBe(200);
      l.rotate({ ...server, crls: [await ca.crl(['0b01'])] });
      await expect(get(l.port, server.trustBundle, peer)).rejects.toThrow();
      l.rotate({ ...server, crls: [await ca.crl([])] });
      expect((await get(l.port, server.trustBundle, peer)).status).toBe(200);
    } finally {
      await l.transport.stop();
    }
  });

  it('fails closed when a CRL has expired', async () => {
    const ca = await syntheticCa();
    const server = await ca.issue('spiffe://example.org/mcp/server');
    const peer = await ca.issue(caller);
    const own = {
      ...server,
      crls: [await ca.crl([], { nextUpdate: new Date(Date.now() - 1000) })],
    };
    const l = await listener(own);
    try {
      await expect(get(l.port, own.trustBundle, peer)).rejects.toThrow();
      expect(l.handler).not.toHaveBeenCalled();
    } finally {
      await l.transport.stop();
    }
  });

  it('fails closed when an issuer in the peer chain has no CRL', async () => {
    const root = await syntheticCa();
    const intermediate = await root.intermediate();
    const server = await root.issue('spiffe://example.org/mcp/server');
    const peer = await intermediate.issue(caller);
    const withRootCrlOnly = { ...server, crls: [await root.crl([])] };
    const l = await listener(withRootCrlOnly);
    try {
      await expect(get(l.port, server.trustBundle, peer)).rejects.toThrow();
      l.rotate({ ...server, crls: [await root.crl([]), await intermediate.crl([])] });
      expect((await get(l.port, server.trustBundle, peer)).status).toBe(200);
    } finally {
      await l.transport.stop();
    }
  });

  it('does not check revocation when the snapshot carries no CRLs', async () => {
    const ca = await syntheticCa();
    const server = await ca.issue('spiffe://example.org/mcp/server');
    const peer = await (await ca.intermediate()).issue(caller);
    const l = await listener(server);
    try {
      expect((await get(l.port, server.trustBundle, peer)).status).toBe(200);
    } finally {
      await l.transport.stop();
    }
  });
});
