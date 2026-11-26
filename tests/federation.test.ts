import { describe, expect, it, vi } from 'vitest';
import { SpiffeValidator } from '../src/svid/validator.js';
import { getCallerIdentity } from '../src/transport/context.js';
import { MtlsTransportServer } from '../src/transport/mtls.js';
import type { SvidFetcher, SvidWatcher, TrustDomainString, X509Svid } from '../src/types.js';
import { freePort, get, type SyntheticCa, syntheticCa } from './helpers/pki.js';

const partner = 'partner.example.net' as TrustDomainString;
const localCaller = 'spiffe://example.org/agent/research';
const partnerCaller = 'spiffe://partner.example.net/agent/billing';

interface Setup {
  local: SyntheticCa;
  remote: SyntheticCa;
  own: X509Svid;
}

async function setup(): Promise<Setup> {
  const local = await syntheticCa();
  const remote = await syntheticCa();
  const server = await local.issue('spiffe://example.org/mcp/server');
  const own: X509Svid = {
    ...server,
    federatedBundles: new Map([[partner, [remote.der]]]),
  };
  return { local, remote, own };
}

async function listener(
  own: X509Svid,
  opts: { federated?: TrustDomainString[]; allowed?: string[] } = {},
) {
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
    res.end(getCallerIdentity()?.spiffeId.full ?? 'none');
  });
  const audit = { log: vi.fn() };
  const transport = new MtlsTransportServer({
    fetcher,
    validator: new SpiffeValidator(
      {
        allowedCallers: opts.allowed ?? [localCaller, partnerCaller],
        minTtlSeconds: 5,
        ...(opts.federated ? { federatedTrustDomains: opts.federated } : {}),
      },
      fetcher,
    ),
    audit,
    transport: { mode: 'mtls-server', sse: { host: '127.0.0.1', port } },
    ...(opts.federated ? { federatedTrustDomains: opts.federated } : {}),
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

describe('federation at the TLS boundary', () => {
  it('accepts an allowed caller from a configured federated trust domain', async () => {
    const { local, remote, own } = await setup();
    const l = await listener(own, { federated: [partner] });
    try {
      expect(await get(l.port, own.trustBundle, await remote.issue(partnerCaller))).toEqual({
        status: 200,
        body: partnerCaller,
      });
      expect(await get(l.port, own.trustBundle, await local.issue(localCaller))).toEqual({
        status: 200,
        body: localCaller,
      });
    } finally {
      await l.transport.stop();
    }
  });

  it('accepts a federated caller whose chain includes an intermediate', async () => {
    const { remote, own } = await setup();
    const l = await listener(own, { federated: [partner] });
    try {
      const peer = await (await remote.intermediate()).issue(partnerCaller);
      expect(await get(l.port, own.trustBundle, peer)).toEqual({
        status: 200,
        body: partnerCaller,
      });
    } finally {
      await l.transport.stop();
    }
  });

  it('rejects federated callers at TLS when federation is not configured', async () => {
    const { remote, own } = await setup();
    const l = await listener(own);
    try {
      await expect(
        get(l.port, own.trustBundle, await remote.issue(partnerCaller)),
      ).rejects.toThrow();
      expect(l.handler).not.toHaveBeenCalled();
    } finally {
      await l.transport.stop();
    }
  });

  it('refuses a federated CA that issues an identity in the local trust domain', async () => {
    const { remote, own } = await setup();
    const l = await listener(own, { federated: [partner] });
    try {
      expect(await get(l.port, own.trustBundle, await remote.issue(localCaller))).toEqual({
        status: 401,
        body: '{"error":"unauthorized"}',
      });
      expect(l.audit.log).toHaveBeenCalledWith(
        expect.objectContaining({
          denial_reason: expect.stringMatching(
            /^TRUST_DOMAIN_MISMATCH: peer chain does not lead to the trust bundle of example\.org/,
          ),
        }),
      );
      expect(l.handler).not.toHaveBeenCalled();
    } finally {
      await l.transport.stop();
    }
  });

  it('refuses a local CA that issues an identity in a federated trust domain', async () => {
    const { local, own } = await setup();
    const l = await listener(own, { federated: [partner] });
    try {
      expect((await get(l.port, own.trustBundle, await local.issue(partnerCaller))).status).toBe(
        401,
      );
      expect(l.handler).not.toHaveBeenCalled();
    } finally {
      await l.transport.stop();
    }
  });

  it('still requires an allowlist entry for federated callers', async () => {
    const { remote, own } = await setup();
    const l = await listener(own, { federated: [partner], allowed: [localCaller] });
    try {
      expect((await get(l.port, own.trustBundle, await remote.issue(partnerCaller))).status).toBe(
        401,
      );
      expect(l.audit.log).toHaveBeenCalledWith(
        expect.objectContaining({ denial_reason: expect.stringMatching(/^SPIFFE_ID_DISALLOWED/) }),
      );
    } finally {
      await l.transport.stop();
    }
  });

  it('stops trusting a federated domain when its bundle is withdrawn', async () => {
    const { remote, own } = await setup();
    const l = await listener(own, { federated: [partner] });
    try {
      const peer = await remote.issue(partnerCaller);
      expect((await get(l.port, own.trustBundle, peer)).status).toBe(200);
      const { federatedBundles: _withdrawn, ...withoutPartner } = own;
      l.rotate(withoutPartner);
      await expect(get(l.port, own.trustBundle, peer)).rejects.toThrow();
      l.rotate(own);
      expect((await get(l.port, own.trustBundle, peer)).status).toBe(200);
    } finally {
      await l.transport.stop();
    }
  });
});

describe('SpiffeValidator federation rules', () => {
  function fixedFetcher(svid: X509Svid): SvidFetcher {
    return { getX509Svid: async () => svid, watchSvids: () => () => {}, close: async () => {} };
  }

  it('ignores a configured federated domain that has no current bundle', async () => {
    const { remote, own } = await setup();
    const { federatedBundles: _none, ...bare } = own;
    const v = new SpiffeValidator(
      { allowedCallers: [partnerCaller], minTtlSeconds: 5, federatedTrustDomains: [partner] },
      fixedFetcher(bare),
    );
    const peer = await remote.issue(partnerCaller);
    const result = await v.validate(peer.certChain[0] as Uint8Array);
    expect(result).toMatchObject({ ok: false, error: { code: 'TRUST_DOMAIN_MISMATCH' } });
  });

  it('narrows federated domains with allowedTrustDomains', async () => {
    const { remote, own } = await setup();
    const v = new SpiffeValidator(
      {
        allowedCallers: [partnerCaller],
        minTtlSeconds: 5,
        federatedTrustDomains: [partner],
        allowedTrustDomains: ['example.org' as TrustDomainString],
      },
      fixedFetcher(own),
    );
    const peer = await remote.issue(partnerCaller);
    const result = await v.validate(peer.certChain[0] as Uint8Array);
    expect(result).toMatchObject({ ok: false, error: { code: 'TRUST_DOMAIN_MISMATCH' } });
  });

  it('requires the presented chain to bind an intermediate-issued federated leaf', async () => {
    const { remote, own } = await setup();
    const intermediate = await remote.intermediate();
    const peer = await intermediate.issue(partnerCaller);
    const v = new SpiffeValidator(
      { allowedCallers: [partnerCaller], minTtlSeconds: 5, federatedTrustDomains: [partner] },
      fixedFetcher(own),
    );
    const leaf = peer.certChain[0] as Uint8Array;
    expect((await v.validate(leaf)).ok).toBe(false);
    expect((await v.validate(leaf, new Date(), [intermediate.der])).ok).toBe(true);
  });
});
