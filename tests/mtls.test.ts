import { randomUUID, webcrypto } from 'node:crypto';
import * as https from 'node:https';
import * as net from 'node:net';
import * as x509 from '@peculiar/x509';
import { describe, expect, it, vi } from 'vitest';
import { parseSpiffeId } from '../src/spiffe-id.js';
import { SpiffeValidator } from '../src/svid/validator.js';
import { getCallerIdentity } from '../src/transport/context.js';
import { MtlsTransportServer } from '../src/transport/mtls.js';
import type { SvidFetcher, X509Svid } from '../src/types.js';

x509.cryptoProvider.set(webcrypto as unknown as Crypto);
const algorithm = { name: 'ECDSA', namedCurve: 'P-256' };
const signingAlgorithm = { name: 'ECDSA', hash: 'SHA-256' };
const research = 'spiffe://example.org/agent/research';

async function certificates() {
  const keys = await webcrypto.subtle.generateKey(algorithm, true, ['sign', 'verify']);
  const ca = await x509.X509CertificateGenerator.createSelfSigned({
    name: `CN=Synthetic test CA ${randomUUID()}`,
    keys,
    signingAlgorithm,
    notBefore: new Date(Date.now() - 60_000),
    notAfter: new Date(Date.now() + 3_600_000),
    extensions: [
      new x509.BasicConstraintsExtension(true, 1, true),
      new x509.KeyUsagesExtension(
        x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign,
        true,
      ),
    ],
  });
  async function issue(id: string, expires?: Date): Promise<X509Svid> {
    const leafKeys = await webcrypto.subtle.generateKey(algorithm, true, ['sign', 'verify']);
    const cert = await x509.X509CertificateGenerator.create({
      subject: 'CN=Synthetic test workload',
      issuer: ca.subject,
      publicKey: leafKeys.publicKey,
      signingKey: keys.privateKey,
      signingAlgorithm,
      notBefore: new Date(Date.now() - 60_000),
      notAfter: expires ?? new Date(Date.now() + 3_600_000),
      extensions: [
        new x509.BasicConstraintsExtension(false, undefined, true),
        new x509.SubjectAlternativeNameExtension([
          { type: 'url', value: id },
          { type: 'dns', value: 'localhost' },
        ]),
      ],
    });
    const spiffeId = parseSpiffeId(id);
    if (!spiffeId) throw new Error('invalid test identity');
    return {
      spiffeId,
      certChain: [new Uint8Array(cert.rawData)],
      trustBundle: [new Uint8Array(ca.rawData)],
      privateKey: new Uint8Array(await webcrypto.subtle.exportKey('pkcs8', leafKeys.privateKey)),
      notBefore: cert.notBefore,
      notAfter: cert.notAfter,
    };
  }
  return { issue };
}
function pem(label: string, value: Uint8Array) {
  return `-----BEGIN ${label}-----\n${Buffer.from(value)
    .toString('base64')
    .match(/.{1,64}/g)
    ?.join('\n')}\n-----END ${label}-----`;
}
async function freePort() {
  const server = net.createServer();
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('port unavailable');
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return address.port;
}
function request(
  port: number,
  own: X509Svid,
  peer?: X509Svid,
  onPeer?: (raw: Buffer, socket: import('node:tls').TLSSocket) => void,
  maxVersion?: import('node:tls').SecureVersion,
  agent?: https.Agent,
): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = https.get(
      {
        hostname: 'localhost',
        port,
        family: 4,
        agent: agent ?? false,
        ...(maxVersion ? { maxVersion } : {}),
        ca: own.trustBundle.map((cert) => pem('CERTIFICATE', cert)),
        ...(peer
          ? {
              cert: peer.certChain.map((cert) => pem('CERTIFICATE', cert)).join('\n'),
              key: pem('PRIVATE KEY', peer.privateKey),
            }
          : {}),
      },
      (res) => {
        if (onPeer) {
          const socket = res.socket as import('node:tls').TLSSocket;
          onPeer(socket.getPeerCertificate().raw, socket);
        }
        let body = '';
        res.on('data', (chunk) => {
          body += chunk;
        });
        res.on('end', () => resolve({ status: res.statusCode ?? 0, body }));
      },
    );
    req.on('error', reject);
  });
}

describe('real TLS boundary', () => {
  it('authenticates the caller, rejects absent/foreign/disallowed certs and catches handler errors', async () => {
    const ca = await certificates();
    const own = await ca.issue('spiffe://example.org/mcp/fhir');
    const peer = await ca.issue(research);
    const intruder = await ca.issue('spiffe://example.org/agent/intruder');
    const foreign = await (await certificates()).issue(research);
    const port = await freePort();
    const fetcher: SvidFetcher = {
      getX509Svid: vi.fn(async () => own),
      watchSvids: () => () => {},
      close: async () => {},
    };
    const audit = { log: vi.fn() };
    const transport = new MtlsTransportServer({
      fetcher,
      validator: new SpiffeValidator({ allowedCallers: [research], minTtlSeconds: 5 }, fetcher),
      audit,
      transport: { mode: 'mtls-server', sse: { host: '127.0.0.1', port } },
    });
    transport.setAuthorizedHandler(async (_req, res) => {
      await Promise.resolve();
      res.end(getCallerIdentity()?.spiffeId.full);
    });
    await transport.start();
    try {
      expect(await request(port, own, peer)).toEqual({ status: 200, body: research });
      expect(await request(port, own, intruder)).toEqual({
        status: 401,
        body: '{"error":"unauthorized"}',
      });
      expect(audit.log).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'auth_failure',
          denial_reason: expect.stringMatching(/^SPIFFE_ID_DISALLOWED: /),
        }),
      );
      await expect(request(port, own)).rejects.toThrow();
      await expect(request(port, own, foreign)).rejects.toThrow();
      expect(getCallerIdentity()).toBeNull();
      transport.setAuthorizedHandler(() => {
        throw new Error('synthetic secret');
      });
      expect(await request(port, own, peer)).toEqual({
        status: 503,
        body: '{"error":"service_unavailable"}',
      });
      vi.mocked(fetcher.getX509Svid).mockRejectedValue(new Error('credential expired'));
      expect((await request(port, own, peer)).status).toBe(503);
    } finally {
      await transport.stop();
    }
  });

  it('binds to loopback when no host is configured', async () => {
    const own = await (await certificates()).issue('spiffe://example.org/mcp/fhir');
    const port = await freePort();
    const fetcher: SvidFetcher = {
      getX509Svid: async () => own,
      watchSvids: () => () => {},
      close: async () => {},
    };
    const transport = new MtlsTransportServer({
      fetcher,
      validator: new SpiffeValidator({ allowedCallers: [research], minTtlSeconds: 5 }, fetcher),
      audit: { log: vi.fn() },
      transport: { mode: 'mtls-server', sse: { port } },
    });
    await transport.start();
    try {
      const server = (transport as unknown as { server: https.Server }).server;
      expect(server.address()).toMatchObject({ address: '127.0.0.1', port });
    } finally {
      await transport.stop();
    }
  });

  it('unsubscribes after a listener startup failure', async () => {
    const own = await (await certificates()).issue('spiffe://example.org/mcp/fhir');
    const busy = net.createServer();
    await new Promise<void>((resolve) => busy.listen(0, '127.0.0.1', resolve));
    const address = busy.address();
    if (!address || typeof address === 'string') throw new Error('port unavailable');
    const unsubscribe = vi.fn();
    const fetcher: SvidFetcher = {
      getX509Svid: async () => own,
      watchSvids: () => unsubscribe,
      close: async () => {},
    };
    const transport = new MtlsTransportServer({
      fetcher,
      validator: new SpiffeValidator({ allowedCallers: [research], minTtlSeconds: 5 }, fetcher),
      audit: { log: vi.fn() },
      transport: { mode: 'mtls-server', sse: { host: '127.0.0.1', port: address.port } },
    });
    try {
      await expect(transport.start()).rejects.toThrow();
      expect(unsubscribe).toHaveBeenCalledOnce();
      await transport.stop();
    } finally {
      await new Promise<void>((resolve) => busy.close(() => resolve()));
    }
  });
});

class MutableFetcher implements SvidFetcher {
  readonly watchers = new Set<(svid: X509Svid) => void>();
  readonly health = new Set<(available: boolean) => void>();
  available = true;
  constructor(public current: X509Svid) {}
  async getX509Svid() {
    if (!this.available) throw new Error('credential unavailable');
    return this.current;
  }
  watchSvids(cb: (svid: X509Svid) => void) {
    this.watchers.add(cb);
    return () => {
      this.watchers.delete(cb);
    };
  }
  watchAvailability(cb: (available: boolean) => void) {
    this.health.add(cb);
    return () => {
      this.health.delete(cb);
    };
  }
  update(svid: X509Svid) {
    this.current = svid;
    this.available = true;
    for (const cb of this.watchers) cb(svid);
  }
  loseStream() {
    this.available = false;
    for (const cb of this.health) cb(false);
  }
  async close() {
    this.watchers.clear();
    this.health.clear();
  }
}

async function stream(
  port: number,
  own: X509Svid,
  peer: X509Svid,
): Promise<{ closed: Promise<void> }> {
  return new Promise((resolve, reject) => {
    const req = https.get(
      {
        hostname: 'localhost',
        port,
        family: 4,
        agent: false,
        ca: own.trustBundle.map((cert) => pem('CERTIFICATE', cert)),
        cert: peer.certChain.map((cert) => pem('CERTIFICATE', cert)).join('\n'),
        key: pem('PRIVATE KEY', peer.privateKey),
      },
      (res) => {
        const closed = new Promise<void>((done) => res.once('close', () => done()));
        res.once('data', () => resolve({ closed }));
        res.on('error', () => {});
      },
    );
    req.on('error', reject);
  });
}

async function serverFor(own: X509Svid, minTlsVersion?: 'TLSv1.2' | 'TLSv1.3') {
  const fetcher = new MutableFetcher(own);
  const port = await freePort();
  const audit = { log: vi.fn() };
  const transport = new MtlsTransportServer({
    fetcher,
    validator: new SpiffeValidator({ allowedCallers: [research], minTtlSeconds: 0 }, fetcher),
    audit,
    transport: {
      mode: 'mtls-server',
      sse: { host: '127.0.0.1', port },
      ...(minTlsVersion ? { minTlsVersion } : {}),
    },
  });
  transport.setAuthorizedHandler((_req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/event-stream' });
    res.write('data: synthetic\n\n');
  });
  await transport.start();
  return { fetcher, port, transport, audit };
}

describe('root rotation and established connection policy', () => {
  it.each([
    'TLSv1.2',
    'TLSv1.3',
  ] as const)('uses overlapping roots and rejects a removed root with %s', async (version) => {
    const caA = await certificates();
    const caB = await certificates();
    const ownA = await caA.issue('spiffe://example.org/mcp/fhir');
    const ownB = await caB.issue('spiffe://example.org/mcp/fhir');
    const peerA = await caA.issue(research);
    const peerB = await caB.issue(research);
    const overlap = { ...ownB, trustBundle: [...ownA.trustBundle, ...ownB.trustBundle] };
    const { fetcher, port, transport, audit } = await serverFor(ownA, version);
    try {
      const old = await stream(port, ownA, peerA);
      fetcher.update(overlap);
      await old.closed;
      const overlapA = await stream(port, overlap, peerA);
      const overlapB = await stream(port, overlap, peerB);
      fetcher.update(ownB);
      await Promise.all([overlapA.closed, overlapB.closed]);
      transport.setAuthorizedHandler((_req, res) => res.end('synthetic'));
      let servedLeaf: Buffer | undefined;
      expect(
        (
          await request(port, ownB, peerB, (raw) => {
            servedLeaf = raw;
          })
        ).status,
      ).toBe(200);
      expect(servedLeaf).toEqual(Buffer.from(ownB.certChain[0] ?? []));
      await expect(request(port, ownB, peerA, undefined, version)).rejects.toThrow();
      expect(audit.log).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'auth_failure',
          denial_reason: expect.stringMatching(
            /^SVID_INVALID: TLS (certificate verification failed|client certificate required)$/,
          ),
        }),
      );
    } finally {
      await transport.stop();
    }
    expect(fetcher.watchers.size).toBe(0);
    expect(fetcher.health.size).toBe(0);
  });

  it('closes active streams on credential loss and only recovers after a fresh update', async () => {
    const ca = await certificates();
    const own = await ca.issue('spiffe://example.org/mcp/fhir');
    const peer = await ca.issue(research);
    const { fetcher, port, transport } = await serverFor(own);
    try {
      const active = await stream(port, own, peer);
      fetcher.loseStream();
      await active.closed;
      await expect(request(port, own, peer)).rejects.toThrow();
      fetcher.update(await ca.issue('spiffe://example.org/mcp/fhir'));
      transport.setAuthorizedHandler((_req, res) => res.end('synthetic'));
      expect((await request(port, own, peer)).status).toBe(200);
    } finally {
      await transport.stop();
    }
  });

  it.each([
    'own',
    'peer',
  ])('closes an already-open stream when the %s credential expires', async (kind) => {
    const ca = await certificates();
    const expires = new Date(Date.now() + 2200);
    const own = await ca.issue(
      'spiffe://example.org/mcp/fhir',
      kind === 'own' ? expires : undefined,
    );
    const peer = await ca.issue(research, kind === 'peer' ? expires : undefined);
    const { port, transport } = await serverFor(own);
    try {
      const active = await stream(port, own, peer);
      await active.closed;
      const deadline = Math.min(own.notAfter.getTime(), peer.notAfter.getTime());
      expect(Date.now()).toBeGreaterThanOrEqual(deadline - 20);
      expect(Date.now()).toBeLessThan(deadline + 1000);
    } finally {
      await transport.stop();
    }
  });

  it.each([
    'TLSv1.2',
    'TLSv1.3',
  ] as const)('requires a full handshake for new %s connections', async (version) => {
    const ca = await certificates();
    const own = await ca.issue('spiffe://example.org/mcp/fhir');
    const peer = await ca.issue(research);
    const { fetcher, port, transport } = await serverFor(own, version);
    const agent = new https.Agent({ keepAlive: false, maxCachedSessions: 100 });
    const reused: boolean[] = [];
    transport.setAuthorizedHandler((_req, res) => res.end('synthetic'));
    const observe = (_raw: Buffer, socket: import('node:tls').TLSSocket) => {
      reused.push(socket.isSessionReused());
      expect(socket.getProtocol()).toBe(version);
    };
    try {
      for (let i = 0; i < 2; i++) {
        expect((await request(port, own, peer, observe, version, agent)).status).toBe(200);
      }
      fetcher.update(await ca.issue('spiffe://example.org/mcp/fhir'));
      expect((await request(port, own, peer, observe, version, agent)).status).toBe(200);
      expect(reused).toEqual([false, false, false]);
    } finally {
      agent.destroy();
      await transport.stop();
    }
  });

  it('refuses TLS 1.2 by default and accepts it only when configured', async () => {
    const ca = await certificates();
    const own = await ca.issue('spiffe://example.org/mcp/fhir');
    const peer = await ca.issue(research);
    const strict = await serverFor(own);
    const legacy = await serverFor(own, 'TLSv1.2');
    strict.transport.setAuthorizedHandler((_req, res) => res.end('synthetic'));
    legacy.transport.setAuthorizedHandler((_req, res) => res.end('synthetic'));
    const protocols: (string | null)[] = [];
    const observe = (_raw: Buffer, socket: import('node:tls').TLSSocket) => {
      protocols.push(socket.getProtocol());
    };
    try {
      await expect(request(strict.port, own, peer, undefined, 'TLSv1.2')).rejects.toThrow();
      expect((await request(strict.port, own, peer, observe)).status).toBe(200);
      expect((await request(legacy.port, own, peer, observe, 'TLSv1.2')).status).toBe(200);
      expect(protocols).toEqual(['TLSv1.3', 'TLSv1.2']);
    } finally {
      await strict.transport.stop();
      await legacy.transport.stop();
    }
  });

  it('closes a long-lived connection at the five-minute cap', async () => {
    const ca = await certificates();
    const own = await ca.issue('spiffe://example.org/mcp/fhir');
    const peer = await ca.issue(research);
    const { port, transport } = await serverFor(own);
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    try {
      const active = await stream(port, own, peer);
      let closed = false;
      void active.closed.then(() => {
        closed = true;
      });
      await vi.advanceTimersByTimeAsync(299_999);
      expect(closed).toBe(false);
      await vi.advanceTimersByTimeAsync(1);
      await active.closed;
      expect(closed).toBe(true);
    } finally {
      vi.useRealTimers();
      await transport.stop();
    }
  });

  it('does not dispatch a request whose validation crossed a credential update', async () => {
    const ca = await certificates();
    const own = await ca.issue('spiffe://example.org/mcp/fhir');
    const peer = await ca.issue(research);
    const { fetcher, port, transport } = await serverFor(own);
    let release!: () => void;
    let entered!: () => void;
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    const validating = new Promise<void>((resolve) => {
      entered = resolve;
    });
    const original = SpiffeValidator.prototype.validate;
    const validation = vi
      .spyOn(SpiffeValidator.prototype, 'validate')
      .mockImplementation(async function (this: SpiffeValidator, cert, now) {
        entered();
        await held;
        return original.call(this, cert, now);
      });
    const handler = vi.fn((_req, res) => res.end('synthetic'));
    transport.setAuthorizedHandler(handler);
    try {
      const pending = request(port, own, peer).then(
        () => false,
        () => true,
      );
      await validating;
      fetcher.update(own);
      release();
      expect(await pending).toBe(true);
      await new Promise<void>((resolve) => setImmediate(resolve));
      expect(handler).not.toHaveBeenCalled();
      validation.mockRestore();
      expect((await request(port, own, peer)).status).toBe(200);
    } finally {
      release();
      validation.mockRestore();
      await transport.stop();
    }
  });

  it('invalid TLS material cannot leave an old context serving traffic', async () => {
    const ca = await certificates();
    const own = await ca.issue('spiffe://example.org/mcp/fhir');
    const peer = await ca.issue(research);
    const { fetcher, port, transport } = await serverFor(own);
    const stderr = vi.spyOn(process.stderr, 'write').mockReturnValue(true);
    try {
      const active = await stream(port, own, peer);
      fetcher.update({ ...own, privateKey: new Uint8Array([1, 2, 3]) });
      await active.closed;
      await expect(request(port, own, peer)).rejects.toThrow();
      expect(stderr).toHaveBeenCalledWith('bridge: rotated TLS context unavailable\n');
      fetcher.update(own);
      transport.setAuthorizedHandler((_req, res) => res.end('synthetic'));
      expect((await request(port, own, peer)).status).toBe(200);
    } finally {
      stderr.mockRestore();
      await transport.stop();
    }
  });
});
