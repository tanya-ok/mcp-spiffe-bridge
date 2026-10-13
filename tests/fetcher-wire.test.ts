import { mkdtemp, rm } from 'node:fs/promises';
import { createServer, type ServerHttp2Session, type ServerHttp2Stream } from 'node:http2';
import { X509SVIDResponse } from 'spiffe';
import { expect, it } from 'vitest';
import { WorkloadApiSvidFetcher } from '../src/svid/fetcher.js';
import { makeSpiffeCert } from './helpers/test-certs.js';

it('recovers through the real spiffe gRPC client after a Unix socket connection drops', async () => {
  const directory = await mkdtemp('/tmp/bridge-wire-');
  const socketPath = `${directory}/api.sock`;
  const cert = await makeSpiffeCert({ spiffeId: 'spiffe://example.org/agent/research' });
  const replacement = await makeSpiffeCert({ spiffeId: 'spiffe://example.org/agent/research' });
  const server = createServer();
  const sessions = new Set<ServerHttp2Session>();
  let current: ServerHttp2Stream | undefined;
  let calls = 0;
  let reconnected!: () => void;
  const newCall = new Promise<void>((resolve) => {
    reconnected = resolve;
  });
  function send(stream: ServerHttp2Stream, material: typeof cert) {
    const message = X509SVIDResponse.toBinary(
      X509SVIDResponse.create({
        svids: [
          {
            spiffeId: 'spiffe://example.org/agent/research',
            x509Svid: material.certDer,
            x509SvidKey: material.privateKeyDer,
            bundle: material.certDer,
            hint: '',
          },
        ],
        federatedBundles: {},
        crl: [],
      }),
    );
    const prefix = Buffer.alloc(5);
    prefix.writeUInt32BE(message.byteLength, 1);
    stream.write(Buffer.concat([prefix, message]));
  }
  server.on('session', (session) => {
    sessions.add(session);
    session.once('close', () => sessions.delete(session));
    session.on('error', () => {});
  });
  server.on('stream', (stream, headers) => {
    stream.on('error', () => {});
    stream.resume();
    expect(headers[':path']).toBe('/SpiffeWorkloadAPI/FetchX509SVID');
    expect(headers['workload.spiffe.io']).toBe('true');
    stream.respond({ ':status': 200, 'content-type': 'application/grpc' });
    current = stream;
    calls++;
    if (calls === 1) send(stream, cert);
    else reconnected();
  });
  const fetcher = new WorkloadApiSvidFetcher({
    socketPath,
    connectTimeoutMs: 3000,
    rpcTimeoutMs: 3000,
    reconnect: { maxAttempts: 5, initialDelayMs: 50, maxDelayMs: 200 },
  });
  try {
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(socketPath, resolve);
    });
    const initial = await fetcher.getX509Svid();
    let unavailable!: () => void;
    const lost = new Promise<void>((resolve) => {
      unavailable = resolve;
    });
    fetcher.watchAvailability((available) => {
      if (!available) unavailable();
    });
    for (const session of sessions) session.destroy();
    await lost;
    await expect(fetcher.getX509Svid()).rejects.toThrow('stream unavailable');
    await newCall;
    await expect(fetcher.getX509Svid()).rejects.toThrow('stream unavailable');
    const fresh = new Promise<void>((resolve) => {
      fetcher.watchSvids(() => resolve());
    });
    if (!current) throw new Error('recovery RPC missing');
    send(current, replacement);
    await fresh;
    expect((await fetcher.getX509Svid()).certChain).not.toEqual(initial.certChain);
    expect(calls).toBe(2);
  } finally {
    await fetcher.close();
    for (const session of sessions) session.destroy();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await rm(directory, { recursive: true, force: true });
  }
}, 15_000);
