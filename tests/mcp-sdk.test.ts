import { randomUUID, webcrypto } from 'node:crypto';
import { readFileSync } from 'node:fs';
import * as https from 'node:https';
import * as net from 'node:net';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
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
const allowed = 'spiffe://example.org/agent/research';
const intruder = 'spiffe://example.org/agent/intruder';

async function syntheticCa() {
  const keys = await webcrypto.subtle.generateKey(algorithm, true, ['sign', 'verify']);
  const ca = await x509.X509CertificateGenerator.createSelfSigned({
    name: `CN=Synthetic SDK test CA ${randomUUID()}`,
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
  return async (id: string): Promise<X509Svid> => {
    const leafKeys = await webcrypto.subtle.generateKey(algorithm, true, ['sign', 'verify']);
    const cert = await x509.X509CertificateGenerator.create({
      subject: 'CN=Synthetic SDK test workload',
      issuer: ca.subject,
      publicKey: leafKeys.publicKey,
      signingKey: keys.privateKey,
      signingAlgorithm,
      notBefore: new Date(Date.now() - 60_000),
      notAfter: new Date(Date.now() + 3_600_000),
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
  };
}

function pem(label: string, value: Uint8Array) {
  const body = Buffer.from(value)
    .toString('base64')
    .match(/.{1,64}/g)
    ?.join('\n');
  return `-----BEGIN ${label}-----\n${body}\n-----END ${label}-----`;
}

async function freePort() {
  const server = net.createServer();
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('port unavailable');
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return address.port;
}

/** Fetch over node:https with a client certificate; server verification stays on. */
function mtlsFetch(trust: X509Svid, client: X509Svid) {
  const agent = new https.Agent({
    ca: trust.trustBundle.map((c) => pem('CERTIFICATE', c)),
    cert: client.certChain.map((c) => pem('CERTIFICATE', c)).join('\n'),
    key: pem('PRIVATE KEY', client.privateKey),
    keepAlive: false,
  });
  const fetchLike = async (input: string | URL, init?: RequestInit): Promise<Response> => {
    const url = new URL(input);
    const headers: Record<string, string> = {};
    new Headers(init?.headers).forEach((value, key) => {
      headers[key] = value;
    });
    const body = typeof init?.body === 'string' ? init.body : undefined;
    return new Promise<Response>((resolve, reject) => {
      const req = https.request(
        url,
        {
          method: init?.method ?? 'GET',
          headers,
          agent,
          family: 4,
          signal: init?.signal ?? undefined,
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on('data', (chunk: Buffer) => chunks.push(chunk));
          res.on('error', reject);
          res.on('end', () => {
            const status = res.statusCode ?? 500;
            const responseHeaders = new Headers();
            for (const [key, value] of Object.entries(res.headers)) {
              if (typeof value === 'string') responseHeaders.set(key, value);
              else if (Array.isArray(value)) for (const v of value) responseHeaders.append(key, v);
            }
            const empty = status === 204 || status === 205 || status === 304;
            resolve(
              new Response(empty ? null : Buffer.concat(chunks), {
                status,
                headers: responseHeaders,
              }),
            );
          });
        },
      );
      req.on('error', reject);
      req.end(body);
    });
  };
  return { fetch: fetchLike, close: () => agent.destroy() };
}

async function startServer() {
  const issue = await syntheticCa();
  const own = await issue('spiffe://example.org/mcp/server');
  const port = await freePort();
  const fetcher: SvidFetcher = {
    getX509Svid: async () => own,
    watchSvids: () => () => {},
    close: async () => {},
  };
  const audit = { log: vi.fn() };
  const toolCalls = vi.fn();
  const transport = new MtlsTransportServer({
    fetcher,
    validator: new SpiffeValidator({ allowedCallers: [allowed], minTtlSeconds: 5 }, fetcher),
    audit,
    transport: { mode: 'mtls-server', sse: { host: '127.0.0.1', port } },
  });
  transport.setAuthorizedHandler(async (req, res) => {
    const server = new McpServer({ name: 'sdk-range-test', version: '0.0.0' });
    server.registerTool('whoami', { description: 'Returns the verified caller' }, async () => {
      toolCalls();
      return { content: [{ type: 'text', text: getCallerIdentity()?.spiffeId.full ?? 'none' }] };
    });
    const mcp = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: true,
    });
    res.on('close', () => {
      void mcp.close();
      void server.close();
    });
    await server.connect(mcp);
    await mcp.handleRequest(req, res);
  });
  await transport.start();
  return { issue, own, port, audit, toolCalls, transport };
}

describe('@modelcontextprotocol/sdk behind the mTLS listener', () => {
  it('initializes, lists and calls a tool with the verified caller in context', async () => {
    const { issue, own, port, toolCalls, transport } = await startServer();
    const http = mtlsFetch(own, await issue(allowed));
    const client = new Client({ name: 'sdk-range-client', version: '0.0.0' });
    try {
      await client.connect(
        new StreamableHTTPClientTransport(new URL(`https://localhost:${port}/mcp`), {
          fetch: http.fetch,
        }),
      );
      const tools = await client.listTools();
      expect(tools.tools.map((t) => t.name)).toEqual(['whoami']);
      const result = await client.callTool({ name: 'whoami', arguments: {} });
      expect(result.content).toEqual([{ type: 'text', text: allowed }]);
      expect(toolCalls).toHaveBeenCalledTimes(1);
    } finally {
      await client.close();
      http.close();
      await transport.stop();
    }
  });

  it('never reaches the SDK for a trusted but disallowed caller', async () => {
    const { issue, own, port, audit, toolCalls, transport } = await startServer();
    const http = mtlsFetch(own, await issue(intruder));
    const client = new Client({ name: 'sdk-range-client', version: '0.0.0' });
    try {
      await expect(
        client.connect(
          new StreamableHTTPClientTransport(new URL(`https://localhost:${port}/mcp`), {
            fetch: http.fetch,
          }),
        ),
      ).rejects.toThrow();
      expect(toolCalls).not.toHaveBeenCalled();
      expect(audit.log).toHaveBeenCalledWith(
        expect.objectContaining({ event_type: 'auth_failure', caller_spiffe_id: intruder }),
      );
    } finally {
      await client.close();
      http.close();
      await transport.stop();
    }
  });
});

describe('declared SDK support range', () => {
  const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as {
    peerDependencies: Record<string, string>;
    peerDependenciesMeta?: Record<string, { optional?: boolean }>;
  };
  const sdkPkg = JSON.parse(
    readFileSync(
      new URL('../node_modules/@modelcontextprotocol/sdk/package.json', import.meta.url),
      'utf8',
    ),
  ) as { version: string };

  it('is bounded below the next major and starts at the tested version', () => {
    const range = pkg.peerDependencies['@modelcontextprotocol/sdk'];
    const match = /^>=(\d+)\.(\d+)\.(\d+) <(\d+)\.0\.0$/.exec(range ?? '');
    expect(match, `unexpected range ${range}`).not.toBeNull();
    const [, major, minor, patch, ceiling] = (match ?? []).map(Number);
    const [iMajor, iMinor, iPatch] = sdkPkg.version.split('.').map(Number);
    expect(ceiling).toBe((major ?? 0) + 1);
    expect(iMajor).toBe(major);
    expect((iMinor ?? 0) * 1e6 + (iPatch ?? 0)).toBeGreaterThanOrEqual(
      (minor ?? 0) * 1e6 + (patch ?? 0),
    );
  });

  it('is optional because the library does not import the SDK at runtime', () => {
    expect(pkg.peerDependenciesMeta?.['@modelcontextprotocol/sdk']?.optional).toBe(true);
  });
});
