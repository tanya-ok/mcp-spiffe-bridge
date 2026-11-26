// Caller: node client.mjs <url> [--forged <dir>] [--stream <seconds>]
// Server verification stays on: the CA is the server's trust domain bundle from this workload's SVID.
import { readFileSync } from 'node:fs';
import https from 'node:https';
import { WorkloadApiSvidFetcher } from 'mcp-spiffe-bridge';

const [url, ...rest] = process.argv.slice(2);
const flag = (name) => {
  const i = rest.indexOf(name);
  return i === -1 ? undefined : rest[i + 1];
};
const pem = (label, der) =>
  `-----BEGIN ${label}-----\n${Buffer.from(der)
    .toString('base64')
    .match(/.{1,64}/g)
    .join('\n')}\n-----END ${label}-----\n`;

const fetcher = new WorkloadApiSvidFetcher({ socketPath: 'unix:///run/spire/sockets/agent.sock' });
fetcher.start();
const svid = await fetcher.getX509Svid();
const serverAnchors =
  svid.spiffeId.trustDomain === 'example.org'
    ? svid.trustBundle
    : (svid.federatedBundles?.get('example.org') ?? []);
const forged = flag('--forged');
const cert = forged
  ? readFileSync(`${forged}/chain.pem`, 'utf8')
  : svid.certChain.map((c) => pem('CERTIFICATE', c)).join('');
const key = forged
  ? readFileSync(`${forged}/key.pem`, 'utf8')
  : pem('PRIVATE KEY', svid.privateKey);
const streamSeconds = Number(flag('--stream') ?? 0);

const result = await new Promise((resolve) => {
  const started = Date.now();
  const req = https.get(
    url,
    {
      ca: serverAnchors.map((c) => pem('CERTIFICATE', c)),
      cert,
      key,
      agent: false,
      checkServerIdentity: (_host, peer) =>
        peer.subjectaltname?.split(', ').includes('URI:spiffe://example.org/mcp/server')
          ? undefined
          : new Error('unexpected server SPIFFE ID'),
    },
    (res) => {
      let body = '';
      let chunks = 0;
      res.on('data', (d) => {
        body += d;
        chunks++;
      });
      const done = (closedEarly) =>
        resolve({
          status: res.statusCode,
          chunks,
          closedEarly,
          seconds: (Date.now() - started) / 1000,
          body: streamSeconds ? undefined : body,
        });
      if (streamSeconds) {
        const timer = setTimeout(() => {
          res.destroy();
          done(false);
        }, streamSeconds * 1000);
        res.on('close', () => {
          clearTimeout(timer);
          done(true);
        });
      } else {
        res.on('end', () => done(false));
      }
    },
  );
  req.on('error', (err) => resolve({ error: err.code ?? err.message }));
});
console.log(
  JSON.stringify({ caller: svid.spiffeId.full, serial: svid.certChain.length, ...result }),
);
await fetcher.close();
