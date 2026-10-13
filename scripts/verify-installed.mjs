// Exercise an independently installed package with synthetic certificates and real TLS.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createPrivateKey, X509Certificate } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import https from 'node:https';
import { createRequire } from 'node:module';
import net from 'node:net';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const consumer = process.argv[2];
assert(consumer, 'Pass the independently installed consumer directory');
const require = createRequire(resolve(consumer, 'package.json'));
const { MtlsTransportServer, SpiffeValidator, parseSpiffeId, getCallerIdentity } =
  require('mcp-spiffe-bridge');
const directory = await mkdtemp(join(tmpdir(), 'bridge-installed-demo-'));
const allowed = 'spiffe://example.org/agent/allowed';
const serverId = 'spiffe://example.org/server/demo';
let transport;
let result;
const openssl = (...args) => execFileSync('openssl', args, { cwd: directory, stdio: 'pipe' });
try {
  openssl('genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', 'ca.key');
  openssl(
    'req',
    '-new',
    '-x509',
    '-key',
    'ca.key',
    '-days',
    '1',
    '-subj',
    '/CN=Synthetic local demo CA',
    '-out',
    'ca.pem',
    '-addext',
    'basicConstraints=critical,CA:TRUE',
    '-addext',
    'keyUsage=critical,keyCertSign,cRLSign',
  );
  const caPem = await readFile(join(directory, 'ca.pem'));
  const ca = new X509Certificate(caPem);
  async function issue(name, id) {
    openssl(
      'genpkey',
      '-algorithm',
      'EC',
      '-pkeyopt',
      'ec_paramgen_curve:P-256',
      '-out',
      `${name}.key`,
    );
    openssl('req', '-new', '-key', `${name}.key`, '-subj', '/CN=localhost', '-out', `${name}.csr`);
    await writeFile(
      join(directory, `${name}.ext`),
      `basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=URI:${id},DNS:localhost\n`,
    );
    openssl(
      'x509',
      '-req',
      '-in',
      `${name}.csr`,
      '-CA',
      'ca.pem',
      '-CAkey',
      'ca.key',
      '-CAcreateserial',
      '-days',
      '1',
      '-extfile',
      `${name}.ext`,
      '-out',
      `${name}.pem`,
    );
    const pem = await readFile(join(directory, `${name}.pem`));
    const key = await readFile(join(directory, `${name}.key`));
    const cert = new X509Certificate(pem);
    const spiffeId = parseSpiffeId(id);
    assert(spiffeId);
    return {
      pem,
      key,
      svid: {
        spiffeId,
        certChain: [cert.raw],
        privateKey: createPrivateKey(key).export({ type: 'pkcs8', format: 'der' }),
        trustBundle: [ca.raw],
        notBefore: new Date(cert.validFrom),
        notAfter: new Date(cert.validTo),
      },
    };
  }
  let own = await issue('server', serverId);
  const client = await issue('client', allowed);
  const foreign = await issue('foreign', 'spiffe://example.org/agent/foreign');
  let available = true;
  const svidWatchers = new Set();
  const availabilityWatchers = new Set();
  const fetcher = {
    async getX509Svid() {
      assert(available, 'Synthetic credential source unavailable');
      return own.svid;
    },
    watchSvids(cb) {
      svidWatchers.add(cb);
      return () => svidWatchers.delete(cb);
    },
    watchAvailability(cb) {
      availabilityWatchers.add(cb);
      return () => availabilityWatchers.delete(cb);
    },
    async close() {},
  };
  const reserve = net.createServer();
  await new Promise((done) => reserve.listen(0, '127.0.0.1', done));
  const port = reserve.address().port;
  await new Promise((done) => reserve.close(done));
  const events = [];
  let calls = 0;
  transport = new MtlsTransportServer({
    fetcher,
    validator: new SpiffeValidator({ allowedCallers: [allowed], minTtlSeconds: 60 }, fetcher),
    audit: {
      log(event) {
        events.push(event);
      },
    },
    transport: { mode: 'mtls-server', sse: { host: '127.0.0.1', port } },
  });
  transport.setAuthorizedHandler((_req, res, identity) => {
    assert.equal(identity.spiffeId.full, allowed);
    assert.equal(getCallerIdentity()?.spiffeId.full, allowed);
    calls++;
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ accepted: true }));
  });
  await transport.start();
  function request(peer) {
    return new Promise((done, reject) => {
      const req = https.get(
        {
          hostname: '127.0.0.1',
          servername: 'localhost',
          port,
          ca: caPem,
          agent: false,
          ...(peer ? { cert: peer.pem, key: peer.key } : {}),
        },
        (res) => {
          let body = '';
          res.on('data', (chunk) => {
            body += chunk;
          });
          res.on('end', () => done({ status: res.statusCode, body }));
        },
      );
      req.setTimeout(3000, () => req.destroy(new Error('Request timeout')));
      req.on('error', reject);
    });
  }
  const first = await request(client);
  assert.equal(first.status, 200);
  assert.equal(JSON.parse(first.body).accepted, true);
  const refused = await request(foreign);
  assert.equal(refused.status, 401);
  assert.deepEqual(JSON.parse(refused.body), { error: 'unauthorized' });
  assert(
    events.some(
      (e) => e.outcome === 'denied' && e.denial_reason?.startsWith('SPIFFE_ID_DISALLOWED: '),
    ),
  );
  await assert.rejects(request(), (error) => /CERTIFICATE|ALERT|ECONNRESET/.test(error.code ?? ''));
  assert.equal(calls, 1);
  available = false;
  for (const cb of availabilityWatchers) cb(false);
  const lost = await request(client).catch((error) => {
    assert(/ECONNRESET|ECONNREFUSED|ALERT/.test(error.code ?? ''));
    return { status: 599 };
  });
  assert(lost.status >= 400);
  assert.equal(calls, 1);
  own = await issue('server-recovered', serverId);
  available = true;
  for (const cb of svidWatchers) cb(own.svid);
  for (const cb of availabilityWatchers) cb(true);
  const recovered = await request(client);
  assert.equal(recovered.status, 200);
  assert.equal(calls, 2);
  await transport.stop();
  transport = undefined;
  assert.equal(svidWatchers.size, 0);
  assert.equal(availabilityWatchers.size, 0);
  const listener = net.createServer();
  await new Promise((done, reject) => {
    listener.once('error', reject);
    listener.listen(port, '127.0.0.1', done);
  });
  await new Promise((done) => listener.close(done));
  result = {
    passed: true,
    installed_library: true,
    actual_tls: true,
    allowed: true,
    foreign_identity_denied: true,
    missing_certificate_denied: true,
    credential_loss_denied: true,
    fresh_credential_recovery: true,
    listener_released: true,
    watchers_released: true,
    scope: 'Synthetic local certificate source; no SPIRE attestation or shared-lab run',
  };
} finally {
  try {
    await transport?.stop();
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}
await assert.rejects(readFile(join(directory, 'ca.key')), { code: 'ENOENT' });
console.log(JSON.stringify({ ...result, temporary_keys_removed: true }));
