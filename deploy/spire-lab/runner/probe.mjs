// Prints what the SPIRE Workload API actually returns, from the raw gRPC response.
import { createClient } from 'spiffe';

const client = createClient('unix:///run/spire/sockets/agent.sock');
const abort = new AbortController();
const call = client.fetchX509SVID({}, { abort: abort.signal });
for await (const response of call.responses) {
  console.log(
    JSON.stringify({
      svids: response.svids.map((s) => s.spiffeId),
      crlCount: response.crl.length,
      federatedBundleKeys: Object.keys(response.federatedBundles),
    }),
  );
  break;
}
abort.abort();
