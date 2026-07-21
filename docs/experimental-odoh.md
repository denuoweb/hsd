# Experimental Handshake P2P ODoH relay

This branch is a regtest-only proof of concept for the draft **Handshake P2P
Transport for Oblivious DNS Relay** HIP. It is based on
`feat/p2p-dns-relay` at `ea31be1554f3235bfa96bdd394e6d33e7dda8080` and
reuses that branch's query admission, active-name check, resource limits, and
recursive backend.

The private assignments are:

| Item | Private value |
| --- | ---: |
| `EXPERIMENTAL_ODOH_SERVICE` | `0x20000000` |
| `EXPERIMENTAL_ODOH` packet | `0xf2` |

They are not standards assignments. The implementation refuses to enable a
proxy or target role outside regtest and must not be advertised on mainnet.

## Implemented profile

The PoC implements:

- the version-1 `ODNS` envelope and all ten opcodes;
- proxy and target capability negotiation;
- requester-selected direct Brontide target locators;
- signed, short-lived target configuration records;
- RFC 9230 configuration, message, padding, key-ID, and response encoding;
- RFC 9180 DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, and AES-128-GCM through
  the maintained `@hpke` packages;
- independent random request IDs on the requester-proxy and proxy-target hops;
- bounded proxy mappings, deadlines, cancellation, and disconnect cleanup;
- target replay detection;
- generic target failure mapping without a decryption oracle;
- reuse of the base P2P DNS relay service after target decryption;
- public-address enforcement, with a narrow explicit regtest loopback/private
  exception;
- preconnected authenticated target selection, with no arbitrary socket
  forwarding.

The PoC deliberately does not implement HNSR locators, target connection
establishment on demand, config caching, key rotation/overlap, persistent key
storage, multi-target scheduling, outer bucket padding, or production
telemetry. A proxy can forward only to an already connected outbound Brontide
peer whose address, port, authenticated peer key, service bits, and target role
match the signed locator.

## Configuration

All roles are disabled by default.

```text
Proxy:
  --experimental-odoh-proxy

Target:
  --experimental-dns-relay
  --experimental-odoh-target
  --experimental-odoh-target-host=<numeric host>
  --experimental-odoh-target-port=<brontide port>

Regtest-only private target addresses:
  --experimental-odoh-allow-private-targets

Limits:
  --experimental-odoh-timeout=<milliseconds>
  --experimental-odoh-max-live=<count>
```

`--experimental-odoh-instrumentation` is a regtest-only test hook. It emits
in-memory proxy-ciphertext and target-plaintext events used by the trial
harness. It is off by default and rejected outside regtest.

## Reproducible regtest trial

Install the locked JavaScript dependencies, then run:

```sh
npm ci
node scripts/run-odoh-regtest-trial.js ../artifacts/regtest-trial.json
```

The runner creates three independent persistent-but-disposable FullNodes with
different peer identities:

```text
Requester == Brontide ==> Proxy == Brontide ==> Target
```

The requester retrieves a signed target configuration through the proxy and
sends an encrypted `www.relaytest. A` query. The target decrypts it and passes
the raw DNS query through the prerequisite `DNSRelayService` admission and
scheduling path. A deterministic trial backend returns the response; the
target encrypts it, the proxy forwards it unchanged, and the requester opens
and correlates it.

The runner fails unless all of these hold:

- proxy and target advertise the expected private capabilities;
- the target connection is authenticated by its Brontide peer key;
- the target configuration signature, network, lifetime, locator, and ID
  validate at the requester;
- the serialized plaintext query is absent from the proxy-observed ODoH
  ciphertext;
- the target sees the exact admitted raw query;
- client and target request IDs differ;
- the base relay accepts exactly one request and returns exactly one response;
- the requester receives the expected response;
- the requester rejects malformed, non-recursive, or mismatched DNS replies;
- proxy and target live mappings return to zero.

The JSON artifact contains aggregate counters, public test identities,
per-run configuration/ciphertext digests, and the asserted privacy views. It
contains no private key material.

## Trial boundary

This is a transport/cryptography/regtest integration trial, not the base HIP's
full DNSSEC/DANE acceptance tier. It uses three real `hsd` FullNodes and real
Handshake framing/Brontide, but injects a deterministic recursive backend and
an active-name predicate after the normal base-HIP query parser and scheduler.

Therefore the result does not claim:

- a mined and registered regtest HNS name;
- live delegation recursion or authority isolation;
- requester-side Urkel, DNSSEC, TLSA, or DANE validation;
- an Android/iOS application-binary run;
- HNSR target reachability;
- key rotation, overlap, failover, load, or anonymity-set measurements;
- readiness for testnet or mainnet.

Those are separate acceptance tiers. In particular, the browser's existing
direct P2P DNS relay trial is evidence for the prerequisite path, not evidence
that the browser currently implements this ODoH extension.

## Verification

```sh
npx --yes eslint@9 \
  lib/net/odoh.js lib/net/common.js lib/net/packets.js lib/net/parser.js \
  lib/net/pool.js lib/node/fullnode.js lib/net/index.js \
  test/odoh-test.js scripts/run-odoh-regtest-trial.js

npm run test-file -- \
  test/odoh-test.js test/dns-relay-test.js test/net-test.js
```

The tests cover strict envelope/body parsing, locator restrictions, signed
config verification, all-zero padding, HPKE query/response round trips, wrong
keys, requester-side DNS response correlation, proxy/target routing,
independent hop IDs, replay rejection, and the prerequisite DNS-relay and
network packet regression suites.
