# Experimental HNSR proof of concept

This branch contains a deliberately bounded, regtest-only implementation of
the unnamed `HNS_NODE_V1` path from the draft **Handshake P2P Rendezvous and
Authenticated Service Relay** HIP.

It is reference code for exercising the wire shape, authorization boundaries,
and lifecycle on actual `hsd` peers. It is not a production relay, a permanent
wire assignment, or a claim that every phase of the draft HIP is implemented.

## Private assignments

| Symbol | Private value |
| --- | ---: |
| HNSR rendezvous service | `0x04000000` |
| HNSR relay service | `0x08000000` |
| HNSR packet type | `0xf3` |

The roles cannot be enabled outside regtest. Nodes on other networks do not
advertise either bit. These values are collision-prone experimental values and
must be replaced if the protocol receives assigned values.

## Implemented trial profile

The branch implements:

- the version-1 HNSR envelope and all 21 reserved opcode numbers;
- strict envelope length, flag, version, opcode, and context checks;
- regtest-only role advertisement;
- endpoint-signed `RESERVE`, relay-signed `OFFER`, endpoint `CONFIRM`, and
  jointly authenticated relay tickets;
- strict-DER, low-S secp256k1 signatures with network- and domain-separated
  digests;
- self-authorized unnamed endpoint delegations and route records for
  `HNS_NODE_V1`;
- bounded, expiring, sequence-aware in-memory route storage;
- `PUTROUTE` / `PUTRESULT` and exact-key `GETROUTE` / `ROUTES`;
- `OPEN` / `INCOMING` / `ACCEPT` / `OPENED` circuit establishment;
- opaque `DATA`, directional `WINDOW`, and `CLOSE` forwarding;
- per-ticket circuit and byte limits, bounded frames, and relay-side
  directional credit enforcement;
- immediate local reservation invalidation when the endpoint peer disconnects;
  and
- a virtual socket suitable for a complete end-to-end inner Brontide session.

The proof-of-concept handler does not forward to a requester-selected host or
port. A circuit can terminate only at the exact live peer connection bound to
the signed reservation.

## Deliberately unimplemented

The branch does not yet implement:

- iterative `FINDNODE` / `NODES` XOR routing or eight-node replication;
- `SAMPLEROUTES`, `RENEW`, or `WITHDRAW` behavior;
- named HNS authority, TXT root-key parsing, service authorizations, or
  `HNS_WEB_V1`;
- persistent routing buckets or route storage;
- multi-relay selection, republishing, failover, or topology scoring;
- public-node admission, routability, per-prefix, or netgroup policy;
- RPCs, wallet integration, SPV discovery, Android lifecycle integration, or
  browser-origin behavior;
- relay payment, reputation, or production abuse controls; or
- the production scheduler and telemetry required before any public-network
  experiment.

Those boundaries are intentional. In particular, direct exact-key storage at
one rendezvous FullNode validates authenticated record storage but is not a
Kademlia conformance claim.

## Reproducible trial

From this branch:

```sh
npm ci
NODE_BACKEND=js npm run test-file -- test/hnsr-test.js test/net-test.js
NODE_BACKEND=js node scripts/run-hnsr-regtest-trial.js \
  ../artifacts/hnsr-regtest-trial.json
```

`NODE_BACKEND=js` selects bcrypto's portable JavaScript backend and is not a
protocol requirement.

The trial starts four independently keyed, independently prefixed FullNodes:

```text
Endpoint (no listener) == outer Brontide ==> Relay
Endpoint (no listener) == outer Brontide ==> Rendezvous
Requester              == outer Brontide ==> Relay
Requester              == outer Brontide ==> Rendezvous
```

It then:

1. propagates a mined regtest block to height 1 across all four nodes;
2. obtains and mutually signs a relay reservation;
3. publishes and retrieves an authenticated unnamed route;
4. opens a relayed `HNS_NODE_V1` circuit;
5. completes a second, end-to-end Brontide handshake inside the opaque
   circuit;
6. exchanges ordinary Handshake `version`, `verack`, `ping`, and `pong`
   packets over that inner session;
7. verifies both inner static peer identities;
8. verifies that the ping nonce is absent from every relay-visible `DATA`
   payload; and
9. disconnects the endpoint, retrieves the intentionally stale route, and
   confirms that the relay rejects its now-invalid ticket.

The evidence file contains fresh identities, ticket ID, route key, circuit ID,
opcode counts, byte counts, and a ciphertext transcript hash. Random values
change on every run.

## Configuration surface

The following illustrative flags are recognized by `FullNode`:

```text
--experimental-hnsr
--experimental-hnsr-endpoint
--experimental-hnsr-relay
--experimental-hnsr-rendezvous
--experimental-hnsr-timeout=<milliseconds>
```

The relay role also requires the ordinary peer listener. Endpoint and requester
roles advertise no HNSR service bit.
