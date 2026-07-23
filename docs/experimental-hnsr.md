# Experimental HNSR proof of concept

This branch contains a deliberately bounded, regtest-only implementation of
the Phase 1 `HNS_NODE_V1` and `HNS_WEB_V1` paths from the draft **Handshake P2P
Rendezvous and Authenticated Service Relay** HIP.

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

## Implemented trial profiles

The branch implements:

- the version-1 HNSR envelope and all 21 reserved opcode numbers;
- strict envelope length, flag, version, opcode, and context checks;
- regtest-only role advertisement;
- iterative `FINDNODE` / `NODES` discovery with XOR ordering, parallelism of
  three, a 32-query bound, authenticated rendezvous contacts, and connections
  to newly discovered Handshake peers;
- publisher-driven route replication with a configurable replica count and
  minimum-store quorum;
- deterministic bounded `SAMPLEROUTES` discovery for unnamed node routes;
- endpoint-signed `RESERVE`, relay-signed `OFFER`, endpoint `CONFIRM`, and
  jointly authenticated relay tickets;
- reservation `RENEW` and signed `WITHDRAW`, including retirement of replaced
  tickets;
- strict-DER, low-S secp256k1 signatures with network- and domain-separated
  digests;
- self-authorized unnamed endpoint delegations and route records for
  `HNS_NODE_V1`;
- bounded, expiring, sequence-aware in-memory route storage with global,
  per-key, and per-publishing-peer limits;
- `PUTROUTE` / `PUTRESULT` and exact-key `GETROUTE` / `ROUTES`;
- multi-relay records, renewed-record republishing, sequential relay failover,
  and failure reporting;
- `OPEN` / `INCOMING` / `ACCEPT` / `OPENED` circuit establishment;
- opaque `DATA`, directional `WINDOW`, and `CLOSE` forwarding;
- per-ticket circuit and byte limits, bounded frames, and relay-side
  directional credit enforcement;
- bounded relay queues with burst-yield scheduling, control-request admission,
  request-byte limits, and observable queue/drop counters;
- immediate local reservation invalidation when the endpoint peer disconnects;
  and
- actual inbound and outbound `Peer` objects in the ordinary HSD pool, running
  complete end-to-end Brontide and Handshake peer sessions over virtual circuit
  sockets;
- current, validated, closed HNS name-state lookup and canonical
  `hnsr1 k=<base32-key>` TXT parsing with ambiguity rejection;
- root-signed service authorization, service-signed endpoint delegation, named
  route-key derivation, and complete requester-side authority-chain checks;
- replicated named `HNS_WEB_V1` records for multiple endpoints;
- inner endpoint-authenticated Brontide carrying bounded HTTP/1.1 requests and
  responses without exposing their plaintext to the relay;
- strict Host, HNS authority, and service agreement, with duplicate-header,
  transfer-encoding, upgrade, body-size, request-count, and timeout limits;
- reusable inner web sessions for up to 16 request/response exchanges;
- stable origin derivation from `(hnsr, name_hash, service_name, profile_id)`,
  independent of relay, ticket, and endpoint rotation; and
- sequential named-endpoint and per-record relay failover.

The proof-of-concept handler does not forward to a requester-selected host or
port. A circuit can terminate only at the exact live peer connection bound to
the signed reservation.

## Milestone boundaries

The following groups are deliberately separated so that completion of the
unnamed-node experiment is not confused with named services, client product
work, or public-network readiness.

### Unnamed-node Phase 1: implemented here

The branch completes the directly executable unnamed `HNS_NODE_V1` slice:

- two independent relay candidates in each tested route;
- four iteratively discovered rendezvous nodes and four-copy publication;
- random unnamed-node sampling and exact-key lookup;
- reservation, renewal, replacement publication, withdrawal, disconnect, and
  stale-ticket rejection;
- rendezvous loss and first-relay failure recovery;
- real inner full-node block traffic; and
- flow-control, scheduler saturation, control admission, and zero-drop checks.

The rendezvous table is intentionally the bounded live/recently-connected
contact set for this regtest phase. It exercises iterative XOR routing but is
not yet the persistent bucket implementation required for a public network.

### Phase 1B: named-service regtest implemented here

The branch completes the directly executable, bounded `HNS_WEB_V1` slice:

- an on-chain regtest name auction and authenticated root-key `UPDATE`;
- service authorization, two endpoint delegations, and four-copy named routes;
- inner Brontide HTTP request/response and same-circuit connection reuse;
- authority mismatch rejection and stable browser-origin derivation;
- endpoint failure followed by authenticated fallback; and
- web-specific cryptographic, framing, circuit, byte, and admission limits.

This PoC intentionally buffers each bounded HTTP message (maximum 16 KiB of
headers and 1 MiB of body) instead of providing an unbounded streaming API.
It derives and returns the mandatory origin tuple, but HSD cannot itself
isolate browser cookies, storage, permissions, or service workers. Native
browser enforcement remains a Phase 3 client-integration requirement.

### Phase 2: bounded testnet hardening

Still required before any testnet experiment:

- persistent routing buckets and optional durable route storage;
- eight-replica, multi-path churn tests over larger and adversarial topologies;
- public-address admission, routability, per-prefix, and netgroup policy;
- peer-dial budgets, topology scoring, republish/failover timers, and restart
  recovery; and
- scheduler integration that explicitly prioritizes blocks, headers, proofs,
  and transaction traffic, plus operational telemetry.

### Phase 3: node, mobile, and browser integration

Still required for user-facing adoption:

- RPCs and configuration/status APIs;
- address-manager, wallet, and SPV discovery integration;
- Android foreground/background lifecycle and network-change handling;
- HNS-aware browser navigation and named-origin behavior; and
- operator documentation, compatibility behavior, and upgrade UX.

### Public-network and production readiness

Permanent service/packet assignments, production abuse controls, reputation or
payment policy, privacy review, deployment gates, and sustained public-network
load measurements remain outside this PoC. The regtest-only feature guard stays
in place until those questions are resolved.

## Reproducible trial

From this branch:

```sh
npm ci
NODE_BACKEND=js npm run test-file -- \
  test/hnsr-test.js test/brontide-test.js test/net-test.js
NODE_BACKEND=js node scripts/run-hnsr-regtest-trial.js \
  docs/hnsr-regtest-phase1.json
```

`NODE_BACKEND=js` selects bcrypto's portable JavaScript backend and is not a
protocol requirement.

The trial starts nine independently keyed, independently prefixed FullNodes:

```text
Endpoint/fallback web (no listener) ==> Relay A, Relay B, Rendezvous 0
Primary web endpoint (no listener)  ==> Relay A, Relay B, Rendezvous 0
Requester                           ==> Rendezvous 0
Rendezvous 0 ==> Rendezvous 1 ==> Rendezvous 2 ==> Rendezvous 3

Requester == inner HNS peer ==> surviving relay ==> Endpoint
Requester == inner HNS_WEB_V1 ==> relay ==> authenticated named endpoint
```

It then:

1. mines a shared regtest chain, auctions `phase1b`, and publishes a canonical
   HNSR root key in its authenticated resource;
2. authorizes `p2p-site`, registers two named web endpoints, and publishes both
   named records to four rendezvous nodes;
3. performs an HTTP request over inner Brontide, reuses another inner circuit
   for two requests, rejects a mismatched authority with status 421, and proves
   relay DATA frames do not contain the response plaintext;
4. disconnects the primary named endpoint and reaches the fallback endpoint
   after rejecting the stale higher-sequence candidate;
5. iteratively discovers all four rendezvous nodes from one bootstrap;
6. reserves both relays and stores one signed unnamed route at all four
   rendezvous nodes;
7. discovers the unnamed route with `SAMPLEROUTES`;
8. renews both tickets, republishes a higher sequence, and withdraws the old
   reservations;
9. issues 72 concurrent lookup requests and verifies bounded admission;
10. stops one rendezvous node and retrieves the refreshed record from the three
   survivors;
11. stops Relay A and verifies automatic fallback to Relay B;
12. constructs ordinary inbound/outbound HSD `Peer` objects over the circuit
   and verifies both inner static identities;
13. sends 1,000 ordinary Handshake pings while mining and relaying a real block;
14. proves only endpoint and requester advance from height 47 to 48 while both
    relays and all rendezvous controls remain at height 47;
15. verifies bounded queues, multiple scheduler yields, a control reservation
    during load, and zero relay drops; and
16. disconnects the endpoint, retrieves the intentionally stale route, and
    confirms the surviving relay rejects its invalid ticket.

The checked-in `docs/hnsr-regtest-phase1.json` is one passing run. It records
topology, discovery, replica survival, lifecycle transitions, selected relay,
block-only inner convergence, saturation counters, admission results, opcode
counts, and a ciphertext transcript hash. Random values change on every run.

## Configuration surface

The following illustrative flags are recognized by `FullNode`:

```text
--experimental-hnsr
--experimental-hnsr-endpoint
--experimental-hnsr-relay
--experimental-hnsr-rendezvous
--experimental-hnsr-web
--experimental-hnsr-timeout=<milliseconds>
```

The relay role also requires the ordinary peer listener. Endpoint and requester
roles advertise no HNSR service bit.
