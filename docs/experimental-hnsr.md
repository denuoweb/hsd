# Experimental HNSR proof of concept

This branch contains a deliberately bounded implementation of the Phase 1 and
Phase 2 `HNS_NODE_V1` and `HNS_WEB_V1` paths from the draft **Handshake P2P
Rendezvous and Authenticated Service Relay** HIP. Regtest remains the default;
testnet use requires a second explicit acknowledgement and public addresses.

It is reference code for exercising the wire shape, authorization boundaries,
and lifecycle on actual `hsd` peers. It is not a production relay, a permanent
wire assignment, or a claim that every phase of the draft HIP is implemented.

## Private assignments

| Symbol | Private value |
| --- | ---: |
| HNSR rendezvous service | `0x04000000` |
| HNSR relay service | `0x08000000` |
| HNSR packet type | `0xf3` |

The roles cannot be enabled on mainnet. Testnet nodes do not advertise either
bit unless both HNSR and `--experimental-hnsr-testnet` are set, and relay or
rendezvous roles also require a publicly routable advertised host. These
values are collision-prone experimental values and must be replaced if the
protocol receives assigned values.

## Implemented trial profiles

The branch implements:

- the version-1 HNSR envelope and all 21 reserved opcode numbers;
- strict envelope length, flag, version, opcode, and context checks;
- regtest role advertisement, plus explicitly acknowledged testnet role
  advertisement under the public-address gate;
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
- bounded, expiring, sequence-aware route storage with optional atomic disk
  persistence and global, per-key, per-peer, and per-prefix limits;
- `PUTROUTE` / `PUTRESULT` and exact-key `GETROUTE` / `ROUTES`;
- multi-relay records, renewed-record republishing, scored relay failover,
  timer-driven refresh before one-third lifetime remains, immediate
  network-change refresh, and failure reporting;
- `OPEN` / `INCOMING` / `ACCEPT` / `OPENED` circuit establishment;
- opaque `DATA`, directional `WINDOW`, and `CLOSE` forwarding;
- per-ticket circuit and byte limits, bounded frames, and relay-side
  directional credit enforcement;
- separate bounded node and web relay budgets with 3:1 weighted service,
  burst-yield scheduling, control-request admission, request, byte,
  verification, prefix, and circuit limits, and telemetry snapshots;
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

Phase 2 additionally supplies 256 persistent XOR buckets (`k = 16`), a 2,048
contact cap, public-address and netgroup admission, failure-based eviction,
an eight-dial discovery budget, eight-copy publication with netgroup-aware
selection, durable restart recovery, and a bounded admission-prefix table.

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

The original four-node trial remains as Phase 1 regression coverage. Phase 2
replaces its flat contact set with persistent XOR buckets without changing the
Phase 1 wire format.

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

Implemented and reproducible on regtest:

- persistent XOR routing buckets and durable route storage with restart
  recovery;
- eight-copy replication, diversity selection, larger-topology discovery, and
  recovery after three rendezvous failures;
- public-address, per-prefix, netgroup, dial, verification, store, requester,
  endpoint, profile, and global admission bounds;
- scored multi-relay failover and scheduled or network-triggered republishing;
- separate node/web relay queues and byte budgets, with ordinary HSD core
  traffic outside the HNSR queues;
- a 160-request DDoS exercise, valid signed route spam, circuit saturation,
  and operational telemetry; and
- an actual inner block propagated while a 1 MiB `HNS_WEB_V1` stream saturates
  the same relay.

The companion native Android test build opens the HNSR connection in Rust,
registers an Android default-network callback, invalidates stale probe
generations, and reconnects after loss and restoration. The checked-in device
screenshot records three successful native probes and complete verification of
the refreshed two-relay record.

Still required before calling Phase 2 a real testnet deployment is an external
run across several independently administered machines and networks, followed
by a sustained soak and operator review. The local trial uses distinct keys,
processes, and persistent prefixes to make that exercise directly runnable; it
does not pretend that one workstation represents independent operators.

### Phase 3: node, mobile, and browser integration

Still required for user-facing adoption:

- RPCs and configuration/status APIs;
- address-manager, wallet, and SPV discovery integration;
- production Android foreground/background, metered-network, battery, and
  thermal policy beyond the native network-change diagnostic;
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
NODE_BACKEND=js node scripts/run-hnsr-phase2-trial.js \
  docs/hnsr-regtest-phase2.json
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

The Phase 2 trial starts 12 independently keyed FullNodes with two relays and
eight rendezvous nodes. It verifies eight initial stores, durable contact and
route recovery, five surviving stores after three failures, immediate
network-change republishing, dead-relay failover, the requester circuit cap,
verification-budget route-spam rejection, 160-request rate limiting, and a
real block over `HNS_NODE_V1` during web-profile saturation. One checked-in run
is in `docs/hnsr-regtest-phase2.json`; the matching Pixel 9 native evidence is
`docs/hnsr-phase2-android.png`.

## Configuration surface

The following illustrative flags are recognized by `FullNode`:

```text
--experimental-hnsr
--experimental-hnsr-endpoint
--experimental-hnsr-relay
--experimental-hnsr-rendezvous
--experimental-hnsr-web
--experimental-hnsr-testnet
--experimental-hnsr-persist=<true|false>
--experimental-hnsr-timeout=<milliseconds>
```

The relay role also requires the ordinary peer listener. Endpoint and requester
roles advertise no HNSR service bit.
