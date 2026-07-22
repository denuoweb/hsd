#!/usr/bin/env node

'use strict';

const assert = require('bsert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const random = require('bcrypto/lib/random');
const secp256k1 = require('bcrypto/lib/secp256k1');
const FullNode = require('../lib/node/fullnode');
const Address = require('../lib/primitives/address');
const NetAddress = require('../lib/net/netaddress');
const Network = require('../lib/protocol/network');
const common = require('../lib/net/common');
const {BrontideStream} = require('../lib/net/brontide');
const {
  profiles,
  routeKey,
  RelayTicket,
  EndpointDelegation,
  RouteRecord,
  encodeWebRequest
} = require('../lib/net/hnsr');

function waitFor(test, message, timeout = 30000) {
  const started = Date.now();

  return new Promise((resolve, reject) => {
    const check = () => {
      try {
        if (test()) {
          resolve();
          return;
        }
      } catch (e) {
        reject(e);
        return;
      }

      if (Date.now() - started >= timeout) {
        reject(new Error(typeof message === 'function' ? message() : message));
        return;
      }

      setTimeout(check, 25);
    };

    check();
  });
}

function waitEvent(emitter, event, timeout = 15000) {
  return new Promise((resolve, reject) => {
    let timer = null;
    const onEvent = (...args) => {
      clearTimeout(timer);
      resolve(args);
    };

    timer = setTimeout(() => {
      emitter.removeListener(event, onEvent);
      reject(new Error(`Timed out waiting for ${event}.`));
    }, timeout);

    emitter.once(event, onEvent);
  });
}

function delay(duration) {
  return new Promise(resolve => setTimeout(resolve, duration));
}

function identity() {
  return secp256k1.privateKeyGenerate();
}

function publicKey(key) {
  return secp256k1.publicKeyCreate(key, true);
}

function nodeAddress(key, port) {
  return NetAddress.fromHost(
    '127.0.0.1',
    port,
    publicKey(key),
    'regtest').hostname;
}

function ports(base, index) {
  return {
    p2p: base + index,
    brontide: base + 32 + index,
    http: base + 64 + index
  };
}

function nodeOptions(prefix, identityKey, assigned, extra = {}) {
  return Object.assign({
    network: 'regtest',
    memory: false,
    prefix,
    identityKey,
    workers: false,
    listen: true,
    host: '127.0.0.1',
    port: assigned.p2p,
    brontidePort: assigned.brontide,
    publicPort: assigned.p2p,
    publicBrontidePort: assigned.brontide,
    httpHost: '127.0.0.1',
    httpPort: assigned.http,
    noAuth: true,
    noDns: true,
    seeds: [],
    checkpoints: false,
    logConsole: process.env.HNSR_TRIAL_DEBUG === '1',
    logLevel: process.env.HNSR_TRIAL_DEBUG === '1' ? 'debug' : 'none',
    logFile: false,
    persistentMempool: false,
    maxOutbound: 16,
    experimentalHnsr: true,
    experimentalHnsrPersist: true
  }, extra);
}

function findPeer(node, key) {
  const peer = node.pool.findHNSRPeer(publicKey(key));
  return peer && peer.handshake && !peer.destroyed ? peer : null;
}

async function openNode(node, opened) {
  await node.ensure();
  await node.open();
  opened.push(node);
  await node.connect();
  node.startSync();
}

async function closeNode(node, opened) {
  const index = opened.indexOf(node);

  await node.close();

  if (index !== -1)
    opened.splice(index, 1);
}

function spamRecord(network, relayPrivate, relayKey, index) {
  const timestamp = Math.floor(Date.now() / 1000);
  const endpointPrivate = identity();
  const endpointKey = publicKey(endpointPrivate);
  const reservationID = random.randomBytes(16);

  reservationID.writeUInt32LE(index, 0, true);

  const ticket = new RelayTicket({
    networkMagic: network.magic,
    profile: profiles.HNS_NODE_V1,
    hostType: 1,
    host: Buffer.from('00000000000000000000ffff7f000001', 'hex'),
    port: network.brontidePort,
    relayKey,
    endpointKey,
    reservationID,
    issuedAt: timestamp,
    expiresAt: timestamp + 1800,
    maxActiveCircuits: 1,
    maxBytesPerCircuit: 65536,
    maxTotalBytes: 65536
  }).signRelay(relayPrivate).signEndpoint(endpointPrivate);
  const delegation = new EndpointDelegation({
    endpointKey,
    sequence: 1,
    issuedAt: timestamp,
    expiresAt: timestamp + 900,
    maxActiveCircuits: 1,
    maxBytesPerCircuit: 65536
  }).sign(network.magic, endpointPrivate);
  const key = routeKey(network.magic, endpointKey);

  return new RouteRecord({
    routeKey: key,
    sequence: 1,
    issuedAt: timestamp,
    expiresAt: timestamp + 900,
    delegation,
    tickets: [ticket]
  }).sign(endpointPrivate);
}

async function main() {
  const artifact = process.argv[2] ? path.resolve(process.argv[2]) : null;
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'hsd-hnsr-phase2-'));
  const base = 30000 + (process.pid % 500) * 40;
  const relayKeys = [identity(), identity()];
  const rendezvousKeys = Array.from({length: 8}, () => identity());
  const endpointKey = identity();
  const requesterKey = identity();
  const relayPorts = relayKeys.map((key, index) => ports(base, index));
  const rendezvousPorts = rendezvousKeys.map((key, index) => {
    return ports(base, 2 + index);
  });
  const endpointPorts = ports(base, 10);
  const requesterPorts = ports(base, 11);
  const opened = [];
  const relayPrefixes = relayKeys.map((key, index) => {
    return path.join(root, `operator-relay-${index}`);
  });
  const rendezvousPrefixes = rendezvousKeys.map((key, index) => {
    return path.join(root, `operator-rendezvous-${index}`);
  });
  let relays = [];
  let rendezvous = [];
  let endpoint = null;
  let requester = null;

  try {
    Network.get('regtest').time.setMaxListeners(0);

    relays = relayKeys.map((key, index) => new FullNode(nodeOptions(
      relayPrefixes[index],
      key,
      relayPorts[index],
      {experimentalHnsrRelay: true, experimentalHnsrWeb: true})));
    rendezvous = new Array(8);

    for (let index = 7; index >= 0; index--) {
      const extra = {experimentalHnsrRendezvous: true};

      if (index < 7) {
        extra.nodes = [nodeAddress(
          rendezvousKeys[index + 1],
          rendezvousPorts[index + 1].brontide)];
      }

      rendezvous[index] = new FullNode(nodeOptions(
        rendezvousPrefixes[index],
        rendezvousKeys[index],
        rendezvousPorts[index],
        extra));
    }

    for (const relay of relays)
      await openNode(relay, opened);

    for (let index = 7; index >= 0; index--)
      await openNode(rendezvous[index], opened);

    for (let index = 0; index < 7; index++) {
      await waitFor(
        () => findPeer(rendezvous[index], rendezvousKeys[index + 1]),
        `Rendezvous link ${index}->${index + 1} did not authenticate.`);
    }

    const relayAddresses = relayKeys.map((key, index) => {
      return nodeAddress(key, relayPorts[index].brontide);
    });
    const bootstrapAddress = nodeAddress(
      rendezvousKeys[0],
      rendezvousPorts[0].brontide);

    endpoint = new FullNode(nodeOptions(
      path.join(root, 'operator-endpoint'),
      endpointKey,
      endpointPorts,
      {
        listen: false,
        experimentalHnsrEndpoint: true,
        experimentalHnsrWeb: true,
        nodes: [...relayAddresses, bootstrapAddress]
      }));
    requester = new FullNode(nodeOptions(
      path.join(root, 'operator-requester'),
      requesterKey,
      requesterPorts,
      {listen: false, nodes: [bootstrapAddress]}));

    await openNode(endpoint, opened);
    await openNode(requester, opened);

    await waitFor(() => {
      return relayKeys.every(key => findPeer(endpoint, key))
        && findPeer(endpoint, rendezvousKeys[0])
        && findPeer(requester, rendezvousKeys[0]);
    }, 'Phase 2 endpoint bootstrap peers did not authenticate.');

    for (const node of [...relays, ...rendezvous, endpoint, requester])
      node.chain.synced = true;

    const endpointRelays = relayKeys.map(key => findPeer(endpoint, key));
    const endpointRendezvous = findPeer(endpoint, rendezvousKeys[0]);
    const requesterRendezvous = findPeer(requester, rendezvousKeys[0]);
    const reservationOptions = {
      lifetime: 1800,
      maxCircuits: 16,
      maxBytes: 8 * 1024 * 1024
    };
    const tickets = await Promise.all(endpointRelays.map((peer) => {
      return endpoint.hnsr.reserve(peer, reservationOptions);
    }));
    const publication = await endpoint.hnsr.publishReplicated(
      endpointRendezvous,
      tickets,
      {lifetime: 900, replicas: 8, minimumStores: 8});
    const key = publication.record.routeKey;

    assert.strictEqual(publication.stored.length, 8);
    assert(rendezvous.every(node => node.hnsr.store.size === 1));
    assert(endpoint.hnsr.contacts.size >= 8);

    const preChurnLookup = await requester.hnsr.lookupReplicated(
      requesterRendezvous,
      key,
      8,
      {replicas: 8});

    assert.strictEqual(preChurnLookup.queried.length, 8);
    assert.strictEqual(preChurnLookup.records.length, 1);

    const restartIndex = 6;

    await closeNode(rendezvous[restartIndex], opened);
    const restarted = new FullNode(nodeOptions(
      rendezvousPrefixes[restartIndex],
      rendezvousKeys[restartIndex],
      rendezvousPorts[restartIndex],
      {
        experimentalHnsrRendezvous: true,
        nodes: [nodeAddress(
          rendezvousKeys[restartIndex + 1],
          rendezvousPorts[restartIndex + 1].brontide)]
      }));

    rendezvous[restartIndex] = restarted;
    await openNode(restarted, opened);
    assert.strictEqual(restarted.hnsr.store.size, 1);
    assert(restarted.hnsr.contacts.size > 0);

    const stoppedRendezvous = [1, 3, 5];

    for (const index of stoppedRendezvous)
      await closeNode(rendezvous[index], opened);

    await closeNode(relays[0], opened);
    await delay(1100);

    const republisher = endpoint.hnsr.startRepublisher(
      publication,
      tickets,
      endpointRendezvous,
      {replicas: 8, minimumStores: 3, retry: 250});

    endpoint.hnsr.notifyNetworkChange(endpointRendezvous);
    await waitFor(
      () => republisher.successes === 1,
      'Network-change republish did not reach quorum.');

    const lookup = await requester.hnsr.lookupReplicated(
      requesterRendezvous,
      key,
      8,
      {replicas: 8});

    assert.strictEqual(lookup.records.length, 1);
    assert.strictEqual(
      lookup.records[0].sequence,
      publication.record.sequence + 1);
    assert(lookup.queried.length >= 5);

    const endpointVirtualPromise = waitEvent(endpoint.hnsr, 'virtual peer');
    const openedRoute = await requester.hnsr.openPeer(lookup.records[0]);
    const [endpointVirtual] = await endpointVirtualPromise;
    const requesterVirtual = openedRoute.peer;

    await waitFor(
      () => endpointVirtual.handshake && requesterVirtual.handshake,
      'Phase 2 inner peer did not complete version/verack.');
    assert(openedRoute.ticket.relayKey.equals(relays[1].hnsr.publicKey));
    assert(openedRoute.failures.length >= 1);

    const relay = relays[1];
    const requesterRelay = await requester.pool.connectHNSRTicket(tickets[1]);
    const heldCircuits = [];
    const available = common.hnsr.MAX_REQUESTER_CIRCUITS - 1;

    for (let index = 0; index < available; index++) {
      heldCircuits.push(await requester.hnsr.openCircuit(
        requesterRelay,
        tickets[1]));
    }

    let capacityError = null;

    try {
      await requester.hnsr.openCircuit(requesterRelay, tickets[1]);
    } catch (e) {
      capacityError = e;
    }

    assert(capacityError && capacityError.code === 7);

    for (const circuit of heldCircuits)
      circuit.socket.destroy();

    await waitFor(
      () => Math.floor(relay.hnsr.relayCircuits.size / 2) === 1,
      'Requester circuit quota test did not release its circuits.');

    endpoint.hnsr.webServices.set('phase2/load', {
      origin: null,
      handler: async () => ({statusCode: 200, body: 'ok'})
    });
    const webTicket = await endpoint.hnsr.reserve(endpointRelays[1], {
      profile: profiles.HNS_WEB_V1,
      lifetime: 1800,
      maxCircuits: 4,
      maxBytes: 2 * 1024 * 1024
    });
    const webCircuit = await requester.hnsr.openCircuit(
      requesterRelay,
      webTicket,
      {window: common.hnsr.MAX_WINDOW});
    const webStream = BrontideStream.fromOutbound(
      webCircuit.socket,
      requester.hnsr.identityKey,
      endpoint.hnsr.publicKey);
    const webConnected = waitEvent(webStream, 'connect');

    webStream.on('error', () => {});
    await webConnected;

    const webRequest = encodeWebRequest('phase2', 'load', {
      method: 'POST',
      path: '/saturation',
      body: Buffer.alloc(common.hnsr.MAX_WEB_BODY_SIZE, 0x5a)
    });
    const webFlood = (async () => {
      let frames = 0;

      for (let offset = 0; offset < webRequest.length; offset += 16384) {
        webStream.write(webRequest.slice(offset, offset + 16384));
        frames += 1;

        if (frames >= 3)
          await delay(25);
      }
    })();

    await waitFor(
      () => relay.hnsr.maxRelayQueuedBytes > common.hnsr.RELAY_BURST,
      'Web saturation did not exercise the bounded relay queue.');

    const coinbase = Address.fromProgram(0, Buffer.alloc(20, 0x02));
    const block = await endpoint.miner.mineBlock(endpoint.chain.tip, coinbase);
    const blockHash = block.hash();

    for (let peer = endpoint.pool.peers.head(); peer; peer = peer.next) {
      if (!peer.hnsrVirtual)
        peer.invFilter.add(blockHash);
    }

    for (let peer = requester.pool.peers.head(); peer; peer = peer.next) {
      if (!peer.hnsrVirtual)
        peer.invFilter.add(blockHash);
    }

    const baselineHeight = endpoint.chain.height;
    const propagationStarted = Date.now();

    await endpoint.chain.add(block);
    await waitFor(
      () => requester.chain.height === baselineHeight + 1,
      'Block did not propagate through the priority node circuit.');

    const blockLatency = Date.now() - propagationStarted;

    await webFlood;
    webStream.destroy();
    webCircuit.socket.destroy();
    await waitFor(
      () => relay.hnsr.relayQueueBytes === 0,
      'Profile-aware relay queues did not drain.');
    assert.strictEqual(requester.chain.tip.hash.equals(blockHash), true);
    assert.strictEqual(relay.hnsr.relayDrops, 0);

    const spam = [];

    for (let index = 0; index < 40; index++) {
      const record = spamRecord(
        endpoint.network,
        relayKeys[1],
        publicKey(relayKeys[1]),
        index);

      spam.push(endpoint.hnsr._putRoute(endpointRendezvous, record));
    }

    const spamResults = await Promise.allSettled(spam);
    const spamAccepted = spamResults.filter((item) => {
      return item.status === 'fulfilled';
    });
    const spamRejected = spamResults.filter((item) => {
      return item.status === 'rejected';
    });

    assert(spamAccepted.length > 0);
    assert(spamRejected.length > 0);
    assert(spamRejected.some(item => item.reason.message.includes('rejected')));
    assert(rendezvous[0].hnsr.verificationRejected > 0);

    await delay(1100);
    const flood = [];

    for (let index = 0; index < 160; index++)
      flood.push(requester.hnsr.lookup(requesterRendezvous, key, 1));

    const floodResults = await Promise.allSettled(flood);
    const floodAccepted = floodResults.filter((item) => {
      return item.status === 'fulfilled';
    });
    const floodRejected = floodResults.filter((item) => {
      return item.status === 'rejected';
    });

    assert(floodAccepted.length > 0);
    assert(floodRejected.some((item) => {
      return item.reason.code === 14;
    }));

    const telemetry = {
      relay: relay.hnsr.getTelemetry(),
      rendezvous: rendezvous[0].hnsr.getTelemetry(),
      endpoint: endpoint.hnsr.getTelemetry()
    };
    const result = {
      schema: 1,
      network: 'regtest',
      phase: 2,
      topology: {
        independentlyKeyedProcesses: 12,
        relayOperators: 2,
        rendezvousOperators: 8,
        endpointOperators: 1,
        requesterOperators: 1,
        distinctPersistentPrefixes: 12,
        androidBootstrap:
          `127.0.0.1:${rendezvousPorts[restartIndex].p2p}`
      },
      routing: {
        bucketSize: common.hnsr.ROUTING_BUCKET_SIZE,
        maximumContacts: common.hnsr.MAX_ROUTING_CONTACTS,
        initialContacts: endpoint.hnsr.contacts.size,
        peerDialBudget: common.hnsr.MAX_RENDEZVOUS_DIALS,
        restartedNodeRecoveredContacts: restarted.hnsr.contacts.size
      },
      replication: {
        requestedCopies: 8,
        initialStoredCopies: publication.stored.length,
        restartedNodeRecoveredRoutes: restarted.hnsr.store.size,
        stoppedRendezvous,
        preChurnLookupNodes: preChurnLookup.queried.length,
        liveCopiesAfterChurn: republisher.publication.stored.length,
        lookupLiveNodes: lookup.queried.length,
        latestSequence: lookup.records[0].sequence
      },
      lifecycle: {
        networkChangeTriggeredRepublish: republisher.successes === 1,
        republishAttempts: republisher.attempts,
        deadRelayFailedOver: openedRoute.failures.length >= 1,
        selectedRelay: openedRoute.ticket.relayKey.toString('hex')
      },
      limits: {
        requesterCircuitLimit: common.hnsr.MAX_REQUESTER_CIRCUITS,
        circuitCapacityRejected: capacityError.code === 7,
        nodeRelayBytesPerSecond: common.hnsr.NODE_RELAY_BYTES_PER_SECOND,
        webRelayBytesPerSecond: common.hnsr.WEB_RELAY_BYTES_PER_SECOND,
        routeSpamAccepted: spamAccepted.length,
        routeSpamRejected: spamRejected.length,
        ddosRequests: floodResults.length,
        ddosAccepted: floodAccepted.length,
        ddosRateLimited: floodRejected.length
      },
      priorityTraffic: {
        saturatedProfile: 'HNS_WEB_V1',
        propagatedProfile: 'HNS_NODE_V1',
        actualInnerBlock: blockHash.toString('hex'),
        blockLatencyMs: blockLatency,
        maximumQueuedBytes: relay.hnsr.maxRelayQueuedBytes,
        relayDrops: relay.hnsr.relayDrops
      },
      telemetry,
      result: 'pass'
    };
    const output = `${JSON.stringify(result, null, 2)}\n`;

    if (artifact) {
      fs.mkdirSync(path.dirname(artifact), {recursive: true});
      fs.writeFileSync(artifact, output, {encoding: 'utf8', mode: 0o600});
    }

    process.stdout.write(output);

    if (process.env.HNSR_PHASE2_HOLD_OPEN === '1') {
      process.stderr.write(
        'HNSR Phase 2 Android fixture listening on '
        + `127.0.0.1:${rendezvousPorts[restartIndex].p2p}.\n`);
      await new Promise((resolve) => {
        process.once('SIGINT', resolve);
        process.once('SIGTERM', resolve);
      });
    }

    endpoint.hnsr.stopRepublisher(republisher);
  } finally {
    for (const node of opened.reverse()) {
      try {
        await node.close();
      } catch (e) {
        process.stderr.write(`cleanup warning: ${e.message}\n`);
      }
    }
  }
}

main().catch((error) => {
  process.stderr.write(`${error.stack}\n`);
  process.exitCode = 1;
});
