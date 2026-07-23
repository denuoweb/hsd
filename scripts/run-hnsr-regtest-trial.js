#!/usr/bin/env node

'use strict';

const assert = require('bsert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const base32 = require('bcrypto/lib/encoding/base32');
const secp256k1 = require('bcrypto/lib/secp256k1');
const sha256 = require('bcrypto/lib/sha256');
const FullNode = require('../lib/node/fullnode');
const Address = require('../lib/primitives/address');
const NetAddress = require('../lib/net/netaddress');
const packets = require('../lib/net/packets');
const common = require('../lib/net/common');
const rules = require('../lib/covenants/rules');
const {Resource} = require('../lib/dns/resource');
const walletPlugin = require('../lib/wallet/plugin');
const {BrontideStream} = require('../lib/net/brontide');
const {
  opcodes,
  profiles,
  routeKey,
  ServiceAuthorization,
  HTTPMessageParser
} = require('../lib/net/hnsr');

function waitFor(test, message, timeout = 15000) {
  const start = Date.now();

  return new Promise((resolve, reject) => {
    const check = () => {
      try {
        const result = test();

        if (result) {
          resolve(result);
          return;
        }
      } catch (e) {
        reject(e);
        return;
      }

      if (Date.now() - start >= timeout) {
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
    let onEvent = null;
    const cleanup = () => {
      clearTimeout(timer);
      emitter.removeListener(event, onEvent);
    };
    onEvent = (...args) => {
      cleanup();
      resolve(args);
    };
    timer = setTimeout(() => {
      cleanup();
      reject(new Error(`Timed out waiting for ${event}.`));
    }, timeout);

    emitter.once(event, onEvent);
  });
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

function nodeOptions(prefix, identityKey, ports, extra = {}) {
  return Object.assign({
    network: 'regtest',
    memory: false,
    prefix,
    identityKey,
    workers: false,
    listen: true,
    host: '127.0.0.1',
    port: ports.p2p,
    brontidePort: ports.brontide,
    publicPort: ports.p2p,
    publicBrontidePort: ports.brontide,
    httpHost: '127.0.0.1',
    httpPort: ports.http,
    noAuth: true,
    noDns: true,
    seeds: [],
    checkpoints: false,
    logConsole: process.env.HNSR_TRIAL_DEBUG === '1',
    logLevel: process.env.HNSR_TRIAL_DEBUG === '1' ? 'debug' : 'none',
    logFile: false,
    persistentMempool: false,
    maxOutbound: 12,
    experimentalHnsr: true
  }, extra);
}

function ports(base, index) {
  return {
    p2p: base + index,
    brontide: base + 16 + index,
    http: base + 32 + index,
    wallet: base + 48 + index
  };
}

function findPeer(node, key) {
  const peer = node.pool.findHNSRPeer(publicKey(key));
  return peer && peer.handshake && !peer.destroyed ? peer : null;
}

function opcodeName(value) {
  for (const [name, opcode] of Object.entries(opcodes)) {
    if (opcode === value)
      return name;
  }

  return `UNKNOWN_${value}`;
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

async function mineShared(producer, nodes, count, address) {
  for (let i = 0; i < count; i++) {
    const block = await producer.miner.mineBlock(producer.chain.tip, address);
    const height = producer.chain.height + 1;

    await Promise.all(nodes.map(async (node) => {
      if (node.chain.height < height)
        await node.chain.add(block);
    }));

    assert(nodes.every(node => node.chain.height === height));
  }
}

async function rawWebExchange(service, record, raw) {
  const circuit = await service.openRoute(record);
  const stream = BrontideStream.fromOutbound(
    circuit.socket,
    service.identityKey,
    record.delegation.endpointKey);
  const parser = new HTTPMessageParser('response');

  return new Promise((resolve, reject) => {
    let settled = false;
    let timer = null;
    const finish = (error, response) => {
      if (settled)
        return;
      settled = true;
      clearTimeout(timer);
      stream.destroy();
      circuit.socket.destroy();

      if (error)
        reject(error);
      else
        resolve(response);
    };
    timer = setTimeout(
      () => finish(new Error('Raw HNSR web exchange timed out.')),
      common.hnsr.INNER_HANDSHAKE_TIMEOUT);

    circuit.socket.once('close', () => {
      finish(new Error('Raw HNSR web circuit closed.'));
    });
    stream.once('error', finish);
    stream.once('connect', () => stream.write(raw));
    stream.on('data', (data) => {
      try {
        const messages = parser.feed(data);

        if (messages.length !== 0)
          finish(null, messages[0]);
      } catch (e) {
        finish(e);
      }
    });
  });
}

async function main() {
  const artifact = process.argv[2] ? path.resolve(process.argv[2]) : null;
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'hsd-hnsr-regtest-'));
  const base = 20000 + (process.pid % 1000) * 24;
  const identities = {
    relays: [identity(), identity()],
    rendezvous: [identity(), identity(), identity(), identity()],
    endpoint: identity(),
    webEndpoint: identity(),
    requester: identity()
  };
  const nodePorts = {
    relays: [ports(base, 0), ports(base, 1)],
    rendezvous: [
      ports(base, 2),
      ports(base, 3),
      ports(base, 4),
      ports(base, 5)
    ],
    endpoint: ports(base, 6),
    requester: ports(base, 7),
    webEndpoint: ports(base, 8)
  };
  const opened = [];
  const wireCounts = {};
  const relayWirePayloads = new Map();
  const nodes = [];
  let endpoint = null;
  let webEndpoint = null;
  let requester = null;

  try {
    const relays = identities.relays.map((key, index) => {
      return new FullNode(nodeOptions(
        path.join(root, `relay-${index}`),
        key,
        nodePorts.relays[index],
        {
          experimentalHnsrRelay: true,
          experimentalHnsrWeb: true
        }));
    });
    const rendezvous = new Array(4);

    for (let index = 3; index >= 0; index--) {
      const extra = {experimentalHnsrRendezvous: true};

      if (index === 0) {
        extra.plugins = [walletPlugin];
        extra.walletHttpPort = nodePorts.rendezvous[index].wallet;
      }

      if (index < 3) {
        extra.nodes = [nodeAddress(
          identities.rendezvous[index + 1],
          nodePorts.rendezvous[index + 1].brontide)];
      }

      rendezvous[index] = new FullNode(nodeOptions(
        path.join(root, `rendezvous-${index}`),
        identities.rendezvous[index],
        nodePorts.rendezvous[index],
        extra));
    }

    nodes.push(...relays, ...rendezvous);

    for (const relay of relays)
      await openNode(relay, opened);

    for (let index = 3; index >= 0; index--)
      await openNode(rendezvous[index], opened);

    for (let index = 0; index < 3; index++) {
      await waitFor(
        () => findPeer(rendezvous[index], identities.rendezvous[index + 1]),
        `Rendezvous link ${index}->${index + 1} did not authenticate.`);
    }

    const relayAddresses = identities.relays.map((key, index) => {
      return nodeAddress(key, nodePorts.relays[index].brontide);
    });
    const rendezvousBootstrap = nodeAddress(
      identities.rendezvous[0],
      nodePorts.rendezvous[0].brontide);

    endpoint = new FullNode(nodeOptions(
      path.join(root, 'endpoint'),
      identities.endpoint,
      nodePorts.endpoint,
      {
        listen: false,
        experimentalHnsrEndpoint: true,
        experimentalHnsrWeb: true,
        nodes: [...relayAddresses, rendezvousBootstrap]
      }));
    webEndpoint = new FullNode(nodeOptions(
      path.join(root, 'web-endpoint'),
      identities.webEndpoint,
      nodePorts.webEndpoint,
      {
        listen: false,
        experimentalHnsrEndpoint: true,
        experimentalHnsrWeb: true,
        nodes: [...relayAddresses, rendezvousBootstrap]
      }));
    requester = new FullNode(nodeOptions(
      path.join(root, 'requester'),
      identities.requester,
      nodePorts.requester,
      {listen: false, nodes: [rendezvousBootstrap]}));
    nodes.push(endpoint, webEndpoint, requester);

    await openNode(endpoint, opened);
    await openNode(webEndpoint, opened);
    await openNode(requester, opened);

    await waitFor(() => {
      return identities.relays.every(key => findPeer(endpoint, key))
        && identities.relays.every(key => findPeer(webEndpoint, key))
        && findPeer(endpoint, identities.rendezvous[0])
        && findPeer(webEndpoint, identities.rendezvous[0])
        && findPeer(requester, identities.rendezvous[0]);
    }, 'Endpoint and requester bootstrap peers did not authenticate.');

    const rootPrivate = identity();
    const rootKey = publicKey(rootPrivate);
    const servicePrivate = identity();
    const serviceKey = publicKey(servicePrivate);
    const rootName = 'phase1b';
    const serviceName = 'p2p-site';
    const rootResource = Resource.fromJSON({
      records: [{
        type: 'TXT',
        txt: [`hnsr1 k=${base32.encode(rootKey)}`]
      }]
    });
    const {wdb} = rendezvous[0].require('walletdb');
    const wallet = await wdb.create();
    const miningAddress = await wallet.receiveAddress();
    const [rolloutHeight] = rules.getRollout(
      rules.hashName(rootName),
      endpoint.network);

    await mineShared(
      rendezvous[0],
      nodes,
      Math.max(3, rolloutHeight),
      miningAddress);
    await wdb.rescan(0);
    await wallet.sendOpen(rootName);
    await mineShared(
      rendezvous[0],
      nodes,
      endpoint.network.names.treeInterval + 1,
      miningAddress);
    await wdb.rescan(0);
    await wallet.sendBid(rootName, 100000, 200000);
    await mineShared(
      rendezvous[0],
      nodes,
      endpoint.network.names.biddingPeriod,
      miningAddress);
    await wdb.rescan(0);
    await wallet.sendReveal(rootName);
    await mineShared(
      rendezvous[0],
      nodes,
      endpoint.network.names.revealPeriod + 1,
      miningAddress);
    await wdb.rescan(0);
    await wallet.sendUpdate(rootName, rootResource);
    await mineShared(
      rendezvous[0],
      nodes,
      endpoint.network.names.treeInterval,
      miningAddress);
    await wdb.rescan(0);

    const nameHeight = rendezvous[0].chain.height;
    const authorization = new ServiceAuthorization({
      networkMagic: endpoint.network.magic,
      nameHash: rules.hashName(rootName),
      serviceName,
      profile: profiles.HNS_WEB_V1,
      serviceKey,
      serial: 1,
      validFromHeight: nameHeight,
      validUntilHeight: nameHeight + 1000,
      maxEndpointLifetime: 3600,
      maxRouteLifetime: 900
    }).sign(endpoint.network.magic, rootPrivate);
    const endpointAuthority = await endpoint.hnsr.resolveNamedAuthority(
      rootName);
    const requesterAuthority = await requester.hnsr.resolveNamedAuthority(
      rootName);

    assert(endpointAuthority.rootKey.equals(rootKey));
    assert(requesterAuthority.rootKey.equals(rootKey));
    assert(authorization.verify(rootKey, endpoint.network.magic, nameHeight));

    for (const node of nodes) {
      node.chain.synced = true;
      relayWirePayloads.set(node, []);
      node.pool.on('packet', (packet) => {
        if (packet.type !== packets.types.EXPERIMENTAL_HNSR)
          return;

        const name = opcodeName(packet.opcode);
        wireCounts[name] = (wireCounts[name] || 0) + 1;

        if (node.hnsr.relay && packet.opcode === opcodes.DATA)
          relayWirePayloads.get(node).push(Buffer.from(packet.body));
      });
    }

    const endpointRelays = identities.relays.map(
      key => findPeer(endpoint, key));
    const webEndpointRelays = identities.relays.map(
      key => findPeer(webEndpoint, key));
    const endpointRendezvous = findPeer(
      endpoint,
      identities.rendezvous[0]);
    const requesterRendezvous = findPeer(
      requester,
      identities.rendezvous[0]);
    const webEndpointRendezvous = findPeer(
      webEndpoint,
      identities.rendezvous[0]);
    const reservationOptions = {
      lifetime: 1800,
      maxCircuits: 4,
      maxBytes: 8 * 1024 * 1024
    };
    const initialTickets = await Promise.all(endpointRelays.map((peer) => {
      return endpoint.hnsr.reserve(peer, reservationOptions);
    }));
    const publication = await endpoint.hnsr.publishReplicated(
      endpointRendezvous,
      initialTickets,
      {lifetime: 900, replicas: 4, minimumStores: 4});
    const key = routeKey(endpoint.network.magic, endpoint.hnsr.publicKey);

    assert.strictEqual(publication.stored.length, 4);
    assert(rendezvous.every(node => node.hnsr.store.size === 1));
    assert(endpoint.hnsr.contacts.size >= 4);

    const sampled = await requester.hnsr.sampleRoutes(
      requesterRendezvous,
      8);
    const sampledRoute = sampled.records.find((record) => {
      return record.routeKey.equals(key);
    });

    assert(sampledRoute);
    assert(sampledRoute.verify(requester.network.magic));
    assert(requester.hnsr.contacts.size >= 4);
    const endpointKnownRendezvous = endpoint.hnsr.contacts.size;

    const renewedTickets = await Promise.all(endpointRelays.map(
      (peer, index) => endpoint.hnsr.renew(
        peer,
        initialTickets[index],
        reservationOptions)));
    const refreshed = await endpoint.hnsr.republish(
      publication,
      renewedTickets,
      endpointRendezvous,
      {lifetime: 900, replicas: 4, minimumStores: 4});

    assert.strictEqual(
      refreshed.record.sequence,
      publication.record.sequence + 1);
    assert.strictEqual(
      refreshed.record.delegation.sequence,
      publication.record.delegation.sequence + 1);
    assert.strictEqual(refreshed.stored.length, 4);

    await Promise.all(endpointRelays.map((peer, index) => {
      return endpoint.hnsr.withdraw(peer, initialTickets[index]);
    }));
    assert(relays.every(node => node.hnsr.reservations.size === 1));

    await endpoint.hnsr.registerWebService(
      rootName,
      authorization,
      async request => ({
        statusCode: 200,
        headers: {'Content-Type': 'text/plain; charset=utf-8'},
        body: `fallback:${request.path}`
      }));
    await webEndpoint.hnsr.registerWebService(
      rootName,
      authorization,
      async request => ({
        statusCode: 200,
        headers: {'Content-Type': 'text/plain; charset=utf-8'},
        body: `primary:${request.path}`
      }));

    const webReservationOptions = {
      profile: profiles.HNS_WEB_V1,
      lifetime: 1800,
      maxCircuits: 4,
      maxBytes: 4 * 1024 * 1024
    };
    const fallbackWebTickets = await Promise.all(endpointRelays.map((peer) => {
      return endpoint.hnsr.reserve(peer, webReservationOptions);
    }));
    const primaryWebTickets = await Promise.all(
      webEndpointRelays.map((peer) => {
        return webEndpoint.hnsr.reserve(peer, webReservationOptions);
      }));
    const fallbackWebPublication = await endpoint.hnsr.publishNamedReplicated(
      endpointRendezvous,
      fallbackWebTickets,
      authorization,
      servicePrivate,
      {lifetime: 900, replicas: 4, minimumStores: 4});
    const primaryWebPublication = await webEndpoint.hnsr.publishNamedReplicated(
      webEndpointRendezvous,
      primaryWebTickets,
      authorization,
      servicePrivate,
      {
        sequence: 10,
        endpointSequence: 10,
        lifetime: 900,
        replicas: 4,
        minimumStores: 4
      });

    assert.strictEqual(fallbackWebPublication.stored.length, 4);
    assert.strictEqual(primaryWebPublication.stored.length, 4);
    assert(rendezvous.every(node => node.hnsr.store.size === 3));

    const webURI = `hnsr://${rootName}/${serviceName}/hello?phase=1b`;
    const webTranscriptStart = relays.map(
      node => relayWirePayloads.get(node).length);
    const primaryWebResponse = await requester.hnsr.requestNamedWeb(
      requesterRendezvous,
      webURI);

    assert.strictEqual(primaryWebResponse.statusCode, 200);
    assert.strictEqual(
      primaryWebResponse.body.toString('utf8'),
      'primary:/hello?phase=1b');
    assert.strictEqual(
      primaryWebResponse.origin.key,
      `hnsr:${rules.hashName(rootName).toString('hex')}:${serviceName}:2`);

    const reusableWeb = await requester.hnsr.openNamedWeb(
      requesterRendezvous,
      webURI);
    const reusedResponses = [];

    for (let index = 0;
      index < common.hnsr.MAX_WEB_REQUESTS_PER_CIRCUIT;
      index++) {
      reusedResponses.push(await reusableWeb.session.request(
        rootName,
        serviceName,
        {path: `/reuse/${index + 1}`}));
    }

    await assert.rejects(
      reusableWeb.session.request(rootName, serviceName, {path: '/reuse/17'}),
      /request limit/);
    reusableWeb.session.close();

    assert(reusedResponses.every((response) => {
      return response.circuit === reusedResponses[0].circuit;
    }));
    assert.strictEqual(
      reusedResponses[0].body.toString('utf8'),
      'primary:/reuse/1');
    assert.strictEqual(
      reusedResponses[reusedResponses.length - 1].body.toString('utf8'),
      'primary:/reuse/16');

    const wrongAuthority = Buffer.from(
      'GET / HTTP/1.1\r\n'
      + `Host: attacker.${rootName}\r\n`
      + `HNSR-Authority: ${rootName}\r\n`
      + `HNSR-Service: ${serviceName}\r\n`
      + 'Content-Length: 0\r\n\r\n',
      'ascii');
    const rejectedAuthority = await rawWebExchange(
      requester.hnsr,
      primaryWebPublication.record,
      wrongAuthority);
    assert.strictEqual(rejectedAuthority.statusCode, 421);

    await assert.rejects(async () => {
      await endpoint.hnsr.reserve(endpointRelays[0], {
        profile: profiles.HNS_WEB_V1,
        lifetime: 1800,
        maxCircuits: 5,
        maxBytes: 1024
      });
    });

    await closeNode(webEndpoint, opened);
    await waitFor(
      () => relays.every(node => node.hnsr.reservations.size === 2),
      'Relays did not invalidate the disconnected primary web endpoint.');

    const failedOverWebResponse = await requester.hnsr.requestNamedWeb(
      requesterRendezvous,
      webURI);
    assert.strictEqual(failedOverWebResponse.statusCode, 200);
    assert.strictEqual(
      failedOverWebResponse.body.toString('utf8'),
      'fallback:/hello?phase=1b');
    assert.strictEqual(failedOverWebResponse.failures.length, 1);
    const webPlaintextObserved = relays.some((node, index) => {
      return relayWirePayloads.get(node)
        .slice(webTranscriptStart[index])
        .some(raw => raw.includes(Buffer.from('primary:/hello?phase=1b'))
          || raw.includes(Buffer.from('fallback:/hello?phase=1b')));
    });
    assert.strictEqual(webPlaintextObserved, false);

    await new Promise(resolve => setTimeout(resolve, 1100));
    const admission = await Promise.allSettled(new Array(72).fill(null).map(
      () => requester.hnsr.lookup(requesterRendezvous, key, 1)));
    const admitted = admission.filter(item => item.status === 'fulfilled');
    const rateLimited = admission.filter((item) => {
      return item.status === 'rejected' && item.reason.code === 14;
    });

    assert(admitted.length > 0);
    assert(rateLimited.length > 0);

    await closeNode(rendezvous[3], opened);
    await new Promise(resolve => setTimeout(resolve, 1100));

    const replicatedLookup = await requester.hnsr.lookupReplicated(
      requesterRendezvous,
      key,
      8,
      {replicas: 4});

    assert.strictEqual(replicatedLookup.records.length, 1);
    assert.strictEqual(
      replicatedLookup.records[0].sequence,
      refreshed.record.sequence);
    assert(replicatedLookup.queried.length >= 3);
    assert(replicatedLookup.queried.length < 5);

    await closeNode(relays[0], opened);

    const endpointVirtualPromise = waitEvent(endpoint.hnsr, 'virtual peer');
    const openedRoute = await requester.hnsr.openPeer(
      replicatedLookup.records[0]);
    const [endpointVirtual] = await endpointVirtualPromise;
    const requesterVirtual = openedRoute.peer;

    await waitFor(
      () => endpointVirtual.handshake && requesterVirtual.handshake,
      'Inner HNSR full-node peers did not complete version/verack.');
    assert(openedRoute.ticket.relayKey.equals(relays[1].hnsr.publicKey));
    assert.strictEqual(openedRoute.failures.length, 1);
    assert(requesterVirtual.brontide.remoteStatic.equals(
      endpoint.hnsr.publicKey));
    assert(endpointVirtual.brontide.remoteStatic.equals(
      requester.hnsr.publicKey));

    const relay = relays[1];
    const payloadStart = relayWirePayloads.get(relay).length;
    const loadPackets = process.env.HNSR_LOAD_PACKETS
      ? Number(process.env.HNSR_LOAD_PACKETS)
      : 1000;

    assert(Number.isSafeInteger(loadPackets) && loadPackets >= 0);

    for (let i = 0; i < loadPackets; i++) {
      const nonce = Buffer.allocUnsafe(8);
      nonce.writeUInt32LE(i, 0);
      nonce.writeUInt32LE(i ^ 0x5a5a5a5a, 4);
      requesterVirtual.send(new packets.PingPacket(nonce));
    }

    const controlUnderLoadStarted = Date.now();
    const loadTicketPromise = endpoint.hnsr.reserve(
      endpointRelays[1],
      reservationOptions);

    const coinbase = Address.fromProgram(0, Buffer.alloc(20, 0x01));
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

    const propagationStarted = Date.now();
    await endpoint.chain.add(block);
    await waitFor(
      () => requester.chain.height === nameHeight + 1,
      () => {
        return 'Inner block did not converge ('
          + `requester=${requester.chain.height}).`;
      },
      30000);
    const blockLatency = Date.now() - propagationStarted;
    const loadTicket = await loadTicketPromise;
    const controlUnderLoadLatency = Date.now() - controlUnderLoadStarted;
    await endpoint.hnsr.withdraw(endpointRelays[1], loadTicket);

    await waitFor(
      () => relay.hnsr.relayQueueBytes === 0,
      'Relay scheduler did not drain after saturation.',
      30000);
    await requesterVirtual.drain();

    assert.strictEqual(endpoint.chain.height, nameHeight + 1);
    assert.strictEqual(requester.chain.height, nameHeight + 1);
    assert(relays.every(node => node.chain.height === nameHeight));
    assert(rendezvous.every(node => node.chain.height === nameHeight));
    assert(relay.hnsr.relayFrames > loadPackets);
    assert(relay.hnsr.relayFlushes > 1);
    assert(relay.hnsr.maxRelayQueuedBytes > common.hnsr.RELAY_BURST);
    assert(relay.hnsr.maxRelayQueuedBytes
      <= common.hnsr.MAX_CIRCUIT_QUEUE);
    assert.strictEqual(relay.hnsr.relayDrops, 0);
    const controlNodeHeights = [...relays, ...rendezvous]
      .map(node => node.chain.height);

    assert(controlNodeHeights.every(height => height === nameHeight));

    assert.strictEqual(relay.hnsr.reservations.size, 2);
    assert.strictEqual(
      relayWirePayloads.get(relay).slice(payloadStart)
        .some(raw => raw.includes(blockHash)),
      false);

    await closeNode(endpoint, opened);
    await waitFor(
      () => relay.hnsr.reservations.size === 0,
      'Relay did not invalidate the disconnected endpoint reservation.');

    const staleLookup = await requester.hnsr.lookupReplicated(
      requesterRendezvous,
      key,
      8,
      {replicas: 4});
    let staleRejected = false;

    try {
      await requester.hnsr.openRoute(staleLookup.records[0]);
    } catch (e) {
      staleRejected = Array.isArray(e.failures)
        && e.failures.some(item => item.error.code === 11);
    }

    assert(staleRejected);

    const activeRendezvous = rendezvous.slice(0, 3);
    const transcript = relayWirePayloads.get(relay).length > 0
      ? Buffer.concat(relayWirePayloads.get(relay))
      : Buffer.alloc(0);
    const result = {
      schema: 3,
      network: 'regtest',
      assignment: {
        rendezvousServiceBit:
          `0x${common.EXPERIMENTAL_HNSR_RENDEZVOUS_SERVICE.toString(16)}`,
        relayServiceBit:
          `0x${common.EXPERIMENTAL_HNSR_RELAY_SERVICE.toString(16)}`,
        packetType: `0x${common.EXPERIMENTAL_HNSR.toString(16)}`
      },
      topology: {
        fullNodes: 9,
        relays: 2,
        rendezvousNodes: 4,
        endpointListeners: 0,
        outerTransport: 'authenticated Handshake Brontide',
        innerTransport: 'end-to-end authenticated Handshake Brontide'
      },
      discovery: {
        bootstrapRendezvous: 1,
        endpointKnownRendezvous,
        requesterKnownRendezvous: requester.hnsr.contacts.size,
        sampledRecords: sampled.records.length,
        sampledEndpointFound: Boolean(sampledRoute),
        iterativeLookupLiveNodes: replicatedLookup.queried.length
      },
      replication: {
        requestedCopies: 4,
        initialStoredCopies: publication.stored.length,
        refreshedStoredCopies: refreshed.stored.length,
        survivingStores: activeRendezvous.map(node => node.hnsr.store.size),
        rendezvousFailureRecovered: replicatedLookup.records.length === 1
      },
      namedWeb: {
        rootName,
        serviceName,
        hnsStateHeight: nameHeight,
        canonicalRootKeyAuthenticated:
          requesterAuthority.rootKey.equals(rootKey),
        serviceAuthorizationVerified: authorization.verify(
          rootKey,
          endpoint.network.magic,
          nameHeight),
        namedRouteCopies: primaryWebPublication.stored.length,
        namedEndpoints: 2,
        profile: 'HNS_WEB_V1',
        innerBrontide: true,
        initialStatusCode: primaryWebResponse.statusCode,
        initialBody: primaryWebResponse.body.toString('utf8'),
        connectionReuse: reusedResponses.every((response) => {
          return response.circuit === reusedResponses[0].circuit;
        }),
        reusedRequests: reusedResponses.length,
        firstReusedBody: reusedResponses[0].body.toString('utf8'),
        lastReusedBody:
          reusedResponses[reusedResponses.length - 1].body.toString('utf8'),
        origin: primaryWebResponse.origin.key,
        authorityMismatchStatus: rejectedAuthority.statusCode,
        primaryEndpointStopped: true,
        failedEndpointCandidates: failedOverWebResponse.failures.length,
        failoverStatusCode: failedOverWebResponse.statusCode,
        failoverBody: failedOverWebResponse.body.toString('utf8'),
        relayObservedPlaintext: webPlaintextObserved,
        maximumBodyBytes: common.hnsr.MAX_WEB_BODY_SIZE,
        maximumRequestsPerCircuit:
          common.hnsr.MAX_WEB_REQUESTS_PER_CIRCUIT
      },
      lifecycle: {
        initialSequence: publication.record.sequence,
        refreshedSequence: refreshed.record.sequence,
        renewedTickets: renewedTickets.length,
        oldTicketsWithdrawn: initialTickets.length,
        staleRouteStillReturned: staleLookup.records.length === 1,
        disconnectedReservationInvalidated:
          relay.hnsr.reservations.size === 0,
        staleTicketRejected: staleRejected
      },
      failover: {
        firstRelayStopped: true,
        failedCandidates: openedRoute.failures.length,
        selectedRelay: openedRoute.ticket.relayKey.toString('hex'),
        selectedSecondRelay: openedRoute.ticket.relayKey.equals(
          relays[1].hnsr.publicKey)
      },
      innerPeer: {
        profile: 'HNS_NODE_V1',
        actualHsdPeerObjects: true,
        versionVerack: requesterVirtual.handshake && endpointVirtual.handshake,
        endpointAuthenticated: requesterVirtual.brontide.remoteStatic.equals(
          endpoint.hnsr.publicKey),
        requesterAuthenticated: endpointVirtual.brontide.remoteStatic.equals(
          requester.hnsr.publicKey)
      },
      blockTraffic: {
        hash: blockHash.toString('hex'),
        baselineHeight: nameHeight,
        endpointHeight: nameHeight + 1,
        requesterHeight: requester.chain.height,
        controlNodeHeights,
        deliveredOnlyByInnerPeer: controlNodeHeights
          .every(height => height === nameHeight),
        latencyMs: blockLatency
      },
      saturation: {
        pingPackets: loadPackets,
        relayFrames: relay.hnsr.relayFrames,
        relayBytes: relay.hnsr.relayBytes,
        schedulerFlushes: relay.hnsr.relayFlushes,
        maximumQueuedBytes: relay.hnsr.maxRelayQueuedBytes,
        queueLimitBytes: common.hnsr.MAX_CIRCUIT_QUEUE,
        relayDrops: relay.hnsr.relayDrops,
        controlReservationLatencyMs: controlUnderLoadLatency,
        admissionRequests: admission.length,
        admissionAccepted: admitted.length,
        admissionRateLimited: rateLimited.length
      },
      relayView: {
        plaintextBlockHashObserved: relayWirePayloads.get(relay)
          .some(raw => raw.includes(blockHash)),
        transcriptSHA256: sha256.digest(transcript).toString('hex')
      },
      observedOpcodes: wireCounts,
      result: 'pass'
    };
    const output = `${JSON.stringify(result, null, 2)}\n`;

    if (artifact) {
      fs.mkdirSync(path.dirname(artifact), {recursive: true});
      fs.writeFileSync(artifact, output, {encoding: 'utf8', mode: 0o600});
    }

    process.stdout.write(output);
  } finally {
    for (const node of opened.reverse()) {
      try {
        await node.close();
      } catch (e) {
        process.stderr.write(`cleanup warning: ${e.message}\n`);
      }
    }

    fs.rmSync(root, {recursive: true, force: true});
  }
}

main().catch((err) => {
  process.stderr.write(`${err.stack || err.message}\n`);
  process.exitCode = 1;
});
