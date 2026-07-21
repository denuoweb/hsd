#!/usr/bin/env node

'use strict';

const assert = require('bsert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const random = require('bcrypto/lib/random');
const secp256k1 = require('bcrypto/lib/secp256k1');
const sha256 = require('bcrypto/lib/sha256');
const FullNode = require('../lib/node/fullnode');
const Address = require('../lib/primitives/address');
const NetAddress = require('../lib/net/netaddress');
const Parser = require('../lib/net/parser');
const Framer = require('../lib/net/framer');
const packets = require('../lib/net/packets');
const common = require('../lib/net/common');
const {BrontideStream} = require('../lib/net/brontide');
const {opcodes, routeKey} = require('../lib/net/hnsr');

function waitFor(test, message, timeout = 10000) {
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

function peerAddress(node, port) {
  return NetAddress.fromHost(
    '127.0.0.1',
    port,
    secp256k1.publicKeyCreate(node.identityKey, true),
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
    maxOutbound: 2,
    experimentalHnsr: true
  }, extra);
}

function findPeer(node, services) {
  for (let peer = node.pool.peers.head(); peer; peer = peer.next) {
    if (peer.ack && (peer.services & services) === services)
      return peer;
  }

  return null;
}

function peerCount(node) {
  let count = 0;

  for (let peer = node.pool.peers.head(); peer; peer = peer.next) {
    if (peer.ack)
      count += 1;
  }

  return count;
}

function frame(framer, packet) {
  return framer.packet(packet.type, packet.encode());
}

function version(nonce) {
  return new packets.VersionPacket({
    services: common.services.NETWORK,
    nonce,
    agent: '/hnsr-poc:0.0.1/',
    height: 1,
    noRelay: true
  });
}

async function openNode(node, opened) {
  await node.ensure();
  await node.open();
  opened.push(node);
  await node.connect();
  node.startSync();
}

async function main() {
  const artifact = process.argv[2] ? path.resolve(process.argv[2]) : null;
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'hsd-hnsr-regtest-'));
  const identities = {
    endpoint: secp256k1.privateKeyGenerate(),
    relay: secp256k1.privateKeyGenerate(),
    rendezvous: secp256k1.privateKeyGenerate(),
    requester: secp256k1.privateKeyGenerate()
  };
  const ports = {
    relay: {p2p: 14428, brontide: 14438, http: 14448},
    rendezvous: {p2p: 14429, brontide: 14439, http: 14449},
    endpoint: {p2p: 14427, brontide: 14437, http: 14447},
    requester: {p2p: 14426, brontide: 14436, http: 14446}
  };
  const opened = [];
  let endpoint = null;
  let relay = null;
  let rendezvous = null;
  let requester = null;

  try {
    relay = new FullNode(nodeOptions(
      path.join(root, 'relay'),
      identities.relay,
      ports.relay,
      {experimentalHnsrRelay: true}));
    rendezvous = new FullNode(nodeOptions(
      path.join(root, 'rendezvous'),
      identities.rendezvous,
      ports.rendezvous,
      {experimentalHnsrRendezvous: true}));

    await openNode(relay, opened);
    await openNode(rendezvous, opened);

    const relayAddress = peerAddress(relay, ports.relay.brontide);
    const rendezvousAddress = peerAddress(
      rendezvous,
      ports.rendezvous.brontide);

    endpoint = new FullNode(nodeOptions(
      path.join(root, 'endpoint'),
      identities.endpoint,
      ports.endpoint,
      {
        listen: false,
        experimentalHnsrEndpoint: true,
        nodes: [relayAddress, rendezvousAddress]
      }));
    requester = new FullNode(nodeOptions(
      path.join(root, 'requester'),
      identities.requester,
      ports.requester,
      {
        listen: false,
        nodes: [relayAddress, rendezvousAddress]
      }));

    await openNode(endpoint, opened);
    await openNode(requester, opened);

    await waitFor(
      () => peerCount(endpoint) === 2 && peerCount(requester) === 2,
      'Timed out waiting for the four-node HNSR topology.');

    const endpointRelay = findPeer(
      endpoint,
      common.EXPERIMENTAL_HNSR_RELAY_SERVICE);
    const endpointRendezvous = findPeer(
      endpoint,
      common.EXPERIMENTAL_HNSR_RENDEZVOUS_SERVICE);
    const requesterRelay = findPeer(
      requester,
      common.EXPERIMENTAL_HNSR_RELAY_SERVICE);
    const requesterRendezvous = findPeer(
      requester,
      common.EXPERIMENTAL_HNSR_RENDEZVOUS_SERVICE);

    assert(endpointRelay && endpointRendezvous);
    assert(requesterRelay && requesterRendezvous);
    assert(endpointRelay.address.key.equals(relay.hnsr.publicKey));
    assert(requesterRelay.address.key.equals(relay.hnsr.publicKey));

    for (const node of [endpoint, relay, rendezvous, requester])
      node.chain.synced = true;

    const coinbase = Address.fromProgram(0, Buffer.alloc(20, 0x01));
    const block = await relay.miner.mineBlock(relay.chain.tip, coinbase);
    await relay.chain.add(block);
    relay.pool.announceBlock(block);
    await waitFor(
      () => [endpoint, relay, rendezvous, requester]
        .every(node => node.chain.height === 1),
      () => `Core regtest block did not propagate: ${[
        endpoint,
        relay,
        rendezvous,
        requester
      ].map(node => node.chain.height).join(',')}.`);

    const wireCounts = {};

    for (const node of [endpoint, relay, rendezvous, requester]) {
      node.pool.on('packet', (packet) => {
        if (packet.type !== packets.types.EXPERIMENTAL_HNSR)
          return;
        const name = Object.keys(opcodes)
          .find(key => opcodes[key] === packet.opcode);
        wireCounts[name] = (wireCounts[name] || 0) + 1;
      });
    }

    const ticket = await endpoint.hnsr.reserve(endpointRelay, {
      lifetime: 1800,
      maxCircuits: 4,
      maxBytes: 1048576
    });
    const record = await endpoint.hnsr.publish(
      endpointRendezvous,
      [ticket],
      {lifetime: 900});
    const key = routeKey(
      endpoint.network.magic,
      endpoint.hnsr.publicKey);
    const routes = await requester.hnsr.lookup(
      requesterRendezvous,
      key);

    assert.strictEqual(routes.length, 1);
    assert(routes[0].verify(requester.network.magic));
    assert(routes[0].tickets[0].id().equals(ticket.id()));

    const endpointParser = new Parser('regtest');
    const requesterParser = new Parser('regtest');
    const framer = new Framer('regtest');
    const requesterNonce = random.randomBytes(8);
    const endpointNonce = random.randomBytes(8);
    const pingNonce = random.randomBytes(8);
    let endpointInner = null;
    let requesterInner = null;
    let endpointSawVersion = false;
    let endpointSawVerack = false;
    let requesterSawVersion = false;
    let requesterSawVerack = false;
    let requesterSawPong = false;

    endpointParser.on('error', (err) => {
      throw err;
    });
    requesterParser.on('error', (err) => {
      throw err;
    });
    endpointParser.on('packet', (packet) => {
      if (packet.type === packets.types.VERSION) {
        endpointSawVersion = packet.agent === '/hnsr-poc:0.0.1/';
        endpointInner.write(frame(framer, version(endpointNonce)));
        endpointInner.write(frame(framer, new packets.VerackPacket()));
      } else if (packet.type === packets.types.VERACK) {
        endpointSawVerack = true;
      } else if (packet.type === packets.types.PING) {
        endpointInner.write(frame(
          framer,
          new packets.PongPacket(packet.nonce)));
      }
    });
    requesterParser.on('packet', (packet) => {
      if (packet.type === packets.types.VERSION) {
        requesterSawVersion = packet.agent === '/hnsr-poc:0.0.1/';
        requesterInner.write(frame(framer, new packets.VerackPacket()));
      } else if (packet.type === packets.types.VERACK) {
        requesterSawVerack = true;
      } else if (packet.type === packets.types.PONG) {
        requesterSawPong = packet.nonce.equals(pingNonce);
      }
    });

    endpoint.hnsr.once('circuit', (socket) => {
      socket.on('error', (err) => {
        throw err;
      });
      endpointInner = BrontideStream.fromInbound(
        socket,
        endpoint.identityKey);
      endpointInner.on('error', (err) => {
        throw err;
      });
      endpointInner.on('data', data => endpointParser.feed(data));
    });

    const circuit = await requester.hnsr.openCircuit(
      requesterRelay,
      routes[0].tickets[0]);
    circuit.socket.on('error', (err) => {
      throw err;
    });
    requesterInner = BrontideStream.fromOutbound(
      circuit.socket,
      requester.identityKey,
      routes[0].delegation.endpointKey);
    requesterInner.on('error', (err) => {
      throw err;
    });
    requesterInner.on('data', data => requesterParser.feed(data));

    await new Promise((resolve, reject) => {
      const timer = setTimeout(
        () => reject(new Error('Inner Brontide handshake timed out.')),
        10000);
      requesterInner.once('connect', () => {
        clearTimeout(timer);
        requesterInner.write(frame(framer, version(requesterNonce)));
        resolve();
      });
    });

    await waitFor(
      () => endpointSawVersion
        && endpointSawVerack
        && requesterSawVersion
        && requesterSawVerack,
      'Inner Handshake version/verack exchange did not complete.');

    requesterInner.write(frame(framer, new packets.PingPacket(pingNonce)));
    await waitFor(
      () => requesterSawPong,
      'Inner Handshake ping/pong did not complete.');

    assert(endpointInner.remoteStatic.equals(
      secp256k1.publicKeyCreate(requester.identityKey, true)));
    assert(requesterInner.remoteStatic.equals(endpoint.hnsr.publicKey));
    assert.strictEqual(
      relay.hnsr.relayPayloads.some(raw => raw.includes(pingNonce)),
      false);

    await endpoint.close();
    opened.splice(opened.indexOf(endpoint), 1);
    await waitFor(
      () => relay.hnsr.reservations.size === 0,
      'Relay did not invalidate the disconnected endpoint reservation.');

    const staleRoutes = await requester.hnsr.lookup(
      requesterRendezvous,
      key);
    assert.strictEqual(staleRoutes.length, 1);
    let staleRejected = false;

    try {
      await requester.hnsr.openCircuit(
        requesterRelay,
        staleRoutes[0].tickets[0]);
    } catch (e) {
      staleRejected = e.code === 11;
    }

    assert(staleRejected);

    const result = {
      schema: 1,
      network: 'regtest',
      assignment: {
        rendezvousServiceBit:
          `0x${common.EXPERIMENTAL_HNSR_RENDEZVOUS_SERVICE.toString(16)}`,
        relayServiceBit:
          `0x${common.EXPERIMENTAL_HNSR_RELAY_SERVICE.toString(16)}`,
        packetType: `0x${common.EXPERIMENTAL_HNSR.toString(16)}`
      },
      topology: {
        fullNodes: 4,
        outerTransport: 'authenticated Handshake Brontide',
        endpointListeners: 0,
        convergedRegtestHeight: 1,
        endpoint: endpoint.hnsr.publicKey.toString('hex'),
        relay: relay.hnsr.publicKey.toString('hex'),
        rendezvous: rendezvous.hnsr.publicKey.toString('hex'),
        requester: requester.hnsr.publicKey.toString('hex')
      },
      reservation: {
        relaySignatureVerified: ticket.verifyRelay(),
        endpointSignatureVerified: ticket.verifyEndpoint(),
        ticketID: ticket.id().toString('hex'),
        maxActiveCircuits: ticket.maxActiveCircuits,
        maxBytesPerCircuit: ticket.maxBytesPerCircuit
      },
      rendezvous: {
        routeKey: key.toString('hex'),
        routeBytes: record.encode().length,
        routeSignatureVerified: record.verify(endpoint.network.magic),
        returnedRecords: routes.length,
        storedCopiesInTrial: rendezvous.hnsr.store.size
      },
      circuit: {
        profile: 'HNS_NODE_V1',
        circuitID: circuit.circuitID.toString('hex'),
        innerTransport: 'end-to-end Handshake Brontide',
        endpointAuthenticated: requesterInner.remoteStatic.equals(
          endpoint.hnsr.publicKey),
        requesterAuthenticated: endpointInner.remoteStatic.equals(
          requester.hnsr.publicKey),
        versionVerack: true,
        pingPong: true
      },
      relayView: {
        forwardedEncryptedBytes: relay.hnsr.relayBytes,
        plaintextPingNonceObserved: relay.hnsr.relayPayloads
          .some(raw => raw.includes(pingNonce)),
        transcriptSHA256: sha256.digest(Buffer.concat(
          relay.hnsr.relayPayloads)).toString('hex')
      },
      lifecycle: {
        staleRouteStillReturned: staleRoutes.length === 1,
        disconnectedReservationInvalidated:
          relay.hnsr.reservations.size === 0,
        staleTicketRejected: staleRejected
      },
      observedOpcodes: wireCounts,
      result: 'pass'
    };
    const output = JSON.stringify(result, null, 2) + '\n';

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
