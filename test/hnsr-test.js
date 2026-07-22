'use strict';

const assert = require('bsert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const base32 = require('bcrypto/lib/encoding/base32');
const secp256k1 = require('bcrypto/lib/secp256k1');
const IP = require('binet');
const FullNode = require('../lib/node/fullnode');
const Network = require('../lib/protocol/network');
const common = require('../lib/net/common');
const packets = require('../lib/net/packets');
const rules = require('../lib/covenants/rules');
const {Resource} = require('../lib/dns/resource');
const {
  ReserveRequest,
  RelayTicket,
  ServiceAuthorization,
  EndpointDelegation,
  RouteRecord,
  RoutingTable,
  RouteStore,
  RendezvousContact,
  CircuitSocket,
  HNSRService,
  bucketIndex,
  rendezvousNodeID,
  compareDistance,
  opcodes,
  profiles,
  routeKey,
  namedRouteKey,
  parseHNSRRootKey,
  parseHNSRURI,
  webOrigin,
  HTTPMessageParser,
  encodeWebRequest,
  encodeWebResponse
} = require('../lib/net/hnsr');

const network = Network.get('regtest');
const ORDER = BigInt(
  '0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141');

function writeBig(value, size) {
  const hex = value.toString(16).padStart(size * 2, '0');
  return Buffer.from(hex, 'hex');
}

function highS(signature) {
  const raw = secp256k1.signatureImport(signature);
  const low = BigInt(`0x${raw.slice(32).toString('hex')}`);
  writeBig(ORDER - low, 32).copy(raw, 32);
  return secp256k1.signatureExport(raw);
}

function fixture(timestamp = Math.floor(Date.now() / 1000), sequence = 1) {
  const endpointPrivate = secp256k1.privateKeyGenerate();
  const endpointKey = secp256k1.publicKeyCreate(endpointPrivate, true);
  const relayPrivate = secp256k1.privateKeyGenerate();
  const relayKey = secp256k1.publicKeyCreate(relayPrivate, true);
  const ticket = new RelayTicket({
    networkMagic: network.magic,
    profile: 1,
    transport: 0,
    hostType: 1,
    host: Buffer.alloc(16),
    port: network.brontidePort,
    relayKey,
    endpointKey,
    reservationID: Buffer.alloc(16, 0x01),
    issuedAt: timestamp,
    expiresAt: timestamp + 1800,
    maxActiveCircuits: 8,
    maxBytesPerCircuit: 1048576,
    maxTotalBytes: 8388608
  }).signRelay(relayPrivate).signEndpoint(endpointPrivate);
  const delegation = new EndpointDelegation({
    endpointKey,
    sequence,
    issuedAt: timestamp,
    expiresAt: timestamp + 900,
    maxActiveCircuits: 8,
    maxBytesPerCircuit: 1048576
  }).sign(network.magic, endpointPrivate);
  const key = routeKey(network.magic, endpointKey);
  const record = new RouteRecord({
    routeKey: key,
    sequence,
    issuedAt: timestamp,
    expiresAt: timestamp + 900,
    delegation,
    tickets: [ticket]
  }).sign(endpointPrivate);

  return {
    endpointPrivate,
    endpointKey,
    relayPrivate,
    relayKey,
    ticket,
    delegation,
    key,
    record,
    timestamp
  };
}

function namedFixture(timestamp = Math.floor(Date.now() / 1000)) {
  const rootPrivate = secp256k1.privateKeyGenerate();
  const rootKey = secp256k1.publicKeyCreate(rootPrivate, true);
  const servicePrivate = secp256k1.privateKeyGenerate();
  const serviceKey = secp256k1.publicKeyCreate(servicePrivate, true);
  const endpointPrivate = secp256k1.privateKeyGenerate();
  const endpointKey = secp256k1.publicKeyCreate(endpointPrivate, true);
  const relayPrivate = secp256k1.privateKeyGenerate();
  const relayKey = secp256k1.publicKeyCreate(relayPrivate, true);
  const nameHash = rules.hashName('denuoweb');
  const authorization = new ServiceAuthorization({
    networkMagic: network.magic,
    nameHash,
    serviceName: 'p2p-site',
    profile: profiles.HNS_WEB_V1,
    serviceKey,
    serial: 7,
    validFromHeight: 5,
    validUntilHeight: 100,
    maxEndpointLifetime: 3600,
    maxRouteLifetime: 900
  }).sign(network.magic, rootPrivate);
  const ticket = new RelayTicket({
    networkMagic: network.magic,
    profile: profiles.HNS_WEB_V1,
    hostType: 1,
    host: Buffer.alloc(16),
    port: network.brontidePort,
    relayKey,
    endpointKey,
    reservationID: Buffer.alloc(16, 0x02),
    issuedAt: timestamp,
    expiresAt: timestamp + 1800,
    maxActiveCircuits: 4,
    maxBytesPerCircuit: 1048576,
    maxTotalBytes: 4194304
  }).signRelay(relayPrivate).signEndpoint(endpointPrivate);
  const delegation = new EndpointDelegation({
    authorizationID: authorization.id(),
    endpointKey,
    sequence: 3,
    issuedAt: timestamp,
    expiresAt: timestamp + 900,
    maxActiveCircuits: 4,
    maxBytesPerCircuit: 1048576
  }).sign(network.magic, servicePrivate);
  const key = namedRouteKey(
    network.magic,
    nameHash,
    authorization.serviceName,
    authorization.profile);
  const record = new RouteRecord({
    authorityType: 1,
    routeKey: key,
    profile: profiles.HNS_WEB_V1,
    sequence: 4,
    issuedAt: timestamp,
    expiresAt: timestamp + 900,
    authorization: authorization.encode(),
    delegation,
    tickets: [ticket]
  }).sign(endpointPrivate);

  return {
    rootPrivate,
    rootKey,
    servicePrivate,
    serviceKey,
    endpointPrivate,
    endpointKey,
    authorization,
    ticket,
    delegation,
    key,
    record,
    timestamp
  };
}

function contactFixture(host, timestamp = Math.floor(Date.now() / 1000)) {
  const privateKey = secp256k1.privateKeyGenerate();
  const peerKey = secp256k1.publicKeyCreate(privateKey, true);

  return new RendezvousContact({
    nodeID: rendezvousNodeID(network.magic, peerKey),
    hostType: 1,
    host: IP.toBuffer(host),
    port: network.brontidePort,
    services: common.services.NETWORK
      | common.EXPERIMENTAL_HNSR_RENDEZVOUS_SERVICE,
    peerKey,
    observedAt: timestamp
  });
}

function waitFor(test, timeout = 2000) {
  const started = Date.now();

  return new Promise((resolve, reject) => {
    const check = () => {
      if (test()) {
        resolve();
        return;
      }

      if (Date.now() - started >= timeout) {
        reject(new Error('Timed out waiting for HNSR test condition.'));
        return;
      }

      setTimeout(check, 5);
    };

    check();
  });
}

describe('HNSR', function() {
  it('should parse exactly one canonical HNSR root key from HNS TXT', () => {
    const rootPrivate = secp256k1.privateKeyGenerate();
    const rootKey = secp256k1.publicKeyCreate(rootPrivate, true);
    const encoded = base32.encode(rootKey);
    const resource = Resource.fromJSON({
      records: [
        {type: 'TXT', txt: ['unrelated=value']},
        {type: 'TXT', txt: [`hnsr1 k=${encoded}`]}
      ]
    });

    assert.bufferEqual(parseHNSRRootKey(resource), rootKey);

    resource.records.push(Resource.fromJSON({
      records: [{type: 'TXT', txt: [`hnsr1 k=${encoded}`]}]
    }).records[0]);
    assert.throws(() => parseHNSRRootKey(resource), /ambiguous/);

    const noncanonical = Resource.fromJSON({
      records: [{type: 'TXT', txt: [`HNSR1 k=${encoded}`]}]
    });
    assert.throws(() => parseHNSRRootKey(noncanonical), /no canonical/);
  });

  it('should authenticate and store a named web route trust chain', () => {
    const item = namedFixture();
    const decodedAuthorization = ServiceAuthorization.decode(
      item.authorization.encode());
    const decodedRecord = RouteRecord.decode(item.record.encode());

    assert(decodedAuthorization.verify(item.rootKey, network.magic, 50));
    assert.bufferEqual(decodedAuthorization.id(), item.authorization.id());
    assert(decodedRecord.verify(network.magic, item.timestamp, {
      rootKey: item.rootKey,
      height: 50
    }));

    const store = new RouteStore(network.magic);
    store.put(item.key, item.record.encode(), item.timestamp, 'publisher');
    assert.strictEqual(store.get(item.key, 1, item.timestamp).length, 1);
    assert.strictEqual(store.sample(
      1,
      Buffer.alloc(32, 0x03),
      item.timestamp).length, 0);
  });

  it('should reject named routes outside their HNS authorization', () => {
    const item = namedFixture();
    const otherRoot = secp256k1.publicKeyCreate(
      secp256k1.privateKeyGenerate(),
      true);

    assert(!item.record.verify(network.magic, item.timestamp, {
      rootKey: otherRoot,
      height: 50
    }));
    assert(!item.record.verify(network.magic, item.timestamp, {
      rootKey: item.rootKey,
      height: 101
    }));

    const substituted = RouteRecord.decode(item.record.encode());
    substituted.routeKey = Buffer.alloc(32, 0x04);
    substituted.sign(item.endpointPrivate);
    assert(!substituted.verify(network.magic, item.timestamp, {
      rootKey: item.rootKey,
      height: 50
    }));
  });

  it('should reject malformed named authorization chains', () => {
    const item = namedFixture();
    const highAuthorization = ServiceAuthorization.decode(
      item.authorization.encode());

    assert.strictEqual(
      highAuthorization.verify(item.rootKey, network.magic + 1, 50),
      false);

    highAuthorization.rootSignature = highS(
      highAuthorization.rootSignature);
    assert.strictEqual(
      secp256k1.isLowDER(highAuthorization.rootSignature),
      false);
    assert.strictEqual(
      highAuthorization.verify(item.rootKey, network.magic, 50),
      false);

    const mismatched = RouteRecord.decode(item.record.encode());
    mismatched.delegation.authorizationID = Buffer.alloc(32, 0x05);
    mismatched.delegation.sign(network.magic, item.servicePrivate);
    mismatched.sign(item.endpointPrivate);
    assert.strictEqual(mismatched.verify(network.magic, item.timestamp, {
      rootKey: item.rootKey,
      height: 50
    }), false);

    const overlong = RouteRecord.decode(item.record.encode());
    overlong.delegation.expiresAt = item.timestamp
      + item.authorization.maxEndpointLifetime + 1;
    overlong.delegation.sign(network.magic, item.servicePrivate);
    overlong.sign(item.endpointPrivate);
    assert.strictEqual(overlong.verify(network.magic, item.timestamp, {
      rootKey: item.rootKey,
      height: 50
    }), false);

    const raw = item.authorization.encode();
    const unknownVersion = Buffer.from(raw);
    unknownVersion[0] = 2;
    assert.throws(() => ServiceAuthorization.decode(raw.slice(0, -1)));
    assert.throws(() => ServiceAuthorization.decode(Buffer.concat([
      raw,
      Buffer.from([0x00])
    ])), /Trailing bytes/);
    assert.throws(() => ServiceAuthorization.decode(unknownVersion));
  });

  it('should derive a stable named browser origin independent of relays', () => {
    const item = namedFixture();
    const target = parseHNSRURI(
      'hnsr://denuoweb/p2p-site/articles/one?q=handshake#section');
    const first = webOrigin(
      item.authorization.nameHash,
      target.serviceName,
      profiles.HNS_WEB_V1);
    const second = webOrigin(
      item.authorization.nameHash,
      target.serviceName,
      profiles.HNS_WEB_V1);

    assert.strictEqual(target.rootName, 'denuoweb');
    assert.strictEqual(target.serviceName, 'p2p-site');
    assert.strictEqual(target.path, '/articles/one?q=handshake');
    assert.strictEqual(first.key, second.key);
    assert(!first.key.includes(item.ticket.relayKey.toString('hex')));
    assert(!first.key.includes(item.endpointKey.toString('hex')));
    assert.notStrictEqual(
      first.key,
      webOrigin(
        rules.hashName('other-name'),
        target.serviceName,
        profiles.HNS_WEB_V1).key);
    assert.notStrictEqual(
      first.key,
      webOrigin(
        item.authorization.nameHash,
        'other-service',
        profiles.HNS_WEB_V1).key);
    assert.throws(
      () => parseHNSRURI('hnsr://denuoweb/P2P-site/'),
      /service name/);
  });

  it('should enforce HNSR web authority and bounded HTTP framing', () => {
    const request = encodeWebRequest('denuoweb', 'p2p-site', {
      method: 'POST',
      path: '/submit',
      headers: {'Content-Type': 'text/plain'},
      body: 'hello'
    });
    const parser = new HTTPMessageParser('request');
    const messages = [
      ...parser.feed(request.slice(0, 11)),
      ...parser.feed(request.slice(11))
    ];

    assert.strictEqual(messages.length, 1);
    assert.strictEqual(messages[0].method, 'POST');
    assert.strictEqual(messages[0].headers.get('host'), 'p2p-site.denuoweb');
    assert.strictEqual(
      messages[0].headers.get('hnsr-authority'),
      'denuoweb');
    assert.strictEqual(messages[0].headers.get('hnsr-service'), 'p2p-site');
    assert.bufferEqual(messages[0].body, Buffer.from('hello'));

    const responseParser = new HTTPMessageParser('response');
    const response = responseParser.feed(encodeWebResponse({
      statusCode: 201,
      reason: 'Created',
      body: 'stored'
    }))[0];
    assert.strictEqual(response.statusCode, 201);
    assert.bufferEqual(response.body, Buffer.from('stored'));

    assert.throws(() => encodeWebRequest('denuoweb', 'p2p-site', {
      headers: {Host: 'attacker.invalid'}
    }), /reserved/);
    assert.throws(() => parser.feed(Buffer.from(
      'POST / HTTP/1.1\r\n'
      + 'Host: p2p-site.denuoweb\r\n'
      + 'HNSR-Authority: denuoweb\r\n'
      + 'HNSR-Service: p2p-site\r\n'
      + 'Transfer-Encoding: chunked\r\n\r\n')),
    /upgrade is not permitted/);
    assert.throws(() => encodeWebResponse({
      body: Buffer.alloc(common.hnsr.MAX_WEB_BODY_SIZE + 1)
    }), /response/);

    const pipelined = new HTTPMessageParser('response').feed(Buffer.concat([
      encodeWebResponse({body: 'one'}),
      encodeWebResponse({body: 'two'})
    ]));
    assert.strictEqual(pipelined.length, 2);
    assert.bufferEqual(pipelined[0].body, Buffer.from('one'));
    assert.bufferEqual(pipelined[1].body, Buffer.from('two'));

    assert.throws(() => new HTTPMessageParser('request').feed(Buffer.from(
      'GET / HTTP/1.1\r\n'
      + 'Host: p2p-site.denuoweb\r\n'
      + 'Host: attacker.invalid\r\n'
      + 'HNSR-Authority: denuoweb\r\n'
      + 'HNSR-Service: p2p-site\r\n'
      + 'Content-Length: 0\r\n\r\n')),
    /duplicate/);
    assert.throws(() => new HTTPMessageParser('request').feed(Buffer.from(
      'POST / HTTP/1.1\r\n'
      + 'Host: p2p-site.denuoweb\r\n'
      + 'HNSR-Authority: denuoweb\r\n'
      + 'HNSR-Service: p2p-site\r\n'
      + 'Content-Length: 0\r\n'
      + 'Content-Length: 4\r\n\r\ntest')),
    /duplicate/);
    assert.throws(() => new HTTPMessageParser('request').feed(Buffer.from(
      'GET / HTTP/1.1\r\nX-Fill: '
      + 'a'.repeat(common.hnsr.MAX_WEB_HEADER_SIZE)
      + '\r\n\r\n')),
    /header exceeds/);
  });

  it('should round trip the private HNSR envelope', () => {
    const context = Buffer.from('0102030405060708', 'hex');
    const body = Buffer.from('deadbeef', 'hex');
    const packet = new packets.HNSRPacket(1, 17, context, body);
    const decoded = packets.decode(packet.type, packet.encode());

    assert.strictEqual(decoded.version, 1);
    assert.strictEqual(decoded.opcode, 17);
    assert(decoded.contextID.equals(context));
    assert(decoded.body.equals(body));
  });

  it('should reject malformed HNSR envelopes', () => {
    const context = Buffer.from('0102030405060708', 'hex');
    const packet = new packets.HNSRPacket(1, 17, context, Buffer.alloc(1));
    const raw = packet.encode();

    assert.throws(() => packets.decode(packet.type, raw.slice(0, 11)));

    const badVersion = Buffer.from(raw);
    badVersion[0] = 2;
    assert.throws(() => packets.decode(packet.type, badVersion));

    const flags = Buffer.from(raw);
    flags[2] = 1;
    assert.throws(() => packets.decode(packet.type, flags));

    const zero = Buffer.from(raw);
    zero.fill(0, 4, 12);
    assert.throws(() => packets.decode(packet.type, zero));

    const opcode = Buffer.from(raw);
    opcode[1] = 21;
    assert.throws(() => packets.decode(packet.type, opcode));
  });

  it('should bind a reservation to relay, network, and context', () => {
    const item = fixture();
    const context = Buffer.from('0102030405060708', 'hex');
    const request = new ReserveRequest({
      endpointKey: item.endpointKey,
      profile: 1,
      lifetime: 1800,
      maxCircuits: 8,
      maxBytes: 1048576,
      nonce: Buffer.alloc(16, 0x02)
    }).sign(
      network.magic,
      item.relayKey,
      context,
      item.endpointPrivate);
    const decoded = ReserveRequest.decode(request.encode());

    assert(decoded.verify(network.magic, item.relayKey, context));
    assert.strictEqual(
      decoded.verify(network.magic + 1, item.relayKey, context),
      false);
    assert.strictEqual(
      decoded.verify(network.magic, item.endpointKey, context),
      false);
    assert.strictEqual(
      decoded.verify(network.magic, item.relayKey, Buffer.alloc(8, 0x03)),
      false);
  });

  it('should bind a renewal to its previous reservation', () => {
    const item = fixture();
    const context = Buffer.from('0102030405060708', 'hex');
    const previous = Buffer.alloc(16, 0x04);
    const request = new ReserveRequest({
      endpointKey: item.endpointKey,
      profile: 1,
      lifetime: 1800,
      maxCircuits: 8,
      maxBytes: 1048576,
      nonce: Buffer.alloc(16, 0x05)
    }).signRenewal(
      network.magic,
      item.relayKey,
      context,
      previous,
      item.endpointPrivate);
    const decoded = ReserveRequest.decode(request.encode());

    assert(decoded.verifyRenewal(
      network.magic,
      item.relayKey,
      context,
      previous));
    assert.strictEqual(decoded.verifyRenewal(
      network.magic,
      item.relayKey,
      context,
      Buffer.alloc(16, 0x06)), false);
    assert.strictEqual(
      decoded.verify(network.magic, item.relayKey, context),
      false);
  });

  it('should round trip and authenticate a relay ticket', () => {
    const item = fixture();
    const decoded = RelayTicket.decode(item.ticket.encode());

    assert(decoded.verifyRelay());
    assert(decoded.verifyEndpoint());
    assert(decoded.verify(network.magic, item.timestamp));
    assert(decoded.id().equals(item.ticket.id()));

    decoded.endpointSignature[decoded.endpointSignature.length - 1] ^= 1;
    assert.strictEqual(decoded.verifyEndpoint(), false);
  });

  it('should reject a high-S ticket signature', () => {
    const item = fixture();
    item.ticket.relaySignature = highS(item.ticket.relaySignature);
    assert.strictEqual(secp256k1.isLowDER(item.ticket.relaySignature), false);
    assert.strictEqual(item.ticket.verifyRelay(), false);
  });

  it('should round trip an unnamed route authorization chain', () => {
    const item = fixture();
    const raw = item.record.encode();
    const decoded = RouteRecord.decode(raw);

    assert(raw.length <= common.hnsr.MAX_RECORD_SIZE);
    assert(decoded.verify(network.magic, item.timestamp));
    assert(decoded.routeKey.equals(item.key));
    assert(decoded.delegation.endpointKey.equals(item.endpointKey));
    assert(decoded.tickets[0].id().equals(item.ticket.id()));
  });

  it('should reject a route-key substitution', () => {
    const item = fixture();
    item.record.routeKey[0] ^= 1;
    item.record.sign(item.endpointPrivate);
    assert.strictEqual(item.record.verify(network.magic, item.timestamp), false);
  });

  it('should replace only increasing endpoint route sequences', () => {
    const item = fixture(1700000000, 1);
    const store = new RouteStore(network.magic, {
      maxRecords: 4,
      maxPerKey: 2
    });

    store.put(item.key, item.record.encode(), item.timestamp);
    assert.strictEqual(store.get(item.key, 16, item.timestamp).length, 1);
    assert.throws(() => {
      store.put(item.key, item.record.encode(), item.timestamp);
    }, /Stale HNSR route sequence/);

    item.record.sequence = 2;
    item.record.sign(item.endpointPrivate);
    store.put(item.key, item.record.encode(), item.timestamp);

    const records = store.get(item.key, 16, item.timestamp);
    assert.strictEqual(records.length, 1);
    assert.strictEqual(RouteRecord.decode(records[0]).sequence, 2);
  });

  it('should expire rendezvous records without a withdrawal broadcast', () => {
    const item = fixture(1700000000);
    const store = new RouteStore(network.magic);
    store.put(item.key, item.record.encode(), item.timestamp);

    assert.strictEqual(
      store.get(item.key, 16, item.record.expiresAt).length,
      0);
    assert.strictEqual(store.size, 0);
  });

  it('should encode authenticated rendezvous contacts and XOR order', () => {
    const privateKey = secp256k1.privateKeyGenerate();
    const peerKey = secp256k1.publicKeyCreate(privateKey, true);
    const timestamp = 1700000000;
    const contact = new RendezvousContact({
      nodeID: rendezvousNodeID(network.magic, peerKey),
      hostType: 1,
      host: Buffer.from('00000000000000000000ffff7f000001', 'hex'),
      port: network.brontidePort,
      services: common.services.NETWORK
        | common.EXPERIMENTAL_HNSR_RENDEZVOUS_SERVICE,
      peerKey,
      observedAt: timestamp
    });
    const decoded = RendezvousContact.decode(contact.encode());

    assert.strictEqual(contact.encode().length, 100);
    assert(decoded.verify(network.magic, timestamp));
    assert(decoded.peerKey.equals(peerKey));
    assert.strictEqual(decoded.toAddress(network).host, '127.0.0.1');
    assert.strictEqual(decoded.toAddress(network).port, network.brontidePort);

    const target = Buffer.alloc(32);
    const near = Buffer.alloc(32);
    const far = Buffer.alloc(32);
    near[0] = 1;
    far[0] = 2;
    assert(compareDistance(near, far, target) < 0);
    assert(compareDistance(far, near, target) > 0);
  });

  it('should sample deterministically and enforce source quotas', () => {
    const timestamp = 1700000000;
    const first = fixture(timestamp, 1);
    const second = fixture(timestamp, 1);
    const store = new RouteStore(network.magic, {
      maxRecords: 4,
      maxPerKey: 2,
      maxPerPeer: 1
    });

    store.put(first.key, first.record.encode(), timestamp, 'peer-a');
    assert.throws(() => {
      store.put(second.key, second.record.encode(), timestamp, 'peer-a');
    }, /per-peer route capacity/);
    store.put(second.key, second.record.encode(), timestamp, 'peer-b');

    const seed = Buffer.alloc(32, 0x11);
    const sample = store.sample(2, seed, timestamp);
    const repeated = store.sample(2, seed, timestamp);

    assert.strictEqual(sample.length, 2);
    assert.bufferEqual(sample[0], repeated[0]);
    assert.bufferEqual(sample[1], repeated[1]);

    first.record.sequence = 2;
    first.record.sign(first.endpointPrivate);
    assert.throws(() => {
      store.put(first.key, first.record.encode(), timestamp, 'peer-b');
    }, /per-peer route capacity/);

    const retained = RouteRecord.decode(store.get(
      first.key,
      1,
      timestamp)[0]);
    assert.strictEqual(retained.sequence, 1);
  });

  it('should bound persistent XOR buckets and reject netgroup Sybils', () => {
    const selfKey = secp256k1.publicKeyCreate(
      secp256k1.privateKeyGenerate(),
      true);
    const selfID = rendezvousNodeID(network.magic, selfKey);
    const table = new RoutingTable(network.magic, selfID, network, {
      bucketSize: 4,
      maxEntries: 64,
      maxPerNetgroup: 2
    });
    const selected = [];
    let targetBucket = -1;

    for (let index = 0; selected.length < 3 && index < 500; index++) {
      const third = Math.floor(index / 254);
      const fourth = index % 254 + 1;
      const contact = contactFixture(`8.8.${third}.${fourth}`);
      const bucket = bucketIndex(selfID, contact.nodeID);

      if (targetBucket === -1)
        targetBucket = bucket;

      if (bucket === targetBucket)
        selected.push(contact);
    }

    assert.strictEqual(selected.length, 3);
    assert(table.add(selected[0]));
    assert(table.add(selected[1]));
    assert.strictEqual(table.add(selected[2]), false);
    assert.strictEqual(table.buckets[targetBucket].length, 2);

    for (let index = 0; index < 200; index++)
      table.add(contactFixture(`9.${index + 1}.1.1`));

    assert(table.contacts.size <= 64);
    assert(table.buckets.every(bucket => bucket.length <= 4));
    assert(table.closest(Buffer.alloc(32), 8).length <= 8);

    const rejected = contactFixture('127.0.0.1');
    assert.strictEqual(table.add(rejected), false);

    const key = selected[0].peerKey;
    assert(table.markAttempt(key, false));
    assert(table.markAttempt(key, false));
    assert(table.markAttempt(key, false));
    assert.strictEqual(table.contacts.has(key.toString('hex')), false);
  });

  it('should enforce route storage quotas across a source prefix', () => {
    const first = fixture();
    const second = fixture();
    const store = new RouteStore(network.magic, {
      maxRecords: 4,
      maxPerPeer: 4,
      maxPerPrefix: 1
    });

    store.put(
      first.key,
      first.record.encode(),
      first.timestamp,
      'peer-a',
      '4:080804');
    assert.throws(() => store.put(
      second.key,
      second.record.encode(),
      second.timestamp,
      'peer-b',
      '4:080804'), /per-prefix route capacity/);
    store.put(
      second.key,
      second.record.encode(),
      second.timestamp,
      'peer-b',
      '4:090901');
    assert.strictEqual(store.size, 2);
  });

  it('should recover routing and route state after restart', async () => {
    const prefix = fs.mkdtempSync(path.join(os.tmpdir(), 'hsd-hnsr-state-'));
    const identityKey = secp256k1.privateKeyGenerate();
    const item = fixture();
    const contact = contactFixture('8.8.8.8');
    const options = {
      enabled: true,
      rendezvous: true,
      network,
      identityKey,
      memory: false,
      persist: true,
      prefix
    };

    try {
      const first = new HNSRService(options);
      await first.open();
      assert(first.routing.add(contact));
      first.store.put(
        item.key,
        item.record.encode(),
        item.timestamp,
        'peer-a',
        '4:080808');
      first.routeSequence = 12;
      first.endpointSequence = 9;
      first._markStateDirty();
      await first.close();

      const second = new HNSRService(options);
      await second.open();
      assert.strictEqual(second.contacts.size, 1);
      assert.strictEqual(second.store.size, 1);
      assert.strictEqual(second.routeSequence, 12);
      assert.strictEqual(second.endpointSequence, 9);
      assert.bufferEqual(
        second.store.get(item.key, 1, item.timestamp)[0],
        item.record.encode());
      await second.close();
    } finally {
      fs.rmSync(prefix, {recursive: true, force: true});
    }
  });

  it('should republish immediately after a network change', async () => {
    const item = fixture();
    const service = new HNSRService({
      enabled: true,
      endpoint: true,
      network,
      identityKey: item.endpointPrivate,
      memory: true
    });
    let calls = 0;

    service.republish = async () => {
      calls += 1;
      return {record: item.record, stored: [], failures: []};
    };

    await service.open();
    const state = service.startRepublisher(
      {record: item.record},
      [item.ticket],
      []);
    service.notifyNetworkChange();
    await waitFor(() => state.successes === 1);
    assert.strictEqual(calls, 1);
    assert.strictEqual(service.getTelemetry().republishSuccesses, 1);
    assert(service.stopRepublisher(state));
    await service.close();
  });

  it('should prioritize node relay traffic while keeping web traffic fair',
    async () => {
      const item = fixture();
      const service = new HNSRService({
        enabled: true,
        relay: true,
        network,
        identityKey: item.relayPrivate,
        memory: true
      });
      const sent = [];
      const nodePeer = {
        id: 1,
        destroyed: false,
        send(packet) {
          sent.push({profile: profiles.HNS_NODE_V1, packet});
        }
      };
      const webPeer = {
        id: 2,
        destroyed: false,
        send(packet) {
          sent.push({profile: profiles.HNS_WEB_V1, packet});
        }
      };
      const nodeState = {
        closed: false,
        queuedBytes: 0,
        circuitID: Buffer.alloc(8, 0x01),
        ticket: {profile: profiles.HNS_NODE_V1}
      };
      const webState = {
        closed: false,
        queuedBytes: 0,
        circuitID: Buffer.alloc(8, 0x02),
        ticket: {profile: profiles.HNS_WEB_V1}
      };

      await service.open();

      for (let index = 0; index < 8; index++) {
        service._queueRelayData(
          {state: webState, other: webPeer},
          Buffer.alloc(4096, 0x02));
        service._queueRelayData(
          {state: nodeState, other: nodePeer},
          Buffer.alloc(4096, 0x01));
      }

      await waitFor(() => service.relayQueueBytes === 0);
      assert.strictEqual(sent[0].profile, profiles.HNS_NODE_V1);
      assert(sent.some(item => item.profile === profiles.HNS_WEB_V1));
      assert.strictEqual(service.getTelemetry().relayDrops, 0);
      await service.close();
    });

  it('should apply circuit backpressure and delayed window credit', async () => {
    const sent = [];
    const service = {
      _send(peer, opcode, contextID, body) {
        sent.push({peer, opcode, contextID, body});
        return true;
      },
      _dropSocket() {}
    };
    const peer = {id: 1};
    const contextID = Buffer.from('0102030405060708', 'hex');
    const socket = new CircuitSocket(
      service,
      peer,
      contextID,
      common.hnsr.MIN_WINDOW);
    const payload = Buffer.alloc(common.hnsr.MIN_WINDOW + 10, 0x22);

    assert.strictEqual(socket.write(payload), false);
    assert.strictEqual(sent.length, 1);
    assert.strictEqual(sent[0].opcode, opcodes.DATA);
    assert.strictEqual(sent[0].body.length, common.hnsr.MIN_WINDOW);
    assert.strictEqual(socket.sendQueueBytes, 10);

    const drained = new Promise(resolve => socket.once('drain', resolve));
    socket.addCredit(10);
    await drained;
    assert.strictEqual(socket.sendQueueBytes, 0);
    assert.strictEqual(sent[1].body.length, 10);

    let received = null;
    socket.on('data', (data) => {
      received = data;
    });
    socket.pause();
    socket.receive(Buffer.from('aabb', 'hex'));
    assert.strictEqual(received, null);
    assert.strictEqual(sent.length, 2);
    socket.resume();
    assert.bufferEqual(received, Buffer.from('aabb', 'hex'));
    assert.strictEqual(sent[2].opcode, opcodes.WINDOW);
    assert.strictEqual(sent[2].body.readUInt32LE(0), 2);
  });

  it('should expose role bits only for configured regtest roles', () => {
    const node = new FullNode({
      network: 'regtest',
      memory: true,
      listen: true,
      noDns: true,
      experimentalHnsr: true,
      experimentalHnsrRelay: true,
      experimentalHnsrRendezvous: true
    });
    const expected = common.services.NETWORK
      | common.EXPERIMENTAL_HNSR_RELAY_SERVICE
      | common.EXPERIMENTAL_HNSR_RENDEZVOUS_SERVICE;

    assert.strictEqual(node.pool.options.services, expected);
  });

  it('should refuse the private assignment outside regtest', () => {
    assert.throws(() => new FullNode({
      network: 'main',
      memory: true,
      listen: true,
      noDns: true,
      experimentalHnsr: true,
      experimentalHnsrRelay: true
    }), /regtest-only/);
  });

  it('should require explicit acknowledgement and a public testnet host', () => {
    assert.throws(() => new FullNode({
      network: 'testnet',
      memory: true,
      listen: true,
      noDns: true,
      experimentalHnsr: true,
      experimentalHnsrRelay: true
    }), /explicitly acknowledged/);

    assert.throws(() => new FullNode({
      network: 'testnet',
      memory: true,
      listen: true,
      noDns: true,
      experimentalHnsr: true,
      experimentalHnsrRelay: true,
      experimentalHnsrTestnet: true
    }), /require a public host/);

    const node = new FullNode({
      network: 'testnet',
      memory: true,
      listen: true,
      noDns: true,
      publicHost: '8.8.8.8',
      experimentalHnsr: true,
      experimentalHnsrRelay: true,
      experimentalHnsrTestnet: true
    });

    assert(node.hnsr.enabled);
    assert(node.hnsr.relay);
  });
});
