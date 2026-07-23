/*!
 * hnsr.js - regtest proof of concept for Handshake rendezvous and relay.
 * Copyright (c) 2026, Jaron Rosenau (MIT License).
 */

'use strict';

const assert = require('bsert');
const EventEmitter = require('events');
const bio = require('bufio');
const fs = require('bfile');
const IP = require('binet');
const path = require('path');
const base32 = require('bcrypto/lib/encoding/base32');
const blake2b = require('bcrypto/lib/blake2b');
const random = require('bcrypto/lib/random');
const secp256k1 = require('bcrypto/lib/secp256k1');
const common = require('./common');
const NetAddress = require('./netaddress');
const packets = require('./packets');
const {BrontideStream} = require('./brontide');
const rules = require('../covenants/rules');
const {Resource} = require('../dns/resource');
const {hsTypes} = require('../dns/common');

const ZERO32 = Buffer.alloc(32);
const EMPTY = Buffer.alloc(0);

const domains = {
  RESERVE: Buffer.from('HNSR-RESERVE-V1\0', 'ascii'),
  RENEW: Buffer.from('HNSR-RENEW-V1\0', 'ascii'),
  TICKET_RELAY: Buffer.from('HNSR-RELAY-TICKET-V1\0', 'ascii'),
  TICKET_ENDPOINT: Buffer.from('HNSR-RELAY-CONFIRM-V1\0', 'ascii'),
  DELEGATION: Buffer.from('HNSR-ENDPOINT-DELEGATION-V1\0', 'ascii'),
  ROUTE: Buffer.from('HNSR-ROUTE-RECORD-V1\0', 'ascii'),
  SERVICE_AUTH: Buffer.from('HNSR-SERVICE-AUTH-V1\0', 'ascii'),
  NAMED_ROUTE: Buffer.from('HNSR-NAMED-ROUTE-V1\0', 'ascii'),
  PEER_ROUTE: Buffer.from('HNSR-PEER-ROUTE-V1\0', 'ascii'),
  RENDEZVOUS_NODE: Buffer.from('HNSR-RENDEZVOUS-NODE-V1\0', 'ascii'),
  WITHDRAW: Buffer.from('HNSR-WITHDRAW-V1\0', 'ascii'),
  SAMPLE: Buffer.from('HNSR-SAMPLE-ROUTES-V1\0', 'ascii')
};

const opcodes = {
  FINDNODE: 0,
  NODES: 1,
  PUTROUTE: 2,
  PUTRESULT: 3,
  GETROUTE: 4,
  ROUTES: 5,
  SAMPLEROUTES: 6,
  RESERVE: 7,
  OFFER: 8,
  CONFIRM: 9,
  CONFIRMED: 10,
  RENEW: 11,
  WITHDRAW: 12,
  OPEN: 13,
  INCOMING: 14,
  ACCEPT: 15,
  OPENED: 16,
  DATA: 17,
  WINDOW: 18,
  CLOSE: 19,
  ERROR: 20
};

const errors = {
  NORMAL: 0,
  REFUSED: 1,
  UNSUPPORTED: 2,
  BUSY: 3,
  INVALID: 4,
  NOT_FOUND: 5,
  EXPIRED: 6,
  CAPACITY: 7,
  TIMEOUT: 8,
  PROTOCOL: 9,
  INTERNAL: 10,
  ENDPOINT_GONE: 11,
  AUTH_FAILED: 12,
  FLOW_CONTROL: 13,
  RATE_LIMITED: 14,
  SHUTDOWN: 15,
  PROFILE_DISABLED: 16,
  BYTE_LIMIT: 17
};

const profiles = {
  HNS_NODE_V1: 1,
  HNS_WEB_V1: 2
};

function now() {
  return Math.floor(Date.now() / 1000);
}

function hash(domain, ...items) {
  return blake2b.digest(Buffer.concat([domain, ...items]), 32);
}

function magicBytes(magic) {
  const data = Buffer.allocUnsafe(4);
  data.writeUInt32LE(magic, 0, true);
  return data;
}

function sign(domain, data, key) {
  return secp256k1.signDER(hash(domain, data), key);
}

function verify(domain, data, signature, key) {
  if (!Buffer.isBuffer(signature)
      || signature.length === 0
      || signature.length > common.hnsr.MAX_SIGNATURE_SIZE) {
    return false;
  }

  try {
    return secp256k1.publicKeyVerify(key)
      && secp256k1.isLowDER(signature)
      && secp256k1.verifyDER(hash(domain, data), signature, key);
  } catch (e) {
    return false;
  }
}

function isZero(data) {
  for (const ch of data) {
    if (ch !== 0)
      return false;
  }

  return true;
}

function randomID(size) {
  let id;

  do {
    id = random.randomBytes(size);
  } while (isZero(id));

  return id;
}

function assertU64(value, name) {
  assert(Number.isSafeInteger(value) && value >= 0, `${name} must be a u64.`);
}

function readSignature(br, name) {
  const size = br.readU8();

  if (size > common.hnsr.MAX_SIGNATURE_SIZE)
    throw new Error(`${name} signature exceeds the HNSR limit.`);

  return br.readBytes(size);
}

function writeSignature(bw, signature) {
  assert(Buffer.isBuffer(signature));
  assert(signature.length <= common.hnsr.MAX_SIGNATURE_SIZE);
  bw.writeU8(signature.length);
  bw.writeBytes(signature);
}

function finish(br, name) {
  if (br.left() !== 0)
    throw new Error(`Trailing bytes in ${name}.`);
}

function peerKey(peer, contextID) {
  return `${peer.id}:${contextID.toString('hex')}`;
}

function routeKey(magic, endpointKey) {
  assert(secp256k1.publicKeyVerify(endpointKey));
  return hash(domains.PEER_ROUTE, magicBytes(magic), endpointKey);
}

function validProfile(profile) {
  return profile === profiles.HNS_NODE_V1
    || profile === profiles.HNS_WEB_V1;
}

function canonicalServiceName(name) {
  if (typeof name !== 'string'
      || name.length < 1
      || name.length > 63
      || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(name)) {
    throw new Error('Invalid canonical HNSR service name.');
  }

  return name;
}

function canonicalRootName(name) {
  if (typeof name !== 'string'
      || name !== name.toLowerCase()
      || !rules.verifyString(name)) {
    throw new Error('Invalid canonical HNS root name.');
  }

  return name;
}

function namedRouteKey(magic, nameHash, serviceName, profile) {
  assert((magic >>> 0) === magic);
  assert(Buffer.isBuffer(nameHash) && nameHash.length === 32);
  assert((profile & 0xffff) === profile && validProfile(profile));
  const service = Buffer.from(canonicalServiceName(serviceName), 'ascii');
  return hash(
    domains.NAMED_ROUTE,
    magicBytes(magic),
    nameHash,
    Buffer.from([service.length]),
    service,
    Buffer.from([profile & 0xff, profile >>> 8]));
}

function parseHNSRRootKey(resource) {
  if (!(resource instanceof Resource))
    throw new Error('Authenticated HNS resource is required.');

  const candidates = [];

  for (const record of resource.records) {
    if (record.type !== hsTypes.TXT
        || !Array.isArray(record.txt)
        || record.txt.length !== 1) {
      continue;
    }

    const match = /^hnsr1 k=([a-z2-7]+)$/.exec(record.txt[0]);

    if (!match)
      continue;

    let key;

    try {
      key = base32.decode(match[1]);
    } catch (e) {
      continue;
    }

    if (key.length !== 33
        || base32.encode(key) !== match[1]
        || !secp256k1.publicKeyVerify(key)) {
      continue;
    }

    candidates.push(key);
  }

  if (candidates.length === 0)
    throw new Error('HNS resource has no canonical hnsr1 root key.');

  if (candidates.length !== 1)
    throw new Error('HNS resource has ambiguous hnsr1 root keys.');

  return candidates[0];
}

function parseHNSRURI(uri) {
  if (typeof uri !== 'string' || !uri.startsWith('hnsr://'))
    throw new Error('Invalid HNSR web URI.');

  let parsed;

  try {
    parsed = new URL(uri);
  } catch (e) {
    throw new Error('Invalid HNSR web URI.');
  }

  if (parsed.protocol !== 'hnsr:'
      || parsed.username !== ''
      || parsed.password !== ''
      || parsed.port !== '') {
    throw new Error('Invalid HNSR web URI authority.');
  }

  const rootName = canonicalRootName(parsed.hostname);
  const path = parsed.pathname;
  const slash = path.indexOf('/', 1);
  const rawService = slash === -1
    ? path.slice(1)
    : path.slice(1, slash);
  const serviceName = canonicalServiceName(rawService);
  const requestPath = (slash === -1 ? '/' : path.slice(slash))
    + parsed.search;

  return {
    rootName,
    serviceName,
    path: requestPath,
    fragment: parsed.hash
  };
}

function webOrigin(nameHash, serviceName, profile = profiles.HNS_WEB_V1) {
  assert(Buffer.isBuffer(nameHash) && nameHash.length === 32);
  assert(profile === profiles.HNS_WEB_V1);
  const service = canonicalServiceName(serviceName);
  const name = nameHash.toString('hex');
  return Object.freeze({
    scheme: 'hnsr',
    nameHash: name,
    serviceName: service,
    profile,
    key: `hnsr:${name}:${service}:${profile}`
  });
}

function parseHTTPHead(raw, kind) {
  if (!Buffer.isBuffer(raw)
      || raw.length === 0
      || raw.length > common.hnsr.MAX_WEB_HEADER_SIZE) {
    throw new Error('HNSR web header exceeds the limit.');
  }

  const text = raw.toString('latin1');

  if (text.includes('\0') || /(^|\r\n)[ \t]/.test(text))
    throw new Error('Invalid HNSR web header syntax.');

  const lines = text.split('\r\n');
  const start = lines.shift();
  const headers = new Map();

  for (const line of lines) {
    const colon = line.indexOf(':');

    if (colon < 1)
      throw new Error('Invalid HNSR web header line.');

    const name = line.slice(0, colon).toLowerCase();
    const value = line.slice(colon + 1).trim();

    if (!/^[a-z0-9!#$%&'*+.^_`|~-]+$/.test(name)
        || Array.from(value).some((ch) => {
          const code = ch.charCodeAt(0);
          return code < 0x20 || code === 0x7f;
        })
        || headers.has(name)) {
      throw new Error('Invalid or duplicate HNSR web header.');
    }

    headers.set(name, value);
  }

  if (headers.has('transfer-encoding')
      || headers.has('upgrade')
      || /(?:^|,)\s*upgrade\s*(?:,|$)/i.test(headers.get('connection') || '')) {
    throw new Error('HNSR web transfer coding or upgrade is not permitted.');
  }

  let contentLength = 0;

  if (headers.has('content-length')) {
    const value = headers.get('content-length');

    if (!/^(0|[1-9][0-9]*)$/.test(value))
      throw new Error('Invalid HNSR web Content-Length.');

    contentLength = Number(value);

    if (!Number.isSafeInteger(contentLength)
        || contentLength > common.hnsr.MAX_WEB_BODY_SIZE) {
      throw new Error('HNSR web body exceeds the limit.');
    }
  }

  if (kind === 'request') {
    const match = /^([A-Z]+) ([^ ]+) HTTP\/1\.1$/.exec(start);

    if (!match
        || match[1] === 'CONNECT'
        || match[1] === 'TRACE'
        || !match[2].startsWith('/')
        || /[\0-\x20\x7f]/.test(match[2])) {
      throw new Error('Invalid HNSR web request line.');
    }

    return {method: match[1], path: match[2], headers, contentLength};
  }

  const match = /^HTTP\/1\.1 ([1-5][0-9][0-9]) ([\x20-\x7e]+)$/.exec(start);

  if (!match)
    throw new Error('Invalid HNSR web response line.');

  return {
    statusCode: Number(match[1]),
    reason: match[2],
    headers,
    contentLength
  };
}

class HTTPMessageParser {
  constructor(kind) {
    assert(kind === 'request' || kind === 'response');
    this.kind = kind;
    this.buffer = Buffer.alloc(0);
    this.head = null;
    this.total = 0;
  }

  feed(data) {
    if (!Buffer.isBuffer(data) || data.length === 0)
      throw new Error('Invalid empty HNSR web data.');

    this.total += data.length;

    if (this.total > common.hnsr.MAX_WEB_HEADER_SIZE
        + common.hnsr.MAX_WEB_BODY_SIZE) {
      throw new Error('HNSR web message exceeds the limit.');
    }

    this.buffer = Buffer.concat([this.buffer, data]);
    const messages = [];

    for (;;) {
      if (!this.head) {
        const end = this.buffer.indexOf('\r\n\r\n');

        if (end === -1) {
          if (this.buffer.length > common.hnsr.MAX_WEB_HEADER_SIZE)
            throw new Error('HNSR web header exceeds the limit.');
          break;
        }

        this.head = parseHTTPHead(this.buffer.slice(0, end), this.kind);
        this.buffer = this.buffer.slice(end + 4);
      }

      if (this.buffer.length < this.head.contentLength)
        break;

      const body = this.buffer.slice(0, this.head.contentLength);
      this.buffer = this.buffer.slice(this.head.contentLength);
      messages.push(Object.assign(this.head, {body}));
      this.head = null;
      this.total = this.buffer.length;
    }

    return messages;
  }
}

class HNSRWebSession {
  constructor(circuit, identityKey, endpointKey, origin, record, options = {}) {
    assert(circuit && circuit.socket);
    assert(secp256k1.privateKeyVerify(identityKey));
    assert(secp256k1.publicKeyVerify(endpointKey));

    this.circuit = circuit;
    this.origin = origin;
    this.record = record;
    this.timeout = options.timeout || common.hnsr.INNER_HANDSHAKE_TIMEOUT;
    this.stream = BrontideStream.fromOutbound(
      circuit.socket,
      identityKey,
      endpointKey);
    this.parser = new HTTPMessageParser('response');
    this.pending = [];
    this.requests = 0;
    this.connected = false;
    this.closed = false;
    this.openResolve = null;
    this.openReject = null;
    this.openTimer = null;
    this.opened = new Promise((resolve, reject) => {
      this.openResolve = resolve;
      this.openReject = reject;
    });

    this.onConnect = () => this._handleConnect();
    this.onData = data => this._handleData(data);
    this.onError = error => this._fail(error);
    this.onClose = () => this._fail(
      new Error('HNSR web circuit closed.'));

    this.openTimer = setTimeout(() => {
      this._fail(new Error('HNSR web inner handshake timed out.'));
    }, this.timeout);
    this.stream.once('connect', this.onConnect);
    this.stream.on('data', this.onData);
    this.stream.once('error', this.onError);
    this.circuit.socket.once('error', this.onError);
    this.circuit.socket.once('close', this.onClose);
  }

  async open() {
    await this.opened;
    return this;
  }

  async request(rootName, serviceName, options = {}) {
    await this.open();

    if (this.closed)
      throw new Error('HNSR web session is closed.');

    if (this.requests >= common.hnsr.MAX_WEB_REQUESTS_PER_CIRCUIT)
      throw new Error('HNSR web request limit reached.');

    const request = encodeWebRequest(rootName, serviceName, options);
    const timeout = options.timeout || this.timeout;
    this.requests += 1;

    return new Promise((resolve, reject) => {
      const item = {resolve, reject, timer: null};
      item.timer = setTimeout(() => {
        this._fail(new Error('HNSR web response timed out.'));
      }, timeout);
      this.pending.push(item);

      try {
        this.stream.write(request);
      } catch (e) {
        this._fail(e);
      }
    });
  }

  close() {
    this._fail(new Error('HNSR web session closed.'));
  }

  _handleConnect() {
    if (this.closed)
      return;

    clearTimeout(this.openTimer);
    this.openTimer = null;
    this.connected = true;
    this.openResolve(this);
  }

  _handleData(data) {
    let messages;

    try {
      messages = this.parser.feed(data);
    } catch (e) {
      this._fail(e);
      return;
    }

    for (const message of messages) {
      const item = this.pending.shift();

      if (!item) {
        this._fail(new Error('Unsolicited HNSR web response.'));
        return;
      }

      clearTimeout(item.timer);
      item.resolve({
        statusCode: message.statusCode,
        reason: message.reason,
        headers: Object.fromEntries(message.headers),
        body: message.body,
        origin: this.origin,
        record: this.record,
        circuit: this.circuit
      });
    }
  }

  _fail(error) {
    if (this.closed)
      return;

    this.closed = true;
    clearTimeout(this.openTimer);
    this.openTimer = null;

    this.circuit.socket.removeListener('close', this.onClose);
    this.stream.removeListener('connect', this.onConnect);
    this.stream.removeListener('data', this.onData);
    this.stream.removeListener('error', this.onError);
    this.stream.destroy();
    this.circuit.socket.destroy();

    if (!this.connected)
      this.openReject(error);

    for (const item of this.pending) {
      clearTimeout(item.timer);
      item.reject(error);
    }

    this.pending.length = 0;
  }
}

function headerEntries(headers) {
  if (headers == null)
    return [];

  if (headers instanceof Map)
    return Array.from(headers.entries());

  if (typeof headers === 'object')
    return Object.entries(headers);

  throw new Error('Invalid HNSR web headers.');
}

function encodeHTTPMessage(start, required, headers, body) {
  const lines = [start];
  const seen = new Set();

  for (const [name, value] of required) {
    lines.push(`${name}: ${value}`);
    seen.add(name.toLowerCase());
  }

  for (const [rawName, rawValue] of headerEntries(headers)) {
    const name = String(rawName);
    const lower = name.toLowerCase();
    const value = String(rawValue);

    if (!/^[A-Za-z0-9!#$%&'*+.^_`|~-]+$/.test(name)
        || /[\r\n\0]/.test(value)
        || seen.has(lower)
        || lower === 'transfer-encoding'
        || lower === 'upgrade') {
      throw new Error('Invalid or reserved HNSR web header.');
    }

    lines.push(`${name}: ${value}`);
    seen.add(lower);
  }

  const head = Buffer.from(`${lines.join('\r\n')}\r\n\r\n`, 'latin1');

  if (head.length > common.hnsr.MAX_WEB_HEADER_SIZE)
    throw new Error('HNSR web header exceeds the limit.');

  return Buffer.concat([head, body]);
}

function encodeWebRequest(rootName, serviceName, options = {}) {
  const root = canonicalRootName(rootName);
  const service = canonicalServiceName(serviceName);
  const method = options.method || 'GET';
  const path = options.path || '/';
  const body = Buffer.isBuffer(options.body)
    ? options.body
    : Buffer.from(options.body || '');

  if (!/^[A-Z]+$/.test(method)
      || method === 'CONNECT'
      || method === 'TRACE'
      || typeof path !== 'string'
      || !path.startsWith('/')
      || /[\0-\x20\x7f]/.test(path)
      || body.length > common.hnsr.MAX_WEB_BODY_SIZE) {
    throw new Error('Invalid HNSR web request.');
  }

  return encodeHTTPMessage(
    `${method} ${path} HTTP/1.1`,
    [
      ['Host', `${service}.${root}`],
      ['HNSR-Authority', root],
      ['HNSR-Service', service],
      ['Content-Length', body.length]
    ],
    options.headers,
    body);
}

function encodeWebResponse(response = {}) {
  const statusCode = response.statusCode || 200;
  const reason = response.reason || (statusCode === 200 ? 'OK' : 'Response');
  const body = Buffer.isBuffer(response.body)
    ? response.body
    : Buffer.from(response.body || '');

  if (!Number.isSafeInteger(statusCode)
      || statusCode < 100
      || statusCode > 599
      || !/^[\x20-\x7e]+$/.test(reason)
      || body.length > common.hnsr.MAX_WEB_BODY_SIZE) {
    throw new Error('Invalid HNSR web response.');
  }

  return encodeHTTPMessage(
    `HTTP/1.1 ${statusCode} ${reason}`,
    [['Content-Length', body.length]],
    response.headers,
    body);
}

function withdrawData(magic, relayKey, contextID, reservationID, ticketID) {
  assert(secp256k1.publicKeyVerify(relayKey));
  assert(contextID.length === 8);
  assert(reservationID.length === 16);
  assert(ticketID.length === 32);
  return Buffer.concat([
    magicBytes(magic),
    relayKey,
    contextID,
    reservationID,
    ticketID
  ]);
}

function rendezvousNodeID(magic, peerKey) {
  assert(secp256k1.publicKeyVerify(peerKey));
  return hash(domains.RENDEZVOUS_NODE, magicBytes(magic), peerKey);
}

function compareDistance(a, b, target) {
  assert(a.length === 32 && b.length === 32 && target.length === 32);

  for (let i = 0; i < 32; i++) {
    const left = a[i] ^ target[i];
    const right = b[i] ^ target[i];

    if (left !== right)
      return left - right;
  }

  return 0;
}

function bucketIndex(selfID, nodeID) {
  assert(Buffer.isBuffer(selfID) && selfID.length === 32);
  assert(Buffer.isBuffer(nodeID) && nodeID.length === 32);

  for (let index = 0; index < 32; index++) {
    const distance = selfID[index] ^ nodeID[index];

    if (distance === 0)
      continue;

    let bit = 0;

    while ((distance & (0x80 >>> bit)) === 0)
      bit += 1;

    return index * 8 + bit;
  }

  return -1;
}

function addressPrefix(raw) {
  assert(Buffer.isBuffer(raw) && raw.length === 16);

  if (IP.isIPv4(raw))
    return `4:${raw.slice(12, 15).toString('hex')}`;

  if (IP.isOnion(raw))
    return `o:${raw.slice(0, 6).toString('hex')}`;

  return `6:${raw.slice(0, 6).toString('hex')}`;
}

function peerAddressPrefix(peer) {
  if (!peer || !peer.address || !Buffer.isBuffer(peer.address.raw))
    return 'unknown';

  return addressPrefix(peer.address.raw);
}

function peerIPAddress(peer) {
  if (!peer || !peer.address || !Buffer.isBuffer(peer.address.raw))
    return 'unknown';

  return peer.address.raw.toString('hex');
}

function peerNetgroup(peer) {
  if (!peer || !peer.address || typeof peer.address.getGroup !== 'function')
    return 'unknown';

  return peer.address.getGroup().toString('hex');
}

function selectDiverseNodes(nodes, maximum, network) {
  assert(Array.isArray(nodes));
  assert(Number.isSafeInteger(maximum) && maximum >= 1);

  const selected = [];
  const deferred = [];
  const groups = new Set();

  for (const item of nodes) {
    const group = item.contact.toAddress(network)
      .getGroup()
      .toString('hex');

    if (groups.has(group)) {
      deferred.push(item);
      continue;
    }

    groups.add(group);
    selected.push(item);

    if (selected.length === maximum)
      return selected;
  }

  for (const item of deferred) {
    selected.push(item);

    if (selected.length === maximum)
      break;
  }

  return selected;
}

function peerPublicKey(peer) {
  if (peer && peer.address && secp256k1.publicKeyVerify(peer.address.key))
    return peer.address.key;

  if (peer && peer.brontide
      && secp256k1.publicKeyVerify(peer.brontide.remoteStatic)) {
    return peer.brontide.remoteStatic;
  }

  return null;
}

class RendezvousContact {
  constructor(options = {}) {
    this.nodeID = options.nodeID || Buffer.alloc(32);
    this.hostType = options.hostType || 1;
    this.host = options.host || Buffer.alloc(16);
    this.port = options.port || 0;
    this.services = options.services || 0;
    this.peerKey = options.peerKey || Buffer.alloc(33);
    this.observedAt = options.observedAt || 0;
  }

  verify(magic, timestamp = now()) {
    if (!Buffer.isBuffer(this.nodeID)
        || this.nodeID.length !== 32
        || (this.hostType !== 1 && this.hostType !== 2)
        || !Buffer.isBuffer(this.host)
        || this.host.length !== 16
        || this.port === 0
        || !Number.isSafeInteger(this.services)
        || this.services < 0
        || (this.services
          & common.EXPERIMENTAL_HNSR_RENDEZVOUS_SERVICE) === 0
        || !secp256k1.publicKeyVerify(this.peerKey)
        || !Number.isSafeInteger(this.observedAt)
        || this.observedAt > timestamp + 600
        || timestamp - this.observedAt > 86400) {
      return false;
    }

    return this.nodeID.equals(rendezvousNodeID(magic, this.peerKey));
  }

  encode() {
    assert(this.nodeID.length === 32);
    assert((this.hostType & 0xff) === this.hostType);
    assert(this.host.length === 16);
    assert((this.port & 0xffff) === this.port);
    assertU64(this.services, 'rendezvous services');
    assert(secp256k1.publicKeyVerify(this.peerKey));
    assertU64(this.observedAt, 'observedAt');

    const bw = bio.write(100);
    bw.writeBytes(this.nodeID);
    bw.writeU8(this.hostType);
    bw.writeBytes(this.host);
    bw.writeU16(this.port);
    bw.writeU64(this.services);
    bw.writeBytes(this.peerKey);
    bw.writeU64(this.observedAt);
    return bw.render();
  }

  toAddress(network) {
    const address = NetAddress.fromHost(
      IP.toString(this.host),
      this.port,
      this.peerKey,
      network);
    address.services = this.services;
    address.time = this.observedAt;
    return address;
  }

  static read(br) {
    const contact = new RendezvousContact();
    contact.nodeID = br.readBytes(32);
    contact.hostType = br.readU8();
    contact.host = br.readBytes(16);
    contact.port = br.readU16();
    contact.services = br.readU64();
    contact.peerKey = br.readBytes(33);
    contact.observedAt = br.readU64();
    return contact;
  }

  static decode(data) {
    const br = bio.read(data);
    const contact = RendezvousContact.read(br);
    finish(br, 'HNSR rendezvous contact');
    return contact;
  }
}

class ReserveRequest {
  constructor(options = {}) {
    this.endpointKey = options.endpointKey || Buffer.alloc(33);
    this.profile = options.profile || profiles.HNS_NODE_V1;
    this.lifetime = options.lifetime || 1800;
    this.maxCircuits = options.maxCircuits || 8;
    this.maxBytes = options.maxBytes || 1048576;
    this.nonce = options.nonce || Buffer.alloc(16);
    this.signature = options.signature || EMPTY;
  }

  encodeUnsigned() {
    assert(secp256k1.publicKeyVerify(this.endpointKey));
    assert((this.profile & 0xffff) === this.profile);
    assert((this.lifetime >>> 0) === this.lifetime);
    assert((this.maxCircuits & 0xffff) === this.maxCircuits);
    assertU64(this.maxBytes, 'maxBytes');
    assert(this.nonce.length === 16);

    const bw = bio.write(65);
    bw.writeBytes(this.endpointKey);
    bw.writeU16(this.profile);
    bw.writeU32(this.lifetime);
    bw.writeU16(this.maxCircuits);
    bw.writeU64(this.maxBytes);
    bw.writeBytes(this.nonce);
    return bw.render();
  }

  signatureData(magic, relayKey, contextID) {
    assert(contextID.length === 8);
    return Buffer.concat([
      magicBytes(magic),
      relayKey,
      contextID,
      this.encodeUnsigned()
    ]);
  }

  sign(magic, relayKey, contextID, privateKey) {
    this.signature = sign(
      domains.RESERVE,
      this.signatureData(magic, relayKey, contextID),
      privateKey);
    return this;
  }

  verify(magic, relayKey, contextID) {
    return verify(
      domains.RESERVE,
      this.signatureData(magic, relayKey, contextID),
      this.signature,
      this.endpointKey);
  }

  renewalData(magic, relayKey, contextID, reservationID) {
    assert(Buffer.isBuffer(reservationID) && reservationID.length === 16);
    return Buffer.concat([
      magicBytes(magic),
      relayKey,
      contextID,
      reservationID,
      this.encodeUnsigned()
    ]);
  }

  signRenewal(magic, relayKey, contextID, reservationID, privateKey) {
    this.signature = sign(
      domains.RENEW,
      this.renewalData(magic, relayKey, contextID, reservationID),
      privateKey);
    return this;
  }

  verifyRenewal(magic, relayKey, contextID, reservationID) {
    return verify(
      domains.RENEW,
      this.renewalData(magic, relayKey, contextID, reservationID),
      this.signature,
      this.endpointKey);
  }

  encode() {
    const unsigned = this.encodeUnsigned();
    const bw = bio.write(unsigned.length + 1 + this.signature.length);
    bw.writeBytes(unsigned);
    writeSignature(bw, this.signature);
    return bw.render();
  }

  static decode(data) {
    const br = bio.read(data);
    const request = new ReserveRequest();
    request.endpointKey = br.readBytes(33);
    request.profile = br.readU16();
    request.lifetime = br.readU32();
    request.maxCircuits = br.readU16();
    request.maxBytes = br.readU64();
    request.nonce = br.readBytes(16);
    request.signature = readSignature(br, 'reserve');
    finish(br, 'reserve request');
    request.encodeUnsigned();
    return request;
  }
}

class RelayTicket {
  constructor(options = {}) {
    this.version = 1;
    this.networkMagic = options.networkMagic || 0;
    this.profile = options.profile || profiles.HNS_NODE_V1;
    this.transport = options.transport || 0;
    this.hostType = options.hostType || 1;
    this.host = options.host || Buffer.alloc(16);
    this.port = options.port || 0;
    this.relayKey = options.relayKey || Buffer.alloc(33);
    this.endpointKey = options.endpointKey || Buffer.alloc(33);
    this.reservationID = options.reservationID || Buffer.alloc(16);
    this.issuedAt = options.issuedAt || 0;
    this.expiresAt = options.expiresAt || 0;
    this.maxActiveCircuits = options.maxActiveCircuits || 0;
    this.maxBytesPerCircuit = options.maxBytesPerCircuit || 0;
    this.maxTotalBytes = options.maxTotalBytes || 0;
    this.flags = options.flags || 0;
    this.relaySignature = options.relaySignature || EMPTY;
    this.endpointSignature = options.endpointSignature || EMPTY;
  }

  encodeUnsigned() {
    assert(this.version === 1);
    assert((this.networkMagic >>> 0) === this.networkMagic);
    assert((this.profile & 0xffff) === this.profile);
    assert((this.transport & 0xff) === this.transport);
    assert((this.hostType & 0xff) === this.hostType);
    assert(Buffer.isBuffer(this.host) && this.host.length === 16);
    assert((this.port & 0xffff) === this.port);
    assert(secp256k1.publicKeyVerify(this.relayKey));
    assert(secp256k1.publicKeyVerify(this.endpointKey));
    assert(this.reservationID.length === 16 && !isZero(this.reservationID));
    assertU64(this.issuedAt, 'issuedAt');
    assertU64(this.expiresAt, 'expiresAt');
    assert((this.maxActiveCircuits & 0xffff) === this.maxActiveCircuits);
    assertU64(this.maxBytesPerCircuit, 'maxBytesPerCircuit');
    assertU64(this.maxTotalBytes, 'maxTotalBytes');
    assert((this.flags & 0xffff) === this.flags);

    const bw = bio.write(145);
    bw.writeU8(this.version);
    bw.writeU32(this.networkMagic);
    bw.writeU16(this.profile);
    bw.writeU8(this.transport);
    bw.writeU8(this.hostType);
    bw.writeBytes(this.host);
    bw.writeU16(this.port);
    bw.writeBytes(this.relayKey);
    bw.writeBytes(this.endpointKey);
    bw.writeBytes(this.reservationID);
    bw.writeU64(this.issuedAt);
    bw.writeU64(this.expiresAt);
    bw.writeU16(this.maxActiveCircuits);
    bw.writeU64(this.maxBytesPerCircuit);
    bw.writeU64(this.maxTotalBytes);
    bw.writeU16(this.flags);
    return bw.render();
  }

  signRelay(privateKey) {
    this.relaySignature = sign(
      domains.TICKET_RELAY,
      this.encodeUnsigned(),
      privateKey);
    return this;
  }

  verifyRelay() {
    return verify(
      domains.TICKET_RELAY,
      this.encodeUnsigned(),
      this.relaySignature,
      this.relayKey);
  }

  endpointData() {
    return Buffer.concat([this.encodeUnsigned(), this.relaySignature]);
  }

  signEndpoint(privateKey) {
    assert(this.verifyRelay());
    this.endpointSignature = sign(
      domains.TICKET_ENDPOINT,
      this.endpointData(),
      privateKey);
    return this;
  }

  verifyEndpoint() {
    return verify(
      domains.TICKET_ENDPOINT,
      this.endpointData(),
      this.endpointSignature,
      this.endpointKey);
  }

  verify(magic, timestamp = now()) {
    if (this.networkMagic !== magic
        || !validProfile(this.profile)
        || this.transport !== 0
        || (this.hostType !== 1 && this.hostType !== 2)
        || this.port === 0
        || this.flags !== 0
        || this.relayKey.equals(this.endpointKey)
        || this.maxActiveCircuits < 1
        || this.maxActiveCircuits > common.hnsr.MAX_CIRCUITS
        || this.maxBytesPerCircuit < 1
        || this.maxTotalBytes < this.maxBytesPerCircuit
        || this.expiresAt <= this.issuedAt
        || this.expiresAt - this.issuedAt > common.hnsr.MAX_TICKET_LIFETIME
        || timestamp < this.issuedAt
        || timestamp >= this.expiresAt) {
      return false;
    }

    return this.verifyRelay() && this.verifyEndpoint();
  }

  id() {
    return blake2b.digest(this.encode(), 32);
  }

  encode() {
    const unsigned = this.encodeUnsigned();
    const size = unsigned.length + 2
      + this.relaySignature.length
      + this.endpointSignature.length;
    const bw = bio.write(size);
    bw.writeBytes(unsigned);
    writeSignature(bw, this.relaySignature);
    writeSignature(bw, this.endpointSignature);
    return bw.render();
  }

  static read(br) {
    const ticket = new RelayTicket();
    ticket.version = br.readU8();
    ticket.networkMagic = br.readU32();
    ticket.profile = br.readU16();
    ticket.transport = br.readU8();
    ticket.hostType = br.readU8();
    ticket.host = br.readBytes(16);
    ticket.port = br.readU16();
    ticket.relayKey = br.readBytes(33);
    ticket.endpointKey = br.readBytes(33);
    ticket.reservationID = br.readBytes(16);
    ticket.issuedAt = br.readU64();
    ticket.expiresAt = br.readU64();
    ticket.maxActiveCircuits = br.readU16();
    ticket.maxBytesPerCircuit = br.readU64();
    ticket.maxTotalBytes = br.readU64();
    ticket.flags = br.readU16();
    ticket.relaySignature = readSignature(br, 'relay ticket');
    ticket.endpointSignature = readSignature(br, 'endpoint ticket');
    ticket.encodeUnsigned();
    return ticket;
  }

  static decode(data) {
    const br = bio.read(data);
    const ticket = RelayTicket.read(br);
    finish(br, 'relay ticket');
    return ticket;
  }
}

class ServiceAuthorization {
  constructor(options = {}) {
    this.version = 1;
    this.networkMagic = options.networkMagic || 0;
    this.nameHash = options.nameHash || Buffer.alloc(32);
    this.serviceName = options.serviceName || '';
    this.profile = options.profile || profiles.HNS_WEB_V1;
    this.serviceKey = options.serviceKey || Buffer.alloc(33);
    this.flags = options.flags || 0;
    this.serial = options.serial || 1;
    this.validFromHeight = options.validFromHeight || 0;
    this.validUntilHeight = options.validUntilHeight || 0;
    this.maxEndpointLifetime = options.maxEndpointLifetime || 3600;
    this.maxRouteLifetime = options.maxRouteLifetime || 900;
    this.rootSignature = options.rootSignature || EMPTY;
  }

  encodeUnsigned() {
    assert(this.version === 1);
    assert((this.networkMagic >>> 0) === this.networkMagic);
    assert(Buffer.isBuffer(this.nameHash) && this.nameHash.length === 32);
    const service = Buffer.from(
      canonicalServiceName(this.serviceName),
      'ascii');
    assert((this.profile & 0xffff) === this.profile
      && validProfile(this.profile));
    assert(secp256k1.publicKeyVerify(this.serviceKey));
    assert((this.flags & 0xffff) === this.flags);
    assertU64(this.serial, 'service authorization serial');
    assert((this.validFromHeight >>> 0) === this.validFromHeight);
    assert((this.validUntilHeight >>> 0) === this.validUntilHeight);
    assert((this.maxEndpointLifetime >>> 0) === this.maxEndpointLifetime);
    assert((this.maxRouteLifetime >>> 0) === this.maxRouteLifetime);

    const bw = bio.write(99 + service.length);
    bw.writeU8(this.version);
    bw.writeU32(this.networkMagic);
    bw.writeBytes(this.nameHash);
    bw.writeU8(service.length);
    bw.writeBytes(service);
    bw.writeU16(this.profile);
    bw.writeBytes(this.serviceKey);
    bw.writeU16(this.flags);
    bw.writeU64(this.serial);
    bw.writeU32(this.validFromHeight);
    bw.writeU32(this.validUntilHeight);
    bw.writeU32(this.maxEndpointLifetime);
    bw.writeU32(this.maxRouteLifetime);
    return bw.render();
  }

  signatureData(magic) {
    return Buffer.concat([magicBytes(magic), this.encodeUnsigned()]);
  }

  sign(magic, rootPrivateKey) {
    this.rootSignature = sign(
      domains.SERVICE_AUTH,
      this.signatureData(magic),
      rootPrivateKey);
    return this;
  }

  validate(magic, height = null) {
    if (this.version !== 1
        || this.networkMagic !== magic
        || !Buffer.isBuffer(this.nameHash)
        || this.nameHash.length !== 32
        || !validProfile(this.profile)
        || !secp256k1.publicKeyVerify(this.serviceKey)
        || this.flags !== 0
        || this.serial < 1
        || (this.validUntilHeight !== 0
          && this.validUntilHeight < this.validFromHeight)
        || this.maxEndpointLifetime < 300
        || this.maxEndpointLifetime > 604800
        || this.maxRouteLifetime < 60
        || this.maxRouteLifetime > common.hnsr.MAX_ROUTE_LIFETIME
        || !Buffer.isBuffer(this.rootSignature)
        || this.rootSignature.length === 0
        || this.rootSignature.length > common.hnsr.MAX_SIGNATURE_SIZE) {
      return false;
    }

    try {
      canonicalServiceName(this.serviceName);

      if (!secp256k1.isLowDER(this.rootSignature))
        return false;
    } catch (e) {
      return false;
    }

    if (height != null) {
      if (!Number.isSafeInteger(height)
          || height < this.validFromHeight
          || (this.validUntilHeight !== 0
            && height > this.validUntilHeight)) {
        return false;
      }
    }

    return true;
  }

  verify(rootKey, magic, height) {
    return this.validate(magic, height)
      && verify(
        domains.SERVICE_AUTH,
        this.signatureData(magic),
        this.rootSignature,
        rootKey);
  }

  id() {
    return blake2b.digest(this.encode(), 32);
  }

  encode() {
    const unsigned = this.encodeUnsigned();
    const bw = bio.write(unsigned.length + 1 + this.rootSignature.length);
    bw.writeBytes(unsigned);
    writeSignature(bw, this.rootSignature);
    return bw.render();
  }

  static decode(data) {
    const br = bio.read(data);
    const authorization = new ServiceAuthorization();
    authorization.version = br.readU8();
    authorization.networkMagic = br.readU32();
    authorization.nameHash = br.readBytes(32);
    const serviceSize = br.readU8();
    authorization.serviceName = br.readString(serviceSize, 'ascii');
    authorization.profile = br.readU16();
    authorization.serviceKey = br.readBytes(33);
    authorization.flags = br.readU16();
    authorization.serial = br.readU64();
    authorization.validFromHeight = br.readU32();
    authorization.validUntilHeight = br.readU32();
    authorization.maxEndpointLifetime = br.readU32();
    authorization.maxRouteLifetime = br.readU32();
    authorization.rootSignature = readSignature(br, 'service authorization');
    finish(br, 'service authorization');
    authorization.encodeUnsigned();
    return authorization;
  }
}

class EndpointDelegation {
  constructor(options = {}) {
    this.version = 1;
    this.authorizationID = options.authorizationID || ZERO32;
    this.endpointKey = options.endpointKey || Buffer.alloc(33);
    this.sequence = options.sequence || 1;
    this.issuedAt = options.issuedAt || 0;
    this.expiresAt = options.expiresAt || 0;
    this.maxActiveCircuits = options.maxActiveCircuits || 8;
    this.maxBytesPerCircuit = options.maxBytesPerCircuit || 1048576;
    this.flags = options.flags || 0;
    this.signature = options.signature || EMPTY;
  }

  encodeUnsigned() {
    assert(this.version === 1);
    assert(this.authorizationID.length === 32);
    assert(secp256k1.publicKeyVerify(this.endpointKey));
    assertU64(this.sequence, 'endpoint sequence');
    assertU64(this.issuedAt, 'issuedAt');
    assertU64(this.expiresAt, 'expiresAt');
    assert((this.maxActiveCircuits & 0xffff) === this.maxActiveCircuits);
    assertU64(this.maxBytesPerCircuit, 'maxBytesPerCircuit');
    assert((this.flags & 0xffff) === this.flags);

    const bw = bio.write(102);
    bw.writeU8(this.version);
    bw.writeBytes(this.authorizationID);
    bw.writeBytes(this.endpointKey);
    bw.writeU64(this.sequence);
    bw.writeU64(this.issuedAt);
    bw.writeU64(this.expiresAt);
    bw.writeU16(this.maxActiveCircuits);
    bw.writeU64(this.maxBytesPerCircuit);
    bw.writeU16(this.flags);
    return bw.render();
  }

  sign(magic, privateKey) {
    this.signature = sign(
      domains.DELEGATION,
      Buffer.concat([magicBytes(magic), this.encodeUnsigned()]),
      privateKey);
    return this;
  }

  verify(magic, timestamp = now(), authorization = null) {
    if (this.sequence < 1
        || this.expiresAt <= this.issuedAt
        || timestamp < this.issuedAt
        || timestamp >= this.expiresAt
        || this.maxActiveCircuits < 1
        || this.maxActiveCircuits > common.hnsr.MAX_CIRCUITS
        || this.maxBytesPerCircuit < 1
        || this.flags !== 0) {
      return false;
    }

    let signer = this.endpointKey;
    let maximumLifetime = 604800;

    if (isZero(this.authorizationID)) {
      if (authorization)
        return false;
    } else {
      if (!(authorization instanceof ServiceAuthorization)
          || !this.authorizationID.equals(authorization.id())) {
        return false;
      }

      signer = authorization.serviceKey;
      maximumLifetime = authorization.maxEndpointLifetime;
    }

    if (this.expiresAt - this.issuedAt > maximumLifetime)
      return false;

    return verify(
      domains.DELEGATION,
      Buffer.concat([magicBytes(magic), this.encodeUnsigned()]),
      this.signature,
      signer);
  }

  encode() {
    const unsigned = this.encodeUnsigned();
    const bw = bio.write(unsigned.length + 1 + this.signature.length);
    bw.writeBytes(unsigned);
    writeSignature(bw, this.signature);
    return bw.render();
  }

  static decode(data) {
    const br = bio.read(data);
    const delegation = new EndpointDelegation();
    delegation.version = br.readU8();
    delegation.authorizationID = br.readBytes(32);
    delegation.endpointKey = br.readBytes(33);
    delegation.sequence = br.readU64();
    delegation.issuedAt = br.readU64();
    delegation.expiresAt = br.readU64();
    delegation.maxActiveCircuits = br.readU16();
    delegation.maxBytesPerCircuit = br.readU64();
    delegation.flags = br.readU16();
    delegation.signature = readSignature(br, 'endpoint delegation');
    finish(br, 'endpoint delegation');
    delegation.encodeUnsigned();
    return delegation;
  }
}

class RouteRecord {
  constructor(options = {}) {
    this.version = 1;
    this.authorityType = options.authorityType || 0;
    this.routeKey = options.routeKey || Buffer.alloc(32);
    this.profile = options.profile || profiles.HNS_NODE_V1;
    this.sequence = options.sequence || 1;
    this.issuedAt = options.issuedAt || 0;
    this.expiresAt = options.expiresAt || 0;
    this.authorization = options.authorization || EMPTY;
    this.delegation = options.delegation || new EndpointDelegation();
    this.tickets = options.tickets || [];
    this.endpointSignature = options.endpointSignature || EMPTY;
  }

  encodeUnsigned() {
    assert(this.version === 1);
    assert(this.authorityType === 0 || this.authorityType === 1);
    assert(this.routeKey.length === 32);
    assert(validProfile(this.profile));
    assertU64(this.sequence, 'record sequence');
    assertU64(this.issuedAt, 'issuedAt');
    assertU64(this.expiresAt, 'expiresAt');
    assert(Buffer.isBuffer(this.authorization));

    if (this.authorityType === 0)
      assert(this.authorization.length === 0);
    else
      assert(this.authorization.length > 0);

    assert(this.tickets.length >= 1 && this.tickets.length <= 8);

    const delegation = this.delegation.encode();
    const encodedTickets = this.tickets.map(ticket => ticket.encode());
    let size = 65 + this.authorization.length + delegation.length;

    for (const ticket of encodedTickets)
      size += ticket.length;

    const bw = bio.write(size);
    bw.writeU8(this.version);
    bw.writeU8(this.authorityType);
    bw.writeBytes(this.routeKey);
    bw.writeU16(this.profile);
    bw.writeU64(this.sequence);
    bw.writeU64(this.issuedAt);
    bw.writeU64(this.expiresAt);
    bw.writeU16(this.authorization.length);
    bw.writeBytes(this.authorization);
    bw.writeU16(delegation.length);
    bw.writeBytes(delegation);
    bw.writeU8(encodedTickets.length);

    for (const ticket of encodedTickets)
      bw.writeBytes(ticket);

    return bw.render();
  }

  sign(privateKey) {
    this.endpointSignature = sign(
      domains.ROUTE,
      this.encodeUnsigned(),
      privateKey);
    return this;
  }

  verify(magic, timestamp = now(), options = {}) {
    if (this.version !== 1
        || (this.authorityType !== 0 && this.authorityType !== 1)
        || !validProfile(this.profile)
        || this.sequence < 1
        || this.expiresAt <= this.issuedAt
        || this.expiresAt - this.issuedAt > common.hnsr.MAX_ROUTE_LIFETIME
        || timestamp < this.issuedAt
        || timestamp >= this.expiresAt
        || this.tickets.length < 1
        || this.tickets.length > 8
        || this.delegation.expiresAt < this.expiresAt) {
      return false;
    }

    let authorization = null;
    let maximumLifetime = common.hnsr.MAX_ROUTE_LIFETIME;

    if (this.authorityType === 0) {
      if (this.profile !== profiles.HNS_NODE_V1
          || this.authorization.length !== 0
          || !this.routeKey.equals(
            routeKey(magic, this.delegation.endpointKey))
          || !this.delegation.verify(magic, timestamp)) {
        return false;
      }
    } else {
      try {
        authorization = ServiceAuthorization.decode(this.authorization);
      } catch (e) {
        return false;
      }

      const height = options.height != null ? options.height : null;

      if (!authorization.validate(magic, height)
          || (options.rootKey
            && !authorization.verify(options.rootKey, magic, height))
          || authorization.profile !== this.profile
          || !this.routeKey.equals(namedRouteKey(
            magic,
            authorization.nameHash,
            authorization.serviceName,
            authorization.profile))
          || !this.delegation.verify(magic, timestamp, authorization)) {
        return false;
      }

      maximumLifetime = authorization.maxRouteLifetime;
    }

    if (this.expiresAt - this.issuedAt > maximumLifetime)
      return false;

    for (const ticket of this.tickets) {
      if (!ticket.endpointKey.equals(this.delegation.endpointKey)
          || ticket.profile !== this.profile
          || ticket.expiresAt < this.expiresAt
          || !ticket.verify(magic, timestamp)) {
        return false;
      }
    }

    return verify(
      domains.ROUTE,
      this.encodeUnsigned(),
      this.endpointSignature,
      this.delegation.endpointKey);
  }

  encode() {
    const unsigned = this.encodeUnsigned();
    const bw = bio.write(unsigned.length + 1 + this.endpointSignature.length);
    bw.writeBytes(unsigned);
    writeSignature(bw, this.endpointSignature);
    return bw.render();
  }

  static decode(data) {
    if (data.length === 0 || data.length > common.hnsr.MAX_RECORD_SIZE)
      throw new Error('Route record exceeds the HNSR limit.');

    const br = bio.read(data);
    const record = new RouteRecord();
    record.version = br.readU8();
    record.authorityType = br.readU8();
    record.routeKey = br.readBytes(32);
    record.profile = br.readU16();
    record.sequence = br.readU64();
    record.issuedAt = br.readU64();
    record.expiresAt = br.readU64();
    const authSize = br.readU16();
    record.authorization = br.readBytes(authSize);
    const delegationSize = br.readU16();
    record.delegation = EndpointDelegation.decode(br.readBytes(delegationSize));
    const count = br.readU8();

    if (count < 1 || count > 8)
      throw new Error('Invalid HNSR route ticket count.');

    record.tickets = [];

    for (let i = 0; i < count; i++)
      record.tickets.push(RelayTicket.read(br));

    record.endpointSignature = readSignature(br, 'route record');
    finish(br, 'route record');
    record.encodeUnsigned();
    return record;
  }
}

class RoutingTable {
  constructor(magic, selfID, network, options = {}) {
    assert((magic >>> 0) === magic);
    assert(Buffer.isBuffer(selfID) && selfID.length === 32);
    assert(network);

    this.magic = magic;
    this.selfID = Buffer.from(selfID);
    this.network = network;
    this.allowLocal = options.allowLocal === true;
    this.bucketSize = options.bucketSize
      || common.hnsr.ROUTING_BUCKET_SIZE;
    this.maxEntries = options.maxEntries
      || common.hnsr.MAX_ROUTING_CONTACTS;
    this.maxPerNetgroup = options.maxPerNetgroup
      || common.hnsr.MAX_ROUTING_PER_NETGROUP;
    this.onChange = typeof options.onChange === 'function'
      ? options.onChange
      : null;
    this.contacts = new Map();
    this.metadata = new Map();
    this.buckets = Array.from({length: 256}, () => []);
  }

  add(contact, timestamp = now(), connected = false) {
    if (!(contact instanceof RendezvousContact)
        || !this._admissible(contact, timestamp)
        || contact.nodeID.equals(this.selfID)) {
      return false;
    }

    this.prune(timestamp);

    const key = contact.peerKey.toString('hex');
    const bucket = bucketIndex(this.selfID, contact.nodeID);

    if (bucket < 0)
      return false;

    const keys = this.buckets[bucket];
    const existing = this.contacts.get(key);

    if (existing) {
      if (contact.observedAt >= existing.observedAt)
        this.contacts.set(key, this._cloneContact(contact));

      const index = keys.indexOf(key);

      if (index !== -1) {
        keys.splice(index, 1);
        keys.push(key);
      }

      const meta = this.metadata.get(key);
      meta.lastSeen = Math.max(meta.lastSeen, contact.observedAt);
      meta.failures = connected ? 0 : meta.failures;
      meta.connected = connected || meta.connected;
      this._changed();
      return true;
    }

    const group = this._netgroup(contact);
    let groupCount = 0;

    for (const known of keys) {
      const item = this.contacts.get(known);

      if (item && this._netgroup(item) === group)
        groupCount += 1;
    }

    if (groupCount >= this.maxPerNetgroup)
      return false;

    if (keys.length >= this.bucketSize) {
      const evicted = keys.find((known) => {
        const meta = this.metadata.get(known);
        return meta && meta.failures >= 3;
      });

      if (!evicted)
        return false;

      this.remove(evicted);
    }

    if (this.contacts.size >= this.maxEntries) {
      const evicted = this._oldestFailed();

      if (!evicted)
        return false;

      this.remove(evicted);
    }

    this.contacts.set(key, this._cloneContact(contact));
    this.metadata.set(key, {
      bucket,
      netgroup: group,
      prefix: addressPrefix(contact.host),
      lastSeen: contact.observedAt,
      lastAttempt: 0,
      failures: 0,
      connected
    });
    keys.push(key);
    this._changed();
    return true;
  }

  remove(key) {
    if (Buffer.isBuffer(key))
      key = key.toString('hex');

    const meta = this.metadata.get(key);

    if (!meta)
      return false;

    const keys = this.buckets[meta.bucket];
    const index = keys.indexOf(key);

    if (index !== -1)
      keys.splice(index, 1);

    this.contacts.delete(key);
    this.metadata.delete(key);
    this._changed();
    return true;
  }

  markAttempt(peerKey, success, timestamp = now()) {
    const key = Buffer.isBuffer(peerKey)
      ? peerKey.toString('hex')
      : peerKey;
    const meta = this.metadata.get(key);

    if (!meta)
      return false;

    meta.lastAttempt = timestamp;
    meta.connected = success;

    if (success) {
      meta.lastSeen = timestamp;
      meta.failures = 0;
    } else {
      meta.failures += 1;

      if (meta.failures >= 3) {
        this.remove(key);
        return true;
      }
    }

    this._changed();
    return true;
  }

  closest(target, maximum, timestamp = now()) {
    assert(Buffer.isBuffer(target) && target.length === 32);
    assert(Number.isSafeInteger(maximum) && maximum >= 1);
    this.prune(timestamp);

    return Array.from(this.contacts.values())
      .filter(contact => this.isAdmissible(contact, timestamp))
      .sort((a, b) => compareDistance(a.nodeID, b.nodeID, target))
      .slice(0, maximum);
  }

  prune(timestamp = now()) {
    for (const [key, contact] of Array.from(this.contacts)) {
      if (!this.isAdmissible(contact, timestamp))
        this.remove(key);
    }
  }

  isAdmissible(contact, timestamp = now()) {
    return this._admissible(contact, timestamp);
  }

  toJSON(timestamp = now()) {
    this.prune(timestamp);

    const entries = [];

    for (const [key, contact] of this.contacts) {
      const meta = this.metadata.get(key);
      entries.push({
        contact: contact.encode().toString('hex'),
        lastSeen: meta.lastSeen,
        lastAttempt: meta.lastAttempt,
        failures: meta.failures
      });
    }

    return entries;
  }

  fromJSON(entries, timestamp = now()) {
    if (!Array.isArray(entries))
      throw new Error('Invalid HNSR routing-table state.');

    for (const item of entries) {
      if (!item || typeof item.contact !== 'string')
        continue;

      try {
        const contact = RendezvousContact.decode(
          Buffer.from(item.contact, 'hex'));

        if (!this.add(contact, timestamp, false))
          continue;

        const key = contact.peerKey.toString('hex');
        const meta = this.metadata.get(key);

        if (Number.isSafeInteger(item.lastSeen))
          meta.lastSeen = item.lastSeen;

        if (Number.isSafeInteger(item.lastAttempt))
          meta.lastAttempt = item.lastAttempt;

        if (Number.isSafeInteger(item.failures)
            && item.failures >= 0
            && item.failures < 3) {
          meta.failures = item.failures;
        }
      } catch (e) {
        continue;
      }
    }
  }

  _admissible(contact, timestamp) {
    if (!contact.verify(this.magic, timestamp))
      return false;

    const address = contact.toAddress(this.network);

    if (!address.isValid())
      return false;

    return this.allowLocal || address.isRoutable() || address.isOnion();
  }

  _netgroup(contact) {
    return contact.toAddress(this.network).getGroup().toString('hex');
  }

  _oldestFailed() {
    let selected = null;
    let oldest = Infinity;

    for (const [key, meta] of this.metadata) {
      if (meta.failures === 0 || meta.lastSeen >= oldest)
        continue;

      selected = key;
      oldest = meta.lastSeen;
    }

    return selected;
  }

  _cloneContact(contact) {
    return RendezvousContact.decode(contact.encode());
  }

  _changed() {
    if (this.onChange)
      this.onChange();
  }
}

class RouteStore {
  constructor(magic, options = {}) {
    this.magic = magic;
    this.maxRecords = options.maxRecords || common.hnsr.MAX_STORED_RECORDS;
    this.maxPerKey = options.maxPerKey || common.hnsr.MAX_RECORDS_PER_KEY;
    this.maxPerPeer = options.maxPerPeer
      || common.hnsr.MAX_STORES_PER_PEER;
    this.maxPerPrefix = options.maxPerPrefix
      || common.hnsr.MAX_STORES_PER_PREFIX;
    this.onChange = typeof options.onChange === 'function'
      ? options.onChange
      : null;
    this.records = new Map();
    this.sourceCounts = new Map();
    this.prefixCounts = new Map();
    this.size = 0;
  }

  put(
    key,
    raw,
    timestamp = now(),
    source = 'local',
    prefix = source,
    decoded = null) {
    if (!Buffer.isBuffer(key) || key.length !== 32)
      throw new Error('Invalid HNSR route key.');

    if (typeof source !== 'string' || source.length === 0)
      throw new Error('Invalid HNSR route source.');

    if (typeof prefix !== 'string' || prefix.length === 0)
      throw new Error('Invalid HNSR route source prefix.');

    const record = decoded || RouteRecord.decode(raw);

    if (!record.routeKey.equals(key) || !record.verify(this.magic, timestamp))
      throw new Error('Invalid HNSR route record.');

    const hex = key.toString('hex');
    const items = this._active(hex, timestamp);
    const endpoint = record.delegation.endpointKey.toString('hex');
    const index = items.findIndex(item => item.endpoint === endpoint);
    const previous = index !== -1 ? items[index] : null;

    if (previous) {
      if (previous.sequence >= record.sequence)
        throw new Error('Stale HNSR route sequence.');
    }

    if (!previous && items.length >= this.maxPerKey)
      throw new Error('HNSR per-key route capacity reached.');

    if (!previous && this.size >= this.maxRecords)
      throw new Error('HNSR route store capacity reached.');

    const sourceCount = this.sourceCounts.get(source) || 0;
    const replacesSameSource = previous && previous.source === source;
    const prefixCount = this.prefixCounts.get(prefix) || 0;
    const replacesSamePrefix = previous && previous.prefix === prefix;

    if (sourceCount >= this.maxPerPeer && !replacesSameSource)
      throw new Error('HNSR per-peer route capacity reached.');

    if (prefixCount >= this.maxPerPrefix && !replacesSamePrefix)
      throw new Error('HNSR per-prefix route capacity reached.');

    if (previous) {
      this._decrementSource(previous.source);
      this._decrementPrefix(previous.prefix);
      items.splice(index, 1);
      this.size -= 1;
    }

    items.push({
      endpoint,
      sequence: record.sequence,
      expiresAt: record.expiresAt,
      authorityType: record.authorityType,
      profile: record.profile,
      source,
      prefix,
      raw: Buffer.from(raw)
    });

    this.records.set(hex, items);
    this.sourceCounts.set(source, (this.sourceCounts.get(source) || 0) + 1);
    this.prefixCounts.set(prefix, (this.prefixCounts.get(prefix) || 0) + 1);
    this.size += 1;
    this._changed();

    return record.expiresAt;
  }

  get(key, maximum = 16, timestamp = now()) {
    assert(Buffer.isBuffer(key) && key.length === 32);
    const items = this._active(key.toString('hex'), timestamp);
    items.sort((a, b) => b.sequence - a.sequence);
    return items.slice(0, maximum).map(item => Buffer.from(item.raw));
  }

  sample(maximum, seed, timestamp = now()) {
    assert(Number.isSafeInteger(maximum) && maximum >= 1 && maximum <= 16);
    assert(Buffer.isBuffer(seed) && seed.length === 32);

    const items = [];

    for (const hex of Array.from(this.records.keys())) {
      for (const item of this._active(hex, timestamp)) {
        if (item.authorityType !== 0
            || item.profile !== profiles.HNS_NODE_V1) {
          continue;
        }

        items.push({
          score: hash(domains.SAMPLE, seed, item.raw),
          raw: item.raw
        });
      }
    }

    items.sort((a, b) => a.score.compare(b.score));
    return items.slice(0, maximum).map(item => Buffer.from(item.raw));
  }

  toJSON(timestamp = now()) {
    const records = [];

    for (const hex of Array.from(this.records.keys())) {
      for (const item of this._active(hex, timestamp)) {
        records.push({
          source: item.source,
          prefix: item.prefix,
          raw: item.raw.toString('hex')
        });
      }
    }

    return records;
  }

  fromJSON(records, timestamp = now()) {
    if (!Array.isArray(records))
      throw new Error('Invalid HNSR route-store state.');

    for (const item of records) {
      if (!item
          || typeof item.raw !== 'string'
          || typeof item.source !== 'string'
          || typeof item.prefix !== 'string') {
        continue;
      }

      try {
        const raw = Buffer.from(item.raw, 'hex');
        const record = RouteRecord.decode(raw);
        this.put(
          record.routeKey,
          raw,
          timestamp,
          item.source,
          item.prefix,
          record);
      } catch (e) {
        continue;
      }
    }
  }

  _decrementSource(source) {
    const count = this.sourceCounts.get(source) || 0;

    if (count <= 1)
      this.sourceCounts.delete(source);
    else
      this.sourceCounts.set(source, count - 1);
  }

  _decrementPrefix(prefix) {
    const count = this.prefixCounts.get(prefix) || 0;

    if (count <= 1)
      this.prefixCounts.delete(prefix);
    else
      this.prefixCounts.set(prefix, count - 1);
  }

  _active(hex, timestamp) {
    const items = this.records.get(hex) || [];
    const active = items.filter(item => item.expiresAt > timestamp);

    for (const item of items) {
      if (item.expiresAt <= timestamp) {
        this._decrementSource(item.source);
        this._decrementPrefix(item.prefix);
      }
    }

    this.size -= items.length - active.length;

    if (active.length === 0)
      this.records.delete(hex);
    else
      this.records.set(hex, active);

    if (active.length !== items.length)
      this._changed();

    return active;
  }

  _changed() {
    if (this.onChange)
      this.onChange();
  }
}

class CircuitSocket extends EventEmitter {
  constructor(service, peer, contextID, window) {
    super();

    this.service = service;
    this.peer = peer;
    this.contextID = Buffer.from(contextID);
    this.sendCredit = window;
    this.sendQueue = [];
    this.sendQueueBytes = 0;
    this.receiveQueue = [];
    this.receiveQueueBytes = 0;
    this.paused = false;
    this.destroyed = false;
    this.connected = false;
    this.readable = true;
    this.writable = true;
    this.remoteAddress = '127.0.0.1';
    this.localAddress = '127.0.0.1';
    this.remotePort = 49152 + contextID.readUInt16LE(0, true) % 16384;
    this.localPort = 0;
  }

  connect() {
    if (this.destroyed || this.connected)
      return;

    this.connected = true;
    this.emit('connect');
  }

  write(data) {
    assert(Buffer.isBuffer(data));

    if (this.destroyed)
      return false;

    if (data.length === 0)
      return true;

    if (this.sendQueueBytes + data.length > common.hnsr.MAX_SOCKET_QUEUE) {
      const err = new Error('HNSR circuit send queue exhausted.');
      this.destroy();
      this.emit('error', err);
      return false;
    }

    this.sendQueue.push(Buffer.from(data));
    this.sendQueueBytes += data.length;
    this._flush();
    return this.sendQueueBytes === 0;
  }

  _sendData(data) {
    assert(data.length > 0 && data.length <= common.hnsr.MAX_DATA_SIZE);
    assert(data.length <= this.sendCredit);
    this.sendCredit -= data.length;
    this.service._send(this.peer, opcodes.DATA, this.contextID, data);
  }

  _flush() {
    while (!this.destroyed && this.sendCredit > 0
        && this.sendQueue.length > 0) {
      const data = this.sendQueue[0];
      const size = Math.min(
        data.length,
        this.sendCredit,
        common.hnsr.MAX_DATA_SIZE);
      const chunk = data.slice(0, size);

      this._sendData(chunk);
      this.sendQueueBytes -= size;

      if (size === data.length)
        this.sendQueue.shift();
      else
        this.sendQueue[0] = data.slice(size);
    }

    if (!this.destroyed && this.sendQueueBytes === 0)
      setImmediate(() => this.emit('drain'));
  }

  addCredit(credit) {
    if (!Number.isSafeInteger(credit) || credit <= 0)
      throw new Error('Invalid HNSR window credit.');

    if (this.sendCredit + credit > common.hnsr.MAX_WINDOW)
      throw new Error('HNSR window exceeds the maximum.');

    this.sendCredit += credit;
    this._flush();
  }

  receive(data) {
    if (this.destroyed)
      return;

    if (this.paused) {
      if (this.receiveQueueBytes + data.length
          > common.hnsr.MAX_CIRCUIT_QUEUE) {
        const err = new Error('HNSR circuit receive queue exhausted.');
        this.destroy();
        this.emit('error', err);
        return;
      }

      this.receiveQueue.push(Buffer.from(data));
      this.receiveQueueBytes += data.length;
      return;
    }

    this._deliver(data);
  }

  _deliver(data) {
    this.emit('data', data);

    const bw = bio.write(4);
    bw.writeU32(data.length);
    this.service._send(
      this.peer,
      opcodes.WINDOW,
      this.contextID,
      bw.render());
  }

  pause() {
    this.paused = true;
    return this;
  }

  resume() {
    this.paused = false;

    while (!this.destroyed && !this.paused
        && this.receiveQueue.length > 0) {
      const data = this.receiveQueue.shift();
      this.receiveQueueBytes -= data.length;
      this._deliver(data);
    }

    return this;
  }

  setNoDelay() {
    return this;
  }

  setKeepAlive() {
    return this;
  }

  setTimeout() {
    return this;
  }

  _clear() {
    this.readable = false;
    this.writable = false;
    this.sendQueue.length = 0;
    this.sendQueueBytes = 0;
    this.receiveQueue.length = 0;
    this.receiveQueueBytes = 0;
  }

  remoteClose() {
    if (this.destroyed)
      return;

    this.destroyed = true;
    this._clear();
    this.emit('close');
  }

  destroy() {
    if (this.destroyed)
      return;

    this.destroyed = true;
    this._clear();
    const bw = bio.write(3);
    bw.writeU16(errors.NORMAL);
    bw.writeU8(0);
    this.service._send(
      this.peer,
      opcodes.CLOSE,
      this.contextID,
      bw.render());
    this.service._dropSocket(this.peer, this.contextID);
    this.emit('close');
  }

  end() {
    this.destroy();
  }
}

class HNSRService extends EventEmitter {
  constructor(options) {
    super();

    assert(options);
    assert(options.network);
    assert(Buffer.isBuffer(options.identityKey));
    assert(secp256k1.privateKeyVerify(options.identityKey));

    this.network = options.network;
    this.chain = options.chain || null;
    this.identityKey = options.identityKey;
    this.publicKey = secp256k1.publicKeyCreate(this.identityKey, true);
    this.pool = options.pool || null;
    this.logger = options.logger && options.logger.context
      ? options.logger.context('hnsr')
      : options.logger;
    this.enabled = options.enabled === true;
    this.rendezvous = options.rendezvous === true;
    this.relay = options.relay === true;
    this.endpoint = options.endpoint === true;
    this.web = options.web === true;
    this.relayHost = options.relayHost || Buffer.from([
      0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0xff, 0xff, 127, 0, 0, 1
    ]);
    this.relayPort = options.relayPort || this.network.port;
    this.timeout = options.timeout || common.hnsr.DEFAULT_TIMEOUT;
    this.allowLocal = options.allowLocal === true
      || this.network.type === 'regtest';
    this.memory = options.memory !== false;
    this.stateFilename = options.stateFilename || (options.prefix
      ? path.join(options.prefix, 'hnsr-state.json')
      : null);
    this.persist = options.persist !== false
      && !this.memory
      && this.stateFilename != null;
    this.stateDirty = false;
    this.stateMuted = false;
    this.stateFlushing = null;
    this.stateTimer = null;
    this.opened = false;
    const routingOptions = Object.assign({}, options.routingOptions, {
      allowLocal: this.allowLocal,
      onChange: () => this._markStateDirty()
    });

    if (this.allowLocal && routingOptions.maxPerNetgroup == null) {
      routingOptions.maxPerNetgroup = routingOptions.bucketSize
        || common.hnsr.ROUTING_BUCKET_SIZE;
    }

    const storeOptions = Object.assign({}, options.storeOptions, {
      onChange: () => this._markStateDirty()
    });
    this.routing = new RoutingTable(
      this.network.magic,
      rendezvousNodeID(this.network.magic, this.publicKey),
      this.network,
      routingOptions);
    this.contacts = this.routing.contacts;
    this.store = new RouteStore(this.network.magic, storeOptions);
    this.admission = new Map();
    this.prefixAdmission = new Map();
    this.pending = new Map();
    this.provisional = new Map();
    this.reservations = new Map();
    this.endpointTickets = new Map();
    this.relayHealth = new Map();
    this.webServices = new Map();
    this.opening = new Map();
    this.relayCircuits = new Map();
    this.relayQueue = [];
    this.relayQueueBytes = 0;
    this.relayFlushScheduled = false;
    this.relayFlushHandle = null;
    this.relayFlushDelayed = false;
    this.relayScheduleCursor = 0;
    this.relayTokens = {
      updated: Date.now(),
      node: common.hnsr.RELAY_BURST,
      web: common.hnsr.RELAY_BURST
    };
    this.sockets = new Map();
    this.relayBytes = 0;
    this.relayFrames = 0;
    this.relayFlushes = 0;
    this.maxRelayQueuedBytes = 0;
    this.relayDrops = 0;
    this.admissionRejected = 0;
    this.verifications = 0;
    this.verificationRejected = 0;
    this.circuitRejected = 0;
    this.republishers = new Set();
    this.republishAttempts = 0;
    this.republishSuccesses = 0;
    this.republishFailures = 0;
    this.relayPayloads = [];
    this.routeSequence = 0;
    this.endpointSequence = 0;
  }

  async open() {
    await this._loadState();
    this.opened = true;

    if (this.persist) {
      this.stateTimer = setInterval(() => {
        this.flushState().catch(error => this.emit('error', error));
      }, common.hnsr.STATE_FLUSH_INTERVAL);

      if (typeof this.stateTimer.unref === 'function')
        this.stateTimer.unref();
    }
  }

  async close() {
    this.opened = false;

    if (this.stateTimer) {
      clearInterval(this.stateTimer);
      this.stateTimer = null;
    }

    if (this.relayFlushHandle != null) {
      if (this.relayFlushDelayed)
        clearTimeout(this.relayFlushHandle);
      else
        clearImmediate(this.relayFlushHandle);

      this.relayFlushHandle = null;
    }

    this.relayFlushScheduled = false;
    this.relayFlushDelayed = false;
    this.relayQueue.length = 0;
    this.relayQueueBytes = 0;

    for (const pending of this.pending.values()) {
      clearTimeout(pending.timer);
      pending.reject(new Error('HNSR service closed.'));
    }

    this.pending.clear();

    for (const socket of this.sockets.values())
      socket.remoteClose();

    this.sockets.clear();

    for (const state of this.opening.values())
      clearTimeout(state.timer);

    this.opening.clear();
    this.relayCircuits.clear();
    this.provisional.clear();
    this.reservations.clear();
    this.endpointTickets.clear();
    this.webServices.clear();
    this.admission.clear();
    this.prefixAdmission.clear();

    for (const state of this.republishers) {
      state.stopped = true;

      if (state.timer)
        clearTimeout(state.timer);
    }

    this.republishers.clear();
    await this.flushState(true);
  }

  _markStateDirty() {
    if (!this.stateMuted)
      this.stateDirty = true;
  }

  async _loadState() {
    if (!this.persist || fs.unsupported)
      return;

    let raw;

    try {
      raw = await fs.readFile(this.stateFilename, 'utf8');
    } catch (e) {
      if (e.code === 'ENOENT')
        return;
      throw e;
    }

    const json = JSON.parse(raw);

    if (!json
        || json.version !== 1
        || json.networkMagic !== this.network.magic
        || !Array.isArray(json.contacts)
        || !Array.isArray(json.routes)) {
      throw new Error('Invalid or wrong-network HNSR persistent state.');
    }

    this.stateMuted = true;

    try {
      this.routing.fromJSON(json.contacts);
      this.store.fromJSON(json.routes);

      if (Number.isSafeInteger(json.routeSequence)
          && json.routeSequence >= 0) {
        this.routeSequence = json.routeSequence;
      }

      if (Number.isSafeInteger(json.endpointSequence)
          && json.endpointSequence >= 0) {
        this.endpointSequence = json.endpointSequence;
      }
    } finally {
      this.stateMuted = false;
    }

    this.stateDirty = false;
  }

  async flushState(force = false) {
    if (!this.persist || fs.unsupported)
      return false;

    if (this.stateFlushing) {
      await this.stateFlushing;

      if (!force || !this.stateDirty)
        return false;
    }

    if (!force && !this.stateDirty)
      return false;

    this.stateFlushing = this._flushState();

    try {
      await this.stateFlushing;
    } finally {
      this.stateFlushing = null;
    }

    return true;
  }

  async _flushState() {
    this.stateMuted = true;
    let data;

    try {
      data = JSON.stringify({
        version: 1,
        networkMagic: this.network.magic,
        routeSequence: this.routeSequence,
        endpointSequence: this.endpointSequence,
        contacts: this.routing.toJSON(),
        routes: this.store.toJSON()
      });
    } finally {
      this.stateMuted = false;
    }

    const temporary = `${this.stateFilename}.tmp`;

    try {
      await fs.writeFile(temporary, data, 'utf8');
      await fs.rename(temporary, this.stateFilename);
      this.stateDirty = false;
    } catch (e) {
      this.stateDirty = true;

      try {
        await fs.unlink(temporary);
      } catch (unlinkError) {
        if (unlinkError.code !== 'ENOENT')
          this.emit('error', unlinkError);
      }

      throw e;
    }
  }

  isReady() {
    return this.enabled && this.opened;
  }

  getTelemetry() {
    const queues = {
      node: 0,
      web: 0
    };

    for (const item of this.relayQueue) {
      if (item.profile === profiles.HNS_WEB_V1)
        queues.web += item.data.length;
      else
        queues.node += item.data.length;
    }

    return {
      contacts: this.contacts.size,
      storedRoutes: this.store.size,
      activeReservations: this.reservations.size,
      activeCircuits: Math.floor(this.relayCircuits.size / 2),
      trackedRelays: this.relayHealth.size,
      queuedBytes: this.relayQueueBytes,
      queuedNodeBytes: queues.node,
      queuedWebBytes: queues.web,
      relayBytes: this.relayBytes,
      relayFrames: this.relayFrames,
      relayDrops: this.relayDrops,
      admissionRejected: this.admissionRejected,
      verificationChecks: this.verifications,
      verificationRejected: this.verificationRejected,
      circuitRejected: this.circuitRejected,
      republishAttempts: this.republishAttempts,
      republishSuccesses: this.republishSuccesses,
      republishFailures: this.republishFailures
    };
  }

  services() {
    let bits = 0;

    if (this.enabled && this.rendezvous)
      bits |= common.EXPERIMENTAL_HNSR_RENDEZVOUS_SERVICE;

    if (this.enabled && this.relay)
      bits |= common.EXPERIMENTAL_HNSR_RELAY_SERVICE;

    return bits >>> 0;
  }

  selfContact(timestamp = now()) {
    if (!this.rendezvous)
      return null;

    return new RendezvousContact({
      nodeID: rendezvousNodeID(this.network.magic, this.publicKey),
      hostType: 1,
      host: Buffer.from(this.relayHost),
      port: this.relayPort,
      services: this.services(),
      peerKey: this.publicKey,
      observedAt: timestamp
    });
  }

  addPeer(peer) {
    if (!this.enabled || !peer || !peer.outbound || peer.hnsrVirtual)
      return null;

    if ((peer.services
        & common.EXPERIMENTAL_HNSR_RENDEZVOUS_SERVICE) === 0) {
      return null;
    }

    const key = peerPublicKey(peer);

    if (!key || !peer.address || peer.address.port === 0)
      return null;

    const contact = new RendezvousContact({
      nodeID: rendezvousNodeID(this.network.magic, key),
      hostType: 1,
      host: Buffer.from(peer.address.raw),
      port: peer.address.port,
      services: peer.services,
      peerKey: Buffer.from(key),
      observedAt: now()
    });

    if (!this.routing.isAdmissible(contact))
      return null;

    return this.routing.add(contact, now(), true) ? contact : null;
  }

  _admit(peer, bytes, opcode) {
    const timestamp = Date.now();
    const key = peer.id;
    let state = this.admission.get(key);

    if (!state) {
      state = {
        secondStarted: timestamp,
        minuteStarted: timestamp,
        requests: 0,
        bytes: 0,
        puts: 0,
        gets: 0,
        verifications: 0
      };
      this.admission.set(key, state);
    }

    if (timestamp - state.secondStarted >= 1000) {
      state.secondStarted = timestamp;
      state.requests = 0;
      state.bytes = 0;
    }

    if (timestamp - state.minuteStarted >= 60000) {
      state.minuteStarted = timestamp;
      state.puts = 0;
      state.gets = 0;
      state.verifications = 0;
    }

    state.requests += 1;
    state.bytes += bytes;

    if (opcode === opcodes.PUTROUTE)
      state.puts += 1;

    if (opcode === opcodes.GETROUTE
        || opcode === opcodes.SAMPLEROUTES
        || opcode === opcodes.FINDNODE) {
      state.gets += 1;
    }

    const prefix = peerAddressPrefix(peer);
    let prefixState = this.prefixAdmission.get(prefix);

    if (!prefixState || timestamp - prefixState.started >= 1000) {
      if (!prefixState) {
        for (const [known, item] of this.prefixAdmission) {
          if (timestamp - item.started >= 1000)
            this.prefixAdmission.delete(known);
        }

        if (this.prefixAdmission.size
            >= common.hnsr.MAX_ADMISSION_PREFIXES) {
          this.admissionRejected += 1;
          return false;
        }
      }

      prefixState = {started: timestamp, requests: 0, bytes: 0};
      this.prefixAdmission.set(prefix, prefixState);
    }

    prefixState.requests += 1;
    prefixState.bytes += bytes;

    const admitted = state.requests <= common.hnsr.MAX_REQUESTS_PER_SECOND
      && state.bytes <= common.hnsr.MAX_REQUEST_BYTES_PER_SECOND
      && state.puts <= common.hnsr.MAX_PUTS_PER_MINUTE
      && state.gets <= common.hnsr.MAX_GETS_PER_MINUTE
      && prefixState.requests
        <= common.hnsr.MAX_PREFIX_REQUESTS_PER_SECOND
      && prefixState.bytes <= common.hnsr.MAX_PREFIX_BYTES_PER_SECOND;

    if (!admitted)
      this.admissionRejected += 1;

    return admitted;
  }

  _admitVerifications(peer, count) {
    assert(Number.isSafeInteger(count) && count >= 1);

    const timestamp = Date.now();
    let state = this.admission.get(peer.id);

    if (!state) {
      this._admit(peer, 0, -1);
      state = this.admission.get(peer.id);
    }

    if (timestamp - state.minuteStarted >= 60000) {
      state.minuteStarted = timestamp;
      state.puts = 0;
      state.gets = 0;
      state.verifications = 0;
    }

    if (state.verifications + count
        > common.hnsr.MAX_VERIFICATIONS_PER_MINUTE) {
      this.verificationRejected += count;
      return false;
    }

    state.verifications += count;
    this.verifications += count;
    return true;
  }

  _closestContacts(target, maximum) {
    const contacts = [];
    const seen = new Set();
    const self = this.selfContact();

    if (self) {
      contacts.push(self);
      seen.add(self.peerKey.toString('hex'));
    }

    for (const contact of this.routing.closest(
      target,
      common.hnsr.MAX_ROUTING_CONTACTS)) {
      const key = contact.peerKey.toString('hex');

      if (seen.has(key))
        continue;

      seen.add(key);
      contacts.push(contact);
    }

    contacts.sort((a, b) => compareDistance(a.nodeID, b.nodeID, target));
    return contacts.slice(0, maximum);
  }

  _send(peer, opcode, contextID, body) {
    if (!this.enabled || !peer || peer.destroyed)
      return false;

    assert(Buffer.isBuffer(contextID) && contextID.length === 8);
    assert(!isZero(contextID));
    assert(Buffer.isBuffer(body));
    assert(body.length <= common.hnsr.MAX_PACKET_SIZE - 12);

    peer.send(new packets.HNSRPacket(1, opcode, contextID, body));
    return true;
  }

  _request(peer, opcode, body, expected, contextID = randomID(8)) {
    assert(Array.isArray(expected));

    const key = peerKey(peer, contextID);

    if (this.pending.has(key))
      return Promise.reject(new Error('Duplicate live HNSR context ID.'));

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(key);
        reject(new Error('HNSR request timed out.'));
      }, this.timeout);

      this.pending.set(key, {
        expected: new Set(expected),
        resolve,
        reject,
        timer
      });

      if (!this._send(peer, opcode, contextID, body)) {
        clearTimeout(timer);
        this.pending.delete(key);
        reject(new Error('HNSR peer is unavailable.'));
      }
    });
  }

  _resolvePending(peer, packet) {
    const key = peerKey(peer, packet.contextID);
    const pending = this.pending.get(key);

    if (!pending)
      return false;

    if (packet.opcode === opcodes.ERROR) {
      clearTimeout(pending.timer);
      this.pending.delete(key);

      try {
        const br = bio.read(packet.body);
        const reason = br.readU16();
        const size = br.readU8();
        const detail = br.readString(size, 'utf8');
        finish(br, 'HNSR error');
        const err = new Error(detail || `HNSR error ${reason}.`);
        err.code = reason;
        pending.reject(err);
      } catch (e) {
        pending.reject(e);
      }

      return true;
    }

    if (!pending.expected.has(packet.opcode))
      return false;

    clearTimeout(pending.timer);
    this.pending.delete(key);
    pending.resolve(packet);
    return true;
  }

  _sendError(peer, contextID, reason, detail) {
    const message = Buffer.from(detail || '', 'utf8').slice(0, 128);
    const bw = bio.write(3 + message.length);
    bw.writeU16(reason);
    bw.writeU8(message.length);
    bw.writeBytes(message);
    this._send(peer, opcodes.ERROR, contextID, bw.render());
  }

  async handle(peer, packet) {
    if (!this.enabled)
      return;

    if (this._resolvePending(peer, packet))
      return;

    if (packet.opcode === opcodes.FINDNODE
        || packet.opcode === opcodes.PUTROUTE
        || packet.opcode === opcodes.GETROUTE
        || packet.opcode === opcodes.SAMPLEROUTES
        || packet.opcode === opcodes.RESERVE
        || packet.opcode === opcodes.RENEW
        || packet.opcode === opcodes.WITHDRAW
        || packet.opcode === opcodes.OPEN) {
      if (!this._admit(peer, packet.body.length + 12, packet.opcode)) {
        this._sendError(
          peer,
          packet.contextID,
          errors.RATE_LIMITED,
          'HNSR peer admission limit reached.');
        return;
      }
    }

    try {
      switch (packet.opcode) {
        case opcodes.FINDNODE:
          this._handleFindNode(peer, packet);
          break;
        case opcodes.PUTROUTE:
          this._handlePutRoute(peer, packet);
          break;
        case opcodes.GETROUTE:
          this._handleGetRoute(peer, packet);
          break;
        case opcodes.SAMPLEROUTES:
          this._handleSampleRoutes(peer, packet);
          break;
        case opcodes.RESERVE:
          this._handleReserve(peer, packet, false);
          break;
        case opcodes.RENEW:
          this._handleReserve(peer, packet, true);
          break;
        case opcodes.WITHDRAW:
          this._handleWithdraw(peer, packet);
          break;
        case opcodes.CONFIRM:
          this._handleConfirm(peer, packet);
          break;
        case opcodes.OPEN:
          this._handleOpen(peer, packet);
          break;
        case opcodes.INCOMING:
          this._handleIncoming(peer, packet);
          break;
        case opcodes.ACCEPT:
          this._handleAccept(peer, packet);
          break;
        case opcodes.DATA:
          this._handleData(peer, packet);
          break;
        case opcodes.WINDOW:
          this._handleWindow(peer, packet);
          break;
        case opcodes.CLOSE:
          this._handleClose(peer, packet);
          break;
        case opcodes.OFFER:
        case opcodes.NODES:
        case opcodes.CONFIRMED:
        case opcodes.PUTRESULT:
        case opcodes.ROUTES:
        case opcodes.OPENED:
        case opcodes.ERROR:
          this.emit('unsolicited response', peer, packet);
          return;
        default:
          this._sendError(
            peer,
            packet.contextID,
            errors.UNSUPPORTED,
            'HNSR opcode is not implemented by this PoC.');
          break;
      }
    } catch (e) {
      this.emit('protocol error', e, peer, packet);
      this._sendError(peer, packet.contextID, errors.INVALID, e.message);
    }
  }

  async reserve(peer, options = {}) {
    return this._reserve(peer, options, null);
  }

  async renew(peer, ticket, options = {}) {
    if (!(ticket instanceof RelayTicket)
        || !ticket.verify(this.network.magic)) {
      throw new Error('Invalid HNSR ticket to renew.');
    }

    return this._reserve(peer, options, ticket);
  }

  async _reserve(peer, options = {}, previous) {
    if (!this.enabled || !this.endpoint)
      throw new Error('HNSR endpoint role is disabled.');

    if (!(peer.services & common.EXPERIMENTAL_HNSR_RELAY_SERVICE))
      throw new Error('Peer does not advertise the HNSR relay role.');

    const relayKey = options.relayKey
      || (peer.address && peer.address.key);

    if (!Buffer.isBuffer(relayKey) || !secp256k1.publicKeyVerify(relayKey))
      throw new Error('Authenticated HNSR relay key is required.');

    const contextID = randomID(8);
    const request = new ReserveRequest({
      endpointKey: this.publicKey,
      profile: options.profile || profiles.HNS_NODE_V1,
      lifetime: options.lifetime || 1800,
      maxCircuits: options.maxCircuits || 8,
      maxBytes: options.maxBytes || 1048576,
      nonce: randomID(16)
    });

    if (previous) {
      request.signRenewal(
        this.network.magic,
        relayKey,
        contextID,
        previous.reservationID,
        this.identityKey);
    } else {
      request.sign(
        this.network.magic,
        relayKey,
        contextID,
        this.identityKey);
    }

    let body = request.encode();

    if (previous)
      body = Buffer.concat([previous.reservationID, body]);

    const offered = await this._request(
      peer,
      previous ? opcodes.RENEW : opcodes.RESERVE,
      body,
      [opcodes.OFFER],
      contextID);
    const ticket = RelayTicket.decode(offered.body);

    if (!ticket.relayKey.equals(relayKey)
        || !ticket.endpointKey.equals(this.publicKey)
        || ticket.networkMagic !== this.network.magic
        || ticket.endpointSignature.length !== 0
        || !ticket.verifyRelay()
        || ticket.expiresAt <= now()) {
      throw new Error('Invalid HNSR relay offer.');
    }

    ticket.signEndpoint(this.identityKey);

    const bw = bio.write(17 + ticket.endpointSignature.length);
    bw.writeBytes(ticket.reservationID);
    writeSignature(bw, ticket.endpointSignature);

    const confirmed = await this._request(
      peer,
      opcodes.CONFIRM,
      bw.render(),
      [opcodes.CONFIRMED],
      contextID);
    const br = bio.read(confirmed.body);
    const reservationID = br.readBytes(16);
    const ticketID = br.readBytes(32);
    const expiresAt = br.readU64();
    finish(br, 'HNSR confirmation');

    if (!reservationID.equals(ticket.reservationID)
        || !ticketID.equals(ticket.id())
        || expiresAt !== ticket.expiresAt) {
      throw new Error('Mismatched HNSR confirmation.');
    }

    this.endpointTickets.set(ticketID.toString('hex'), {peer, ticket});
    return ticket;
  }

  async withdraw(peer, ticket) {
    if (!this.enabled || !this.endpoint)
      throw new Error('HNSR endpoint role is disabled.');

    if (!(ticket instanceof RelayTicket)
        || !ticket.verify(this.network.magic)) {
      throw new Error('Invalid HNSR ticket to withdraw.');
    }

    const relayKey = peerPublicKey(peer);

    if (!relayKey || !relayKey.equals(ticket.relayKey))
      throw new Error('HNSR withdrawal relay key mismatch.');

    const contextID = randomID(8);
    const ticketID = ticket.id();
    const signature = sign(
      domains.WITHDRAW,
      withdrawData(
        this.network.magic,
        relayKey,
        contextID,
        ticket.reservationID,
        ticketID),
      this.identityKey);
    const bw = bio.write(49 + signature.length);
    bw.writeBytes(ticket.reservationID);
    bw.writeBytes(ticketID);
    writeSignature(bw, signature);
    const response = await this._request(
      peer,
      opcodes.WITHDRAW,
      bw.render(),
      [opcodes.CONFIRMED],
      contextID);
    const br = bio.read(response.body);
    const reservationID = br.readBytes(16);
    const confirmedTicket = br.readBytes(32);
    const expiresAt = br.readU64();
    finish(br, 'HNSR withdrawal confirmation');

    if (!reservationID.equals(ticket.reservationID)
        || !confirmedTicket.equals(ticketID)
        || expiresAt !== 0) {
      throw new Error('Mismatched HNSR withdrawal confirmation.');
    }

    this.endpointTickets.delete(ticketID.toString('hex'));
    return true;
  }

  async _queryFindNode(peer, target, maximum) {
    const bw = bio.write(33);
    bw.writeBytes(target);
    bw.writeU8(maximum);
    const response = await this._request(
      peer,
      opcodes.FINDNODE,
      bw.render(),
      [opcodes.NODES]);
    const br = bio.read(response.body);
    const count = br.readU8();

    if (count > maximum || count > common.hnsr.MAX_CONTACTS)
      throw new Error('Too many HNSR rendezvous contacts returned.');

    const contacts = [];

    for (let i = 0; i < count; i++) {
      const contact = RendezvousContact.read(br);

      if (!this.routing.isAdmissible(contact))
        throw new Error('Invalid HNSR rendezvous contact.');

      this.routing.add(contact);
      contacts.push(contact);
    }

    finish(br, 'HNSR nodes response');
    return contacts;
  }

  async _peerForContact(contact) {
    if (!this.pool)
      throw new Error('HNSR rendezvous discovery requires a peer pool.');

    let peer = this.pool.findHNSRPeer(contact.peerKey);

    if (peer && peer.handshake && !peer.destroyed)
      return peer;

    try {
      peer = await this.pool.connectHNSRContact(contact);
    } catch (e) {
      this.routing.markAttempt(contact.peerKey, false);
      throw e;
    }

    if (!peer || !peer.handshake || peer.destroyed) {
      this.routing.markAttempt(contact.peerKey, false);
      throw new Error('Could not connect to discovered HNSR rendezvous peer.');
    }

    this.routing.markAttempt(contact.peerKey, true);

    return peer;
  }

  async findNodes(
    bootstrap,
    target,
    maximum = common.hnsr.ROUTE_REPLICATION,
    options = {}) {
    if (!Buffer.isBuffer(target) || target.length !== 32)
      throw new Error('Invalid HNSR rendezvous target.');

    if (!Array.isArray(bootstrap))
      bootstrap = [bootstrap];

    if (maximum < 1 || maximum > common.hnsr.MAX_CONTACTS)
      throw new Error('Invalid HNSR rendezvous result limit.');

    const candidates = new Map();
    const peers = new Map();
    const queried = new Set();
    let queries = 0;
    let dials = 0;
    const maximumDials = options.maximumDials
      || common.hnsr.MAX_RENDEZVOUS_DIALS;

    for (const peer of bootstrap) {
      if (!peer || peer.destroyed
          || (peer.services
            & common.EXPERIMENTAL_HNSR_RENDEZVOUS_SERVICE) === 0) {
        continue;
      }

      const contact = this.addPeer(peer);

      if (!contact)
        continue;

      const key = contact.peerKey.toString('hex');
      candidates.set(key, contact);
      peers.set(key, peer);
    }

    for (const contact of this.routing.closest(
      target,
      common.hnsr.MAX_CONTACTS)) {
      const key = contact.peerKey.toString('hex');

      if (!candidates.has(key))
        candidates.set(key, contact);
    }

    if (candidates.size === 0)
      throw new Error('No usable HNSR rendezvous bootstrap or routing peer.');

    while (queries < common.hnsr.MAX_FIND_QUERIES) {
      const ordered = Array.from(candidates.values()).sort(
        (a, b) => compareDistance(a.nodeID, b.nodeID, target));
      const batch = ordered.filter((contact) => {
        return !queried.has(contact.peerKey.toString('hex'));
      }).slice(0, Math.min(
        3,
        common.hnsr.MAX_FIND_QUERIES - queries));

      if (batch.length === 0)
        break;

      const results = await Promise.all(batch.map(async (contact) => {
        const key = contact.peerKey.toString('hex');
        queried.add(key);
        queries += 1;

        try {
          let peer = peers.get(key);

          if (!peer || peer.destroyed || !peer.handshake) {
            if (dials >= maximumDials)
              throw new Error('HNSR rendezvous peer-dial budget exhausted.');

            dials += 1;
            peer = await this._peerForContact(contact);
          }

          peers.set(key, peer);
          return await this._queryFindNode(
            peer,
            target,
            common.hnsr.MAX_CONTACTS);
        } catch (e) {
          this.emit('discovery failure', e, contact);
          return [];
        }
      }));

      for (const contacts of results) {
        for (const contact of contacts) {
          if (contact.peerKey.equals(this.publicKey))
            continue;

          const key = contact.peerKey.toString('hex');

          if (!candidates.has(key))
            candidates.set(key, contact);
        }
      }
    }

    const selected = Array.from(candidates.values()).sort(
      (a, b) => compareDistance(a.nodeID, b.nodeID, target)).slice(0, maximum);
    const result = [];

    for (const contact of selected) {
      const key = contact.peerKey.toString('hex');

      try {
        let peer = peers.get(key);

        if (!peer || peer.destroyed || !peer.handshake) {
          if (dials >= maximumDials)
            throw new Error('HNSR rendezvous peer-dial budget exhausted.');

          dials += 1;
          peer = await this._peerForContact(contact);
        }

        result.push({contact, peer});
      } catch (e) {
        this.emit('discovery failure', e, contact);
      }
    }

    if (result.length === 0)
      throw new Error('HNSR iterative lookup found no live rendezvous peers.');

    return result;
  }

  _createRoute(tickets, options = {}) {
    assert(Array.isArray(tickets) && tickets.length > 0);

    const timestamp = now();
    const expiresAt = Math.min(
      timestamp + (options.lifetime || 900),
      ...tickets.map(ticket => ticket.expiresAt));
    const endpointSequence = options.endpointSequence
      || ++this.endpointSequence;
    const sequence = options.sequence || ++this.routeSequence;

    this._markStateDirty();
    const delegation = new EndpointDelegation({
      endpointKey: this.publicKey,
      sequence: endpointSequence,
      issuedAt: timestamp,
      expiresAt,
      maxActiveCircuits: Math.min(
        ...tickets.map(ticket => ticket.maxActiveCircuits)),
      maxBytesPerCircuit: Math.min(
        ...tickets.map(ticket => ticket.maxBytesPerCircuit))
    }).sign(this.network.magic, this.identityKey);
    const key = routeKey(this.network.magic, this.publicKey);
    const record = new RouteRecord({
      routeKey: key,
      profile: profiles.HNS_NODE_V1,
      sequence,
      issuedAt: timestamp,
      expiresAt,
      delegation,
      tickets
    }).sign(this.identityKey);

    if (record.encode().length > common.hnsr.MAX_RECORD_SIZE)
      throw new Error('HNSR route record exceeds the storage limit.');

    return record;
  }

  async _putRoute(peer, record) {
    const raw = record.encode();
    const bw = bio.write(34 + raw.length);
    bw.writeBytes(record.routeKey);
    bw.writeU16(raw.length);
    bw.writeBytes(raw);
    const result = await this._request(
      peer,
      opcodes.PUTROUTE,
      bw.render(),
      [opcodes.PUTRESULT]);
    const br = bio.read(result.body);
    const status = br.readU16();
    const storedUntil = br.readU64();
    finish(br, 'HNSR put result');

    if (status !== 0 || storedUntil !== record.expiresAt)
      throw new Error(`HNSR rendezvous store rejected route (${status}).`);

    return storedUntil;
  }

  async publish(peer, tickets, options = {}) {
    if (!this.enabled || !this.endpoint)
      throw new Error('HNSR endpoint role is disabled.');

    if (!(peer.services & common.EXPERIMENTAL_HNSR_RENDEZVOUS_SERVICE))
      throw new Error('Peer does not advertise the HNSR rendezvous role.');

    const record = this._createRoute(tickets, options);
    await this._putRoute(peer, record);
    return record;
  }

  async publishReplicated(bootstrap, tickets, options = {}) {
    if (!this.enabled || !this.endpoint)
      throw new Error('HNSR endpoint role is disabled.');

    const record = this._createRoute(tickets, options);
    const replicas = options.replicas || common.hnsr.ROUTE_REPLICATION;
    const candidates = await this.findNodes(
      bootstrap,
      record.routeKey,
      Math.min(common.hnsr.MAX_CONTACTS, replicas * 2),
      options);
    const nodes = selectDiverseNodes(candidates, replicas, this.network);
    const stored = [];
    const failures = [];

    await Promise.all(nodes.map(async ({contact, peer}) => {
      try {
        await this._putRoute(peer, record);
        stored.push(contact);
      } catch (e) {
        failures.push({contact, error: e});
      }
    }));

    const required = options.minimumStores
      || common.hnsr.MIN_ROUTE_STORES;

    if (stored.length < required) {
      throw new Error(
        `HNSR route replication quorum failed (${stored.length}/${required}).`);
    }

    return {record, stored, failures};
  }

  async republish(publication, tickets, bootstrap, options = {}) {
    const previous = publication.record || publication;

    if (!(previous instanceof RouteRecord))
      throw new Error('Invalid HNSR publication to refresh.');

    return this.publishReplicated(
      bootstrap,
      tickets,
      Object.assign({}, options, {
        sequence: previous.sequence + 1,
        endpointSequence: previous.delegation.sequence + 1
      }));
  }

  startRepublisher(publication, tickets, bootstrap, options = {}) {
    const record = publication.record || publication;

    if (!(record instanceof RouteRecord))
      throw new Error('Invalid HNSR publication to schedule.');

    if (!Array.isArray(tickets) || tickets.length === 0)
      throw new Error('HNSR republisher requires live relay tickets.');

    const state = {
      publication,
      tickets: tickets.slice(),
      bootstrap: Array.isArray(bootstrap) ? bootstrap.slice() : [bootstrap],
      options: Object.assign({}, options),
      timer: null,
      running: false,
      stopped: false,
      attempts: 0,
      successes: 0,
      failures: 0,
      lastAttempt: 0,
      lastSuccess: 0,
      lastError: null
    };

    this.republishers.add(state);
    this._scheduleRepublisher(state);
    return state;
  }

  stopRepublisher(state) {
    if (!this.republishers.has(state))
      return false;

    state.stopped = true;

    if (state.timer)
      clearTimeout(state.timer);

    state.timer = null;
    this.republishers.delete(state);
    return true;
  }

  notifyNetworkChange(bootstrap = null) {
    for (const state of this.republishers) {
      if (bootstrap != null) {
        state.bootstrap = Array.isArray(bootstrap)
          ? bootstrap.slice()
          : [bootstrap];
      }

      this._scheduleRepublisher(state, 0);
    }
  }

  _scheduleRepublisher(state, delay = null) {
    if (state.stopped || !this.opened)
      return;

    if (state.timer)
      clearTimeout(state.timer);

    if (delay == null) {
      const record = state.publication.record || state.publication;
      const remaining = Math.max(0, record.expiresAt - now()) * 1000;
      const refresh = Math.floor(remaining * 2 / 3);
      delay = Math.min(
        state.options.interval || common.hnsr.DEFAULT_REPUBLISH_INTERVAL,
        Math.max(common.hnsr.DEFAULT_REPUBLISH_RETRY, refresh));
    }

    state.timer = setTimeout(() => {
      state.timer = null;
      this._runRepublisher(state).catch(error => this.emit('error', error));
    }, delay);

    if (typeof state.timer.unref === 'function')
      state.timer.unref();
  }

  async _runRepublisher(state) {
    if (state.stopped || state.running || !this.opened)
      return;

    state.running = true;
    state.attempts += 1;
    state.lastAttempt = Date.now();
    this.republishAttempts += 1;

    try {
      const previous = state.publication.record || state.publication;
      let publication;

      if (previous.authorityType === 1) {
        publication = await this.publishNamedReplicated(
          state.bootstrap,
          state.tickets,
          state.options.authorization,
          state.options.servicePrivateKey,
          Object.assign({}, state.options, {
            sequence: previous.sequence + 1,
            endpointSequence: previous.delegation.sequence + 1
          }));
      } else {
        publication = await this.republish(
          state.publication,
          state.tickets,
          state.bootstrap,
          state.options);
      }

      state.publication = publication;
      state.successes += 1;
      state.lastSuccess = Date.now();
      state.lastError = null;
      this.republishSuccesses += 1;
      this.emit('republished', publication, state);
      this._scheduleRepublisher(state);
    } catch (e) {
      state.failures += 1;
      state.lastError = e;
      this.republishFailures += 1;
      this.emit('republish failure', e, state);
      this._scheduleRepublisher(
        state,
        state.options.retry || common.hnsr.DEFAULT_REPUBLISH_RETRY);
    } finally {
      state.running = false;
    }
  }

  _createNamedRoute(tickets, authorization, servicePrivateKey, options = {}) {
    assert(Array.isArray(tickets) && tickets.length > 0);

    if (!(authorization instanceof ServiceAuthorization)
        || !authorization.validate(this.network.magic)) {
      throw new Error('Invalid HNSR named service authorization.');
    }

    if (!Buffer.isBuffer(servicePrivateKey)
        || !secp256k1.privateKeyVerify(servicePrivateKey)
        || !secp256k1.publicKeyCreate(servicePrivateKey, true)
          .equals(authorization.serviceKey)) {
      throw new Error('HNSR service private key does not match authorization.');
    }

    for (const ticket of tickets) {
      if (!(ticket instanceof RelayTicket)
          || ticket.profile !== authorization.profile
          || !ticket.endpointKey.equals(this.publicKey)
          || !ticket.verify(this.network.magic)) {
        throw new Error('Invalid HNSR named-service relay ticket.');
      }
    }

    const timestamp = now();
    const lifetime = options.lifetime || authorization.maxRouteLifetime;
    const expiresAt = Math.min(
      timestamp + lifetime,
      timestamp + authorization.maxRouteLifetime,
      timestamp + authorization.maxEndpointLifetime,
      ...tickets.map(ticket => ticket.expiresAt));
    const endpointSequence = options.endpointSequence
      || ++this.endpointSequence;
    const sequence = options.sequence || ++this.routeSequence;

    this._markStateDirty();
    const delegation = new EndpointDelegation({
      authorizationID: authorization.id(),
      endpointKey: this.publicKey,
      sequence: endpointSequence,
      issuedAt: timestamp,
      expiresAt,
      maxActiveCircuits: Math.min(
        ...tickets.map(ticket => ticket.maxActiveCircuits)),
      maxBytesPerCircuit: Math.min(
        ...tickets.map(ticket => ticket.maxBytesPerCircuit))
    }).sign(this.network.magic, servicePrivateKey);
    const key = namedRouteKey(
      this.network.magic,
      authorization.nameHash,
      authorization.serviceName,
      authorization.profile);
    const record = new RouteRecord({
      authorityType: 1,
      routeKey: key,
      profile: authorization.profile,
      sequence,
      issuedAt: timestamp,
      expiresAt,
      authorization: authorization.encode(),
      delegation,
      tickets
    }).sign(this.identityKey);

    if (!record.verify(this.network.magic)
        || record.encode().length > common.hnsr.MAX_RECORD_SIZE) {
      throw new Error('Invalid or oversized HNSR named route record.');
    }

    return record;
  }

  async publishNamedReplicated(
    bootstrap,
    tickets,
    authorization,
    servicePrivateKey,
    options = {}) {
    if (!this.enabled || !this.endpoint)
      throw new Error('HNSR endpoint role is disabled.');

    const record = this._createNamedRoute(
      tickets,
      authorization,
      servicePrivateKey,
      options);
    const replicas = options.replicas || common.hnsr.ROUTE_REPLICATION;
    const candidates = await this.findNodes(
      bootstrap,
      record.routeKey,
      Math.min(common.hnsr.MAX_CONTACTS, replicas * 2),
      options);
    const nodes = selectDiverseNodes(candidates, replicas, this.network);
    const stored = [];
    const failures = [];

    await Promise.all(nodes.map(async ({contact, peer}) => {
      try {
        await this._putRoute(peer, record);
        stored.push(contact);
      } catch (e) {
        failures.push({contact, error: e});
      }
    }));

    const required = options.minimumStores || common.hnsr.MIN_ROUTE_STORES;

    if (stored.length < required) {
      throw new Error(
        'HNSR named route replication quorum failed '
        + `(${stored.length}/${required}).`);
    }

    return {record, stored, failures};
  }

  async resolveNamedAuthority(rootName) {
    const name = canonicalRootName(rootName);

    if (!this.chain)
      throw new Error('HNSR named authority requires a validated HNS chain.');

    const height = this.chain.height;
    const nameHash = rules.hashName(name);
    const state = await this.chain.db.getNameStatus(nameHash, height);

    if (!state
        || !state.isClosed(height, this.network)
        || !Buffer.isBuffer(state.data)
        || state.data.length === 0) {
      throw new Error('HNSR root name is not active with authenticated data.');
    }

    const resource = Resource.decode(state.data);
    const rootKey = parseHNSRRootKey(resource);
    return {name, nameHash, rootKey, height, resource};
  }

  async lookupNamed(
    bootstrap,
    rootName,
    serviceName,
    maximum = 16,
    options = {}) {
    const authority = await this.resolveNamedAuthority(rootName);
    const service = canonicalServiceName(serviceName);
    const profile = options.profile || profiles.HNS_WEB_V1;
    const key = namedRouteKey(
      this.network.magic,
      authority.nameHash,
      service,
      profile);
    const lookup = await this.lookupReplicated(
      bootstrap,
      key,
      maximum,
      options);
    const records = lookup.records.filter((record) => {
      if (!record.verify(this.network.magic, now(), {
        rootKey: authority.rootKey,
        height: authority.height
      })) {
        return false;
      }

      const authorization = ServiceAuthorization.decode(record.authorization);
      return authorization.nameHash.equals(authority.nameHash)
        && authorization.serviceName === service
        && authorization.profile === profile;
    });

    return Object.assign({}, lookup, {
      authority,
      routeKey: key,
      records
    });
  }

  async registerWebService(rootName, authorization, handler) {
    if (!this.enabled || !this.endpoint || !this.web)
      throw new Error('HNSR web endpoint role is disabled.');

    if (!(authorization instanceof ServiceAuthorization)
        || authorization.profile !== profiles.HNS_WEB_V1
        || typeof handler !== 'function') {
      throw new Error('Invalid HNSR web service registration.');
    }

    const authority = await this.resolveNamedAuthority(rootName);

    if (!authorization.nameHash.equals(authority.nameHash)
        || !authorization.verify(
          authority.rootKey,
          this.network.magic,
          authority.height)) {
      throw new Error(
        'HNSR web service is not authorized by current HNS state.');
    }

    const key = `${authority.name}/${authorization.serviceName}`;
    const registration = {
      authority,
      authorization,
      handler,
      origin: webOrigin(
        authority.nameHash,
        authorization.serviceName,
        authorization.profile)
    };
    this.webServices.set(key, registration);
    return registration;
  }

  unregisterWebService(rootName, serviceName) {
    const root = canonicalRootName(rootName);
    const service = canonicalServiceName(serviceName);
    const key = `${root}/${service}`;
    return this.webServices.delete(key);
  }

  async requestNamedWeb(bootstrap, uri, options = {}) {
    const target = parseHNSRURI(uri);
    const lookup = await this.lookupNamed(
      bootstrap,
      target.rootName,
      target.serviceName,
      options.maximumRecords || 16,
      Object.assign({}, options, {profile: profiles.HNS_WEB_V1}));

    if (lookup.records.length === 0)
      throw new Error('No authenticated HNSR web routes were found.');

    const failures = [];

    for (const record of lookup.records) {
      try {
        const response = await this._requestWebRecord(
          record,
          lookup.authority,
          target,
          options);
        return Object.assign(response, {lookup, failures});
      } catch (e) {
        failures.push({record, error: e});
      }
    }

    const err = new Error('All authenticated HNSR web endpoints failed.');
    err.failures = failures;
    throw err;
  }

  async openNamedWeb(bootstrap, uri, options = {}) {
    const target = parseHNSRURI(uri);
    const lookup = await this.lookupNamed(
      bootstrap,
      target.rootName,
      target.serviceName,
      options.maximumRecords || 16,
      Object.assign({}, options, {profile: profiles.HNS_WEB_V1}));

    if (lookup.records.length === 0)
      throw new Error('No authenticated HNSR web routes were found.');

    const failures = [];

    for (const record of lookup.records) {
      try {
        const session = await this._openWebRecord(
          record,
          lookup.authority,
          target,
          options);
        return {session, lookup, failures, target};
      } catch (e) {
        failures.push({record, error: e});
      }
    }

    const err = new Error('All authenticated HNSR web endpoints failed.');
    err.failures = failures;
    throw err;
  }

  async _requestWebRecord(record, authority, target, options) {
    const session = await this._openWebRecord(
      record,
      authority,
      target,
      options);

    try {
      return await session.request(
        target.rootName,
        target.serviceName,
        Object.assign({}, options, {path: options.path || target.path}));
    } finally {
      session.close();
    }
  }

  async _openWebRecord(record, authority, target, options) {
    if (!record.verify(this.network.magic, now(), {
      rootKey: authority.rootKey,
      height: authority.height
    })) {
      throw new Error('Invalid authenticated HNSR web route.');
    }

    const authorization = ServiceAuthorization.decode(record.authorization);

    if (!authorization.nameHash.equals(authority.nameHash)
        || authorization.serviceName !== target.serviceName
        || authorization.profile !== profiles.HNS_WEB_V1) {
      throw new Error('HNSR web route does not match the requested authority.');
    }

    const circuit = await this.openRoute(record, options);
    const session = new HNSRWebSession(
      circuit,
      this.identityKey,
      record.delegation.endpointKey,
      webOrigin(
        authority.nameHash,
        target.serviceName,
        profiles.HNS_WEB_V1),
      record,
      options);

    return session.open();
  }

  _handleWebCircuit(socket, info) {
    const stream = BrontideStream.fromInbound(socket, this.identityKey);
    const parser = new HTTPMessageParser('request');
    let requests = 0;
    let queue = Promise.resolve();
    let timer = null;

    const armTimer = (duration) => {
      clearTimeout(timer);
      timer = setTimeout(() => socket.destroy(), duration);
    };
    const sendError = (statusCode, reason, detail) => {
      try {
        stream.write(encodeWebResponse({
          statusCode,
          reason,
          headers: {'Content-Type': 'text/plain; charset=utf-8'},
          body: `${detail}\n`
        }));
      } catch (e) {
        socket.destroy();
      }
    };
    const handle = async (request) => {
      requests += 1;

      if (requests > common.hnsr.MAX_WEB_REQUESTS_PER_CIRCUIT) {
        sendError(429, 'Too Many Requests', 'HNSR web request limit reached.');
        socket.destroy();
        return;
      }

      const rootName = request.headers.get('hnsr-authority');
      const serviceName = request.headers.get('hnsr-service');
      const host = request.headers.get('host');
      let root;
      let service;

      try {
        root = canonicalRootName(rootName);
        service = canonicalServiceName(serviceName);
      } catch (e) {
        sendError(421, 'Misdirected Request', 'Invalid HNSR authority.');
        return;
      }

      if (host !== `${service}.${root}`) {
        sendError(
          421,
          'Misdirected Request',
          'HNSR authority headers disagree.');
        return;
      }

      const registration = this.webServices.get(`${root}/${service}`);

      if (!registration) {
        sendError(421, 'Misdirected Request', 'Unknown HNSR web service.');
        return;
      }

      const response = await registration.handler({
        method: request.method,
        path: request.path,
        headers: Object.fromEntries(request.headers),
        body: request.body,
        origin: registration.origin,
        ticket: info.ticket
      });
      stream.write(encodeWebResponse(response));

      if ((request.headers.get('connection') || '').toLowerCase() === 'close')
        socket.destroy();
    };

    armTimer(common.hnsr.INNER_HANDSHAKE_TIMEOUT);
    stream.once('connect', () => armTimer(common.hnsr.WEB_IDLE_TIMEOUT));
    stream.on('data', (data) => {
      armTimer(common.hnsr.WEB_IDLE_TIMEOUT);

      try {
        for (const request of parser.feed(data)) {
          queue = queue.then(() => handle(request)).catch((error) => {
            this.emit('web error', error, info);
            sendError(500, 'Internal Server Error', 'HNSR web handler failed.');
          });
        }
      } catch (e) {
        this.emit('web error', e, info);
        sendError(400, 'Bad Request', e.message);
        socket.destroy();
      }
    });
    stream.on('error', (error) => {
      this.emit('web error', error, info);
      socket.destroy();
    });
    socket.once('error', (error) => {
      this.emit('web error', error, info);
      stream.destroy();
    });
    socket.once('close', () => {
      clearTimeout(timer);
      stream.destroy();
    });
    this.emit('web circuit', stream, info);
  }

  async lookup(peer, key, maximum = 16) {
    if (!this.enabled)
      throw new Error('HNSR is disabled.');

    if (!(peer.services & common.EXPERIMENTAL_HNSR_RENDEZVOUS_SERVICE))
      throw new Error('Peer does not advertise the HNSR rendezvous role.');

    if (!Buffer.isBuffer(key) || key.length !== 32)
      throw new Error('Invalid HNSR route key.');

    if (maximum < 1 || maximum > 16)
      throw new Error('Invalid HNSR route result limit.');

    const bw = bio.write(33);
    bw.writeBytes(key);
    bw.writeU8(maximum);
    const response = await this._request(
      peer,
      opcodes.GETROUTE,
      bw.render(),
      [opcodes.ROUTES]);
    const br = bio.read(response.body);
    const count = br.readU8();

    if (count > maximum)
      throw new Error('Too many HNSR route records returned.');

    const records = [];

    for (let i = 0; i < count; i++) {
      const size = br.readU16();

      if (size === 0 || size > common.hnsr.MAX_RECORD_SIZE)
        throw new Error('Invalid returned HNSR record length.');

      const record = RouteRecord.decode(br.readBytes(size));

      if (!record.routeKey.equals(key)
          || !record.verify(this.network.magic)) {
        throw new Error('Rendezvous peer returned an invalid HNSR record.');
      }

      records.push(record);
    }

    finish(br, 'HNSR routes response');
    return records;
  }

  async lookupReplicated(bootstrap, key, maximum = 16, options = {}) {
    const nodes = await this.findNodes(
      bootstrap,
      key,
      options.replicas || common.hnsr.ROUTE_REPLICATION,
      options);
    const failures = [];
    const records = new Map();

    await Promise.all(nodes.map(async ({contact, peer}) => {
      try {
        for (const record of await this.lookup(peer, key, maximum)) {
          const endpoint = record.delegation.endpointKey.toString('hex');
          const current = records.get(endpoint);

          if (!current || current.sequence < record.sequence)
            records.set(endpoint, record);
        }
      } catch (e) {
        failures.push({contact, error: e});
      }
    }));

    const result = Array.from(records.values())
      .sort((a, b) => b.sequence - a.sequence)
      .slice(0, maximum);

    return {
      records: result,
      queried: nodes.map(item => item.contact),
      failures
    };
  }

  async sampleRoutes(bootstrap, maximum = 16) {
    if (maximum < 1 || maximum > 16)
      throw new Error('Invalid HNSR sample result limit.');

    const seed = random.randomBytes(32);
    const target = hash(domains.SAMPLE, seed);
    const nodes = await this.findNodes(bootstrap, target, 3);
    const records = new Map();
    const failures = [];

    await Promise.all(nodes.map(async ({contact, peer}) => {
      const bw = bio.write(33);
      bw.writeU8(maximum);
      bw.writeBytes(seed);

      try {
        const response = await this._request(
          peer,
          opcodes.SAMPLEROUTES,
          bw.render(),
          [opcodes.ROUTES]);
        const br = bio.read(response.body);
        const count = br.readU8();

        if (count > maximum)
          throw new Error('Too many sampled HNSR routes returned.');

        for (let i = 0; i < count; i++) {
          const size = br.readU16();

          if (size === 0 || size > common.hnsr.MAX_RECORD_SIZE)
            throw new Error('Invalid sampled HNSR route length.');

          const record = RouteRecord.decode(br.readBytes(size));

          if (!record.verify(this.network.magic))
            throw new Error('Invalid sampled HNSR route.');

          const key = record.routeKey.toString('hex');
          const current = records.get(key);

          if (!current || current.sequence < record.sequence)
            records.set(key, record);
        }

        finish(br, 'HNSR sampled routes response');
      } catch (e) {
        failures.push({contact, error: e});
      }
    }));

    return {
      records: Array.from(records.values()).slice(0, maximum),
      queried: nodes.map(item => item.contact),
      failures
    };
  }

  async openRoute(record, options = {}) {
    if (!(record instanceof RouteRecord)
        || !record.verify(this.network.magic)) {
      throw new Error('Invalid HNSR route record.');
    }

    if (!this.pool)
      throw new Error('HNSR route opening requires a peer pool.');

    const failures = [];
    const tickets = record.tickets.map((ticket, index) => {
      return {ticket, index, score: this._relayScore(ticket)};
    }).sort((a, b) => a.score - b.score || a.index - b.index);

    for (const item of tickets) {
      const {ticket} = item;
      const started = Date.now();

      try {
        const peer = await this.pool.connectHNSRTicket(ticket);
        const circuit = await this.openCircuit(peer, ticket, options);
        this._markRelayHealth(ticket, true, Date.now() - started);
        return {ticket, relayPeer: peer, failures, ...circuit};
      } catch (e) {
        this._markRelayHealth(ticket, false, Date.now() - started);
        failures.push({ticket, error: e});
      }
    }

    const err = new Error('All HNSR relay candidates failed.');
    err.failures = failures;
    throw err;
  }

  _relayScore(ticket) {
    const key = ticket.relayKey.toString('hex');
    const health = this.relayHealth.get(key);

    if (!health)
      return 0;

    return health.failures * 100000
      + Math.min(health.latency, 60000)
      - Math.min(health.successes, 100);
  }

  _markRelayHealth(ticket, success, latency) {
    const key = ticket.relayKey.toString('hex');
    let health = this.relayHealth.get(key);

    if (!health) {
      health = {
        successes: 0,
        failures: 0,
        latency: 0,
        lastAttempt: 0
      };
      this.relayHealth.set(key, health);
    }

    health.lastAttempt = Date.now();

    if (success) {
      health.successes += 1;
      health.failures = Math.max(0, health.failures - 1);
      health.latency = health.latency === 0
        ? latency
        : Math.floor((health.latency * 3 + latency) / 4);
    } else {
      health.failures += 1;
    }
  }

  async openPeer(record, options = {}) {
    const circuit = await this.openRoute(record, options);
    const peer = await this.pool.addHNSROutbound(
      circuit.socket,
      circuit.ticket.endpointKey,
      circuit);
    return {peer, ...circuit};
  }

  async openCircuit(peer, ticket, options = {}) {
    if (!this.enabled)
      throw new Error('HNSR is disabled.');

    if (!(peer.services & common.EXPERIMENTAL_HNSR_RELAY_SERVICE))
      throw new Error('Peer does not advertise the HNSR relay role.');

    if (!ticket.verify(this.network.magic))
      throw new Error('Invalid or expired HNSR relay ticket.');

    const window = options.window || common.hnsr.DEFAULT_WINDOW;

    if (window < common.hnsr.MIN_WINDOW || window > common.hnsr.MAX_WINDOW)
      throw new Error('Invalid HNSR initial window.');

    const bw = bio.write(103);
    bw.writeBytes(ticket.id());
    bw.writeBytes(ticket.reservationID);
    bw.writeBytes(ticket.endpointKey);
    bw.writeU16(ticket.profile);
    bw.writeBytes(randomID(16));
    bw.writeU32(window);
    const response = await this._request(
      peer,
      opcodes.OPEN,
      bw.render(),
      [opcodes.OPENED]);
    const br = bio.read(response.body);
    const circuitID = br.readBytes(8);
    const acceptedWindow = br.readU32();
    const endpointNonce = br.readBytes(16);
    finish(br, 'HNSR opened response');

    if (isZero(circuitID)
        || isZero(endpointNonce)
        || acceptedWindow < common.hnsr.MIN_WINDOW
        || acceptedWindow > window) {
      throw new Error('Invalid HNSR opened response.');
    }

    const socket = new CircuitSocket(this, peer, circuitID, acceptedWindow);
    this.sockets.set(peerKey(peer, circuitID), socket);
    setImmediate(() => socket.connect());

    return {socket, circuitID, endpointNonce};
  }

  _handleReserve(peer, packet, renewal) {
    if (!this.relay)
      throw new Error('HNSR relay role is disabled.');

    let previous = null;
    let body = packet.body;

    if (renewal) {
      const br = bio.read(packet.body);
      const reservationID = br.readBytes(16);
      body = br.readBytes(br.left());
      previous = this.reservations.get(reservationID.toString('hex'));

      if (!previous
          || previous.peer !== peer
          || previous.ticket.expiresAt <= now()) {
        throw new Error('Unknown HNSR reservation to renew.');
      }
    }

    const request = ReserveRequest.decode(body);

    if (request.profile === profiles.HNS_WEB_V1 && !this.web) {
      this._sendError(
        peer,
        packet.contextID,
        errors.PROFILE_DISABLED,
        'HNSR web relay profile is disabled.');
      return;
    }

    const validSignature = renewal
      ? request.verifyRenewal(
        this.network.magic,
        this.publicKey,
        packet.contextID,
        previous.ticket.reservationID)
      : request.verify(
        this.network.magic,
        this.publicKey,
        packet.contextID);

    if (!validSignature) {
      throw new Error('Invalid HNSR reservation signature.');
    }

    const maximumCircuits = request.profile === profiles.HNS_WEB_V1
      ? 4
      : common.hnsr.MAX_CIRCUITS;

    if (!validProfile(request.profile)
        || request.lifetime < 300
        || request.lifetime > common.hnsr.MAX_TICKET_LIFETIME
        || request.maxCircuits < 1
        || request.maxCircuits > maximumCircuits
        || request.maxBytes < 1
        || request.maxBytes > 67108864) {
      throw new Error('HNSR reservation exceeds PoC policy.');
    }

    if (previous
        && !previous.ticket.endpointKey.equals(request.endpointKey)) {
      throw new Error('HNSR renewal endpoint key mismatch.');
    }

    const renewalAllowance = previous ? 1 : 0;
    const reservationCount = this.reservations.size + this.provisional.size;

    if (reservationCount
        >= common.hnsr.MAX_RESERVATIONS + renewalAllowance) {
      throw new Error('HNSR relay reservation capacity reached.');
    }

    let provisionalCount = 0;
    let peerCount = 0;

    for (const item of this.provisional.values()) {
      if (item.peer !== peer)
        continue;
      provisionalCount += 1;
      peerCount += 1;
    }

    for (const item of this.reservations.values()) {
      if (item.peer === peer)
        peerCount += 1;
    }

    if (provisionalCount >= 2)
      throw new Error('HNSR provisional reservation capacity reached.');

    if (peerCount
        >= common.hnsr.MAX_RESERVATIONS_PER_PEER + renewalAllowance) {
      throw new Error('HNSR per-peer reservation capacity reached.');
    }

    const timestamp = now();
    const ticket = new RelayTicket({
      networkMagic: this.network.magic,
      profile: request.profile,
      transport: 0,
      hostType: 1,
      host: this.relayHost,
      port: this.relayPort,
      relayKey: this.publicKey,
      endpointKey: request.endpointKey,
      reservationID: randomID(16),
      issuedAt: timestamp,
      expiresAt: timestamp + request.lifetime,
      maxActiveCircuits: request.maxCircuits,
      maxBytesPerCircuit: request.maxBytes,
      maxTotalBytes: request.maxBytes * request.maxCircuits,
      flags: 0
    }).signRelay(this.identityKey);
    const key = ticket.reservationID.toString('hex');

    this.provisional.set(key, {
      peer,
      ticket,
      replaces: previous ? previous.ticket.reservationID.toString('hex') : null
    });
    this._send(peer, opcodes.OFFER, packet.contextID, ticket.encode());
  }

  _handleConfirm(peer, packet) {
    if (!this.relay)
      throw new Error('HNSR relay role is disabled.');

    const br = bio.read(packet.body);
    const reservationID = br.readBytes(16);
    const endpointSignature = readSignature(br, 'reservation confirmation');
    finish(br, 'HNSR reservation confirmation');
    const key = reservationID.toString('hex');
    const item = this.provisional.get(key);

    if (!item || item.peer !== peer)
      throw new Error('Unknown HNSR provisional reservation.');

    const ticket = item.ticket;
    ticket.endpointSignature = endpointSignature;

    if (!ticket.verify(this.network.magic))
      throw new Error('Invalid HNSR endpoint confirmation.');

    this.provisional.delete(key);
    this.reservations.set(key, {
      peer,
      ticket,
      activeCircuits: 0,
      totalBytes: 0,
      retired: false
    });

    if (item.replaces) {
      const previous = this.reservations.get(item.replaces);

      if (previous)
        previous.retired = true;
    }

    const bw = bio.write(56);
    bw.writeBytes(ticket.reservationID);
    bw.writeBytes(ticket.id());
    bw.writeU64(ticket.expiresAt);
    this._send(peer, opcodes.CONFIRMED, packet.contextID, bw.render());
  }

  _handleFindNode(peer, packet) {
    if (!this.rendezvous)
      throw new Error('HNSR rendezvous role is disabled.');

    const br = bio.read(packet.body);
    const target = br.readBytes(32);
    const maximum = br.readU8();
    finish(br, 'HNSR find-node request');

    if (maximum < 1 || maximum > common.hnsr.MAX_CONTACTS)
      throw new Error('Invalid HNSR rendezvous result limit.');

    const contacts = this._closestContacts(target, maximum);
    const bw = bio.write(1 + contacts.length * 100);
    bw.writeU8(contacts.length);

    for (const contact of contacts)
      bw.writeBytes(contact.encode());

    this._send(peer, opcodes.NODES, packet.contextID, bw.render());
  }

  _sendRoutes(peer, contextID, records) {
    let size = 1;

    for (const raw of records)
      size += 2 + raw.length;

    if (size > common.hnsr.MAX_PACKET_SIZE - 12)
      throw new Error('HNSR routes response exceeds packet limit.');

    const bw = bio.write(size);
    bw.writeU8(records.length);

    for (const raw of records) {
      bw.writeU16(raw.length);
      bw.writeBytes(raw);
    }

    this._send(peer, opcodes.ROUTES, contextID, bw.render());
  }

  _handleSampleRoutes(peer, packet) {
    if (!this.rendezvous)
      throw new Error('HNSR rendezvous role is disabled.');

    const br = bio.read(packet.body);
    const maximum = br.readU8();
    const seed = br.readBytes(32);
    finish(br, 'HNSR sample-routes request');

    if (maximum < 1 || maximum > 16 || isZero(seed))
      throw new Error('Invalid HNSR sample-routes parameters.');

    this._sendRoutes(
      peer,
      packet.contextID,
      this.store.sample(maximum, seed));
  }

  _handleWithdraw(peer, packet) {
    if (!this.relay)
      throw new Error('HNSR relay role is disabled.');

    const br = bio.read(packet.body);
    const reservationID = br.readBytes(16);
    const ticketID = br.readBytes(32);
    const signature = readSignature(br, 'reservation withdrawal');
    finish(br, 'HNSR reservation withdrawal');
    const key = reservationID.toString('hex');
    const reservation = this.reservations.get(key);

    if (!reservation
        || reservation.peer !== peer
        || !reservation.ticket.id().equals(ticketID)
        || !verify(
          domains.WITHDRAW,
          withdrawData(
            this.network.magic,
            this.publicKey,
            packet.contextID,
            reservationID,
            ticketID),
          signature,
          reservation.ticket.endpointKey)) {
      throw new Error('Invalid HNSR reservation withdrawal.');
    }

    const states = new Set();

    for (const circuit of this.relayCircuits.values()) {
      if (circuit.state.reservation === reservation)
        states.add(circuit.state);
    }

    for (const state of states)
      this._closeRelayCircuit(state, errors.SHUTDOWN);

    this.reservations.delete(key);
    const bw = bio.write(56);
    bw.writeBytes(reservationID);
    bw.writeBytes(ticketID);
    bw.writeU64(0);
    this._send(peer, opcodes.CONFIRMED, packet.contextID, bw.render());
  }

  _handlePutRoute(peer, packet) {
    if (!this.rendezvous)
      throw new Error('HNSR rendezvous role is disabled.');

    const br = bio.read(packet.body);
    const key = br.readBytes(32);
    const size = br.readU16();

    if (size === 0 || size > common.hnsr.MAX_RECORD_SIZE || br.left() !== size)
      throw new Error('Invalid HNSR put-route length.');

    const raw = br.readBytes(size);
    let status = 0;
    let storedUntil = 0;

    try {
      const record = RouteRecord.decode(raw);
      const signatures = 2 + record.tickets.length * 2
        + (record.authorityType === 1 ? 1 : 0);

      if (!this._admitVerifications(peer, signatures)) {
        status = errors.RATE_LIMITED;
        throw new Error('HNSR signature-verification budget exhausted.');
      }

      const sourceKey = peerPublicKey(peer);
      const source = sourceKey
        ? sourceKey.toString('hex')
        : `peer:${peer.id}`;
      const prefix = peerAddressPrefix(peer);
      storedUntil = this.store.put(
        key,
        raw,
        now(),
        source,
        prefix,
        record);
    } catch (e) {
      if (status === 0)
        status = errors.INVALID;
      this.emit('store reject', e, peer);
    }

    const bw = bio.write(10);
    bw.writeU16(status);
    bw.writeU64(storedUntil);
    this._send(peer, opcodes.PUTRESULT, packet.contextID, bw.render());
  }

  _handleGetRoute(peer, packet) {
    if (!this.rendezvous)
      throw new Error('HNSR rendezvous role is disabled.');

    const br = bio.read(packet.body);
    const key = br.readBytes(32);
    const maximum = br.readU8();
    finish(br, 'HNSR get-route request');

    if (maximum < 1 || maximum > 16)
      throw new Error('Invalid HNSR route result limit.');

    this._sendRoutes(
      peer,
      packet.contextID,
      this.store.get(key, maximum));
  }

  _admitCircuit(requester, reservation) {
    const states = new Set(this.opening.values());

    for (const circuit of this.relayCircuits.values())
      states.add(circuit.state);

    const address = peerIPAddress(requester);
    const group = peerNetgroup(requester);
    const endpoint = reservation.ticket.endpointKey;
    const profile = reservation.ticket.profile;
    let requesterCount = 0;
    let addressCount = 0;
    let groupCount = 0;
    let endpointCount = 0;
    let profileCount = 0;

    for (const state of states) {
      if (state.requesterPeer === requester)
        requesterCount += 1;

      if (peerIPAddress(state.requesterPeer) === address)
        addressCount += 1;

      if (peerNetgroup(state.requesterPeer) === group)
        groupCount += 1;

      if (state.ticket.endpointKey.equals(endpoint))
        endpointCount += 1;

      if (state.ticket.profile === profile)
        profileCount += 1;
    }

    if (states.size >= common.hnsr.MAX_ACTIVE_RELAY_CIRCUITS
        || requesterCount >= common.hnsr.MAX_REQUESTER_CIRCUITS
        || addressCount >= common.hnsr.MAX_IP_CIRCUITS
        || groupCount >= common.hnsr.MAX_NETGROUP_CIRCUITS
        || endpointCount >= common.hnsr.MAX_ENDPOINT_CIRCUITS
        || (profile === profiles.HNS_WEB_V1
          && profileCount >= common.hnsr.MAX_ACTIVE_WEB_CIRCUITS)) {
      this.circuitRejected += 1;
      return false;
    }

    return true;
  }

  _handleOpen(peer, packet) {
    if (!this.relay)
      throw new Error('HNSR relay role is disabled.');

    const br = bio.read(packet.body);
    const ticketID = br.readBytes(32);
    const reservationID = br.readBytes(16);
    const endpointKey = br.readBytes(33);
    const profile = br.readU16();
    const requesterNonce = br.readBytes(16);
    const initialWindow = br.readU32();
    finish(br, 'HNSR open request');

    if (isZero(requesterNonce)
        || initialWindow < common.hnsr.MIN_WINDOW
        || initialWindow > common.hnsr.MAX_WINDOW) {
      throw new Error('Invalid HNSR open parameters.');
    }

    const reservation = this.reservations.get(
      reservationID.toString('hex'));

    if (!reservation
        || reservation.retired
        || reservation.ticket.expiresAt <= now()
        || !reservation.ticket.id().equals(ticketID)
        || !reservation.ticket.endpointKey.equals(endpointKey)
        || reservation.ticket.profile !== profile
        || reservation.activeCircuits
          >= reservation.ticket.maxActiveCircuits
        || reservation.peer.destroyed) {
      this._sendError(
        peer,
        packet.contextID,
        errors.ENDPOINT_GONE,
        'HNSR reservation is unavailable.');
      return;
    }

    if (!this._admitCircuit(peer, reservation)) {
      this._sendError(
        peer,
        packet.contextID,
        errors.CAPACITY,
        'HNSR requester or topology circuit limit reached.');
      return;
    }

    const circuitID = randomID(8);
    const key = peerKey(reservation.peer, circuitID);
    const state = {
      requesterPeer: peer,
      requesterContext: Buffer.from(packet.contextID),
      endpointPeer: reservation.peer,
      circuitID,
      ticket: reservation.ticket,
      reservation,
      requesterNonce,
      initialWindow,
      totalBytes: 0,
      timer: null
    };

    state.timer = setTimeout(() => {
      this.opening.delete(key);
      this._sendError(
        peer,
        packet.contextID,
        errors.TIMEOUT,
        'HNSR endpoint did not accept the circuit.');
    }, 10000);

    this.opening.set(key, state);

    const bw = bio.write(62);
    bw.writeBytes(ticketID);
    bw.writeBytes(packet.contextID);
    bw.writeU16(profile);
    bw.writeBytes(requesterNonce);
    bw.writeU32(initialWindow);
    this._send(
      reservation.peer,
      opcodes.INCOMING,
      circuitID,
      bw.render());
  }

  _handleIncoming(peer, packet) {
    if (!this.endpoint)
      throw new Error('HNSR endpoint role is disabled.');

    const br = bio.read(packet.body);
    const ticketID = br.readBytes(32);
    const openRequestID = br.readBytes(8);
    const profile = br.readU16();
    const requesterNonce = br.readBytes(16);
    const initialWindow = br.readU32();
    finish(br, 'HNSR incoming request');
    const item = this.endpointTickets.get(ticketID.toString('hex'));

    if (!item
        || item.peer !== peer
        || item.ticket.profile !== profile
        || item.ticket.expiresAt <= now()
        || isZero(openRequestID)
        || isZero(requesterNonce)
        || initialWindow < common.hnsr.MIN_WINDOW
        || initialWindow > common.hnsr.MAX_WINDOW) {
      throw new Error('Invalid HNSR incoming circuit.');
    }

    if (profile === profiles.HNS_WEB_V1
        && (!this.web || this.webServices.size === 0)) {
      throw new Error('HNSR web endpoint profile is disabled.');
    }

    if (!validProfile(profile))
      throw new Error('Unsupported HNSR incoming profile.');

    const endpointNonce = randomID(16);
    const socket = new CircuitSocket(
      this,
      peer,
      packet.contextID,
      initialWindow);
    this.sockets.set(peerKey(peer, packet.contextID), socket);
    const info = {
      circuitID: Buffer.from(packet.contextID),
      ticket: item.ticket,
      requesterNonce,
      endpointNonce,
      profile
    };

    if (profile === profiles.HNS_NODE_V1)
      this.emit('circuit', socket, info);
    else
      this._handleWebCircuit(socket, info);

    const bw = bio.write(20);
    bw.writeU32(initialWindow);
    bw.writeBytes(endpointNonce);
    this._send(peer, opcodes.ACCEPT, packet.contextID, bw.render());
  }

  _handleAccept(peer, packet) {
    if (!this.relay)
      throw new Error('HNSR relay role is disabled.');

    const key = peerKey(peer, packet.contextID);
    const state = this.opening.get(key);

    if (!state || state.endpointPeer !== peer)
      throw new Error('Unknown HNSR pending circuit.');

    const br = bio.read(packet.body);
    const acceptedWindow = br.readU32();
    const endpointNonce = br.readBytes(16);
    finish(br, 'HNSR accept response');

    if (acceptedWindow < common.hnsr.MIN_WINDOW
        || acceptedWindow > state.initialWindow
        || isZero(endpointNonce)) {
      throw new Error('Invalid HNSR accept response.');
    }

    clearTimeout(state.timer);
    this.opening.delete(key);
    state.reservation.activeCircuits += 1;
    state.acceptedWindow = acceptedWindow;
    state.endpointNonce = endpointNonce;
    state.credit = {
      requester: acceptedWindow,
      endpoint: acceptedWindow
    };
    state.queuedBytes = 0;
    state.closed = false;
    this.relayCircuits.set(
      peerKey(state.requesterPeer, state.circuitID),
      {state, other: state.endpointPeer, side: 'requester'});
    this.relayCircuits.set(
      peerKey(state.endpointPeer, state.circuitID),
      {state, other: state.requesterPeer, side: 'endpoint'});

    const bw = bio.write(28);
    bw.writeBytes(state.circuitID);
    bw.writeU32(acceptedWindow);
    bw.writeBytes(endpointNonce);
    this._send(
      state.requesterPeer,
      opcodes.OPENED,
      state.requesterContext,
      bw.render());
  }

  _handleData(peer, packet) {
    if (packet.body.length === 0
        || packet.body.length > common.hnsr.MAX_DATA_SIZE) {
      throw new Error('Invalid HNSR DATA size.');
    }

    const key = peerKey(peer, packet.contextID);
    const circuit = this.relayCircuits.get(key);

    if (circuit) {
      if (packet.body.length > circuit.state.credit[circuit.side]) {
        this._closeRelayCircuit(circuit.state, errors.FLOW_CONTROL);
        return;
      }

      circuit.state.credit[circuit.side] -= packet.body.length;
      circuit.state.totalBytes += packet.body.length;
      circuit.state.reservation.totalBytes += packet.body.length;

      if (circuit.state.totalBytes
          > circuit.state.ticket.maxBytesPerCircuit
          || circuit.state.reservation.totalBytes
          > circuit.state.ticket.maxTotalBytes) {
        this._closeRelayCircuit(circuit.state, errors.BYTE_LIMIT);
        return;
      }

      this._queueRelayData(circuit, packet.body);
      return;
    }

    const socket = this.sockets.get(key);

    if (!socket)
      throw new Error('Unknown HNSR circuit DATA.');

    socket.receive(Buffer.from(packet.body));
  }

  _queueRelayData(circuit, data) {
    const state = circuit.state;

    if (state.closed)
      return;

    if (state.queuedBytes + data.length > common.hnsr.MAX_CIRCUIT_QUEUE) {
      this.relayDrops += 1;
      this._closeRelayCircuit(state, errors.CAPACITY);
      return;
    }

    if (this.relayQueueBytes + data.length > common.hnsr.MAX_RELAY_QUEUE) {
      this.relayDrops += 1;
      this._closeRelayCircuit(state, errors.CAPACITY);
      return;
    }

    const raw = Buffer.from(data);
    state.queuedBytes += raw.length;
    this.relayQueueBytes += raw.length;
    this.maxRelayQueuedBytes = Math.max(
      this.maxRelayQueuedBytes,
      this.relayQueueBytes);
    this.relayQueue.push({
      state,
      other: circuit.other,
      contextID: Buffer.from(state.circuitID),
      profile: state.ticket.profile,
      data: raw
    });
    this._scheduleRelayFlush();
  }

  _scheduleRelayFlush(delay = 0) {
    if (this.relayFlushScheduled || !this.opened)
      return;

    this.relayFlushScheduled = true;
    this.relayFlushDelayed = delay > 0;
    const callback = () => {
      this.relayFlushHandle = null;
      this.relayFlushScheduled = false;
      this.relayFlushDelayed = false;
      this._flushRelayQueue();
    };

    if (delay > 0)
      this.relayFlushHandle = setTimeout(callback, delay);
    else
      this.relayFlushHandle = setImmediate(callback);
  }

  _refillRelayTokens() {
    const timestamp = Date.now();
    const elapsed = Math.max(0, timestamp - this.relayTokens.updated);

    this.relayTokens.updated = timestamp;
    this.relayTokens.node = Math.min(
      common.hnsr.RELAY_BURST,
      this.relayTokens.node
        + elapsed * common.hnsr.NODE_RELAY_BYTES_PER_SECOND / 1000);
    this.relayTokens.web = Math.min(
      common.hnsr.RELAY_BURST,
      this.relayTokens.web
        + elapsed * common.hnsr.WEB_RELAY_BYTES_PER_SECOND / 1000);
  }

  _pruneRelayQueue() {
    const active = [];

    for (const item of this.relayQueue) {
      if (item.state.closed) {
        this.relayQueueBytes -= item.data.length;
        continue;
      }

      active.push(item);
    }

    this.relayQueue = active;
  }

  _flushRelayProfile(profile, maximum) {
    const token = profile === profiles.HNS_WEB_V1 ? 'web' : 'node';
    let bytes = 0;

    while (bytes < maximum) {
      const index = this.relayQueue.findIndex((item) => {
        return item.profile === profile;
      });

      if (index === -1)
        break;

      const item = this.relayQueue[index];

      if (item.data.length > maximum - bytes
          || item.data.length > this.relayTokens[token]) {
        break;
      }

      this.relayQueue.splice(index, 1);
      item.state.queuedBytes -= item.data.length;
      this.relayQueueBytes -= item.data.length;
      this.relayTokens[token] -= item.data.length;
      bytes += item.data.length;
      this.relayBytes += item.data.length;
      this.relayFrames += 1;

      if (this.relayPayloads.length < 128)
        this.relayPayloads.push(Buffer.from(item.data));

      this._send(
        item.other,
        opcodes.DATA,
        item.contextID,
        item.data);
    }

    return bytes;
  }

  _flushRelayQueue() {
    this.relayFlushes += 1;
    this._refillRelayTokens();
    this._pruneRelayQueue();

    const node = profiles.HNS_NODE_V1;
    const web = profiles.HNS_WEB_V1;
    const preferred = this.relayScheduleCursor % 4 === 3 ? web : node;
    const alternate = preferred === node ? web : node;
    let bytes = this._flushRelayProfile(
      preferred,
      common.hnsr.RELAY_BURST);

    if (bytes < common.hnsr.RELAY_BURST) {
      bytes += this._flushRelayProfile(
        alternate,
        common.hnsr.RELAY_BURST - bytes);
    }

    this.relayScheduleCursor += 1;

    if (this.relayQueue.length > 0)
      this._scheduleRelayFlush(bytes === 0 ? 10 : 0);
  }

  _handleWindow(peer, packet) {
    const br = bio.read(packet.body);
    const credit = br.readU32();
    finish(br, 'HNSR window update');

    if (credit === 0 || credit > common.hnsr.MAX_WINDOW)
      throw new Error('Invalid HNSR window credit.');

    const key = peerKey(peer, packet.contextID);
    const circuit = this.relayCircuits.get(key);

    if (circuit) {
      const side = circuit.side === 'requester' ? 'endpoint' : 'requester';

      if (circuit.state.credit[side] + credit > common.hnsr.MAX_WINDOW) {
        this._closeRelayCircuit(circuit.state, errors.FLOW_CONTROL);
        return;
      }

      circuit.state.credit[side] += credit;
      this._send(
        circuit.other,
        opcodes.WINDOW,
        packet.contextID,
        packet.body);
      return;
    }

    const socket = this.sockets.get(key);

    if (!socket)
      throw new Error('Unknown HNSR circuit window.');

    socket.addCredit(credit);
  }

  _handleClose(peer, packet) {
    const br = bio.read(packet.body);
    br.readU16();
    const size = br.readU8();

    if (size > 128)
      throw new Error('HNSR close detail exceeds the limit.');

    br.readBytes(size);
    finish(br, 'HNSR close');
    const key = peerKey(peer, packet.contextID);
    const circuit = this.relayCircuits.get(key);

    if (circuit) {
      this._send(
        circuit.other,
        opcodes.CLOSE,
        packet.contextID,
        packet.body);
      this._dropRelayCircuit(circuit.state);
      return;
    }

    const socket = this.sockets.get(key);

    if (socket) {
      this.sockets.delete(key);
      socket.remoteClose();
    }
  }

  _closeRelayCircuit(state, reason) {
    const bw = bio.write(3);
    bw.writeU16(reason);
    bw.writeU8(0);
    const body = bw.render();
    this._send(state.requesterPeer, opcodes.CLOSE, state.circuitID, body);
    this._send(state.endpointPeer, opcodes.CLOSE, state.circuitID, body);
    this._dropRelayCircuit(state);
  }

  _dropRelayCircuit(state) {
    state.closed = true;
    this.relayCircuits.delete(peerKey(state.requesterPeer, state.circuitID));
    this.relayCircuits.delete(peerKey(state.endpointPeer, state.circuitID));

    if (state.queuedBytes > 0) {
      const retained = [];

      for (const item of this.relayQueue) {
        if (item.state === state)
          this.relayQueueBytes -= item.data.length;
        else
          retained.push(item);
      }

      this.relayQueue = retained;
      state.queuedBytes = 0;
    }

    if (state.reservation.activeCircuits > 0)
      state.reservation.activeCircuits -= 1;
  }

  _dropSocket(peer, contextID) {
    this.sockets.delete(peerKey(peer, contextID));
  }

  cancelPeer(peer) {
    const prefix = `${peer.id}:`;

    this.admission.delete(peer.id);

    for (const [key, pending] of this.pending) {
      if (!key.startsWith(prefix))
        continue;
      clearTimeout(pending.timer);
      pending.reject(new Error('HNSR peer disconnected.'));
      this.pending.delete(key);
    }

    for (const [key, item] of this.provisional) {
      if (item.peer === peer)
        this.provisional.delete(key);
    }

    for (const [key, item] of this.reservations) {
      if (item.peer === peer)
        this.reservations.delete(key);
    }

    for (const [key, item] of this.endpointTickets) {
      if (item.peer === peer)
        this.endpointTickets.delete(key);
    }

    for (const [key, state] of this.opening) {
      if (state.requesterPeer !== peer && state.endpointPeer !== peer)
        continue;
      clearTimeout(state.timer);
      this.opening.delete(key);
    }

    const states = new Set();

    for (const circuit of this.relayCircuits.values()) {
      if (circuit.state.requesterPeer === peer
          || circuit.state.endpointPeer === peer) {
        states.add(circuit.state);
      }
    }

    for (const state of states)
      this._closeRelayCircuit(state, errors.ENDPOINT_GONE);

    for (const [key, socket] of this.sockets) {
      if (!key.startsWith(prefix))
        continue;
      this.sockets.delete(key);
      socket.remoteClose();
    }
  }
}

exports.opcodes = opcodes;
exports.errors = errors;
exports.profiles = profiles;
exports.routeKey = routeKey;
exports.namedRouteKey = namedRouteKey;
exports.canonicalServiceName = canonicalServiceName;
exports.canonicalRootName = canonicalRootName;
exports.parseHNSRRootKey = parseHNSRRootKey;
exports.parseHNSRURI = parseHNSRURI;
exports.webOrigin = webOrigin;
exports.HTTPMessageParser = HTTPMessageParser;
exports.HNSRWebSession = HNSRWebSession;
exports.encodeWebRequest = encodeWebRequest;
exports.encodeWebResponse = encodeWebResponse;
exports.rendezvousNodeID = rendezvousNodeID;
exports.compareDistance = compareDistance;
exports.bucketIndex = bucketIndex;
exports.addressPrefix = addressPrefix;
exports.selectDiverseNodes = selectDiverseNodes;
exports.RendezvousContact = RendezvousContact;
exports.ReserveRequest = ReserveRequest;
exports.RelayTicket = RelayTicket;
exports.ServiceAuthorization = ServiceAuthorization;
exports.EndpointDelegation = EndpointDelegation;
exports.RouteRecord = RouteRecord;
exports.RoutingTable = RoutingTable;
exports.RouteStore = RouteStore;
exports.CircuitSocket = CircuitSocket;
exports.HNSRService = HNSRService;
