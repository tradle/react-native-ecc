'use strict'

import { NativeModules, Platform } from 'react-native'
import { Buffer } from 'buffer'
import hasher from 'hash.js'
const { RNECC } = NativeModules
const preHash = RNECC.preHash !== false
const isAndroid = Platform.OS === 'android'
const encoding = 'base64'
const curves = {
  p192: 192,
  p224: 224,
  p256: 256,
  p384: 384,
  secp192r1: 192,
  secp256r1: 256,
  secp224r1: 224,
  secp384r1: 384
  // p521: 521 // should be supported, but SecKeyRawSign fails with OSStatus -1
}

let serviceID
let accessGroup

module.exports = {
  encoding,
  curves,
  setServiceID,
  getServiceID,
  setAccessGroup,
  getAccessGroup,
  keyPair,
  sign,
  verify,
  lookupKey,
  hasKey,
  keyFromPublic
}

function setServiceID (id) {
  if (serviceID) throw new Error('serviceID can only be set once')

  serviceID = id
}

function getServiceID () {
  return serviceID
}

function setAccessGroup (val) {
  if (accessGroup) throw new Error('accessGroup can only be set once')

  accessGroup = val
}

function getAccessGroup () {
  return accessGroup
}

/**
 * generates a new key pair, calls back with pub key
 * @param  {String}   curve - elliptic curve
 * @param  {Function} cb - calls back with a new key with the API: { sign, verify, pub }
 */
function keyPair (curve, cb) {
  checkServiceID()
  assert(typeof curve === 'string')
  assert(typeof cb === 'function')
  if (!(curve in curves)) throw new Error('unsupported curve')

  let sizeInBits = curves[curve]
  RNECC.generateECPair({
    curve: curve,
    bits: sizeInBits,
    service: serviceID,
    accessGroup: accessGroup
  }, function (err, base64pubKey) {
    cb(convertError(err), base64pubKey && keyFromPublic(toBuffer(base64pubKey)))
  })
}

/**
 * signs a hash
 * @param  {Buffer|String}   options.pubKey - pubKey corresponding to private key to sign hash with
 * @param  {Buffer|String}   options.data - data to sign
 * @param  {String}          options.algorithm - algorithm to use to hash data before signing
 * @param  {Function} cb
 */
function sign ({ pubKey, data, algorithm }, cb) {
  checkServiceID()
  assert(Buffer.isBuffer(pubKey) || typeof pubKey === 'string')
  assert(Buffer.isBuffer(data) || typeof data === 'string')

  checkNotCompact(pubKey)

  const opts = {
    service: serviceID,
    accessGroup: accessGroup,
    pub: pubKey
  }

  assert(typeof cb === 'function')
  if (preHash) {
    opts.hash = getHash(data, algorithm)
  } else {
    opts.data = data
    opts.algorithm = algorithm
  }

  RNECC.sign(normalizeOpts(opts), normalizeCallback(cb))
}

/**
 * verifies a signature
 * @param  {Buffer|String}   options.pubKey - pubKey corresponding to private key to sign hash with
 * @param  {Buffer|String}   options.data - signed data
 * @param  {String}          options.algorithm - algorithm used to hash data before it was signed
 * @param  {Buffer}          options.sig - signature
 * @param  {Function} cb
 */
function verify ({ pubKey, data, algorithm, sig }, cb) {
  checkNotCompact(pubKey)

  assert(Buffer.isBuffer(data) || typeof data === 'string')
  assert(typeof pubKey === 'string' || Buffer.isBuffer(pubKey))
  assert(typeof cb === 'function')

  const opts = {
    pub: pubKey,
    sig,
  }

  if (preHash) {
    opts.hash = getHash(data, algorithm)
  } else {
    opts.data = data
    opts.algorithm = algorithm
  }

  RNECC.verify(normalizeOpts(opts), normalizeCallback(cb))
}

function normalizeOpts (opts) {
  ;['data', 'hash', 'pub', 'sig'].forEach(prop => {
    if (opts[prop]) opts[prop] = toString(opts[prop])
  })

  return opts
}

function hasKey (pubKey, cb) {
  checkServiceID()
  assert(Buffer.isBuffer(pubKey) || typeof pubKey === 'string')
  checkNotCompact(pubKey)
  pubKey = toString(pubKey)
  cb = normalizeCallback(cb)
  if (isAndroid) return RNECC.hasKey(pubKey, cb)

  RNECC.hasKey({
    service: serviceID,
    accessGroup: accessGroup,
    pub: pubKey
  }, cb)
}

function lookupKey (pubKey, cb) {
  hasKey(pubKey, function (err, exists) {
    if (err) return cb(convertError(err))
    if (exists) return cb(null, keyFromPublic(pubKey))

    cb(new Error('NotFound'))
  })
}

/**
 * Returns a key with the API as the one returned by keyPair(...)
 * @param  {Buffer} pub pubKey buffer for existing key (created with keyPair(...))
 * @return {Object} key
 */
function keyFromPublic (pubKey) {
  checkNotCompact(pubKey)
  let base64pub = toString(pubKey)
  return {
    sign: (opts, cb) => {
      sign({ ...opts, pubKey: base64pub }, cb)
    },
    verify: (opts, cb) => {
      verify({ ...opts, pubKey: base64pub }, cb)
    },
    pub: pubKey
  }
}

function assert (statement, errMsg) {
  if (!statement) throw new Error(errMsg || 'assertion failed')
}

function toString (buf) {
  if (typeof buf === 'string') return buf
  if (Buffer.isBuffer(buf)) return buf.toString(encoding)

  return buf.toString()
}

function toBuffer (str) {
  if (Buffer.isBuffer(str)) return str
  if (typeof str === 'string') return new Buffer(str, encoding)

  throw new Error('expected string or buffer')
}

function checkServiceID () {
  if (!serviceID) {
    throw new Error('call setServiceID() first')
  }
}

function convertError (error) {
  if (!error) {
    return null;
  }

  var message = error.message || (typeof error === 'string' ? error : JSON.stringify(error))
  var out = new Error(message)
  out.key = error.key // flow doesn't like this :(
  return out
}

function normalizeCallback (cb) {
  return function (err, result) {
    if (err) return cb(convertError(err))

    result = typeof result === 'string'
      ? toBuffer(result)
      : result

    return cb(null, result)
  }
}

function getHash (data, algorithm) {
  if (!algorithm) return data

  const arr = hasher[algorithm]().update(data).digest()
  return new Buffer(arr)
}

function checkNotCompact (pub) {
  assert(toBuffer(pub)[0] === 4, 'compact keys not supported')
}
