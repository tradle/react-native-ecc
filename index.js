'use strict'

import { NativeModules } from 'react-native'
import { Buffer } from 'buffer'
const RNECC = NativeModules.RNECC
const encoding = 'base64'
let serviceID
let accessGroup

module.exports = {
  encoding,
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
    accessGroup: accessGroup,
    bits: sizeInBits
  }, function (err, base64pubKey) {
    cb(convertError(err), base64pubKey && keyFromPublic(toBuffer(base64pubKey)))
  })
}

/**
 * signs a hash
 * @param  {Buffer|String}   pub - pubKey corresponding to private key to sign hash with
 * @param  {Buffer|String}   hash - hash to sign
 * @param  {Function} cb
 */
function sign (pub, hash, cb) {
  checkServiceID()
  assert(Buffer.isBuffer(pub) || typeof pub === 'string')
  assert(Buffer.isBuffer(hash) || typeof hash === 'string')
  assert(typeof cb === 'function')

  RNECC.sign({
    service: serviceID,
    accessGroup: accessGroup,
    pub: toString(pub),
    hash: toString(hash)
  }, normalizeCallback(cb))
}

/**
 * verifies a signature
 * @param  {Buffer}   pubKey - pubKey to verify with
 * @param  {Buffer}   hash - hash that is signed by sig
 * @param  {Buffer}   sig - signature of hash
 * @param  {Function} cb
 */
function verify (pubKey, hash, sig, cb) {
  pubKey = toString(pubKey)

  assert(typeof pubKey === 'string')
  assert(Buffer.isBuffer(hash))
  assert(Buffer.isBuffer(sig))
  assert(typeof cb === 'function')

  RNECC.verify(pubKey, toString(hash), toString(sig), normalizeCallback(cb))
}

function hasKey (pub, cb) {
  checkServiceID()
  assert(Buffer.isBuffer(pub) || typeof pub === 'string')
  RNECC.hasKey({
    service: serviceID,
    accessGroup: accessGroup,
    pub: toString(pub)
  }, normalizeCallback(cb))
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
function keyFromPublic (pubKeyBuf) {
  let base64pub = toString(pubKeyBuf)
  return {
    sign: sign.bind(null, base64pub),
    verify: verify.bind(null, base64pub),
    pub: pubKeyBuf
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
  var out = new Error(error.message);
  out.key = error.key; // flow doesn't like this :(
  return out;
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
