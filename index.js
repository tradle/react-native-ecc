
import { NativeModules } from 'react-native'
import { Buffer } from 'buffer'
const RNECC = NativeModules.RNECC
let serviceID

export const encoding = 'base64'
export function setServiceID (id) {
  if (serviceID) throw new Error('serviceID can only be set once')

  serviceID = id
}

export function getServiceID () {
  return serviceID
}

export const curves = {
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
export function keyPair (curve, cb) {
  checkServiceID()
  assert(typeof curve === 'string')
  assert(typeof cb === 'function')
  if (!(curve in curves)) throw new Error('unsupported curve')

  let sizeInBits = curves[curve]
  RNECC.generateECPair(serviceID, sizeInBits, function (err, base64pubKey) {
    if (err) return cb(err)

    cb(null, keyFromPublic(toBuffer(base64pubKey)))
  })
}

/**
 * signs a hash
 * @param  {Buffer}   pubKey - pubKey corresponding to private key to sign hash with
 * @param  {Buffer}   hash - hash to sign
 * @param  {Function} cb
 */
export function sign (pubKey, hash, cb) {
  checkServiceID()
  pubKey = toString(pubKey)

  assert(typeof pubKey === 'string')
  assert(Buffer.isBuffer(hash))
  assert(typeof cb === 'function')

  RNECC.sign(serviceID, pubKey, toString(hash), function (err, base64sig) {
    if (err) return cb(err)

    cb(null, toBuffer(base64sig))
  })
}

/**
 * verifies a signature
 * @param  {Buffer}   pubKey - pubKey to verify with
 * @param  {Buffer}   hash - hash that is signed by sig
 * @param  {Buffer}   sig - signature of hash
 * @param  {Function} cb
 */
export function verify (pubKey, hash, sig, cb) {
  pubKey = toString(pubKey)

  assert(typeof pubKey === 'string')
  assert(Buffer.isBuffer(hash))
  assert(Buffer.isBuffer(sig))
  assert(typeof cb === 'function')

  RNECC.verify(pubKey, toString(hash), toString(sig), cb)
}

/**
 * Returns a key with the API as the one returned by keyPair(...)
 * @param  {Buffer} pub pubKey buffer for existing key (created with keyPair(...))
 * @return {Object} key
 */
export function keyFromPublic (pubKeyBuf) {
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
