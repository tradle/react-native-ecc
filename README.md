# react-native-ecc

basic elliptic curve crypto for React Native

**this module is used by [Tradle](https://github.com/tradle/tim)**

## Installation

See [Linking Libraries](http://facebook.github.io/react-native/docs/linking-libraries-ios.html)

## Usage

```js
import * as ec from 'react-native-ecc'
import { Buffer } from 'buffer'

// if you want to be able to find your keys
// next time, make sure to use the same service ID 
ec.setServiceID('be.excellent.to.each.other')

// this library allows you to sign 32 byte hashes (e.g. sha256 hashes)
let plaintextHash = new Buffer('c764320a6820c75c82ec43523690bdfd547a077fd6fb805dc3fb9517d23ca527', 'hex')
// check ec.curves for supported curves
let curve = 'p256'
ec.keyPair(curve, function (err, key) {
  // pub tested for compatibility with npm library "elliptic"
  let pub = key.pub
  console.log('pub', key.pub.toString('hex'))

  // look up the key later like this:
  // let key = ec.keyFromPublic(pub)

  key.sign(plaintextHash, function (err, sig) {
    // signatures tested for compatibility with npm library "elliptic"
    console.log('sig', sig.toString('hex'))
    key.verify(plaintextHash, sig, function (err, verified) {
      console.log('verified:', verified)
    })
  })
})
```
