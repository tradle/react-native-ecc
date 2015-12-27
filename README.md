# react-native-ecc

basic elliptic curve crypto for React Native

**this module is used by [Tradle](https://github.com/tradle/tim)**

## Usage

```js
import * as ec from 'react-native-ecc'
import { Buffer } from 'buffer'

// this library allows you to sign 32 byte hashes (e.g. sha256 hashes)
var plaintextHash = new Buffer('c764320a6820c75c82ec43523690bdfd547a077fd6fb805dc3fb9517d23ca527', 'hex')
// check ec.curves for supported curves
var curve = 'p256'
ec.keyPair(curve, function (err, key) {
  // key.pub is tested for compatibility with npm library "elliptic"
  console.log('pub', key.pub.toString('hex'))
  key.sign(plaintextHash, function (err, sig) {
    // signatures tested for compatibility with npm library "elliptic"
    console.log('sig', sig.toString('hex'))
    key.verify(plaintextHash, sig, function (err, verified) {
      console.log('verified:', verified)
    })
  })
})
```
