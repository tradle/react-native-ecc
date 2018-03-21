//
//  RNECC.m
//
//  Created by Mark Vayngrib on 12/24/15.
//  Copyright © 2015 Tradle, Inc. All rights reserved.
//

#import "RNECC.h"
#include "CommonCrypto/CommonDigest.h"
#import <React/RCTUtils.h>

#define HASH_LENGTH             CC_SHA256_DIGEST_LENGTH
#define kTypeOfSigPadding       kSecPaddingPKCS1

#if TARGET_OS_SIMULATOR
static BOOL isSimulator = YES;
#else
static BOOL isSimulator = NO;
#endif

@implementation RNECC

RCT_EXPORT_MODULE();

RCT_EXPORT_METHOD(test)
{
  NSString* errMsg;
  NSString* serviceId = @"this.is.a.test";
  NSString* pub = [self generateECPair:@{
                                         @"service": serviceId,
                                         @"bits": @256
                                         }
                                errMsg:&errMsg];

  if (pub == nil) return;

  NSMutableData* hash = [NSMutableData dataWithLength:HASH_LENGTH];
  SecRandomCopyBytes(kSecRandomDefault, HASH_LENGTH, [hash mutableBytes]);
  NSDictionary* options = @{
                           @"service": serviceId,
                           @"pub":pub,
                           @"hash":[hash base64EncodedStringWithOptions:0]
                           };

  NSData* sig = [self sign:options errMsg:&errMsg];
  if (sig == nil) return;

  BOOL verified = [self verify:pub hash:hash sig:sig errMsg:&errMsg];
  NSLog(@"success: %i", verified);
}

RCT_EXPORT_METHOD(generateECPair:(nonnull NSDictionary*) options
                        callback:(RCTResponseSenderBlock)callback) {
  dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
    NSString* errMsg;
    NSString* base64pub = [self generateECPair:options errMsg:&errMsg];
    if (base64pub == nil) {
      return callback(@[rneccMakeError(errMsg)]);
    } else {
      callback(@[[NSNull null], base64pub]);
    }
  });
}

/**
 * @return base64 pub key string
 */
- (NSString *) generateECPair:(nonnull NSDictionary*) options
                        errMsg:(NSString **)errMsg
{
  CFErrorRef sacErr = NULL;
  SecAccessControlRef sacObject;

  // Should be the secret invalidated when passcode is removed? If not then use `kSecAttrAccessibleWhenUnlocked`.
  sacObject = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                              kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
//                                              kSecAccessControlTouchIDAny | kSecAccessControlPrivateKeyUsage,
//                                              kSecAccessControlUserPresence,
                                              kNilOptions,
                                              &sacErr);

  if (sacErr) {
    *errMsg = [(__bridge NSError *)sacErr description];
    return nil;
  }

  // Create parameters dictionary for key generation.
  NSString* uuid = [self uuidString];
  NSString* pubKeyLabel = [self toPublicIdentifier:uuid];
  NSMutableDictionary *privateKeyAttrs = [NSMutableDictionary dictionaryWithDictionary: @{
                                    (__bridge id)kSecAttrIsPermanent: @YES,
                                    (__bridge id)kSecAttrApplicationLabel: uuid,
                                    }];

  if (!isSimulator) {
    [privateKeyAttrs setObject:(__bridge_transfer id)sacObject forKey:(__bridge id)kSecAttrAccessControl];
//    [privateKeyAttrs setObject:(__bridge id)kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly forKey:(__bridge id)kSecAttrAccessible];
  }

  NSString* serviceID = [options valueForKey:@"service"];
  NSNumber* sizeInBits = [options objectForKey:@"bits"];
  if (sizeInBits == nil) {
    sizeInBits = @256;
  }

  NSString* accessGroup = [options valueForKey:@"accessGroup"];
  if (accessGroup) {
    [privateKeyAttrs setObject:accessGroup forKey:(__bridge id)kSecAttrAccessGroup];
  }

  NSDictionary *publicKeyAttrs = @{
                                   (__bridge id)kSecAttrIsPermanent: isSimulator ? @YES : @NO,
                                   (__bridge id)kSecAttrApplicationLabel: pubKeyLabel,
                                   };

  NSMutableDictionary *parameters = [NSMutableDictionary dictionaryWithDictionary: @{
                               (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeEC,
                               (__bridge id)kSecAttrKeySizeInBits: sizeInBits,
                               (__bridge id)kSecPrivateKeyAttrs: privateKeyAttrs,
                               (__bridge id)kSecPublicKeyAttrs: publicKeyAttrs,
                               }];

  if (accessGroup) {
    [parameters setObject:accessGroup forKey:(__bridge id)kSecAttrAccessGroup];
  }

  if (sizeInBits == @256 && !isSimulator && floor(NSFoundationVersionNumber) > NSFoundationVersionNumber_iOS_8_0) {
    NSOperatingSystemVersion os = [[NSProcessInfo processInfo] operatingSystemVersion];
    if (os.majorVersion >= 9) {
      [parameters setObject:(__bridge id)kSecAttrTokenIDSecureEnclave forKey:(__bridge id)kSecAttrTokenID];
    }
  }

  SecKeyRef publicKey, privateKey;
  OSStatus status = SecKeyGeneratePair((__bridge CFDictionaryRef)parameters, &publicKey, &privateKey);
  if (status != errSecSuccess) {
    *errMsg = keychainStatusToString(status);
    return nil;
  }

  if (!isSimulator) {
    status = SecItemAdd((__bridge CFDictionaryRef)@{
                                             (__bridge id)kSecClass: (__bridge id)kSecClassKey,
                                             (__bridge id)kSecAttrKeyClass: (__bridge id)kSecAttrKeyClassPublic,
                                             (__bridge id)kSecAttrApplicationLabel: pubKeyLabel,
                                             (__bridge id)kSecValueRef: (__bridge id)publicKey
                                             }, nil);

    if (status != errSecSuccess) {
      CFRelease(privateKey);
      CFRelease(publicKey);
      *errMsg = keychainStatusToString(status);
      return nil;
    }
  }

  NSData *data = [self getPublicKeyDataByLabel:pubKeyLabel];
  NSString* base64str = [data base64EncodedStringWithOptions:0];

  sacObject = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                              kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                                              0, &sacErr);

  status = SecItemAdd((__bridge CFDictionaryRef)@{
                                    (__bridge id)kSecAttrAccessControl: (__bridge_transfer id)sacObject,
                                    (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                                    (__bridge id)kSecAttrService: serviceID,
                                    (__bridge id)kSecAttrAccount:base64str,
                                    (__bridge id)kSecAttrGeneric:uuid,
                                    }, nil);

  if (status != errSecSuccess) {
    CFRelease(privateKey);
    CFRelease(publicKey);
    *errMsg = keychainStatusToString(status);
    return nil;
  }


  status = [self tagKeyWithLabel:pubKeyLabel tag:[self toPublicIdentifier:base64str]];

  CFRelease(privateKey);
  CFRelease(publicKey);
  if (status != errSecSuccess) {
    *errMsg = keychainStatusToString(status);
    return nil;
  }

  return base64str;
}

RCT_EXPORT_METHOD(hasKey:(nonnull NSDictionary *)options
                  callback:(RCTResponseSenderBlock)callback)
{
  dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
    OSStatus status;
    SecKeyRef privateKey = [self getPrivateKeyRef:options status:&status];
    if (privateKey) {
      CFRelease(privateKey);
      callback(@[[NSNull null], @YES]);
    } else if (status == errSecItemNotFound) {
      callback(@[[NSNull null], @NO]);
    } else {
      callback(@[rneccMakeError(keychainStatusToString(status))]);
    }
  });
}

RCT_EXPORT_METHOD(sign:(nonnull NSDictionary *)options
                  //                  withAuthenticationPrompt:(NSString *)prompt
                  callback:(RCTResponseSenderBlock)callback) {
  // Query private key object from the keychain.
  dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
    NSString* errMsg;
    NSData* sig = [self sign:options errMsg:&errMsg];
    if (!sig) {
      callback(@[rneccMakeError(errMsg)]);
      return;
    }

    NSString* base64sig = [sig base64EncodedStringWithOptions:0];
    callback(@[[NSNull null], base64sig]);
  });
}

-(NSData *)sign:(nonnull NSDictionary*)options
          errMsg:(NSString **) errMsg {

  OSStatus status;
  NSString* base64hash = [options valueForKey:@"hash"];
  NSData *hash = [[NSData alloc] initWithBase64EncodedString:base64hash options:0];
  if ([hash length] != HASH_LENGTH) {
    *errMsg = [NSString stringWithFormat:@"hash parameter must be %d bytes", HASH_LENGTH];
    return nil;
  }

  SecKeyRef privateKey = [self getPrivateKeyRef:options status:&status];
  if (!privateKey) {
    *errMsg = keychainStatusToString(status);
    return nil;
  }

  // Sign the data in the digest/digestLength memory block.
  uint8_t signature[128];
  size_t signatureLength = sizeof(signature);
  status = SecKeyRawSign(
                         privateKey,
                         kTypeOfSigPadding,
                         (const uint8_t*)[hash bytes],
                         HASH_LENGTH,
                         signature,
                         &signatureLength);

  CFRelease(privateKey);
  if (status != errSecSuccess) {
    *errMsg = keychainStatusToString(status);
    return nil;
  }

//  NSError* vError;
  NSData* sigData = [NSData dataWithBytes:(const void *)signature length:signatureLength];
//  BOOL verified = [self verify:base64pub hash:hash sig:sigData error:&vError];
//  if (!verified) {
//    NSLog(@"uh oh, failed to verify sig");
//  }

  return sigData;
}

RCT_EXPORT_METHOD(verify:(nonnull NSDictionary *)options
                  callback:(RCTResponseSenderBlock)callback) {
  NSString* pub = [options valueForKey:@"pub"];
  NSString* hash = [options valueForKey:@"hash"];
  NSString* sig = [options valueForKey:@"sig"];
  [self doVerify:pub hash:hash sig:sig callback:callback];
}

-(OSStatus) importPubKey:(NSString *)base64pub {

  NSData *keyData = [[NSData alloc] initWithBase64EncodedString:base64pub options:0];
  // one byte prefix, then key
  // if first byte is 0x04, it's a regular public key, if it's 0x02 or 0x03, then it's compact
  // the byteLength is compactLength - 1 or (regularLength - 1) / 2
  // NSNumber* sizeInBits = byteLength * 8
  NSDictionary *saveDict = @{
                             (__bridge id) kSecClass : (__bridge id) kSecClassKey,
                             (__bridge id) kSecAttrKeyType : (__bridge id) kSecAttrKeyTypeEC,
                             (__bridge id) kSecAttrApplicationTag : [self toPublicIdentifier:base64pub],
                             (__bridge id) kSecAttrKeyClass : (__bridge id)kSecAttrKeyClassPublic,
                             (__bridge id) kSecValueData : keyData,
                             // (__bridge id) kSecAttrKeySizeInBits : sizeInBits,
                             // (__bridge id) kSecAttrEffectiveKeySize : sizeInBits,
                             (__bridge id) kSecAttrCanDerive : (__bridge id) kCFBooleanFalse,
//                             (__bridge id) kSecAttrCanEncrypt : (__bridge id) kCFBooleanTrue,
//                             (__bridge id) kSecAttrCanDecrypt : (__bridge id) kCFBooleanFalse,
                             (__bridge id) kSecAttrCanVerify : (__bridge id) kCFBooleanTrue,
                             (__bridge id) kSecAttrCanSign : (__bridge id) kCFBooleanFalse,
                             (__bridge id) kSecAttrCanWrap : (__bridge id) kCFBooleanTrue,
                             (__bridge id) kSecAttrCanUnwrap : (__bridge id) kCFBooleanFalse
                             };

  SecKeyRef savedKeyRef = NULL;
  return SecItemAdd((__bridge CFDictionaryRef)saveDict, (CFTypeRef *)&savedKeyRef);
//  if (sanityCheck != errSecSuccess) {
//
//  }
}

-(BOOL) verify:(NSString *)base64pub
          hash:(NSData *)hash
           sig:(NSData *)sig
         errMsg:(NSString **)errMsg {

  // we might already have the key in the keychain
  SecKeyRef publicKey = [self getPublicKeyRef:base64pub];
  if (!publicKey) {
    // import the key, then query for it
    OSStatus status = [self importPubKey:base64pub];
    if (status != errSecSuccess && status != errSecDuplicateItem) {
      *errMsg = keychainStatusToString(errSecBadReq);
      return false;
    }

    publicKey = [self getPublicKeyRef:base64pub];
    if (!publicKey) {
      *errMsg = keychainStatusToString(errSecItemNotFound);
      return false;
    }
  }

  OSStatus status = SecKeyRawVerify(
                                publicKey,
                                kTypeOfSigPadding,
                                (const uint8_t *)[hash bytes],
                                HASH_LENGTH,
                                (const uint8_t *)[sig bytes],
                                [sig length]
                                );

  CFRelease(publicKey);
  if (status != errSecSuccess) {
    *errMsg = keychainStatusToString(status);
    return false;
  }

  return true;
}

-(void) doVerify:(NSString *)base64pub
            hash:(NSString *)base64hash
             sig:(NSString *)sig
        callback:(RCTResponseSenderBlock)callback {
  NSData *hash = [[NSData alloc] initWithBase64EncodedString:base64hash options:0];
  if ([hash length] != HASH_LENGTH) {
    NSString* message = [NSString stringWithFormat:@"hash parameter must be %d bytes", HASH_LENGTH];
    callback(@[rneccMakeError(message)]);
    return;
  }

  dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
    NSData* sigData = [[NSData alloc] initWithBase64EncodedString:sig options:0];
    NSString* errMsg = nil;
    BOOL verified = [self verify:base64pub hash:hash sig:sigData errMsg:&errMsg];
    if (!verified) {
      callback(@[rneccMakeError(errMsg), @NO]);
      return;
    }

    callback(@[[NSNull null], @YES]);
  });
}

-(OSStatus) tagKeyWithLabel:(NSString*)label tag:(NSString*)tag
{
  SecKeyRef foundItem;
  OSStatus findStatus = SecItemCopyMatching((__bridge CFDictionaryRef)@{
                                                                        (__bridge id)kSecClass: (__bridge id)kSecClassKey,
                                                                        (__bridge id)kSecAttrApplicationLabel: label,
                                                                        (__bridge id)kSecReturnAttributes: @YES,
                                                                        }, (CFTypeRef *)&foundItem);

  if (findStatus != errSecSuccess) {
    NSLog(@"failed to find key: %d", (int)findStatus);
    return findStatus;
  }

  NSMutableDictionary *updateDict = (__bridge NSMutableDictionary *)foundItem;
  [updateDict setObject:tag forKey:(__bridge id)kSecAttrApplicationTag];
  [updateDict removeObjectForKey:(__bridge id)kSecClass];
  OSStatus updateStatus = SecItemUpdate((__bridge CFDictionaryRef)@{
                                                                    (__bridge id)kSecClass: (__bridge id)kSecClassKey,
                                                                    (__bridge id)kSecAttrApplicationLabel: label,
                                                                    }, (__bridge CFDictionaryRef)updateDict);

  if (updateStatus != errSecSuccess) {
    NSLog(@"failed to update key: %d", (int)updateStatus);
    return updateStatus;
  }

  OSStatus check = SecItemCopyMatching((__bridge CFDictionaryRef)@{
                                                                   (__bridge id)kSecClass: (__bridge id)kSecClassKey,
                                                                   (__bridge id)kSecAttrApplicationTag: tag,
                                                                   (__bridge id)kSecReturnAttributes: @YES,
                                                                   }, (CFTypeRef *)&foundItem);

  if (check != errSecSuccess) {
    NSLog(@"failed to retrieve key based on new attributes: %d", (int)check);
  }

  return check;
}

- (NSString *) toPublicIdentifier:(NSString *)pubIdentifier
{
  return [pubIdentifier stringByAppendingString:@"-pub"];
}

- (NSString *) toUUIDIdentifier:(NSString *)privIdentifier
{
  return [privIdentifier stringByAppendingString:@"-uuid"];
}

NSDictionary* rneccMakeError(NSString* errMsg)
{
  return RCTMakeAndLogError(errMsg, nil, nil);
}

-(NSData *)getPublicKeyDataByLabel:(NSString *)label
{

  NSDictionary* keyAttrs = @{
                             (__bridge id)kSecClass: (__bridge id)kSecClassKey,
                             (__bridge id)kSecAttrKeyClass: (__bridge id)kSecAttrKeyClassPublic,
                             (__bridge id)kSecAttrApplicationLabel: label,
                             (__bridge id)kSecReturnData: @YES,
                             };

  CFTypeRef result;
  OSStatus sanityCheck = SecItemCopyMatching((__bridge CFDictionaryRef)keyAttrs, &result);

  if (sanityCheck != noErr)
  {
    return nil;
  }

  return CFBridgingRelease(result);
}

-(SecKeyRef)getKeyRefByLabel:(NSString *)label status:(OSStatus*)status
{
  SecKeyRef keyRef;
  *status = SecItemCopyMatching((__bridge CFDictionaryRef)@{
    (__bridge id)kSecClass: (__bridge id)kSecClassKey,
    (__bridge id)kSecReturnRef: @YES,
    (__bridge id)kSecAttrApplicationLabel:label
  }, (CFTypeRef *)&keyRef);

  if (*status != errSecSuccess)
  {
    return nil;
  }

  return keyRef;
}

-(SecKeyRef)getPrivateKeyRef:(nonnull NSDictionary *)options
                      status:(OSStatus *)status
{
  NSMutableDictionary* uuidAttrs = [NSMutableDictionary dictionaryWithDictionary: @{
                             (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                             (__bridge id)kSecReturnAttributes: @YES,
                             }];

  NSString* serviceID = [options valueForKey:@"service"];
  NSString* base64pub = [options valueForKey:@"pub"];

  [uuidAttrs setObject:serviceID forKey:(__bridge id)kSecAttrService];

  NSString* accessGroup = [options valueForKey:@"accessGroup"];
  if (accessGroup) {
    [uuidAttrs setObject:accessGroup forKey:(__bridge id)kSecAttrAccessGroup];
  }

  if (base64pub) {
    [uuidAttrs setObject:base64pub forKey:(__bridge id)kSecAttrAccount];
  }

  NSDictionary* found = nil;
  CFTypeRef foundTypeRef = NULL;
  *status = SecItemCopyMatching((__bridge CFDictionaryRef) uuidAttrs, (CFTypeRef*)&foundTypeRef);

  if (*status != errSecSuccess) {
    return nil;
  }

  found = (__bridge NSDictionary*)(foundTypeRef);
  NSString* uuid = [found objectForKey:(__bridge id)(kSecAttrGeneric)];
  return [self getKeyRefByLabel:uuid status:status];
}

-(SecKeyRef)getPublicKeyRef:(NSString *)base64pub
{
  NSDictionary* keyAttrs = @{
                              (__bridge id)kSecClass: (__bridge id)kSecClassKey,
                              (__bridge id)kSecReturnRef: @YES,
                              (__bridge id)kSecAttrApplicationTag: [self toPublicIdentifier:base64pub]
                              };

  SecKeyRef keyRef;
  OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)keyAttrs, (CFTypeRef *)&keyRef);
  if (status != errSecSuccess)
  {
    return nil;
  }

  return keyRef;
}

- (NSString *)uuidString {
  CFUUIDRef uuid = CFUUIDCreate(kCFAllocatorDefault);
  NSString *uuidString = (__bridge_transfer NSString *)CFUUIDCreateString(kCFAllocatorDefault, uuid);
  CFRelease(uuid);

  return uuidString;
}

NSString *keychainStatusToString(OSStatus status) {
  NSString *message = [NSString stringWithFormat:@"%ld", (long)status];

  switch (status) {
    case errSecSuccess:
      message = @"success";
      break;

    case errSecDuplicateItem:
      message = @"error item already exists";
      break;

    case errSecItemNotFound :
      message = @"error item not found";
      break;

    case errSecAuthFailed:
      message = @"error item authentication failed";
      break;

    default:
      message = [NSString stringWithFormat:@"error with OSStatus %d", status];
      break;
  }

  return message;
}

@end
