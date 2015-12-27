//
//  RNCryptoUtils.m
//  rnecc
//
//  Created by Mark Vayngrib on 12/24/15.
//  Copyright © 2015 Facebook. All rights reserved.
//

#import "RNECC.h"
#include "CommonCrypto/CommonDigest.h"

#define HASH_LENGTH             CC_SHA256_DIGEST_LENGTH
#define kTypeOfSigPadding       kSecPaddingPKCS1

NSString *const RNECCErrorDomain = @"RNECCErrorDomain";
//NSString *const SIGN_PROMPT = @"Authenticate to sign data";
//NSString *const SERVICE_ID = @"io.tradle.tim";

#if TARGET_OS_SIMULATOR
static BOOL isSimulator = YES;
#else
static BOOL isSimulator = NO;
#endif

@implementation RNECC

RCT_EXPORT_MODULE();

//RCT_EXPORT_METHOD(test) {
//  CFErrorRef error = NULL;
//  SecAccessControlRef sacObject;
//
//  // Should be the secret invalidated when passcode is removed? If not then use `kSecAttrAccessibleWhenUnlocked`.
//  sacObject = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
//                                              kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
//                                              kSecAccessControlTouchIDAny | kSecAccessControlPrivateKeyUsage, &error);
//
//  // Create parameters dictionary for key generation.
//  NSNumber* sizeInBits = @192;
//  NSString* uuid = [self uuidString];
//  NSString* pubKeyLabel = [self toPublicIdentifier:uuid];
//  NSDictionary *privateKeyAttrs = @{
//                                    (__bridge id)kSecAttrAccessControl: (__bridge_transfer id)sacObject,
//                                    (__bridge id)kSecAttrIsPermanent: @YES,
//                                    (__bridge id)kSecAttrApplicationLabel: uuid,
//                                    };
//  NSDictionary *publicKeyAttrs = @{
//                                   (__bridge id)kSecAttrIsPermanent: @YES,
//                                   (__bridge id)kSecAttrApplicationLabel: pubKeyLabel,
//                                  };
//
//  NSDictionary *parameters = @{
//                               (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeEC,
//                               (__bridge id)kSecAttrKeySizeInBits: sizeInBits,
//                               (__bridge id)kSecPrivateKeyAttrs: privateKeyAttrs,
//                               (__bridge id)kSecPublicKeyAttrs: publicKeyAttrs,
//                               };
//
//  dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
//    SecKeyRef publicKey, privateKey;
//    OSStatus status = SecKeyGeneratePair((__bridge CFDictionaryRef)parameters, &publicKey, &privateKey);
//    if (status == errSecSuccess) {
//      CFRelease(publicKey);
//      CFRelease(privateKey);
//    }
//    else if (status != errSecDuplicateItem) {
//      return;
//    }
//
//    NSData *data = [self getPublicKeyDataByLabel:pubKeyLabel];
//    NSString* base64str = [data base64EncodedStringWithOptions:0];
//    OSStatus privUpdateStatus = [self tagKeyWithLabel:uuid tag:base64str];
//    OSStatus pubUpdateStatus = [self tagKeyWithLabel:pubKeyLabel tag:[self toPublicIdentifier:base64str]];
//
//    if (privUpdateStatus != errSecSuccess && privUpdateStatus != errSecDuplicateItem) {
//      return;
//    }
//
//    if (pubUpdateStatus != errSecSuccess && pubUpdateStatus != errSecDuplicateItem) {
//      return;
//    }
//
//    NSLog(@"pubkey: %@", base64str);
//
//    uint8_t signature[128];
//    size_t signatureLength = sizeof(signature);
//    uint8_t digestData[32];
//    size_t digestLength = sizeof(digestData);
//    SecKeyRef privKey = [self getKeyRef:base64str];
//    status = SecKeyRawSign(privKey, kTypeOfSigPadding, digestData, digestLength, signature, &signatureLength);
//    if (status == errSecSuccess) {
//      SecKeyRef pubKey = [self getKeyRef:[self toPublicIdentifier:base64str]];
//      if (pubKey) {
//        status = SecKeyRawVerify(pubKey, kTypeOfSigPadding, digestData, digestLength, signature, signatureLength);
//        NSLog(@"status: %d", status);
//        CFRelease(pubKey);
//      }
//
//      CFRelease(privKey);
//    }
//  });
//}

RCT_EXPORT_METHOD(generateECPair:(nonnull NSNumber*)sizeInBits
                  callback:(RCTResponseSenderBlock)callback) {
  CFErrorRef error = NULL;
  SecAccessControlRef sacObject;

  // Should be the secret invalidated when passcode is removed? If not then use `kSecAttrAccessibleWhenUnlocked`.
  sacObject = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                              kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                                              kSecAccessControlTouchIDAny | kSecAccessControlPrivateKeyUsage, &error);

  // Create parameters dictionary for key generation.
  NSString* uuid = [self uuidString];
  NSString* pubKeyLabel = [self toPublicIdentifier:uuid];
  NSDictionary *privateKeyAttrs = @{
                                    (__bridge id)kSecAttrAccessControl: (__bridge_transfer id)sacObject,
                                    (__bridge id)kSecAttrIsPermanent: @YES,
                                    (__bridge id)kSecAttrApplicationLabel: uuid,
                                    };
  NSDictionary *publicKeyAttrs = @{
                                   (__bridge id)kSecAttrIsPermanent: @YES,
                                   (__bridge id)kSecAttrApplicationLabel: pubKeyLabel,
                                   };

  NSMutableDictionary *parameters = [NSMutableDictionary dictionaryWithDictionary: @{
                               (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeEC,
                               (__bridge id)kSecAttrKeySizeInBits: sizeInBits,
                               (__bridge id)kSecPrivateKeyAttrs: privateKeyAttrs,
                               (__bridge id)kSecPublicKeyAttrs: publicKeyAttrs,
                               }];

  if (!isSimulator && floor(NSFoundationVersionNumber) > NSFoundationVersionNumber_iOS_8_0) {
    NSOperatingSystemVersion os = [[NSProcessInfo processInfo] operatingSystemVersion];
    if (os.majorVersion >= 9) {
      [parameters setObject:(__bridge id)kSecAttrTokenIDSecureEnclave forKey:(__bridge id)kSecAttrTokenID];
    }
  }

  dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
    SecKeyRef publicKey, privateKey;
    OSStatus status = SecKeyGeneratePair((__bridge CFDictionaryRef)parameters, &publicKey, &privateKey);
    if (status == errSecSuccess) {
      CFRelease(publicKey);
      CFRelease(privateKey);
    }
    else if (status != errSecDuplicateItem) {
      callback(@[[self genericErrorFromStatus:status]]);
      return;
    }

    NSData *data = [self getPublicKeyDataByLabel:pubKeyLabel];
    NSString* base64str = [data base64EncodedStringWithOptions:0];
    OSStatus privUpdateStatus = [self tagKeyWithLabel:uuid tag:base64str];
    OSStatus pubUpdateStatus = [self tagKeyWithLabel:pubKeyLabel tag:[self toPublicIdentifier:base64str]];

    if (privUpdateStatus != errSecSuccess) {
      callback(@[[self genericErrorFromStatus:status]]);
      return;
    }

    if (pubUpdateStatus != errSecSuccess) {
      callback(@[[self genericErrorFromStatus:status]]);
      return;
    }

    callback(@[[NSNull null], base64str]);
  });
}

RCT_EXPORT_METHOD(sign:(nonnull NSString *)base64pub
                  hash:(nonnull NSString *)base64Hash
                  //                  withAuthenticationPrompt:(NSString *)prompt
                  callback:(RCTResponseSenderBlock)callback) {
  // Query private key object from the keychain.
  NSData *hash = [[NSData alloc] initWithBase64EncodedString:base64Hash options:0];
  if ([hash length] != HASH_LENGTH) {
    NSString* message = [NSString stringWithFormat:@"hash parameter must be %d bytes", HASH_LENGTH];
    callback(@[[self createError:RNECCBadParamError msg:message]]);
    return;
  }

  dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
    NSError* error;
    NSData* sig = [self sign:base64pub hash:hash error:&error];
    if (!sig) {
      callback(@[error]);
      return;
    }

    NSString* base64sig = [sig base64EncodedStringWithOptions:0];
    callback(@[[NSNull null], base64sig]);
  });
}

-(NSData *)sign:(nonnull NSString *)base64pub
           hash:(nonnull NSData *)hash
          error:(NSError **) error {

  SecKeyRef privateKey = [self getKeyRef:base64pub];
  if (!privateKey) {
    *error = [self genericError:@"key not found"];
    return nil;
  }

  // Sign the data in the digest/digestLength memory block.
  uint8_t signature[128];
  size_t signatureLength = sizeof(signature);
  OSStatus status = SecKeyRawSign(
                         privateKey,
                         kTypeOfSigPadding,
                         (const uint8_t*)[hash bytes],
                         HASH_LENGTH,
                         signature,
                         &signatureLength);

  CFRelease(privateKey);
  if (status != errSecSuccess) {
    *error = [self genericErrorFromStatus:status];
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

RCT_EXPORT_METHOD(verify:(NSString *)base64pub
                  hash:(NSString *)base64Hash
                  sig:(NSString *)sig
             callback:(RCTResponseSenderBlock)callback) {

  NSData *hash = [[NSData alloc] initWithBase64EncodedString:base64Hash options:0];
  if ([hash length] != HASH_LENGTH) {
    NSString* message = [NSString stringWithFormat:@"hash parameter must be %d bytes", HASH_LENGTH];
    callback(@[[self createError:RNECCBadParamError msg:message]]);
    return;
  }

  dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
    NSData* sigData = [[NSData alloc] initWithBase64EncodedString:sig options:0];
    NSError* error = nil;
    BOOL verified = [self verify:base64pub hash:hash sig:sigData error:&error];
    if (!verified) {
      callback(@[error, @NO]);
      return;
    }

    callback(@[[NSNull null], @YES]);
  });
}

-(BOOL) verify:(NSString *)base64pub
          hash:(NSData *)hash
           sig:(NSData *)sig
       error:(NSError** )error {

  SecKeyRef publicKey = [self getKeyRef:[self toPublicIdentifier:base64pub]];
  if (!publicKey) {
    *error = [self genericError:@"key not found"];
    return false;
  }

  OSStatus status = SecKeyRawVerify(
                                publicKey,
                                kTypeOfSigPadding,
                                (const uint8_t *)[hash bytes],
                                HASH_LENGTH,
                                (const uint8_t *)[sig bytes],
                                [sig length]
                                );

  if (status != errSecSuccess) {
    *error = [self genericErrorFromStatus:status];
    return false;
  }

  return true;
}

-(OSStatus) tagKeyWithLabel:(NSString*)label tag:(NSString*)tag
{
  SecKeyRef foundItem = [self getKeyRefByLabel:label];
  OSStatus findStatus = SecItemCopyMatching((__bridge CFDictionaryRef)@{
                                                           (__bridge id)kSecClass: (__bridge id)kSecClassKey,
                                                           (__bridge id)kSecAttrApplicationLabel: label,
                                                           (__bridge id)kSecReturnAttributes: @YES,
                                                           }, (CFTypeRef *)&foundItem);

  if (findStatus != errSecSuccess) {
    NSLog(@"failed to find key: %d", findStatus);
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
    NSLog(@"failed to update key: %d", updateStatus);
    return updateStatus;
  }

  OSStatus check = SecItemCopyMatching((__bridge CFDictionaryRef)@{
                                                           (__bridge id)kSecClass: (__bridge id)kSecClassKey,
                                                           (__bridge id)kSecAttrApplicationTag: tag,
                                                           (__bridge id)kSecReturnAttributes: @YES,
                                                           }, (CFTypeRef *)&foundItem);

  if (check != errSecSuccess) {
    NSLog(@"failed to retrieve key based on new attributes: %d", check);
  }

  return check;
}

//- (CFStringRef) getKeyType:(NSString *)keyType {
//  if ([keyType isEqualToString:@"EC"]) return kSecAttrKeyTypeEC;
//  else if ([keyType isEqualToString:@"RSA"]) return kSecAttrKeyTypeRSA;
//  else return nil;
//}

- (NSString *) toPublicIdentifier:(NSString *)privIdentifier
{
  return [privIdentifier stringByAppendingString:@"-pub"];
}

- (NSError *)genericError:(NSString *)errMsg
{
  return [self createError:RNECCOtherError msg:errMsg];
}

- (NSError *)genericErrorFromStatus:(OSStatus)status
{
  return [self createError:RNECCOtherError msg:[self keychainErrorToString:status]];
}

- (NSError *)createError:(RNECCError)type msg:(NSString *)msg
{
  NSDictionary *userInfo = [NSDictionary dictionaryWithObject:msg forKey:NSLocalizedDescriptionKey];
  return [NSError errorWithDomain:RNECCErrorDomain
                             code:RNECCOtherError
                         userInfo:userInfo];
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

-(SecKeyRef)getKeyRefByLabel:(NSString *)label
{
  SecKeyRef keyRef;
  OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)@{
    (__bridge id)kSecClass: (__bridge id)kSecClassKey,
    (__bridge id)kSecReturnRef: @YES,
    (__bridge id)kSecAttrApplicationLabel:label
  }, (CFTypeRef *)&keyRef);

  if (status != errSecSuccess)
  {
    return nil;
  }

  return keyRef;
}

-(SecKeyRef)getKeyRef:(NSString *)tag
{
  NSMutableDictionary* keyAttrs = [NSMutableDictionary dictionaryWithDictionary:@{
                              (__bridge id)kSecClass: (__bridge id)kSecClassKey,
                              (__bridge id)kSecReturnRef: @YES,
                              }];

  if (tag) {
    [keyAttrs setObject:tag forKey:(__bridge id)kSecAttrApplicationTag];
  }

  SecKeyRef keyRef;
  OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)keyAttrs, (CFTypeRef *)&keyRef);

  if (status != errSecSuccess)
  {
    return nil;
  }

  return keyRef;
}

- (NSString *)keychainErrorToString:(OSStatus)error {
  NSString *message = [NSString stringWithFormat:@"%ld", (long)error];

  switch (error) {
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
      break;
  }

  return message;
}

- (NSString *)uuidString {
  CFUUIDRef uuid = CFUUIDCreate(kCFAllocatorDefault);
  NSString *uuidString = (__bridge_transfer NSString *)CFUUIDCreateString(kCFAllocatorDefault, uuid);
  CFRelease(uuid);

  return uuidString;
}

@end
