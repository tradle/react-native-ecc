//
//  RNCryptoUtils.h
//  rnecc
//
//  Created by Mark Vayngrib on 12/24/15.
//  Copyright © 2015 Tradle, Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <RCTBridgeModule.h>

@interface RNECC : NSObject <RCTBridgeModule>

extern NSString *const RNECCErrorDomain;

enum RNECCError
{
  RNECCNoError = 0,           // Never used
  RNECCInvalidInvocationError,// Invalid method invocation
  RNECCBadConfigError,        // Invalid configuration
  RNECCBadParamError,         // Invalid parameter was passed
  RNECCDuplicateKeyError,     // Attempt to create a key with the same attributes as an existing one
  RNECCOtherError,            // Description provided in userInfo
};

typedef enum RNECCError RNECCError;

- (NSString *) toPublicIdentifier:(NSString *)privIdentifier;
- (NSData *) getPublicKeyDataByLabel:(NSString *)label;
- (SecKeyRef) getPublicKeyRef:(NSString *)base64pub;
- (SecKeyRef) getPrivateKeyRef:(NSString *)serviceID pub:(NSString *)base64pub;
- (OSStatus) tagKeyWithLabel:(NSString*)label tag:(NSString*)tag;
- (NSString *) uuidString;
- (NSData *) sign:(NSString *)serviceID pub:(NSString *)base64pub hash:(NSData *)hash error:(NSDictionary **) error;
- (BOOL) verify:(NSString *)base64pub hash:(NSData *)hash sig:(NSData *)sig error:(NSDictionary **)error;
@end
